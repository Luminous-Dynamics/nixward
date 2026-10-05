// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reconstitution and continuity planning for sovereign Holons.
//!
//! A Holon identity is not a disk serial or motherboard. V30 makes that
//! distinction executable: a verified Genesis/First-Breath lineage can be
//! converted into a [`ContinuityAnchor`], then bound to a new physical
//! embodiment through a non-destructive [`ReconstitutionPlan`].
//!
//! This module deliberately covers **declarative system continuity**, not user
//! data restoration. Data continuity requires separate backup/content evidence
//! and must not be implied by a successful system reconstitution.

use crate::data_continuity::{DataContinuityReceipt, DataRestorePlan};
use crate::genesis_covenant::{
    AuthorityEvidenceRecord, BirthReceipt, FirstBreathReceipt, GenesisError, GenesisPlan,
    HolonIdentity, VerifiedAuthorityEvidence,
};
use crate::storage_intent::{StableDiskIdentity, StoragePlan};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const RECONSTITUTION_SCHEMA_VERSION: u32 = 1;
const RECONSTITUTION_PLAN_DOMAIN: &[u8] = b"symthaea-reconstitution-plan-v1\0";
const CONTINUITY_ANCHOR_DOMAIN: &[u8] = b"symthaea-continuity-anchor-v1\0";
const CONTINUITY_RECEIPT_DOMAIN: &[u8] = b"symthaea-continuity-receipt-v1\0";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("continuity evidence serialization is infallible");
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    hasher.finalize().to_hex().to_string()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReconstitutionError {
    #[error("genesis lineage is not internally consistent")]
    InvalidLineage,
    #[error("first-breath evidence is not verified")]
    UnverifiedLineage,
    #[error("replacement architecture differs from the anchored architecture")]
    ArchitectureMigrationRequired,
    #[error("reconstitution requires an authoritative StoragePlan")]
    InvalidStoragePlan,
    #[error("invalid digest in reconstitution input")]
    InvalidDigest,
    #[error("reconstitution expected toplevel must be a /nix/store path")]
    InvalidToplevel,
    #[error("continuity receipt does not preserve the anchored Holon identity")]
    IdentityMismatch,
    #[error("authority evidence is not bound to the exact reconstitution plan")]
    AuthorityMismatch,
    #[error("data restore plan does not preserve this Holon identity")]
    DataRestoreMismatch,
    #[error(transparent)]
    Genesis(#[from] GenesisError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityAnchor {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub genesis_plan_blake3: String,
    pub birth_receipt_blake3: String,
    pub first_breath_receipt_blake3: String,
    /// Most recent verified rebirth continuity receipt. Empty on original Genesis.
    #[serde(default)]
    pub parent_continuity_receipt_blake3: String,
    pub system: String,
    pub hostname: String,
    pub storage_layout: String,
    pub last_disk_by_id: String,
    pub sovereign_bundle_blake3: String,
    pub flake_lock_blake3: String,
    pub source_policy_blake3: String,
    pub evaluator_policy_blake3: String,
    pub last_verified_toplevel: String,
    pub last_machine_id_blake3: String,
    pub authority_issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signer_key_id: Option<String>,
    /// Trust-policy identity authorized by Genesis. Legacy local-session births
    /// leave this empty and cannot perform high-assurance destructive rebirth
    /// until a separate owner-key enrollment is completed.
    #[serde(default)]
    pub authority_policy_blake3: String,
    /// V30 does not claim user data was backed up merely because system state
    /// is reproducible. A future data-continuity receipt can upgrade this.
    pub data_continuity: String,
}

impl ContinuityAnchor {
    pub fn from_verified_lineage(
        plan: &GenesisPlan,
        birth: &BirthReceipt,
        first_breath: &FirstBreathReceipt,
    ) -> Result<Self, ReconstitutionError> {
        if birth.genesis_plan_blake3 != plan.digest()
            || first_breath.genesis_plan_blake3 != plan.digest()
            || first_breath.birth_receipt_blake3 != birth.digest()
            || &birth.holon != plan.holon()
            || &first_breath.holon != plan.holon()
        {
            return Err(ReconstitutionError::InvalidLineage);
        }
        if !first_breath.is_verified() {
            return Err(ReconstitutionError::UnverifiedLineage);
        }
        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-continuity-anchor-v1".into(),
            holon: plan.holon().clone(),
            genesis_plan_blake3: plan.digest(),
            birth_receipt_blake3: birth.digest(),
            first_breath_receipt_blake3: first_breath.digest(),
            parent_continuity_receipt_blake3: String::new(),
            system: plan.inputs().system.clone(),
            hostname: plan.inputs().hostname.clone(),
            storage_layout: if plan.inputs().storage_layout.is_empty() {
                "unknown-legacy-v29".into()
            } else {
                plan.inputs().storage_layout.clone()
            },
            last_disk_by_id: plan.inputs().target_disk_by_id.clone(),
            sovereign_bundle_blake3: plan.inputs().sovereign_bundle_blake3.clone(),
            flake_lock_blake3: plan.inputs().flake_lock_blake3.clone(),
            source_policy_blake3: plan.inputs().source_policy_blake3.clone(),
            evaluator_policy_blake3: plan.inputs().evaluator_policy_blake3.clone(),
            last_verified_toplevel: first_breath.observed_toplevel.clone(),
            last_machine_id_blake3: first_breath.machine_id_blake3.clone(),
            authority_issuer: plan.authority.issuer.clone(),
            authority_signer_key_id: plan.authority.signer_key_id.clone(),
            authority_policy_blake3: plan
                .authority
                .claims
                .get("authority_policy_blake3")
                .cloned()
                .unwrap_or_default(),
            data_continuity: "not-attested-v1".into(),
        })
    }

    /// Advance the persistent continuity anchor after a cryptographically
    /// authorized rebirth reaches verified First Breath. Genesis ancestry is
    /// retained, while the current embodiment/provenance fields move forward.
    pub fn from_verified_reconstitution(
        plan: &ReconstitutionPlan,
        first_breath: &ReconstitutionFirstBreathReceipt,
        continuity: &ContinuityReceipt,
        authority: &AuthorityEvidenceRecord,
    ) -> Result<Self, ReconstitutionError> {
        if first_breath.holon != plan.anchor.holon
            || first_breath.reconstitution_plan_blake3 != plan.digest()
            || !first_breath.is_verified()
            || continuity.holon != plan.anchor.holon
            || continuity.parent_anchor_blake3 != plan.anchor.digest()
            || continuity.reconstitution_plan_blake3 != plan.digest()
            || continuity.first_breath_receipt_blake3 != first_breath.digest()
            || continuity.system_continuity != "verified-v1"
            || plan.authority_policy_blake3.is_empty()
            || authority.kind != "detached-ed25519-authority-v1"
            || authority.subject_blake3 != plan.digest()
            || authority.signer_key_id.is_none()
            || authority
                .claims
                .get("authority_policy_blake3")
                .map(String::as_str)
                != Some(plan.authority_policy_blake3.as_str())
        {
            return Err(ReconstitutionError::InvalidLineage);
        }
        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-continuity-anchor-v1".into(),
            holon: plan.anchor.holon.clone(),
            genesis_plan_blake3: plan.anchor.genesis_plan_blake3.clone(),
            birth_receipt_blake3: plan.anchor.birth_receipt_blake3.clone(),
            first_breath_receipt_blake3: plan.anchor.first_breath_receipt_blake3.clone(),
            parent_continuity_receipt_blake3: continuity.digest(),
            system: plan.target.system.clone(),
            hostname: plan.anchor.hostname.clone(),
            storage_layout: plan.storage_layout.clone(),
            last_disk_by_id: plan.target.primary_disk.by_id.clone(),
            sovereign_bundle_blake3: plan.sovereign_bundle_blake3.clone(),
            flake_lock_blake3: plan.flake_lock_blake3.clone(),
            source_policy_blake3: plan.source_policy_blake3.clone(),
            evaluator_policy_blake3: plan.evaluator_policy_blake3.clone(),
            last_verified_toplevel: first_breath.observed_toplevel.clone(),
            last_machine_id_blake3: first_breath.machine_id_blake3.clone(),
            authority_issuer: authority.issuer.clone(),
            authority_signer_key_id: authority.signer_key_id.clone(),
            authority_policy_blake3: plan.authority_policy_blake3.clone(),
            data_continuity: continuity.data_continuity.clone(),
        })
    }

    pub fn digest(&self) -> String {
        hash_serialized(CONTINUITY_ANCHOR_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FirmwareMode {
    Uefi,
    Bios,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbodimentObservation {
    pub system: String,
    pub primary_disk: StableDiskIdentity,
    pub firmware: FirmwareMode,
    pub tpm2_present: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeClass {
    Preserved,
    ExpectedEmbodimentChange,
    RequiresOwnerReauthorization,
    ForbiddenWithoutMigration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityChange {
    pub field: String,
    pub before: String,
    pub after: String,
    pub class: ChangeClass,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconstitutionPlan {
    pub schema_version: u32,
    pub kind: String,
    pub anchor: ContinuityAnchor,
    pub target: EmbodimentObservation,
    pub storage_plan_blake3: String,
    pub storage_layout: String,
    pub sovereign_bundle_blake3: String,
    pub flake_lock_blake3: String,
    pub source_policy_blake3: String,
    pub evaluator_policy_blake3: String,
    pub preflight_receipt_blake3: String,
    #[serde(default)]
    pub authority_policy_blake3: String,
    pub expected_toplevel: String,
    /// Digest over exact staged candidate source bytes used during preflight.
    #[serde(default)]
    pub candidate_source_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_restore_plan_blake3: Option<String>,
    pub changes: Vec<ContinuityChange>,
    pub owner_reauthorization_required: bool,
    pub data_restore_status: String,
    pub issued_at_ms: u64,
    pub nonce_blake3: String,
}

impl ReconstitutionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        anchor: ContinuityAnchor,
        target: EmbodimentObservation,
        storage_plan: &StoragePlan,
        sovereign_bundle_blake3: impl Into<String>,
        flake_lock_blake3: impl Into<String>,
        source_policy_blake3: impl Into<String>,
        evaluator_policy_blake3: impl Into<String>,
        preflight_receipt_blake3: impl Into<String>,
        expected_toplevel: impl Into<String>,
        candidate_source_blake3: impl Into<String>,
        nonce_entropy: [u8; 32],
    ) -> Result<Self, ReconstitutionError> {
        target
            .primary_disk
            .validate()
            .map_err(|_| ReconstitutionError::InvalidStoragePlan)?;
        if target.system != anchor.system {
            return Err(ReconstitutionError::ArchitectureMigrationRequired);
        }
        let sovereign_bundle_blake3 = sovereign_bundle_blake3.into();
        let flake_lock_blake3 = flake_lock_blake3.into();
        let source_policy_blake3 = source_policy_blake3.into();
        let evaluator_policy_blake3 = evaluator_policy_blake3.into();
        let preflight_receipt_blake3 = preflight_receipt_blake3.into();
        let candidate_source_blake3 = candidate_source_blake3.into();
        for digest in [
            storage_plan.plan_digest_blake3.as_str(),
            sovereign_bundle_blake3.as_str(),
            flake_lock_blake3.as_str(),
            source_policy_blake3.as_str(),
            evaluator_policy_blake3.as_str(),
            preflight_receipt_blake3.as_str(),
            candidate_source_blake3.as_str(),
        ] {
            if !valid_digest(digest) {
                return Err(ReconstitutionError::InvalidDigest);
            }
        }
        let expected_toplevel = expected_toplevel.into();
        if !expected_toplevel.starts_with("/nix/store/") {
            return Err(ReconstitutionError::InvalidToplevel);
        }

        let storage_layout = storage_plan.intent.layout.as_install_layout().to_string();
        let mut changes = Vec::new();
        changes.push(change(
            "holon.identity",
            &anchor.holon.id,
            &anchor.holon.id,
            ChangeClass::Preserved,
            "persistent Holon identity is never regenerated during reconstitution",
        ));
        changes.push(change(
            "embodiment.primary_disk",
            &anchor.last_disk_by_id,
            &target.primary_disk.by_id,
            if anchor.last_disk_by_id == target.primary_disk.by_id {
                ChangeClass::Preserved
            } else {
                ChangeClass::ExpectedEmbodimentChange
            },
            "physical storage may be replaced without changing Holon identity",
        ));
        changes.push(change(
            "storage.layout",
            &anchor.storage_layout,
            &storage_layout,
            if anchor.storage_layout == storage_layout {
                ChangeClass::Preserved
            } else {
                ChangeClass::RequiresOwnerReauthorization
            },
            "changing storage semantics is not inferred from replacement hardware",
        ));
        changes.push(change(
            "source.bundle",
            &anchor.sovereign_bundle_blake3,
            &sovereign_bundle_blake3,
            if anchor.sovereign_bundle_blake3 == sovereign_bundle_blake3 {
                ChangeClass::Preserved
            } else {
                ChangeClass::RequiresOwnerReauthorization
            },
            "source changes during recovery are explicit upgrades, not embodiment drift",
        ));
        changes.push(change(
            "dependency.lock",
            &anchor.flake_lock_blake3,
            &flake_lock_blake3,
            if anchor.flake_lock_blake3 == flake_lock_blake3 {
                ChangeClass::Preserved
            } else {
                ChangeClass::RequiresOwnerReauthorization
            },
            "dependency movement during recovery requires explicit review",
        ));
        changes.push(change(
            "nixos.toplevel",
            &anchor.last_verified_toplevel,
            &expected_toplevel,
            if anchor.last_verified_toplevel == expected_toplevel {
                ChangeClass::Preserved
            } else {
                ChangeClass::ExpectedEmbodimentChange
            },
            "hardware-sensitive closure changes are expected but must be preflighted exactly",
        ));

        let mut nonce = blake3::Hasher::new();
        nonce.update(RECONSTITUTION_PLAN_DOMAIN);
        nonce.update(&nonce_entropy);
        nonce.update(anchor.digest().as_bytes());
        nonce.update(expected_toplevel.as_bytes());
        nonce.update(storage_plan.plan_digest_blake3.as_bytes());

        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-reconstitution-plan-v1".into(),
            anchor: anchor.clone(),
            target,
            storage_plan_blake3: storage_plan.plan_digest_blake3.clone(),
            storage_layout,
            sovereign_bundle_blake3,
            flake_lock_blake3,
            source_policy_blake3,
            evaluator_policy_blake3,
            preflight_receipt_blake3,
            authority_policy_blake3: anchor.authority_policy_blake3.clone(),
            expected_toplevel,
            candidate_source_blake3,
            data_restore_plan_blake3: None,
            changes,
            // Reconstitution is destructive and identity-bearing even when all
            // source bytes are unchanged. Never infer consent from sameness.
            owner_reauthorization_required: true,
            data_restore_status: "not-attested-v1".into(),
            issued_at_ms: now_ms(),
            nonce_blake3: nonce.finalize().to_hex().to_string(),
        })
    }

    pub fn bind_data_restore(
        mut self,
        restore: &DataRestorePlan,
    ) -> Result<Self, ReconstitutionError> {
        restore
            .validate()
            .map_err(|_| ReconstitutionError::DataRestoreMismatch)?;
        if restore.holon != self.anchor.holon {
            return Err(ReconstitutionError::DataRestoreMismatch);
        }
        self.data_restore_plan_blake3 = Some(restore.digest());
        self.data_restore_status = "planned-v1".into();
        Ok(self)
    }

    pub fn digest(&self) -> String {
        hash_serialized(RECONSTITUTION_PLAN_DOMAIN, self)
    }

    pub fn has_forbidden_changes(&self) -> bool {
        self.changes
            .iter()
            .any(|c| c.class == ChangeClass::ForbiddenWithoutMigration)
    }
}

/// Destructive reconstitution capability. A plain [`ReconstitutionPlan`] is
/// deliberately review-only; mutation sinks should require this wrapper.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthorizedReconstitutionPlan {
    pub schema_version: u32,
    pub kind: String,
    pub plan: ReconstitutionPlan,
    pub authority: AuthorityEvidenceRecord,
}

impl AuthorizedReconstitutionPlan {
    pub fn authorize(
        plan: ReconstitutionPlan,
        authority: &VerifiedAuthorityEvidence,
    ) -> Result<Self, ReconstitutionError> {
        if authority.record().subject_blake3 != plan.digest() {
            return Err(ReconstitutionError::AuthorityMismatch);
        }
        if plan.authority_policy_blake3.is_empty()
            || authority
                .record()
                .claims
                .get("authority_policy_blake3")
                .map(String::as_str)
                != Some(plan.authority_policy_blake3.as_str())
        {
            return Err(ReconstitutionError::AuthorityMismatch);
        }
        if authority
            .record()
            .claims
            .get("authority_action")
            .map(String::as_str)
            != Some("reconstitute")
        {
            return Err(ReconstitutionError::AuthorityMismatch);
        }
        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-authorized-reconstitution-plan-v1".into(),
            plan,
            authority: authority.record().clone(),
        })
    }

    pub fn digest(&self) -> String {
        hash_serialized(b"symthaea-authorized-reconstitution-v1\0", self)
    }
}

fn change(
    field: &str,
    before: &str,
    after: &str,
    class: ChangeClass,
    explanation: &str,
) -> ContinuityChange {
    ContinuityChange {
        field: field.into(),
        before: before.into(),
        after: after.into(),
        class,
        explanation: explanation.into(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReconstitutionFirstBreathStatus {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconstitutionFirstBreathReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub reconstitution_plan_blake3: String,
    pub expected_toplevel: String,
    pub observed_toplevel: String,
    pub machine_id_blake3: String,
    pub status: ReconstitutionFirstBreathStatus,
    pub diagnostics: Vec<String>,
    pub verified_at_ms: u64,
}

impl ReconstitutionFirstBreathReceipt {
    pub fn verify(
        plan: &ReconstitutionPlan,
        observed_toplevel: impl Into<String>,
        machine_id_blake3: impl Into<String>,
    ) -> Result<Self, ReconstitutionError> {
        let observed_toplevel = observed_toplevel.into();
        let machine_id_blake3 = machine_id_blake3.into();
        if !valid_digest(&machine_id_blake3) {
            return Err(ReconstitutionError::InvalidDigest);
        }
        let mut diagnostics = Vec::new();
        let status = if observed_toplevel == plan.expected_toplevel {
            ReconstitutionFirstBreathStatus::Verified
        } else {
            diagnostics.push(format!(
                "authorized reconstitution toplevel {} but observed {}",
                plan.expected_toplevel, observed_toplevel
            ));
            ReconstitutionFirstBreathStatus::Rejected
        };
        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-reconstitution-first-breath-v1".into(),
            holon: plan.anchor.holon.clone(),
            reconstitution_plan_blake3: plan.digest(),
            expected_toplevel: plan.expected_toplevel.clone(),
            observed_toplevel,
            machine_id_blake3,
            status,
            diagnostics,
            verified_at_ms: now_ms(),
        })
    }

    pub fn is_verified(&self) -> bool {
        self.status == ReconstitutionFirstBreathStatus::Verified
    }

    pub fn digest(&self) -> String {
        hash_serialized(b"symthaea-reconstitution-first-breath-v1\0", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub parent_anchor_blake3: String,
    pub reconstitution_plan_blake3: String,
    pub first_breath_receipt_blake3: String,
    pub system_continuity: String,
    pub data_continuity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_continuity_receipt_blake3: Option<String>,
    pub completed_at_ms: u64,
}

impl ContinuityReceipt {
    pub fn new(
        plan: &ReconstitutionPlan,
        first_breath: &ReconstitutionFirstBreathReceipt,
    ) -> Result<Self, ReconstitutionError> {
        Self::new_with_data(plan, first_breath, None)
    }

    pub fn new_with_data(
        plan: &ReconstitutionPlan,
        first_breath: &ReconstitutionFirstBreathReceipt,
        data: Option<&DataContinuityReceipt>,
    ) -> Result<Self, ReconstitutionError> {
        if first_breath.holon != plan.anchor.holon
            || first_breath.reconstitution_plan_blake3 != plan.digest()
            || !first_breath.is_verified()
        {
            return Err(ReconstitutionError::IdentityMismatch);
        }
        if first_breath.observed_toplevel.as_str() != plan.expected_toplevel.as_str() {
            return Err(ReconstitutionError::IdentityMismatch);
        }
        let (data_continuity, data_continuity_receipt_blake3) =
            match (&plan.data_restore_plan_blake3, data) {
                (None, None) => ("not-attested-v1".into(), None),
                (Some(_), None) => ("planned-not-verified-v1".into(), None),
                (Some(expected), Some(receipt))
                    if receipt.restore_plan_blake3 == *expected
                        && receipt.holon == plan.anchor.holon
                        && receipt.is_verified() =>
                {
                    ("verified-v1".into(), Some(receipt.digest()))
                }
                _ => return Err(ReconstitutionError::DataRestoreMismatch),
            };
        Ok(Self {
            schema_version: RECONSTITUTION_SCHEMA_VERSION,
            kind: "symthaea-continuity-receipt-v1".into(),
            holon: plan.anchor.holon.clone(),
            parent_anchor_blake3: plan.anchor.digest(),
            reconstitution_plan_blake3: plan.digest(),
            first_breath_receipt_blake3: first_breath.digest(),
            system_continuity: "verified-v1".into(),
            data_continuity,
            data_continuity_receipt_blake3,
            completed_at_ms: now_ms(),
        })
    }

    pub fn digest(&self) -> String {
        hash_serialized(CONTINUITY_RECEIPT_DOMAIN, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis_covenant::{
        GenesisInputs, GenesisIntent, GenesisPlan, GenesisSecurityIntent, VerifiedAuthorityEvidence,
    };
    use crate::storage_intent::{StorageIntent, StorageLayout};
    use std::collections::BTreeMap;

    fn lineage() -> (GenesisPlan, BirthReceipt, FirstBreathReceipt) {
        let inputs = GenesisInputs {
            hostname: "guardian".into(),
            system: "x86_64-linux".into(),
            sovereign_bundle_blake3: "01".repeat(32),
            flake_lock_blake3: "02".repeat(32),
            storage_plan_blake3: "03".repeat(32),
            storage_layout: "single".into(),
            source_policy_blake3: "04".repeat(32),
            evaluator_policy_blake3: "05".repeat(32),
            preflight_receipt_blake3: "06".repeat(32),
            expected_toplevel: "/nix/store/aaaaaaaa-system".into(),
            target_disk_by_id: "/dev/disk/by-id/old-disk".into(),
            security: GenesisSecurityIntent {
                secure_boot_requested: false,
                tpm2_unlock_requested: false,
                fido2_unlock_requested: false,
            },
        };
        let intent =
            GenesisIntent::new(HolonIdentity::from_entropy([1; 32]), inputs, [2; 32]).unwrap();
        let authority = VerifiedAuthorityEvidence::from_external_verifier(
            "test",
            "owner",
            "verifier",
            "11".repeat(32),
            intent.digest(),
            None,
            BTreeMap::from([("authority_policy_blake3".into(), "19".repeat(32))]),
            true,
        )
        .unwrap();
        let plan = GenesisPlan::authorize(intent, &authority).unwrap();
        let birth = BirthReceipt::new(
            &plan,
            plan.inputs().expected_toplevel.clone(),
            "aa".repeat(32),
            "bb".repeat(32),
            plan.inputs().flake_lock_blake3.clone(),
        )
        .unwrap();
        let first = FirstBreathReceipt::verify(
            &plan,
            &birth,
            plan.inputs().expected_toplevel.clone(),
            "cc".repeat(32),
            None,
            false,
            None,
        )
        .unwrap();
        (plan, birth, first)
    }

    fn replacement_disk() -> StableDiskIdentity {
        StableDiskIdentity {
            by_id: "/dev/disk/by-id/new-disk".into(),
            model: "replacement".into(),
            serial: "new".into(),
            wwn: "wwn-new".into(),
            size: "2T".into(),
        }
    }

    #[test]
    fn anchor_preserves_holon_not_machine() {
        let (plan, birth, first) = lineage();
        let anchor = ContinuityAnchor::from_verified_lineage(&plan, &birth, &first).unwrap();
        assert_eq!(&anchor.holon, plan.holon());
        assert_ne!(anchor.holon.id, anchor.last_machine_id_blake3);
        assert_eq!(anchor.data_continuity, "not-attested-v1");
    }

    #[test]
    fn replacement_first_breath_is_bound_to_reconstitution_not_genesis() {
        let (genesis, birth, first) = lineage();
        let anchor = ContinuityAnchor::from_verified_lineage(&genesis, &birth, &first).unwrap();
        let storage = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: replacement_disk(),
        }
        .into_plan()
        .unwrap();
        let plan = ReconstitutionPlan::new(
            anchor,
            EmbodimentObservation {
                system: "x86_64-linux".into(),
                primary_disk: replacement_disk(),
                firmware: FirmwareMode::Uefi,
                tpm2_present: true,
            },
            &storage,
            "99".repeat(32),
            "02".repeat(32),
            "04".repeat(32),
            "05".repeat(32),
            "06".repeat(32),
            "/nix/store/bbbbbbbb-system",
            "77".repeat(32),
            [8; 32],
        )
        .unwrap();
        let breath = ReconstitutionFirstBreathReceipt::verify(
            &plan,
            "/nix/store/bbbbbbbb-system",
            "88".repeat(32),
        )
        .unwrap();
        assert!(breath.is_verified());
        assert_eq!(breath.reconstitution_plan_blake3, plan.digest());
    }

    #[test]
    fn verified_rebirth_advances_current_continuity_anchor() {
        let (genesis, birth, first) = lineage();
        let anchor = ContinuityAnchor::from_verified_lineage(&genesis, &birth, &first).unwrap();
        let original_anchor_digest = anchor.digest();
        let storage = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: replacement_disk(),
        }
        .into_plan()
        .unwrap();
        let plan = ReconstitutionPlan::new(
            anchor,
            EmbodimentObservation {
                system: "x86_64-linux".into(),
                primary_disk: replacement_disk(),
                firmware: FirmwareMode::Uefi,
                tpm2_present: true,
            },
            &storage,
            "99".repeat(32),
            "12".repeat(32),
            "13".repeat(32),
            "14".repeat(32),
            "15".repeat(32),
            "/nix/store/bbbbbbbb-system",
            "16".repeat(32),
            [10; 32],
        )
        .unwrap();
        let breath = ReconstitutionFirstBreathReceipt::verify(
            &plan,
            "/nix/store/bbbbbbbb-system",
            "17".repeat(32),
        )
        .unwrap();
        let continuity = ContinuityReceipt::new(&plan, &breath).unwrap();
        let authority = AuthorityEvidenceRecord {
            kind: "detached-ed25519-authority-v1".into(),
            issuer: "owner".into(),
            verifier: "nixward-ed25519-verifier-v1".into(),
            evidence_blake3: "18".repeat(32),
            subject_blake3: plan.digest(),
            signer_key_id: Some("owner-root".into()),
            claims: BTreeMap::from([(
                "authority_policy_blake3".into(),
                plan.authority_policy_blake3.clone(),
            )]),
        };
        let advanced =
            ContinuityAnchor::from_verified_reconstitution(&plan, &breath, &continuity, &authority)
                .unwrap();
        assert_eq!(advanced.holon, plan.anchor.holon);
        assert_eq!(
            advanced.parent_continuity_receipt_blake3,
            continuity.digest()
        );
        assert_eq!(advanced.last_disk_by_id, "/dev/disk/by-id/new-disk");
        assert_eq!(
            advanced.last_verified_toplevel,
            "/nix/store/bbbbbbbb-system"
        );
        assert_ne!(advanced.digest(), original_anchor_digest);
    }

    #[test]
    fn replacement_disk_is_expected_but_source_drift_requires_reauth() {
        let (plan, birth, first) = lineage();
        let anchor = ContinuityAnchor::from_verified_lineage(&plan, &birth, &first).unwrap();
        let storage = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: replacement_disk(),
        }
        .into_plan()
        .unwrap();
        let plan = ReconstitutionPlan::new(
            anchor,
            EmbodimentObservation {
                system: "x86_64-linux".into(),
                primary_disk: replacement_disk(),
                firmware: FirmwareMode::Uefi,
                tpm2_present: true,
            },
            &storage,
            "99".repeat(32),
            "02".repeat(32),
            "04".repeat(32),
            "05".repeat(32),
            "06".repeat(32),
            "/nix/store/bbbbbbbb-system",
            "77".repeat(32),
            [9; 32],
        )
        .unwrap();
        assert!(plan.changes.iter().any(|c| {
            c.field == "embodiment.primary_disk" && c.class == ChangeClass::ExpectedEmbodimentChange
        }));
        assert!(plan.changes.iter().any(|c| {
            c.field == "source.bundle" && c.class == ChangeClass::RequiresOwnerReauthorization
        }));
        assert!(plan.owner_reauthorization_required);
    }
}

/// Machine-readable policy shipped with every sovereign bundle so both Spore
/// and future Xenia/Mycelix tooling agree on what "same Holon" means.
pub fn continuity_policy_json() -> String {
    let policy = serde_json::json!({
        "schema_version": RECONSTITUTION_SCHEMA_VERSION,
        "kind": "symthaea-continuity-policy-v1",
        "persistent_identity": "holon-id",
        "system_continuity": "genesis-lineage-plus-exact-first-breath",
        "data_continuity": "separate-attestation-required",
        "expected_embodiment_changes": [
            "physical-disk-identity",
            "machine-id",
            "hardware-sensitive-toplevel"
        ],
        "owner_reauthorization_required": [
            "every-destructive-reconstitution",
            "storage-layout-change",
            "source-bundle-change",
            "flake-lock-change"
        ],
        "migration_required": [
            "architecture-change",
            "unknown-future-continuity-schema"
        ],
        "never_infer": [
            "data-restored-from-system-rebuild",
            "owner-consent-from-byte-equality",
            "identity-from-disk-or-motherboard"
        ]
    });
    serde_json::to_string_pretty(&policy)
        .map(|json| json + "\n")
        .unwrap_or_else(|_| {
            "{\"schema_version\":1,\"error\":\"continuity policy serialization failed\"}\n".into()
        })
}
