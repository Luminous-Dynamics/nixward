// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Genesis Covenant — evidence-bound birth plans and first-boot receipts.
//!
//! V29 distinguishes three states that conventional installers often collapse:
//! 1. [`GenesisPlan`] — the exact birth that was proposed and authorized.
//! 2. [`BirthReceipt`] — the storage/system realization completed successfully.
//! 3. [`FirstBreathReceipt`] — the newly booted Holon is actually running the
//!    exact toplevel authorized by the GenesisPlan.
//!
//! Authority is deliberately not inferred from cognition, a browser payload, or
//! an unsigned JSON field.  The constructor consumes [`VerifiedAuthorityEvidence`],
//! a non-deserializable capability that may only be minted by a trusted verifier
//! after it has validated the owner/Mycelix/Xenia/local-session evidence.

use crate::authority_signature::VerifiedSignatureEvidence;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const GENESIS_SCHEMA_VERSION: u32 = 1;
pub const GENESIS_KIND: &str = "symthaea-genesis-plan-v1";
pub const BIRTH_RECEIPT_KIND: &str = "symthaea-birth-receipt-v1";
pub const FIRST_BREATH_KIND: &str = "symthaea-first-breath-receipt-v1";

const GENESIS_INTENT_DOMAIN: &[u8] = b"symthaea-genesis-intent-v1\0";
const GENESIS_PLAN_DOMAIN: &[u8] = b"symthaea-genesis-plan-v1\0";
const BIRTH_RECEIPT_DOMAIN: &[u8] = b"symthaea-birth-receipt-v1\0";
const FIRST_BREATH_DOMAIN: &[u8] = b"symthaea-first-breath-v1\0";
const HOLON_ID_DOMAIN: &[u8] = b"symthaea-holon-identity-v1\0";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("genesis evidence serialization is infallible");
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    hasher.finalize().to_hex().to_string()
}

fn valid_blake3_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_digest(label: &str, value: &str) -> Result<(), GenesisError> {
    if valid_blake3_hex(value) {
        Ok(())
    } else {
        Err(GenesisError::InvalidDigest(label.to_string()))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GenesisError {
    #[error("invalid BLAKE3 digest for {0}")]
    InvalidDigest(String),
    #[error("invalid Holon identity")]
    InvalidHolonIdentity,
    #[error("expected NixOS toplevel must be an absolute /nix/store path")]
    InvalidToplevel,
    #[error("target disk must use a stable /dev/disk/by-id identity")]
    InvalidTargetDisk,
    #[error("authority evidence was not verified")]
    UnverifiedAuthority,
    #[error("genesis evidence is bound to a different plan")]
    PlanMismatch,
    #[error("birth receipt is bound to a different Holon")]
    HolonMismatch,
    #[error("first breath is not running the authorized NixOS toplevel")]
    ToplevelMismatch,
}

/// Persistent identity of the Holon, independent of any one motherboard/disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct HolonIdentity {
    pub id: String,
}

impl HolonIdentity {
    /// Derive a stable public identity from 32 bytes supplied by the trusted
    /// host's cryptographic entropy source. The entropy itself is not stored.
    pub fn from_entropy(entropy: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(HOLON_ID_DOMAIN);
        hasher.update(&entropy);
        Self {
            id: hasher.finalize().to_hex().to_string(),
        }
    }

    pub fn parse(id: impl Into<String>) -> Result<Self, GenesisError> {
        let id = id.into();
        if valid_blake3_hex(&id) {
            Ok(Self { id })
        } else {
            Err(GenesisError::InvalidHolonIdentity)
        }
    }
}

/// Serializable record of authority verification. This is evidence, not a
/// capability: deserializing it later does not grant permission to mutate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityEvidenceRecord {
    pub kind: String,
    pub issuer: String,
    pub verifier: String,
    pub evidence_blake3: String,
    /// Digest of the exact pre-authorization GenesisIntent that was verified.
    pub subject_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

/// Non-deserializable authority capability accepted by GenesisPlan creation.
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityEvidence {
    record: AuthorityEvidenceRecord,
}

impl VerifiedAuthorityEvidence {
    /// Convert the result of Nixward's cryptographic detached-signature
    /// verifier into the non-deserializable Genesis authority capability.
    pub fn from_verified_signature(
        verified: &VerifiedSignatureEvidence,
    ) -> Result<Self, GenesisError> {
        validate_digest("authority evidence", &verified.evidence_blake3)?;
        validate_digest("authority subject", &verified.subject_blake3)?;
        let mut claims = verified.claims.clone();
        claims.insert("challenge_blake3".into(), verified.challenge_blake3.clone());
        claims.insert("replay_key".into(), verified.replay_key.clone());
        Ok(Self {
            record: AuthorityEvidenceRecord {
                kind: "detached-ed25519-authority-v1".into(),
                issuer: verified.issuer.clone(),
                verifier: "nixward-ed25519-verifier-v1".into(),
                evidence_blake3: verified.evidence_blake3.clone(),
                subject_blake3: verified.subject_blake3.clone(),
                signer_key_id: Some(verified.signer_key_id.clone()),
                claims,
            },
        })
    }

    /// Construct only after a trusted boundary has verified the underlying
    /// authorization evidence. This method deliberately requires an explicit
    /// `verified` bit from that boundary and rejects zero/placeholder digests.
    #[deprecated(
        note = "V31: prefer AuthorityVerifier + from_verified_signature; boolean verification is compatibility-only"
    )]
    pub fn from_external_verifier(
        kind: impl Into<String>,
        issuer: impl Into<String>,
        verifier: impl Into<String>,
        evidence_blake3: impl Into<String>,
        subject_blake3: impl Into<String>,
        signer_key_id: Option<String>,
        claims: BTreeMap<String, String>,
        verified: bool,
    ) -> Result<Self, GenesisError> {
        if !verified {
            return Err(GenesisError::UnverifiedAuthority);
        }
        let evidence_blake3 = evidence_blake3.into();
        validate_digest("authority evidence", &evidence_blake3)?;
        let subject_blake3 = subject_blake3.into();
        validate_digest("authority subject", &subject_blake3)?;
        let issuer = issuer.into();
        let verifier = verifier.into();
        if issuer.trim().is_empty() || verifier.trim().is_empty() {
            return Err(GenesisError::UnverifiedAuthority);
        }
        Ok(Self {
            record: AuthorityEvidenceRecord {
                kind: kind.into(),
                issuer,
                verifier,
                evidence_blake3,
                subject_blake3,
                signer_key_id,
                claims,
            },
        })
    }

    pub fn record(&self) -> &AuthorityEvidenceRecord {
        &self.record
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisSecurityIntent {
    pub secure_boot_requested: bool,
    pub tpm2_unlock_requested: bool,
    pub fido2_unlock_requested: bool,
}

/// Exact immutable inputs whose combination constitutes the proposed birth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisInputs {
    pub hostname: String,
    pub system: String,
    pub sovereign_bundle_blake3: String,
    pub flake_lock_blake3: String,
    pub storage_plan_blake3: String,
    #[serde(default)]
    pub storage_layout: String,
    pub source_policy_blake3: String,
    pub evaluator_policy_blake3: String,
    pub preflight_receipt_blake3: String,
    pub expected_toplevel: String,
    pub target_disk_by_id: String,
    pub security: GenesisSecurityIntent,
}

impl GenesisInputs {
    pub fn validate(&self) -> Result<(), GenesisError> {
        for (label, digest) in [
            ("sovereign bundle", self.sovereign_bundle_blake3.as_str()),
            ("flake.lock", self.flake_lock_blake3.as_str()),
            ("storage plan", self.storage_plan_blake3.as_str()),
            ("source policy", self.source_policy_blake3.as_str()),
            ("evaluator policy", self.evaluator_policy_blake3.as_str()),
            ("preflight receipt", self.preflight_receipt_blake3.as_str()),
        ] {
            validate_digest(label, digest)?;
        }
        if !self.expected_toplevel.starts_with("/nix/store/") {
            return Err(GenesisError::InvalidToplevel);
        }
        if !self.target_disk_by_id.starts_with("/dev/disk/by-id/") {
            return Err(GenesisError::InvalidTargetDisk);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisIntent {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub inputs: GenesisInputs,
    pub issued_at_ms: u64,
    pub nonce_blake3: String,
}

impl GenesisIntent {
    pub fn new(
        holon: HolonIdentity,
        inputs: GenesisInputs,
        nonce_entropy: [u8; 32],
    ) -> Result<Self, GenesisError> {
        inputs.validate()?;
        let mut nonce = blake3::Hasher::new();
        nonce.update(GENESIS_INTENT_DOMAIN);
        nonce.update(&nonce_entropy);
        nonce.update(holon.id.as_bytes());
        nonce.update(inputs.preflight_receipt_blake3.as_bytes());
        Ok(Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            kind: "symthaea-genesis-intent-v1".into(),
            holon,
            inputs,
            issued_at_ms: now_ms(),
            nonce_blake3: nonce.finalize().to_hex().to_string(),
        })
    }

    pub fn digest(&self) -> String {
        hash_serialized(GENESIS_INTENT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisPlan {
    pub schema_version: u32,
    pub kind: String,
    pub intent: GenesisIntent,
    pub authority: AuthorityEvidenceRecord,
}

impl GenesisPlan {
    pub fn authorize(
        intent: GenesisIntent,
        authority: &VerifiedAuthorityEvidence,
    ) -> Result<Self, GenesisError> {
        if authority.record.subject_blake3 != intent.digest() {
            return Err(GenesisError::PlanMismatch);
        }
        Ok(Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            kind: GENESIS_KIND.into(),
            intent,
            authority: authority.record.clone(),
        })
    }

    pub fn holon(&self) -> &HolonIdentity {
        &self.intent.holon
    }

    pub fn inputs(&self) -> &GenesisInputs {
        &self.intent.inputs
    }

    pub fn digest(&self) -> String {
        hash_serialized(GENESIS_PLAN_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BirthStatus {
    InstalledAwaitingFirstBreath,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BirthReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub genesis_plan_blake3: String,
    pub installed_toplevel: String,
    pub storage_realization_blake3: String,
    pub hardware_configuration_blake3: String,
    pub installed_flake_lock_blake3: String,
    pub status: BirthStatus,
    pub completed_at_ms: u64,
}

impl BirthReceipt {
    pub fn new(
        plan: &GenesisPlan,
        installed_toplevel: impl Into<String>,
        storage_realization_blake3: impl Into<String>,
        hardware_configuration_blake3: impl Into<String>,
        installed_flake_lock_blake3: impl Into<String>,
    ) -> Result<Self, GenesisError> {
        let installed_toplevel = installed_toplevel.into();
        if installed_toplevel != plan.inputs().expected_toplevel.as_str() {
            return Err(GenesisError::ToplevelMismatch);
        }
        let storage_realization_blake3 = storage_realization_blake3.into();
        let hardware_configuration_blake3 = hardware_configuration_blake3.into();
        let installed_flake_lock_blake3 = installed_flake_lock_blake3.into();
        validate_digest("storage realization", &storage_realization_blake3)?;
        validate_digest("hardware configuration", &hardware_configuration_blake3)?;
        validate_digest("installed flake.lock", &installed_flake_lock_blake3)?;
        if installed_flake_lock_blake3 != plan.inputs().flake_lock_blake3.as_str() {
            return Err(GenesisError::PlanMismatch);
        }
        Ok(Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            kind: BIRTH_RECEIPT_KIND.into(),
            holon: plan.holon().clone(),
            genesis_plan_blake3: plan.digest(),
            installed_toplevel,
            storage_realization_blake3,
            hardware_configuration_blake3,
            installed_flake_lock_blake3,
            status: BirthStatus::InstalledAwaitingFirstBreath,
            completed_at_ms: now_ms(),
        })
    }

    pub fn digest(&self) -> String {
        hash_serialized(BIRTH_RECEIPT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FirstBreathStatus {
    Verified,
    VerifiedWithWarnings,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirstBreathReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub genesis_plan_blake3: String,
    pub birth_receipt_blake3: String,
    pub expected_toplevel: String,
    pub observed_toplevel: String,
    pub machine_id_blake3: String,
    pub secure_boot_observed: Option<bool>,
    pub tpm2_observed: bool,
    pub fido2_enrollment_observed: Option<bool>,
    pub status: FirstBreathStatus,
    pub diagnostics: Vec<String>,
    pub verified_at_ms: u64,
}

impl FirstBreathReceipt {
    pub fn verify(
        plan: &GenesisPlan,
        birth: &BirthReceipt,
        observed_toplevel: impl Into<String>,
        machine_id_blake3: impl Into<String>,
        secure_boot_observed: Option<bool>,
        tpm2_observed: bool,
        fido2_enrollment_observed: Option<bool>,
    ) -> Result<Self, GenesisError> {
        if birth.genesis_plan_blake3 != plan.digest() {
            return Err(GenesisError::PlanMismatch);
        }
        if &birth.holon != plan.holon() {
            return Err(GenesisError::HolonMismatch);
        }
        let machine_id_blake3 = machine_id_blake3.into();
        validate_digest("machine-id", &machine_id_blake3)?;
        let observed_toplevel = observed_toplevel.into();
        let mut diagnostics = Vec::new();
        let toplevel_matches = observed_toplevel == plan.inputs().expected_toplevel.as_str()
            && observed_toplevel == birth.installed_toplevel.as_str();
        if !toplevel_matches {
            diagnostics.push(format!(
                "authorized toplevel {} but observed {}",
                plan.inputs().expected_toplevel,
                observed_toplevel
            ));
        }
        let secure_boot_ok = if plan.inputs().security.secure_boot_requested {
            match secure_boot_observed {
                Some(true) => true,
                Some(false) => {
                    diagnostics.push("Secure Boot was requested but is observed disabled".into());
                    false
                }
                None => {
                    diagnostics.push(
                        "Secure Boot was requested but its state could not be attested".into(),
                    );
                    true
                }
            }
        } else {
            true
        };
        let tpm_ok = if plan.inputs().security.tpm2_unlock_requested && !tpm2_observed {
            diagnostics.push("TPM2 unlock was requested but no TPM2 device is observed".into());
            false
        } else {
            true
        };
        if plan.inputs().security.fido2_unlock_requested && fido2_enrollment_observed != Some(true)
        {
            diagnostics.push(
                "FIDO2 unlock was requested but enrollment is not independently attested".into(),
            );
        }
        let status = if !toplevel_matches || !secure_boot_ok || !tpm_ok {
            FirstBreathStatus::Rejected
        } else if diagnostics.is_empty() {
            FirstBreathStatus::Verified
        } else {
            FirstBreathStatus::VerifiedWithWarnings
        };
        Ok(Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            kind: FIRST_BREATH_KIND.into(),
            holon: plan.holon().clone(),
            genesis_plan_blake3: plan.digest(),
            birth_receipt_blake3: birth.digest(),
            expected_toplevel: plan.inputs().expected_toplevel.clone(),
            observed_toplevel,
            machine_id_blake3,
            secure_boot_observed,
            tpm2_observed,
            fido2_enrollment_observed,
            status,
            diagnostics,
            verified_at_ms: now_ms(),
        })
    }

    pub fn is_verified(&self) -> bool {
        matches!(
            self.status,
            FirstBreathStatus::Verified | FirstBreathStatus::VerifiedWithWarnings
        )
    }

    pub fn digest(&self) -> String {
        hash_serialized(FIRST_BREATH_DOMAIN, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> GenesisInputs {
        GenesisInputs {
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
            target_disk_by_id: "/dev/disk/by-id/test-disk".into(),
            security: GenesisSecurityIntent {
                secure_boot_requested: true,
                tpm2_unlock_requested: true,
                fido2_unlock_requested: false,
            },
        }
    }

    fn authorized_plan(seed: u8) -> GenesisPlan {
        let intent = GenesisIntent::new(
            HolonIdentity::from_entropy([seed; 32]),
            inputs(),
            [seed.wrapping_add(1); 32],
        )
        .unwrap();
        let authority = VerifiedAuthorityEvidence::from_external_verifier(
            "local-owner-session-v1",
            "owner",
            "test-verifier",
            "11".repeat(32),
            intent.digest(),
            None,
            BTreeMap::new(),
            true,
        )
        .unwrap();
        GenesisPlan::authorize(intent, &authority).unwrap()
    }

    #[test]
    fn authority_is_bound_to_pre_authorization_intent() {
        let first =
            GenesisIntent::new(HolonIdentity::from_entropy([7; 32]), inputs(), [8; 32]).unwrap();
        let second =
            GenesisIntent::new(HolonIdentity::from_entropy([7; 32]), inputs(), [9; 32]).unwrap();
        let authority = VerifiedAuthorityEvidence::from_external_verifier(
            "test",
            "owner",
            "verifier",
            "12".repeat(32),
            first.digest(),
            None,
            BTreeMap::new(),
            true,
        )
        .unwrap();
        assert!(GenesisPlan::authorize(first, &authority).is_ok());
        assert!(GenesisPlan::authorize(second, &authority).is_err());
    }

    #[test]
    fn birth_rejects_different_realization() {
        let plan = authorized_plan(1);
        assert!(
            BirthReceipt::new(
                &plan,
                "/nix/store/not-authorized-system",
                "aa".repeat(32),
                "bb".repeat(32),
                plan.inputs().flake_lock_blake3.clone(),
            )
            .is_err()
        );
    }

    #[test]
    fn first_breath_requires_exact_authorized_toplevel() {
        let plan = authorized_plan(3);
        let birth = BirthReceipt::new(
            &plan,
            plan.inputs().expected_toplevel.clone(),
            "aa".repeat(32),
            "bb".repeat(32),
            plan.inputs().flake_lock_blake3.clone(),
        )
        .unwrap();
        let receipt = FirstBreathReceipt::verify(
            &plan,
            &birth,
            plan.inputs().expected_toplevel.clone(),
            "cc".repeat(32),
            Some(true),
            true,
            Some(true),
        )
        .unwrap();
        assert!(receipt.is_verified());
    }
}
