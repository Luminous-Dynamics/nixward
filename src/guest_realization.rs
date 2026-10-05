// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Sovereign guest realization evidence.
//!
//! V36 defined guest *intent* without claiming a runtime had actually realized
//! it. V37 adds the evidence boundary between a typed S2/S3 plan and observed
//! external guest state. This module is WASM-safe on purpose: planning and
//! receipt verification do not require process execution or ambient host state.
//!
//! A receipt never upgrades an S3 capsule into a reproducible claim. S2
//! receipts prove artifact identity plus the authority envelope the trusted
//! backend enforced/observed. The NixOS host closure remains a separate domain.

use crate::software_ingress::{
    ContentDigest, EphemeralCapsulePlan, FlatpakGuestPlan, OciGuestPlan, SoftwareIngressError,
    SoftwareIngressPlan, SoftwareIngressSpec, SoftwareTrustClass,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const INTENT_DOMAIN: &[u8] = b"symthaea:nixward:guest-realization-intent:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"symthaea:nixward:guest-realization-receipt:v1\0";
const MANIFEST_DOMAIN: &[u8] = b"symthaea:nixward:guest-realization-manifest:v1\0";
const OCI_MOUNTS_DOMAIN: &[u8] = b"symthaea:nixward:oci-mounts:v1\0";

pub const GUEST_REALIZATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRealizationIntent {
    pub schema_version: u32,
    pub kind: String,
    pub holon_id: String,
    pub plan: SoftwareIngressPlan,
    /// Exact declarative guest-state identity bound into the Holon source.
    pub declared_guest_state_blake3: String,
    /// Exact runtime realization ledger observed when the owner reviewed this
    /// change. Any other guest mutation makes this authorization stale.
    pub prior_realization_blake3: String,
    pub nonce_blake3: String,
}

impl GuestRealizationIntent {
    pub fn new(
        holon_id: impl Into<String>,
        plan: SoftwareIngressPlan,
        declared_guest_state_blake3: impl Into<String>,
        prior_realization_blake3: impl Into<String>,
        nonce_entropy: [u8; 32],
    ) -> Result<Self, GuestRealizationError> {
        plan.validate()?;
        if !matches!(
            plan.trust_class(),
            SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
        ) {
            return Err(GuestRealizationError::NotGuestState);
        }
        let holon_id = holon_id.into();
        let declared_guest_state_blake3 = declared_guest_state_blake3.into();
        let prior_realization_blake3 = prior_realization_blake3.into();
        validate_digest(&holon_id)?;
        validate_digest(&declared_guest_state_blake3)?;
        validate_digest(&prior_realization_blake3)?;
        let mut nonce = blake3::Hasher::new();
        nonce.update(INTENT_DOMAIN);
        nonce.update(&nonce_entropy);
        nonce.update(holon_id.as_bytes());
        nonce.update(plan.digest_hex()?.as_bytes());
        nonce.update(declared_guest_state_blake3.as_bytes());
        nonce.update(prior_realization_blake3.as_bytes());
        Ok(Self {
            schema_version: GUEST_REALIZATION_SCHEMA_VERSION,
            kind: "symthaea-guest-realization-intent-v1".into(),
            holon_id,
            plan,
            declared_guest_state_blake3,
            prior_realization_blake3,
            nonce_blake3: nonce.finalize().to_hex().to_string(),
        })
    }

    pub fn digest_hex(&self) -> Result<String, GuestRealizationError> {
        if self.schema_version != GUEST_REALIZATION_SCHEMA_VERSION
            || self.kind != "symthaea-guest-realization-intent-v1"
        {
            return Err(GuestRealizationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.holon_id)?;
        validate_digest(&self.declared_guest_state_blake3)?;
        validate_digest(&self.prior_realization_blake3)?;
        validate_digest(&self.nonce_blake3)?;
        self.plan.validate()?;
        hash_json(INTENT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum GuestBackend {
    FlatpakUser,
    RootlessPodman,
    BubblewrapCapsule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestAssurance {
    /// Exact external artifact/runtime identity was verified and the exact
    /// launch/sandbox contract is cryptographically bound into the receipt.
    /// This does not claim the application has already run under that contract.
    PinnedArtifactAndLaunchContract,
    /// S3 is intentionally not reproducible; this means only that the observed
    /// capsule ran under the exact bounded policy and source digest requested.
    EphemeralObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakObservation {
    pub app_id: String,
    pub remote: String,
    pub branch: String,
    pub installed_commit: String,
    /// Full runtime ref -> exact installed OSTree commit.
    pub runtime_commits: BTreeMap<String, String>,
    /// Digest of the exact launcher permission contract bound to this realized artifact.
    pub launch_contract_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciObservation {
    pub image: String,
    pub image_digest: String,
    pub rootless: bool,
    pub read_only_root: bool,
    pub host_network: bool,
    pub mounts_blake3: String,
    pub launch_contract_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleObservation {
    pub source_digest: ContentDigest,
    pub sandbox_backend: String,
    pub launch_contract_blake3: String,
    pub network_isolated: bool,
    pub host_root_read_only: bool,
    pub nix_daemon_absent: bool,
    pub exit_code: i32,
    pub workspace_preserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GuestObservation {
    Flatpak(FlatpakObservation),
    Oci(OciObservation),
    Capsule(CapsuleObservation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRealizationReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub guest_name: String,
    pub trust_class: SoftwareTrustClass,
    pub backend: GuestBackend,
    pub plan_blake3: String,
    pub artifact_identity: String,
    pub launch_contract_blake3: String,
    pub assurance: GuestAssurance,
    pub observation: GuestObservation,
}

impl GuestRealizationReceipt {
    pub fn verify(
        plan: &SoftwareIngressPlan,
        observation: GuestObservation,
    ) -> Result<Self, GuestRealizationError> {
        plan.validate()?;
        let plan_blake3 = plan.digest_hex()?;
        let launch_contract_blake3 = plan.spec.authority_digest_hex()?;
        let artifact_identity = plan.spec.artifact_identity();

        let (backend, assurance) = match (&plan.spec, &observation) {
            (SoftwareIngressSpec::FlatpakGuest(spec), GuestObservation::Flatpak(obs)) => {
                verify_flatpak(spec, &launch_contract_blake3, obs)?;
                (
                    GuestBackend::FlatpakUser,
                    GuestAssurance::PinnedArtifactAndLaunchContract,
                )
            }
            (SoftwareIngressSpec::OciGuest(spec), GuestObservation::Oci(obs)) => {
                verify_oci(spec, &launch_contract_blake3, obs)?;
                (
                    GuestBackend::RootlessPodman,
                    GuestAssurance::PinnedArtifactAndLaunchContract,
                )
            }
            (SoftwareIngressSpec::EphemeralCapsule(spec), GuestObservation::Capsule(obs)) => {
                verify_capsule(spec, &launch_contract_blake3, obs)?;
                (
                    GuestBackend::BubblewrapCapsule,
                    GuestAssurance::EphemeralObserved,
                )
            }
            (SoftwareIngressSpec::SovereignNix(_), _)
            | (SoftwareIngressSpec::NixEnclosedForeign(_), _) => {
                return Err(GuestRealizationError::NotGuestState);
            }
            _ => return Err(GuestRealizationError::BackendMismatch),
        };

        Ok(Self {
            schema_version: GUEST_REALIZATION_SCHEMA_VERSION,
            kind: "symthaea-guest-realization-receipt-v1".into(),
            guest_name: plan.name.clone(),
            trust_class: plan.trust_class(),
            backend,
            plan_blake3,
            artifact_identity,
            launch_contract_blake3,
            assurance,
            observation,
        })
    }

    pub fn digest_hex(&self) -> Result<String, GuestRealizationError> {
        if self.schema_version != GUEST_REALIZATION_SCHEMA_VERSION
            || self.kind != "symthaea-guest-realization-receipt-v1"
        {
            return Err(GuestRealizationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.plan_blake3)?;
        validate_digest(&self.launch_contract_blake3)?;
        hash_json(RECEIPT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRealizationManifest {
    pub schema_version: u32,
    pub kind: String,
    pub receipts: Vec<GuestRealizationReceipt>,
}

impl GuestRealizationManifest {
    pub fn from_receipts(
        mut receipts: Vec<GuestRealizationReceipt>,
    ) -> Result<Self, GuestRealizationError> {
        receipts.sort_by(|a, b| {
            a.guest_name
                .cmp(&b.guest_name)
                .then(a.plan_blake3.cmp(&b.plan_blake3))
        });
        let mut names = BTreeSet::new();
        for receipt in &receipts {
            let _ = receipt.digest_hex()?;
            if !names.insert(receipt.guest_name.as_str()) {
                return Err(GuestRealizationError::DuplicateGuest(
                    receipt.guest_name.clone(),
                ));
            }
        }
        Ok(Self {
            schema_version: GUEST_REALIZATION_SCHEMA_VERSION,
            kind: "symthaea-guest-realization-manifest-v1".into(),
            receipts,
        })
    }

    pub fn digest_hex(&self) -> Result<String, GuestRealizationError> {
        if self.schema_version != GUEST_REALIZATION_SCHEMA_VERSION
            || self.kind != "symthaea-guest-realization-manifest-v1"
        {
            return Err(GuestRealizationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        let mut names = BTreeSet::new();
        for receipt in &self.receipts {
            let _ = receipt.digest_hex()?;
            if !names.insert(receipt.guest_name.as_str()) {
                return Err(GuestRealizationError::DuplicateGuest(
                    receipt.guest_name.clone(),
                ));
            }
        }
        hash_json(MANIFEST_DOMAIN, self)
    }

    pub fn receipt(&self, name: &str) -> Option<&GuestRealizationReceipt> {
        self.receipts
            .iter()
            .find(|receipt| receipt.guest_name == name)
    }
}

pub fn empty_guest_realization_manifest_json() -> String {
    let manifest = GuestRealizationManifest {
        schema_version: GUEST_REALIZATION_SCHEMA_VERSION,
        kind: "symthaea-guest-realization-manifest-v1".into(),
        receipts: Vec::new(),
    };
    serde_json::to_string_pretty(&manifest)
        .unwrap_or_else(|_| {
            "{\"schema_version\":1,\"kind\":\"symthaea-guest-realization-manifest-v1\",\"receipts\":[]}".into()
        })
        + "\n"
}

pub fn oci_mounts_digest_hex(spec: &OciGuestPlan) -> Result<String, GuestRealizationError> {
    let encoded = serde_json::to_vec(&spec.mounts)
        .map_err(|_| GuestRealizationError::EvidenceSerialization)?;
    let mut h = blake3::Hasher::new();
    h.update(OCI_MOUNTS_DOMAIN);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

fn verify_flatpak(
    spec: &FlatpakGuestPlan,
    expected_authority: &str,
    obs: &FlatpakObservation,
) -> Result<(), GuestRealizationError> {
    if obs.app_id != spec.app_id
        || obs.remote != spec.remote
        || obs.branch != spec.branch
        || obs.installed_commit != spec.commit
        || obs.launch_contract_blake3 != expected_authority
    {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    if spec.runtime_pins.is_empty() {
        return Err(GuestRealizationError::UnpinnedFlatpakRuntime);
    }
    if obs.runtime_commits.len() != spec.runtime_pins.len() {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    for runtime in &spec.runtime_pins {
        if obs.runtime_commits.get(&runtime.reference) != Some(&runtime.commit) {
            return Err(GuestRealizationError::ObservationMismatch);
        }
    }
    Ok(())
}

fn verify_oci(
    spec: &OciGuestPlan,
    expected_authority: &str,
    obs: &OciObservation,
) -> Result<(), GuestRealizationError> {
    if obs.image != spec.image
        || obs.image_digest != spec.image_digest
        || !obs.rootless
        || !spec.rootless
        || obs.read_only_root != spec.read_only_root
        || obs.host_network
        || spec.host_network
        || obs.launch_contract_blake3 != expected_authority
        || obs.mounts_blake3 != oci_mounts_digest_hex(spec)?
    {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    Ok(())
}

fn verify_capsule(
    spec: &EphemeralCapsulePlan,
    expected_authority: &str,
    obs: &CapsuleObservation,
) -> Result<(), GuestRealizationError> {
    if obs.source_digest != spec.source_digest
        || obs.launch_contract_blake3 != expected_authority
        || obs.sandbox_backend != "bubblewrap-v1"
        || !obs.host_root_read_only
        || !obs.nix_daemon_absent
    {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    let expect_network_isolated = matches!(
        spec.network,
        crate::software_ingress::CapsuleNetworkPolicy::None
    );
    if obs.network_isolated != expect_network_isolated {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    let expect_preserved = matches!(
        spec.persistence,
        crate::software_ingress::CapsulePersistence::PreserveWorkspaceData
    );
    if obs.workspace_preserved != expect_preserved {
        return Err(GuestRealizationError::ObservationMismatch);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), GuestRealizationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(GuestRealizationError::InvalidDigest)
    }
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, GuestRealizationError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| GuestRealizationError::EvidenceSerialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GuestRealizationError {
    #[error("unsupported guest-realization schema version {0}")]
    UnsupportedSchema(u32),
    #[error("software ingress error: {0}")]
    SoftwareIngress(#[from] SoftwareIngressError),
    #[error("plan is not S2/S3 guest state")]
    NotGuestState,
    #[error("guest observation uses the wrong backend")]
    BackendMismatch,
    #[error("observed guest state does not match the exact plan")]
    ObservationMismatch,
    #[error("high-assurance Flatpak realization requires explicit runtime commit pins")]
    UnpinnedFlatpakRuntime,
    #[error("guest evidence contains an invalid digest")]
    InvalidDigest,
    #[error("guest evidence serialization failed")]
    EvidenceSerialization,
    #[error("duplicate guest realization receipt: {0}")]
    DuplicateGuest(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_ingress::{
        CapsuleNetworkPolicy, CapsulePersistence, FlatpakRuntimePin, GuestPermissionEnvelope,
        SoftwareIngressSpec,
    };

    fn hex(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn flatpak_receipt_requires_app_and_runtime_commit_identity() {
        let plan = SoftwareIngressPlan::new(
            "signal",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.signal.Signal".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: hex('a'),
                runtime_pins: vec![FlatpakRuntimePin {
                    reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                    commit: hex('b'),
                }],
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let authority = plan.spec.authority_digest_hex().unwrap();
        let receipt = GuestRealizationReceipt::verify(
            &plan,
            GuestObservation::Flatpak(FlatpakObservation {
                app_id: "org.signal.Signal".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                installed_commit: hex('a'),
                runtime_commits: BTreeMap::from([(
                    "org.freedesktop.Platform/x86_64/24.08".into(),
                    hex('b'),
                )]),
                launch_contract_blake3: authority,
            }),
        )
        .unwrap();
        assert_eq!(
            receipt.assurance,
            GuestAssurance::PinnedArtifactAndLaunchContract
        );
    }

    #[test]
    fn flatpak_receipt_rejects_unpinned_runtime() {
        let plan = SoftwareIngressPlan::new(
            "app",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.example.App".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: hex('a'),
                runtime_pins: vec![],
                permissions: GuestPermissionEnvelope::default(),
            }),
        );
        assert!(plan.is_err());
    }

    #[test]
    fn oci_receipt_requires_rootless_exact_digest_and_mounts() {
        let plan = SoftwareIngressPlan::new(
            "db",
            SoftwareIngressSpec::OciGuest(OciGuestPlan {
                image: "docker.io/library/postgres".into(),
                image_digest: format!("sha256:{}", hex('c')),
                rootless: true,
                read_only_root: true,
                host_network: false,
                mounts: vec![],
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let authority = plan.spec.authority_digest_hex().unwrap();
        let mounts = match &plan.spec {
            SoftwareIngressSpec::OciGuest(spec) => oci_mounts_digest_hex(spec).unwrap(),
            _ => unreachable!(),
        };
        let receipt = GuestRealizationReceipt::verify(
            &plan,
            GuestObservation::Oci(OciObservation {
                image: "docker.io/library/postgres".into(),
                image_digest: format!("sha256:{}", hex('c')),
                rootless: true,
                read_only_root: true,
                host_network: false,
                mounts_blake3: mounts,
                launch_contract_blake3: authority,
            }),
        )
        .unwrap();
        assert_eq!(receipt.backend, GuestBackend::RootlessPodman);
    }

    #[test]
    fn realization_intent_binds_declarative_and_runtime_prestate() {
        let plan = SoftwareIngressPlan::new(
            "experiment",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('d')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let first =
            GuestRealizationIntent::new(hex('1'), plan.clone(), hex('2'), hex('3'), [7u8; 32])
                .unwrap();
        let second =
            GuestRealizationIntent::new(hex('1'), plan, hex('2'), hex('4'), [7u8; 32]).unwrap();
        assert_ne!(first.digest_hex().unwrap(), second.digest_hex().unwrap());
    }

    #[test]
    fn realization_manifest_rejects_duplicate_guest_names() {
        let plan = SoftwareIngressPlan::new(
            "experiment",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('d')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let authority = plan.spec.authority_digest_hex().unwrap();
        let receipt = GuestRealizationReceipt::verify(
            &plan,
            GuestObservation::Capsule(CapsuleObservation {
                source_digest: ContentDigest::blake3(hex('d')).unwrap(),
                sandbox_backend: "bubblewrap-v1".into(),
                launch_contract_blake3: authority,
                network_isolated: true,
                host_root_read_only: true,
                nix_daemon_absent: true,
                exit_code: 0,
                workspace_preserved: false,
            }),
        )
        .unwrap();
        assert!(GuestRealizationManifest::from_receipts(vec![receipt.clone(), receipt]).is_err());
    }

    #[test]
    fn capsule_receipt_never_claims_reproducibility() {
        let plan = SoftwareIngressPlan::new(
            "experiment",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('d')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let authority = plan.spec.authority_digest_hex().unwrap();
        let receipt = GuestRealizationReceipt::verify(
            &plan,
            GuestObservation::Capsule(CapsuleObservation {
                source_digest: ContentDigest::blake3(hex('d')).unwrap(),
                sandbox_backend: "bubblewrap-v1".into(),
                launch_contract_blake3: authority,
                network_isolated: true,
                host_root_read_only: true,
                nix_daemon_absent: true,
                exit_code: 0,
                workspace_preserved: false,
            }),
        )
        .unwrap();
        assert_eq!(receipt.assurance, GuestAssurance::EphemeralObserved);
    }
}
