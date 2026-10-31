// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verify signed evidence-capture bundles before semantic evaluation.
//!
//! This authenticates a capture statement against a locally loaded trust
//! policy and verifies every referenced artifact byte. It does not prove
//! that a root-owned collector, kernel, systemd manager, storage stack or
//! boot chain was uncompromised. A trusted host key attests the collector's
//! statement, not the truth of a compromised host.

use crate::systemd_semantic_evidence::{
    evaluate, SemanticEvaluation, SystemdExecutionEvidence, EVIDENCE_SCHEMA, EVIDENCE_VERSION,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CAPTURE_SCHEMA: &str = "org.luminousdynamics.nixward.signed-evidence-capture";
pub const CAPTURE_VERSION: u32 = 1;
pub const CAPTURE_POLICY_SCHEMA: &str = "org.luminousdynamics.nixward.evidence-capture-trust-policy";
pub const CAPTURE_POLICY_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"nixward-systemd-evidence-capture-signature-v1\0";
const POLICY_DOMAIN: &[u8] = b"nixward-evidence-capture-policy-v1\0";
const MAX_ARTIFACT_COUNT: usize = 64;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SEMANTIC_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_manager_unique_owner(value: &str) -> bool {
    value.starts_with(":1.")
        && value.len() > 3
        && value[3..].bytes().all(|byte| byte.is_ascii_digit())
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("malformed Ed25519 signature encoding".into());
    }
    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = (bytes[index * 2] as char)
            .to_digit(16)
            .ok_or_else(|| "malformed Ed25519 signature encoding".to_string())?;
        let low = (bytes[index * 2 + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "malformed Ed25519 signature encoding".to_string())?;
        out[index] = ((high << 4) | low) as u8;
    }
    Ok(out)
}

fn signed_manifest_bytes(manifest: &EvidenceCaptureManifest) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(manifest)
        .map_err(|error| format!("cannot serialize canonical capture manifest: {error}"))?;
    if json.len() > MAX_MANIFEST_BYTES {
        return Err("capture manifest exceeds maximum size".into());
    }
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + json.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&(json.len() as u64).to_le_bytes());
    payload.extend_from_slice(&json);
    Ok(payload)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureTrustKey {
    pub key_id: String,
    /// Ed25519 public key as exactly 32 bytes of hex.
    pub public_key_hex: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCaptureTrustPolicy {
    pub schema: String,
    pub version: u32,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub keys: Vec<CaptureTrustKey>,
}

impl EvidenceCaptureTrustPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CAPTURE_POLICY_SCHEMA
            || self.version != CAPTURE_POLICY_VERSION
            || !valid_token(&self.policy_id)
            || self.policy_epoch == 0
            || self.keys.is_empty()
        {
            return Err("invalid evidence-capture trust-policy header".into());
        }
        let mut key_ids = BTreeSet::new();
        for key in &self.keys {
            if !valid_token(&key.key_id) || !key_ids.insert(key.key_id.as_str()) {
                return Err("invalid or duplicate evidence-capture key ID".into());
            }
            let _ = decode_hex::<32>(&key.public_key_hex)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("cannot serialize evidence policy: {error}"))?;
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DOMAIN);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    /// Stable logical ID, e.g. dbus-events, journal-slice, pidfd-observation.
    pub artifact_id: String,
    pub source_kind: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCaptureManifest {
    pub schema: String,
    pub version: u32,
    pub capture_id: String,
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub host_key_id: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub policy_digest: String,
    pub kernel_boot_id: String,
    pub systemd_version: String,
    /// D-Bus unique name of the manager owner at capture time, e.g. :1.3.
    pub manager_unique_owner: String,
    pub capture_started_monotonic_ns: u64,
    pub capture_finished_monotonic_ns: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u64,
    pub semantic_envelope_sha256: String,
    /// Must be unique and lexicographically sorted before signing.
    pub artifacts: Vec<ArtifactDigest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceCapture {
    pub schema: String,
    pub version: u32,
    pub manifest: EvidenceCaptureManifest,
    /// Ed25519 signature over the domain-separated canonical manifest bytes.
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureVerificationError {
    InvalidPolicy,
    UnknownSigner,
    RevokedSigner,
    InvalidSignature,
    InvalidManifest,
    PolicyEpochMismatch,
    ArtifactSetMismatch,
    ArtifactDigestMismatch,
    SemanticBindingMismatch,
}

impl CaptureVerificationError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPolicy => "invalid evidence-capture trust policy",
            Self::UnknownSigner => "evidence-capture signer is not trusted",
            Self::RevokedSigner => "evidence-capture signer is revoked",
            Self::InvalidSignature => "evidence-capture signature is invalid",
            Self::InvalidManifest => "evidence-capture manifest is malformed",
            Self::PolicyEpochMismatch => "evidence-capture policy identity or epoch differs",
            Self::ArtifactSetMismatch => "capture artifact set differs from signed manifest",
            Self::ArtifactDigestMismatch => "capture artifact bytes do not match signed digest",
            Self::SemanticBindingMismatch => "semantic envelope differs from signed capture bindings",
        }
    }
}
impl std::fmt::Display for CaptureVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for CaptureVerificationError {}

/// Runtime-only verified capture. Fields are private and it has no
/// Serialize/Deserialize implementation. It attests the signed collector
/// statement and artifact bytes, not the absence of host-root compromise.
#[derive(Debug)]
pub struct VerifiedEvidenceCapture {
    manifest: EvidenceCaptureManifest,
    semantic_evidence: SystemdExecutionEvidence,
    raw_artifacts: BTreeMap<String, Vec<u8>>,
}
impl VerifiedEvidenceCapture {
    pub fn manifest(&self) -> &EvidenceCaptureManifest { &self.manifest }
    pub fn raw_artifacts(&self) -> &BTreeMap<String, Vec<u8>> { &self.raw_artifacts }
    pub fn evaluate_semantics(&self) -> Result<SemanticEvaluation, String> {
        let mut result = evaluate(&self.semantic_evidence).map_err(|error| error.to_string())?;
        result.operational_qualification =
            "signed-capture-verified-host-root-and-kernel-integrity-unverified".into();
        Ok(result)
    }
    pub fn into_parts(self) -> (EvidenceCaptureManifest, SystemdExecutionEvidence, BTreeMap<String, Vec<u8>>) {
        (self.manifest, self.semantic_evidence, self.raw_artifacts)
    }
}

fn validate_manifest(
    manifest: &EvidenceCaptureManifest,
    policy: &EvidenceCaptureTrustPolicy,
    raw_artifacts: &BTreeMap<String, Vec<u8>>,
    semantic_envelope: &[u8],
) -> Result<(), CaptureVerificationError> {
    if manifest.schema != CAPTURE_SCHEMA
        || manifest.version != CAPTURE_VERSION
        || !valid_token(&manifest.capture_id)
        || !valid_token(&manifest.transaction_id)
        || !valid_token(&manifest.attempt_id)
        || !valid_token(&manifest.admission_commit_id)
        || !valid_sha256(&manifest.plan_digest)
        || !valid_sha256(&manifest.machine_binding_digest)
        || !valid_token(&manifest.host_key_id)
        || !valid_boot_id(&manifest.kernel_boot_id)
        || !valid_token(&manifest.systemd_version)
        || !valid_manager_unique_owner(&manifest.manager_unique_owner)
        || manifest.capture_started_monotonic_ns == 0
        || manifest.capture_finished_monotonic_ns < manifest.capture_started_monotonic_ns
        || manifest.first_sequence == 0
        || manifest.last_sequence < manifest.first_sequence
        || manifest.event_count == 0
        || manifest.last_sequence.checked_sub(manifest.first_sequence)
            .and_then(|delta| delta.checked_add(1)) != Some(manifest.event_count)
        || !valid_sha256(&manifest.semantic_envelope_sha256)
        || semantic_envelope.is_empty()
        || semantic_envelope.len() > MAX_SEMANTIC_ENVELOPE_BYTES
        || sha256_hex(semantic_envelope) != manifest.semantic_envelope_sha256
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > MAX_ARTIFACT_COUNT
    {
        return Err(CaptureVerificationError::InvalidManifest);
    }
    if manifest.policy_id != policy.policy_id || manifest.policy_epoch != policy.policy_epoch {
        return Err(CaptureVerificationError::PolicyEpochMismatch);
    }
    if manifest.artifacts.len() != raw_artifacts.len() {
        return Err(CaptureVerificationError::ArtifactSetMismatch);
    }
    let mut previous_id: Option<&str> = None;
    let mut total_bytes = 0u64;
    for artifact in &manifest.artifacts {
        if !valid_token(&artifact.artifact_id)
            || !valid_token(&artifact.source_kind)
            || !valid_sha256(&artifact.sha256)
            || artifact.byte_length == 0
            || artifact.byte_length > MAX_ARTIFACT_BYTES
            || previous_id.is_some_and(|previous| previous >= artifact.artifact_id.as_str())
        {
            return Err(CaptureVerificationError::InvalidManifest);
        }
        previous_id = Some(&artifact.artifact_id);
        total_bytes = total_bytes.checked_add(artifact.byte_length)
            .ok_or(CaptureVerificationError::InvalidManifest)?;
        let bytes = raw_artifacts.get(&artifact.artifact_id)
            .ok_or(CaptureVerificationError::ArtifactSetMismatch)?;
        if bytes.len() as u64 != artifact.byte_length || sha256_hex(bytes) != artifact.sha256 {
            return Err(CaptureVerificationError::ArtifactDigestMismatch);
        }
    }
    if total_bytes > MAX_TOTAL_ARTIFACT_BYTES
        || raw_artifacts.keys().any(|key| !manifest.artifacts.iter().any(|item| &item.artifact_id == key))
    {
        return Err(CaptureVerificationError::ArtifactSetMismatch);
    }
    let semantic: SystemdExecutionEvidence =
        serde_json::from_slice(semantic_envelope)
            .map_err(|_| CaptureVerificationError::SemanticBindingMismatch)?;
    if semantic.schema != EVIDENCE_SCHEMA
        || semantic.version != EVIDENCE_VERSION
        || semantic.binding.transaction_id != manifest.transaction_id
        || semantic.binding.attempt_id != manifest.attempt_id
        || semantic.binding.admission_commit_id != manifest.admission_commit_id
        || semantic.binding.plan_digest != manifest.plan_digest
        || semantic.binding.machine_binding_digest != manifest.machine_binding_digest
        || semantic.binding.kernel_boot_id != manifest.kernel_boot_id
        || semantic.binding.systemd_version != manifest.systemd_version
    {
        return Err(CaptureVerificationError::SemanticBindingMismatch);
    }
    Ok(())
}

/// Verify host-capture signature, local policy, raw artifact bytes, sequence
/// continuity and semantic-envelope bindings.
pub fn verify_capture(
    signed_capture: &SignedEvidenceCapture,
    policy: &EvidenceCaptureTrustPolicy,
    raw_artifacts: BTreeMap<String, Vec<u8>>,
    semantic_envelope: &[u8],
) -> Result<VerifiedEvidenceCapture, CaptureVerificationError> {
    policy.validate().map_err(|_| CaptureVerificationError::InvalidPolicy)?;
    if signed_capture.schema != CAPTURE_SCHEMA || signed_capture.version != CAPTURE_VERSION {
        return Err(CaptureVerificationError::InvalidManifest);
    }
    let manifest = &signed_capture.manifest;
    if manifest.policy_digest != policy.digest().map_err(|_| CaptureVerificationError::InvalidPolicy)?
        || manifest.policy_id != policy.policy_id
        || manifest.policy_epoch != policy.policy_epoch
    {
        return Err(CaptureVerificationError::PolicyEpochMismatch);
    }
    let key = policy.keys.iter()
        .find(|key| key.key_id == manifest.host_key_id)
        .ok_or(CaptureVerificationError::UnknownSigner)?;
    if key.revoked { return Err(CaptureVerificationError::RevokedSigner); }
    validate_manifest(manifest, policy, &raw_artifacts, semantic_envelope)?;

    let public_key_bytes = decode_hex::<32>(&key.public_key_hex)
        .map_err(|_| CaptureVerificationError::InvalidPolicy)?;
    let signature_bytes = decode_hex::<64>(&signed_capture.signature_hex)
        .map_err(|_| CaptureVerificationError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| CaptureVerificationError::InvalidPolicy)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = signed_manifest_bytes(manifest)
        .map_err(|_| CaptureVerificationError::InvalidManifest)?;
    verifying_key.verify_strict(&payload, &signature)
        .map_err(|_| CaptureVerificationError::InvalidSignature)?;

    let semantic_evidence: SystemdExecutionEvidence =
        serde_json::from_slice(semantic_envelope)
            .map_err(|_| CaptureVerificationError::SemanticBindingMismatch)?;
    Ok(VerifiedEvidenceCapture {
        manifest: manifest.clone(),
        semantic_evidence,
        raw_artifacts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_semantic_evidence::{
        AdmissionEvidence, DispatchEvidence, ManagerEvent, ManagerEventKind, NixosOperation,
        NixosPostState, OperationPlan, SafetyFence, SystemdExecutionEvidence,
        TransactionBinding,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
    fn digest(byte: u8) -> String { format!("{byte:02x}").repeat(32) }

    fn semantic_envelope() -> Vec<u8> {
        let boot = "01234567-89ab-cdef-0123-456789abcdef".to_string();
        let candidate = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-candidate-system".to_string();
        let predecessor = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-predecessor-system".to_string();
        let evidence = SystemdExecutionEvidence {
            schema: EVIDENCE_SCHEMA.into(), version: EVIDENCE_VERSION,
            binding: TransactionBinding {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(),
                admission_commit_id: "commit-1".into(), replay_key_digest: digest(1),
                permit_digest: digest(2), plan_digest: digest(3), machine_binding_digest: digest(4),
                kernel_boot_id: boot.clone(), systemd_version: "systemd-262".into(),
            },
            plan: OperationPlan {
                operation: NixosOperation::Switch, unit_name: "nixward-worker@attempt-1.service".into(),
                unit_start_mode: "replace".into(), expected_unit_active_state: "inactive".into(),
                expected_unit_sub_state: "dead".into(), expected_unit_result: "success".into(),
                candidate_store_path: candidate.clone(), predecessor_store_path: predecessor,
                required_health_check_ids: vec![],
            },
            admission: AdmissionEvidence {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(),
                admission_commit_id: "commit-1".into(), replay_key_digest: digest(1),
                permit_digest: digest(2), plan_digest: digest(3), machine_binding_digest: digest(4),
                committed_at_ns: 1, readback_at_ns: 2,
            },
            dispatch: DispatchEvidence {
                subscription_boot_id: boot.clone(), manager_subscribe_completed_at_ns: 3,
                job_signal_match_installed_at_ns: 4, subscription_established_at_ns: 5,
                start_request_at_ns: 6, start_reply_at_ns: None,
                returned_job_object_path: None, requested_unit_name: "nixward-worker@attempt-1.service".into(),
                requested_mode: "replace".into(), start_call_count: 0,
            },
            manager_events: vec![ManagerEvent {
                kind: ManagerEventKind::JobNew, job_id: 7,
                job_object_path: "/org/freedesktop/systemd1/job/7".into(),
                unit_name: "nixward-worker@attempt-1.service".into(), result: None,
                manager_boot_id: boot.clone(), monotonic_at_ns: 7,
            }],
            worker_identity: None, unit_snapshot: None, process_receipt: None, payload_release: None,
            post_state: Some(NixosPostState {
                kernel_boot_id: boot, observed_at_ns: 8,
                selected_profile_store_path: candidate.clone(),
                running_system_store_path: candidate.clone(), boot_default_store_path: candidate,
            }),
            health_observations: vec![], recovery: None,
            safety_fence: SafetyFence { actions_fenced: true, fenced_at_ns: Some(9) },
        };
        serde_json::to_vec(&evidence).unwrap()
    }

    fn fixture() -> (
        SignedEvidenceCapture, EvidenceCaptureTrustPolicy,
        BTreeMap<String, Vec<u8>>, Vec<u8>, SigningKey
    ) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let policy = EvidenceCaptureTrustPolicy {
            schema: CAPTURE_POLICY_SCHEMA.into(), version: CAPTURE_POLICY_VERSION,
            policy_id: "host-capture-policy-v1".into(), policy_epoch: 4,
            keys: vec![CaptureTrustKey {
                key_id: "host-boot-key-1".into(),
                public_key_hex: hex(signing.verifying_key().as_bytes()), revoked: false,
            }],
        };
        let artifacts = BTreeMap::from([
            ("dbus-events".to_string(), b"raw-dbus-event-stream".to_vec()),
            ("host-observations".to_string(), b"raw-profile-and-health-observations".to_vec()),
        ]);
        let semantic = semantic_envelope();
        let manifest = EvidenceCaptureManifest {
            schema: CAPTURE_SCHEMA.into(), version: CAPTURE_VERSION,
            capture_id: "capture-1".into(), transaction_id: "txn-1".into(),
            attempt_id: "attempt-1".into(), admission_commit_id: "commit-1".into(),
            plan_digest: digest(3), machine_binding_digest: digest(4),
            host_key_id: "host-boot-key-1".into(), policy_id: policy.policy_id.clone(),
            policy_epoch: policy.policy_epoch, policy_digest: policy.digest().unwrap(),
            kernel_boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            systemd_version: "systemd-262".into(), manager_unique_owner: ":1.42".into(),
            capture_started_monotonic_ns: 10, capture_finished_monotonic_ns: 20,
            first_sequence: 1, last_sequence: 2, event_count: 2,
            semantic_envelope_sha256: sha256_hex(&semantic),
            artifacts: vec![
                ArtifactDigest {
                    artifact_id: "dbus-events".into(), source_kind: "systemd-dbus".into(),
                    sha256: sha256_hex(b"raw-dbus-event-stream"),
                    byte_length: b"raw-dbus-event-stream".len() as u64,
                },
                ArtifactDigest {
                    artifact_id: "host-observations".into(), source_kind: "nixos-host-state".into(),
                    sha256: sha256_hex(b"raw-profile-and-health-observations"),
                    byte_length: b"raw-profile-and-health-observations".len() as u64,
                },
            ],
        };
        let payload = signed_manifest_bytes(&manifest).unwrap();
        let signed = SignedEvidenceCapture {
            schema: CAPTURE_SCHEMA.into(), version: CAPTURE_VERSION,
            manifest, signature_hex: hex(&signing.sign(&payload).to_bytes()),
        };
        (signed, policy, artifacts, semantic, signing)
    }

    #[test]
    fn accepts_signed_capture_and_runs_semantic_consistency() {
        let (signed, policy, artifacts, semantic, _) = fixture();
        let verified = verify_capture(&signed, &policy, artifacts, &semantic).unwrap();
        assert_eq!(verified.manifest().capture_id, "capture-1");
        let evaluation = verified.evaluate_semantics().unwrap();
        assert_eq!(
            evaluation.classification,
            crate::systemd_semantic_evidence::TerminalClassification::SafeHold
        );
        assert_eq!(
            evaluation.operational_qualification,
            "signed-capture-verified-host-root-and-kernel-integrity-unverified"
        );
    }

    #[test]
    fn rejects_invalid_ed25519_capture_signature() {
        let (mut signed, policy, artifacts, semantic, _) = fixture();
        signed.signature_hex = "00".repeat(64);
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::InvalidSignature
        );
    }

    #[test]
    fn rejects_tampered_raw_artifact() {
        let (signed, policy, mut artifacts, semantic, _) = fixture();
        artifacts.get_mut("dbus-events").unwrap()[0] ^= 1;
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::ArtifactDigestMismatch
        );
    }

    #[test]
    fn rejects_policy_epoch_drift() {
        let (signed, mut policy, artifacts, semantic, _) = fixture();
        policy.policy_epoch += 1;
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::PolicyEpochMismatch
        );
    }

    #[test]
    fn rejects_revoked_capture_key() {
        let (mut signed, mut policy, artifacts, semantic, signing) = fixture();
        policy.keys[0].revoked = true;
        signed.manifest.policy_digest = policy.digest().unwrap();
        let payload = signed_manifest_bytes(&signed.manifest).unwrap();
        signed.signature_hex = hex(&signing.sign(&payload).to_bytes());
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::RevokedSigner
        );
    }

    #[test]
    fn rejects_sequence_gaps() {
        let (mut signed, policy, artifacts, semantic, signing) = fixture();
        signed.manifest.last_sequence += 1;
        let payload = signed_manifest_bytes(&signed.manifest).unwrap();
        signed.signature_hex = hex(&signing.sign(&payload).to_bytes());
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::InvalidManifest
        );
    }

    #[test]
    fn rejects_foreign_transaction_binding() {
        let (mut signed, policy, artifacts, semantic, signing) = fixture();
        signed.manifest.transaction_id = "foreign-transaction".into();
        let payload = signed_manifest_bytes(&signed.manifest).unwrap();
        signed.signature_hex = hex(&signing.sign(&payload).to_bytes());
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::SemanticBindingMismatch
        );
    }

    #[test]
    fn strict_json_rejects_unknown_manifest_fields() {
        let (signed, _, _, _, _) = fixture();
        let mut value = serde_json::to_value(signed).unwrap();
        value["manifest"]["trust_everything"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedEvidenceCapture>(value).is_err());
    }

    #[test]
    fn rejects_missing_or_extra_artifacts() {
        let (signed, policy, mut artifacts, semantic, _) = fixture();
        artifacts.remove("dbus-events");
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::ArtifactSetMismatch
        );
        let (signed, policy, mut artifacts, semantic, _) = fixture();
        artifacts.insert("unsigned-extra".into(), b"extra".to_vec());
        assert_eq!(
            verify_capture(&signed, &policy, artifacts, &semantic).unwrap_err(),
            CaptureVerificationError::ArtifactSetMismatch
        );
    }
}
