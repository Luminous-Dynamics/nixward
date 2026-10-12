// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Versioned system-transaction envelope.
//!
//! This module does not introduce another authorization mechanism. It wraps
//! the existing ChangePlan and ChangeAuthorization identities with lifecycle
//! receipts so the installer, management UI, and remote transports can
//! exchange one stable, digest-addressed transaction vocabulary.

use super::ai_proposal_binding::{
    AiProposalBinding, AiProposalOutputIntent, AiProposalResolutionReceipt,
    AiProposalResolvedValidationEvidence, AiProposalRuntimeVerifiedValidationEvidence,
    AiProposalValidationEvidence,
};
use crate::release_integrity::SignedReleaseManifest;
use std::path::Path;
use super::change_covenant::{ApprovalEvidenceKind, ChangeAuthorization, ChangePlan};
use serde::{Deserialize, Serialize};

const TRANSACTION_DOMAIN: &[u8] = b"nixward-system-transaction-v1\0";
pub const SYSTEM_TRANSACTION_SCHEMA: &str = "luminous-nixward-system-transaction-v1";
pub const SYSTEM_TRANSACTION_VERSION: u16 = 1;
const MAX_ISSUER_BYTES: usize = 256;
const MAX_SUMMARY_BYTES: usize = 4096;
const MAX_REASON_BYTES: usize = 4096;
const MAX_SIGNER_KEY_ID_BYTES: usize = 256;

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn transaction_id(plan: &ChangePlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(&plan.digest());
    hasher.update(&plan.nonce());
    digest_hex(hasher.finalize().as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPhase {
    Planned,
    Authorized,
    Validated,
    Snapshotted,
    Applied,
    Verified,
    Promoted,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    pub issuer: String,
    pub evidence_digest: String,
    pub evidence_kind: ApprovalEvidenceKind,
    pub expires_at_ms: u64,
    pub signer_key_id: Option<String>,
    pub challenge_blake3: Option<String>,
    pub replay_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReceipt {
    pub evidence_digest: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReceipt {
    pub pre_state_digest: String,
    pub recovery_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationReceipt {
    pub command_digest: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub exit_status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub post_state_digest: String,
    pub evidence_digest: String,
    pub boot_healthy: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeReceipt {
    pub phase: TransactionPhase,
    pub reason: Option<String>,
}

/// Serialized transaction vocabulary shared across Nixward consumers.
///
/// Digest-bearing fields intentionally contain no secret material. A caller
/// can exchange this envelope through browser/relay/IPC boundaries without
/// exposing passwords, private keys, or raw filesystem state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTransaction {
    pub schema: String,
    pub version: u16,
    pub transaction_id: String,
    pub target_machine_digest: String,
    pub plan_digest: String,
    pub phase: TransactionPhase,
    pub authorization: Option<AuthorizationReceipt>,
    pub validation: Option<ValidationReceipt>,
    pub snapshot: Option<SnapshotReceipt>,
    pub application: Option<ApplicationReceipt>,
    pub verification: Option<VerificationReceipt>,
    pub outcome: Option<OutcomeReceipt>,
}

impl SystemTransaction {
    pub fn planned(plan: &ChangePlan) -> Self {
        Self {
            schema: SYSTEM_TRANSACTION_SCHEMA.to_string(),
            version: SYSTEM_TRANSACTION_VERSION,
            transaction_id: transaction_id(plan),
            target_machine_digest: digest_hex(&plan.machine().digest()),
            plan_digest: digest_hex(&plan.digest()),
            phase: TransactionPhase::Planned,
            authorization: None,
            validation: None,
            snapshot: None,
            application: None,
            verification: None,
            outcome: None,
        }
    }

    fn ensure_identity(&self, plan: &ChangePlan) -> Result<(), String> {
        if self.schema != SYSTEM_TRANSACTION_SCHEMA || self.version != SYSTEM_TRANSACTION_VERSION {
            return Err("unsupported system transaction schema".into());
        }
        if self.plan_digest != digest_hex(&plan.digest()) {
            return Err("transaction references a different change plan".into());
        }
        if self.target_machine_digest != digest_hex(&plan.machine().digest()) {
            return Err("transaction references a different target machine".into());
        }
        if self.transaction_id != transaction_id(plan) {
            return Err("transaction identity does not match the change plan".into());
        }
        Ok(())
    }

    pub fn authorize(
        &mut self,
        plan: &ChangePlan,
        authorization: &ChangeAuthorization,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Validated) || self.validation.is_none() {
            return Err("authorization requires completed validation evidence".into());
        }
        authorization.validate_plan(plan)?;
        if authorization.issuer().len() > MAX_ISSUER_BYTES {
            return Err("authorization issuer exceeds wire limit".into());
        }
        self.authorization = Some(AuthorizationReceipt {
            issuer: authorization.issuer().to_string(),
            evidence_digest: digest_hex(&authorization.evidence_digest()),
            evidence_kind: authorization.approval_evidence_kind(),
            expires_at_ms: authorization.expires_at_ms(),
            signer_key_id: authorization.authority_signer_key_id().map(ToOwned::to_owned),
            challenge_blake3: authorization
                .authority_challenge_blake3()
                .map(ToOwned::to_owned),
            replay_key: authorization.authority_replay_key().map(ToOwned::to_owned),
        });
        self.phase = TransactionPhase::Authorized;
        Ok(())
    }

    pub fn record_validation(
        &mut self,
        plan: &ChangePlan,
        evidence_digest: [u8; 32],
        summary: impl Into<String>,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Planned) {
            return Err("validation must occur before authorization and snapshot".into());
        }
        if evidence_digest == [0; 32] {
            return Err("validation evidence digest must be non-zero".into());
        }
        let summary = summary.into();
        if summary.len() > MAX_SUMMARY_BYTES {
            return Err("validation summary exceeds wire limit".into());
        }
        self.validation = Some(ValidationReceipt {
            evidence_digest: digest_hex(&evidence_digest),
            summary,
        });
        self.phase = TransactionPhase::Validated;
        Ok(())
    }

    /// Record normal validation while binding it to exact AI-proposal provenance.
    ///
    /// The returned evidence envelope must be persisted by the caller alongside
    /// the referenced validation evidence and proposal binding. Its digest is
    /// stored in the existing validation receipt, so the transaction wire shape
    /// and authorization protocol remain unchanged.
    ///
    /// This method validates byte/digest correspondence and checks that the
    /// canonical structured proposal intent equals the exact plan. It does not
    /// prove upstream natural-language conversion fidelity, input truth, policy
    /// quality, or proof soundness. It never authorizes or executes the change.
    #[allow(clippy::too_many_arguments)]
    pub fn record_validation_with_ai_proposal(
        &mut self,
        plan: &ChangePlan,
        validation_evidence_digest: [u8; 32],
        summary: impl Into<String>,
        proposal: &AiProposalBinding,
        model_artifact_bytes: &[u8],
        input_canonical_bytes: &[u8],
        policy_canonical_bytes: &[u8],
        proposal_output_canonical_bytes: &[u8],
        verifier_artifact_bytes: &[u8],
        evaluation_evidence_canonical_bytes: &[u8],
    ) -> Result<AiProposalValidationEvidence, String> {
        proposal
            .validate_against_artifacts(
                plan,
                model_artifact_bytes,
                input_canonical_bytes,
                policy_canonical_bytes,
                proposal_output_canonical_bytes,
                verifier_artifact_bytes,
                evaluation_evidence_canonical_bytes,
            )
            .map_err(|error| format!("AI proposal provenance validation failed: {error}"))?;

        let evidence = AiProposalValidationEvidence::new(
            plan,
            validation_evidence_digest,
            proposal,
        )
        .map_err(|error| format!("AI proposal validation envelope is invalid: {error}"))?;
        let evidence_digest = evidence
            .digest()
            .map_err(|error| format!("AI proposal validation envelope is invalid: {error}"))?;

        // All proposal and artifact checks happen before this state transition.
        self.record_validation(plan, evidence_digest, summary)?;
        Ok(evidence)
    }

    /// Record validation while binding raw provider JSON to a deterministic
    /// resolution receipt, the exact ChangePlan, and AI-proposal provenance.
    ///
    /// The returned resolved envelope's digest is stored in the existing
    /// ValidationReceipt. Persist that envelope plus the resolution receipt,
    /// proposal binding, raw response, canonical intent, referenced artifacts,
    /// and ordinary validation evidence. All resolution and artifact checks
    /// happen before the transaction changes phase.
    ///
    /// The receipt identifies this build's embedded resolver source; it is not
    /// a software attestation proving that the executing binary is untampered.
    /// This method neither authorizes nor executes the change.
    #[allow(clippy::too_many_arguments)]
    pub fn record_validation_with_resolved_ai_proposal(
        &mut self,
        plan: &ChangePlan,
        validation_evidence_digest: [u8; 32],
        summary: impl Into<String>,
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
        model_artifact_bytes: &[u8],
        input_canonical_bytes: &[u8],
        policy_canonical_bytes: &[u8],
        verifier_artifact_bytes: &[u8],
        evaluation_evidence_canonical_bytes: &[u8],
    ) -> Result<AiProposalResolvedValidationEvidence, String> {
        proposal
            .validate_against_artifacts(
                plan,
                model_artifact_bytes,
                input_canonical_bytes,
                policy_canonical_bytes,
                canonical_intent_bytes,
                verifier_artifact_bytes,
                evaluation_evidence_canonical_bytes,
            )
            .map_err(|error| format!("AI proposal provenance validation failed: {error}"))?;

        let evidence = AiProposalResolvedValidationEvidence::new(
            plan,
            validation_evidence_digest,
            proposal,
            resolution,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )
        .map_err(|error| format!("AI proposal resolved validation envelope is invalid: {error}"))?;
        let evidence_digest = evidence
            .digest()
            .map_err(|error| format!("AI proposal resolved validation envelope is invalid: {error}"))?;

        // No transaction state mutation occurs until all referenced evidence is checked.
        self.record_validation(plan, evidence_digest, summary)?;
        Ok(evidence)
    }

    /// Record validation only after the current process executable is found in a
    /// release tree signed by the independently trusted offline release root.
    ///
    /// The signed release manifest must include both the current executable and
    /// the resolver source file at resolver_source_relative_path. The resolver
    /// source file must exactly match the source digest in the resolution receipt.
    /// The returned runtime-verified evidence digest occupies the existing
    /// ValidationReceipt field; no new authorization mechanism is introduced.
    ///
    /// On Linux this checks /proc/self/exe bytes plus the signed release tree.
    /// It is software-level evidence under the OS/kernel trust assumption, not
    /// hardware-backed measured boot or remote runtime attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn record_validation_with_runtime_verified_ai_proposal(
        &mut self,
        plan: &ChangePlan,
        validation_evidence_digest: [u8; 32],
        summary: impl Into<String>,
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
        model_artifact_bytes: &[u8],
        input_canonical_bytes: &[u8],
        policy_canonical_bytes: &[u8],
        verifier_artifact_bytes: &[u8],
        evaluation_evidence_canonical_bytes: &[u8],
        release_root: &Path,
        signed_release: &SignedReleaseManifest,
        trusted_release_public_key_hex: &str,
        resolver_source_relative_path: &str,
    ) -> Result<AiProposalRuntimeVerifiedValidationEvidence, String> {
        proposal
            .validate_against_artifacts(
                plan,
                model_artifact_bytes,
                input_canonical_bytes,
                policy_canonical_bytes,
                canonical_intent_bytes,
                verifier_artifact_bytes,
                evaluation_evidence_canonical_bytes,
            )
            .map_err(|error| format!("AI proposal provenance validation failed: {error}"))?;

        let runtime = resolution
            .verify_current_runtime(
                release_root,
                signed_release,
                trusted_release_public_key_hex,
                plan,
                raw_model_output_bytes,
                canonical_intent_bytes,
                resolver_source_relative_path,
            )
            .map_err(|error| format!("resolver runtime verification failed: {error}"))?;

        let resolved = AiProposalResolvedValidationEvidence::new(
            plan,
            validation_evidence_digest,
            proposal,
            resolution,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )
        .map_err(|error| format!("resolved AI proposal evidence is invalid: {error}"))?;

        let evidence = AiProposalRuntimeVerifiedValidationEvidence::new(
            plan,
            &resolved,
            proposal,
            resolution,
            &runtime,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )
        .map_err(|error| format!("runtime-verified AI proposal evidence is invalid: {error}"))?;
        let evidence_digest = evidence
            .digest()
            .map_err(|error| format!("runtime-verified AI proposal evidence is invalid: {error}"))?;

        // Release signature, artifact tree, current executable, source, raw response,
        // structured intent, and model artifact checks all precede this state change.
        self.record_validation(plan, evidence_digest, summary)?;
        Ok(evidence)
    }

    pub fn record_snapshot(
        &mut self,
        plan: &ChangePlan,
        pre_state_digest: [u8; 32],
        recovery_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Authorized)
            || self.validation.is_none()
            || self.authorization.is_none()
        {
            return Err("snapshot requires validated and authorized transaction intent".into());
        }
        if pre_state_digest == [0; 32] || recovery_binding_digest == [0; 32] {
            return Err("snapshot digests must be non-zero".into());
        }
        self.snapshot = Some(SnapshotReceipt {
            pre_state_digest: digest_hex(&pre_state_digest),
            recovery_binding_digest: digest_hex(&recovery_binding_digest),
        });
        self.phase = TransactionPhase::Snapshotted;
        Ok(())
    }

    pub fn record_application(
        &mut self,
        plan: &ChangePlan,
        command_digest: [u8; 32],
        started_at_ms: u64,
        finished_at_ms: u64,
        exit_status: i32,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Snapshotted)
            || self.authorization.is_none()
            || self.validation.is_none()
            || self.snapshot.is_none()
        {
            return Err("application requires authorized, validated, and snapshotted transaction intent".into());
        }
        if command_digest == [0; 32] {
            return Err("application command digest must be non-zero".into());
        }
        if finished_at_ms < started_at_ms {
            return Err("application receipt has an invalid time range".into());
        }
        if let Some(authorization) = &self.authorization {
            if let Some(signer_key_id) = &authorization.signer_key_id {
                if signer_key_id.len() > MAX_SIGNER_KEY_ID_BYTES {
                    return Err("authorization signer key id exceeds wire limit".into());
                }
            }
        }
        let Some(command) = plan.command() else {
            return Err("application receipt requires a command-backed change plan".into());
        };
        if command.command_digest() != command_digest {
            return Err("application command digest differs from the approved plan".into());
        }
        self.application = Some(ApplicationReceipt {
            command_digest: digest_hex(&command_digest),
            started_at_ms,
            finished_at_ms,
            exit_status,
        });
        if exit_status == 0 {
            self.phase = TransactionPhase::Applied;
        } else {
            self.phase = TransactionPhase::Failed;
            self.outcome = Some(OutcomeReceipt {
                phase: TransactionPhase::Failed,
                reason: Some(format!("command exited with status {exit_status}")),
            });
        }
        Ok(())
    }

    pub fn record_verification(
        &mut self,
        plan: &ChangePlan,
        post_state_digest: [u8; 32],
        evidence_digest: [u8; 32],
        boot_healthy: Option<bool>,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Applied) {
            return Err("verification requires a successfully applied transaction".into());
        }
        if post_state_digest == [0; 32] || evidence_digest == [0; 32] {
            return Err("verification digests must be non-zero".into());
        }
        self.verification = Some(VerificationReceipt {
            post_state_digest: digest_hex(&post_state_digest),
            evidence_digest: digest_hex(&evidence_digest),
            boot_healthy,
        });
        self.phase = TransactionPhase::Verified;
        Ok(())
    }

    pub fn promote(&mut self, plan: &ChangePlan) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Verified) {
            return Err("promotion requires verified post-state evidence".into());
        }
        if self
            .verification
            .as_ref()
            .and_then(|receipt| receipt.boot_healthy)
            .is_some_and(|healthy| !healthy)
        {
            return Err("unhealthy boot cannot be promoted".into());
        }
        self.phase = TransactionPhase::Promoted;
        self.outcome = Some(OutcomeReceipt {
            phase: TransactionPhase::Promoted,
            reason: None,
        });
        Ok(())
    }

    pub fn recover(&mut self, plan: &ChangePlan, reason: impl Into<String>) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Failed | TransactionPhase::Verified)
            || self.snapshot.is_none()
        {
            return Err("recovery requires a failed/unhealthy transaction with snapshot evidence".into());
        }
        let reason = reason.into();
        if reason.len() > MAX_REASON_BYTES {
            return Err("recovery reason exceeds wire limit".into());
        }
        self.phase = TransactionPhase::Recovered;
        self.outcome = Some(OutcomeReceipt {
            phase: TransactionPhase::Recovered,
            reason: Some(reason),
        });
        Ok(())
    }

    pub fn validate_wire(&self) -> Result<(), String> {
        if self.schema != SYSTEM_TRANSACTION_SCHEMA || self.version != SYSTEM_TRANSACTION_VERSION {
            return Err("unsupported system transaction schema".into());
        }

        for (label, value) in [
            ("transaction_id", &self.transaction_id),
            ("target_machine_digest", &self.target_machine_digest),
            ("plan_digest", &self.plan_digest),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(format!("{label} must be 64 lowercase hexadecimal characters"));
            }
        }

        if let Some(auth) = &self.authorization {
            if auth.issuer.is_empty() || auth.issuer.len() > MAX_ISSUER_BYTES {
                return Err("authorization issuer has invalid size".into());
            }
            if auth.evidence_digest.len() != 64
                || !auth
                    .evidence_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("authorization evidence digest is invalid".into());
            }
            if let Some(value) = &auth.signer_key_id {
                if value.is_empty() || value.len() > MAX_SIGNER_KEY_ID_BYTES {
                    return Err("authorization signer key id has invalid size".into());
                }
            }
            for (label, value) in [
                ("authorization challenge", &auth.challenge_blake3),
                ("authorization replay", &auth.replay_key),
            ] {
                if let Some(value) = value {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    {
                        return Err(format!("{label} digest is invalid"));
                    }
                }
            }
        }

        if let Some(validation) = &self.validation {
            if validation.evidence_digest.len() != 64
                || !validation
                    .evidence_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("validation evidence digest is invalid".into());
            }
            if validation.summary.len() > MAX_SUMMARY_BYTES {
                return Err("validation summary exceeds wire limit".into());
            }
        }

        if let Some(snapshot) = &self.snapshot {
            for (label, value) in [
                ("snapshot pre-state", &snapshot.pre_state_digest),
                ("snapshot recovery", &snapshot.recovery_binding_digest),
            ] {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(format!("{label} digest is invalid"));
                }
            }
        }

        if let Some(application) = &self.application {
            if application.command_digest.len() != 64
                || !application
                    .command_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("application command digest is invalid".into());
            }
            if application.finished_at_ms < application.started_at_ms {
                return Err("application receipt has an invalid time range".into());
            }
        }

        if let Some(verification) = &self.verification {
            for (label, value) in [
                ("verification post-state", &verification.post_state_digest),
                ("verification evidence", &verification.evidence_digest),
            ] {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(format!("{label} digest is invalid"));
                }
            }
        }

        if let Some(outcome) = &self.outcome {
            if let Some(reason) = &outcome.reason {
                if reason.len() > MAX_REASON_BYTES {
                    return Err("outcome reason exceeds wire limit".into());
                }
            }
        }

        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate_wire()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(*blake3::hash(bytes.as_slice()).as_bytes())
    }

    pub fn digest_hex(&self) -> Result<String, String> {
        self.digest().map(|digest| digest_hex(&digest))
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            TransactionPhase::Promoted | TransactionPhase::Recovered | TransactionPhase::Failed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::executor::NixOSCommand;
    use crate::action::ai_proposal_binding::{digest_artifact, ProposalArtifactKind};
    use crate::release_integrity::{
        RELEASE_MANIFEST_KIND, RELEASE_SCHEMA_VERSION, RELEASE_SIGNATURE_KIND, ReleaseArtifact,
        ReleaseManifest,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn plan() -> ChangePlan {
        ChangePlan::command_only(
            crate::action::change_covenant::MachineBinding::new("machine-a").unwrap(),
            NixOSCommand::RebuildSwitch {
                flake: None,
                extra_args: Vec::new(),
            },
            60_000,
        )
        .unwrap()
    }

    fn authorization(plan: &ChangePlan) -> ChangeAuthorization {
        ChangeAuthorization::from_verified_approval(plan, "test-owner", [7; 32]).unwrap()
    }

    fn ai_proposal_output(plan: &ChangePlan) -> Vec<u8> {
        AiProposalOutputIntent::new(plan.machine(), None, plan.command())
            .unwrap()
            .canonical_bytes()
            .unwrap()
    }

    fn raw_ai_proposal_output(plan: &ChangePlan) -> Vec<u8> {
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        serde_json::to_vec_pretty(&intent).unwrap()
    }

    #[cfg(target_os = "linux")]
    fn sign_current_process_release(
        release_root: &Path,
        resolver_source_relative_path: &str,
        source_bytes: &[u8],
        signing: &SigningKey,
    ) -> SignedReleaseManifest {
        use std::os::unix::fs::PermissionsExt;

        let runtime_path = std::fs::read_link("/proc/self/exe").unwrap();
        let runtime_path = runtime_path.canonicalize().unwrap();
        let runtime_relative = runtime_path
            .strip_prefix(release_root)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let source_path = release_root.join(resolver_source_relative_path);
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(&source_path, source_bytes).unwrap();

        let runtime_bytes = std::fs::read("/proc/self/exe").unwrap();
        let runtime_metadata = std::fs::metadata(&runtime_path).unwrap();
        let source_metadata = std::fs::metadata(&source_path).unwrap();
        let mut artifacts = vec![
            ReleaseArtifact {
                path: resolver_source_relative_path.into(),
                blake3: blake3::hash(source_bytes).to_hex().to_string(),
                size_bytes: source_bytes.len() as u64,
                executable: source_metadata.permissions().mode() & 0o111 != 0,
            },
            ReleaseArtifact {
                path: runtime_relative,
                blake3: blake3::hash(&runtime_bytes).to_hex().to_string(),
                size_bytes: runtime_bytes.len() as u64,
                executable: runtime_metadata.permissions().mode() & 0o111 != 0,
            },
        ];
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "nixward-runtime-transaction-test".into(),
            created_at_ms: 1_800_000_000_000,
            source_revision: format!("test-revision-{}", std::process::id()),
            artifacts,
        };
        let signature = signing.sign(&manifest.signing_bytes().unwrap());
        SignedReleaseManifest {
            kind: RELEASE_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            signer_public_key_hex: signing
                .verifying_key()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            signature_hex: signature
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            manifest,
        }
    }

    fn ai_proposal(plan: &ChangePlan) -> AiProposalBinding {
        let output = ai_proposal_output(plan);
        AiProposalBinding::new(
            plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &output,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap()
    }

    #[test]
    fn external_wire_receipts_are_bounded_and_structurally_validated() {
        let mut tx = SystemTransaction::planned(&plan());
        assert!(tx.validate_wire().is_ok());

        tx.transaction_id = "A".repeat(64);
        assert!(tx.validate_wire().is_err());

        let mut tx = SystemTransaction::planned(&plan());
        tx.validation = Some(ValidationReceipt {
            evidence_digest: "00".repeat(32),
            summary: "x".repeat(MAX_SUMMARY_BYTES + 1),
        });
        assert!(tx.validate_wire().is_err());
    }

    #[test]
    fn wire_fixture_round_trips_with_stable_schema() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/system-transaction-v1.json"
        ));
        let parsed: SystemTransaction = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.schema, SYSTEM_TRANSACTION_SCHEMA);
        assert_eq!(parsed.version, SYSTEM_TRANSACTION_VERSION);
        assert_eq!(parsed.phase, TransactionPhase::Planned);
        assert!(!parsed.is_terminal());
        assert!(parsed.digest_hex().unwrap().len() == 64);
    }

    #[test]
    fn transaction_id_is_bound_to_plan_and_nonce() {
        let plan = plan();
        let tx = SystemTransaction::planned(&plan);
        assert_eq!(tx.plan_digest, digest_hex(&plan.digest()));
        assert_eq!(tx.target_machine_digest, digest_hex(&plan.machine().digest()));
        assert_eq!(tx.transaction_id, transaction_id(&plan));
    }

    #[test]
    fn ai_proposal_validation_is_committed_to_transaction_validation_receipt() {
        let plan = plan();
        let proposal = ai_proposal(&plan);
        let mut tx = SystemTransaction::planned(&plan);

        let evidence = tx
            .record_validation_with_ai_proposal(
                &plan,
                [31; 32],
                "validated proposal and policy",
                &proposal,
                b"model-artifact-v1",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                &ai_proposal_output(&plan),
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
            )
            .unwrap();

        assert_eq!(tx.phase, TransactionPhase::Validated);
        assert_eq!(evidence.plan_digest(), plan.digest());
        assert_eq!(evidence.validation_evidence_digest(), [31; 32]);
        assert_eq!(
            evidence.proposal_binding_digest(),
            proposal.digest().unwrap()
        );

        // The returned envelope is the persisted evidence whose digest is in the receipt.
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: AiProposalValidationEvidence = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.validate_for(&plan, &proposal).is_ok());
        assert_eq!(
            tx.validation.as_ref().unwrap().evidence_digest,
            digest_hex(&decoded.digest().unwrap())
        );
        assert!(tx.validate_wire().is_ok());

        // Provenance records evidence only; normal authorization remains required.
        assert!(tx.authorization.is_none());
        tx.authorize(&plan, &authorization(&plan)).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Authorized);
    }

    #[test]
    fn invalid_ai_proposal_artifact_leaves_transaction_unmodified() {
        let plan = plan();
        let proposal = ai_proposal(&plan);
        let mut tx = SystemTransaction::planned(&plan);

        let result = tx.record_validation_with_ai_proposal(
            &plan,
            [31; 32],
            "validated proposal and policy",
            &proposal,
            b"SUBSTITUTED-model-artifact",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &ai_proposal_output(&plan),
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        );

        assert!(result.is_err());
        assert_eq!(tx.phase, TransactionPhase::Planned);
        assert!(tx.validation.is_none());
        assert!(tx.authorization.is_none());
    }

    #[test]
    fn forged_binding_with_matching_digest_but_wrong_intent_does_not_advance_transaction() {
        let plan = plan();
        let wrong_command = NixOSCommand::Search {
            query: "nixpkgs#different".into(),
            json: true,
        };
        let wrong_output = AiProposalOutputIntent::new(
            plan.machine(),
            None,
            Some(&wrong_command),
        )
        .unwrap()
        .canonical_bytes()
        .unwrap();

        // Simulate a decoded, attacker-constructed envelope whose output digest
        // honestly matches the wrong bytes. The digest alone must not suffice.
        let mut value = serde_json::to_value(ai_proposal(&plan)).unwrap();
        let output_digest =
            digest_artifact(ProposalArtifactKind::ProposalOutput, &wrong_output);
        value["proposal_output_digest"] = serde_json::json!(digest_hex(&output_digest));
        let forged: AiProposalBinding = serde_json::from_value(value).unwrap();

        let mut tx = SystemTransaction::planned(&plan);
        let result = tx.record_validation_with_ai_proposal(
            &plan,
            [31; 32],
            "validated proposal and policy",
            &forged,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &wrong_output,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        );

        assert!(result
            .unwrap_err()
            .contains("AI proposal output intent does not exactly match the ChangePlan"));
        assert_eq!(tx.phase, TransactionPhase::Planned);
        assert!(tx.validation.is_none());
        assert!(tx.authorization.is_none());
    }

    #[test]
    fn resolved_ai_proposal_commits_raw_output_and_resolver_receipt_before_validation() {
        let plan = plan();
        let raw = raw_ai_proposal_output(&plan);
        let (resolution, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let proposal = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &canonical,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap();

        let mut tx = SystemTransaction::planned(&plan);
        let evidence = tx
            .record_validation_with_resolved_ai_proposal(
                &plan,
                [32; 32],
                "resolved and validated model proposal",
                &proposal,
                &resolution,
                &raw,
                &canonical,
                b"model-artifact-v1",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
            )
            .unwrap();

        assert_eq!(tx.phase, TransactionPhase::Validated);
        assert_eq!(evidence.plan_digest(), plan.digest());
        assert_eq!(evidence.validation_evidence_digest(), [32; 32]);
        assert_eq!(
            evidence.resolution_receipt_digest(),
            resolution.digest().unwrap()
        );
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: AiProposalResolvedValidationEvidence =
            serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.validate_for(&plan, &proposal, &resolution, &raw, &canonical).is_ok());
        assert_eq!(
            tx.validation.as_ref().unwrap().evidence_digest,
            digest_hex(&decoded.digest().unwrap())
        );
        assert!(tx.validate_wire().is_ok());

        // Even resolved evidence is not authority.
        assert!(tx.authorization.is_none());
        tx.authorize(&plan, &authorization(&plan)).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Authorized);
    }

    #[test]
    fn resolved_ai_proposal_rejects_raw_response_substitution_without_state_change() {
        let plan = plan();
        let raw = raw_ai_proposal_output(&plan);
        let (resolution, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let proposal = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &canonical,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap();
        let mut substituted_raw = raw.clone();
        substituted_raw.push(b' '); // Same parsed intent, different exact source bytes.

        let mut tx = SystemTransaction::planned(&plan);
        let result = tx.record_validation_with_resolved_ai_proposal(
            &plan,
            [32; 32],
            "resolved and validated model proposal",
            &proposal,
            &resolution,
            &substituted_raw,
            &canonical,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        );

        assert!(result.unwrap_err().contains("AI proposal resolution receipt does not match"));
        assert_eq!(tx.phase, TransactionPhase::Planned);
        assert!(tx.validation.is_none());
        assert!(tx.authorization.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_verified_proposal_validation_binds_signed_current_executable() {
        let plan = plan();
        let raw = raw_ai_proposal_output(&plan);
        let (resolution, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let proposal = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &canonical,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap();

        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let release_root = executable.parent().unwrap().to_path_buf();
        let source_path = format!(
            "share/nixward/runtime-evidence-positive-{}.rs",
            std::process::id()
        );
        let signing = SigningKey::from_bytes(&[121u8; 32]);
        let signed = sign_current_process_release(
            &release_root,
            &source_path,
            include_bytes!("ai_proposal_binding.rs"),
            &signing,
        );
        let trusted_key: String = signing
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let mut tx = SystemTransaction::planned(&plan);
        let evidence = tx
            .record_validation_with_runtime_verified_ai_proposal(
                &plan,
                [33; 32],
                "release-verified proposal",
                &proposal,
                &resolution,
                &raw,
                &canonical,
                b"model-artifact-v1",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
                &release_root,
                &signed,
                &trusted_key,
                &source_path,
            )
            .unwrap();

        assert_eq!(tx.phase, TransactionPhase::Validated);
        assert_eq!(evidence.plan_digest(), plan.digest());
        assert_eq!(
            evidence.resolution_receipt_digest(),
            resolution.digest().unwrap()
        );
        assert_ne!(evidence.runtime_binding_digest(), [0; 32]);
        assert_eq!(
            tx.validation.as_ref().unwrap().evidence_digest,
            digest_hex(&evidence.digest().unwrap())
        );
        assert!(tx.authorization.is_none());

        // Signed provenance binds code/runtime identity, but does not confer authority.
        tx.authorize(&plan, &authorization(&plan)).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Authorized);
        std::fs::remove_file(release_root.join(&source_path)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_verified_proposal_rejects_untrusted_release_root_without_state_change() {
        let plan = plan();
        let raw = raw_ai_proposal_output(&plan);
        let (resolution, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let proposal = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &canonical,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap();

        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let release_root = executable.parent().unwrap().to_path_buf();
        let source_path = format!(
            "share/nixward/runtime-evidence-untrusted-{}.rs",
            std::process::id()
        );
        let signing = SigningKey::from_bytes(&[122u8; 32]);
        let signed = sign_current_process_release(
            &release_root,
            &source_path,
            include_bytes!("ai_proposal_binding.rs"),
            &signing,
        );
        let wrong_trust_root = SigningKey::from_bytes(&[123u8; 32]);
        let wrong_key: String = wrong_trust_root
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let mut tx = SystemTransaction::planned(&plan);
        let result = tx.record_validation_with_runtime_verified_ai_proposal(
            &plan,
            [33; 32],
            "release-verified proposal",
            &proposal,
            &resolution,
            &raw,
            &canonical,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
            &release_root,
            &signed,
            &wrong_key,
            &source_path,
        );

        assert!(result.unwrap_err().contains("release signature verification failed"));
        assert_eq!(tx.phase, TransactionPhase::Planned);
        assert!(tx.validation.is_none());
        assert!(tx.authorization.is_none());
        std::fs::remove_file(release_root.join(&source_path)).unwrap();
    }

    #[test]
    fn snapshot_requires_authorization_even_after_validation() {
        let plan = plan();
        let mut tx = SystemTransaction::planned(&plan);
        tx.record_validation(&plan, [3; 32], "validation").unwrap();
        assert!(tx.record_snapshot(&plan, [4; 32], [5; 32]).is_err());

        tx.authorize(&plan, &authorization(&plan)).unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();
    }

    #[test]
    fn lifecycle_is_fail_closed_and_terminal() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);

        assert!(tx.record_snapshot(&plan, [1; 32], [2; 32]).is_err());
        assert!(tx.authorize(&plan, &auth).is_err());
        tx.record_validation(&plan, [3; 32], "syntax + policy validation")
            .unwrap();
        tx.authorize(&plan, &auth).unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();

        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 0).unwrap();
        tx.record_verification(&plan, [6; 32], [8; 32], Some(true))
            .unwrap();
        tx.promote(&plan).unwrap();

        assert_eq!(tx.phase, TransactionPhase::Promoted);
        assert!(tx.is_terminal());
        assert_eq!(tx.digest_hex().unwrap().len(), 64);
    }

    #[test]
    fn failed_apply_can_only_finish_as_recovery_or_failure() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);
        tx.record_validation(&plan, [3; 32], "validation").unwrap();
        tx.authorize(&plan, &auth).unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();

        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 1).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Failed);
        assert!(tx.promote(&plan).is_err());

        tx.recover(&plan, "restored previous generation").unwrap();
        assert_eq!(tx.phase, TransactionPhase::Recovered);
        assert!(tx.is_terminal());
    }

    #[test]
    fn unhealthy_boot_cannot_be_promoted() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);
        tx.record_validation(&plan, [3; 32], "validation").unwrap();
        tx.authorize(&plan, &auth).unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();
        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 0).unwrap();
        tx.record_verification(&plan, [6; 32], [8; 32], Some(false))
            .unwrap();
        assert!(tx.promote(&plan).is_err());
    }
}
