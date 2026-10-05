// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Change Covenant — canonical, evidence-bound host mutation plans.
//!
//! A privileged change is not "a command plus some approval". It is one exact
//! plan that binds the target machine, optional configuration mutation, exact
//! structured command, rollback state, freshness window, and a unique nonce.
//! Approval evidence is then bound to the digest of that whole plan.

use super::config_writer::ConfigPatch;
use super::execution_intent::VerifiedExecutionBundle;
use super::executor::NixOSCommand;
use crate::authority_signature::VerifiedSignatureEvidence;
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CHANGE_PLAN_DOMAIN: &[u8] = b"nixward-change-plan-v1\0";
const MACHINE_BINDING_DOMAIN: &[u8] = b"nixward-machine-binding-v1\0";
const NONCE_DOMAIN: &[u8] = b"nixward-change-nonce-v1\0";
const MAX_PLAN_TTL_MS: u64 = 5 * 60 * 1000;
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn digest_text(value: &str) -> [u8; 32] {
    *blake3::hash(value.as_bytes()).as_bytes()
}

fn short_hex(digest: &[u8; 32]) -> String {
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Stable identity of the machine a change is allowed to mutate.
///
/// `/etc/machine-id` is not treated as a secret or hardware attestation. It is
/// a practical anti-confusion/anti-cross-host binding. TPM-backed identity can
/// replace or augment this value without changing the ChangePlan contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineBinding {
    machine_id: String,
    binding_digest: [u8; 32],
}

impl MachineBinding {
    pub fn new(machine_id: impl Into<String>) -> Result<Self, String> {
        let machine_id = machine_id.into();
        let trimmed = machine_id.trim();
        if trimmed.is_empty() {
            return Err("machine binding must not be empty".into());
        }
        if trimmed.len() > 256 {
            return Err("machine binding exceeds 256 bytes".into());
        }
        if trimmed.chars().any(char::is_control) {
            return Err("machine binding contains control characters".into());
        }
        let machine_id = trimmed.to_string();
        let binding_digest = hash_bytes(MACHINE_BINDING_DOMAIN, machine_id.as_bytes());
        Ok(Self {
            machine_id,
            binding_digest,
        })
    }

    /// Bind to the local host's systemd machine-id. Fail closed when it is not
    /// available rather than silently authorizing a generic/unknown machine.
    pub fn local() -> io::Result<Self> {
        let machine_id = std::fs::read_to_string("/etc/machine-id")?;
        Self::new(machine_id).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    pub fn digest(&self) -> [u8; 32] {
        self.binding_digest
    }
}

/// Digest-only binding of an exact configuration file transformation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigMutationBinding {
    target: String,
    original_digest: [u8; 32],
    modified_digest: [u8; 32],
    description_digest: [u8; 32],
}

impl ConfigMutationBinding {
    pub fn from_patch(patch: &ConfigPatch) -> Result<Self, String> {
        let target = patch
            .target
            .to_str()
            .ok_or_else(|| "configuration target path is not valid UTF-8".to_string())?
            .to_string();
        if target.trim().is_empty() {
            return Err("configuration target path must not be empty".into());
        }
        Ok(Self {
            target,
            original_digest: digest_text(&patch.original),
            modified_digest: digest_text(&patch.modified),
            description_digest: digest_text(&patch.description),
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn original_digest(&self) -> [u8; 32] {
        self.original_digest
    }

    pub fn modified_digest(&self) -> [u8; 32] {
        self.modified_digest
    }

    pub fn matches_patch(&self, patch: &ConfigPatch) -> bool {
        Self::from_patch(patch).is_ok_and(|candidate| candidate == *self)
    }
}

/// Rollback state captured when the plan is created, before approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackBinding {
    /// Exact configuration bytes to restore are identified by this digest.
    config_restore_digest: Option<[u8; 32]>,
    /// Exact structured rollback command, if the primary command provides one.
    command_digest: Option<[u8; 32]>,
}

impl RollbackBinding {
    pub fn config_restore_digest(&self) -> Option<[u8; 32]> {
        self.config_restore_digest
    }

    pub fn command_digest(&self) -> Option<[u8; 32]> {
        self.command_digest
    }
}

/// Canonical intent for one privileged host transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePlan {
    version: u16,
    machine: MachineBinding,
    config_mutation: Option<ConfigMutationBinding>,
    command: Option<NixOSCommand>,
    rollback: RollbackBinding,
    nonce: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl ChangePlan {
    fn build(
        machine: MachineBinding,
        config_mutation: Option<ConfigMutationBinding>,
        command: Option<NixOSCommand>,
        ttl_ms: u64,
    ) -> Result<Self, String> {
        if config_mutation.is_none() && command.is_none() {
            return Err("change plan must contain a config mutation or command".into());
        }
        if ttl_ms == 0 || ttl_ms > MAX_PLAN_TTL_MS {
            return Err(format!(
                "change plan TTL must be in 1..={MAX_PLAN_TTL_MS} ms"
            ));
        }

        let issued_at_ms = now_ms();
        let expires_at_ms = issued_at_ms.saturating_add(ttl_ms);
        let rollback = RollbackBinding {
            config_restore_digest: config_mutation.as_ref().map(|c| c.original_digest),
            command_digest: command
                .as_ref()
                .and_then(NixOSCommand::rollback_command)
                .map(|rollback| rollback.command_digest()),
        };

        let nonce = Self::fresh_nonce(
            &machine,
            config_mutation.as_ref(),
            command.as_ref(),
            issued_at_ms,
        );

        Ok(Self {
            version: 1,
            machine,
            config_mutation,
            command,
            rollback,
            nonce,
            issued_at_ms,
            expires_at_ms,
        })
    }

    pub fn command_only(
        machine: MachineBinding,
        command: NixOSCommand,
        ttl_ms: u64,
    ) -> Result<Self, String> {
        Self::build(machine, None, Some(command), ttl_ms)
    }

    pub fn config_only(
        machine: MachineBinding,
        patch: &ConfigPatch,
        ttl_ms: u64,
    ) -> Result<Self, String> {
        Self::build(
            machine,
            Some(ConfigMutationBinding::from_patch(patch)?),
            None,
            ttl_ms,
        )
    }

    pub fn config_and_command(
        machine: MachineBinding,
        patch: &ConfigPatch,
        command: NixOSCommand,
        ttl_ms: u64,
    ) -> Result<Self, String> {
        Self::build(
            machine,
            Some(ConfigMutationBinding::from_patch(patch)?),
            Some(command),
            ttl_ms,
        )
    }

    fn fresh_nonce(
        machine: &MachineBinding,
        config: Option<&ConfigMutationBinding>,
        command: Option<&NixOSCommand>,
        issued_at_ms: u64,
    ) -> [u8; 32] {
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = blake3::Hasher::new();
        hasher.update(NONCE_DOMAIN);
        hasher.update(&issued_at_ms.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(&machine.digest());
        if let Some(config) = config {
            hasher.update(&config.modified_digest);
        }
        if let Some(command) = command {
            hasher.update(&command.command_digest());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn digest(&self) -> [u8; 32] {
        let encoded = serde_json::to_vec(self)
            .expect("ChangePlan serialization is infallible for in-memory fields");
        hash_bytes(CHANGE_PLAN_DOMAIN, &encoded)
    }

    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    pub fn machine(&self) -> &MachineBinding {
        &self.machine
    }

    pub fn config_mutation(&self) -> Option<&ConfigMutationBinding> {
        self.config_mutation.as_ref()
    }

    pub fn command(&self) -> Option<&NixOSCommand> {
        self.command.as_ref()
    }

    pub fn rollback(&self) -> &RollbackBinding {
        &self.rollback
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn validate_fresh(&self) -> Result<(), String> {
        if now_ms() > self.expires_at_ms {
            return Err("change plan expired".into());
        }
        Ok(())
    }

    pub fn validate_machine(&self, machine: &MachineBinding) -> Result<(), String> {
        if &self.machine != machine {
            return Err("change plan is bound to a different machine".into());
        }
        Ok(())
    }

    pub fn validate_patch(&self, patch: &ConfigPatch) -> Result<(), String> {
        let Some(expected) = &self.config_mutation else {
            return Err("change plan does not authorize a configuration mutation".into());
        };
        if !expected.matches_patch(patch) {
            return Err("configuration patch differs from the approved change plan".into());
        }
        Ok(())
    }

    pub fn validate_command(&self, command: &NixOSCommand) -> Result<(), String> {
        let Some(expected) = &self.command else {
            return Err("change plan does not authorize command execution".into());
        };
        if expected.command_digest() != command.command_digest() {
            return Err("command differs from the approved change plan".into());
        }
        Ok(())
    }

    /// Compare the current proposed mutation with this already-issued plan.
    /// Freshness/nonce are intentionally not regenerated: the approved plan is
    /// reused only when the underlying machine, patch, and command are exact.
    pub fn matches_intent(
        &self,
        machine: &MachineBinding,
        patch: Option<&ConfigPatch>,
        command: Option<&NixOSCommand>,
    ) -> bool {
        if self.machine != *machine {
            return false;
        }
        let patch_matches = match (&self.config_mutation, patch) {
            (None, None) => true,
            (Some(expected), Some(candidate)) => expected.matches_patch(candidate),
            _ => false,
        };
        let command_matches = match (&self.command, command) {
            (None, None) => true,
            (Some(expected), Some(candidate)) => {
                expected.command_digest() == candidate.command_digest()
            }
            _ => false,
        };
        patch_matches && command_matches
    }
}

/// Classifies the independently verified evidence that authorized a change.
///
/// `ExecutionIntent` is reserved for the v34 intent + exact realization-plan
/// bundle.  It is intentionally distinct from generic approval evidence so an
/// ordinary ChangePlan approval cannot activate a framework-bound system closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalEvidenceKind {
    /// Transitional pre-v36 caller-supplied digest path. Not accepted for
    /// framework-bound immutable closure activation.
    GeneralChange,
    /// Transitional v35 execution-intent path. v36's executor deliberately
    /// refuses this class for ActivateSystemClosure.
    ExecutionIntent,
    /// AuthorityVerifier-backed general change approval.
    AuthoritySignature,
    /// AuthorityVerifier-backed exact v34 intent + realization approval.
    ExecutionIntentAuthority,
}

/// Verified approval evidence bound to one exact [`ChangePlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeAuthorization {
    plan_digest: [u8; 32],
    issuer: String,
    evidence_digest: [u8; 32],
    approval_evidence_kind: ApprovalEvidenceKind,
    execution_intent_digest: Option<[u8; 32]>,
    realization_plan_digest: Option<[u8; 32]>,
    authority_signer_key_id: Option<String>,
    authority_challenge_blake3: Option<String>,
    authority_replay_key: Option<String>,
    authority_subject_blake3: Option<String>,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl ChangeAuthorization {
    pub fn from_verified_approval(
        plan: &ChangePlan,
        issuer: impl Into<String>,
        evidence_digest: [u8; 32],
    ) -> Result<Self, String> {
        plan.validate_fresh()?;
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err("change authorization issuer must not be empty".into());
        }
        if evidence_digest == [0; 32] {
            return Err("change authorization requires non-zero evidence digest".into());
        }
        Ok(Self {
            plan_digest: plan.digest(),
            issuer,
            evidence_digest,
            approval_evidence_kind: ApprovalEvidenceKind::GeneralChange,
            execution_intent_digest: None,
            realization_plan_digest: None,
            authority_signer_key_id: None,
            authority_challenge_blake3: None,
            authority_replay_key: None,
            authority_subject_blake3: None,
            issued_at_ms: now_ms(),
            expires_at_ms: plan.expires_at_ms,
        })
    }

    /// Create approval evidence for one exact v34 Nixward execution intent.
    ///
    /// The verified bundle has private fields and can only be constructed by
    /// re-verifying the canonical execution-intent and realization-plan JSON.
    /// The target machine and immutable system closure must match the ChangePlan.
    pub fn from_verified_execution_intent(
        plan: &ChangePlan,
        issuer: impl Into<String>,
        approval_evidence_digest: [u8; 32],
        bundle: &VerifiedExecutionBundle,
    ) -> Result<Self, String> {
        plan.validate_fresh()?;
        if plan.machine().machine_id() != bundle.execution_target_identity() {
            return Err("execution intent targets a different machine".into());
        }
        let command = plan.command().ok_or_else(|| {
            "execution-intent authorization requires an executable command".to_string()
        })?;
        match command {
            NixOSCommand::ActivateSystemClosure { store_path, .. }
                if store_path == bundle.expected_out_path() => {}
            NixOSCommand::ActivateSystemClosure { .. } => {
                return Err("system closure differs from the verified realization plan".into());
            }
            _ => {
                return Err("execution-intent authorization requires ActivateSystemClosure".into());
            }
        }
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err("change authorization issuer must not be empty".into());
        }
        if approval_evidence_digest == [0; 32] {
            return Err(
                "execution-intent authorization requires non-zero approval evidence".into(),
            );
        }
        Ok(Self {
            plan_digest: plan.digest(),
            issuer,
            evidence_digest: approval_evidence_digest,
            approval_evidence_kind: ApprovalEvidenceKind::ExecutionIntent,
            execution_intent_digest: Some(bundle.intent_digest()),
            realization_plan_digest: Some(bundle.realization_plan_digest()),
            authority_signer_key_id: None,
            authority_challenge_blake3: None,
            authority_replay_key: None,
            authority_subject_blake3: None,
            issued_at_ms: now_ms(),
            expires_at_ms: plan.expires_at_ms,
        })
    }

    fn decode_authority_digest(label: &str, value: &str) -> Result<[u8; 32], String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid {label} authority digest"));
        }
        let mut out = [0u8; 32];
        let bytes = value.as_bytes();
        for index in 0..32 {
            let hi = (bytes[index * 2] as char)
                .to_digit(16)
                .ok_or_else(|| format!("invalid {label} authority digest"))?;
            let lo = (bytes[index * 2 + 1] as char)
                .to_digit(16)
                .ok_or_else(|| format!("invalid {label} authority digest"))?;
            out[index] = ((hi << 4) | lo) as u8;
        }
        Ok(out)
    }

    fn validate_verified_signature_evidence(
        evidence: &VerifiedSignatureEvidence,
        expected_subject: &str,
    ) -> Result<[u8; 32], String> {
        if evidence.issuer.trim().is_empty() || evidence.signer_key_id.trim().is_empty() {
            return Err("verified authority evidence omitted signer identity".into());
        }
        if evidence.subject_blake3.as_str() != expected_subject {
            return Err("verified authority evidence is bound to a different subject".into());
        }
        Self::decode_authority_digest("evidence", &evidence.evidence_blake3)?;
        Self::decode_authority_digest("challenge", &evidence.challenge_blake3)?;
        Self::decode_authority_digest("replay", &evidence.replay_key)?;
        Self::decode_authority_digest("subject", &evidence.subject_blake3)?;
        Self::decode_authority_digest("evidence", &evidence.evidence_blake3)
    }

    /// Construct a ChangeAuthorization only from opaque cryptographically
    /// verified authority evidence. This constructor is crate-private so callers
    /// cannot substitute strings for AuthorityVerifier's result.
    pub(crate) fn from_verified_authority_evidence(
        plan: &ChangePlan,
        evidence: &VerifiedSignatureEvidence,
        expected_subject: &str,
        signed_expires_at_ms: u64,
    ) -> Result<Self, String> {
        plan.validate_fresh()?;
        let evidence_digest =
            Self::validate_verified_signature_evidence(evidence, expected_subject)?;
        Ok(Self {
            plan_digest: plan.digest(),
            issuer: evidence.issuer.clone(),
            evidence_digest,
            approval_evidence_kind: ApprovalEvidenceKind::AuthoritySignature,
            execution_intent_digest: None,
            realization_plan_digest: None,
            authority_signer_key_id: Some(evidence.signer_key_id.clone()),
            authority_challenge_blake3: Some(evidence.challenge_blake3.clone()),
            authority_replay_key: Some(evidence.replay_key.clone()),
            authority_subject_blake3: Some(evidence.subject_blake3.clone()),
            issued_at_ms: now_ms(),
            expires_at_ms: plan.expires_at_ms.min(signed_expires_at_ms),
        })
    }

    /// Same as from_verified_authority_evidence, additionally binding the v34
    /// execution intent and exact immutable realization selected by v35.
    pub(crate) fn from_verified_execution_intent_authority_evidence(
        plan: &ChangePlan,
        bundle: &VerifiedExecutionBundle,
        evidence: &VerifiedSignatureEvidence,
        expected_subject: &str,
        signed_expires_at_ms: u64,
    ) -> Result<Self, String> {
        plan.validate_fresh()?;
        if plan.machine().machine_id() != bundle.execution_target_identity() {
            return Err("execution intent targets a different machine".into());
        }
        let command = plan.command().ok_or_else(|| {
            "execution-intent authority requires an executable command".to_string()
        })?;
        match command {
            NixOSCommand::ActivateSystemClosure { store_path, .. }
                if store_path == bundle.expected_out_path() => {}
            NixOSCommand::ActivateSystemClosure { .. } => {
                return Err("system closure differs from the verified realization plan".into());
            }
            _ => {
                return Err("execution-intent authority requires ActivateSystemClosure".into());
            }
        }
        let evidence_digest =
            Self::validate_verified_signature_evidence(evidence, expected_subject)?;
        Ok(Self {
            plan_digest: plan.digest(),
            issuer: evidence.issuer.clone(),
            evidence_digest,
            approval_evidence_kind: ApprovalEvidenceKind::ExecutionIntentAuthority,
            execution_intent_digest: Some(bundle.intent_digest()),
            realization_plan_digest: Some(bundle.realization_plan_digest()),
            authority_signer_key_id: Some(evidence.signer_key_id.clone()),
            authority_challenge_blake3: Some(evidence.challenge_blake3.clone()),
            authority_replay_key: Some(evidence.replay_key.clone()),
            authority_subject_blake3: Some(evidence.subject_blake3.clone()),
            issued_at_ms: now_ms(),
            expires_at_ms: plan.expires_at_ms.min(signed_expires_at_ms),
        })
    }

    pub fn validate_plan(&self, plan: &ChangePlan) -> Result<(), String> {
        plan.validate_fresh()?;
        self.validate_plan_binding(plan)?;
        if now_ms() > self.expires_at_ms {
            return Err("change authorization expired".into());
        }
        Ok(())
    }

    /// Validate immutable plan/evidence binding without requiring the approval
    /// window to still be open. This is crate-internal and exists only for an
    /// exact restorative rollback after a change began while authorization was
    /// fresh. It must never be used to initiate a new mutation.
    pub(crate) fn validate_plan_binding(&self, plan: &ChangePlan) -> Result<(), String> {
        if self.plan_digest != plan.digest() {
            return Err("approval evidence is bound to a different change plan".into());
        }
        if self.evidence_digest == [0; 32] {
            return Err("change authorization has no approval evidence".into());
        }
        let has_authority = self.authority_signer_key_id.is_some()
            && self.authority_challenge_blake3.is_some()
            && self.authority_replay_key.is_some()
            && self.authority_subject_blake3.is_some();
        let has_execution_intent =
            self.execution_intent_digest.is_some() && self.realization_plan_digest.is_some();
        let shape_is_valid = match self.approval_evidence_kind {
            ApprovalEvidenceKind::GeneralChange => !has_authority && !has_execution_intent,
            ApprovalEvidenceKind::ExecutionIntent => !has_authority && has_execution_intent,
            ApprovalEvidenceKind::AuthoritySignature => has_authority && !has_execution_intent,
            ApprovalEvidenceKind::ExecutionIntentAuthority => has_authority && has_execution_intent,
        };
        if !shape_is_valid {
            return Err(
                "change authorization evidence shape does not match its evidence class".into(),
            );
        }
        Ok(())
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    pub fn approval_evidence_kind(&self) -> ApprovalEvidenceKind {
        self.approval_evidence_kind
    }

    pub fn execution_intent_digest(&self) -> Option<[u8; 32]> {
        self.execution_intent_digest
    }

    pub fn realization_plan_digest(&self) -> Option<[u8; 32]> {
        self.realization_plan_digest
    }

    pub fn authority_signer_key_id(&self) -> Option<&str> {
        self.authority_signer_key_id.as_deref()
    }

    pub fn authority_challenge_blake3(&self) -> Option<&str> {
        self.authority_challenge_blake3.as_deref()
    }

    pub fn authority_replay_key(&self) -> Option<&str> {
        self.authority_replay_key.as_deref()
    }

    pub fn authority_subject_blake3(&self) -> Option<&str> {
        self.authority_subject_blake3.as_deref()
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn patch(modified: &str) -> ConfigPatch {
        ConfigPatch {
            target: PathBuf::from("/etc/nixos/configuration.nix"),
            original: "{ networking.hostName = \"before\"; }".into(),
            modified: modified.into(),
            description: "set hostname".into(),
        }
    }

    fn command() -> NixOSCommand {
        NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        }
    }

    #[test]
    fn plan_digest_binds_machine_patch_and_command() {
        let machine = MachineBinding::new("machine-a").unwrap();
        let first = ChangePlan::config_and_command(
            machine.clone(),
            &patch("{ networking.hostName = \"after\"; }"),
            command(),
            60_000,
        )
        .unwrap();

        assert!(first.matches_intent(
            &machine,
            Some(&patch("{ networking.hostName = \"after\"; }")),
            Some(&command())
        ));
        assert!(!first.matches_intent(
            &MachineBinding::new("machine-b").unwrap(),
            Some(&patch("{ networking.hostName = \"after\"; }")),
            Some(&command())
        ));
        assert!(!first.matches_intent(
            &machine,
            Some(&patch("{ networking.hostName = \"tampered\"; }")),
            Some(&command())
        ));
    }

    #[test]
    fn nonce_makes_reissued_plan_distinct() {
        let machine = MachineBinding::new("machine-a").unwrap();
        let first = ChangePlan::command_only(machine.clone(), command(), 60_000).unwrap();
        let second = ChangePlan::command_only(machine, command(), 60_000).unwrap();
        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn authorization_is_plan_bound() {
        let machine = MachineBinding::new("machine-a").unwrap();
        let first = ChangePlan::command_only(machine.clone(), command(), 60_000).unwrap();
        let second = ChangePlan::command_only(machine, command(), 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&first, "test-owner", [7; 32]).unwrap();
        assert!(auth.validate_plan(&first).is_ok());
        assert!(auth.validate_plan(&second).is_err());
    }

    #[test]
    fn rollback_binding_captures_prestate_and_command() {
        let p = patch("{ networking.hostName = \"after\"; }");
        let plan = ChangePlan::config_and_command(
            MachineBinding::new("machine-a").unwrap(),
            &p,
            command(),
            60_000,
        )
        .unwrap();
        assert_eq!(
            plan.rollback().config_restore_digest(),
            Some(digest_text(&p.original))
        );
        assert_eq!(
            plan.rollback().command_digest(),
            command().rollback_command().map(|c| c.command_digest())
        );
    }

    #[test]
    fn invalid_plan_or_approval_is_rejected() {
        let machine = MachineBinding::new("machine-a").unwrap();
        assert!(ChangePlan::command_only(machine.clone(), command(), 0).is_err());
        let plan = ChangePlan::command_only(machine, command(), 60_000).unwrap();
        assert!(ChangeAuthorization::from_verified_approval(&plan, "", [1; 32]).is_err());
        assert!(ChangeAuthorization::from_verified_approval(&plan, "owner", [0; 32]).is_err());
    }
}
