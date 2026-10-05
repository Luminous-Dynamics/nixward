// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-authorized production activation covenant for workload-aware networking.
//!
//! V46 is the missing production rung after V40/V42/V44.  A lab attestation is
//! backend-maturity evidence, not permission to mutate a real Holon.  An
//! activation must bind the exact enforcement plan, production-readiness join,
//! target system closure, BPF object, policy generation, prior activation state,
//! and an owner signature whose action is specifically `network-activate`.

use crate::authority_signature::VerifiedSignatureEvidence;
use crate::network_enforcement::{NetworkEnforcementPlan, NetworkProductionReadiness};
use crate::network_runtime_lab::NETWORK_RUNTIME_LAB_BACKEND;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const INTENT_DOMAIN: &[u8] = b"symthaea:nixward:network-activation-intent:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"symthaea:nixward:network-activation-receipt:v1\0";

pub const NETWORK_ACTIVATION_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_ACTIVATION_STATUS: &str = "owner-authorized-production-activation-v46";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkActivationOperation {
    Activate,
    ReplaceGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkActivationIntent {
    pub schema_version: u32,
    pub holon_id: String,
    pub operation: NetworkActivationOperation,
    pub backend: String,
    pub enforcement_plan_blake3: String,
    pub production_readiness_blake3: String,
    pub network_policy_blake3: String,
    pub target_system_toplevel: String,
    pub bpf_object_blake3: String,
    pub target_policy_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_activation_receipt_blake3: Option<String>,
    pub rollback_invariant: String,
    pub reasoning_authority: String,
}

impl NetworkActivationIntent {
    pub fn new(
        holon_id: impl Into<String>,
        operation: NetworkActivationOperation,
        plan: &NetworkEnforcementPlan,
        readiness: &NetworkProductionReadiness,
        target_system_toplevel: impl Into<String>,
        bpf_object_blake3: impl Into<String>,
        target_policy_generation: u64,
        prior_activation_receipt_blake3: Option<String>,
    ) -> Result<Self, NetworkActivationError> {
        plan.validate()?;
        readiness.validate()?;
        if readiness.enforcement_plan_blake3 != plan.digest_hex()?
            || readiness.backend != plan.backend
            || readiness.backend != NETWORK_RUNTIME_LAB_BACKEND
        {
            return Err(NetworkActivationError::ReadinessMismatch);
        }
        let intent = Self {
            schema_version: NETWORK_ACTIVATION_SCHEMA_VERSION,
            holon_id: holon_id.into(),
            operation,
            backend: plan.backend.clone(),
            enforcement_plan_blake3: plan.digest_hex()?,
            production_readiness_blake3: readiness.digest_hex()?,
            network_policy_blake3: plan.network_policy_blake3.clone(),
            target_system_toplevel: target_system_toplevel.into(),
            bpf_object_blake3: bpf_object_blake3.into(),
            target_policy_generation,
            prior_activation_receipt_blake3,
            rollback_invariant: "preserve-nixos-nftables-baseline-v46".into(),
            reasoning_authority: "none".into(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), NetworkActivationError> {
        if self.schema_version != NETWORK_ACTIVATION_SCHEMA_VERSION {
            return Err(NetworkActivationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.holon_id.trim().is_empty() || self.holon_id.contains('\0') {
            return Err(NetworkActivationError::InvalidIntent(
                "invalid Holon identity".into(),
            ));
        }
        if self.backend != NETWORK_RUNTIME_LAB_BACKEND {
            return Err(NetworkActivationError::InvalidIntent(
                "backend identity drifted".into(),
            ));
        }
        for digest in [
            &self.enforcement_plan_blake3,
            &self.production_readiness_blake3,
            &self.network_policy_blake3,
            &self.bpf_object_blake3,
        ] {
            validate_digest(digest)?;
        }
        if let Some(previous) = &self.prior_activation_receipt_blake3 {
            validate_digest(previous)?;
        }
        if matches!(
            self.operation,
            NetworkActivationOperation::ReplaceGeneration
        ) && self.prior_activation_receipt_blake3.is_none()
        {
            return Err(NetworkActivationError::InvalidIntent(
                "generation replacement must bind the exact prior activation receipt".into(),
            ));
        }
        if self.target_policy_generation == 0 {
            return Err(NetworkActivationError::InvalidIntent(
                "policy generation must be non-zero".into(),
            ));
        }
        if !self.target_system_toplevel.starts_with("/nix/store/")
            || self.target_system_toplevel.contains('\0')
        {
            return Err(NetworkActivationError::InvalidIntent(
                "target system must be an exact /nix/store toplevel".into(),
            ));
        }
        if self.rollback_invariant != "preserve-nixos-nftables-baseline-v46" {
            return Err(NetworkActivationError::InvalidIntent(
                "ordinary NixOS/nftables baseline must survive activation failure".into(),
            ));
        }
        if self.reasoning_authority != "none" {
            return Err(NetworkActivationError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkActivationError> {
        self.validate()?;
        hash_json(INTENT_DOMAIN, self)
    }
}

/// Non-deserializable capability proving that the owner authorized one exact
/// production network activation intent.
#[derive(Debug, Clone)]
pub struct AuthorizedNetworkActivation {
    pub intent: NetworkActivationIntent,
    pub authority_evidence_blake3: String,
    pub signer_key_id: String,
    pub replay_key: String,
}

impl AuthorizedNetworkActivation {
    pub fn authorize(
        intent: NetworkActivationIntent,
        evidence: &VerifiedSignatureEvidence,
    ) -> Result<Self, NetworkActivationError> {
        intent.validate()?;
        let digest = intent.digest_hex()?;
        if evidence.subject_blake3 != digest {
            return Err(NetworkActivationError::AuthoritySubjectMismatch);
        }
        if evidence.claims.get("authority_action").map(String::as_str) != Some("network-activate") {
            return Err(NetworkActivationError::AuthorityActionMismatch);
        }
        validate_digest(&evidence.evidence_blake3)?;
        validate_digest(&evidence.replay_key)?;
        Ok(Self {
            intent,
            authority_evidence_blake3: evidence.evidence_blake3.clone(),
            signer_key_id: evidence.signer_key_id.clone(),
            replay_key: evidence.replay_key.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkKernelAttachmentObservation {
    pub hook: String,
    pub cgroup_path: String,
    pub program_id: u32,
    pub program_tag: String,
    pub map_ids: Vec<u32>,
}

impl NetworkKernelAttachmentObservation {
    fn validate(&self) -> Result<(), NetworkActivationError> {
        if !matches!(
            self.hook.as_str(),
            "connect4" | "connect6" | "sendmsg4" | "sendmsg6"
        ) || !self.cgroup_path.starts_with('/')
            || self.cgroup_path.contains("..")
            || self.program_id == 0
            || self.program_tag.trim().is_empty()
            || self.program_tag.contains('\0')
        {
            return Err(NetworkActivationError::InvalidReceipt(
                "invalid kernel attachment observation".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkActivationReceipt {
    pub schema_version: u32,
    pub status: String,
    pub holon_id: String,
    pub activation_intent_blake3: String,
    pub enforcement_plan_blake3: String,
    pub production_readiness_blake3: String,
    pub network_policy_blake3: String,
    pub target_system_toplevel: String,
    pub bpf_object_blake3: String,
    pub activated_policy_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_activation_receipt_blake3: Option<String>,
    pub authority_evidence_blake3: String,
    pub signer_key_id: String,
    pub attachments: Vec<NetworkKernelAttachmentObservation>,
    pub allow_smoke_test_passed: bool,
    pub deny_smoke_test_passed: bool,
    pub nftables_baseline_preserved: bool,
    pub reasoning_authority: String,
}

impl NetworkActivationReceipt {
    pub fn seal(
        authorized: &AuthorizedNetworkActivation,
        attachments: Vec<NetworkKernelAttachmentObservation>,
        allow_smoke_test_passed: bool,
        deny_smoke_test_passed: bool,
        nftables_baseline_preserved: bool,
    ) -> Result<Self, NetworkActivationError> {
        let intent = &authorized.intent;
        intent.validate()?;
        let receipt = Self {
            schema_version: NETWORK_ACTIVATION_SCHEMA_VERSION,
            status: "activated-and-observed-v46".into(),
            holon_id: intent.holon_id.clone(),
            activation_intent_blake3: intent.digest_hex()?,
            enforcement_plan_blake3: intent.enforcement_plan_blake3.clone(),
            production_readiness_blake3: intent.production_readiness_blake3.clone(),
            network_policy_blake3: intent.network_policy_blake3.clone(),
            target_system_toplevel: intent.target_system_toplevel.clone(),
            bpf_object_blake3: intent.bpf_object_blake3.clone(),
            activated_policy_generation: intent.target_policy_generation,
            prior_activation_receipt_blake3: intent.prior_activation_receipt_blake3.clone(),
            authority_evidence_blake3: authorized.authority_evidence_blake3.clone(),
            signer_key_id: authorized.signer_key_id.clone(),
            attachments,
            allow_smoke_test_passed,
            deny_smoke_test_passed,
            nftables_baseline_preserved,
            reasoning_authority: "none".into(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), NetworkActivationError> {
        if self.schema_version != NETWORK_ACTIVATION_SCHEMA_VERSION {
            return Err(NetworkActivationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.status != "activated-and-observed-v46" || self.reasoning_authority != "none" {
            return Err(NetworkActivationError::AuthorityEscalation);
        }
        for digest in [
            &self.activation_intent_blake3,
            &self.enforcement_plan_blake3,
            &self.production_readiness_blake3,
            &self.network_policy_blake3,
            &self.bpf_object_blake3,
            &self.authority_evidence_blake3,
        ] {
            validate_digest(digest)?;
        }
        if let Some(previous) = &self.prior_activation_receipt_blake3 {
            validate_digest(previous)?;
        }
        if self.activated_policy_generation == 0
            || !self.target_system_toplevel.starts_with("/nix/store/")
            || self.attachments.is_empty()
            || !self.allow_smoke_test_passed
            || !self.deny_smoke_test_passed
            || !self.nftables_baseline_preserved
        {
            return Err(NetworkActivationError::InvalidReceipt(
                "activation receipt is missing required post-activation proof".into(),
            ));
        }
        for attachment in &self.attachments {
            attachment.validate()?;
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkActivationError> {
        self.validate()?;
        hash_json(RECEIPT_DOMAIN, self)
    }
}

pub fn network_activation_policy_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_ACTIVATION_SCHEMA_VERSION,
        "kind": "symthaea-network-activation-policy-v1",
        "status": NETWORK_ACTIVATION_STATUS,
        "source_claim": "not-activated-by-generated-source",
        "owner_authorization": "detached-network-activate-signature-required",
        "production_readiness": "v42-v44-lab-plus-target-proof-required",
        "post_activation": {
            "exact-kernel-attachments": true,
            "allow-smoke-test": true,
            "deny-smoke-test": true,
            "preserve-nftables-baseline": true
        },
        "reasoning_authority": "none",
        "automatic_activation": false
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| "{\"schema_version\":1,\"status\":\"serialization-failed\"}\n".into())
}

fn validate_digest(value: &str) -> Result<(), NetworkActivationError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetworkActivationError::InvalidDigest);
    }
    Ok(())
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkActivationError> {
    let bytes = serde_json::to_vec(value).map_err(|_| NetworkActivationError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error)]
pub enum NetworkActivationError {
    #[error("unsupported network activation schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid BLAKE3 digest")]
    InvalidDigest,
    #[error("network activation intent is invalid: {0}")]
    InvalidIntent(String),
    #[error("network activation receipt is invalid: {0}")]
    InvalidReceipt(String),
    #[error("network production readiness does not match the exact enforcement plan")]
    ReadinessMismatch,
    #[error("detached authority subject is not the exact activation intent")]
    AuthoritySubjectMismatch,
    #[error("detached authority is not permitted for network activation")]
    AuthorityActionMismatch,
    #[error("reasoning plane may not become activation authority")]
    AuthorityEscalation,
    #[error("network activation evidence serialization failed")]
    Serialization,
    #[error("network enforcement evidence error: {0}")]
    Enforcement(#[from] crate::network_enforcement::NetworkEnforcementError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn evidence(subject: String) -> VerifiedSignatureEvidence {
        let mut claims = BTreeMap::new();
        claims.insert("authority_action".into(), "network-activate".into());
        VerifiedSignatureEvidence {
            issuer: "owner".into(),
            signer_key_id: "owner-root".into(),
            evidence_blake3: "aa".repeat(32),
            subject_blake3: subject,
            challenge_blake3: "bb".repeat(32),
            replay_key: "cc".repeat(32),
            claims,
        }
    }

    #[test]
    fn generated_policy_cannot_claim_activation() {
        let policy: serde_json::Value =
            serde_json::from_str(&network_activation_policy_json()).unwrap();
        assert_eq!(policy["source_claim"], "not-activated-by-generated-source");
        assert_eq!(policy["automatic_activation"], false);
        assert_eq!(policy["reasoning_authority"], "none");
    }

    #[test]
    fn authorization_capability_requires_network_activate_action() {
        let intent = NetworkActivationIntent {
            schema_version: 1,
            holon_id: "holon-a".into(),
            operation: NetworkActivationOperation::Activate,
            backend: NETWORK_RUNTIME_LAB_BACKEND.into(),
            enforcement_plan_blake3: "11".repeat(32),
            production_readiness_blake3: "22".repeat(32),
            network_policy_blake3: "33".repeat(32),
            target_system_toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system".into(),
            bpf_object_blake3: "44".repeat(32),
            target_policy_generation: 1,
            prior_activation_receipt_blake3: None,
            rollback_invariant: "preserve-nixos-nftables-baseline-v46".into(),
            reasoning_authority: "none".into(),
        };
        let subject = intent.digest_hex().unwrap();
        assert!(AuthorizedNetworkActivation::authorize(intent.clone(), &evidence(subject)).is_ok());
        let mut wrong = evidence(intent.digest_hex().unwrap());
        wrong
            .claims
            .insert("authority_action".into(), "change".into());
        assert!(matches!(
            AuthorizedNetworkActivation::authorize(intent, &wrong),
            Err(NetworkActivationError::AuthorityActionMismatch)
        ));
    }
}
