// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Isolated runtime-lab evidence for the V40 workload-aware network backend.
//!
//! V42 exists to prove that the *backend design* behaves correctly on a real
//! kernel before any production Holon is allowed to treat it as mature.  A lab
//! attestation is deliberately weaker than a target-host activation receipt:
//! passing the VM lab never means that a production cgroup has BPF attached.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const REPORT_DOMAIN: &[u8] = b"symthaea:nixward:network-runtime-lab-report:v1\0";
const ATTESTATION_DOMAIN: &[u8] = b"symthaea:nixward:network-runtime-lab-attestation:v1\0";

pub const NETWORK_RUNTIME_LAB_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_RUNTIME_LAB_BACKEND: &str = "cgroup-sockaddr-bpf-contract-v40";
pub const NETWORK_RUNTIME_LAB_STATUS: &str = "isolated-runtime-lab-v42";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkRuntimeLabCaseKind {
    FeatureProbe,
    Ipv4Allow,
    Ipv4Deny,
    Ipv6Allow,
    Ipv6Deny,
    UdpAllow,
    UdpDeny,
    LeaseActive,
    LeaseExpired,
    PolicySwap,
    CgroupRebind,
    EnforcerRestart,
    StalePolicyReplay,
    AttachFailureFailClosed,
}

impl NetworkRuntimeLabCaseKind {
    pub const REQUIRED: [Self; 14] = [
        Self::FeatureProbe,
        Self::Ipv4Allow,
        Self::Ipv4Deny,
        Self::Ipv6Allow,
        Self::Ipv6Deny,
        Self::UdpAllow,
        Self::UdpDeny,
        Self::LeaseActive,
        Self::LeaseExpired,
        Self::PolicySwap,
        Self::CgroupRebind,
        Self::EnforcerRestart,
        Self::StalePolicyReplay,
        Self::AttachFailureFailClosed,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRuntimeLabCaseResult {
    pub case_id: String,
    pub kind: NetworkRuntimeLabCaseKind,
    pub passed: bool,
    pub observed: String,
    pub evidence_blake3: String,
}

impl NetworkRuntimeLabCaseResult {
    fn validate(&self) -> Result<(), NetworkRuntimeLabError> {
        validate_token("case id", &self.case_id, 128)?;
        validate_token("observed result", &self.observed, 2048)?;
        validate_digest(&self.evidence_blake3)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRuntimeLabReport {
    pub schema_version: u32,
    pub backend: String,
    pub status: String,
    pub kernel_release: String,
    pub nixos_system: String,
    pub harness_blake3: String,
    pub isolated_environment: bool,
    pub payload_capture: bool,
    pub production_activation_performed: bool,
    pub reasoning_authority: String,
    pub cases: Vec<NetworkRuntimeLabCaseResult>,
}

impl NetworkRuntimeLabReport {
    pub fn validate(&self) -> Result<(), NetworkRuntimeLabError> {
        if self.schema_version != NETWORK_RUNTIME_LAB_SCHEMA_VERSION {
            return Err(NetworkRuntimeLabError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.backend != NETWORK_RUNTIME_LAB_BACKEND || self.status != NETWORK_RUNTIME_LAB_STATUS
        {
            return Err(NetworkRuntimeLabError::BackendIdentityDrift);
        }
        validate_token("kernel release", &self.kernel_release, 256)?;
        if !self.nixos_system.starts_with("/nix/store/") {
            return Err(NetworkRuntimeLabError::InvalidNixosSystem);
        }
        validate_digest(&self.harness_blake3)?;
        if !self.isolated_environment {
            return Err(NetworkRuntimeLabError::NotIsolated);
        }
        if self.payload_capture {
            return Err(NetworkRuntimeLabError::PayloadCaptureForbidden);
        }
        if self.production_activation_performed {
            return Err(NetworkRuntimeLabError::ProductionActivationClaim);
        }
        if self.reasoning_authority != "none" {
            return Err(NetworkRuntimeLabError::AuthorityEscalation);
        }

        let mut seen = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !seen.insert(case.kind) {
                return Err(NetworkRuntimeLabError::DuplicateCase(case.kind));
            }
        }
        for required in NetworkRuntimeLabCaseKind::REQUIRED {
            if !seen.contains(&required) {
                return Err(NetworkRuntimeLabError::MissingCase(required));
            }
        }
        if let Some(failed) = self.cases.iter().find(|case| !case.passed) {
            return Err(NetworkRuntimeLabError::FailedCase(failed.case_id.clone()));
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkRuntimeLabError> {
        self.validate()?;
        hash_json(REPORT_DOMAIN, self)
    }

    pub fn attest(&self) -> Result<NetworkBackendLabAttestation, NetworkRuntimeLabError> {
        self.validate()?;
        let attestation = NetworkBackendLabAttestation {
            schema_version: NETWORK_RUNTIME_LAB_SCHEMA_VERSION,
            backend: NETWORK_RUNTIME_LAB_BACKEND.into(),
            lab_report_blake3: self.digest_hex()?,
            kernel_release: self.kernel_release.clone(),
            nixos_system: self.nixos_system.clone(),
            status: "runtime-lab-proven-v42".into(),
            production_activation_authority: false,
            target_host_runtime_proof_required: true,
            owner_authorization_required: true,
            reasoning_authority: "none".into(),
        };
        attestation.validate()?;
        Ok(attestation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBackendLabAttestation {
    pub schema_version: u32,
    pub backend: String,
    pub lab_report_blake3: String,
    pub kernel_release: String,
    pub nixos_system: String,
    pub status: String,
    pub production_activation_authority: bool,
    pub target_host_runtime_proof_required: bool,
    pub owner_authorization_required: bool,
    pub reasoning_authority: String,
}

impl NetworkBackendLabAttestation {
    pub fn validate(&self) -> Result<(), NetworkRuntimeLabError> {
        if self.schema_version != NETWORK_RUNTIME_LAB_SCHEMA_VERSION {
            return Err(NetworkRuntimeLabError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.backend != NETWORK_RUNTIME_LAB_BACKEND || self.status != "runtime-lab-proven-v42" {
            return Err(NetworkRuntimeLabError::BackendIdentityDrift);
        }
        validate_digest(&self.lab_report_blake3)?;
        validate_token("kernel release", &self.kernel_release, 256)?;
        if !self.nixos_system.starts_with("/nix/store/") {
            return Err(NetworkRuntimeLabError::InvalidNixosSystem);
        }
        if self.production_activation_authority
            || !self.target_host_runtime_proof_required
            || !self.owner_authorization_required
            || self.reasoning_authority != "none"
        {
            return Err(NetworkRuntimeLabError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkRuntimeLabError> {
        self.validate()?;
        hash_json(ATTESTATION_DOMAIN, self)
    }
}

pub fn network_runtime_lab_policy_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_RUNTIME_LAB_SCHEMA_VERSION,
        "kind": "symthaea-network-runtime-lab-policy-v1",
        "status": "runtime-lab-required-v42",
        "backend": NETWORK_RUNTIME_LAB_BACKEND,
        "generated_source_claim": "not-run",
        "execution_harness": {
            "status": "executable-runner-v44",
            "runner": "tests/network-runtime-lab/run-runtime-lab.py",
            "report_requires_all_14_cases": true,
            "lab_attestation_requires_execution": true
        },
        "required_cases": [
            "feature-probe",
            "ipv4-allow",
            "ipv4-deny",
            "ipv6-allow",
            "ipv6-deny",
            "udp-allow",
            "udp-deny",
            "lease-active",
            "lease-expired",
            "policy-swap",
            "cgroup-rebind",
            "enforcer-restart",
            "stale-policy-replay",
            "attach-failure-fail-closed"
        ],
        "evidence_separation": {
            "lab_proves": "isolated-backend-behavior",
            "lab_does_not_prove": "production-holon-activation",
            "target_host_runtime_proof_required": true,
            "owner_authorization_required": true
        },
        "privacy": {
            "payload_capture": false
        },
        "authority": {
            "reasoning": "none",
            "production_activation": false
        }
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"status\":\"serialization-failed\"}}\n",
            NETWORK_RUNTIME_LAB_SCHEMA_VERSION
        )
    })
}

fn validate_digest(value: &str) -> Result<(), NetworkRuntimeLabError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NetworkRuntimeLabError::InvalidDigest)
    }
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), NetworkRuntimeLabError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(NetworkRuntimeLabError::InvalidToken(field))
    } else {
        Ok(())
    }
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkRuntimeLabError> {
    let encoded = serde_json::to_vec(value).map_err(|_| NetworkRuntimeLabError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkRuntimeLabError {
    #[error("unsupported network runtime-lab schema version {0}")]
    UnsupportedSchema(u32),
    #[error("network runtime-lab backend/status drifted from the reviewed V42 contract")]
    BackendIdentityDrift,
    #[error("invalid runtime-lab digest")]
    InvalidDigest,
    #[error("invalid runtime-lab token {0}")]
    InvalidToken(&'static str),
    #[error("runtime-lab NixOS system must be an exact /nix/store path")]
    InvalidNixosSystem,
    #[error("runtime-lab evidence must come from an isolated disposable environment")]
    NotIsolated,
    #[error("payload capture is forbidden in the V42 runtime lab")]
    PayloadCaptureForbidden,
    #[error("runtime-lab evidence may not claim production activation")]
    ProductionActivationClaim,
    #[error("runtime-lab evidence attempted to gain enforcement/reasoning authority")]
    AuthorityEscalation,
    #[error("runtime-lab case appears more than once: {0:?}")]
    DuplicateCase(NetworkRuntimeLabCaseKind),
    #[error("required runtime-lab case missing: {0:?}")]
    MissingCase(NetworkRuntimeLabCaseKind),
    #[error("runtime-lab case failed: {0}")]
    FailedCase(String),
    #[error("runtime-lab evidence serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> NetworkRuntimeLabReport {
        NetworkRuntimeLabReport {
            schema_version: 1,
            backend: NETWORK_RUNTIME_LAB_BACKEND.into(),
            status: NETWORK_RUNTIME_LAB_STATUS.into(),
            kernel_release: "6.18-test".into(),
            nixos_system: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-lab".into(),
            harness_blake3: "11".repeat(32),
            isolated_environment: true,
            payload_capture: false,
            production_activation_performed: false,
            reasoning_authority: "none".into(),
            cases: NetworkRuntimeLabCaseKind::REQUIRED
                .iter()
                .enumerate()
                .map(|(index, kind)| NetworkRuntimeLabCaseResult {
                    case_id: format!("case-{index}"),
                    kind: *kind,
                    passed: true,
                    observed: "expected result observed".into(),
                    evidence_blake3: format!("{:064x}", index + 1),
                })
                .collect(),
        }
    }

    #[test]
    fn complete_lab_attests_backend_without_claiming_production_activation() {
        let attestation = report().attest().unwrap();
        assert_eq!(attestation.status, "runtime-lab-proven-v42");
        assert!(!attestation.production_activation_authority);
        assert!(attestation.target_host_runtime_proof_required);
        assert!(attestation.owner_authorization_required);
    }

    #[test]
    fn any_failed_case_prevents_attestation() {
        let mut report = report();
        report.cases[3].passed = false;
        assert!(matches!(
            report.attest(),
            Err(NetworkRuntimeLabError::FailedCase(_))
        ));
    }

    #[test]
    fn lab_cannot_claim_production_activation() {
        let mut report = report();
        report.production_activation_performed = true;
        assert_eq!(
            report.validate(),
            Err(NetworkRuntimeLabError::ProductionActivationClaim)
        );
    }
}
