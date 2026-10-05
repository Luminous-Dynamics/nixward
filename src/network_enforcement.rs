// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Workload-aware kernel enforcement contract.
//!
//! V40 deliberately separates *compilation* of exact network authority from
//! *activation* of a kernel backend. A plan may be produced and reviewed on any
//! host; it becomes eligible for activation only after the target kernel has
//! proven the required cgroup/BPF features and the workload has an exact cgroup
//! binding. Symthaea reasoning never mints these proofs.

use crate::network_covenant::{
    DestinationSet, NETWORK_COVENANT_SCHEMA_VERSION, NetworkCapability, NetworkCovenantError,
    NetworkDirection, NetworkPolicyPlan, NetworkProtocol, NetworkZone, WorkloadIdentity,
    WorkloadSource,
};
use crate::network_runtime_lab::{NETWORK_RUNTIME_LAB_BACKEND, NetworkBackendLabAttestation};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const PLAN_DOMAIN: &[u8] = b"symthaea:nixward:network-enforcement-plan:v1\0";
const KERNEL_PROBE_DOMAIN: &[u8] = b"symthaea:nixward:network-kernel-probe:v1\0";
const TARGET_PROOF_DOMAIN: &[u8] = b"symthaea:nixward:network-target-runtime-proof:v1\0";
const READINESS_DOMAIN: &[u8] = b"symthaea:nixward:network-production-readiness:v1\0";

pub const NETWORK_ENFORCEMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum KernelNetworkFeature {
    CgroupV2,
    CgroupInet4Connect,
    CgroupInet6Connect,
    CgroupUdp4Sendmsg,
    CgroupUdp6Sendmsg,
    BpfLink,
    BpfMapPinning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelFeatureProbe {
    pub schema_version: u32,
    pub kernel_release: String,
    pub cgroup_mode: String,
    pub observed_features: Vec<KernelNetworkFeature>,
    pub probe_method: String,
}

impl KernelFeatureProbe {
    pub fn validate(&self) -> Result<(), NetworkEnforcementError> {
        if self.schema_version != NETWORK_ENFORCEMENT_SCHEMA_VERSION {
            return Err(NetworkEnforcementError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.kernel_release.trim().is_empty() || self.probe_method.trim().is_empty() {
            return Err(NetworkEnforcementError::InvalidProbe);
        }
        if self.cgroup_mode != "v2-unified" {
            return Err(NetworkEnforcementError::UnsupportedCgroupMode(
                self.cgroup_mode.clone(),
            ));
        }
        let unique = self.observed_features.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.observed_features.len() {
            return Err(NetworkEnforcementError::DuplicateKernelFeature);
        }
        Ok(())
    }

    pub fn supports(&self, required: &[KernelNetworkFeature]) -> bool {
        required
            .iter()
            .all(|feature| self.observed_features.contains(feature))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupWorkloadBinding {
    pub workload_blake3: String,
    /// Exact cgroup v2 path observed for the workload at activation time.
    pub cgroup_path: String,
    /// Unit or guest-runtime identity that was used to establish the binding.
    pub binding_subject: String,
}

impl CgroupWorkloadBinding {
    pub fn validate(&self) -> Result<(), NetworkEnforcementError> {
        validate_digest(&self.workload_blake3)?;
        if !self.cgroup_path.starts_with('/')
            || self.cgroup_path.contains("..")
            || self.cgroup_path.contains('\0')
            || self.binding_subject.trim().is_empty()
        {
            return Err(NetworkEnforcementError::InvalidCgroupBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelNetworkRule {
    pub capability_id: String,
    pub capability_blake3: String,
    pub workload_blake3: String,
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
    pub destinations: DestinationSet,
    pub ports: Vec<(u16, u16)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedKernelRule {
    pub capability_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEnforcementPlan {
    pub schema_version: u32,
    pub holon_id: String,
    pub network_policy_blake3: String,
    pub backend: String,
    pub activation: String,
    pub fail_open: bool,
    pub reasoning_authority: String,
    pub required_kernel_features: Vec<KernelNetworkFeature>,
    pub workload_subjects: BTreeMap<String, String>,
    pub rules: Vec<KernelNetworkRule>,
    pub unresolved: Vec<UnresolvedKernelRule>,
}

impl NetworkEnforcementPlan {
    pub fn compile(policy: &NetworkPolicyPlan) -> Result<Self, NetworkEnforcementError> {
        policy.validate()?;
        let network_policy_blake3 = policy.digest_hex()?;
        let mut workload_subjects = BTreeMap::new();
        for workload in &policy.workloads {
            let digest = workload.digest_hex()?;
            workload_subjects.insert(digest, workload_binding_subject(workload));
        }

        let mut required = BTreeSet::from([
            KernelNetworkFeature::CgroupV2,
            KernelNetworkFeature::CgroupInet4Connect,
            KernelNetworkFeature::CgroupInet6Connect,
            KernelNetworkFeature::BpfLink,
        ]);
        let mut rules = Vec::new();
        let mut unresolved = Vec::new();
        for capability in &policy.capabilities {
            match compile_capability(capability) {
                Ok(rule) => {
                    if matches!(rule.protocol, NetworkProtocol::Udp | NetworkProtocol::Any) {
                        required.insert(KernelNetworkFeature::CgroupUdp4Sendmsg);
                        required.insert(KernelNetworkFeature::CgroupUdp6Sendmsg);
                    }
                    rules.push(rule);
                }
                Err(reason) => unresolved.push(UnresolvedKernelRule {
                    capability_id: capability.capability_id.clone(),
                    reason,
                }),
            }
        }

        Ok(Self {
            schema_version: NETWORK_ENFORCEMENT_SCHEMA_VERSION,
            holon_id: policy.holon_id.clone(),
            network_policy_blake3,
            backend: "cgroup-sockaddr-bpf-contract-v40".into(),
            activation: "disabled-until-runtime-proof-v40".into(),
            fail_open: false,
            reasoning_authority: "none".into(),
            required_kernel_features: required.into_iter().collect(),
            workload_subjects,
            rules,
            unresolved,
        })
    }

    pub fn validate(&self) -> Result<(), NetworkEnforcementError> {
        if self.schema_version != NETWORK_ENFORCEMENT_SCHEMA_VERSION {
            return Err(NetworkEnforcementError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.network_policy_blake3)?;
        if self.backend != "cgroup-sockaddr-bpf-contract-v40" {
            return Err(NetworkEnforcementError::UnsafeContract(
                "network enforcement backend identity drifted from the reviewed V40 contract"
                    .into(),
            ));
        }
        if self.fail_open {
            return Err(NetworkEnforcementError::UnsafeContract(
                "fail-open kernel enforcement".into(),
            ));
        }
        if self.reasoning_authority != "none" {
            return Err(NetworkEnforcementError::UnsafeContract(
                "reasoning plane cannot activate or mutate kernel policy".into(),
            ));
        }
        if self.activation != "disabled-until-runtime-proof-v40" {
            return Err(NetworkEnforcementError::UnsafeContract(
                "V40 activation must remain proof-gated".into(),
            ));
        }
        for digest in self.workload_subjects.keys() {
            validate_digest(digest)?;
        }
        for rule in &self.rules {
            validate_digest(&rule.capability_blake3)?;
            validate_digest(&rule.workload_blake3)?;
            if !self.workload_subjects.contains_key(&rule.workload_blake3) {
                return Err(NetworkEnforcementError::UnknownWorkload(
                    rule.workload_blake3.clone(),
                ));
            }
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkEnforcementError> {
        self.validate()?;
        hash_json(PLAN_DOMAIN, self)
    }

    pub fn activation_eligibility(
        &self,
        probe: &KernelFeatureProbe,
        bindings: &[CgroupWorkloadBinding],
    ) -> Result<NetworkEnforcementRuntimeProof, NetworkEnforcementError> {
        self.validate()?;
        probe.validate()?;
        if !self.unresolved.is_empty() {
            return Err(NetworkEnforcementError::UnresolvedRules(
                self.unresolved.len(),
            ));
        }
        if !probe.supports(&self.required_kernel_features) {
            return Err(NetworkEnforcementError::MissingKernelFeatures);
        }
        let mut bound = BTreeMap::new();
        for binding in bindings {
            binding.validate()?;
            if !self
                .workload_subjects
                .contains_key(&binding.workload_blake3)
            {
                return Err(NetworkEnforcementError::UnknownWorkload(
                    binding.workload_blake3.clone(),
                ));
            }
            if bound
                .insert(binding.workload_blake3.clone(), binding.clone())
                .is_some()
            {
                return Err(NetworkEnforcementError::DuplicateCgroupBinding);
            }
        }
        if bound.len() != self.workload_subjects.len() {
            return Err(NetworkEnforcementError::MissingCgroupBindings);
        }
        let proof = NetworkEnforcementRuntimeProof {
            schema_version: NETWORK_ENFORCEMENT_SCHEMA_VERSION,
            enforcement_plan_blake3: self.digest_hex()?,
            network_policy_blake3: self.network_policy_blake3.clone(),
            kernel_release: probe.kernel_release.clone(),
            kernel_probe_blake3: hash_json(KERNEL_PROBE_DOMAIN, probe)?,
            bindings: bindings.to_vec(),
            eligibility: "eligible-for-separate-owner-authorized-activation".into(),
            activation_performed: false,
            reasoning_authority: "none".into(),
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Join isolated backend maturity evidence with this target host's exact
    /// feature/binding proof. Even a valid result is readiness evidence only;
    /// V42 never performs or authorizes production activation.
    pub fn production_readiness(
        &self,
        probe: &KernelFeatureProbe,
        bindings: &[CgroupWorkloadBinding],
        lab: &NetworkBackendLabAttestation,
    ) -> Result<NetworkProductionReadiness, NetworkEnforcementError> {
        self.validate()?;
        lab.validate()?;
        if lab.backend != self.backend || lab.backend != NETWORK_RUNTIME_LAB_BACKEND {
            return Err(NetworkEnforcementError::LabBackendMismatch);
        }
        let target = self.activation_eligibility(probe, bindings)?;
        let readiness = NetworkProductionReadiness {
            schema_version: NETWORK_ENFORCEMENT_SCHEMA_VERSION,
            backend: self.backend.clone(),
            enforcement_plan_blake3: self.digest_hex()?,
            backend_lab_attestation_blake3: lab.digest_hex()?,
            target_runtime_proof_blake3: target.digest_hex()?,
            status: "ready-for-owner-authorized-activation-v42".into(),
            activation_performed: false,
            owner_authorization_required: true,
            reasoning_authority: "none".into(),
        };
        readiness.validate()?;
        Ok(readiness)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEnforcementRuntimeProof {
    pub schema_version: u32,
    pub enforcement_plan_blake3: String,
    pub network_policy_blake3: String,
    pub kernel_release: String,
    pub kernel_probe_blake3: String,
    pub bindings: Vec<CgroupWorkloadBinding>,
    pub eligibility: String,
    pub activation_performed: bool,
    pub reasoning_authority: String,
}

impl NetworkEnforcementRuntimeProof {
    pub fn validate(&self) -> Result<(), NetworkEnforcementError> {
        if self.schema_version != NETWORK_ENFORCEMENT_SCHEMA_VERSION {
            return Err(NetworkEnforcementError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        for digest in [
            &self.enforcement_plan_blake3,
            &self.network_policy_blake3,
            &self.kernel_probe_blake3,
        ] {
            validate_digest(digest)?;
        }
        if self.activation_performed {
            return Err(NetworkEnforcementError::UnsafeContract(
                "V40 proof is eligibility evidence only; it cannot claim activation".into(),
            ));
        }
        if self.reasoning_authority != "none" {
            return Err(NetworkEnforcementError::UnsafeContract(
                "reasoning plane cannot become activation authority".into(),
            ));
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkEnforcementError> {
        self.validate()?;
        hash_json(TARGET_PROOF_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProductionReadiness {
    pub schema_version: u32,
    pub backend: String,
    pub enforcement_plan_blake3: String,
    pub backend_lab_attestation_blake3: String,
    pub target_runtime_proof_blake3: String,
    pub status: String,
    pub activation_performed: bool,
    pub owner_authorization_required: bool,
    pub reasoning_authority: String,
}

impl NetworkProductionReadiness {
    pub fn validate(&self) -> Result<(), NetworkEnforcementError> {
        if self.schema_version != NETWORK_ENFORCEMENT_SCHEMA_VERSION {
            return Err(NetworkEnforcementError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.backend != NETWORK_RUNTIME_LAB_BACKEND
            || self.status != "ready-for-owner-authorized-activation-v42"
        {
            return Err(NetworkEnforcementError::UnsafeContract(
                "V42 production-readiness backend/status drifted".into(),
            ));
        }
        for digest in [
            &self.enforcement_plan_blake3,
            &self.backend_lab_attestation_blake3,
            &self.target_runtime_proof_blake3,
        ] {
            validate_digest(digest)?;
        }
        if self.activation_performed
            || !self.owner_authorization_required
            || self.reasoning_authority != "none"
        {
            return Err(NetworkEnforcementError::UnsafeContract(
                "V42 readiness may not claim activation or bypass owner authority".into(),
            ));
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkEnforcementError> {
        self.validate()?;
        hash_json(READINESS_DOMAIN, self)
    }
}

pub fn network_enforcement_policy_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_ENFORCEMENT_SCHEMA_VERSION,
        "kind": "symthaea-network-enforcement-policy-v1",
        "status": "compiled-contract-runtime-lab-and-target-proof-required-v42",
        "backend": "cgroup-sockaddr-bpf-contract-v40",
        "activation": "disabled-until-runtime-proof-v40",
        "fail_open": false,
        "reasoning_authority": "none",
        "runtime_proof": {
            "requires": [
                "exact-network-policy-digest",
                "cgroup-v2",
                "required-bpf-hook-probes",
                "exact-workload-cgroup-bindings",
                "zero-unresolved-rules",
                "runtime-lab-proven-v42",
                "separate-owner-authorized-activation"
            ]
        },
        "not_claimed": [
            "bpf-program-loaded",
            "kernel-rule-enforced",
            "dynamic-capability-leases-enforced",
            "runtime-authority-observed",
            "production-activation-performed"
        ]
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"status\":\"serialization-failed\"}}\n",
            NETWORK_ENFORCEMENT_SCHEMA_VERSION
        )
    })
}

fn workload_binding_subject(workload: &WorkloadIdentity) -> String {
    match &workload.source {
        WorkloadSource::NixSystemdUnit {
            unit,
            closure_store_path,
            ..
        } => {
            format!("systemd-unit:{unit}:closure:{closure_store_path}")
        }
        WorkloadSource::SovereignGuest {
            guest_plan_blake3,
            artifact_identity,
            ..
        } => {
            format!("guest-plan:{guest_plan_blake3}:artifact:{artifact_identity}")
        }
        WorkloadSource::UserSession {
            uid,
            profile_blake3,
        } => {
            format!("user-session:{uid}:profile:{profile_blake3}")
        }
    }
}

fn compile_capability(capability: &NetworkCapability) -> Result<KernelNetworkRule, String> {
    capability.validate().map_err(|e| e.to_string())?;
    if matches!(
        capability.direction,
        NetworkDirection::Ingress | NetworkDirection::Listen
    ) {
        return Err("host/listen ingress remains in the nftables baseline in V40".into());
    }
    match &capability.destinations {
        DestinationSet::Hostnames { .. } => {
            return Err("hostname capabilities require an authenticated DNS/resolution covenant before kernel pinning".into());
        }
        DestinationSet::Zone { zone } if !matches!(zone, NetworkZone::Loopback) => {
            return Err(format!(
                "semantic zone {zone:?} requires target-local address-set materialization"
            ));
        }
        DestinationSet::Zone { .. } | DestinationSet::Cidrs { .. } => {}
    }
    Ok(KernelNetworkRule {
        capability_id: capability.capability_id.clone(),
        capability_blake3: capability.digest_hex().map_err(|e| e.to_string())?,
        workload_blake3: capability.workload_blake3.clone(),
        direction: capability.direction,
        protocol: capability.protocol,
        destinations: capability.destinations.clone(),
        ports: capability.ports.iter().map(|p| (p.from, p.to)).collect(),
    })
}

fn validate_digest(value: &str) -> Result<(), NetworkEnforcementError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NetworkEnforcementError::InvalidDigest)
    }
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkEnforcementError> {
    let encoded = serde_json::to_vec(value).map_err(|_| NetworkEnforcementError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkEnforcementError {
    #[error("unsupported network-enforcement schema version {0}")]
    UnsupportedSchema(u32),
    #[error("network covenant error: {0}")]
    NetworkCovenant(#[from] NetworkCovenantError),
    #[error("invalid network enforcement digest")]
    InvalidDigest,
    #[error("invalid kernel feature probe")]
    InvalidProbe,
    #[error("unsupported cgroup mode {0}")]
    UnsupportedCgroupMode(String),
    #[error("kernel feature probe contains duplicate features")]
    DuplicateKernelFeature,
    #[error("invalid cgroup workload binding")]
    InvalidCgroupBinding,
    #[error("unsafe network enforcement contract: {0}")]
    UnsafeContract(String),
    #[error("unknown workload digest {0}")]
    UnknownWorkload(String),
    #[error("network enforcement plan has {0} unresolved rule(s)")]
    UnresolvedRules(usize),
    #[error("target kernel does not prove all required cgroup/BPF features")]
    MissingKernelFeatures,
    #[error("duplicate workload cgroup binding")]
    DuplicateCgroupBinding,
    #[error("one or more workload cgroup bindings are missing")]
    MissingCgroupBindings,
    #[error("V42 runtime-lab attestation names a different enforcement backend")]
    LabBackendMismatch,
    #[error("network runtime-lab evidence error: {0}")]
    RuntimeLab(#[from] crate::network_runtime_lab::NetworkRuntimeLabError),
    #[error("network enforcement evidence serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_covenant::{PortRange, WorkloadIdentity};

    fn policy(destination: DestinationSet) -> NetworkPolicyPlan {
        let workload = WorkloadIdentity::new(
            "holon-a",
            "sync",
            WorkloadSource::NixSystemdUnit {
                unit: "sync.service".into(),
                closure_store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sync".into(),
                config_blake3: "11".repeat(32),
            },
        )
        .unwrap();
        let capability = NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "sync-egress".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: destination,
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "sync".into(),
        };
        NetworkPolicyPlan::new("holon-a", vec![workload], vec![capability]).unwrap()
    }

    #[test]
    fn cidr_policy_compiles_but_activation_stays_disabled() {
        let policy = policy(DestinationSet::Cidrs {
            values: vec!["203.0.113.0/24".into()],
        });
        let plan = NetworkEnforcementPlan::compile(&policy).unwrap();
        assert!(plan.unresolved.is_empty());
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.activation, "disabled-until-runtime-proof-v40");
        assert!(!plan.fail_open);
    }

    #[test]
    fn hostname_policy_is_not_silently_resolved_in_privileged_enforcement() {
        let policy = policy(DestinationSet::Hostnames {
            values: vec!["example.org".into()],
        });
        let plan = NetworkEnforcementPlan::compile(&policy).unwrap();
        assert_eq!(plan.unresolved.len(), 1);
        assert!(matches!(
            plan.activation_eligibility(
                &KernelFeatureProbe {
                    schema_version: 1,
                    kernel_release: "test".into(),
                    cgroup_mode: "v2-unified".into(),
                    observed_features: plan.required_kernel_features.clone(),
                    probe_method: "fixture".into(),
                },
                &[]
            ),
            Err(NetworkEnforcementError::UnresolvedRules(1))
        ));
    }
}
