//! Task-bound, fail-closed contract for isolated agent workloads.
//!
//! This joins existing Nixward contracts:
//! - SoftwareIngressPlan pins the OCI artifact and guest permissions.
//! - GuestRealizationReceipt records the observed artifact and launch contract.
//! - WorkloadIdentity binds the guest plan and artifact to one Holon.
//! - NetworkPolicyPlan declares exact workload egress capabilities.
//! - NetworkEnforcementPlan compiles those capabilities, but remains disabled
//!   until separate target/runtime proofs and owner-authorized activation exist.
//! - AuthorityVerifier signs/verifies the digest of this exact task binding.
//!
//! A valid AgentTaskNetworkContract is a binding/readiness artifact only.
//! It is not proof that a cgroup, BPF program, DNS policy, or network rule is
//! active. No task launcher or remediation path is provided here.

use crate::authority_signature::{
    AuthorityAction, AuthorityChallenge, AuthorityError, AuthorityVerifier,
    DetachedAuthoritySignature, VerifiedSignatureEvidence,
};
use crate::guest_realization::{
    GuestBackend, GuestRealizationError, GuestRealizationReceipt,
};
use crate::network_covenant::{
    DestinationSet, NetworkDirection, NetworkPolicyPlan, NetworkProtocol,
    WorkloadIdentity, WorkloadSource,
};
use crate::network_enforcement::{NetworkEnforcementError, NetworkEnforcementPlan};
use crate::network_containment::{VerifiedPolicyContainment, NETWORK_CONTAINMENT_PROVER_VERSION};
use crate::observe::oci_runtime::OciRuntimeConsistencySnapshot;
use crate::software_ingress::{
    OciGuestPlan, SoftwareIngressError, SoftwareIngressPlan, SoftwareIngressSpec,
    SoftwareTrustClass,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

const CONTRACT_DOMAIN: &[u8] = b"symthaea:nixward:agent-task-network-contract:v3\0";
const HOLON_DOMAIN: &[u8] = b"symthaea:nixward:agent-task-holon:v1\0";
const NONCE_DOMAIN: &[u8] = b"symthaea:nixward:agent-task-network-nonce:v1\0";
const TARGET_SET_DOMAIN: &[u8] = b"symthaea:nixward:agent-task-target-set:v1\0";

pub const AGENT_TASK_NETWORK_SCHEMA_VERSION: u32 = 3;
pub const AGENT_TASK_NETWORK_STATUS: &str = "runtime-observed-not-enforced-v3";
pub const GUEST_RECEIPT_SCOPE: &str = "plan-consistency-and-artifact-identity-only-not-runtime-isolation-proof-v1";
pub const RUNTIME_OBSERVATION_SCOPE: &str = "podman-procfs-source-agreement-and-temporal-pair-not-host-attestation-or-enforcement-v1";
pub const AGENT_TASK_MAX_TTL_MS: u64 = 15 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTaskNetworkContract {
    pub schema_version: u32,
    pub kind: String,
    /// Human-readable local Holon identifier. The authority challenge uses
    /// holon_blake3, avoiding ambiguity in the signed subject.
    pub holon_id: String,
    pub holon_blake3: String,
    pub task_id: String,
    pub principal_blake3: String,
    pub task_plan_blake3: String,
    pub guest_plan_blake3: String,
    pub guest_receipt_blake3: String,
    pub guest_receipt_scope: String,
    pub runtime_observation_scope: String,
    pub runtime_observation_blake3: String,
    pub runtime_container_id: String,
    pub runtime_process_pid: u32,
    pub runtime_process_start_time_ticks: u64,
    pub runtime_cgroup_path: String,
    pub runtime_boot_id: String,
    pub runtime_machine_id_blake3: String,
    pub runtime_observer_sequence_start: u64,
    pub runtime_observer_sequence_end: u64,
    pub runtime_observation_interval_ns: u128,
    pub artifact_identity: String,
    pub workload_blake3: String,
    pub network_policy_blake3: String,
    pub network_enforcement_plan_blake3: String,
    pub allowed_destinations_blake3: String,
    /// Owner-bound finite-set policy-containment result; not runtime enforcement.
    pub policy_boundary_blake3: String,
    pub policy_containment_report_blake3: String,
    pub policy_containment_prover_version: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce_blake3: String,
    /// This contract may never be interpreted as proof of active enforcement.
    pub status: String,
    pub activation_performed: bool,
    pub reasoning_authority: String,
}

impl AgentTaskNetworkContract {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        holon_id: impl Into<String>,
        task_id: impl Into<String>,
        principal_blake3: impl Into<String>,
        task_plan_blake3: impl Into<String>,
        guest_plan: &SoftwareIngressPlan,
        guest_receipt: &GuestRealizationReceipt,
        runtime_observation: &OciRuntimeConsistencySnapshot,
        workload: &WorkloadIdentity,
        network_policy: &NetworkPolicyPlan,
        policy_proof: &VerifiedPolicyContainment,
        enforcement_plan: &NetworkEnforcementPlan,
        issued_at_ms: u64,
        ttl_ms: u64,
        nonce_entropy: [u8; 32],
    ) -> Result<Self, AgentTaskNetworkError> {
        let holon_id = holon_id.into();
        let task_id = task_id.into();
        let principal_blake3 = principal_blake3.into();
        let task_plan_blake3 = task_plan_blake3.into();

        validate_token("holon id", &holon_id, 256)?;
        validate_token("task id", &task_id, 256)?;
        validate_digest("principal digest", &principal_blake3)?;
        validate_digest("task plan digest", &task_plan_blake3)?;

        if ttl_ms == 0 || ttl_ms > AGENT_TASK_MAX_TTL_MS {
            return Err(AgentTaskNetworkError::InvalidTtl);
        }
        let expires_at_ms = issued_at_ms
            .checked_add(ttl_ms)
            .ok_or(AgentTaskNetworkError::InvalidTtl)?;

        let SoftwareIngressSpec::OciGuest(oci) = &guest_plan.spec else {
            return Err(AgentTaskNetworkError::UnsupportedGuestBackend);
        };
        validate_agent_oci_plan(oci)?;
        guest_plan.validate()?;

        // Re-derive the receipt from the original plan and observed runtime
        // fields. Do not accept a caller-mutated receipt as proof.
        // IMPORTANT: this re-derivation checks structural consistency and
        // artifact/launch identity only. The current observe_oci adapter fills
        // rootless/read-only/host-network/mount fields partly from the plan;
        // it does not independently inspect the running container. Never
        // treat this receipt as runtime isolation attestation.
        let rederived_receipt =
            GuestRealizationReceipt::verify(guest_plan, guest_receipt.observation.clone())?;
        if rederived_receipt != *guest_receipt
            || guest_receipt.backend != GuestBackend::RootlessPodman
        {
            return Err(AgentTaskNetworkError::GuestReceiptMismatch);
        }

        // The opaque token comes from the Linux Podman/procfs collector.
        // It establishes bounded source agreement, not host attestation or active
        // network enforcement.
        let runtime_observation_blake3 = runtime_observation
            .digest_blake3()
            .map_err(|_| AgentTaskNetworkError::RuntimeObservationMismatch)?;
        let runtime_container_id = runtime_observation.container_id().to_owned();
        let runtime_cgroup_path = runtime_observation.cgroup_path().to_owned();
        let runtime_boot_id = runtime_observation.boot_id().to_owned();
        let runtime_machine_id_blake3 = runtime_observation.machine_id_blake3().to_owned();
        if !runtime_observation.source_agreement()
            || !runtime_observation.stable_across_observation_window()
            || runtime_observation.runtime_enforcement_proven()
            || runtime_observation.image_id() != oci.image_digest
            || !runtime_observation.root_mount_read_only()
            || !runtime_observation.no_new_privileges()
            || runtime_observation.effective_capabilities() != 0
            || runtime_observation.podman_declared_mount_count() != 0
            || runtime_observation.host_network()
            || runtime_observation.host_pid()
            || runtime_observation.privileged()
            || runtime_observation.process_pid() <= 1
            || runtime_observation.process_start_time_ticks() == 0
            || runtime_observation.observation_interval_ns() == 0
            || runtime_observation.observer_sequence_end()
                <= runtime_observation.observer_sequence_start()
            || runtime_boot_id.len() != 36
            || runtime_cgroup_path.is_empty()
            || !runtime_cgroup_path.starts_with('/')
        {
            return Err(AgentTaskNetworkError::RuntimeObservationMismatch);
        }
        validate_digest("runtime container id", &runtime_container_id)?;
        validate_digest("runtime machine id digest", &runtime_machine_id_blake3)?;
        validate_digest("runtime observer snapshot digest", &runtime_observation_blake3)?;

        let launch_contract_blake3 = guest_plan.spec.authority_digest_hex()?;
        let guest_plan_blake3 = guest_plan.digest_hex()?;
        let guest_receipt_blake3 = guest_receipt.digest_hex()?;
        let artifact_identity = guest_plan.spec.artifact_identity();

        // A workload identity is the immutable join between tenant, exact
        // guest plan, pinned artifact, and launch authority.
        workload.validate()?;
        if workload.holon_id != holon_id {
            return Err(AgentTaskNetworkError::HolonMismatch);
        }
        match &workload.source {
            WorkloadSource::SovereignGuest {
                trust_class,
                guest_plan_blake3: bound_plan,
                artifact_identity: bound_artifact,
                authority_blake3,
            } if *trust_class == SoftwareTrustClass::SovereignGuest
                && bound_plan == &guest_plan_blake3
                && bound_artifact == &artifact_identity
                && authority_blake3 == &launch_contract_blake3 => {}
            _ => return Err(AgentTaskNetworkError::WorkloadIdentityMismatch),
        }
        let workload_blake3 = workload.digest_hex()?;

        network_policy.validate()?;
        if network_policy.holon_id != holon_id {
            return Err(AgentTaskNetworkError::HolonMismatch);
        }
        if network_policy.workloads.len() != 1
            || network_policy.workloads[0] != *workload
            || network_policy.workloads[0].digest_hex()? != workload_blake3
        {
            return Err(AgentTaskNetworkError::PolicyWorkloadMismatch);
        }

        // Agent egress is intentionally narrower than the generic covenant:
        // only explicit IP CIDRs and TCP/UDP egress are accepted here.
        // Hostnames remain unresolved by the current enforcement compiler;
        // DNS/redirect pinning needs a separate authenticated resolution
        // contract before those capabilities can be admitted.
        validate_agent_capabilities(network_policy)?;

        let network_policy_blake3 = network_policy.digest_hex()?;
        validate_digest("policy boundary digest", policy_proof.boundary_policy_blake3())?;
        validate_digest("policy containment report digest", policy_proof.report_digest_blake3())?;
        if policy_proof.candidate_policy_blake3() != network_policy_blake3
            || policy_proof.prover_version() != NETWORK_CONTAINMENT_PROVER_VERSION
        {
            return Err(AgentTaskNetworkError::PolicyContainmentMismatch);
        }

        if oci.permissions.network != !network_policy.capabilities.is_empty() {
            return Err(AgentTaskNetworkError::NetworkPermissionMismatch);
        }

        let expected_plan = NetworkEnforcementPlan::compile(network_policy)?;
        expected_plan.validate()?;
        if expected_plan.digest_hex()? != enforcement_plan.digest_hex()?
            || enforcement_plan.network_policy_blake3 != network_policy.digest_hex()?
            || enforcement_plan.workload_subjects.len() != 1
            || !enforcement_plan.workload_subjects.contains_key(&workload_blake3)
            || !enforcement_plan.unresolved.is_empty()
            || enforcement_plan.fail_open
            || enforcement_plan.activation != "disabled-until-runtime-proof-v40"
            || enforcement_plan.reasoning_authority != "none"
        {
            return Err(AgentTaskNetworkError::EnforcementPlanMismatch);
        }

        let allowed_destinations_blake3 =
            hash_json(TARGET_SET_DOMAIN, &network_policy.capabilities)?;
        let holon_blake3 = hash_bytes(HOLON_DOMAIN, holon_id.as_bytes());
        let nonce_blake3 = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(NONCE_DOMAIN);
            hasher.update(&nonce_entropy);
            hasher.update(holon_id.as_bytes());
            hasher.update(task_id.as_bytes());
            hasher.update(task_plan_blake3.as_bytes());
            hasher.finalize().to_hex().to_string()
        };

        let contract = Self {
            schema_version: AGENT_TASK_NETWORK_SCHEMA_VERSION,
            kind: "symthaea-agent-task-network-contract-v3".into(),
            holon_id,
            holon_blake3,
            task_id,
            principal_blake3,
            task_plan_blake3,
            guest_plan_blake3,
            guest_receipt_blake3,
            guest_receipt_scope: GUEST_RECEIPT_SCOPE.into(),
            runtime_observation_scope: RUNTIME_OBSERVATION_SCOPE.into(),
            runtime_observation_blake3,
            runtime_container_id,
            runtime_process_pid: runtime_observation.process_pid(),
            runtime_process_start_time_ticks: runtime_observation.process_start_time_ticks(),
            runtime_cgroup_path,
            runtime_boot_id,
            runtime_machine_id_blake3,
            runtime_observer_sequence_start: runtime_observation.observer_sequence_start(),
            runtime_observer_sequence_end: runtime_observation.observer_sequence_end(),
            runtime_observation_interval_ns: runtime_observation.observation_interval_ns(),
            artifact_identity,
            workload_blake3,
            network_policy_blake3: network_policy.digest_hex()?,
            network_enforcement_plan_blake3: enforcement_plan.digest_hex()?,
            allowed_destinations_blake3,
            policy_boundary_blake3: policy_proof.boundary_policy_blake3().to_owned(),
            policy_containment_report_blake3: policy_proof.report_digest_blake3().to_owned(),
            policy_containment_prover_version: policy_proof.prover_version().to_owned(),
            issued_at_ms,
            expires_at_ms,
            nonce_blake3,
            status: AGENT_TASK_NETWORK_STATUS.into(),
            activation_performed: false,
            reasoning_authority: "none".into(),
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), AgentTaskNetworkError> {
        if self.schema_version != AGENT_TASK_NETWORK_SCHEMA_VERSION
            || self.kind != "symthaea-agent-task-network-contract-v3"
            || self.status != AGENT_TASK_NETWORK_STATUS
            || self.guest_receipt_scope != GUEST_RECEIPT_SCOPE
            || self.runtime_observation_scope != RUNTIME_OBSERVATION_SCOPE
        {
            return Err(AgentTaskNetworkError::UnsupportedSchema);
        }
        validate_token("holon id", &self.holon_id, 256)?;
        validate_token("task id", &self.task_id, 256)?;
        for (label, digest) in [
            ("holon digest", &self.holon_blake3),
            ("principal digest", &self.principal_blake3),
            ("task plan digest", &self.task_plan_blake3),
            ("guest plan digest", &self.guest_plan_blake3),
            ("guest receipt digest", &self.guest_receipt_blake3),
            ("runtime observation digest", &self.runtime_observation_blake3),
            ("runtime container ID", &self.runtime_container_id),
            ("runtime machine ID digest", &self.runtime_machine_id_blake3),
            ("workload digest", &self.workload_blake3),
            ("network policy digest", &self.network_policy_blake3),
            ("network enforcement digest", &self.network_enforcement_plan_blake3),
            ("target-set digest", &self.allowed_destinations_blake3),
            ("policy boundary digest", &self.policy_boundary_blake3),
            ("policy containment report digest", &self.policy_containment_report_blake3),
            ("nonce digest", &self.nonce_blake3),
        ] {
            validate_digest(label, digest)?;
        }
        if self.artifact_identity.trim().is_empty()
            || self.artifact_identity.len() > 2048
            || self.artifact_identity.contains('\0')
        {
            return Err(AgentTaskNetworkError::InvalidValue("artifact identity"));
        }
        if self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > AGENT_TASK_MAX_TTL_MS
        {
            return Err(AgentTaskNetworkError::InvalidTtl);
        }
        if self.runtime_process_pid <= 1
            || self.runtime_process_start_time_ticks == 0
            || self.runtime_observer_sequence_start == 0
            || self.runtime_observer_sequence_end <= self.runtime_observer_sequence_start
            || self.runtime_observation_interval_ns == 0
            || self.runtime_boot_id.len() != 36
            || !self.runtime_cgroup_path.starts_with('/')
            || self.runtime_cgroup_path.bytes().any(|b| b.is_ascii_control())
        {
            return Err(AgentTaskNetworkError::RuntimeObservationMismatch);
        }
        if self.policy_containment_prover_version != NETWORK_CONTAINMENT_PROVER_VERSION {
            return Err(AgentTaskNetworkError::PolicyContainmentMismatch);
        }
        if self.activation_performed || self.reasoning_authority != "none" {
            return Err(AgentTaskNetworkError::AuthorityEscalation);
        }
        if self.holon_blake3 != hash_bytes(HOLON_DOMAIN, self.holon_id.as_bytes()) {
            return Err(AgentTaskNetworkError::HolonMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now_ms: u64) -> Result<(), AgentTaskNetworkError> {
        self.validate()?;
        if now_ms < self.issued_at_ms || now_ms > self.expires_at_ms {
            return Err(AgentTaskNetworkError::ExpiredOrNotYetValid);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, AgentTaskNetworkError> {
        self.validate()?;
        hash_json(CONTRACT_DOMAIN, self)
    }

    /// Produce the owner-signable challenge for this exact task binding.
    ///
    /// `nonce_entropy` must come from the host OS CSPRNG; this module does not
    /// generate entropy, sign the challenge, consume replay state, or activate networking.
    /// This does not sign, consume replay state, or activate networking.
    pub fn authority_challenge(
        &self,
        audience: impl Into<String>,
        nonce_entropy: [u8; 32],
    ) -> Result<AuthorityChallenge, AgentTaskNetworkError> {
        self.validate()?;
        let ttl = self.expires_at_ms - self.issued_at_ms;
        Ok(AuthorityChallenge::new(
            AuthorityAction::NetworkActivate,
            self.digest_hex()?,
            self.holon_blake3.clone(),
            audience,
            nonce_entropy,
            self.issued_at_ms,
            ttl,
        )?)
    }

    /// Verify an Ed25519 owner authorization over this exact task, workload,
    /// artifact, policy, and destination-set digest. The participant still
    /// must atomically consume evidence.replay_key before any real act.
    pub fn verify_authorization(
        &self,
        verifier: &AuthorityVerifier<'_>,
        signature: &DetachedAuthoritySignature,
        now_ms: u64,
    ) -> Result<VerifiedSignatureEvidence, AgentTaskNetworkError> {
        self.validate_at(now_ms)?;
        Ok(verifier.verify(
            signature,
            AuthorityAction::NetworkActivate,
            &self.digest_hex()?,
            &self.holon_blake3,
            now_ms,
        )?)
    }
}

fn validate_agent_oci_plan(plan: &OciGuestPlan) -> Result<(), AgentTaskNetworkError> {
    if !plan.rootless || !plan.read_only_root || plan.host_network {
        return Err(AgentTaskNetworkError::UnsafeGuestIsolation);
    }
    if !plan.mounts.is_empty()
        || !plan.permissions.filesystems.is_empty()
        || !plan.permissions.devices.is_empty()
        || !plan.permissions.secrets.is_empty()
        || plan.permissions.privileged
        || plan.permissions.host_pid_namespace
        || plan.permissions.host_root_write
        || plan.permissions.nix_daemon_access
    {
        return Err(AgentTaskNetworkError::UnsafeGuestIsolation);
    }
    Ok(())
}

fn validate_agent_capabilities(
    policy: &NetworkPolicyPlan,
) -> Result<(), AgentTaskNetworkError> {
    let mut ids = BTreeSet::new();
    for capability in &policy.capabilities {
        capability.validate()?;
        if capability.direction != NetworkDirection::Egress
            || !matches!(capability.protocol, NetworkProtocol::Tcp | NetworkProtocol::Udp)
            || !ids.insert(capability.capability_id.as_str())
            || capability.ports.is_empty()
            || capability.ports.iter().any(|range| {
                range.to.saturating_sub(range.from) > 31
            })
        {
            return Err(AgentTaskNetworkError::InvalidNetworkCapability);
        }
        match &capability.destinations {
            DestinationSet::Cidrs { values } => {
                for cidr in values {
                    if cidr == "0.0.0.0/0" || cidr == "::/0" {
                        return Err(AgentTaskNetworkError::UnboundedDestination);
                    }
                    validate_canonical_cidr(cidr)?;
                }
            }
            DestinationSet::Hostnames { .. } => {
                return Err(AgentTaskNetworkError::HostnameNeedsResolutionProof)
            }
            DestinationSet::Zone { .. } => {
                return Err(AgentTaskNetworkError::UnboundedDestination)
            }
        }
    }
    Ok(())
}

fn validate_canonical_cidr(value: &str) -> Result<(), AgentTaskNetworkError> {
    let Some((address, prefix_text)) = value.split_once('/') else {
        return Err(AgentTaskNetworkError::InvalidCidr);
    };
    if prefix_text.contains('/') || prefix_text.is_empty() {
        return Err(AgentTaskNetworkError::InvalidCidr);
    }
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|_| AgentTaskNetworkError::InvalidCidr)?;
    if let Ok(ip) = address.parse::<Ipv4Addr>() {
        if prefix > 32 {
            return Err(AgentTaskNetworkError::InvalidCidr);
        }
        let bits = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        if bits & mask != bits {
            return Err(AgentTaskNetworkError::NonCanonicalCidr);
        }
        if prefix == 0 {
            return Err(AgentTaskNetworkError::UnboundedDestination);
        }
        return Ok(());
    }
    if let Ok(ip) = address.parse::<Ipv6Addr>() {
        if prefix > 128 {
            return Err(AgentTaskNetworkError::InvalidCidr);
        }
        let bits = u128::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        if bits & mask != bits {
            return Err(AgentTaskNetworkError::NonCanonicalCidr);
        }
        if prefix == 0 {
            return Err(AgentTaskNetworkError::UnboundedDestination);
        }
        return Ok(());
    }
    Err(AgentTaskNetworkError::InvalidCidr)
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), AgentTaskNetworkError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(AgentTaskNetworkError::InvalidValue(field))
    } else {
        Ok(())
    }
}

fn validate_digest(label: &'static str, value: &str) -> Result<(), AgentTaskNetworkError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AgentTaskNetworkError::InvalidDigest(label))
    }
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn hash_json<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, AgentTaskNetworkError> {
    let encoded = serde_json::to_vec(value).map_err(|_| AgentTaskNetworkError::Serialization)?;
    Ok(hash_bytes(domain, &encoded))
}

#[derive(Debug, Error)]
pub enum AgentTaskNetworkError {
    #[error("unsupported agent task network contract schema")]
    UnsupportedSchema,
    #[error("invalid {0}")]
    InvalidValue(&'static str),
    #[error("invalid agent task network digest: {0}")]
    InvalidDigest(&'static str),
    #[error("policy-containment proof does not bind the exact candidate policy or approved prover")]
    PolicyContainmentMismatch,
    #[error("OCI runtime observation is missing, stale, source-discordant or outside the strict profile")]
    RuntimeObservationMismatch,
    #[error("invalid task grant TTL")]
    InvalidTtl,
    #[error("task grant is expired or not yet valid")]
    ExpiredOrNotYetValid,
    #[error("agent task guest must be an OCI S2 workload in the supported rootless profile")]
    UnsupportedGuestBackend,
    #[error("guest isolation claims are outside the supported strict profile")]
    UnsafeGuestIsolation,
    #[error("guest realization receipt does not match the supplied plan")]
    GuestReceiptMismatch,
    #[error("guest workload identity does not match the exact realized artifact")]
    WorkloadIdentityMismatch,
    #[error("agent task tenant/Holon mismatch")]
    HolonMismatch,
    #[error("network policy does not contain exactly this single task workload")]
    PolicyWorkloadMismatch,
    #[error("guest network permission and declared egress capabilities disagree")]
    NetworkPermissionMismatch,
    #[error("agent network capability must be unique TCP/UDP egress")]
    InvalidNetworkCapability,
    #[error("agent task cannot use all-address destinations")]
    UnboundedDestination,
    #[error("agent task destination is not a valid IPv4/IPv6 CIDR")]
    InvalidCidr,
    #[error("agent task CIDR contains host bits; use its canonical network address")]
    NonCanonicalCidr,
    #[error("hostname egress requires an authenticated DNS/resolution proof")]
    HostnameNeedsResolutionProof,
    #[error("compiled network enforcement plan does not match exact policy or remains unresolved")]
    EnforcementPlanMismatch,
    #[error("agent task contract cannot grant enforcement/reasoning authority")]
    AuthorityEscalation,
    #[error("software ingress validation failed: {0}")]
    SoftwareIngress(#[from] SoftwareIngressError),
    #[error("guest realization verification failed: {0}")]
    GuestRealization(#[from] GuestRealizationError),
    #[error("network covenant validation failed: {0}")]
    NetworkCovenant(#[from] crate::network_covenant::NetworkCovenantError),
    #[error("network enforcement validation failed: {0}")]
    NetworkEnforcement(#[from] NetworkEnforcementError),
    #[error("authority verification failed: {0}")]
    Authority(#[from] AuthorityError),
    #[error("serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_signature::{
        AUTHORITY_POLICY_KIND, AUTHORITY_SCHEMA_VERSION, AUTHORITY_SIGNATURE_KIND,
        AuthorityTrustPolicy, TrustedAuthorityKey,
    };
    use crate::guest_realization::{GuestObservation, OciObservation, oci_mounts_digest_hex};
    use crate::network_covenant::{
        NetworkCapability, WorkloadSource, NETWORK_COVENANT_SCHEMA_VERSION,
    };
    use crate::software_ingress::{GuestPermissionEnvelope, OciGuestPlan};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn runtime_for(plan: &SoftwareIngressPlan) -> OciRuntimeConsistencySnapshot {
        let SoftwareIngressSpec::OciGuest(oci) = &plan.spec else {
            panic!("test plan must be OCI");
        };
        crate::observe::oci_runtime::test_fixture_for_contract(&oci.image_digest)
    }

    fn build_fixture(
        destination: DestinationSet,
    ) -> Result<
        (
            AgentTaskNetworkContract,
            SoftwareIngressPlan,
            GuestRealizationReceipt,
            WorkloadIdentity,
            NetworkPolicyPlan,
            NetworkEnforcementPlan,
        ),
        AgentTaskNetworkError,
    > {
        let guest_plan = SoftwareIngressPlan::new(
            "artex-agent-worker",
            SoftwareIngressSpec::OciGuest(OciGuestPlan {
                image: "registry.invalid/artex-worker".into(),
                image_digest: format!("sha256:{}", "d".repeat(64)),
                rootless: true,
                read_only_root: true,
                host_network: false,
                mounts: Vec::new(),
                permissions: GuestPermissionEnvelope {
                    network: true,
                    ..Default::default()
                },
            }),
        )?;
        let oci = match &guest_plan.spec {
            SoftwareIngressSpec::OciGuest(spec) => spec,
            _ => return Err(AgentTaskNetworkError::UnsupportedGuestBackend),
        };
        let launch_contract_blake3 = guest_plan.spec.authority_digest_hex()?;
        let guest_receipt = GuestRealizationReceipt::verify(
            &guest_plan,
            GuestObservation::Oci(OciObservation {
                image: oci.image.clone(),
                image_digest: oci.image_digest.clone(),
                rootless: true,
                read_only_root: true,
                host_network: false,
                mounts_blake3: oci_mounts_digest_hex(oci).unwrap(),
                launch_contract_blake3: launch_contract_blake3.clone(),
            }),
        )?;
        let workload = WorkloadIdentity::new(
            "tenant-a",
            "artex-agent-worker",
            WorkloadSource::SovereignGuest {
                trust_class: SoftwareTrustClass::SovereignGuest,
                guest_plan_blake3: guest_plan.digest_hex()?,
                artifact_identity: guest_plan.spec.artifact_identity(),
                authority_blake3: launch_contract_blake3,
            },
        )?;
        let capability = NetworkCapability {
            schema_version: crate::network_covenant::NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "agent-api-egress".into(),
            workload_blake3: workload.digest_hex()?,
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: destination,
            ports: vec![crate::network_covenant::PortRange { from: 443, to: 443 }],
            justification: "one task-specific HTTPS endpoint".into(),
        };
        let policy = NetworkPolicyPlan::new("tenant-a", vec![workload.clone()], vec![capability])?;
        let enforcement = NetworkEnforcementPlan::compile(&policy)?;
        validate_agent_capabilities(&policy)?;
        let mut owner_boundary = policy.clone();
        for cap in &mut owner_boundary.capabilities {
            if let DestinationSet::Cidrs { values } = &mut cap.destinations {
                for cidr in values {
                    if cidr == "203.0.113.17/32" {
                        *cidr = "203.0.113.0/24".into();
                    }
                }
            }
        }
        let policy_proof = verify_policy_within_boundary(&owner_boundary, &policy)
            .map_err(|_| AgentTaskNetworkError::PolicyContainmentMismatch)?;
        let runtime_observation = runtime_for(&guest_plan);
        let contract = AgentTaskNetworkContract::bind(
            "tenant-a",
            "task-atr-001",
            "a".repeat(64),
            "b".repeat(64),
            &guest_plan,
            &guest_receipt,
            &runtime_observation,
            &workload,
            &policy,
            &policy_proof,
            &enforcement,
            1_000_000,
            60_000,
            [7; 32],
        )?;
        Ok((contract, guest_plan, guest_receipt, workload, policy, enforcement))
    }

    fn fixture(
        destination: DestinationSet,
    ) -> (
        AgentTaskNetworkContract,
        SoftwareIngressPlan,
        GuestRealizationReceipt,
        WorkloadIdentity,
        NetworkPolicyPlan,
        NetworkEnforcementPlan,
    ) {
        build_fixture(destination).unwrap()
    }

    fn authority_policy(signing: &SigningKey) -> AuthorityTrustPolicy {
        AuthorityTrustPolicy {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_POLICY_KIND.into(),
            policy_id: "tenant-a-owner-v1".into(),
            keys: vec![TrustedAuthorityKey {
                key_id: "owner-key-1".into(),
                issuer: "tenant-a-owner".into(),
                public_key_hex: hex(signing.verifying_key().as_bytes()),
                allowed_actions: vec![AuthorityAction::NetworkActivate],
                revoked: false,
                claims: BTreeMap::new(),
            }],
            max_ttl_ms: AGENT_TASK_MAX_TTL_MS,
            allowed_audiences: vec!["nixward-agent-egress".into()],
        }
    }

    fn signed(
        signing: &SigningKey,
        challenge: AuthorityChallenge,
    ) -> DetachedAuthoritySignature {
        let signature = signing.sign(&challenge.signing_bytes().unwrap());
        DetachedAuthoritySignature {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            key_id: "owner-key-1".into(),
            public_key_hex: hex(signing.verifying_key().as_bytes()),
            signature_hex: hex(&signature.to_bytes()),
            challenge,
        }
    }

    #[test]
    fn binds_exact_guest_artifact_to_one_tenant_task_and_network_policy() {
        let (contract, _, _, _, _, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        contract.validate_at(1_030_000).unwrap();
        assert_eq!(contract.status, AGENT_TASK_NETWORK_STATUS);
        assert_eq!(contract.guest_receipt_scope, GUEST_RECEIPT_SCOPE);
        assert!(!contract.activation_performed);
        assert_eq!(contract.reasoning_authority, "none");
    }

    #[test]
    fn rejects_wildcard_egress_even_when_the_generic_policy_accepts_it() {
        let result = build_fixture(DestinationSet::Cidrs {
            values: vec!["0.0.0.0/0".into()],
        });
        assert!(matches!(result, Err(AgentTaskNetworkError::UnboundedDestination)));
    }

    #[test]
    fn rejects_expanded_ipv6_default_route() {
        let result = build_fixture(DestinationSet::Cidrs {
            values: vec!["0:0:0:0:0:0:0:0/0".into()],
        });
        assert!(matches!(
            result,
            Err(AgentTaskNetworkError::UnboundedDestination)
        ));
    }

    #[test]
    fn rejects_invalid_and_noncanonical_cidr_ranges() {
        let invalid = build_fixture(DestinationSet::Cidrs {
            values: vec!["not-an-ip/24".into()],
        });
        assert!(matches!(invalid, Err(AgentTaskNetworkError::InvalidCidr)));

        let noncanonical = build_fixture(DestinationSet::Cidrs {
            values: vec!["203.0.113.17/24".into()],
        });
        assert!(matches!(
            noncanonical,
            Err(AgentTaskNetworkError::NonCanonicalCidr)
        ));
    }

    #[test]
    fn rejects_hostname_egress_without_resolution_attestation() {
        let result = build_fixture(DestinationSet::Hostnames {
            values: vec!["api.example.invalid".into()],
        });
        assert!(matches!(
            result,
            Err(AgentTaskNetworkError::HostnameNeedsResolutionProof)
        ));
    }

    #[test]
    fn rejects_policy_bound_to_another_workload() {
        let (_, guest_plan, guest_receipt, workload, _, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let other_workload = WorkloadIdentity::new(
            "tenant-a",
            "other-worker",
            workload.source.clone(),
        ).unwrap();
        let policy = NetworkPolicyPlan::new("tenant-a", vec![other_workload], vec![]).unwrap();
        let enforcement = NetworkEnforcementPlan::compile(&policy).unwrap();
        let policy_proof = verify_policy_within_boundary(&policy, &policy).unwrap();
        let runtime_observation = runtime_for(&guest_plan);
        let result = AgentTaskNetworkContract::bind(
            "tenant-a", "task-atr-001", "a".repeat(64), "b".repeat(64),
            &guest_plan, &guest_receipt, &runtime_observation, &workload, &policy, &policy_proof, &enforcement,
            1_000_000, 60_000, [7; 32],
        );
        assert!(matches!(result, Err(AgentTaskNetworkError::PolicyWorkloadMismatch)));
    }

    #[test]
    fn rejects_guest_receipt_substitution() {
        let (_, guest_plan, receipt, workload, policy, enforcement) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let policy_proof = verify_policy_within_boundary(&policy, &policy).unwrap();
        let runtime_observation = runtime_for(&guest_plan);
        let mut substituted = receipt.clone();
        substituted.artifact_identity = "registry.invalid/other@sha256:".to_string() + &"e".repeat(64);
        let result = AgentTaskNetworkContract::bind(
            "tenant-a", "task-atr-001", "a".repeat(64), "b".repeat(64),
            &guest_plan, &substituted, &runtime_observation, &workload, &policy, &policy_proof, &enforcement,
            1_000_000, 60_000, [8; 32],
        );
        assert!(matches!(result, Err(AgentTaskNetworkError::GuestReceiptMismatch)));
    }

    #[test]
    fn rejects_runtime_snapshot_bound_to_a_different_image() {
        let (_, guest_plan, receipt, workload, policy, enforcement) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let policy_proof = verify_policy_within_boundary(&policy, &policy).unwrap();
        let wrong_runtime = crate::observe::oci_runtime::test_fixture_for_contract(
            &format!("sha256:{}", "f".repeat(64))
        );
        let result = AgentTaskNetworkContract::bind(
            "tenant-a",
            "task-atr-001",
            "a".repeat(64),
            "b".repeat(64),
            &guest_plan,
            &receipt,
            &wrong_runtime,
            &workload,
            &policy,
            &policy_proof,
            &enforcement,
            1_000_000,
            60_000,
            [13; 32],
        );
        assert!(matches!(
            result,
            Err(AgentTaskNetworkError::RuntimeObservationMismatch)
        ));
    }

    #[test]
    fn rejects_policy_proof_replay_after_candidate_policy_changes() {
        let (_, guest_plan, guest_receipt, workload, policy, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let stale_proof = verify_policy_within_boundary(&policy, &policy).unwrap();
        let runtime_observation = runtime_for(&guest_plan);

        let mut changed_policy = policy.clone();
        changed_policy.capabilities[0].destinations = DestinationSet::Cidrs {
            values: vec!["203.0.113.18/32".into()],
        };
        let changed_enforcement = NetworkEnforcementPlan::compile(&changed_policy).unwrap();
        let result = AgentTaskNetworkContract::bind(
            "tenant-a",
            "task-atr-001",
            "a".repeat(64),
            "b".repeat(64),
            &guest_plan,
            &guest_receipt,
            &runtime_observation,
            &workload,
            &changed_policy,
            &stale_proof,
            &changed_enforcement,
            1_000_000,
            60_000,
            [12; 32],
        );
        assert!(matches!(
            result,
            Err(AgentTaskNetworkError::PolicyContainmentMismatch)
        ));
    }

    #[test]
    fn owner_signature_is_bound_to_the_complete_task_network_contract() {
        let (contract, _, _, _, _, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let signing = SigningKey::from_bytes(&[42; 32]);
        let challenge = contract.authority_challenge("nixward-agent-egress", [9; 32]).unwrap();
        let signature = signed(&signing, challenge);
        let verifier = AuthorityVerifier::new(&authority_policy(&signing)).unwrap();
        let verified = contract.verify_authorization(&verifier, &signature, 1_030_000).unwrap();
        assert_eq!(verified.subject_blake3, contract.digest_hex().unwrap());
        assert_ne!(contract.policy_boundary_blake3, contract.network_policy_blake3);
        assert_eq!(contract.policy_containment_prover_version, NETWORK_CONTAINMENT_PROVER_VERSION);
        assert_eq!(contract.policy_containment_report_blake3.len(), 64);
        let mut changed_boundary = contract.clone();
        changed_boundary.policy_boundary_blake3 = "f".repeat(64);
        assert_ne!(
            contract.digest_hex().unwrap(),
            changed_boundary.digest_hex().unwrap(),
            "owner boundary must be inside the signed contract subject"
        );
        assert_eq!(verified.signer_key_id, "owner-key-1");
        assert!(!verified.replay_key.is_empty());
    }

    #[test]
    fn task_or_policy_change_invalidates_the_old_authorization() {
        let (mut contract, _, _, _, _, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let signing = SigningKey::from_bytes(&[43; 32]);
        let challenge = contract.authority_challenge("nixward-agent-egress", [10; 32]).unwrap();
        let signature = signed(&signing, challenge);
        contract.task_id = "different-task".into();
        let verifier = AuthorityVerifier::new(&authority_policy(&signing)).unwrap();
        let err = contract.verify_authorization(&verifier, &signature, 1_030_000).unwrap_err();
        assert!(matches!(
            err,
            AgentTaskNetworkError::Authority(AuthorityError::SubjectMismatch)
        ));
    }

    #[test]
    fn expired_task_binding_is_rejected_before_signature_use() {
        let (contract, _, _, _, _, _) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        assert!(matches!(
            contract.validate_at(1_060_001),
            Err(AgentTaskNetworkError::ExpiredOrNotYetValid)
        ));
    }

    #[test]
    fn refuses_host_mounts_and_privileged_guest_authority() {
        let (_, guest_plan, receipt, workload, policy, enforcement) =
            fixture(DestinationSet::Cidrs { values: vec!["203.0.113.17/32".into()] });
        let policy_proof = verify_policy_within_boundary(&policy, &policy).unwrap();
        let runtime_observation = runtime_for(&guest_plan);
        let mut changed_plan = guest_plan.clone();
        let SoftwareIngressSpec::OciGuest(oci) = &mut changed_plan.spec else {
            unreachable!()
        };
        oci.mounts.push(crate::software_ingress::OciMount {
            source: "/var/run/docker.sock".into(),
            target: "/var/run/docker.sock".into(),
            access: crate::software_ingress::FilesystemAccess::ReadWrite,
        });
        let result = AgentTaskNetworkContract::bind(
            "tenant-a", "task-atr-001", "a".repeat(64), "b".repeat(64),
            &changed_plan, &receipt, &runtime_observation, &workload, &policy, &policy_proof, &enforcement,
            1_000_000, 60_000, [11; 32],
        );
        assert!(matches!(result, Err(AgentTaskNetworkError::UnsafeGuestIsolation)));
    }
}
