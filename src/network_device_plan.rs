// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only, deterministic planning primitives for device/topology networking.
//!
//! This module is deliberately not a Linux networking adapter or executor. It
//! compares caller-supplied, validated observations with desired state and
//! emits a reviewable proposal. It does not open sockets, invoke commands,
//! authorize changes, mutate a kernel, or delete resources.
//!
//! Workload-level cgroup/BPF policy and activation remain in
//! `network_covenant`, `network_enforcement`, `network_runtime_lab`, and
//! `network_activation`. The resource domain here is device/topology state:
//! links, addresses, routes, bridges, VLANs, firewall tables, and WireGuard
//! device configuration. A device-level implementation needs its own adapter
//! and qualification evidence; workload BPF evidence is not a substitute.
//!
//! The planner has no mutation authority. Its `ProposedRuntime*` decisions
//! are descriptive outputs for a later, separately authorized transaction path.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const SNAPSHOT_DOMAIN: &[u8] = b"symthaea:nixward:network-device-snapshot:v1\0";
const DESIRED_DOMAIN: &[u8] = b"symthaea:nixward:network-device-desired:v1\0";
const PLAN_DOMAIN: &[u8] = b"symthaea:nixward:network-device-plan:v1\0";

pub const NETWORK_DEVICE_PLAN_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_DEVICE_PLAN_STATUS: &str = "read-only-device-plan-m0";

/// A stable, caller-defined identity for a network resource.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NetworkResourceId(String);

impl NetworkResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkDevicePlanError> {
        let id = Self(value.into());
        validate_token("resource id", &id.0, 256)?;
        Ok(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        validate_token("resource id", &self.0, 256)
    }
}

/// Resource types supported by the initial portable intent vocabulary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkResourceKind {
    Link,
    Address,
    Route,
    Bridge,
    Vlan,
    FirewallTable,
    WireGuardDevice,
}

/// Source of configuration intent. It is distinct from the process that
/// currently applies or maintains the effective kernel configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "kebab-case")]
pub enum NetworkConfigurationOwner {
    NixOsDeclarative,
    NixwardDesiredState,
    External { authority_id: String },
    Unknown,
}

impl NetworkConfigurationOwner {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        if let Self::External { authority_id } = self {
            validate_token("external authority id", authority_id, 256)?;
        }
        Ok(())
    }
}

/// Process/control system currently responsible for the effective resource.
/// NixOS intent may be realized by systemd-networkd or NetworkManager; these
/// are runtime owners, not configuration authorities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "kebab-case")]
pub enum NetworkRuntimeOwner {
    NixwardRuntime,
    SystemdNetworkd,
    NetworkManager,
    External { manager_id: String },
    Unknown,
}

impl NetworkRuntimeOwner {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        if let Self::External { manager_id } = self {
            validate_token("external manager id", manager_id, 256)?;
        }
        Ok(())
    }
}

/// Intended ownership is separate from the resource's network semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkManagementMode {
    /// A change must be represented in the declared NixOS configuration.
    NixOsDeclarative,
    /// A change may eventually be handled by a dedicated Nixward adapter.
    /// This value never authorizes or executes the change in this module.
    NixwardRuntime,
}

impl NetworkManagementMode {
    fn expected_configuration_owner(self) -> NetworkConfigurationOwner {
        match self {
            Self::NixOsDeclarative => NetworkConfigurationOwner::NixOsDeclarative,
            Self::NixwardRuntime => NetworkConfigurationOwner::NixwardDesiredState,
        }
    }

    fn allows_runtime_owner(self, owner: &NetworkRuntimeOwner) -> bool {
        matches!(
            (self, owner),
            (Self::NixwardRuntime, NetworkRuntimeOwner::NixwardRuntime)
                | (Self::NixOsDeclarative, NetworkRuntimeOwner::SystemdNetworkd)
                | (Self::NixOsDeclarative, NetworkRuntimeOwner::NetworkManager)
        )
    }
}

/// Capability discovery is explicit. Missing capability entries mean unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "support", rename_all = "kebab-case")]
pub enum NetworkResourceCapability {
    Supported,
    Unsupported { reason: String },
    Unknown { reason: String },
}

impl NetworkResourceCapability {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        match self {
            Self::Supported => Ok(()),
            Self::Unsupported { reason } | Self::Unknown { reason } => {
                validate_token("capability reason", reason, 512)
            }
        }
    }
}

/// A directly observed state or an explicit statement that the state is unknown.
/// `Known` fingerprints must be domain-separated and bind target, scope,
/// resource id, resource kind, schema version, and normalized non-secret
/// semantics. Do not fingerprint secrets, packet payloads, volatile counters,
/// or wall-clock timestamps as resource state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "observation", rename_all = "kebab-case")]
pub enum NetworkResourceObservation {
    Known {
        fingerprint_blake3: String,
        configuration_owner: NetworkConfigurationOwner,
        runtime_owner: NetworkRuntimeOwner,
    },
    Unknown {
        reason: String,
    },
}

impl NetworkResourceObservation {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        match self {
            Self::Known {
                fingerprint_blake3,
                configuration_owner,
                runtime_owner,
            } => {
                validate_digest(fingerprint_blake3)?;
                configuration_owner.validate()?;
                runtime_owner.validate()
            }
            Self::Unknown { reason } => validate_token("observation reason", reason, 512),
        }
    }

    fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::Known {
                fingerprint_blake3, ..
            } => Some(fingerprint_blake3),
            Self::Unknown { .. } => None,
        }
    }

    fn configuration_owner(&self) -> Option<&NetworkConfigurationOwner> {
        match self {
            Self::Known { configuration_owner, .. } => Some(configuration_owner),
            Self::Unknown { .. } => None,
        }
    }

    fn runtime_owner(&self) -> Option<&NetworkRuntimeOwner> {
        match self {
            Self::Known { runtime_owner, .. } => Some(runtime_owner),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedNetworkResource {
    pub id: NetworkResourceId,
    pub kind: NetworkResourceKind,
    pub observation: NetworkResourceObservation,
}

impl ObservedNetworkResource {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        self.id.validate()?;
        self.observation.validate()
    }
}

/// Identity of the system and network namespace the inventory describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDeviceTarget {
    pub machine_id: String,
    pub namespace_id: String,
    pub kernel_release: String,
}

impl NetworkDeviceTarget {
    pub fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        validate_token("machine id", &self.machine_id, 256)?;
        validate_token("network namespace id", &self.namespace_id, 256)?;
        validate_token("kernel release", &self.kernel_release, 256)
    }
}

/// Caller-supplied inventory snapshot. Completeness is asserted per resource
/// kind rather than globally: absence is evidence only for kinds explicitly
/// listed in `complete_kinds`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDeviceSnapshot {
    pub schema_version: u32,
    pub target: NetworkDeviceTarget,
    pub scope_id: String,
    pub observation_generation: u64,
    /// Identity of the collector that assembled this snapshot.
    pub collector_id: String,
    /// Digest of the exact collector build/configuration used to collect it.
    pub collector_build_blake3: String,
    pub resources: BTreeMap<NetworkResourceId, ObservedNetworkResource>,
    pub capabilities: BTreeMap<NetworkResourceKind, NetworkResourceCapability>,
    /// A kind is complete only when its evidence digest is present below.
    pub complete_kinds: BTreeSet<NetworkResourceKind>,
    /// Digests of artifacts supporting the completeness claim, keyed by kind.
    /// Evidence should bind target/namespace, resource family, collector build,
    /// request/reply boundaries, and all loss/interruption indicators. For
    /// Netlink dumps, an interrupted dump (NLM_F_DUMP_INTR), receive loss, or a
    /// truncated result must not be attested complete; retry within a bounded
    /// policy or keep that kind incomplete. This planner only binds these
    /// digests; a separate verifier must validate the referenced artifacts
    /// before any future adapter could use the inventory for actuation.
    pub completeness_evidence_blake3: BTreeMap<NetworkResourceKind, String>,
}

impl NetworkDeviceSnapshot {
    pub fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        if self.schema_version != NETWORK_DEVICE_PLAN_SCHEMA_VERSION {
            return Err(NetworkDevicePlanError::UnsupportedSchema(self.schema_version));
        }
        self.target.validate()?;
        validate_token("inventory scope id", &self.scope_id, 256)?;
        validate_token("collector id", &self.collector_id, 256)?;
        validate_digest(&self.collector_build_blake3)?;
        let evidence_kinds = self
            .completeness_evidence_blake3
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if evidence_kinds != self.complete_kinds {
            return Err(NetworkDevicePlanError::CompletenessEvidenceMismatch);
        }
        for digest in self.completeness_evidence_blake3.values() {
            validate_digest(digest)?;
        }
        for (key, resource) in &self.resources {
            key.validate()?;
            resource.validate()?;
            if key != &resource.id {
                return Err(NetworkDevicePlanError::ResourceKeyMismatch);
            }
        }
        for capability in self.capabilities.values() {
            capability.validate()?;
        }
        Ok(())
    }

    /// Schema-v1 digest uses deterministic JSON serialization of structs and
    /// BTree collections, domain-separated from other Nixward evidence digests.
    pub fn digest_hex(&self) -> Result<String, NetworkDevicePlanError> {
        self.validate()?;
        hash_json(SNAPSHOT_DOMAIN, self)
    }

    fn capability_for(&self, kind: NetworkResourceKind) -> NetworkResourceCapability {
        self.capabilities
            .get(&kind)
            .cloned()
            .unwrap_or(NetworkResourceCapability::Unknown {
                reason: "capability-not-observed".into(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredNetworkResource {
    pub id: NetworkResourceId,
    pub kind: NetworkResourceKind,
    pub desired_fingerprint_blake3: String,
    pub management_mode: NetworkManagementMode,
    /// Expected runtime manager, distinct from configuration ownership.
    pub expected_runtime_owner: NetworkRuntimeOwner,
}

impl DesiredNetworkResource {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        self.id.validate()?;
        validate_digest(&self.desired_fingerprint_blake3)?;
        self.expected_runtime_owner.validate()?;
        if !self.management_mode.allows_runtime_owner(&self.expected_runtime_owner) {
            return Err(NetworkDevicePlanError::InvalidDesiredOwnership);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredNetworkState {
    pub schema_version: u32,
    pub target: NetworkDeviceTarget,
    pub scope_id: String,
    pub resources: BTreeMap<NetworkResourceId, DesiredNetworkResource>,
}

impl DesiredNetworkState {
    pub fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        if self.schema_version != NETWORK_DEVICE_PLAN_SCHEMA_VERSION {
            return Err(NetworkDevicePlanError::UnsupportedSchema(self.schema_version));
        }
        self.target.validate()?;
        validate_token("desired scope id", &self.scope_id, 256)?;
        for (key, resource) in &self.resources {
            key.validate()?;
            resource.validate()?;
            if key != &resource.id {
                return Err(NetworkDevicePlanError::ResourceKeyMismatch);
            }
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkDevicePlanError> {
        self.validate()?;
        hash_json(DESIRED_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPlanBlockReason {
    ObservationUnknown,
    InventoryIncomplete,
    CapabilityUnknown,
    UnsupportedCapability,
    ResourceKindMismatch,
    ResourceOwnerConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum NetworkPlanDecision {
    NoOp,
    ProposedRuntimeCreate,
    ProposedRuntimeUpdate,
    RequiresDeclarativeChange,
    Blocked { reason: NetworkPlanBlockReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPlanEntry {
    pub resource_id: NetworkResourceId,
    pub kind: NetworkResourceKind,
    pub desired_fingerprint_blake3: String,
    pub observed_fingerprint_blake3: Option<String>,
    pub observed_configuration_owner: Option<NetworkConfigurationOwner>,
    pub observed_runtime_owner: Option<NetworkRuntimeOwner>,
    pub management_mode: NetworkManagementMode,
    pub expected_runtime_owner: NetworkRuntimeOwner,
    pub decision: NetworkPlanDecision,
}

impl NetworkPlanEntry {
    fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        self.resource_id.validate()?;
        validate_digest(&self.desired_fingerprint_blake3)?;
        if let Some(fingerprint) = &self.observed_fingerprint_blake3 {
            validate_digest(fingerprint)?;
        }
        if let Some(owner) = &self.observed_configuration_owner {
            owner.validate()?;
        }
        if let Some(owner) = &self.observed_runtime_owner {
            owner.validate()?;
        }
        self.expected_runtime_owner.validate()?;
        if !self.management_mode.allows_runtime_owner(&self.expected_runtime_owner) {
            return Err(NetworkDevicePlanError::InvalidDesiredOwnership);
        }
        Ok(())
    }
}

/// Review artifact only. It has no executor, no authorization token, and no
/// production-activation semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDevicePlan {
    pub schema_version: u32,
    pub status: String,
    pub target: NetworkDeviceTarget,
    pub scope_id: String,
    pub snapshot_blake3: String,
    pub desired_state_blake3: String,
    pub entries: Vec<NetworkPlanEntry>,
    pub reasoning_authority: String,
    pub execution_authority: String,
}

impl NetworkDevicePlan {
    pub fn validate(&self) -> Result<(), NetworkDevicePlanError> {
        if self.schema_version != NETWORK_DEVICE_PLAN_SCHEMA_VERSION {
            return Err(NetworkDevicePlanError::UnsupportedSchema(self.schema_version));
        }
        if self.status != NETWORK_DEVICE_PLAN_STATUS {
            return Err(NetworkDevicePlanError::InvalidPlanStatus);
        }
        self.target.validate()?;
        validate_token("plan scope id", &self.scope_id, 256)?;
        validate_digest(&self.snapshot_blake3)?;
        validate_digest(&self.desired_state_blake3)?;
        if self.reasoning_authority != "none" || self.execution_authority != "none" {
            return Err(NetworkDevicePlanError::AuthorityEscalation);
        }
        let mut previous: Option<&NetworkResourceId> = None;
        for entry in &self.entries {
            entry.validate()?;
            if let Some(last) = previous {
                if last >= &entry.resource_id {
                    return Err(NetworkDevicePlanError::EntriesNotStrictlySorted);
                }
            }
            previous = Some(&entry.resource_id);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkDevicePlanError> {
        self.validate()?;
        hash_json(PLAN_DOMAIN, self)
    }

    pub fn has_blocked_entries(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(&entry.decision, NetworkPlanDecision::Blocked { .. }))
    }
}

pub struct NetworkDevicePlanner;

impl NetworkDevicePlanner {
    /// Generate a deterministic proposal from validated inputs. This function
    /// is pure: it performs no I/O and returns no mutation authority.
    pub fn plan(
        snapshot: &NetworkDeviceSnapshot,
        desired: &DesiredNetworkState,
    ) -> Result<NetworkDevicePlan, NetworkDevicePlanError> {
        snapshot.validate()?;
        desired.validate()?;
        if snapshot.target != desired.target {
            return Err(NetworkDevicePlanError::TargetMismatch);
        }
        if snapshot.scope_id != desired.scope_id {
            return Err(NetworkDevicePlanError::ScopeMismatch);
        }

        let snapshot_blake3 = snapshot.digest_hex()?;
        let desired_state_blake3 = desired.digest_hex()?;
        let entries = desired
            .resources
            .values()
            .map(|resource| plan_entry(snapshot, resource))
            .collect::<Vec<_>>();

        let plan = NetworkDevicePlan {
            schema_version: NETWORK_DEVICE_PLAN_SCHEMA_VERSION,
            status: NETWORK_DEVICE_PLAN_STATUS.into(),
            target: desired.target.clone(),
            scope_id: desired.scope_id.clone(),
            snapshot_blake3,
            desired_state_blake3,
            entries,
            reasoning_authority: "none".into(),
            execution_authority: "none".into(),
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Verify that a candidate plan is exactly the deterministic output for
    /// these snapshot and desired-state inputs. Validating a plan in isolation
    /// checks structure only; it does not prove derivation from the referenced
    /// inputs. Future write-capable code must recompute and compare rather than
    /// trusting a supplied plan digest or serialized decision.
    pub fn verify_plan(
        snapshot: &NetworkDeviceSnapshot,
        desired: &DesiredNetworkState,
        candidate: &NetworkDevicePlan,
    ) -> Result<(), NetworkDevicePlanError> {
        candidate.validate()?;
        let recomputed = Self::plan(snapshot, desired)?;
        if candidate != &recomputed {
            return Err(NetworkDevicePlanError::PlanDoesNotMatchInputs);
        }
        Ok(())
    }
}

fn plan_entry(
    snapshot: &NetworkDeviceSnapshot,
    desired: &DesiredNetworkResource,
) -> NetworkPlanEntry {
    let observed = snapshot.resources.get(&desired.id);
    let (observed_fingerprint_blake3, observed_configuration_owner, observed_runtime_owner) =
        observed
            .map(|resource| {
                (
                    resource.observation.fingerprint().map(str::to_owned),
                    resource.observation.configuration_owner().cloned(),
                    resource.observation.runtime_owner().cloned(),
                )
            })
            .unwrap_or((None, None, None));

    // A partial family dump must never authorize a change to a resource that
    // happened to appear in the partial results. Its neighbours, dependencies,
    // or conflicting owners may have been omitted. Fail closed for the entire
    // desired resource kind until completeness evidence is available.
    let decision = if !snapshot.complete_kinds.contains(&desired.kind) {
        NetworkPlanDecision::Blocked {
            reason: NetworkPlanBlockReason::InventoryIncomplete,
        }
    } else {
        match observed {
            Some(resource) if resource.kind != desired.kind => NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::ResourceKindMismatch,
            },
            Some(resource) => match &resource.observation {
                NetworkResourceObservation::Unknown { .. } => NetworkPlanDecision::Blocked {
                    reason: NetworkPlanBlockReason::ObservationUnknown,
                },
                NetworkResourceObservation::Known {
                    fingerprint_blake3,
                    configuration_owner,
                    runtime_owner,
                } => {
                    // Matching state must not hide that another controller owns it.
                    if configuration_owner != &desired.management_mode.expected_configuration_owner()
                        || runtime_owner != &desired.expected_runtime_owner
                    {
                        NetworkPlanDecision::Blocked {
                            reason: NetworkPlanBlockReason::ResourceOwnerConflict,
                        }
                    } else if fingerprint_blake3 == &desired.desired_fingerprint_blake3 {
                        NetworkPlanDecision::NoOp
                    } else if let Some(reason) = capability_block_reason(snapshot, desired.kind) {
                        NetworkPlanDecision::Blocked { reason }
                    } else {
                        match desired.management_mode {
                            NetworkManagementMode::NixOsDeclarative => {
                                NetworkPlanDecision::RequiresDeclarativeChange
                            }
                            NetworkManagementMode::NixwardRuntime => {
                                NetworkPlanDecision::ProposedRuntimeUpdate
                            }
                        }
                    }
                }
            },
            None => {
                if let Some(reason) = capability_block_reason(snapshot, desired.kind) {
                    NetworkPlanDecision::Blocked { reason }
                } else {
                    match desired.management_mode {
                        NetworkManagementMode::NixOsDeclarative => {
                            NetworkPlanDecision::RequiresDeclarativeChange
                        }
                        NetworkManagementMode::NixwardRuntime => {
                            NetworkPlanDecision::ProposedRuntimeCreate
                        }
                    }
                }
            }
        }
    };

    NetworkPlanEntry {
        resource_id: desired.id.clone(),
        kind: desired.kind,
        desired_fingerprint_blake3: desired.desired_fingerprint_blake3.clone(),
        observed_fingerprint_blake3,
        observed_configuration_owner,
        observed_runtime_owner,
        management_mode: desired.management_mode,
        expected_runtime_owner: desired.expected_runtime_owner.clone(),
        decision,
    }
}

fn capability_block_reason(
    snapshot: &NetworkDeviceSnapshot,
    kind: NetworkResourceKind,
) -> Option<NetworkPlanBlockReason> {
    match snapshot.capability_for(kind) {
        NetworkResourceCapability::Supported => None,
        NetworkResourceCapability::Unknown { .. } => {
            Some(NetworkPlanBlockReason::CapabilityUnknown)
        }
        NetworkResourceCapability::Unsupported { .. } => {
            Some(NetworkPlanBlockReason::UnsupportedCapability)
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkDevicePlanError {
    #[error("unsupported network-device plan schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),
    #[error("invalid BLAKE3 digest")]
    InvalidDigest,
    #[error("resource map key does not match its embedded resource id")]
    ResourceKeyMismatch,
    #[error("complete resource kinds and completeness evidence keys differ")]
    CompletenessEvidenceMismatch,
    #[error("snapshot and desired state target identities differ")]
    TargetMismatch,
    #[error("snapshot and desired state scopes differ")]
    ScopeMismatch,
    #[error("desired management mode and expected runtime owner are incompatible")]
    InvalidDesiredOwnership,
    #[error("candidate plan does not match a fresh plan from the supplied inputs")]
    PlanDoesNotMatchInputs,
    #[error("plan status is not the read-only M0 status")]
    InvalidPlanStatus,
    #[error("plan claims reasoning or execution authority")]
    AuthorityEscalation,
    #[error("plan entries are not strictly sorted or contain duplicate identities")]
    EntriesNotStrictlySorted,
    #[error("plan JSON serialization failed")]
    Serialization,
}

fn validate_token(
    label: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), NetworkDevicePlanError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > max_len
        || value.contains('\0')
    {
        return Err(NetworkDevicePlanError::InvalidToken(label));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), NetworkDevicePlanError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NetworkDevicePlanError::InvalidDigest);
    }
    Ok(())
}

fn hash_json<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, NetworkDevicePlanError> {
    let bytes = serde_json::to_vec(value).map_err(|_| NetworkDevicePlanError::Serialization)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn target() -> NetworkDeviceTarget {
        NetworkDeviceTarget {
            machine_id: "lab-router-1".into(),
            namespace_id: "netns:isolated-router".into(),
            kernel_release: "6.12.0-test".into(),
        }
    }

    fn id(value: &str) -> NetworkResourceId {
        NetworkResourceId::new(value).expect("valid test resource id")
    }

    fn snapshot() -> NetworkDeviceSnapshot {
        NetworkDeviceSnapshot {
            schema_version: NETWORK_DEVICE_PLAN_SCHEMA_VERSION,
            target: target(),
            scope_id: "lab-router-networking-v1".into(),
            observation_generation: 1,
            collector_id: "fixture:network-device-planner-tests".into(),
            collector_build_blake3: fingerprint('d'),
            resources: BTreeMap::new(),
            capabilities: BTreeMap::from([(
                NetworkResourceKind::Link,
                NetworkResourceCapability::Supported,
            )]),
            complete_kinds: BTreeSet::from([NetworkResourceKind::Link]),
            completeness_evidence_blake3: BTreeMap::from([(
                NetworkResourceKind::Link,
                fingerprint('c'),
            )]),
        }
    }

    fn desired(mode: NetworkManagementMode) -> DesiredNetworkState {
        let id = id("link:lan0");
        let expected_runtime_owner = match mode {
            NetworkManagementMode::NixOsDeclarative => NetworkRuntimeOwner::SystemdNetworkd,
            NetworkManagementMode::NixwardRuntime => NetworkRuntimeOwner::NixwardRuntime,
        };
        DesiredNetworkState {
            schema_version: NETWORK_DEVICE_PLAN_SCHEMA_VERSION,
            target: target(),
            scope_id: "lab-router-networking-v1".into(),
            resources: BTreeMap::from([(
                id.clone(),
                DesiredNetworkResource {
                    id,
                    kind: NetworkResourceKind::Link,
                    desired_fingerprint_blake3: fingerprint('a'),
                    management_mode: mode,
                    expected_runtime_owner,
                },
            )]),
        }
    }

    fn known_observation(
        fingerprint_blake3: String,
        configuration_owner: NetworkConfigurationOwner,
        runtime_owner: NetworkRuntimeOwner,
    ) -> ObservedNetworkResource {
        ObservedNetworkResource {
            id: id("link:lan0"),
            kind: NetworkResourceKind::Link,
            observation: NetworkResourceObservation::Known {
                fingerprint_blake3,
                configuration_owner,
                runtime_owner,
            },
        }
    }

    fn entry(plan: &NetworkDevicePlan) -> &NetworkPlanEntry {
        plan.entries.first().expect("one desired resource")
    }

    #[test]
    fn identical_state_is_a_no_op_with_no_authority() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            known_observation(
                fingerprint('a'),
                NetworkConfigurationOwner::NixwardDesiredState,
                NetworkRuntimeOwner::NixwardRuntime,
            ),
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid plan");

        assert_eq!(entry(&plan).decision, NetworkPlanDecision::NoOp);
        assert_eq!(plan.reasoning_authority, "none");
        assert_eq!(plan.execution_authority, "none");
        assert!(!plan.has_blocked_entries());
        plan.validate().expect("validated plan");
    }

    #[test]
    fn complete_supported_inventory_proposes_runtime_create_only() {
        let plan = NetworkDevicePlanner::plan(
            &snapshot(),
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::ProposedRuntimeCreate
        );
        assert_eq!(plan.execution_authority, "none");
    }

    #[test]
    fn complete_kinds_require_matching_completeness_evidence() {
        let mut snapshot = snapshot();
        snapshot.completeness_evidence_blake3.clear();

        assert_eq!(
            snapshot.validate(),
            Err(NetworkDevicePlanError::CompletenessEvidenceMismatch)
        );
    }

    #[test]
    fn incomplete_inventory_never_infers_resource_absence() {
        let mut snapshot = snapshot();
        snapshot.complete_kinds.clear();
        snapshot.completeness_evidence_blake3.clear();

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::InventoryIncomplete
            }
        );
    }

    #[test]
    fn incomplete_inventory_blocks_update_even_when_resource_appears_in_partial_dump() {
        let mut snapshot = snapshot();
        // Model a partial/interrupted link-family dump. The target resource
        // happened to arrive, but the family is not complete and must not be
        // used to authorize updates.
        snapshot.complete_kinds.clear();
        snapshot.completeness_evidence_blake3.clear();
        snapshot.resources.insert(
            id("link:lan0"),
            known_observation(
                fingerprint('b'),
                NetworkConfigurationOwner::NixwardDesiredState,
                NetworkRuntimeOwner::NixwardRuntime,
            ),
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::InventoryIncomplete
            }
        );
    }

    #[test]
    fn declarative_resources_produce_no_runtime_update_proposal() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            known_observation(
                fingerprint('b'),
                NetworkConfigurationOwner::NixOsDeclarative,
                NetworkRuntimeOwner::SystemdNetworkd,
            ),
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixOsDeclarative),
        )
        .expect("valid plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::RequiresDeclarativeChange
        );
    }

    #[test]
    fn external_manager_conflict_blocks_runtime_change() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            known_observation(
                fingerprint('b'),
                NetworkConfigurationOwner::NixwardDesiredState,
                NetworkRuntimeOwner::NetworkManager,
            ),
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::ResourceOwnerConflict
            }
        );
    }

    #[test]
    fn unknown_capability_blocks_creation() {
        let mut snapshot = snapshot();
        snapshot.capabilities.remove(&NetworkResourceKind::Link);

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::CapabilityUnknown
            }
        );
    }

    #[test]
    fn explicitly_unsupported_capability_blocks_creation() {
        let mut snapshot = snapshot();
        snapshot.capabilities.insert(
            NetworkResourceKind::Link,
            NetworkResourceCapability::Unsupported {
                reason: "adapter does not manage links".into(),
            },
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::UnsupportedCapability
            }
        );
    }

    #[test]
    fn resource_kind_change_is_not_silently_reinterpreted() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            ObservedNetworkResource {
                id: id("link:lan0"),
                kind: NetworkResourceKind::Bridge,
                observation: NetworkResourceObservation::Known {
                    fingerprint_blake3: fingerprint('b'),
                    configuration_owner: NetworkConfigurationOwner::NixwardDesiredState,
                    runtime_owner: NetworkRuntimeOwner::NixwardRuntime,
                },
            },
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::ResourceKindMismatch
            }
        );
    }

    #[test]
    fn unknown_observation_blocks_mutation_proposal() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            ObservedNetworkResource {
                id: id("link:lan0"),
                kind: NetworkResourceKind::Link,
                observation: NetworkResourceObservation::Unknown {
                    reason: "kernel dump incomplete".into(),
                },
            },
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::ObservationUnknown
            }
        );
    }

    #[test]
    fn matching_fingerprint_does_not_hide_ownership_conflict() {
        let mut snapshot = snapshot();
        snapshot.resources.insert(
            id("link:lan0"),
            known_observation(
                fingerprint('a'),
                NetworkConfigurationOwner::NixOsDeclarative,
                NetworkRuntimeOwner::SystemdNetworkd,
            ),
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid blocked plan");

        assert_eq!(
            entry(&plan).decision,
            NetworkPlanDecision::Blocked {
                reason: NetworkPlanBlockReason::ResourceOwnerConflict
            }
        );
    }

    #[test]
    fn plans_are_deterministic_for_identical_inputs() {
        let snapshot = snapshot();
        let desired = desired(NetworkManagementMode::NixwardRuntime);
        let first = NetworkDevicePlanner::plan(&snapshot, &desired).expect("first plan");
        let second = NetworkDevicePlanner::plan(&snapshot, &desired).expect("second plan");

        assert_eq!(first, second);
        assert_eq!(first.digest_hex().expect("first digest"), second.digest_hex().expect("second digest"));
    }

    #[test]
    fn plan_verifier_rejects_tampered_decision() {
        let snapshot = snapshot();
        let desired = desired(NetworkManagementMode::NixwardRuntime);
        let mut candidate = NetworkDevicePlanner::plan(&snapshot, &desired)
            .expect("valid plan");
        candidate.entries[0].decision = NetworkPlanDecision::NoOp;

        assert_eq!(
            NetworkDevicePlanner::verify_plan(&snapshot, &desired, &candidate),
            Err(NetworkDevicePlanError::PlanDoesNotMatchInputs)
        );
    }

    #[test]
    fn desired_state_rejects_incompatible_runtime_owner() {
        let mut desired = desired(NetworkManagementMode::NixOsDeclarative);
        desired
            .resources
            .get_mut(&id("link:lan0"))
            .expect("resource")
            .expected_runtime_owner = NetworkRuntimeOwner::NixwardRuntime;

        assert_eq!(
            desired.validate(),
            Err(NetworkDevicePlanError::InvalidDesiredOwnership)
        );
    }

    #[test]
    fn target_mismatch_is_rejected_before_planning() {
        let snapshot = snapshot();
        let mut desired = desired(NetworkManagementMode::NixwardRuntime);
        desired.target.machine_id = "different-machine".into();

        assert_eq!(
            NetworkDevicePlanner::plan(&snapshot, &desired),
            Err(NetworkDevicePlanError::TargetMismatch)
        );
    }

    #[test]
    fn unrelated_observed_resources_are_never_deleted() {
        let mut snapshot = snapshot();
        let extra_id = id("link:unmanaged0");
        snapshot.resources.insert(
            extra_id.clone(),
            ObservedNetworkResource {
                id: extra_id.clone(),
                kind: NetworkResourceKind::Link,
                observation: NetworkResourceObservation::Known {
                    fingerprint_blake3: fingerprint('b'),
                    configuration_owner: NetworkConfigurationOwner::NixwardDesiredState,
                    runtime_owner: NetworkRuntimeOwner::NixwardRuntime,
                },
            },
        );

        let plan = NetworkDevicePlanner::plan(
            &snapshot,
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid plan");

        assert_eq!(plan.entries.len(), 1);
        assert!(plan.entries.iter().all(|entry| entry.resource_id != extra_id));
    }

    #[test]
    fn authority_escalation_in_serialized_plan_is_rejected() {
        let mut plan = NetworkDevicePlanner::plan(
            &snapshot(),
            &desired(NetworkManagementMode::NixwardRuntime),
        )
        .expect("valid plan");
        plan.execution_authority = "automatic".into();

        assert_eq!(
            plan.validate(),
            Err(NetworkDevicePlanError::AuthorityEscalation)
        );
    }

    #[test]
    fn invalid_uppercase_digest_is_rejected() {
        let mut desired = desired(NetworkManagementMode::NixwardRuntime);
        desired
            .resources
            .get_mut(&id("link:lan0"))
            .expect("resource")
            .desired_fingerprint_blake3 = fingerprint('A');

        assert_eq!(
            desired.validate(),
            Err(NetworkDevicePlanError::InvalidDigest)
        );
    }
}
