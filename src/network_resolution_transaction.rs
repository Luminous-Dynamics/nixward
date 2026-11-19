// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure, fail-closed reducer for one request-scoped network lease activation.
//!
//! This module does not write kernel maps or consume a replay ledger. It models
//! the broker transaction boundary so runtime code can persist/replay events
//! and cannot confuse an unknown generation-switch outcome with success.
//!
//! A snapshot is not an authority token. Runtime execution is permitted only
//! after a separately authenticated broker has applied the events and read
//! back the exact active map generation and digest.

use crate::network_covenant::{
    NetworkCapability, NetworkCapabilityLease, NetworkPolicyPlan, NetworkProtocol,
};
use crate::network_resolution_lease::{
    AuthorizedNetworkResolutionLease, NetworkResolutionLeaseV1,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

pub const NETWORK_RESOLUTION_TRANSACTION_SCHEMA_VERSION: u32 = 1;
const TRANSACTION_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-transaction:v1\0";
const MAP_PAYLOAD_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-map-payload:v1\0";
const REPLAY_RECORD_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-replay-record:v1\0";

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_serialized_domain<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, NetworkResolutionTransactionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| NetworkResolutionTransactionError::Serialization)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_serialized<T: Serialize>(value: &T) -> Result<String, NetworkResolutionTransactionError> {
    hash_serialized_domain(TRANSACTION_DOMAIN, value)
}

/// Non-deserializable proof that a resolution lease passed detached-signature
/// verification and exact owner-authorized parent-policy binding.
///
/// It is deliberately distinct from a structurally valid lease. Production
/// transaction APIs accept this type rather than raw lease JSON or a caller-
/// assembled struct. It remains a source-level proof object: the privileged
/// broker must still authenticate its IPC caller/cgroup and recheck current
/// policy generation and expiry immediately before each mutation.
#[must_use]
#[derive(Debug, Clone)]
pub struct ParentBoundNetworkResolutionLease {
    lease: NetworkResolutionLeaseV1,
    parent_policy_blake3: String,
    parent_capability_blake3: String,
    parent_authority_lease_blake3: String,
    parent_expires_at_unix: u64,
    active_policy_generation: u64,
    authority_evidence_blake3: String,
    resolver_key_id: String,
    replay_key: String,
}

impl ParentBoundNetworkResolutionLease {
    /// Verify the signature-sealed lease against the exact parent policy,
    /// capability and owner-issued parent lease before it can enter the
    /// transaction reducer.
    pub fn bind(
        authorized: AuthorizedNetworkResolutionLease,
        policy: &NetworkPolicyPlan,
        capability: &NetworkCapability,
        parent_lease: &NetworkCapabilityLease,
        now_unix: u64,
        active_policy_generation: u64,
    ) -> Result<Self, NetworkResolutionTransactionError> {
        authorized
            .validate_parent_binding(
                policy,
                capability,
                parent_lease,
                now_unix,
                active_policy_generation,
            )
            .map_err(|error| {
                NetworkResolutionTransactionError::ParentBinding(error.to_string())
            })?;

        let parent_policy_blake3 = policy
            .digest_hex()
            .map_err(|error| NetworkResolutionTransactionError::ParentBinding(error.to_string()))?;
        let parent_capability_blake3 = capability.digest_hex().map_err(|error| {
            NetworkResolutionTransactionError::ParentBinding(error.to_string())
        })?;
        let parent_authority_lease_blake3 = parent_lease.digest_hex().map_err(|error| {
            NetworkResolutionTransactionError::ParentBinding(error.to_string())
        })?;

        Ok(Self {
            lease: authorized.lease().clone(),
            parent_policy_blake3,
            parent_capability_blake3,
            parent_authority_lease_blake3,
            parent_expires_at_unix: parent_lease.expires_at_unix,
            active_policy_generation,
            authority_evidence_blake3: authorized.evidence_blake3().to_owned(),
            resolver_key_id: authorized.signer_key_id().to_owned(),
            replay_key: authorized.replay_key().to_owned(),
        })
    }

    /// Test-only constructor for deterministic state-machine tests. It bypasses
    /// cryptographic and parent-policy verification and is unavailable outside
    /// cfg(test) builds.
    #[cfg(test)]
    fn test_only(
        lease: NetworkResolutionLeaseV1,
        parent_expires_at_unix: u64,
    ) -> Self {
        Self {
            parent_policy_blake3: lease.network_policy_blake3.clone(),
            parent_capability_blake3: lease.parent_capability_blake3.clone(),
            parent_authority_lease_blake3: lease.parent_authority_lease_blake3.clone(),
            active_policy_generation: lease.policy_generation,
            authority_evidence_blake3: "aa".repeat(32),
            resolver_key_id: lease.issuer_key_id.clone(),
            replay_key: "bb".repeat(32),
            lease,
            parent_expires_at_unix,
        }
    }

    pub fn lease(&self) -> &NetworkResolutionLeaseV1 {
        &self.lease
    }

    pub fn parent_policy_blake3(&self) -> &str {
        &self.parent_policy_blake3
    }

    pub fn parent_capability_blake3(&self) -> &str {
        &self.parent_capability_blake3
    }

    pub fn parent_authority_lease_blake3(&self) -> &str {
        &self.parent_authority_lease_blake3
    }

    pub fn authority_evidence_blake3(&self) -> &str {
        &self.authority_evidence_blake3
    }

    pub fn resolver_key_id(&self) -> &str {
        &self.resolver_key_id
    }

    pub fn replay_key(&self) -> &str {
        &self.replay_key
    }

    fn validate_at(
        &self,
        now_unix: u64,
        active_policy_generation: u64,
    ) -> Result<(), NetworkResolutionTransactionError> {
        if active_policy_generation != self.active_policy_generation
            || active_policy_generation != self.lease.policy_generation
        {
            return Err(NetworkResolutionTransactionError::PolicyGenerationMismatch);
        }
        if self.lease.expires_at_unix > self.parent_expires_at_unix {
            return Err(NetworkResolutionTransactionError::ParentLeaseTimeMismatch);
        }
        if now_unix < self.lease.issued_at_unix
            || now_unix >= self.lease.expires_at_unix
            || now_unix >= self.parent_expires_at_unix
        {
            return Err(NetworkResolutionTransactionError::ParentLeaseExpired);
        }
        Ok(())
    }
}

/// Exact v1 contents expected in the inactive workload address-map generation.
///
/// This binds the cgroup identity, workload, parent-derived policy, request
/// lease, complete address set, TCP port, policy generation, expiry and target
/// map generation. It is a deterministic payload description, not proof that
/// a privileged broker actually wrote or activated the map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResolutionMapPayloadV1 {
    pub schema_version: u32,
    pub cgroup_identity_blake3: String,
    pub bpf_program_blake3: String,
    pub workload_blake3: String,
    pub network_policy_blake3: String,
    pub parent_capability_blake3: String,
    pub parent_authority_lease_blake3: String,
    pub address_policy_blake3: String,
    pub resolver_snapshot_blake3: String,
    pub lease_blake3: String,
    pub address_set_blake3: String,
    pub transport: NetworkProtocol,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub policy_generation: u64,
    pub target_active_generation: u64,
    pub lease_expires_at_unix: u64,
}

impl NetworkResolutionMapPayloadV1 {
    /// Build a payload bound to one validated lease and one broker-observed
    /// cgroup identity. The broker must obtain the cgroup digest itself; it
    /// must never trust a caller-supplied PID or cgroup path as proof.
    pub fn for_lease(
        bound_lease: &ParentBoundNetworkResolutionLease,
        cgroup_identity_blake3: impl Into<String>,
        bpf_program_blake3: impl Into<String>,
        target_active_generation: u64,
        now_unix: u64,
        active_policy_generation: u64,
    ) -> Result<Self, NetworkResolutionTransactionError> {
        bound_lease.validate_at(now_unix, active_policy_generation)?;
        let lease = bound_lease.lease();
        lease
            .validate_structure()
            .map_err(|_| NetworkResolutionTransactionError::InvalidLease)?;
        let payload = Self {
            schema_version: 1,
            cgroup_identity_blake3: cgroup_identity_blake3.into(),
            bpf_program_blake3: bpf_program_blake3.into(),
            workload_blake3: lease.workload_blake3.clone(),
            network_policy_blake3: bound_lease.parent_policy_blake3().to_owned(),
            parent_capability_blake3: bound_lease.parent_capability_blake3().to_owned(),
            parent_authority_lease_blake3: bound_lease.parent_authority_lease_blake3().to_owned(),
            address_policy_blake3: lease.address_policy_blake3.clone(),
            resolver_snapshot_blake3: lease.resolver_snapshot_blake3.clone(),
            lease_blake3,
            address_set_blake3: lease.address_set_digest_hex(),
            transport: lease.transport,
            port: lease.port,
            addresses: lease.addresses.clone(),
            policy_generation: lease.policy_generation,
            target_active_generation,
            lease_expires_at_unix: lease.expires_at_unix,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), NetworkResolutionTransactionError> {
        if self.schema_version != 1
            || !is_digest(&self.cgroup_identity_blake3)
            || !is_digest(&self.bpf_program_blake3)
            || !is_digest(&self.workload_blake3)
            || !is_digest(&self.network_policy_blake3)
            || !is_digest(&self.parent_capability_blake3)
            || !is_digest(&self.parent_authority_lease_blake3)
            || !is_digest(&self.address_policy_blake3)
            || !is_digest(&self.resolver_snapshot_blake3)
            || !is_digest(&self.lease_blake3)
            || !is_digest(&self.address_set_blake3)
            || self.transport != NetworkProtocol::Tcp
            || self.port == 0
            || self.addresses.is_empty()
            || self.addresses.len() > 32
            || self.policy_generation == 0
            || self.target_active_generation == 0
            || self.lease_expires_at_unix == 0
        {
            return Err(NetworkResolutionTransactionError::InvalidMapPayload);
        }
        let mut canonical = self.addresses.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical != self.addresses
            || self.addresses.iter().any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(NetworkResolutionTransactionError::InvalidMapPayload);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkResolutionTransactionError> {
        self.validate()?;
        hash_serialized_domain(MAP_PAYLOAD_DOMAIN, self)
    }

    fn validate_for_lease(
        &self,
        bound_lease: &ParentBoundNetworkResolutionLease,
        expected_generation: u64,
    ) -> Result<(), NetworkResolutionTransactionError> {
        self.validate()?;
        let lease = bound_lease.lease();
        let lease_digest = lease
            .digest_hex()
            .map_err(|_| NetworkResolutionTransactionError::InvalidLease)?;
        if self.workload_blake3 != lease.workload_blake3
            || self.network_policy_blake3 != bound_lease.parent_policy_blake3()
            || self.parent_capability_blake3 != bound_lease.parent_capability_blake3()
            || self.parent_authority_lease_blake3 != bound_lease.parent_authority_lease_blake3()
            || self.address_policy_blake3 != lease.address_policy_blake3
            || self.resolver_snapshot_blake3 != lease.resolver_snapshot_blake3
            || self.lease_blake3 != lease_digest
            || self.address_set_blake3 != lease.address_set_digest_hex()
            || self.transport != lease.transport
            || self.port != lease.port
            || self.addresses != lease.addresses
            || self.policy_generation != lease.policy_generation
            || self.lease_expires_at_unix != lease.expires_at_unix
            || self.target_active_generation != expected_generation
        {
            return Err(NetworkResolutionTransactionError::MapPayloadMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkResolutionSwitchOutcome {
    Committed,
    NotCommitted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkResolutionTransactionState {
    Prepared,
    NonceReconciliationRequired,
    NonceConsumed,
    MapStageReconciliationRequired,
    MapStaged,
    MapVerified,
    ReconciliationRequired,
    Active,
    NotCommitted,
    Conflict,
}

/// Append-only events accepted by the transaction reducer.
///
/// The event stream may be persisted by a future broker, but event data alone
/// does not authenticate the producer. The broker must bind replay-ledger and
/// kernel read-back records to its own authenticated IPC/runtime observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NetworkResolutionTransactionEvent {
    NonceConsumptionUnknown {
        replay_record_blake3: String,
    },
    ReplayLedgerReconciled {
        replay_record_blake3: Option<String>,
    },
    NonceConsumed {
        replay_record_blake3: String,
    },
    MapStageOutcomeUnknown {
        generation: u64,
        map_payload_blake3: String,
    },
    StagedMapReconciled {
        generation: u64,
        map_payload_blake3: Option<String>,
    },
    MapStaged {
        generation: u64,
        map_payload_blake3: String,
    },
    MapVerified {
        generation: u64,
        map_payload_blake3: String,
    },
    SwitchAttempted {
        outcome: NetworkResolutionSwitchOutcome,
    },
    Reconciled {
        active_generation: u64,
        active_map_payload_blake3: Option<String>,
    },
}

#[derive(Serialize)]
struct ReplayRecordBinding<'a> {
    lease_blake3: &'a str,
    replay_key: &'a str,
    resolver_key_id: &'a str,
    authority_evidence_blake3: &'a str,
}

/// A single lease's expected transition from prepared authority to an
/// observed active kernel-map generation.
///
/// Fields are private and the type intentionally has no Deserialize
/// implementation. Reconstruct state by replaying validated events through
/// `apply`, never by deserializing a caller-supplied "Active" snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkResolutionTransaction {
    schema_version: u32,
    logical_request_id: String,
    redirect_hop: u8,
    lease_blake3: String,
    address_set_blake3: String,
    parent_policy_blake3: String,
    parent_capability_blake3: String,
    parent_authority_lease_blake3: String,
    authority_evidence_blake3: String,
    resolver_key_id: String,
    replay_key: String,
    expected_replay_record_blake3: String,
    expected_map_payload_blake3: String,
    prior_active_generation: u64,
    prior_active_map_payload_blake3: String,
    target_active_generation: u64,
    state: NetworkResolutionTransactionState,
    pending_replay_record_blake3: Option<String>,
    replay_record_blake3: Option<String>,
    pending_staged_map_payload_blake3: Option<String>,
    staged_map_payload_blake3: Option<String>,
    verified_map_payload_blake3: Option<String>,
    switch_outcome: Option<NetworkResolutionSwitchOutcome>,
    reconciled_active_generation: Option<u64>,
}

impl NetworkResolutionTransaction {
    /// Begin one transaction from an already structurally validated lease
    /// and its exact cgroup-bound kernel-map payload.
    pub fn begin(
        bound_lease: &ParentBoundNetworkResolutionLease,
        map_payload: NetworkResolutionMapPayloadV1,
        now_unix: u64,
        active_policy_generation: u64,
        prior_active_generation: u64,
        prior_active_map_payload_blake3: impl Into<String>,
    ) -> Result<Self, NetworkResolutionTransactionError> {
        bound_lease.validate_at(now_unix, active_policy_generation)?;
        let lease = bound_lease.lease();
        lease
            .validate_structure()
            .map_err(|_| NetworkResolutionTransactionError::InvalidLease)?;
        let prior_active_map_payload_blake3 = prior_active_map_payload_blake3.into();
        if !is_digest(&prior_active_map_payload_blake3) {
            return Err(NetworkResolutionTransactionError::InvalidDigest);
        }
        let target_active_generation = prior_active_generation
            .checked_add(1)
            .ok_or(NetworkResolutionTransactionError::GenerationOverflow)?;
        map_payload.validate_for_lease(bound_lease, target_active_generation)?;
        let expected_map_payload_blake3 = map_payload.digest_hex()?;
        let lease_blake3 = lease
            .digest_hex()
            .map_err(|_| NetworkResolutionTransactionError::InvalidLease)?;
        let expected_replay_record_blake3 = hash_serialized_domain(
            REPLAY_RECORD_DOMAIN,
            &ReplayRecordBinding {
                lease_blake3: &lease_blake3,
                replay_key: bound_lease.replay_key(),
                resolver_key_id: bound_lease.resolver_key_id(),
                authority_evidence_blake3: bound_lease.authority_evidence_blake3(),
            },
        )?;

        Ok(Self {
            schema_version: NETWORK_RESOLUTION_TRANSACTION_SCHEMA_VERSION,
            logical_request_id: lease.logical_request_id.clone(),
            redirect_hop: lease.redirect_hop,
            lease_blake3: lease
                .digest_hex()
                .map_err(|_| NetworkResolutionTransactionError::InvalidLease)?,
            address_set_blake3: lease.address_set_digest_hex(),
            parent_policy_blake3: bound_lease.parent_policy_blake3().to_owned(),
            parent_capability_blake3: bound_lease.parent_capability_blake3().to_owned(),
            parent_authority_lease_blake3: bound_lease.parent_authority_lease_blake3().to_owned(),
            authority_evidence_blake3: bound_lease.authority_evidence_blake3().to_owned(),
            resolver_key_id: bound_lease.resolver_key_id().to_owned(),
            replay_key: bound_lease.replay_key().to_owned(),
            expected_replay_record_blake3,
            expected_map_payload_blake3,
            prior_active_generation,
            prior_active_map_payload_blake3,
            target_active_generation,
            state: NetworkResolutionTransactionState::Prepared,
            pending_replay_record_blake3: None,
            replay_record_blake3: None,
            pending_staged_map_payload_blake3: None,
            staged_map_payload_blake3: None,
            verified_map_payload_blake3: None,
            switch_outcome: None,
            reconciled_active_generation: None,
        })
    }

    /// Apply one event. Any out-of-order or contradictory event permanently
    /// places this in Conflict; a caller must start with a fresh, authorized
    /// lease rather than attempting to repair or replay a widened transaction.
    pub fn apply(
        &mut self,
        event: NetworkResolutionTransactionEvent,
    ) -> Result<(), NetworkResolutionTransactionError> {
        let result = self.apply_checked(event);
        if result.is_err() {
            self.state = NetworkResolutionTransactionState::Conflict;
        }
        result
    }

    fn apply_checked(
        &mut self,
        event: NetworkResolutionTransactionEvent,
    ) -> Result<(), NetworkResolutionTransactionError> {
        match event {
            NetworkResolutionTransactionEvent::NonceConsumptionUnknown {
                replay_record_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::Prepared)?;
                if !is_digest(&replay_record_blake3) {
                    return Err(NetworkResolutionTransactionError::InvalidDigest);
                }
                if replay_record_blake3 != self.expected_replay_record_blake3 {
                    return Err(NetworkResolutionTransactionError::ReplayRecordConflict);
                }
                self.pending_replay_record_blake3 = Some(replay_record_blake3);
                self.state = NetworkResolutionTransactionState::NonceReconciliationRequired;
            }
            NetworkResolutionTransactionEvent::ReplayLedgerReconciled {
                replay_record_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::NonceReconciliationRequired)?;
                match replay_record_blake3 {
                    Some(observed) => {
                        if self.pending_replay_record_blake3.as_deref() != Some(observed.as_str())
                            || !is_digest(&observed)
                        {
                            return Err(NetworkResolutionTransactionError::ReplayRecordConflict);
                        }
                        self.replay_record_blake3 = Some(observed);
                        self.pending_replay_record_blake3 = None;
                        self.state = NetworkResolutionTransactionState::NonceConsumed;
                    }
                    None => {
                        self.pending_replay_record_blake3 = None;
                        self.state = NetworkResolutionTransactionState::Prepared;
                    }
                }
            }
            NetworkResolutionTransactionEvent::NonceConsumed { replay_record_blake3 } => {
                self.require_state(NetworkResolutionTransactionState::Prepared)?;
                if !is_digest(&replay_record_blake3) {
                    return Err(NetworkResolutionTransactionError::InvalidDigest);
                }
                if replay_record_blake3 != self.expected_replay_record_blake3 {
                    return Err(NetworkResolutionTransactionError::ReplayRecordConflict);
                }
                self.replay_record_blake3 = Some(replay_record_blake3);
                self.state = NetworkResolutionTransactionState::NonceConsumed;
            }
            NetworkResolutionTransactionEvent::MapStageOutcomeUnknown {
                generation,
                map_payload_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::NonceConsumed)?;
                self.require_target_generation(generation)?;
                self.require_expected_map_digest(&map_payload_blake3)?;
                self.pending_staged_map_payload_blake3 = Some(map_payload_blake3);
                self.state = NetworkResolutionTransactionState::MapStageReconciliationRequired;
            }
            NetworkResolutionTransactionEvent::StagedMapReconciled {
                generation,
                map_payload_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::MapStageReconciliationRequired)?;
                self.require_target_generation(generation)?;
                match map_payload_blake3 {
                    Some(observed) => {
                        self.require_expected_map_digest(&observed)?;
                        if self.pending_staged_map_payload_blake3.as_deref()
                            != Some(observed.as_str())
                        {
                            return Err(NetworkResolutionTransactionError::MapDigestMismatch);
                        }
                        self.staged_map_payload_blake3 = Some(observed);
                        self.pending_staged_map_payload_blake3 = None;
                        self.state = NetworkResolutionTransactionState::MapStaged;
                    }
                    None => {
                        self.pending_staged_map_payload_blake3 = None;
                        self.state = NetworkResolutionTransactionState::NonceConsumed;
                    }
                }
            }
            NetworkResolutionTransactionEvent::MapStaged {
                generation,
                map_payload_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::NonceConsumed)?;
                self.require_target_generation(generation)?;
                self.require_expected_map_digest(&map_payload_blake3)?;
                self.staged_map_payload_blake3 = Some(map_payload_blake3);
                self.state = NetworkResolutionTransactionState::MapStaged;
            }
            NetworkResolutionTransactionEvent::MapVerified {
                generation,
                map_payload_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::MapStaged)?;
                self.require_target_generation(generation)?;
                self.require_expected_map_digest(&map_payload_blake3)?;
                if self.staged_map_payload_blake3.as_deref()
                    != Some(map_payload_blake3.as_str())
                {
                    return Err(NetworkResolutionTransactionError::MapDigestMismatch);
                }
                self.verified_map_payload_blake3 = Some(map_payload_blake3);
                self.state = NetworkResolutionTransactionState::MapVerified;
            }
            NetworkResolutionTransactionEvent::SwitchAttempted { outcome } => {
                self.require_state(NetworkResolutionTransactionState::MapVerified)?;
                self.switch_outcome = Some(outcome);
                self.state = NetworkResolutionTransactionState::ReconciliationRequired;
            }
            NetworkResolutionTransactionEvent::Reconciled {
                active_generation,
                active_map_payload_blake3,
            } => {
                self.require_state(NetworkResolutionTransactionState::ReconciliationRequired)?;
                let outcome = self
                    .switch_outcome
                    .ok_or(NetworkResolutionTransactionError::MissingSwitchOutcome)?;

                if active_generation == self.target_active_generation {
                    if outcome == NetworkResolutionSwitchOutcome::NotCommitted
                        || active_map_payload_blake3.as_deref()
                            != Some(self.expected_map_payload_blake3.as_str())
                    {
                        return Err(NetworkResolutionTransactionError::ReadbackConflict);
                    }
                    self.reconciled_active_generation = Some(active_generation);
                    self.state = NetworkResolutionTransactionState::Active;
                } else if active_generation == self.prior_active_generation {
                    if outcome == NetworkResolutionSwitchOutcome::Committed
                        || active_map_payload_blake3.as_deref()
                            != Some(self.prior_active_map_payload_blake3.as_str())
                    {
                        return Err(NetworkResolutionTransactionError::ReadbackConflict);
                    }
                    self.reconciled_active_generation = Some(active_generation);
                    self.state = NetworkResolutionTransactionState::NotCommitted;
                } else {
                    return Err(NetworkResolutionTransactionError::UnexpectedGeneration);
                }
            }
        }
        Ok(())
    }

    fn require_state(
        &self,
        expected: NetworkResolutionTransactionState,
    ) -> Result<(), NetworkResolutionTransactionError> {
        if self.state != expected {
            return Err(NetworkResolutionTransactionError::InvalidTransition {
                from: self.state,
                expected,
            });
        }
        Ok(())
    }

    fn require_target_generation(
        &self,
        generation: u64,
    ) -> Result<(), NetworkResolutionTransactionError> {
        if generation != self.target_active_generation {
            return Err(NetworkResolutionTransactionError::GenerationMismatch);
        }
        Ok(())
    }

    fn require_expected_map_digest(
        &self,
        digest: &str,
    ) -> Result<(), NetworkResolutionTransactionError> {
        if !is_digest(digest) {
            return Err(NetworkResolutionTransactionError::InvalidDigest);
        }
        if digest != self.expected_map_payload_blake3 {
            return Err(NetworkResolutionTransactionError::MapDigestMismatch);
        }
        Ok(())
    }

    pub fn state(&self) -> NetworkResolutionTransactionState {
        self.state
    }

    pub fn logical_request_id(&self) -> &str {
        &self.logical_request_id
    }

    pub fn redirect_hop(&self) -> u8 {
        self.redirect_hop
    }

    pub fn lease_blake3(&self) -> &str {
        &self.lease_blake3
    }

    pub fn address_set_blake3(&self) -> &str {
        &self.address_set_blake3
    }

    pub fn parent_policy_blake3(&self) -> &str {
        &self.parent_policy_blake3
    }

    pub fn parent_capability_blake3(&self) -> &str {
        &self.parent_capability_blake3
    }

    pub fn parent_authority_lease_blake3(&self) -> &str {
        &self.parent_authority_lease_blake3
    }

    pub fn authority_evidence_blake3(&self) -> &str {
        &self.authority_evidence_blake3
    }

    pub fn resolver_key_id(&self) -> &str {
        &self.resolver_key_id
    }

    pub fn replay_key(&self) -> &str {
        &self.replay_key
    }

    pub fn expected_replay_record_blake3(&self) -> &str {
        &self.expected_replay_record_blake3
    }

    pub fn prior_active_generation(&self) -> u64 {
        self.prior_active_generation
    }

    pub fn prior_active_map_payload_blake3(&self) -> &str {
        &self.prior_active_map_payload_blake3
    }

    pub fn expected_map_payload_blake3(&self) -> &str {
        &self.expected_map_payload_blake3
    }

    pub fn target_active_generation(&self) -> u64 {
        self.target_active_generation
    }

    /// New request execution may proceed only after exact-generation read-back.
    pub fn may_execute(&self) -> bool {
        self.state == NetworkResolutionTransactionState::Active
            && self.reconciled_active_generation == Some(self.target_active_generation)
            && self.verified_map_payload_blake3.as_deref()
                == Some(self.expected_map_payload_blake3.as_str())
    }

    pub fn requires_reconciliation(&self) -> bool {
        self.state == NetworkResolutionTransactionState::ReconciliationRequired
    }

    pub fn digest_hex(&self) -> Result<String, NetworkResolutionTransactionError> {
        hash_serialized(self)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkResolutionTransactionError {
    #[error("resolution lease is structurally invalid")]
    InvalidLease,
    #[error("signature-verified lease failed exact parent binding: {0}")]
    ParentBinding(String),
    #[error("parent capability or resolution lease is expired")]
    ParentLeaseExpired,
    #[error("parent authority lease expires before the resolution lease")]
    ParentLeaseTimeMismatch,
    #[error("active policy generation differs from the parent-bound lease")]
    PolicyGenerationMismatch,
    #[error("transaction digest is invalid")]
    InvalidDigest,
    #[error("kernel map payload is structurally invalid")]
    InvalidMapPayload,
    #[error("kernel map payload does not exactly narrow the supplied resolution lease")]
    MapPayloadMismatch,
    #[error("kernel map generation overflow")]
    GenerationOverflow,
    #[error("event is invalid for transaction state {from:?}; expected {expected:?}")]
    InvalidTransition {
        from: NetworkResolutionTransactionState,
        expected: NetworkResolutionTransactionState,
    },
    #[error("event generation does not match the exact target generation")]
    GenerationMismatch,
    #[error("staged/read-back map payload digest does not match the authorized payload")]
    MapDigestMismatch,
    #[error("replay-ledger read-back does not match the pending consume-once record")]
    ReplayRecordConflict,
    #[error("switch outcome is missing during reconciliation")]
    MissingSwitchOutcome,
    #[error("kernel read-back contradicts the reported switch outcome or map digest")]
    ReadbackConflict,
    #[error("kernel read-back reported an unexpected active generation")]
    UnexpectedGeneration,
    #[error("transaction serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_resolution_lease::DnssecStatus;
    use crate::network_covenant::NetworkProtocol;
    use std::net::IpAddr;

    fn lease() -> NetworkResolutionLeaseV1 {
        NetworkResolutionLeaseV1 {
            schema_version: 1,
            lease_id: "01".repeat(16),
            logical_request_id: "02".repeat(16),
            redirect_hop: 0,
            holon_id: "test-holon".into(),
            workload_blake3: "11".repeat(32),
            network_policy_blake3: "22".repeat(32),
            parent_capability_blake3: "33".repeat(32),
            parent_authority_lease_blake3: "44".repeat(32),
            address_policy_blake3: "55".repeat(32),
            hostname: "api.example.org".into(),
            transport: NetworkProtocol::Tcp,
            port: 443,
            addresses: vec!["93.184.216.34".parse::<IpAddr>().unwrap()],
            resolver_profile_id: "test-resolver".into(),
            resolver_snapshot_blake3: "66".repeat(32),
            resolved_at_unix: 100,
            resolver_valid_until_unix: 110,
            issued_at_unix: 101,
            expires_at_unix: 105,
            policy_generation: 7,
            issuer_key_id: "resolver-key".into(),
            nonce: "77".repeat(32),
            dnssec_status: DnssecStatus::NotValidated,
        }
    }

    fn started() -> NetworkResolutionTransaction {
        let lease = lease();
        let bound = ParentBoundNetworkResolutionLease::test_only(lease, 109);
        let payload = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "88".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        NetworkResolutionTransaction::begin(&bound, payload, 102, 7, 40, "cc".repeat(32))
            .unwrap()
    }

    fn stage_and_verify(transaction: &mut NetworkResolutionTransaction) {
        let replay_record_blake3 = transaction.expected_replay_record_blake3().to_owned();
        transaction
            .apply(NetworkResolutionTransactionEvent::NonceConsumed {
                replay_record_blake3,
            })
            .unwrap();
        let map_digest = transaction.expected_map_payload_blake3().to_owned();
        transaction
            .apply(NetworkResolutionTransactionEvent::MapStaged {
                generation: 41,
                map_payload_blake3: map_digest.clone(),
            })
            .unwrap();
        transaction
            .apply(NetworkResolutionTransactionEvent::MapVerified {
                generation: 41,
                map_payload_blake3: map_digest,
            })
            .unwrap();
    }

    #[test]
    fn map_payload_rejects_substitution_of_workload_port_policy_or_address_set() {
        let lease = lease();
        let bound = ParentBoundNetworkResolutionLease::test_only(lease, 109);
        let mut payload = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "88".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        payload.port = 8443;
        assert_eq!(
            NetworkResolutionTransaction::begin(
                &bound,
                payload,
                102,
                7,
                40,
                "cc".repeat(32)
            ),
            Err(NetworkResolutionTransactionError::MapPayloadMismatch)
        );

        let mut wrong_cgroup = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "99".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        wrong_cgroup.cgroup_identity_blake3 = "not-a-digest".into();
        assert_eq!(
            wrong_cgroup.validate(),
            Err(NetworkResolutionTransactionError::InvalidMapPayload)
        );

        let canonical_payload = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "88".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        let changed_cgroup = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "77".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        let changed_program = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "88".repeat(32),
            "66".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        assert_ne!(
            canonical_payload.digest_hex().unwrap(),
            changed_cgroup.digest_hex().unwrap()
        );
        assert_ne!(
            canonical_payload.digest_hex().unwrap(),
            changed_program.digest_hex().unwrap()
        );

        let mut wrong_parent_capability = canonical_payload.clone();
        wrong_parent_capability.parent_capability_blake3 = "dd".repeat(32);
        let mut wrong_parent_lease = canonical_payload.clone();
        wrong_parent_lease.parent_authority_lease_blake3 = "ee".repeat(32);
        let mut wrong_scope = canonical_payload.clone();
        wrong_scope.address_policy_blake3 = "ff".repeat(32);
        let mut wrong_resolver_snapshot = canonical_payload.clone();
        wrong_resolver_snapshot.resolver_snapshot_blake3 = "ab".repeat(32);

        for substituted in [
            wrong_parent_capability,
            wrong_parent_lease,
            wrong_scope,
            wrong_resolver_snapshot,
        ] {
            assert_eq!(
                NetworkResolutionTransaction::begin(
                    &bound,
                    substituted,
                    102,
                    7,
                    40,
                    "cc".repeat(32)
                ),
                Err(NetworkResolutionTransactionError::MapPayloadMismatch)
            );
        }
    }

    #[test]
    fn transaction_refuses_expired_parent_lease_or_stale_policy_generation() {
        let lease = lease();
        let bound = ParentBoundNetworkResolutionLease::test_only(lease, 104);
        let payload = NetworkResolutionMapPayloadV1::for_lease(
            &bound,
            "88".repeat(32),
            "99".repeat(32),
            41,
            102,
            7,
        )
        .unwrap();
        assert!(matches!(
            NetworkResolutionTransaction::begin(
                &bound,
                payload.clone(),
                105,
                7,
                40,
                "cc".repeat(32)
            ),
            Err(NetworkResolutionTransactionError::ParentLeaseExpired)
        ));
        assert!(matches!(
            NetworkResolutionTransaction::begin(
                &bound,
                payload,
                102,
                8,
                40,
                "cc".repeat(32)
            ),
            Err(NetworkResolutionTransactionError::PolicyGenerationMismatch)
        ));
    }

    #[test]
    fn new_transaction_binds_lease_request_hop_and_exact_next_generation() {
        let tx = started();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Prepared);
        assert_eq!(tx.logical_request_id(), "02".repeat(16));
        assert_eq!(tx.redirect_hop(), 0);
        assert_eq!(tx.target_active_generation(), 41);
        assert_eq!(tx.prior_active_generation(), 40);
        assert!(!tx.may_execute());
    }

    #[test]
    fn nonce_consumption_unknown_requires_replay_ledger_reconciliation() {
        let mut tx = started();
        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumptionUnknown {
            replay_record_blake3,
        })
        .unwrap();
        assert_eq!(
            tx.state(),
            NetworkResolutionTransactionState::NonceReconciliationRequired
        );
        assert!(!tx.may_execute());

        tx.apply(NetworkResolutionTransactionEvent::ReplayLedgerReconciled {
            replay_record_blake3: None,
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Prepared);

        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
            replay_record_blake3,
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::NonceConsumed);
    }

    #[test]
    fn nonce_consumption_rejects_record_not_bound_to_this_lease() {
        let mut tx = started();
        assert_eq!(
            tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
                replay_record_blake3: "ff".repeat(32),
            }),
            Err(NetworkResolutionTransactionError::ReplayRecordConflict)
        );
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Conflict);
        assert!(!tx.may_execute());
    }

    #[test]
    fn nonce_ledger_mismatch_quarantines_transaction() {
        let mut tx = started();
        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumptionUnknown {
            replay_record_blake3,
        })
        .unwrap();
        assert_eq!(
            tx.apply(NetworkResolutionTransactionEvent::ReplayLedgerReconciled {
                replay_record_blake3: Some("dd".repeat(32)),
            }),
            Err(NetworkResolutionTransactionError::ReplayRecordConflict)
        );
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Conflict);
    }

    #[test]
    fn staged_map_unknown_requires_exact_readback_before_retry_or_switch() {
        let mut tx = started();
        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
            replay_record_blake3,
        })
        .unwrap();
        let map_digest = tx.expected_map_payload_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::MapStageOutcomeUnknown {
            generation: 41,
            map_payload_blake3: map_digest.clone(),
        })
        .unwrap();
        assert_eq!(
            tx.state(),
            NetworkResolutionTransactionState::MapStageReconciliationRequired
        );
        assert!(!tx.may_execute());

        tx.apply(NetworkResolutionTransactionEvent::StagedMapReconciled {
            generation: 41,
            map_payload_blake3: None,
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::NonceConsumed);

        tx.apply(NetworkResolutionTransactionEvent::MapStageOutcomeUnknown {
            generation: 41,
            map_payload_blake3: map_digest.clone(),
        })
        .unwrap();
        tx.apply(NetworkResolutionTransactionEvent::StagedMapReconciled {
            generation: 41,
            map_payload_blake3: Some(map_digest.clone()),
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::MapStaged);

        tx.apply(NetworkResolutionTransactionEvent::MapVerified {
            generation: 41,
            map_payload_blake3: map_digest,
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::MapVerified);
    }

    #[test]
    fn only_verified_readback_after_switch_can_enable_execution() {
        let mut tx = started();
        stage_and_verify(&mut tx);
        assert!(!tx.may_execute());

        tx.apply(NetworkResolutionTransactionEvent::SwitchAttempted {
            outcome: NetworkResolutionSwitchOutcome::Committed,
        })
        .unwrap();
        assert!(tx.requires_reconciliation());
        assert!(!tx.may_execute());

        let map_digest = tx.expected_map_payload_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::Reconciled {
            active_generation: 41,
            active_map_payload_blake3: Some(map_digest),
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Active);
        assert!(tx.may_execute());
    }

    #[test]
    fn unknown_switch_outcome_reconciles_to_active_only_with_exact_map_readback() {
        let mut tx = started();
        stage_and_verify(&mut tx);
        tx.apply(NetworkResolutionTransactionEvent::SwitchAttempted {
            outcome: NetworkResolutionSwitchOutcome::Unknown,
        })
        .unwrap();
        assert!(tx.requires_reconciliation());

        let map_digest = tx.expected_map_payload_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::Reconciled {
            active_generation: 41,
            active_map_payload_blake3: Some(map_digest),
        })
        .unwrap();
        assert!(tx.may_execute());
    }

    #[test]
    fn unknown_switch_outcome_with_prior_generation_is_not_committed() {
        let mut tx = started();
        stage_and_verify(&mut tx);
        tx.apply(NetworkResolutionTransactionEvent::SwitchAttempted {
            outcome: NetworkResolutionSwitchOutcome::Unknown,
        })
        .unwrap();
        tx.apply(NetworkResolutionTransactionEvent::Reconciled {
            active_generation: 40,
            active_map_payload_blake3: Some("cc".repeat(32)),
        })
        .unwrap();
        assert_eq!(tx.state(), NetworkResolutionTransactionState::NotCommitted);
        assert!(!tx.may_execute());
    }

    #[test]
    fn contradictory_or_unexpected_readback_quarantines_transaction() {
        let mut committed_but_old = started();
        stage_and_verify(&mut committed_but_old);
        committed_but_old
            .apply(NetworkResolutionTransactionEvent::SwitchAttempted {
                outcome: NetworkResolutionSwitchOutcome::Committed,
            })
            .unwrap();
        assert_eq!(
            committed_but_old.apply(NetworkResolutionTransactionEvent::Reconciled {
                active_generation: 40,
                active_map_payload_blake3: Some("cc".repeat(32)),
            }),
            Err(NetworkResolutionTransactionError::ReadbackConflict)
        );
        assert_eq!(
            committed_but_old.state(),
            NetworkResolutionTransactionState::Conflict
        );
        assert!(!committed_but_old.may_execute());

        let mut unexpected = started();
        stage_and_verify(&mut unexpected);
        unexpected
            .apply(NetworkResolutionTransactionEvent::SwitchAttempted {
                outcome: NetworkResolutionSwitchOutcome::Unknown,
            })
            .unwrap();
        let map_digest = unexpected.expected_map_payload_blake3().to_owned();
        assert_eq!(
            unexpected.apply(NetworkResolutionTransactionEvent::Reconciled {
                active_generation: 99,
                active_map_payload_blake3: Some(map_digest),
            }),
            Err(NetworkResolutionTransactionError::UnexpectedGeneration)
        );
        assert_eq!(unexpected.state(), NetworkResolutionTransactionState::Conflict);
    }

    #[test]
    fn map_digest_or_generation_mismatch_conflicts_before_execution() {
        let mut tx = started();
        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
            replay_record_blake3,
        })
        .unwrap();
        let map_digest = tx.expected_map_payload_blake3().to_owned();
        assert_eq!(
            tx.apply(NetworkResolutionTransactionEvent::MapStaged {
                generation: 42,
                map_payload_blake3: map_digest,
            }),
            Err(NetworkResolutionTransactionError::GenerationMismatch)
        );
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Conflict);
        assert!(!tx.may_execute());
    }

    #[test]
    fn out_of_order_events_conflict_and_cannot_be_repaired_in_place() {
        let mut tx = started();
        assert!(matches!(
            tx.apply(NetworkResolutionTransactionEvent::SwitchAttempted {
                outcome: NetworkResolutionSwitchOutcome::Committed,
            }),
            Err(NetworkResolutionTransactionError::InvalidTransition { .. })
        ));
        assert_eq!(tx.state(), NetworkResolutionTransactionState::Conflict);
        assert!(tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
            replay_record_blake3: tx.expected_replay_record_blake3().to_owned(),
        }).is_err());
        assert!(!tx.may_execute());
    }

    #[test]
    fn transaction_snapshot_digest_is_stable_and_changes_with_state() {
        let mut tx = started();
        let prepared = tx.digest_hex().unwrap();
        let replay_record_blake3 = tx.expected_replay_record_blake3().to_owned();
        tx.apply(NetworkResolutionTransactionEvent::NonceConsumed {
            replay_record_blake3,
        })
        .unwrap();
        assert_ne!(prepared, tx.digest_hex().unwrap());
    }
}
