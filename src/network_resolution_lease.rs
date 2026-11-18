// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure, versioned model for a request-scoped resolved-address lease.
//!
//! This module validates lease structure and binding to an existing parent
//! NetworkCapability/NetworkCapabilityLease. It does not resolve DNS, verify a
//! resolver signature, classify public-unicast addresses, consume replay
//! nonces, write BPF maps, or authorize production activation.

use crate::authority_signature::{AuthorityAction, AuthorityChallenge, VerifiedSignatureEvidence};
use crate::network_covenant::{
    AddressScopePolicy, DestinationSet, NetworkCapability, NetworkCapabilityLease,
    NetworkDirection, NetworkPolicyPlan, NetworkProtocol,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use thiserror::Error;

const LEASE_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-lease:v1\0";

pub const NETWORK_RESOLUTION_LEASE_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_RESOLUTION_LEASE_MAX_LIFETIME_SECS: u64 = 5;
pub const NETWORK_RESOLUTION_LEASE_MAX_ADDRESSES: usize = 32;
pub const NETWORK_RESOLUTION_LEASE_MAX_REDIRECT_HOPS: u8 = 5;
pub const NETWORK_RESOLUTION_LEASE_AUDIENCE: &str = "nixward-network-resolution-lease-v1";
const RESOLUTION_HOLON_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-holon:v1\0";
const RESOLUTION_REPLAY_DOMAIN: &[u8] = b"symthaea:nixward:network-resolution-replay:v1\0";

/// Stable challenge identity for a named Holon. This is distinct from the
/// lease subject digest, which binds the complete serialized lease.
pub fn network_resolution_authority_holon_blake3(holon_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESOLUTION_HOLON_DOMAIN);
    hasher.update(&(holon_id.len() as u64).to_le_bytes());
    hasher.update(holon_id.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Build the only supported signing challenge for a resolution lease. The
/// challenge nonce is derived from the lease's own 32-byte one-shot nonce, so
/// re-signing the same lease with a different timestamp cannot create a new
/// lease replay identity.
pub fn build_network_resolution_lease_challenge(
    lease: &NetworkResolutionLeaseV1,
    issued_at_ms: u64,
    ttl_ms: u64,
) -> Result<AuthorityChallenge, NetworkResolutionLeaseError> {
    lease.validate_structure()?;
    let nonce_entropy = decode_nonce_entropy(&lease.nonce)?;
    AuthorityChallenge::new(
        AuthorityAction::NetworkResolve,
        lease.digest_hex()?,
        network_resolution_authority_holon_blake3(&lease.holon_id),
        NETWORK_RESOLUTION_LEASE_AUDIENCE,
        nonce_entropy,
        issued_at_ms,
        ttl_ms,
    )
    .map_err(|_| NetworkResolutionLeaseError::InvalidAuthorityEvidence)
}

fn decode_nonce_entropy(value: &str) -> Result<[u8; 32], NetworkResolutionLeaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NetworkResolutionLeaseError::InvalidAuthorityEvidence);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(NetworkResolutionLeaseError::InvalidAuthorityEvidence)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(NetworkResolutionLeaseError::InvalidAuthorityEvidence)?;
        bytes[index] = ((high << 4) | low) as u8;
    }
    Ok(bytes)
}

fn resolution_lease_replay_key(
    lease: &NetworkResolutionLeaseV1,
) -> Result<String, NetworkResolutionLeaseError> {
    // The nonce is a globally unique, 256-bit, one-use token. Do not include
    // the subject digest: reusing the same nonce for a modified lease must
    // still collide with the original consumed nonce.
    let nonce_entropy = decode_nonce_entropy(&lease.nonce)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESOLUTION_REPLAY_DOMAIN);
    hasher.update(&nonce_entropy);
    Ok(hasher.finalize().to_hex().to_string())
}

/// A cryptographically verified resolution lease. This wrapper cannot be
/// deserialized or constructed from caller-supplied fields: it requires the
/// sealed output of AuthorityVerifier and binds that evidence to the exact
/// lease digest, resolver key, action, audience and Holon.
///
/// This is still not a kernel permission by itself. Before staging rules, the
/// privileged broker must verify parent/cgroup state and atomically consume
/// replay_key in persistent replay state.
#[must_use]
#[derive(Debug, Clone)]
pub struct AuthorizedNetworkResolutionLease {
    lease: NetworkResolutionLeaseV1,
    verified_evidence: VerifiedSignatureEvidence,
    /// Stable across re-signatures of the same lease; bound to its own random
    /// nonce and the exact lease digest.
    replay_key: String,
}

impl AuthorizedNetworkResolutionLease {
    pub fn authorize(
        lease: NetworkResolutionLeaseV1,
        evidence: &VerifiedSignatureEvidence,
    ) -> Result<Self, NetworkResolutionLeaseError> {
        lease.validate_structure()?;
        let subject = lease.digest_hex()?;
        if evidence.subject_blake3() != subject {
            return Err(NetworkResolutionLeaseError::AuthoritySubjectMismatch);
        }
        if evidence.signer_key_id() != lease.issuer_key_id {
            return Err(NetworkResolutionLeaseError::AuthoritySignerMismatch);
        }
        if evidence.claims().get("authority_action").map(String::as_str)
            != Some("network-resolve")
        {
            return Err(NetworkResolutionLeaseError::AuthorityActionMismatch);
        }
        if evidence.claims().get("authority_audience").map(String::as_str)
            != Some(NETWORK_RESOLUTION_LEASE_AUDIENCE)
        {
            return Err(NetworkResolutionLeaseError::AuthorityAudienceMismatch);
        }
        let expected_holon = network_resolution_authority_holon_blake3(&lease.holon_id);
        if evidence.claims().get("challenge_holon_blake3") != Some(&expected_holon) {
            return Err(NetworkResolutionLeaseError::AuthorityHolonMismatch);
        }
        let nonce_entropy = decode_nonce_entropy(&lease.nonce)?;
        let expected_challenge_nonce = AuthorityChallenge::nonce_blake3(
            AuthorityAction::NetworkResolve,
            &subject,
            &expected_holon,
            nonce_entropy,
        )
        .map_err(|_| NetworkResolutionLeaseError::InvalidAuthorityEvidence)?;
        if evidence.claims().get("challenge_nonce_blake3")
            != Some(&expected_challenge_nonce)
            || evidence.claims().get("replay_key").map(String::as_str)
                != Some(evidence.replay_key())
            || !is_digest(evidence.evidence_blake3())
            || !is_digest(evidence.challenge_blake3())
            || !is_digest(evidence.replay_key())
        {
            return Err(NetworkResolutionLeaseError::InvalidAuthorityEvidence);
        }

        let replay_key = resolution_lease_replay_key(&lease)?;
        Ok(Self {
            lease,
            verified_evidence: evidence.clone(),
            replay_key,
        })
    }

    pub fn lease(&self) -> &NetworkResolutionLeaseV1 {
        &self.lease
    }

    pub fn evidence_blake3(&self) -> &str {
        self.verified_evidence.evidence_blake3()
    }

    pub fn signer_key_id(&self) -> &str {
        self.verified_evidence.signer_key_id()
    }

    /// Read-only sealed evidence for the privileged broker's typed
    /// AuthorityReplayLedger::consume_verified call immediately before map
    /// staging. The caller cannot replace or mutate its signed fields.
    pub fn verified_evidence(&self) -> &VerifiedSignatureEvidence {
        &self.verified_evidence
    }

    /// One-shot lease replay key, distinct from the challenge replay key.
    /// Re-signing the identical lease cannot create a second usable lease.
    pub fn replay_key(&self) -> &str {
        &self.replay_key
    }

    pub fn challenge_blake3(&self) -> &str {
        self.verified_evidence.challenge_blake3()
    }

    pub fn validate_parent_binding(
        &self,
        policy: &NetworkPolicyPlan,
        capability: &NetworkCapability,
        parent_lease: &NetworkCapabilityLease,
        now_unix: u64,
        active_policy_generation: u64,
    ) -> Result<(), NetworkResolutionLeaseError> {
        self.lease.validate_parent_binding(
            policy,
            capability,
            parent_lease,
            now_unix,
            active_policy_generation,
        )
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnssecStatus {
    Validated,
    NotValidated,
    Unsupported,
    Indeterminate,
}

/// Request/hop-scoped IP address lease produced by a trusted Nixward resolver
/// authority. A valid structure is not authority by itself: callers must also
/// verify the parent policy, delegated address-scope authorization, resolver
/// provenance, caller/cgroup identity and nonce consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResolutionLeaseV1 {
    pub schema_version: u32,
    /// Random opaque identifier, 16 bytes encoded as 32 lowercase hex digits.
    pub lease_id: String,
    /// Opaque logical HTTP operation identifier; it must not contain a URL.
    pub logical_request_id: String,
    /// Redirect index. Each redirect must receive a fresh lease.
    pub redirect_hop: u8,
    pub holon_id: String,
    pub workload_blake3: String,
    pub network_policy_blake3: String,
    pub parent_capability_blake3: String,
    pub parent_authority_lease_blake3: String,
    /// Digest of a separately owner-authorized address-scope policy.
    ///
    /// This digest is only shape-checked here. It must be resolved to and
    /// verified against the exact policy object before a kernel rule is made.
    pub address_policy_blake3: String,
    /// Canonical lowercase ASCII A-label DNS name; no wildcard or trailing dot.
    pub hostname: String,
    /// v1 deliberately supports TCP only. UDP/QUIC needs a separate profile.
    pub transport: NetworkProtocol,
    pub port: u16,
    /// Sorted, unique complete A/AAAA address set. Address class/scope must be
    /// checked against the separately authorized address policy.
    pub addresses: Vec<IpAddr>,
    pub resolver_profile_id: String,
    pub resolver_snapshot_blake3: String,
    pub resolved_at_unix: u64,
    pub resolver_valid_until_unix: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub policy_generation: u64,
    pub issuer_key_id: String,
    /// Random 32-byte consume-once nonce, lowercase hex.
    pub nonce: String,
    pub dnssec_status: DnssecStatus,
}

impl NetworkResolutionLeaseV1 {
    /// Validate canonical encoding, bounded complete-set shape and expiry.
    ///
    /// This does not classify IP ranges as public/private and does not prove
    /// resolver authenticity. Those checks require the separately authorized
    /// address policy and trusted resolver evidence.
    pub fn validate_structure(&self) -> Result<(), NetworkResolutionLeaseError> {
        if self.schema_version != NETWORK_RESOLUTION_LEASE_SCHEMA_VERSION {
            return Err(NetworkResolutionLeaseError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_hex(&self.lease_id, 32, "lease id")?;
        validate_hex(&self.logical_request_id, 32, "logical request id")?;
        validate_hex(&self.workload_blake3, 64, "workload digest")?;
        validate_hex(&self.network_policy_blake3, 64, "network policy digest")?;
        validate_hex(
            &self.parent_capability_blake3,
            64,
            "parent capability digest",
        )?;
        validate_hex(
            &self.parent_authority_lease_blake3,
            64,
            "parent authority lease digest",
        )?;
        validate_hex(
            &self.address_policy_blake3,
            64,
            "address policy digest",
        )?;
        validate_hex(
            &self.resolver_snapshot_blake3,
            64,
            "resolver snapshot digest",
        )?;
        validate_hex(&self.nonce, 64, "lease nonce")?;
        validate_token("Holon id", &self.holon_id, 256)?;
        validate_token("resolver profile id", &self.resolver_profile_id, 256)?;
        validate_token("issuer key id", &self.issuer_key_id, 256)?;
        validate_hostname(&self.hostname)?;

        if self.transport != NetworkProtocol::Tcp {
            return Err(NetworkResolutionLeaseError::UnsupportedTransport);
        }
        if self.port == 0 {
            return Err(NetworkResolutionLeaseError::InvalidPort);
        }
        if self.redirect_hop > NETWORK_RESOLUTION_LEASE_MAX_REDIRECT_HOPS {
            return Err(NetworkResolutionLeaseError::RedirectLimitExceeded);
        }
        if self.policy_generation == 0 {
            return Err(NetworkResolutionLeaseError::InvalidPolicyGeneration);
        }
        if self.addresses.is_empty()
            || self.addresses.len() > NETWORK_RESOLUTION_LEASE_MAX_ADDRESSES
        {
            return Err(NetworkResolutionLeaseError::InvalidAddressSet);
        }

        let mut seen = BTreeSet::new();
        let mut previous = None;
        for address in &self.addresses {
            if address.is_unspecified() || address.is_multicast() || !seen.insert(*address) {
                return Err(NetworkResolutionLeaseError::InvalidAddressSet);
            }
            if previous.is_some_and(|last| last >= *address) {
                return Err(NetworkResolutionLeaseError::NonCanonicalAddressOrder);
            }
            previous = Some(*address);
        }

        if self.resolver_valid_until_unix <= self.resolved_at_unix
            || self.issued_at_unix < self.resolved_at_unix
            || self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix > self.resolver_valid_until_unix
            || self
                .expires_at_unix
                .saturating_sub(self.issued_at_unix)
                > NETWORK_RESOLUTION_LEASE_MAX_LIFETIME_SECS
        {
            return Err(NetworkResolutionLeaseError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkResolutionLeaseError> {
        self.validate_structure()?;
        hash_json(LEASE_DOMAIN, self)
    }

    /// Verify the lease narrows one exact parent policy/capability/lease.
    ///
    /// The caller must still verify the delegated address-scope policy,
    /// resolver evidence, local broker peer identity, cgroup binding and
    /// persistent consume-once nonce before staging kernel rules.
    pub fn validate_parent_binding(
        &self,
        policy: &NetworkPolicyPlan,
        capability: &NetworkCapability,
        parent_lease: &NetworkCapabilityLease,
        now_unix: u64,
        active_policy_generation: u64,
    ) -> Result<(), NetworkResolutionLeaseError> {
        self.validate_structure()?;
        policy
            .validate()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;
        capability
            .validate()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;
        parent_lease
            .validate()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;

        let policy_digest = policy
            .digest_hex()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;
        let capability_digest = capability
            .digest_hex()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;
        let authority_lease_digest = parent_lease
            .digest_hex()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;

        if policy.holon_id != self.holon_id
            || parent_lease.holon_id != self.holon_id
            || policy_digest != self.network_policy_blake3
            || capability_digest != self.parent_capability_blake3
            || authority_lease_digest != self.parent_authority_lease_blake3
            || capability.workload_blake3 != self.workload_blake3
            || parent_lease.policy_blake3 != self.network_policy_blake3
            || parent_lease.capability_blake3 != self.parent_capability_blake3
        {
            return Err(NetworkResolutionLeaseError::ParentBindingMismatch);
        }

        let capability_is_in_policy = policy.capabilities.iter().any(|candidate| {
            candidate
                .digest_hex()
                .is_ok_and(|digest| digest == self.parent_capability_blake3)
        });
        if !capability_is_in_policy {
            return Err(NetworkResolutionLeaseError::ParentBindingMismatch);
        }

        if capability.direction != NetworkDirection::Egress
            || !matches!(capability.protocol, NetworkProtocol::Tcp | NetworkProtocol::Any)
            || !capability.ports.iter().any(|range| {
                range.from <= self.port && self.port <= range.to
            })
        {
            return Err(NetworkResolutionLeaseError::ParentScopeMismatch);
        }

        match &capability.destinations {
            DestinationSet::Hostnames { values }
                if values
                    .iter()
                    .any(|hostname| hostname.eq_ignore_ascii_case(&self.hostname)) => {}
            _ => return Err(NetworkResolutionLeaseError::ParentScopeMismatch),
        }

        let address_scope = capability
            .address_scope
            .as_ref()
            .ok_or(NetworkResolutionLeaseError::ParentAddressScopeMismatch)?;
        let address_scope_digest = address_scope
            .digest_hex()
            .map_err(|error| NetworkResolutionLeaseError::ParentPolicy(error.to_string()))?;
        if address_scope_digest != self.address_policy_blake3
            || !address_scope.permits_all(&self.addresses)
        {
            return Err(NetworkResolutionLeaseError::ParentAddressScopeMismatch);
        }

        if parent_lease.issued_at_unix > self.resolved_at_unix
            || parent_lease.expires_at_unix < self.expires_at_unix
        {
            return Err(NetworkResolutionLeaseError::ParentLeaseTimeMismatch);
        }
        if self.policy_generation != active_policy_generation {
            return Err(NetworkResolutionLeaseError::PolicyGenerationMismatch);
        }
        if now_unix < self.issued_at_unix || now_unix >= self.expires_at_unix {
            return Err(NetworkResolutionLeaseError::Expired);
        }
        if now_unix < parent_lease.issued_at_unix || now_unix >= parent_lease.expires_at_unix {
            return Err(NetworkResolutionLeaseError::ParentLeaseExpired);
        }
        Ok(())
    }
}

fn validate_hostname(value: &str) -> Result<(), NetworkResolutionLeaseError> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value != value.to_ascii_lowercase()
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(NetworkResolutionLeaseError::InvalidHostname);
    }
    Ok(())
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), NetworkResolutionLeaseError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(NetworkResolutionLeaseError::InvalidToken(field))
    } else {
        Ok(())
    }
}

fn validate_hex(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<(), NetworkResolutionLeaseError> {
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(NetworkResolutionLeaseError::InvalidHex(field))
    } else {
        Ok(())
    }
}

fn hash_json<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, NetworkResolutionLeaseError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| NetworkResolutionLeaseError::Serialization)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkResolutionLeaseError {
    #[error("unsupported network resolution lease schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid {0} hexadecimal field")]
    InvalidHex(&'static str),
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),
    #[error("hostname must be a canonical lowercase ASCII A-label")]
    InvalidHostname,
    #[error("v1 resolution leases support TCP only")]
    UnsupportedTransport,
    #[error("destination port must be non-zero")]
    InvalidPort,
    #[error("redirect hop exceeds the policy maximum")]
    RedirectLimitExceeded,
    #[error("policy generation must be non-zero")]
    InvalidPolicyGeneration,
    #[error("resolved address set is empty, oversized, duplicated, or contains unspecified/multicast addresses")]
    InvalidAddressSet,
    #[error("resolved addresses must be sorted and unique before digesting")]
    NonCanonicalAddressOrder,
    #[error("resolver validity, issue time, expiry or maximum lease lifetime is invalid")]
    InvalidTimeWindow,
    #[error("parent policy or capability is invalid: {0}")]
    ParentPolicy(String),
    #[error("lease does not match the exact parent policy, capability, workload or authority lease")]
    ParentBindingMismatch,
    #[error("parent capability does not grant this egress hostname, protocol and port")]
    ParentScopeMismatch,
    #[error("resolved address set or address-policy digest is outside the owner-authorized parent scope")]
    ParentAddressScopeMismatch,
    #[error("parent authority lease does not cover the resolution snapshot lifetime")]
    ParentLeaseTimeMismatch,
    #[error("parent authority lease is expired or not yet valid")]
    ParentLeaseExpired,
    #[error("resolution lease policy generation is not the active generation")]
    PolicyGenerationMismatch,
    #[error("resolution lease is expired or not yet valid")]
    Expired,
    #[error("detached authority subject does not bind the exact resolution lease")]
    AuthoritySubjectMismatch,
    #[error("detached authority signer does not match the lease issuer")]
    AuthoritySignerMismatch,
    #[error("detached authority action is not network-resolve")]
    AuthorityActionMismatch,
    #[error("detached authority audience is not the resolution-lease audience")]
    AuthorityAudienceMismatch,
    #[error("detached authority is not bound to this Holon")]
    AuthorityHolonMismatch,
    #[error("verified authority evidence is incomplete or internally inconsistent")]
    InvalidAuthorityEvidence,
    #[error("network resolution lease serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_covenant::{
        AddressScopePolicy, NetworkCapability, NetworkCapabilityLease, NetworkDirection,
        NetworkPolicyPlan, NetworkProtocol, PortRange, WorkloadIdentity, WorkloadSource,
    };
    use std::collections::BTreeMap;

    fn parent() -> (NetworkPolicyPlan, NetworkCapability, NetworkCapabilityLease) {
        parent_with_scope(AddressScopePolicy::PublicUnicastOnly)
    }

    fn parent_with_scope(
        address_scope: AddressScopePolicy,
    ) -> (NetworkPolicyPlan, NetworkCapability, NetworkCapabilityLease) {
        let workload = WorkloadIdentity::new(
            "holon-prism",
            "prism-proxy",
            WorkloadSource::NixSystemdUnit {
                unit: "prism-proxy.service".into(),
                closure_store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-prism-proxy"
                    .into(),
                config_blake3: "11".repeat(32),
            },
        )
        .unwrap();
        let capability = NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "prism-public-api".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Hostnames {
                values: vec!["api.example.org".into()],
            },
            address_scope: Some(address_scope),
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "owner-approved Prism public HTTPS egress".into(),
        };
        let policy = NetworkPolicyPlan::new(
            "holon-prism",
            vec![workload],
            vec![capability.clone()],
        )
        .unwrap();
        let parent_lease = NetworkCapabilityLease {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            holon_id: "holon-prism".into(),
            policy_blake3: policy.digest_hex().unwrap(),
            capability_blake3: capability.digest_hex().unwrap(),
            issuer_key_id: "owner-network-root".into(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            nonce: "22".repeat(32),
        };
        (policy, capability, parent_lease)
    }

    fn lease(
        capability: &NetworkCapability,
        parent_lease: &NetworkCapabilityLease,
    ) -> NetworkResolutionLeaseV1 {
        NetworkResolutionLeaseV1 {
            schema_version: 1,
            lease_id: "00112233445566778899aabbccddeeff".into(),
            logical_request_id: "102132435465768798a9bacbdcedfe0f".into(),
            redirect_hop: 0,
            holon_id: "holon-prism".into(),
            workload_blake3: capability.workload_blake3.clone(),
            network_policy_blake3: parent_lease.policy_blake3.clone(),
            parent_capability_blake3: parent_lease.capability_blake3.clone(),
            parent_authority_lease_blake3: parent_lease.digest_hex().unwrap(),
            address_policy_blake3: capability.address_scope.as_ref().unwrap().digest_hex().unwrap(),
            hostname: "api.example.org".into(),
            transport: NetworkProtocol::Tcp,
            port: 443,
            addresses: vec![
                "93.184.216.34".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ],
            resolver_profile_id: "test-resolver-v1".into(),
            resolver_snapshot_blake3: "44".repeat(32),
            resolved_at_unix: 110,
            resolver_valid_until_unix: 140,
            issued_at_unix: 111,
            expires_at_unix: 115,
            policy_generation: 7,
            issuer_key_id: "nixward-resolver-broker".into(),
            nonce: "55".repeat(32),
            dnssec_status: DnssecStatus::NotValidated,
        }
    }

    fn signed_evidence(
        lease: &NetworkResolutionLeaseV1,
        action: crate::authority_signature::AuthorityAction,
        audience: &str,
        key_id: &str,
        challenge_holon: Option<&str>,
    ) -> VerifiedSignatureEvidence {
        signed_evidence_at(
            lease,
            action,
            audience,
            key_id,
            challenge_holon,
            1_000_000,
        )
    }

    fn signed_evidence_at(
        lease: &NetworkResolutionLeaseV1,
        action: crate::authority_signature::AuthorityAction,
        audience: &str,
        key_id: &str,
        challenge_holon: Option<&str>,
        issued_at_ms: u64,
    ) -> VerifiedSignatureEvidence {
        use crate::authority_signature::{
            AuthorityChallenge, AuthorityTrustPolicy, AuthorityVerifier,
            DetachedAuthoritySignature, TrustedAuthorityKey, AUTHORITY_POLICY_KIND,
            AUTHORITY_SCHEMA_VERSION, AUTHORITY_SIGNATURE_KIND,
        };
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[23u8; 32]);
        let subject = lease.digest_hex().unwrap();
        let expected_holon = challenge_holon
            .map(str::to_owned)
            .unwrap_or_else(|| network_resolution_authority_holon_blake3(&lease.holon_id));
        // The lease's own nonce, not fresh unrelated entropy, is bound into
        // every signature challenge for this exact lease.
        let nonce_entropy = decode_nonce_entropy(&lease.nonce).unwrap();
        let challenge = AuthorityChallenge::new(
            action,
            subject.clone(),
            expected_holon.clone(),
            audience,
            nonce_entropy,
            issued_at_ms,
            30_000,
        )
        .unwrap();
        let signature = signing.sign(&challenge.signing_bytes().unwrap());
        let public_key_hex = signing
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let signed = DetachedAuthoritySignature {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            key_id: key_id.into(),
            public_key_hex: public_key_hex.clone(),
            signature_hex: signature
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            challenge,
        };
        let policy = AuthorityTrustPolicy {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_POLICY_KIND.into(),
            policy_id: "resolution-lease-test-policy".into(),
            keys: vec![TrustedAuthorityKey {
                key_id: key_id.into(),
                issuer: "nixward-test-resolver".into(),
                public_key_hex,
                allowed_actions: vec![
                    crate::authority_signature::AuthorityAction::NetworkResolve,
                    crate::authority_signature::AuthorityAction::NetworkActivate,
                ],
                revoked: false,
                claims: BTreeMap::from([("holon_id".into(), expected_holon.clone())]),
            }],
            max_ttl_ms: 60_000,
            // The lease wrapper independently enforces its exact audience.
            allowed_audiences: Vec::new(),
        };
        AuthorityVerifier::new(&policy)
            .unwrap()
            .verify(
                &signed,
                action,
                &subject,
                &expected_holon,
                issued_at_ms + 1_000,
            )
            .unwrap()
    }

    #[test]
    fn signed_resolution_lease_is_bound_to_exact_lease_signer_action_audience_and_holon() {
        use crate::authority_signature::AuthorityAction;

        let (_, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        let evidence = signed_evidence(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
        );
        let authorized =
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &evidence).unwrap();
        assert_eq!(authorized.lease(), &lease);
        assert_eq!(authorized.signer_key_id(), lease.issuer_key_id);
        assert_eq!(authorized.replay_key().len(), 64);
        assert_eq!(authorized.evidence_blake3().len(), 64);

        let wrong_action = signed_evidence(
            &lease,
            AuthorityAction::NetworkActivate,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
        );
        assert_eq!(
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &wrong_action).unwrap_err(),
            NetworkResolutionLeaseError::AuthorityActionMismatch
        );

        let wrong_audience = signed_evidence(
            &lease,
            AuthorityAction::NetworkResolve,
            "nixward-other-audience",
            &lease.issuer_key_id,
            None,
        );
        assert_eq!(
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &wrong_audience).unwrap_err(),
            NetworkResolutionLeaseError::AuthorityAudienceMismatch
        );

        let wrong_signer = signed_evidence(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            "untrusted-other-resolver-key",
            None,
        );
        assert_eq!(
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &wrong_signer).unwrap_err(),
            NetworkResolutionLeaseError::AuthoritySignerMismatch
        );

        let wrong_holon = signed_evidence(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            Some(&"99".repeat(32)),
        );
        assert_eq!(
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &wrong_holon).unwrap_err(),
            NetworkResolutionLeaseError::AuthorityHolonMismatch
        );

        let mut altered = lease;
        altered.port = 8443;
        assert_eq!(
            AuthorizedNetworkResolutionLease::authorize(altered, &evidence).unwrap_err(),
            NetworkResolutionLeaseError::AuthoritySubjectMismatch
        );
    }

    #[test]
    fn resolution_lease_nonce_is_one_shot_even_when_the_same_lease_is_resigned() {
        use crate::action::authority_replay::{AuthorityReplayError, AuthorityReplayLedger};
        use crate::authority_signature::AuthorityAction;

        let (_, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        let challenge = build_network_resolution_lease_challenge(&lease, 1_000_000, 30_000)
            .unwrap();
        assert_eq!(challenge.action, AuthorityAction::NetworkResolve);
        assert_eq!(challenge.subject_blake3, lease.digest_hex().unwrap());
        assert_eq!(
            challenge.holon_id,
            network_resolution_authority_holon_blake3(&lease.holon_id)
        );
        assert_eq!(challenge.audience, NETWORK_RESOLUTION_LEASE_AUDIENCE);

        let first_evidence = signed_evidence_at(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
            1_000_000,
        );
        let second_evidence = signed_evidence_at(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
            1_001_000,
        );
        assert_ne!(
            first_evidence.challenge_blake3(),
            second_evidence.challenge_blake3(),
            "the detached challenges should be distinct because their time windows differ"
        );

        let first =
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &first_evidence).unwrap();
        let second =
            AuthorizedNetworkResolutionLease::authorize(lease.clone(), &second_evidence).unwrap();

        // Even a second, validly signed lease object cannot reuse the same
        // nonce to alter any other field and acquire a distinct replay slot.
        let mut same_nonce_different_subject = lease.clone();
        same_nonce_different_subject.resolver_snapshot_blake3 = "66".repeat(32);
        let third_evidence = signed_evidence_at(
            &same_nonce_different_subject,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
            1_002_000,
        );
        let third = AuthorizedNetworkResolutionLease::authorize(
            same_nonce_different_subject,
            &third_evidence,
        )
        .unwrap();

        assert_eq!(
            first.replay_key(),
            second.replay_key(),
            "the lease nonce defines the one-shot identity across re-signatures"
        );
        assert_eq!(
            first.replay_key(),
            third.replay_key(),
            "reusing one nonce with a different subject must not create a second replay slot"
        );

        let temp = tempfile::tempdir().unwrap();
        let ledger = AuthorityReplayLedger::new(temp.path().join("nixward/resolution-replay.sqlite3"));
        ledger
            .consume_authorized_resolution_lease(&first, 1_002_000)
            .unwrap();
        assert!(matches!(
            ledger.consume_authorized_resolution_lease(&second, 1_003_000),
            Err(AuthorityReplayError::AlreadyConsumed)
        ));
        assert!(matches!(
            ledger.consume_authorized_resolution_lease(&third, 1_003_500),
            Err(AuthorityReplayError::AlreadyConsumed)
        ));
        let reopened = AuthorityReplayLedger::new(ledger.path().to_path_buf());
        assert!(matches!(
            reopened.consume_authorized_resolution_lease(&third, 1_004_000),
            Err(AuthorityReplayError::AlreadyConsumed)
        ));
    }

    #[test]
    fn authorized_resolution_lease_keeps_parent_scope_validation_fail_closed() {
        use crate::authority_signature::AuthorityAction;

        let (policy, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        let evidence = signed_evidence(
            &lease,
            AuthorityAction::NetworkResolve,
            NETWORK_RESOLUTION_LEASE_AUDIENCE,
            &lease.issuer_key_id,
            None,
        );
        let authorized = AuthorizedNetworkResolutionLease::authorize(lease, &evidence).unwrap();
        assert!(authorized
            .validate_parent_binding(&policy, &capability, &parent_lease, 112, 7)
            .is_ok());
        assert_eq!(
            authorized.validate_parent_binding(&policy, &capability, &parent_lease, 115, 7),
            Err(NetworkResolutionLeaseError::Expired)
        );
    }

    #[test]
    fn valid_lease_is_structurally_canonical() {
        let (_, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        assert!(lease.validate_structure().is_ok());
        assert_eq!(lease.digest_hex().unwrap().len(), 64);
    }

    #[test]
    fn lease_binds_exact_parent_policy_capability_and_authority_lease() {
        let (policy, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        assert!(
            lease
                .validate_parent_binding(&policy, &capability, &parent_lease, 112, 7)
                .is_ok()
        );
    }

    #[test]
    fn lease_rejects_hostname_port_workload_and_generation_widening() {
        let (policy, capability, parent_lease) = parent();

        let mut wrong_host = lease(&capability, &parent_lease);
        wrong_host.hostname = "attacker.example.org".into();
        assert_eq!(
            wrong_host.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentScopeMismatch)
        );

        let mut wrong_port = lease(&capability, &parent_lease);
        wrong_port.port = 8443;
        assert_eq!(
            wrong_port.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentScopeMismatch)
        );

        let mut wrong_workload = lease(&capability, &parent_lease);
        wrong_workload.workload_blake3 = "66".repeat(32);
        assert_eq!(
            wrong_workload.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentBindingMismatch)
        );
    }

    #[test]
    fn lease_rejects_private_answers_under_public_unicast_parent_scope() {
        let (policy, capability, parent_lease) = parent();
        let mut private_answer = lease(&capability, &parent_lease);
        private_answer.addresses = vec!["10.0.0.8".parse().unwrap()];
        assert_eq!(
            private_answer.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentAddressScopeMismatch)
        );

        let mut substituted_policy = lease(&capability, &parent_lease);
        substituted_policy.address_policy_blake3 = "66".repeat(32);
        assert_eq!(
            substituted_policy.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentAddressScopeMismatch)
        );
    }

    #[test]
    fn explicit_cidr_parent_scope_allows_only_its_approved_lan_addresses() {
        let scope = AddressScopePolicy::ExplicitCidrs {
            values: vec!["192.168.0.0/16".into()],
        };
        let (policy, capability, parent_lease) = parent_with_scope(scope);
        let mut authorized = lease(&capability, &parent_lease);
        authorized.addresses = vec!["192.168.1.10".parse().unwrap()];
        assert!(authorized
            .validate_parent_binding(&policy, &capability, &parent_lease, 112, 7)
            .is_ok());

        authorized.addresses = vec!["10.0.0.1".parse().unwrap()];
        assert_eq!(
            authorized.validate_parent_binding(&policy, &capability, &parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentAddressScopeMismatch)
        );
    }

    #[test]
    fn lease_rejects_expiry_beyond_dns_validity_or_parent_lease() {
        let (policy, capability, parent_lease) = parent();

        let mut beyond_dns = lease(&capability, &parent_lease);
        beyond_dns.expires_at_unix = 141;
        assert_eq!(
            beyond_dns.validate_structure(),
            Err(NetworkResolutionLeaseError::InvalidTimeWindow)
        );

        let mut short_parent_lease = parent_lease.clone();
        short_parent_lease.expires_at_unix = 114;
        let beyond_parent = lease(&capability, &short_parent_lease);
        assert_eq!(
            beyond_parent.validate_parent_binding(&policy, &capability, &short_parent_lease, 112, 7),
            Err(NetworkResolutionLeaseError::ParentLeaseTimeMismatch)
        );
    }

    #[test]
    fn lease_rejects_unsorted_duplicate_or_empty_address_sets() {
        let (_, capability, parent_lease) = parent();

        let mut empty = lease(&capability, &parent_lease);
        empty.addresses.clear();
        assert_eq!(
            empty.validate_structure(),
            Err(NetworkResolutionLeaseError::InvalidAddressSet)
        );

        let mut duplicate = lease(&capability, &parent_lease);
        duplicate.addresses = vec![
            "93.184.216.34".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
        ];
        assert_eq!(
            duplicate.validate_structure(),
            Err(NetworkResolutionLeaseError::InvalidAddressSet)
        );

        let mut unsorted = lease(&capability, &parent_lease);
        unsorted.addresses.reverse();
        assert_eq!(
            unsorted.validate_structure(),
            Err(NetworkResolutionLeaseError::NonCanonicalAddressOrder)
        );
    }

    #[test]
    fn lease_rejects_noncanonical_hostnames_and_non_tcp_transports() {
        let (_, capability, parent_lease) = parent();

        let mut uppercase = lease(&capability, &parent_lease);
        uppercase.hostname = "API.example.org".into();
        assert_eq!(
            uppercase.validate_structure(),
            Err(NetworkResolutionLeaseError::InvalidHostname)
        );

        let mut wildcard = lease(&capability, &parent_lease);
        wildcard.hostname = "*.example.org".into();
        assert_eq!(
            wildcard.validate_structure(),
            Err(NetworkResolutionLeaseError::InvalidHostname)
        );

        let mut udp = lease(&capability, &parent_lease);
        udp.transport = NetworkProtocol::Udp;
        assert_eq!(
            udp.validate_structure(),
            Err(NetworkResolutionLeaseError::UnsupportedTransport)
        );
    }

    #[test]
    fn lease_rejects_stale_policy_generation() {
        let (policy, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        assert_eq!(
            lease.validate_parent_binding(&policy, &capability, &parent_lease, 112, 6),
            Err(NetworkResolutionLeaseError::PolicyGenerationMismatch)
        );
    }

    #[test]
    fn lease_fails_closed_at_and_after_expiry() {
        let (policy, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        assert_eq!(
            lease.validate_parent_binding(&policy, &capability, &parent_lease, 115, 7),
            Err(NetworkResolutionLeaseError::Expired)
        );
        assert_eq!(
            lease.validate_parent_binding(&policy, &capability, &parent_lease, 116, 7),
            Err(NetworkResolutionLeaseError::Expired)
        );
    }
}
