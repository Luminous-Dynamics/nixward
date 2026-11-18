// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure, versioned model for a request-scoped resolved-address lease.
//!
//! This module validates lease structure and binding to an existing parent
//! NetworkCapability/NetworkCapabilityLease. It does not resolve DNS, verify a
//! resolver signature, classify public-unicast addresses, consume replay
//! nonces, write BPF maps, or authorize production activation.

use crate::network_covenant::{
    DestinationSet, NetworkCapability, NetworkCapabilityLease, NetworkDirection, NetworkPolicyPlan,
    NetworkProtocol,
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

        if parent_lease.issued_at_unix > self.resolved_at_unix
            || parent_lease.expires_at_unix < self.expires_at_unix
        {
            return Err(NetworkResolutionLeaseError::ParentLeaseTimeMismatch);
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
    #[error("parent authority lease does not cover the resolution snapshot lifetime")]
    ParentLeaseTimeMismatch,
    #[error("parent authority lease is expired or not yet valid")]
    ParentLeaseExpired,
    #[error("resolution lease is expired or not yet valid")]
    Expired,
    #[error("network resolution lease serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_covenant::{
        NetworkCapability, NetworkCapabilityLease, NetworkDirection, NetworkPolicyPlan,
        NetworkProtocol, PortRange, WorkloadIdentity, WorkloadSource,
    };

    fn parent() -> (NetworkPolicyPlan, NetworkCapability, NetworkCapabilityLease) {
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
            schema_version: 1,
            capability_id: "prism-public-api".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Hostnames {
                values: vec!["api.example.org".into()],
            },
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
            schema_version: 1,
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
            address_policy_blake3: "33".repeat(32),
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
                .validate_parent_binding(&policy, &capability, &parent_lease, 112)
                .is_ok()
        );
    }

    #[test]
    fn lease_rejects_hostname_port_workload_and_generation_widening() {
        let (policy, capability, parent_lease) = parent();

        let mut wrong_host = lease(&capability, &parent_lease);
        wrong_host.hostname = "attacker.example.org".into();
        assert_eq!(
            wrong_host.validate_parent_binding(&policy, &capability, &parent_lease, 112),
            Err(NetworkResolutionLeaseError::ParentScopeMismatch)
        );

        let mut wrong_port = lease(&capability, &parent_lease);
        wrong_port.port = 8443;
        assert_eq!(
            wrong_port.validate_parent_binding(&policy, &capability, &parent_lease, 112),
            Err(NetworkResolutionLeaseError::ParentScopeMismatch)
        );

        let mut wrong_workload = lease(&capability, &parent_lease);
        wrong_workload.workload_blake3 = "66".repeat(32);
        assert_eq!(
            wrong_workload.validate_parent_binding(&policy, &capability, &parent_lease, 112),
            Err(NetworkResolutionLeaseError::ParentBindingMismatch)
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
            beyond_parent.validate_parent_binding(&policy, &capability, &short_parent_lease, 112),
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
    fn lease_fails_closed_at_and_after_expiry() {
        let (policy, capability, parent_lease) = parent();
        let lease = lease(&capability, &parent_lease);
        assert_eq!(
            lease.validate_parent_binding(&policy, &capability, &parent_lease, 115),
            Err(NetworkResolutionLeaseError::Expired)
        );
        assert_eq!(
            lease.validate_parent_binding(&policy, &capability, &parent_lease, 116),
            Err(NetworkResolutionLeaseError::Expired)
        );
    }
}
