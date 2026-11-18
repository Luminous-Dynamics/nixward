// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network Covenant foundation.
//!
//! Network authority is explicit typed intent. The kernel enforcement plane may
//! implement that intent through nftables/cgroup BPF/Landlock/etc., but the
//! reasoning plane never becomes network authority merely because it observed
//! anomalous behaviour.

use crate::software_ingress::SoftwareTrustClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

const WORKLOAD_DOMAIN: &[u8] = b"symthaea:nixward:workload-identity:v2\0";
const CAPABILITY_DOMAIN: &[u8] = b"symthaea:nixward:network-capability:v2\0";
const POLICY_DOMAIN: &[u8] = b"symthaea:nixward:network-policy:v2\0";
const LEASE_DOMAIN: &[u8] = b"symthaea:nixward:network-capability-lease:v2\0";
const ADDRESS_SCOPE_DOMAIN: &[u8] = b"symthaea:nixward:address-scope:v1\0";

pub const NETWORK_COVENANT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkDirection {
    Egress,
    Ingress,
    Listen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkZone {
    Loopback,
    Lan,
    Internet,
    Mycelix,
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DestinationSet {
    Zone { zone: NetworkZone },
    Cidrs { values: Vec<String> },
    Hostnames { values: Vec<String> },
}

impl DestinationSet {
    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        match self {
            Self::Zone {
                zone: NetworkZone::Explicit,
            } => Err(NetworkCovenantError::InvalidDestination(
                "explicit zone requires CIDR/hostname values".into(),
            )),
            Self::Zone { .. } => Ok(()),
            Self::Cidrs { values } => {
                if values.is_empty() {
                    return Err(NetworkCovenantError::InvalidDestination(
                        "empty CIDR set".into(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for value in values {
                    validate_token("CIDR", value, 128)?;
                    if !value.contains('/') {
                        return Err(NetworkCovenantError::InvalidDestination(value.clone()));
                    }
                    if !seen.insert(value) {
                        return Err(NetworkCovenantError::DuplicateDestination(value.clone()));
                    }
                }
                Ok(())
            }
            Self::Hostnames { values } => {
                if values.is_empty() {
                    return Err(NetworkCovenantError::InvalidDestination(
                        "empty hostname set".into(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for value in values {
                    validate_hostname(value)?;
                    if !seen.insert(value) {
                        return Err(NetworkCovenantError::DuplicateDestination(value.clone()));
                    }
                }
                Ok(())
            }
        }
    }
}


/// Owner-authorized classification of addresses obtained for a hostname capability.
///
/// The scope is part of the parent capability digest. A resolution lease may
/// narrow it, never select or broaden it. Hostname capabilities must declare
/// one of these policies; a hostname string alone is never an IP policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AddressScopePolicy {
    /// Permit only conservative public-unicast destinations.
    PublicUnicastOnly,
    /// Permit addresses inside this exact, canonical, sorted CIDR set.
    /// Private/LAN ranges are usable only when explicitly listed here.
    ExplicitCidrs { values: Vec<String> },
}

impl AddressScopePolicy {
    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        if let Self::ExplicitCidrs { values } = self {
            if values.is_empty() {
                return Err(NetworkCovenantError::InvalidDestination(
                    "explicit address scope requires at least one CIDR".into(),
                ));
            }
            let mut previous: Option<&str> = None;
            for value in values {
                if parse_canonical_cidr(value).is_none() {
                    return Err(NetworkCovenantError::InvalidDestination(format!(
                        "address-scope CIDR is invalid, non-canonical, unaligned, or too broad: {value}"
                    )));
                }
                if previous.is_some_and(|last| last >= value.as_str()) {
                    return Err(NetworkCovenantError::InvalidDestination(
                        "address-scope CIDRs must be sorted and unique".into(),
                    ));
                }
                previous = Some(value);
            }
        }
        Ok(())
    }

    /// Digest the exact owner-authorized scope object using its own domain.
    pub fn digest_hex(&self) -> Result<String, NetworkCovenantError> {
        self.validate()?;
        hash_json(ADDRESS_SCOPE_DOMAIN, self)
    }

    /// Check one address against the selected scope and mandatory exclusions.
    pub fn permits_address(&self, address: IpAddr) -> bool {
        if is_hard_denied_address(address) {
            return false;
        }
        match self {
            Self::PublicUnicastOnly => is_public_unicast(address),
            Self::ExplicitCidrs { values } => values.iter().any(|cidr| {
                parse_canonical_cidr(cidr)
                    .is_some_and(|(network, prefix)| ip_in_prefix(address, network, prefix))
            }),
        }
    }

    /// A lease is accepted only when every resolved address fits the scope.
    pub fn permits_all(&self, addresses: &[IpAddr]) -> bool {
        !addresses.is_empty()
            && addresses
                .iter()
                .copied()
                .all(|address| self.permits_address(address))
    }
}

/// Parse canonical CIDRs only. Host bits must be zero, prefix lengths must be
/// canonical decimal, and /0 is deliberately forbidden.
fn parse_canonical_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address_text, prefix_text) = value.split_once('/')?;
    let address = address_text.parse::<IpAddr>().ok()?;
    let prefix = prefix_text.parse::<u8>().ok()?;
    if prefix == 0 || format!("{address}/{prefix}") != value {
        return None;
    }
    let aligned = match address {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = u32::MAX << u32::from(32 - prefix);
            (u32::from(ip) & mask) == u32::from(ip)
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = u128::MAX << u32::from(128 - prefix);
            (u128::from(ip) & mask) == u128::from(ip)
        }
        _ => false,
    };
    aligned.then_some((address, prefix))
}

fn ip_in_prefix(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = u32::MAX << u32::from(32 - prefix);
            (u32::from(address) & mask) == u32::from(network)
        }
        (IpAddr::V6(address), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = u128::MAX << u32::from(128 - prefix);
            (u128::from(address) & mask) == u128::from(network)
        }
        _ => false,
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    ip_in_prefix(IpAddr::V4(address), IpAddr::V4(network), prefix)
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    ip_in_prefix(IpAddr::V6(address), IpAddr::V6(network), prefix)
}

/// Addresses that are never accepted as hostname egress destinations, even
/// under an explicit LAN CIDR scope.
fn is_hard_denied_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || ipv4_in_prefix(ip, Ipv4Addr::new(0, 0, 0, 0), 8)
                || ipv4_in_prefix(ip, Ipv4Addr::new(240, 0, 0, 0), 4)
                || ip == Ipv4Addr::new(169, 254, 169, 254)
                || ip == Ipv4Addr::new(100, 100, 100, 200)
                || ip == Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip == "fd00:ec2::254".parse::<Ipv6Addr>().expect("constant IPv6 address")
                || ipv6_in_prefix(ip, "::ffff:0:0".parse().expect("constant IPv6 prefix"), 96)
                || ipv6_in_prefix(ip, "64:ff9b::".parse().expect("constant IPv6 prefix"), 96)
                || ipv6_in_prefix(ip, "64:ff9b:1::".parse().expect("constant IPv6 prefix"), 48)
                || ipv6_in_prefix(ip, "100::".parse().expect("constant IPv6 prefix"), 64)
                || ipv6_in_prefix(ip, "100:0:0:1::".parse().expect("constant IPv6 prefix"), 64)
                || ipv6_in_prefix(ip, "2001:db8::".parse().expect("constant IPv6 prefix"), 32)
                || ipv6_in_prefix(ip, "3fff::".parse().expect("constant IPv6 prefix"), 20)
        }
    }
}

/// Conservative public-unicast classification. Some more-specific globally
/// reachable allocations inside special-purpose parent aggregates are blocked
/// deliberately rather than creating resolver-policy exceptions.
fn is_public_unicast(address: IpAddr) -> bool {
    if is_hard_denied_address(address) {
        return false;
    }
    match address {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ipv4_in_prefix(ip, Ipv4Addr::new(100, 64, 0, 0), 10)
                && !ipv4_in_prefix(ip, Ipv4Addr::new(192, 0, 0, 0), 24)
                && !ipv4_in_prefix(ip, Ipv4Addr::new(192, 88, 99, 0), 24)
                && !ipv4_in_prefix(ip, Ipv4Addr::new(198, 18, 0, 0), 15)
        }
        IpAddr::V6(ip) => {
            !ip.is_unique_local()
                && !ipv6_in_prefix(ip, "fec0::".parse().expect("constant IPv6 prefix"), 10)
                && !ipv6_in_prefix(ip, "::".parse().expect("constant IPv6 prefix"), 96)
                && !ipv6_in_prefix(ip, "2001::".parse().expect("constant IPv6 prefix"), 23)
                && !ipv6_in_prefix(ip, "2001:2::".parse().expect("constant IPv6 prefix"), 48)
                && !ipv6_in_prefix(ip, "2001:20::".parse().expect("constant IPv6 prefix"), 28)
                && !ipv6_in_prefix(ip, "2002::".parse().expect("constant IPv6 prefix"), 16)
                && !ipv6_in_prefix(ip, "5f00::".parse().expect("constant IPv6 prefix"), 16)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WorkloadSource {
    NixSystemdUnit {
        unit: String,
        closure_store_path: String,
        config_blake3: String,
    },
    SovereignGuest {
        trust_class: SoftwareTrustClass,
        guest_plan_blake3: String,
        artifact_identity: String,
        authority_blake3: String,
    },
    UserSession {
        uid: u32,
        profile_blake3: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub schema_version: u32,
    pub holon_id: String,
    pub name: String,
    pub source: WorkloadSource,
}

impl WorkloadIdentity {
    pub fn new(
        holon_id: impl Into<String>,
        name: impl Into<String>,
        source: WorkloadSource,
    ) -> Result<Self, NetworkCovenantError> {
        let identity = Self {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            holon_id: holon_id.into(),
            name: name.into(),
            source,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        if self.schema_version != NETWORK_COVENANT_SCHEMA_VERSION {
            return Err(NetworkCovenantError::UnsupportedSchema(self.schema_version));
        }
        validate_token("holon id", &self.holon_id, 256)?;
        validate_token("workload name", &self.name, 256)?;
        match &self.source {
            WorkloadSource::NixSystemdUnit {
                unit,
                closure_store_path,
                config_blake3,
            } => {
                validate_token("systemd unit", unit, 256)?;
                if !closure_store_path.starts_with("/nix/store/")
                    || closure_store_path.contains('\0')
                {
                    return Err(NetworkCovenantError::InvalidWorkloadIdentity(
                        "Nix workload closure must be an absolute /nix/store path".into(),
                    ));
                }
                validate_digest(config_blake3)?;
            }
            WorkloadSource::SovereignGuest {
                trust_class,
                guest_plan_blake3,
                artifact_identity,
                authority_blake3,
            } => {
                if !matches!(
                    trust_class,
                    SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
                ) {
                    return Err(NetworkCovenantError::InvalidWorkloadIdentity(
                        "guest workload identity must be S2 or S3".into(),
                    ));
                }
                validate_digest(guest_plan_blake3)?;
                validate_token("guest artifact identity", artifact_identity, 2048)?;
                validate_digest(authority_blake3)?;
            }
            WorkloadSource::UserSession { profile_blake3, .. } => validate_digest(profile_blake3)?,
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCovenantError> {
        self.validate()?;
        hash_json(WORKLOAD_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    fn validate(&self, protocol: NetworkProtocol) -> Result<(), NetworkCovenantError> {
        if matches!(protocol, NetworkProtocol::Icmp) {
            return Err(NetworkCovenantError::InvalidPortRange(
                "ICMP capabilities do not carry TCP/UDP ports".into(),
            ));
        }
        if self.from == 0 || self.to == 0 || self.from > self.to {
            return Err(NetworkCovenantError::InvalidPortRange(format!(
                "{}-{}",
                self.from, self.to
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCapability {
    pub schema_version: u32,
    pub capability_id: String,
    pub workload_blake3: String,
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
    pub destinations: DestinationSet,
    /// Required for hostname destinations and included in the capability digest.
    pub address_scope: Option<AddressScopePolicy>,
    pub ports: Vec<PortRange>,
    pub justification: String,
}

impl NetworkCapability {
    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        if self.schema_version != NETWORK_COVENANT_SCHEMA_VERSION {
            return Err(NetworkCovenantError::UnsupportedSchema(self.schema_version));
        }
        validate_token("capability id", &self.capability_id, 256)?;
        validate_digest(&self.workload_blake3)?;
        self.destinations.validate()?;
        match (&self.destinations, &self.address_scope) {
            (DestinationSet::Hostnames { .. }, Some(scope)) => scope.validate()?,
            (DestinationSet::Hostnames { .. }, None) => {
                return Err(NetworkCovenantError::InvalidDestination(
                    "hostname capabilities require an explicit owner-authorized address scope".into(),
                ));
            }
            (_, Some(_)) => {
                return Err(NetworkCovenantError::InvalidDestination(
                    "address_scope is only valid for hostname destinations".into(),
                ));
            }
            (_, None) => {}
        }
        if matches!(self.protocol, NetworkProtocol::Icmp) && !self.ports.is_empty() {
            return Err(NetworkCovenantError::InvalidPortRange(
                "ICMP capability may not declare ports".into(),
            ));
        }
        for port in &self.ports {
            port.validate(self.protocol)?;
        }
        validate_token("network justification", &self.justification, 2048)?;
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCovenantError> {
        self.validate()?;
        hash_json(CAPABILITY_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyPlan {
    pub schema_version: u32,
    pub holon_id: String,
    pub workloads: Vec<WorkloadIdentity>,
    pub capabilities: Vec<NetworkCapability>,
    pub host_ingress_default: String,
    pub host_forward_default: String,
    pub workload_egress_status: String,
    pub reasoning_authority: String,
    pub payload_capture_default: bool,
}

impl NetworkPolicyPlan {
    pub fn new(
        holon_id: impl Into<String>,
        workloads: Vec<WorkloadIdentity>,
        capabilities: Vec<NetworkCapability>,
    ) -> Result<Self, NetworkCovenantError> {
        let plan = Self {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            holon_id: holon_id.into(),
            workloads,
            capabilities,
            host_ingress_default: "deny".into(),
            host_forward_default: "deny".into(),
            workload_egress_status: "declared-not-runtime-enforced-v39".into(),
            reasoning_authority: "none".into(),
            payload_capture_default: false,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        if self.schema_version != NETWORK_COVENANT_SCHEMA_VERSION {
            return Err(NetworkCovenantError::UnsupportedSchema(self.schema_version));
        }
        validate_token("holon id", &self.holon_id, 256)?;
        if self.host_ingress_default != "deny" || self.host_forward_default != "deny" {
            return Err(NetworkCovenantError::UnsafeBaseline(
                "sovereign baseline requires deny ingress and deny forward".into(),
            ));
        }
        if self.workload_egress_status != "declared-not-runtime-enforced-v39" {
            return Err(NetworkCovenantError::UnsafeBaseline(
                "V39 workload egress status may not claim runtime enforcement".into(),
            ));
        }
        if self.reasoning_authority != "none" {
            return Err(NetworkCovenantError::UnsafeBaseline(
                "reasoning/anomaly layer cannot hold network enforcement authority".into(),
            ));
        }
        if self.payload_capture_default {
            return Err(NetworkCovenantError::UnsafeBaseline(
                "payload capture must be explicit opt-in evidence, never baseline telemetry".into(),
            ));
        }

        let mut workloads = BTreeSet::new();
        for workload in &self.workloads {
            workload.validate()?;
            if workload.holon_id != self.holon_id {
                return Err(NetworkCovenantError::HolonMismatch);
            }
            let digest = workload.digest_hex()?;
            if !workloads.insert(digest) {
                return Err(NetworkCovenantError::DuplicateWorkload(
                    workload.name.clone(),
                ));
            }
        }
        let mut capability_ids = BTreeSet::new();
        for capability in &self.capabilities {
            capability.validate()?;
            if !workloads.contains(&capability.workload_blake3) {
                return Err(NetworkCovenantError::UnknownWorkload(
                    capability.workload_blake3.clone(),
                ));
            }
            if !capability_ids.insert(capability.capability_id.as_str()) {
                return Err(NetworkCovenantError::DuplicateCapability(
                    capability.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCovenantError> {
        self.validate()?;
        hash_json(POLICY_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCapabilityLease {
    pub schema_version: u32,
    pub holon_id: String,
    pub policy_blake3: String,
    pub capability_blake3: String,
    pub issuer_key_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
}

impl NetworkCapabilityLease {
    pub fn validate(&self) -> Result<(), NetworkCovenantError> {
        if self.schema_version != NETWORK_COVENANT_SCHEMA_VERSION {
            return Err(NetworkCovenantError::UnsupportedSchema(self.schema_version));
        }
        validate_token("holon id", &self.holon_id, 256)?;
        validate_digest(&self.policy_blake3)?;
        validate_digest(&self.capability_blake3)?;
        validate_token("issuer key id", &self.issuer_key_id, 256)?;
        validate_token("lease nonce", &self.nonce, 512)?;
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(NetworkCovenantError::InvalidLeaseTime);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCovenantError> {
        self.validate()?;
        hash_json(LEASE_DOMAIN, self)
    }
}

pub fn network_policy_json_for_holon(holon_id: &str) -> Result<String, NetworkCovenantError> {
    let policy = NetworkPolicyPlan::new(holon_id, Vec::new(), Vec::new())?;
    let rendered = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_COVENANT_SCHEMA_VERSION,
        "kind": "symthaea-network-policy-v1",
        "status": "host-baseline-enforced-workload-egress-declared-v39",
        "policy": policy,
        "enforcement": {
            "host": "nixos-firewall+nftables",
            "workload": "declared-not-runtime-enforced-v39",
            "dynamic_leases": "typed-not-runtime-enforced-v39"
        },
        "reasoning": {
            "authority": "none",
            "anomaly_action": "evidence-only",
            "payload_capture_default": false
        }
    }))
    .map_err(|_| NetworkCovenantError::Serialization)?;
    Ok(rendered + "\n")
}

pub fn default_network_policy_json() -> String {
    network_policy_json_for_holon("unbound-holon").unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"status\":\"serialization-failed\"}}\n",
            NETWORK_COVENANT_SCHEMA_VERSION
        )
    })
}

fn validate_digest(value: &str) -> Result<(), NetworkCovenantError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NetworkCovenantError::InvalidDigest)
    }
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), NetworkCovenantError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(NetworkCovenantError::InvalidValue {
            field,
            value: value.into(),
        })
    } else {
        Ok(())
    }
}

fn validate_hostname(value: &str) -> Result<(), NetworkCovenantError> {
    validate_token("hostname", value, 253)?;
    let canonical = value.strip_suffix('.').unwrap_or(value);
    if canonical.is_empty()
        || canonical.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(NetworkCovenantError::InvalidDestination(value.into()));
    }
    Ok(())
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkCovenantError> {
    let encoded = serde_json::to_vec(value).map_err(|_| NetworkCovenantError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkCovenantError {
    #[error("unsupported network-covenant schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid {field}: {value:?}")]
    InvalidValue { field: &'static str, value: String },
    #[error("invalid content digest")]
    InvalidDigest,
    #[error("invalid workload identity: {0}")]
    InvalidWorkloadIdentity(String),
    #[error("invalid network destination: {0}")]
    InvalidDestination(String),
    #[error("duplicate destination {0}")]
    DuplicateDestination(String),
    #[error("invalid port range: {0}")]
    InvalidPortRange(String),
    #[error("unsafe network baseline: {0}")]
    UnsafeBaseline(String),
    #[error("workload belongs to a different Holon")]
    HolonMismatch,
    #[error("duplicate workload {0}")]
    DuplicateWorkload(String),
    #[error("unknown workload digest {0}")]
    UnknownWorkload(String),
    #[error("duplicate capability id {0}")]
    DuplicateCapability(String),
    #[error("invalid capability lease time window")]
    InvalidLeaseTime,
    #[error("network evidence serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload() -> WorkloadIdentity {
        WorkloadIdentity::new(
            "holon-a",
            "backup-agent",
            WorkloadSource::NixSystemdUnit {
                unit: "backup-agent.service".into(),
                closure_store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-backup-agent"
                    .into(),
                config_blake3: "11".repeat(32),
            },
        )
        .unwrap()
    }

    #[test]
    fn policy_requires_capabilities_to_reference_declared_workloads() {
        let w = workload();
        let capability = NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "backup-egress".into(),
            workload_blake3: w.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Hostnames {
                values: vec!["backup.example".into()],
            },
            address_scope: Some(AddressScopePolicy::PublicUnicastOnly),
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "encrypted owner-authorized backup transport".into(),
        };
        let policy = NetworkPolicyPlan::new("holon-a", vec![w], vec![capability]).unwrap();
        assert_eq!(policy.reasoning_authority, "none");
        assert_eq!(policy.host_ingress_default, "deny");
        assert_eq!(policy.digest_hex().unwrap().len(), 64);
    }

    #[test]
    fn hostname_capabilities_require_an_explicit_owner_address_scope() {
        let w = workload();
        let mut capability = NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "backup-egress".into(),
            workload_blake3: w.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Hostnames {
                values: vec!["backup.example".into()],
            },
            address_scope: None,
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "owner-approved backup".into(),
        };
        assert!(matches!(
            capability.validate(),
            Err(NetworkCovenantError::InvalidDestination(_))
        ));

        capability.address_scope = Some(AddressScopePolicy::PublicUnicastOnly);
        assert!(capability.validate().is_ok());

        capability.destinations = DestinationSet::Cidrs {
            values: vec!["192.168.0.0/16".into()],
        };
        assert!(matches!(
            capability.validate(),
            Err(NetworkCovenantError::InvalidDestination(_))
        ));
    }

    #[test]
    fn public_unicast_scope_rejects_special_ranges_and_mixed_answer_sets() {
        let scope = AddressScopePolicy::PublicUnicastOnly;
        assert!(scope.permits_address("93.184.216.34".parse().unwrap()));
        assert!(scope.permits_address("2606:4700:4700::1111".parse().unwrap()));

        for address in [
            "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1",
            "169.254.1.1", "169.254.169.254", "172.16.0.1",
            "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1",
            "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
            "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8",
            "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001::1",
            "2001:2::1", "2001:db8::1", "2002::1", "3fff::1", "5f00::1",
            "fc00::1", "fe80::1", "ff02::1"
        ] {
            let parsed = address.parse::<IpAddr>().unwrap();
            assert!(!scope.permits_address(parsed), "unexpectedly allowed {address}");
        }

        assert!(!scope.permits_all(&[
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap()
        ]));
    }

    #[test]
    fn explicit_cidr_scope_is_canonical_and_narrow() {
        let scope = AddressScopePolicy::ExplicitCidrs {
            values: vec!["192.168.0.0/16".into(), "fd12:3456::/32".into()],
        };
        assert!(scope.validate().is_ok());
        assert!(scope.permits_address("192.168.1.10".parse().unwrap()));
        assert!(scope.permits_address("fd12:3456::10".parse().unwrap()));
        assert!(!scope.permits_address("10.0.0.1".parse().unwrap()));
        assert!(!AddressScopePolicy::ExplicitCidrs {
            values: vec!["169.254.0.0/16".into()]
        }.permits_address("169.254.169.254".parse().unwrap()));

        for values in [
            vec![],
            vec!["0.0.0.0/0".into()],
            vec!["192.168.1.1/24".into()],
            vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()]
        ] {
            assert!(AddressScopePolicy::ExplicitCidrs { values }.validate().is_err());
        }
    }

    #[test]
    fn anomaly_reasoning_cannot_be_network_authority() {
        let mut policy = NetworkPolicyPlan::new("holon-a", vec![], vec![]).unwrap();
        policy.reasoning_authority = "symthaea-active-inference".into();
        assert!(matches!(
            policy.validate(),
            Err(NetworkCovenantError::UnsafeBaseline(_))
        ));
    }

    #[test]
    fn guest_identity_is_more_than_process_hash() {
        let w = WorkloadIdentity::new(
            "holon-a",
            "signal",
            WorkloadSource::SovereignGuest {
                trust_class: SoftwareTrustClass::SovereignGuest,
                guest_plan_blake3: "22".repeat(32),
                artifact_identity: "flatpak:org.signal.Signal@deadbeef".into(),
                authority_blake3: "33".repeat(32),
            },
        )
        .unwrap();
        assert_eq!(w.digest_hex().unwrap().len(), 64);
    }

    #[test]
    fn leases_are_subject_bound_and_expiring() {
        let lease = NetworkCapabilityLease {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            holon_id: "holon-a".into(),
            policy_blake3: "44".repeat(32),
            capability_blake3: "55".repeat(32),
            issuer_key_id: "owner-root".into(),
            issued_at_unix: 10,
            expires_at_unix: 20,
            nonce: "nonce-123".into(),
        };
        assert_eq!(lease.digest_hex().unwrap().len(), 64);
    }
}
