//! Conservative, fail-closed containment proof for finite network policies.
//!
//! This v0.1 implementation proves that explicit candidate (workload, direction,
//! protocol, CIDR, port) tuples are a subset of an operator-supplied policy.
//! It is not a signature verifier, authorization primitive, runtime enforcer,
//! credential-risk model, or semantic-risk classifier.
//!
//! Supported: exact WorkloadIdentity digests, TCP/UDP, canonical IPv4/IPv6
//! CIDRs, and explicit port ranges. Hostnames, zones, ICMP, Any, malformed
//! policy shapes and resource-budget exhaustion never produce Within.

use crate::network_covenant::{
    DestinationSet, NetworkCapability, NetworkDirection, NetworkPolicyPlan,
    NetworkProtocol, PortRange,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const NETWORK_CONTAINMENT_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_CONTAINMENT_PROVER_VERSION: &str = "nixward-network-containment-v0.1";
pub const MAX_POLICY_WORKLOADS: usize = 256;
pub const MAX_POLICY_CAPABILITIES: usize = 1024;
pub const MAX_CIDRS_PER_CAPABILITY: usize = 256;
pub const MAX_PORT_RANGES_PER_CAPABILITY: usize = 256;
pub const MAX_POLICY_COMPARISON_WORK: usize = 100_000;
const REPORT_DIGEST_DOMAIN: &[u8] = b"nixward:network-policy-containment-report:v1\\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentState {
    Within,
    Exceeds,
    Unsupported,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDeltaKind {
    CandidateGrantAdded,
    CandidateGrantRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDeltaEntry {
    pub kind: PolicyDeltaKind,
    pub capability_id: String,
    pub capability_blake3: String,
    pub workload_blake3: String,
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleKind {
    WorkloadExpansion,
    NetworkReachExpansion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCounterexample {
    pub kind: CounterexampleKind,
    pub capability_id: Option<String>,
    pub workload_blake3: String,
    pub direction: Option<NetworkDirection>,
    pub protocol: Option<NetworkProtocol>,
    pub destination: Option<String>,
    pub port: Option<u16>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContainmentReport {
    pub schema_version: u32,
    pub kind: String,
    pub state: ContainmentState,
    pub prover_version: String,
    pub boundary_policy_blake3: Option<String>,
    pub candidate_policy_blake3: Option<String>,
    pub delta: Vec<PolicyDeltaEntry>,
    pub counterexamples: Vec<PolicyCounterexample>,
    pub unsupported_reasons: Vec<String>,
    pub runtime_enforcement_proven: bool,
}

impl PolicyContainmentReport {
    fn new(state: ContainmentState) -> Self {
        Self {
            schema_version: NETWORK_CONTAINMENT_SCHEMA_VERSION,
            kind: "nixward-network-policy-containment-report-v1".into(),
            state,
            prover_version: NETWORK_CONTAINMENT_PROVER_VERSION.into(),
            boundary_policy_blake3: None,
            candidate_policy_blake3: None,
            delta: Vec::new(),
            counterexamples: Vec::new(),
            unsupported_reasons: Vec::new(),
            runtime_enforcement_proven: false,
        }
    }

    /// Domain-separated digest of this exact report, including its decision,
    /// policy digests, prover version, deltas, counterexamples and limitations.
    /// This is an integrity commitment only; it is not an owner signature or
    /// evidence that the declared network policy is active at runtime.
    pub fn digest_hex(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REPORT_DIGEST_DOMAIN);
        hasher.update(&(encoded.len() as u64).to_le_bytes());
        hasher.update(&encoded);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRange {
    family: AddressFamily,
    start: u128,
    end: u128,
}

impl IpRange {
    fn parse(value: &str) -> Result<Self, String> {
        let Some((address, prefix_text)) = value.split_once('/') else {
            return Err(format!("invalid CIDR {value}"));
        };
        if prefix_text.is_empty() || prefix_text.contains('/') {
            return Err(format!("invalid CIDR {value}"));
        }
        let prefix = prefix_text
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix {value}"))?;

        if let Ok(ip) = address.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return Err(format!("IPv4 prefix out of range {value}"));
            }
            let bits = u32::from(ip);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let network = bits & mask;
            if network != bits {
                return Err(format!("non-canonical CIDR {value}"));
            }
            return Ok(Self {
                family: AddressFamily::V4,
                start: u128::from(network),
                end: u128::from(network | !mask),
            });
        }

        if let Ok(ip) = address.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return Err(format!("IPv6 prefix out of range {value}"));
            }
            let bits = u128::from(ip);
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            let network = bits & mask;
            if network != bits {
                return Err(format!("non-canonical CIDR {value}"));
            }
            return Ok(Self {
                family: AddressFamily::V6,
                start: network,
                end: network | !mask,
            });
        }

        Err(format!("invalid IP address in CIDR {value}"))
    }

    fn host_at(self, address: u128) -> String {
        match self.family {
            AddressFamily::V4 => Ipv4Addr::from(address as u32).to_string(),
            AddressFamily::V6 => Ipv6Addr::from(address).to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedCapability {
    capability_id: String,
    workload_blake3: String,
    direction: NetworkDirection,
    protocol: NetworkProtocol,
    destinations: Vec<IpRange>,
    ports: Vec<PortRange>,
}

fn parse_capability(capability: &NetworkCapability) -> Result<ParsedCapability, String> {
    if capability.direction != NetworkDirection::Egress {
        return Err("ingress/listen is unsupported in the agent egress profile".into());
    }
    let destinations = match &capability.destinations {
        DestinationSet::Cidrs { values } => {
            if values.is_empty() || values.len() > MAX_CIDRS_PER_CAPABILITY {
                return Err("CIDR count outside v0.1 model".into());
            }
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let range = IpRange::parse(value)?;
                let is_v4_all = range.family == AddressFamily::V4
                    && range.start == 0
                    && range.end == u128::from(u32::MAX);
                let is_v6_all = range.family == AddressFamily::V6
                    && range.start == 0
                    && range.end == u128::MAX;
                if is_v4_all || is_v6_all {
                    return Err("all-address CIDR is prohibited in the v0.1 agent profile".into());
                }
                parsed.push(range);
            }
            parsed
        }
        DestinationSet::Hostnames { .. } => {
            return Err("hostname requires authenticated DNS/connection evidence".into())
        }
        DestinationSet::Zone { zone } => {
            return Err(format!("zone selector {zone:?} is unsupported"))
        }
    };

    if !matches!(capability.protocol, NetworkProtocol::Tcp | NetworkProtocol::Udp) {
        return Err(format!("protocol {:?} is unsupported", capability.protocol));
    }
    if capability.ports.is_empty() || capability.ports.len() > MAX_PORT_RANGES_PER_CAPABILITY {
        return Err("port range count outside v0.1 model".into());
    }

    Ok(ParsedCapability {
        capability_id: capability.capability_id.clone(),
        workload_blake3: capability.workload_blake3.clone(),
        direction: capability.direction,
        protocol: capability.protocol,
        destinations,
        ports: capability.ports.clone(),
    })
}

fn matching_boundary_rules<'a>(
    capability: &NetworkCapability,
    boundary: &'a NetworkPolicyPlan,
) -> Vec<&'a NetworkCapability> {
    boundary.capabilities.iter().filter(|rule| {
        rule.workload_blake3 == capability.workload_blake3
            && rule.direction == capability.direction
            // An Any rule may cover this protocol, but parse_capability rejects
            // it as unsupported. Keep it in the comparison so it yields
            // Unsupported rather than a false expansion witness.
            && (rule.protocol == capability.protocol || rule.protocol == NetworkProtocol::Any)
    }).collect()
}

fn first_uncovered_ip(candidate: IpRange, intervals: &mut [IpRange]) -> Option<u128> {
    intervals.sort_by_key(|range| (range.start, range.end));
    let mut cursor = candidate.start;
    for interval in intervals.iter().filter(|range| range.family == candidate.family) {
        if interval.end < cursor || interval.start > candidate.end {
            continue;
        }
        if interval.start > cursor {
            return Some(cursor);
        }
        if interval.end >= candidate.end {
            return None;
        }
        cursor = interval.end.saturating_add(1);
        if cursor > candidate.end {
            return None;
        }
    }
    (cursor <= candidate.end).then_some(cursor)
}

/// Checks one candidate CIDR × port-range rectangle against the union of
/// matching boundary rules. Port partitions make the active rule set constant
/// on each segment; IP coverage is then an exact interval-union check.
fn check_rectangle(
    candidate_ip: IpRange,
    candidate_port: PortRange,
    boundary_rules: &[&NetworkCapability],
) -> Result<Option<(u128, u16)>, String> {
    let mut parsed = Vec::new();
    let mut has_unmodeled_rule = false;
    for rule in boundary_rules {
        match parse_capability(rule) {
            Ok(parsed_rule) => parsed.push(parsed_rule),
            Err(_) => has_unmodeled_rule = true,
        }
    }

    let mut cuts = vec![
        u32::from(candidate_port.from),
        u32::from(candidate_port.to) + 1,
    ];
    for rule in &parsed {
        for range in &rule.ports {
            let start = range.from.max(candidate_port.from);
            let end = range.to.min(candidate_port.to);
            if start <= end {
                cuts.push(u32::from(start));
                cuts.push(u32::from(end) + 1);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();

    for segment in cuts.windows(2) {
        let port_start = segment[0] as u16;
        let port_end = (segment[1] - 1) as u16;
        if port_start > candidate_port.to || port_end < candidate_port.from {
            continue;
        }

        let mut intervals = Vec::new();
        for rule in &parsed {
            let covers_port_segment = rule.ports.iter().any(|range| {
                range.from <= port_start && range.to >= port_end
            });
            if covers_port_segment {
                intervals.extend(rule.destinations.iter().copied());
            }
        }

        if let Some(uncovered) = first_uncovered_ip(candidate_ip, &mut intervals) {
            if has_unmodeled_rule {
                return Err(
                    "matching boundary includes an unsupported selector; subset cannot be proven"
                        .into(),
                );
            }
            return Ok(Some((uncovered, port_start)));
        }
    }
    Ok(None)
}

fn make_delta(
    boundary: &NetworkPolicyPlan,
    candidate: &NetworkPolicyPlan,
) -> Vec<PolicyDeltaEntry> {
    let boundary_digests: BTreeSet<String> = boundary.capabilities
        .iter().filter_map(|cap| cap.digest_hex().ok()).collect();
    let candidate_digests: BTreeSet<String> = candidate.capabilities
        .iter().filter_map(|cap| cap.digest_hex().ok()).collect();

    let mut delta = Vec::new();
    for (kind, policy, other) in [
        (PolicyDeltaKind::CandidateGrantAdded, candidate, &boundary_digests),
        (PolicyDeltaKind::CandidateGrantRemoved, boundary, &candidate_digests),
    ] {
        for cap in &policy.capabilities {
            if let Ok(digest) = cap.digest_hex() {
                if !other.contains(&digest) {
                    delta.push(PolicyDeltaEntry {
                        kind,
                        capability_id: cap.capability_id.clone(),
                        capability_blake3: digest,
                        workload_blake3: cap.workload_blake3.clone(),
                        direction: cap.direction,
                        protocol: cap.protocol,
                    });
                }
            }
        }
    }
    delta.sort_by(|a, b| {
        (a.kind, &a.workload_blake3, &a.capability_id)
            .cmp(&(b.kind, &b.workload_blake3, &b.capability_id))
    });
    delta
}

/// Proves that the candidate's declared network capabilities are contained
/// by the supplied boundary for the supported finite model.
///
/// This function does not authenticate the owner boundary, attach the policy
/// to a runtime, verify credential-provider reach, consume replay state, sign,
/// launch, or activate networking.
pub fn check_policy_within_boundary(
    boundary: &NetworkPolicyPlan,
    candidate: &NetworkPolicyPlan,
) -> PolicyContainmentReport {
    let mut report = PolicyContainmentReport::new(ContainmentState::Unsupported);

    if boundary.workloads.len() > MAX_POLICY_WORKLOADS
        || candidate.workloads.len() > MAX_POLICY_WORKLOADS
        || boundary.capabilities.len() > MAX_POLICY_CAPABILITIES
        || candidate.capabilities.len() > MAX_POLICY_CAPABILITIES
    {
        report.state = ContainmentState::Inconclusive;
        report.unsupported_reasons.push("policy exceeds v0.1 deterministic resource budget".into());
        return report;
    }
    if let Err(error) = boundary.validate() {
        report.unsupported_reasons.push(format!("invalid boundary policy: {error}"));
        return report;
    }
    if let Err(error) = candidate.validate() {
        report.unsupported_reasons.push(format!("invalid candidate policy: {error}"));
        return report;
    }
    report.boundary_policy_blake3 = boundary.digest_hex().ok();
    report.candidate_policy_blake3 = candidate.digest_hex().ok();
    report.delta = make_delta(boundary, candidate);

    if boundary.holon_id != candidate.holon_id {
        report.state = ContainmentState::Exceeds;
        report.counterexamples.push(PolicyCounterexample {
            kind: CounterexampleKind::WorkloadExpansion,
            capability_id: None,
            workload_blake3: String::new(),
            direction: None,
            protocol: None,
            destination: None,
            port: None,
            reason: "candidate Holon differs from operator boundary".into(),
        });
        return report;
    }

    let boundary_workloads: BTreeSet<String> = boundary.workloads
        .iter().filter_map(|workload| workload.digest_hex().ok()).collect();
    for workload in &candidate.workloads {
        let digest = match workload.digest_hex() {
            Ok(digest) => digest,
            Err(error) => {
                report.unsupported_reasons.push(format!("workload digest: {error}"));
                return report;
            }
        };
        if !boundary_workloads.contains(&digest) {
            report.state = ContainmentState::Exceeds;
            report.counterexamples.push(PolicyCounterexample {
                kind: CounterexampleKind::WorkloadExpansion,
                capability_id: None,
                workload_blake3: digest,
                direction: None,
                protocol: None,
                destination: None,
                port: None,
                reason: "candidate introduces a workload identity absent from the boundary".into(),
            });
        }
    }
    if report.state == ContainmentState::Exceeds {
        return report;
    }

    let mut estimated_work = 0usize;
    for capability in &candidate.capabilities {
        let destination_count = match &capability.destinations {
            DestinationSet::Cidrs { values } => values.len(),
            DestinationSet::Hostnames { .. } | DestinationSet::Zone { .. } => 1,
        };
        let candidate_rectangles = match destination_count.checked_mul(capability.ports.len()) {
            Some(value) => value,
            None => {
                report.state = ContainmentState::Inconclusive;
                report.unsupported_reasons.push("candidate rectangle estimate overflowed".into());
                return report;
            }
        };
        let mut boundary_rule_cost = 1usize;
        for rule in matching_boundary_rules(capability, boundary) {
            let rule_destinations = match &rule.destinations {
                DestinationSet::Cidrs { values } => values.len(),
                DestinationSet::Hostnames { .. } | DestinationSet::Zone { .. } => 1,
            };
            let rule_cost = match rule_destinations.checked_mul(rule.ports.len().max(1)) {
                Some(value) => value,
                None => {
                    report.state = ContainmentState::Inconclusive;
                    report.unsupported_reasons.push("boundary rule estimate overflowed".into());
                    return report;
                }
            };
            boundary_rule_cost = match boundary_rule_cost.checked_add(rule_cost) {
                Some(value) => value,
                None => {
                    report.state = ContainmentState::Inconclusive;
                    report.unsupported_reasons.push("boundary work estimate overflowed".into());
                    return report;
                }
            };
        }
        let unit_work = match candidate_rectangles.checked_mul(boundary_rule_cost) {
            Some(value) => value,
            None => {
                report.state = ContainmentState::Inconclusive;
                report.unsupported_reasons.push("policy comparison work estimate overflowed".into());
                return report;
            }
        };
        let Some(total_work) = estimated_work.checked_add(unit_work) else {
            report.state = ContainmentState::Inconclusive;
            report.unsupported_reasons.push("policy comparison work estimate overflowed".into());
            return report;
        };
        estimated_work = total_work;
        if estimated_work > MAX_POLICY_COMPARISON_WORK {
            report.state = ContainmentState::Inconclusive;
            report.unsupported_reasons.push(format!(
                "policy comparison work {estimated_work} exceeds budget {MAX_POLICY_COMPARISON_WORK}"
            ));
            return report;
        }
    }

    let mut unsupported = false;
    for capability in &candidate.capabilities {
        let parsed_candidate = match parse_capability(capability) {
            Ok(parsed) => parsed,
            Err(error) => {
                unsupported = true;
                report.unsupported_reasons.push(format!(
                    "candidate capability {}: {error}",
                    capability.capability_id
                ));
                continue;
            }
        };
        let matching = matching_boundary_rules(capability, boundary);
        for candidate_ip in &parsed_candidate.destinations {
            for candidate_port in &parsed_candidate.ports {
                match check_rectangle(*candidate_ip, candidate_port.clone(), &matching) {
                    Ok(None) => {}
                    Ok(Some((address, port))) => {
                        report.state = ContainmentState::Exceeds;
                        report.counterexamples.push(PolicyCounterexample {
                            kind: CounterexampleKind::NetworkReachExpansion,
                            capability_id: Some(parsed_candidate.capability_id.clone()),
                            workload_blake3: parsed_candidate.workload_blake3.clone(),
                            direction: Some(parsed_candidate.direction),
                            protocol: Some(parsed_candidate.protocol),
                            destination: Some(candidate_ip.host_at(address)),
                            port: Some(port),
                            reason: "candidate grants a tuple outside the operator boundary".into(),
                        });
                    }
                    Err(error) => {
                        unsupported = true;
                        report.unsupported_reasons.push(format!(
                            "boundary capability for {}: {error}",
                            parsed_candidate.capability_id
                        ));
                    }
                }
            }
        }
    }

    if report.state == ContainmentState::Exceeds {
        return report;
    }
    if unsupported {
        report.state = ContainmentState::Unsupported;
    } else {
        report.state = ContainmentState::Within;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_covenant::{
        NetworkZone, WorkloadIdentity, WorkloadSource, NETWORK_COVENANT_SCHEMA_VERSION,
    };

    fn workload(name: &str, unit: &str, hash: &str) -> WorkloadIdentity {
        WorkloadIdentity::new(
            "tenant-a",
            name,
            WorkloadSource::NixSystemdUnit {
                unit: unit.into(),
                closure_store_path: format!("/nix/store/{}-{}", "a".repeat(32), name),
                config_blake3: hash.repeat(32),
            },
        ).unwrap()
    }

    fn capability(
        workload: &WorkloadIdentity,
        id: &str,
        cidrs: &[&str],
        ports: &[(u16, u16)],
    ) -> NetworkCapability {
        NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: id.into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Cidrs {
                values: cidrs.iter().map(|value| (*value).to_string()).collect(),
            },
            ports: ports.iter().map(|(from, to)| PortRange { from: *from, to: *to }).collect(),
            justification: "bounded policy test".into(),
        }
    }

    fn policy(workload: WorkloadIdentity, capabilities: Vec<NetworkCapability>) -> NetworkPolicyPlan {
        NetworkPolicyPlan::new("tenant-a", vec![workload], capabilities).unwrap()
    }

    #[test]
    fn identical_policy_is_within_boundary() {
        let workload = workload("worker", "worker.service", "1");
        let cap = capability(&workload, "api", &["203.0.113.0/24"], &[(443, 443)]);
        let boundary = policy(workload.clone(), vec![cap.clone()]);
        let candidate = policy(workload, vec![cap]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Within);
        assert!(!report.runtime_enforcement_proven);
    }

    #[test]
    fn narrower_cidr_and_ports_are_within() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![capability(&workload, "broad", &["203.0.113.0/24"], &[(80, 100)])]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "narrow", &["203.0.113.64/26"], &[(90, 95)])]);
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Within);
    }

    #[test]
    fn union_of_adjacent_boundary_cidrs_covers_candidate() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![
            capability(&workload, "left", &["203.0.113.0/25"], &[(443, 443)]),
            capability(&workload, "right", &["203.0.113.128/25"], &[(443, 443)]),
        ]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "full", &["203.0.113.0/24"], &[(443, 443)])]);
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Within);
    }

    #[test]
    fn union_of_adjacent_boundary_ports_covers_candidate() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![
            capability(&workload, "low", &["203.0.113.0/24"], &[(80, 89)]),
            capability(&workload, "high", &["203.0.113.0/24"], &[(90, 100)]),
        ]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "combined", &["203.0.113.0/24"], &[(80, 100)])]);
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Within);
    }

    #[test]
    fn new_destination_returns_concrete_counterexample() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![capability(&workload, "api", &["203.0.113.0/24"], &[(443, 443)])]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "new", &["198.51.100.0/24"], &[(443, 443)])]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Exceeds);
        assert_eq!(report.counterexamples[0].destination.as_deref(), Some("198.51.100.0"));
        assert_eq!(report.counterexamples[0].port, Some(443));
    }

    #[test]
    fn new_port_returns_concrete_counterexample() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![capability(&workload, "api", &["203.0.113.0/24"], &[(443, 443)])]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "api-wide", &["203.0.113.0/24"], &[(443, 444)])]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Exceeds);
        assert_eq!(report.counterexamples[0].port, Some(444));
    }

    #[test]
    fn new_workload_is_exceeds() {
        let boundary = policy(workload("worker", "worker.service", "1"), vec![]);
        let candidate = policy(workload("other", "other.service", "2"), vec![]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Exceeds);
        assert_eq!(report.counterexamples[0].kind, CounterexampleKind::WorkloadExpansion);
    }

    #[test]
    fn hostname_is_unsupported_not_within() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![]);
        let candidate = NetworkPolicyPlan::new("tenant-a", vec![workload.clone()], vec![NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "hostname".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Hostnames { values: vec!["api.example.invalid".into()] },
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "test".into(),
        }]).unwrap();
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Unsupported);
    }

    #[test]
    fn ingress_and_all_address_routes_are_unsupported() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![]);
        let ingress = NetworkPolicyPlan::new("tenant-a", vec![workload.clone()], vec![NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "ingress".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Ingress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Cidrs { values: vec!["203.0.113.0/24".into()] },
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "test".into(),
        }]).unwrap();
        assert_eq!(check_policy_within_boundary(&boundary, &ingress).state, ContainmentState::Unsupported);

        let all = policy(workload.clone(), vec![capability(&workload, "all", &["0.0.0.0/0"], &[(443, 443)])]);
        assert_eq!(check_policy_within_boundary(&boundary, &all).state, ContainmentState::Unsupported);
    }

    #[test]
    fn zone_is_unsupported_not_within() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![]);
        let candidate = NetworkPolicyPlan::new("tenant-a", vec![workload.clone()], vec![NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "zone".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Zone { zone: NetworkZone::Internet },
            ports: vec![PortRange { from: 443, to: 443 }],
            justification: "test".into(),
        }]).unwrap();
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Unsupported);
    }

    #[test]
    fn invalid_or_noncanonical_cidr_is_unsupported() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![]);
        let candidate = policy(workload.clone(), vec![capability(&workload, "bad", &["203.0.113.17/24"], &[(443, 443)])]);
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Unsupported);
    }

    #[test]
    fn oversized_policy_is_inconclusive_not_unbounded() {
        let workload = workload("worker", "worker.service", "1");
        let cidrs: Vec<String> = (0..256)
            .map(|i| format!("198.18.0.{i}/32"))
            .collect();
        let ports: Vec<PortRange> = (1..=256)
            .map(|port| PortRange { from: port, to: port })
            .collect();
        let cap = NetworkCapability {
            schema_version: NETWORK_COVENANT_SCHEMA_VERSION,
            capability_id: "large".into(),
            workload_blake3: workload.digest_hex().unwrap(),
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destinations: DestinationSet::Cidrs { values: cidrs },
            ports,
            justification: "bounded resource test".into(),
        };
        let boundary = policy(workload.clone(), vec![cap.clone()]);
        let candidate = policy(workload, vec![cap]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Inconclusive);
        assert!(!report.runtime_enforcement_proven);
    }

    #[test]
    fn report_digest_is_deterministic_and_binds_decision() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(
            workload.clone(),
            vec![capability(&workload, "https", &["203.0.113.0/24"], &[(443, 443)])],
        );
        let candidate = policy(
            workload.clone(),
            vec![capability(&workload, "https", &["203.0.113.0/24"], &[(443, 443)])],
        );
        let report = check_policy_within_boundary(&boundary, &candidate);
        let digest = report.digest_hex().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, report.clone().digest_hex().unwrap());

        let mut changed = report;
        changed.state = ContainmentState::Exceeds;
        assert_ne!(digest, changed.digest_hex().unwrap());
    }

    #[test]
    fn any_protocol_boundary_is_unsupported_not_false_expansion() {
        let workload = workload("worker", "worker.service", "1");
        let mut broad = capability(&workload, "any-protocol", &["203.0.113.0/24"], &[(443, 443)]);
        broad.protocol = NetworkProtocol::Any;
        let boundary = policy(workload.clone(), vec![broad]);
        let candidate = policy(
            workload.clone(),
            vec![capability(&workload, "https", &["203.0.113.0/24"], &[(443, 443)])],
        );
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Unsupported);
        assert!(!report.unsupported_reasons.is_empty());
    }

    #[test]
    fn any_protocol_rule_does_not_block_explicit_full_coverage() {
        let workload = workload("worker", "worker.service", "1");
        let mut broad = capability(&workload, "any-protocol", &["203.0.113.0/24"], &[(443, 443)]);
        broad.protocol = NetworkProtocol::Any;
        let explicit = capability(
            &workload,
            "tcp-explicit",
            &["203.0.113.0/24"],
            &[(443, 443)],
        );
        let boundary = policy(workload.clone(), vec![broad, explicit]);
        let candidate = policy(
            workload.clone(),
            vec![capability(&workload, "https", &["203.0.113.0/24"], &[(443, 443)])],
        );
        assert_eq!(
            check_policy_within_boundary(&boundary, &candidate).state,
            ContainmentState::Within
        );
    }

    #[test]
    fn tcp_boundary_does_not_cover_udp_candidate() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(
            workload.clone(),
            vec![capability(&workload, "tcp-only", &["203.0.113.0/24"], &[(443, 443)])],
        );
        let mut udp = capability(&workload, "udp", &["203.0.113.0/24"], &[(443, 443)]);
        udp.protocol = NetworkProtocol::Udp;
        let candidate = policy(workload, vec![udp]);
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Exceeds);
        assert_eq!(report.counterexamples[0].protocol, Some(NetworkProtocol::Udp));
    }

    #[test]
    fn ipv6_union_of_adjacent_boundary_ranges_covers_candidate() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(workload.clone(), vec![
            capability(&workload, "v6-low", &["2001:db8:1:2::/65"], &[(443, 443)]),
            capability(&workload, "v6-high", &["2001:db8:1:2:8000::/65"], &[(443, 443)]),
        ]);
        let candidate = policy(
            workload.clone(),
            vec![capability(&workload, "v6-full", &["2001:db8:1:2::/64"], &[(443, 443)])],
        );
        assert_eq!(check_policy_within_boundary(&boundary, &candidate).state, ContainmentState::Within);
    }

    #[test]
    fn partial_cidr_overlap_returns_first_uncovered_address() {
        let workload = workload("worker", "worker.service", "1");
        let boundary = policy(
            workload.clone(),
            vec![capability(&workload, "half", &["203.0.113.0/25"], &[(443, 443)])],
        );
        let candidate = policy(
            workload.clone(),
            vec![capability(&workload, "full", &["203.0.113.0/24"], &[(443, 443)])],
        );
        let report = check_policy_within_boundary(&boundary, &candidate);
        assert_eq!(report.state, ContainmentState::Exceeds);
        assert_eq!(report.counterexamples[0].destination.as_deref(), Some("203.0.113.128"));
        assert_eq!(report.counterexamples[0].port, Some(443));
    }

    #[test]
    fn exhaustive_small_ipv4_subset_matches_set_inclusion_oracle() {
        let workload = workload("worker", "worker.service", "1");
        for boundary_mask in 1u8..16 {
            let boundary_values: Vec<String> = (0u32..4)
                .filter(|bit| boundary_mask & (1u8 << *bit) != 0)
                .map(|host| format!("198.18.0.{host}/32"))
                .collect();
            let boundary_refs: Vec<&str> = boundary_values.iter().map(String::as_str).collect();
            let boundary = policy(
                workload.clone(),
                vec![capability(&workload, "boundary", &boundary_refs, &[(443, 443)])],
            );

            for candidate_mask in 1u8..16 {
                let candidate_values: Vec<String> = (0u32..4)
                    .filter(|bit| candidate_mask & (1u8 << *bit) != 0)
                    .map(|host| format!("198.18.0.{host}/32"))
                    .collect();
                let candidate_refs: Vec<&str> =
                    candidate_values.iter().map(String::as_str).collect();
                let candidate = policy(
                    workload.clone(),
                    vec![capability(&workload, "candidate", &candidate_refs, &[(443, 443)])],
                );

                let expected_subset = candidate_mask & !boundary_mask == 0;
                let report = check_policy_within_boundary(&boundary, &candidate);
                assert_eq!(
                    report.state,
                    if expected_subset { ContainmentState::Within } else { ContainmentState::Exceeds },
                    "candidate mask {candidate_mask:04b}, boundary mask {boundary_mask:04b}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_small_port_subset_matches_set_inclusion_oracle() {
        let workload = workload("worker", "worker.service", "1");
        let cidrs = ["198.18.0.1/32"];
        for boundary_mask in 1u8..16 {
            let boundary_ports: Vec<(u16, u16)> = (0u32..4)
                .filter(|bit| boundary_mask & (1u8 << *bit) != 0)
                .map(|port| (1000u16 + port as u16, 1000u16 + port as u16))
                .collect();
            let boundary = policy(
                workload.clone(),
                vec![capability(&workload, "boundary", &cidrs, &boundary_ports)],
            );

            for candidate_mask in 1u8..16 {
                let candidate_ports: Vec<(u16, u16)> = (0u32..4)
                    .filter(|bit| candidate_mask & (1u8 << *bit) != 0)
                    .map(|port| (1000u16 + port as u16, 1000u16 + port as u16))
                    .collect();
                let candidate = policy(
                    workload.clone(),
                    vec![capability(&workload, "candidate", &cidrs, &candidate_ports)],
                );

                let expected_subset = candidate_mask & !boundary_mask == 0;
                let report = check_policy_within_boundary(&boundary, &candidate);
                assert_eq!(
                    report.state,
                    if expected_subset { ContainmentState::Within } else { ContainmentState::Exceeds },
                    "candidate port mask {candidate_mask:04b}, boundary mask {boundary_mask:04b}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_small_destination_port_product_matches_tuple_set_oracle() {
        let workload = workload("worker", "worker.service", "1");
        let addresses = ["198.18.0.1/32", "198.18.0.2/32"];
        let ports = [1000u16, 1001u16];

        for boundary_mask in 1u8..16 {
            let mut boundary_caps = Vec::new();
            for (address_index, address) in addresses.iter().enumerate() {
                for (port_index, port) in ports.iter().enumerate() {
                    let bit = (address_index * ports.len()) + port_index;
                    if boundary_mask & (1u8 << bit) != 0 {
                        boundary_caps.push(capability(
                            &workload,
                            &format!("boundary-{bit}"),
                            &[*address],
                            &[(*port, *port)],
                        ));
                    }
                }
            }
            let boundary = policy(workload.clone(), boundary_caps);

            for candidate_mask in 1u8..16 {
                let mut candidate_caps = Vec::new();
                for (address_index, address) in addresses.iter().enumerate() {
                    for (port_index, port) in ports.iter().enumerate() {
                        let bit = (address_index * ports.len()) + port_index;
                        if candidate_mask & (1u8 << bit) != 0 {
                            candidate_caps.push(capability(
                                &workload,
                                &format!("candidate-{bit}"),
                                &[*address],
                                &[(*port, *port)],
                            ));
                        }
                    }
                }
                let candidate = policy(workload.clone(), candidate_caps);
                let expected_subset = candidate_mask & !boundary_mask == 0;
                let report = check_policy_within_boundary(&boundary, &candidate);
                assert_eq!(
                    report.state,
                    if expected_subset { ContainmentState::Within } else { ContainmentState::Exceeds },
                    "candidate tuple mask {candidate_mask:04b}, boundary tuple mask {boundary_mask:04b}"
                );
            }
        }
    }

    #[test]
    fn report_never_claims_runtime_enforcement() {
        let workload = workload("worker", "worker.service", "1");
        let policy = policy(workload, vec![]);
        let report = check_policy_within_boundary(&policy, &policy);
        assert!(!report.runtime_enforcement_proven);
    }
}
