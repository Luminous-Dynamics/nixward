#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERIFIER_ID: &str = "nixward.network-observation-verifier";
pub const VERIFIER_VERSION: &str = "0.1.0";
pub const ENVELOPE_SCHEMA_ID: &str =
    "https://luminousdynamics.org/schemas/network-observation-envelope-v1.json";
pub const SUPPORTED_FAMILY: &str = "linux.rtnetlink.links.v1";
const HASH_RAW_DOMAIN: &[u8] = b"nixward.network-observation.raw-artifact.v1";
const HASH_SEMANTIC_DOMAIN: &[u8] = b"nixward.network-observation.link-semantics.v1";
const HASH_ENVELOPE_DOMAIN: &[u8] = b"nixward.network-observation.envelope.v1";
const HASH_RECEIPT_DOMAIN: &[u8] = b"nixward.network-observation.receipt.v1";
const HASH_POLICY_DOMAIN: &[u8] = b"nixward.network-observation.policy.v1";
const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
const NLMSG_HDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema_id: String,
    pub schema_version: u32,
    pub collection_id: String,
    pub target: TargetIdentity,
    pub scope: DeclaredScope,
    pub collector: CollectorIdentity,
    pub policy: VerificationPolicy,
    pub captured_at_unix_ms: u64,
    pub verification_time_unix_ms: u64,
    pub source_families: Vec<SourceFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetIdentity {
    pub target_id: String,
    pub boot_id: String,
    pub network_namespace_inode: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredScope {
    pub required_families: Vec<String>,
    pub resource_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorIdentity {
    pub collector_id: String,
    pub build_digest_blake3: String,
    pub source_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPolicy {
    pub policy_id: String,
    pub policy_version: String,
    pub max_age_ms: u64,
    pub max_source_window_ns: u64,
    pub max_total_raw_bytes: usize,
    pub max_messages_per_attempt: usize,
    pub max_objects_per_attempt: usize,
    pub max_retries: u32,
    pub decision_critical_link_attribute_ids: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFamily {
    pub family: String,
    pub attempts: Vec<SourceAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAttempt {
    pub target_id: String,
    pub boot_id: String,
    pub network_namespace_inode: u64,
    pub request_sequence: u32,
    pub byte_order: String,
    pub retry_index: u32,
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
    pub raw_artifact_hex: String,
    pub raw_artifact_blake3: String,
    pub canonical_semantic_blake3: Option<String>,
    pub enobufs_observed: bool,
    pub msg_trunc_observed: bool,
    pub dropped_message_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    CompleteForDeclaredScope,
    Incomplete,
    Unsupported,
    Invalid,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Integrity {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    Complete,
    Incomplete,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalCoherence {
    BoundedSingleSourceWindow,
    NotEstablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Freshness {
    Valid,
    Expired,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ownership {
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub verifier_id: String,
    pub verifier_version: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub verifier_source_revision: String,
    pub verifier_source_digest_blake3: String,
    pub envelope_raw_blake3: String,
    pub policy_digest_blake3: String,
    pub target: TargetIdentity,
    pub scope: DeclaredScope,
    pub policy_id: String,
    pub policy_version: String,
    pub integrity: Integrity,
    pub coverage: Coverage,
    pub temporal_coherence: TemporalCoherence,
    pub freshness: Freshness,
    pub ownership: Ownership,
    pub decision: Decision,
    pub accepted_source_count: usize,
    pub source_results: Vec<SourceReceipt>,
    pub reasons: Vec<String>,
    pub limitations: Vec<String>,
    pub global_atomic_snapshot_claimed: bool,
    pub production_mutation_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    pub family: String,
    pub status: String,
    pub attempts_seen: usize,
    pub accepted_retry_index: Option<u32>,
    pub observed_object_count: usize,
    pub identical_duplicate_count: usize,
    pub observed_links: Vec<LinkSummary>,
    pub raw_artifact_blake3: Vec<String>,
    pub canonical_semantic_blake3: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSummary {
    pub ifindex: i32,
    pub ifname: String,
    pub link_type: u16,
    pub flags: u32,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    pub receipt: ReceiptBody,
    pub receipt_blake3: String,
}

impl ReceiptEnvelope {
    /// Recompute the digest before serialization. A modified receipt cannot retain its old digest.
    pub fn serialize_checked(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(&self.receipt)
            .map_err(|error| format!("receipt serialization failed: {error}"))?;
        let expected = hash_domain(HASH_RECEIPT_DOMAIN, &bytes);
        if expected != self.receipt_blake3 {
            return Err("receipt digest does not match receipt payload".to_owned());
        }
        let mut output = serde_json::to_vec(self)
            .map_err(|error| format!("receipt envelope serialization failed: {error}"))?;
        output.push(b'\n');
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttemptStatus {
    Complete,
    Incomplete(String),
    Invalid(String),
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    ifindex: i32,
    ifname: String,
    link_type: u16,
    flags: u32,
    mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

struct ParsedDump {
    links: Vec<Link>,
    identical_duplicates: usize,
}

struct AttemptEvaluation {
    status: AttemptStatus,
    links: Vec<Link>,
    identical_duplicates: usize,
    canonical_digest: Option<String>,
}

pub fn hash_raw_artifact(bytes: &[u8]) -> String {
    hash_domain(HASH_RAW_DOMAIN, bytes)
}

pub fn hash_canonical_links(links: &[LinkSummary]) -> String {
    let mut sorted = links.to_vec();
    sorted.sort_by_key(|link| link.ifindex);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"NIXWARD-LINK-SEMANTICS-V1\0");
    preimage.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for link in &sorted {
        encode_link(
            &mut preimage,
            &Link {
                ifindex: link.ifindex,
                ifname: link.ifname.clone(),
                link_type: link.link_type,
                flags: link.flags,
                mtu: link.mtu,
            },
        );
    }
    hash_domain(HASH_SEMANTIC_DOMAIN, &preimage)
}

fn canonical_digest(links: &[Link]) -> String {
    let summaries: Vec<LinkSummary> = links.iter().map(LinkSummary::from).collect();
    hash_canonical_links(&summaries)
}

impl From<&Link> for LinkSummary {
    fn from(link: &Link) -> Self {
        Self {
            ifindex: link.ifindex,
            ifname: link.ifname.clone(),
            link_type: link.link_type,
            flags: link.flags,
            mtu: link.mtu,
        }
    }
}

fn encode_link(output: &mut Vec<u8>, link: &Link) {
    output.extend_from_slice(&link.ifindex.to_le_bytes());
    output.extend_from_slice(&(link.ifname.len() as u32).to_le_bytes());
    output.extend_from_slice(link.ifname.as_bytes());
    output.extend_from_slice(&link.link_type.to_le_bytes());
    output.extend_from_slice(&link.flags.to_le_bytes());
    match link.mtu {
        Some(mtu) => {
            output.push(1);
            output.extend_from_slice(&mtu.to_le_bytes());
        }
        None => output.push(0),
    }
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("raw_artifact_hex must have an even number of characters".to_owned());
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("raw_artifact_hex must use lowercase hexadecimal".to_owned());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(|| "invalid hex digit".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "invalid hex digit".to_owned())?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub fn verify_bytes(input: &[u8]) -> Result<ReceiptEnvelope, String> {
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(format!("envelope exceeds hard input limit of {MAX_ENVELOPE_BYTES} bytes"));
    }
    let envelope: Envelope = serde_json::from_slice(input)
        .map_err(|error| format!("invalid or nonconforming envelope JSON: {error}"))?;
    let envelope_digest = hash_domain(HASH_ENVELOPE_DOMAIN, input);
    let receipt = verify_envelope(&envelope, envelope_digest);
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| format!("receipt serialization failed: {error}"))?;
    let receipt_blake3 = hash_domain(HASH_RECEIPT_DOMAIN, &receipt_bytes);
    Ok(ReceiptEnvelope {
        receipt,
        receipt_blake3,
    })
}

fn verify_envelope(envelope: &Envelope, envelope_digest: String) -> ReceiptBody {
    let mut reasons = Vec::new();
    let mut integrity = Integrity::Valid;
    let mut coverage = Coverage::Incomplete;
    let mut freshness = Freshness::Valid;
    let mut temporal_coherence = TemporalCoherence::NotEstablished;
    let mut source_results = Vec::new();
    let mut total_raw_bytes = 0usize;
    let mut accepted_source_count = 0usize;
    let mut fatal_invalid = false;
    let mut unsupported = false;
    let mut every_required_source_complete = true;

    let target = envelope.target.clone();
    let scope = envelope.scope.clone();
    let policy_id = envelope.policy.policy_id.clone();
    let policy_version = envelope.policy.policy_version.clone();
    let policy_bytes = serde_json::to_vec(&envelope.policy).expect("typed policy serializes");
    let policy_digest_blake3 = hash_domain(HASH_POLICY_DOMAIN, &policy_bytes);
    let verifier_source_revision = option_env!("NIXWARD_VERIFIER_SOURCE_REVISION")
        .unwrap_or("unbound-build")
        .to_owned();
    let verifier_source_digest_blake3 = option_env!("NIXWARD_VERIFIER_SOURCE_DIGEST")
        .unwrap_or("build-source-digest-unavailable")
        .to_owned();

    if envelope.schema_id != ENVELOPE_SCHEMA_ID || envelope.schema_version != 1 {
        reasons.push("unsupported_or_mismatched_envelope_schema".to_owned());
        fatal_invalid = true;
    }
    if envelope.collection_id.trim().is_empty()
        || target.target_id.trim().is_empty()
        || target.boot_id.trim().is_empty()
        || target.network_namespace_inode == 0
        || envelope.collector.collector_id.trim().is_empty()
        || envelope.collector.source_revision.trim().is_empty()
        || !is_lower_hex_digest(&envelope.collector.build_digest_blake3)
        || policy_id.trim().is_empty()
        || policy_version.trim().is_empty()
    {
        reasons.push("missing_or_malformed_identity_field".to_owned());
        fatal_invalid = true;
    }
    if envelope.policy.max_age_ms == 0
        || envelope.policy.max_source_window_ns == 0
        || envelope.policy.max_total_raw_bytes == 0
        || envelope.policy.max_messages_per_attempt == 0
        || envelope.policy.max_objects_per_attempt == 0
    {
        reasons.push("invalid_zero_valued_verification_bound".to_owned());
        fatal_invalid = true;
    }
    let mut required_families = BTreeSet::new();
    for family in &scope.required_families {
        if family.trim().is_empty() || !required_families.insert(family.clone()) {
            reasons.push("empty_or_duplicate_required_family".to_owned());
            fatal_invalid = true;
        }
    }
    let mut resource_kinds = BTreeSet::new();
    for kind in &scope.resource_kinds {
        if kind.trim().is_empty() || !resource_kinds.insert(kind.clone()) {
            reasons.push("empty_or_duplicate_resource_kind".to_owned());
            fatal_invalid = true;
        }
    }
    if scope.resource_kinds.iter().any(|kind| kind != "links") {
        reasons.push("resource_kind_outside_m1a_supported_profile".to_owned());
        unsupported = true;
    }
    let critical_ids: BTreeSet<u16> = envelope
        .policy
        .decision_critical_link_attribute_ids
        .iter()
        .copied()
        .collect();
    if critical_ids.len() != envelope.policy.decision_critical_link_attribute_ids.len()
        || critical_ids.contains(&IFLA_IFNAME)
        || critical_ids.contains(&IFLA_MTU)
    {
        reasons.push("contradictory_or_duplicate_critical_attribute_policy".to_owned());
        fatal_invalid = true;
    }
    if envelope.verification_time_unix_ms < envelope.captured_at_unix_ms {
        reasons.push("verification_time_precedes_capture_time".to_owned());
        freshness = Freshness::Invalid;
        fatal_invalid = true;
    } else if envelope
        .verification_time_unix_ms
        .saturating_sub(envelope.captured_at_unix_ms)
        > envelope.policy.max_age_ms
    {
        reasons.push("evidence_expired_under_supplied_policy_clock".to_owned());
        freshness = Freshness::Expired;
    }
    if required_families.is_empty() {
        reasons.push("no_required_family_declared".to_owned());
        fatal_invalid = true;
    }
    if envelope.source_families.len() != required_families.len() {
        reasons.push("source_family_count_does_not_match_declared_scope".to_owned());
        every_required_source_complete = false;
    }
    if required_families.len() == 1
        && required_families.contains(SUPPORTED_FAMILY)
        && envelope.source_families.len() == 1
    {
        temporal_coherence = TemporalCoherence::BoundedSingleSourceWindow;
    } else if !required_families.is_empty() {
        reasons.push("cross_source_temporal_coherence_not_established".to_owned());
    }

    let mut seen_families = BTreeSet::new();
    for source in &envelope.source_families {
        let mut source_reasons = Vec::new();
        let mut source_status = "incomplete".to_owned();
        let mut accepted_retry_index = None;
        let mut final_links = Vec::new();
        let mut final_duplicate_count = 0usize;
        let mut accepted_canonical = None;
        let mut raw_digests = Vec::new();

        if !seen_families.insert(source.family.clone()) {
            source_reasons.push("duplicate_source_family".to_owned());
            fatal_invalid = true;
            source_status = "invalid".to_owned();
        }
        if !required_families.contains(&source.family) {
            source_reasons.push("unrequested_source_family_in_envelope".to_owned());
            fatal_invalid = true;
            source_status = "invalid".to_owned();
        }
        if source.family != SUPPORTED_FAMILY {
            source_reasons.push("source_family_not_implemented_by_m1a_verifier".to_owned());
            unsupported = true;
            every_required_source_complete = false;
            if source_status != "invalid" {
                source_status = "unsupported".to_owned();
            }
        }
        if source.attempts.is_empty() {
            source_reasons.push("required_source_has_no_attempts".to_owned());
            every_required_source_complete = false;
        }
        if source.attempts.len() > envelope.policy.max_retries as usize + 1 {
            source_reasons.push("retry_budget_exceeded".to_owned());
            every_required_source_complete = false;
        }

        let mut attempt_evaluations = Vec::new();
        let mut sequences = BTreeSet::new();
        for (position, attempt) in source.attempts.iter().enumerate() {
            let mut attempt_metadata_invalid = false;
            if attempt.retry_index != position as u32 {
                source_reasons.push("retry_indices_not_contiguous_from_zero".to_owned());
                fatal_invalid = true;
                attempt_metadata_invalid = true;
            }
            if attempt.request_sequence == 0 || !sequences.insert(attempt.request_sequence) {
                source_reasons.push("zero_or_duplicate_request_sequence".to_owned());
                fatal_invalid = true;
                attempt_metadata_invalid = true;
            }
            if attempt.target_id != target.target_id
                || attempt.boot_id != target.boot_id
                || attempt.network_namespace_inode != target.network_namespace_inode
            {
                source_reasons.push("source_target_boot_or_namespace_mismatch".to_owned());
                fatal_invalid = true;
                attempt_metadata_invalid = true;
            }
            if attempt.ended_monotonic_ns < attempt.started_monotonic_ns
                || attempt
                    .ended_monotonic_ns
                    .saturating_sub(attempt.started_monotonic_ns)
                    > envelope.policy.max_source_window_ns
            {
                source_reasons.push("invalid_or_excessive_source_time_window".to_owned());
                fatal_invalid = true;
                attempt_metadata_invalid = true;
            }
            let raw = match decode_hex(&attempt.raw_artifact_hex) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    source_reasons.push(reason);
                    fatal_invalid = true;
                    Vec::new()
                }
            };
            total_raw_bytes = total_raw_bytes.saturating_add(raw.len());
            let raw_digest = hash_raw_artifact(&raw);
            raw_digests.push(raw_digest.clone());
            if !is_lower_hex_digest(&attempt.raw_artifact_blake3)
                || attempt.raw_artifact_blake3 != raw_digest
            {
                source_reasons.push("raw_artifact_digest_mismatch".to_owned());
                fatal_invalid = true;
                attempt_evaluations.push(AttemptEvaluation {
                    status: AttemptStatus::Invalid("raw_artifact_digest_mismatch".to_owned()),
                    links: Vec::new(),
                    identical_duplicates: 0,
                    canonical_digest: None,
                });
                continue;
            }
            if attempt_metadata_invalid {
                attempt_evaluations.push(AttemptEvaluation {
                    status: AttemptStatus::Invalid("attempt_metadata_invalid".to_owned()),
                    links: Vec::new(),
                    identical_duplicates: 0,
                    canonical_digest: None,
                });
                continue;
            }
            if raw.is_empty() || raw.len() > envelope.policy.max_total_raw_bytes {
                source_reasons.push("empty_or_oversized_raw_artifact".to_owned());
                every_required_source_complete = false;
                attempt_evaluations.push(AttemptEvaluation {
                    status: AttemptStatus::Incomplete("empty_or_oversized_raw_artifact".to_owned()),
                    links: Vec::new(),
                    identical_duplicates: 0,
                    canonical_digest: None,
                });
                continue;
            }
            if source.family != SUPPORTED_FAMILY {
                attempt_evaluations.push(AttemptEvaluation {
                    status: AttemptStatus::Unsupported("source_family_not_implemented_by_m1a_verifier".to_owned()),
                    links: Vec::new(),
                    identical_duplicates: 0,
                    canonical_digest: None,
                });
                continue;
            }
            if attempt.byte_order != "little" && attempt.byte_order != "big" {
                source_reasons.push("unsupported_byte_order_marker".to_owned());
                unsupported = true;
                attempt_evaluations.push(AttemptEvaluation {
                    status: AttemptStatus::Unsupported("unsupported_byte_order_marker".to_owned()),
                    links: Vec::new(),
                    identical_duplicates: 0,
                    canonical_digest: None,
                });
                continue;
            }
            let byte_order = if attempt.byte_order == "little" {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            };
            let parsed = parse_link_dump(
                &raw,
                attempt.request_sequence,
                byte_order,
                envelope.policy.max_messages_per_attempt,
                envelope.policy.max_objects_per_attempt,
                &critical_ids,
            );
            let evaluation = match parsed {
                Ok(parsed) => {
                    let digest = canonical_digest(&parsed.links);
                    if attempt
                        .canonical_semantic_blake3
                        .as_deref()
                        .is_none_or(|expected| !is_lower_hex_digest(expected) || expected != digest.as_str())
                    {
                        source_reasons.push("canonical_semantic_digest_mismatch_or_missing".to_owned());
                        fatal_invalid = true;
                        AttemptEvaluation {
                            status: AttemptStatus::Invalid(
                                "canonical_semantic_digest_mismatch_or_missing".to_owned(),
                            ),
                            links: parsed.links,
                            identical_duplicates: parsed.identical_duplicates,
                            canonical_digest: Some(digest),
                        }
                    } else if attempt.enobufs_observed
                        || attempt.msg_trunc_observed
                        || attempt.dropped_message_count > 0
                    {
                        source_reasons.push("transport_loss_or_truncation_observed".to_owned());
                        AttemptEvaluation {
                            status: AttemptStatus::Incomplete(
                                "transport_loss_or_truncation_observed".to_owned(),
                            ),
                            links: parsed.links,
                            identical_duplicates: parsed.identical_duplicates,
                            canonical_digest: Some(digest),
                        }
                    } else {
                        AttemptEvaluation {
                            status: AttemptStatus::Complete,
                            links: parsed.links,
                            identical_duplicates: parsed.identical_duplicates,
                            canonical_digest: Some(digest),
                        }
                    }
                }
                Err(AttemptStatus::Incomplete(reason)) => {
                    source_reasons.push(format!("attempt_retry_{}_incomplete:{reason}", attempt.retry_index));
                    AttemptEvaluation {
                        status: AttemptStatus::Incomplete(reason),
                        links: Vec::new(),
                        identical_duplicates: 0,
                        canonical_digest: None,
                    }
                },
                Err(AttemptStatus::Invalid(reason)) => {
                    source_reasons.push(reason.clone());
                    fatal_invalid = true;
                    AttemptEvaluation {
                        status: AttemptStatus::Invalid(reason),
                        links: Vec::new(),
                        identical_duplicates: 0,
                        canonical_digest: None,
                    }
                }
                Err(AttemptStatus::Unsupported(reason)) => {
                    source_reasons.push(reason.clone());
                    unsupported = true;
                    AttemptEvaluation {
                        status: AttemptStatus::Unsupported(reason),
                        links: Vec::new(),
                        identical_duplicates: 0,
                        canonical_digest: None,
                    }
                }
                Err(AttemptStatus::Complete) => unreachable!("parser never returns Complete as an error"),
            };
            // A retry may recover an incomplete attempt; it cannot erase invalid evidence.
            if matches!(&evaluation.status, AttemptStatus::Invalid(_)) {
                fatal_invalid = true;
            }
            if matches!(&evaluation.status, AttemptStatus::Unsupported(_)) {
                unsupported = true;
            }
            attempt_evaluations.push(evaluation);
        }

        let total_limit_exceeded = total_raw_bytes > envelope.policy.max_total_raw_bytes;
        if total_limit_exceeded {
            source_reasons.push("total_raw_artifact_byte_limit_exceeded".to_owned());
            every_required_source_complete = false;
        }
        if attempt_evaluations.iter().any(|result| matches!(&result.status, AttemptStatus::Invalid(_))) {
            source_status = "invalid".to_owned();
            every_required_source_complete = false;
        } else if attempt_evaluations.iter().any(|result| matches!(&result.status, AttemptStatus::Unsupported(_))) {
            source_status = "unsupported".to_owned();
            every_required_source_complete = false;
        } else if let Some(last) = attempt_evaluations.last() {
            match &last.status {
                AttemptStatus::Complete => {
                    if source.attempts.len() > envelope.policy.max_retries as usize + 1 {
                        source_status = "incomplete".to_owned();
                        every_required_source_complete = false;
                    } else if source.attempts.len() != attempt_evaluations.len() {
                        source_status = "invalid".to_owned();
                        fatal_invalid = true;
                        every_required_source_complete = false;
                    } else if attempt_evaluations[..attempt_evaluations.len() - 1]
                        .iter()
                        .any(|result| matches!(&result.status, AttemptStatus::Complete))
                    {
                        source_reasons.push("unnecessary_attempt_after_completed_dump".to_owned());
                        source_status = "invalid".to_owned();
                        fatal_invalid = true;
                        every_required_source_complete = false;
                    } else {
                        source_status = "complete".to_owned();
                        accepted_retry_index = source.attempts.last().map(|attempt| attempt.retry_index);
                        final_links = last.links.clone();
                        final_duplicate_count = last.identical_duplicates;
                        accepted_canonical = last.canonical_digest.clone();
                        accepted_source_count += 1;
                    }
                }
                AttemptStatus::Incomplete(reason) => {
                    source_reasons.push(format!("final_attempt_incomplete:{reason}"));
                    source_status = "incomplete".to_owned();
                    every_required_source_complete = false;
                }
                AttemptStatus::Invalid(reason) => {
                    source_reasons.push(format!("final_attempt_invalid:{reason}"));
                    source_status = "invalid".to_owned();
                    fatal_invalid = true;
                    every_required_source_complete = false;
                }
                AttemptStatus::Unsupported(reason) => {
                    source_reasons.push(format!("final_attempt_unsupported:{reason}"));
                    source_status = "unsupported".to_owned();
                    unsupported = true;
                    every_required_source_complete = false;
                }
            }
        } else {
            source_status = "incomplete".to_owned();
            every_required_source_complete = false;
        }

        if total_limit_exceeded && source_status == "complete" {
            source_reasons.push("total_raw_artifact_byte_limit_exceeded".to_owned());
            source_status = "incomplete".to_owned();
            accepted_retry_index = None;
            final_links.clear();
            final_duplicate_count = 0;
            accepted_canonical = None;
            accepted_source_count = accepted_source_count.saturating_sub(1);
            every_required_source_complete = false;
        }
        if source_status != "complete" {
            every_required_source_complete = false;
        }
        source_results.push(SourceReceipt {
            family: source.family.clone(),
            status: source_status,
            attempts_seen: source.attempts.len(),
            accepted_retry_index,
            observed_object_count: final_links.len(),
            identical_duplicate_count: final_duplicate_count,
            observed_links: final_links.iter().map(LinkSummary::from).collect(),
            raw_artifact_blake3: raw_digests,
            canonical_semantic_blake3: accepted_canonical,
            reasons: source_reasons,
        });
    }

    if total_raw_bytes > envelope.policy.max_total_raw_bytes {
        reasons.push("total_raw_artifact_byte_limit_exceeded".to_owned());
        every_required_source_complete = false;
    }
    if seen_families != required_families {
        reasons.push("required_source_family_missing_or_unexpected".to_owned());
        every_required_source_complete = false;
    }
    if required_families.len() != 1
        || !required_families.contains(SUPPORTED_FAMILY)
        || source_results.len() != 1
    {
        reasons.push("m1a_requires_one_supported_link_source; cross-source coherence is not proven".to_owned());
        every_required_source_complete = false;
        if required_families.iter().any(|family| family != SUPPORTED_FAMILY) {
            unsupported = true;
        }
        temporal_coherence = TemporalCoherence::NotEstablished;
    }
    if envelope.source_families.iter().any(|source| {
        source.family == SUPPORTED_FAMILY && source.attempts.len() > 1
    }) {
        reasons.push("bounded_retry_history_present; only the final complete attempt is used".to_owned());
    }

    if fatal_invalid {
        integrity = Integrity::Invalid;
        coverage = Coverage::Incomplete;
    } else if unsupported {
        coverage = Coverage::Unsupported;
    } else if every_required_source_complete {
        coverage = Coverage::Complete;
    } else {
        coverage = Coverage::Incomplete;
    }

    let decision = if fatal_invalid || freshness == Freshness::Invalid {
        Decision::Invalid
    } else if unsupported {
        Decision::Unsupported
    } else if coverage != Coverage::Complete {
        Decision::Incomplete
    } else if freshness == Freshness::Expired {
        Decision::Expired
    } else {
        Decision::CompleteForDeclaredScope
    };

    if integrity == Integrity::Invalid && !reasons.iter().any(|reason| reason.contains("invalid")) {
        reasons.push("one_or_more_integrity_checks_failed".to_owned());
    }
    if decision != Decision::CompleteForDeclaredScope && reasons.is_empty() {
        reasons.push("evidence_did_not_satisfy_acceptance_policy".to_owned());
    }
    ReceiptBody {
        verifier_id: VERIFIER_ID.to_owned(),
        verifier_version: VERIFIER_VERSION.to_owned(),
        rustc_version: option_env!("NIXWARD_VERIFIER_RUSTC_VERSION")
            .unwrap_or("toolchain-version-unavailable")
            .to_owned(),
        cargo_version: option_env!("NIXWARD_VERIFIER_CARGO_VERSION")
            .unwrap_or("toolchain-version-unavailable")
            .to_owned(),
        target_os: option_env!("NIXWARD_VERIFIER_TARGET_OS")
            .unwrap_or("target-os-unavailable")
            .to_owned(),
        target_arch: option_env!("NIXWARD_VERIFIER_TARGET_ARCH")
            .unwrap_or("target-arch-unavailable")
            .to_owned(),
        verifier_source_revision,
        verifier_source_digest_blake3,
        envelope_raw_blake3: envelope_digest,
        policy_digest_blake3,
        target,
        scope,
        policy_id,
        policy_version,
        integrity,
        coverage,
        temporal_coherence,
        freshness,
        ownership: Ownership::Unknown,
        decision,
        accepted_source_count,
        source_results,
        reasons,
        limitations: vec![
            "M1a implements only the linux.rtnetlink.links.v1 profile; other families are unsupported.".to_owned(),
            "A byte digest establishes identity relative to the supplied bytes, not origin authenticity or truth.".to_owned(),
            "Collector-reported loss/truncation metadata can fail closed but is not independently authenticated.".to_owned(),
            "The verifier parses supplied evidence only; it opens no sockets and does not verify live kernel or namespace identity.".to_owned(),
            "Temporal result is a bounded single-source observation window, not a global atomic network snapshot.".to_owned(),
            "Ownership is Unknown: a link dump does not establish the configuration/runtime writer.".to_owned(),
            "No signature or protected local provenance is established by this receipt.".to_owned(),
            "The verifier source digest identifies the pinned source/schema bundle used at build time; it is not a measured executable binary hash.".to_owned(),
            "The rustc/Cargo versions and target triple are recorded build metadata; they do not attest to the integrity of the build host.".to_owned(),
        ],
        global_atomic_snapshot_claimed: false,
        production_mutation_enabled: false,
    }
}

fn parse_link_dump(
    bytes: &[u8],
    expected_sequence: u32,
    byte_order: ByteOrder,
    max_messages: usize,
    max_objects: usize,
    critical_ids: &BTreeSet<u16>,
) -> Result<ParsedDump, AttemptStatus> {
    if bytes.is_empty() {
        return Err(AttemptStatus::Incomplete("empty_receive_without_terminal_signal".to_owned()));
    }
    if expected_sequence == 0 {
        return Err(AttemptStatus::Invalid("zero_request_sequence".to_owned()));
    }
    let mut offset = 0usize;
    let mut message_count = 0usize;
    let mut object_count = 0usize;
    let mut terminal_seen = false;
    let mut links: BTreeMap<i32, Link> = BTreeMap::new();
    let mut identical_duplicates = 0usize;
    let mut interrupted = false;

    while offset < bytes.len() {
        if terminal_seen {
            return Err(AttemptStatus::Invalid("message_bytes_after_terminal_signal".to_owned()));
        }
        if bytes.len().saturating_sub(offset) < NLMSG_HDR_LEN {
            return Err(AttemptStatus::Invalid("trailing_partial_netlink_header".to_owned()));
        }
        message_count += 1;
        if message_count > max_messages {
            return Err(AttemptStatus::Incomplete("message_count_limit_exceeded".to_owned()));
        }
        let message_len = read_u32(&bytes[offset..offset + 4], byte_order) as usize;
        let message_type = read_u16(&bytes[offset + 4..offset + 6], byte_order);
        let flags = read_u16(&bytes[offset + 6..offset + 8], byte_order);
        let sequence = read_u32(&bytes[offset + 8..offset + 12], byte_order);
        if message_len < NLMSG_HDR_LEN {
            return Err(AttemptStatus::Invalid("netlink_message_length_below_header_size".to_owned()));
        }
        if message_len > bytes.len().saturating_sub(offset) {
            return Err(AttemptStatus::Invalid("netlink_message_length_exceeds_artifact".to_owned()));
        }
        if align4(message_len) > bytes.len().saturating_sub(offset) {
            return Err(AttemptStatus::Invalid("netlink_message_alignment_exceeds_artifact".to_owned()));
        }
        if sequence != expected_sequence {
            return Err(AttemptStatus::Invalid("unexpected_netlink_request_sequence".to_owned()));
        }
        if flags & NLM_F_DUMP_INTR != 0 {
            interrupted = true;
        }
        let payload_start = offset + NLMSG_HDR_LEN;
        let payload_end = offset + message_len;
        match message_type {
            NLMSG_DONE => {
                let payload = &bytes[payload_start..payload_end];
                if payload.len() < 4 {
                    return Err(AttemptStatus::Incomplete(
                        "terminal_signal_missing_status_payload".to_owned(),
                    ));
                }
                let status = read_i32(payload, byte_order);
                if status != 0 {
                    return Err(AttemptStatus::Incomplete(format!(
                        "negative_or_nonzero_dump_completion_status:{status}"
                    )));
                }
                terminal_seen = true;
            }
            NLMSG_ERROR => {
                let payload = &bytes[payload_start..payload_end];
                if payload.len() < 4 {
                    return Err(AttemptStatus::Incomplete("malformed_nlmsg_error_payload".to_owned()));
                }
                let error = read_i32(payload, byte_order);
                return Err(AttemptStatus::Incomplete(format!(
                    "nlmsg_error_received:{error}"
                )));
            }
            RTM_NEWLINK => {
                if terminal_seen {
                    return Err(AttemptStatus::Invalid("link_object_after_terminal_signal".to_owned()));
                }
                object_count += 1;
                if object_count > max_objects {
                    return Err(AttemptStatus::Incomplete("object_count_limit_exceeded".to_owned()));
                }
                let payload = &bytes[payload_start..payload_end];
                let link = parse_link_message(payload, byte_order, critical_ids)?;
                match links.get(&link.ifindex) {
                    Some(previous) if previous == &link => {
                        identical_duplicates += 1;
                    }
                    Some(_) => {
                        return Err(AttemptStatus::Invalid(
                            "conflicting_duplicate_link_identity".to_owned(),
                        ));
                    }
                    None => {
                        links.insert(link.ifindex, link);
                    }
                }
            }
            other => {
                return Err(AttemptStatus::Unsupported(format!(
                    "unexpected_message_type_for_link_dump:{other}"
                )));
            }
        }
        offset += align4(message_len);
    }

    if interrupted {
        return Err(AttemptStatus::Incomplete("nlm_f_dump_intr_observed".to_owned()));
    }
    if !terminal_seen {
        return Err(AttemptStatus::Incomplete("missing_nlmsg_done_terminal_signal".to_owned()));
    }
    let mut by_name = BTreeSet::new();
    if links.values().any(|link| !by_name.insert(link.ifname.clone())) {
        return Err(AttemptStatus::Invalid(
            "duplicate_interface_name_with_distinct_ifindex".to_owned(),
        ));
    }
    Ok(ParsedDump {
        links: links.into_values().collect(),
        identical_duplicates,
    })
}

fn parse_link_message(
    payload: &[u8],
    byte_order: ByteOrder,
    critical_ids: &BTreeSet<u16>,
) -> Result<Link, AttemptStatus> {
    if payload.len() < IFINFOMSG_LEN {
        return Err(AttemptStatus::Invalid("short_ifinfomsg_payload".to_owned()));
    }
    let link_type = read_u16(&payload[2..4], byte_order);
    let ifindex = read_i32(&payload[4..8], byte_order);
    let flags = read_u32(&payload[8..12], byte_order);
    if ifindex <= 0 {
        return Err(AttemptStatus::Invalid("nonpositive_interface_index".to_owned()));
    }
    let mut ifname: Option<String> = None;
    let mut mtu: Option<u32> = None;
    let mut seen_attributes = BTreeSet::new();
    let attributes = &payload[IFINFOMSG_LEN..];
    let mut offset = 0usize;
    while offset < attributes.len() {
        if attributes.len() - offset < 4 {
            return Err(AttemptStatus::Invalid("partial_rtattr_header".to_owned()));
        }
        let attr_len = read_u16(&attributes[offset..offset + 2], byte_order) as usize;
        let raw_type = read_u16(&attributes[offset + 2..offset + 4], byte_order);
        let attr_type = raw_type & NLA_TYPE_MASK;
        if attr_len < 4 {
            return Err(AttemptStatus::Invalid("rtattr_length_below_header_size".to_owned()));
        }
        if attr_len > attributes.len() - offset {
            return Err(AttemptStatus::Invalid("rtattr_length_exceeds_ifinfomsg".to_owned()));
        }
        let aligned_len = align4(attr_len);
        if aligned_len > attributes.len() - offset {
            return Err(AttemptStatus::Invalid("rtattr_alignment_exceeds_ifinfomsg".to_owned()));
        }
        if !seen_attributes.insert(attr_type) {
            return Err(AttemptStatus::Invalid("duplicate_link_attribute".to_owned()));
        }
        let value = &attributes[offset + 4..offset + attr_len];
        match attr_type {
            IFLA_IFNAME => {
                if value.is_empty() || value.last() != Some(&0) || value[..value.len() - 1].contains(&0) {
                    return Err(AttemptStatus::Invalid("ifla_ifname_not_single_nul_terminated".to_owned()));
                }
                let text = std::str::from_utf8(&value[..value.len() - 1])
                    .map_err(|_| AttemptStatus::Invalid("ifla_ifname_not_utf8".to_owned()))?;
                if text.is_empty() || text.trim().is_empty() {
                    return Err(AttemptStatus::Invalid("empty_ifla_ifname".to_owned()));
                }
                ifname = Some(text.to_owned());
            }
            IFLA_MTU => {
                if value.len() != 4 {
                    return Err(AttemptStatus::Invalid("ifla_mtu_wrong_width".to_owned()));
                }
                mtu = Some(read_u32(value, byte_order));
            }
            IFLA_ADDRESS => {
                // Address bytes remain bound by the exact raw-artifact digest. This M1a
                // semantic profile does not interpret address families or validate them.
                if critical_ids.contains(&IFLA_ADDRESS) {
                    return Err(AttemptStatus::Unsupported(
                        "decision_critical_address_attribute_not_semantically_supported".to_owned(),
                    ));
                }
            }
            other => {
                if critical_ids.contains(&other) {
                    return Err(AttemptStatus::Unsupported(format!(
                        "unknown_decision_critical_link_attribute:{other}"
                    )));
                }
                // Noncritical attributes remain in the exact raw artifact, but do not
                // contribute to this profile's canonical semantic projection.
            }
        }
        offset += aligned_len;
    }
    let ifname = ifname.ok_or_else(|| {
        AttemptStatus::Incomplete("required_ifla_ifname_attribute_missing".to_owned())
    })?;
    Ok(Link {
        ifindex,
        ifname,
        link_type,
        flags,
        mtu,
    })
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn read_u16(bytes: &[u8], byte_order: ByteOrder) -> u16 {
    let value = [bytes[0], bytes[1]];
    match byte_order {
        ByteOrder::Little => u16::from_le_bytes(value),
        ByteOrder::Big => u16::from_be_bytes(value),
    }
}

fn read_u32(bytes: &[u8], byte_order: ByteOrder) -> u32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match byte_order {
        ByteOrder::Little => u32::from_le_bytes(value),
        ByteOrder::Big => u32::from_be_bytes(value),
    }
}

fn read_i32(bytes: &[u8], byte_order: ByteOrder) -> i32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match byte_order {
        ByteOrder::Little => i32::from_le_bytes(value),
        ByteOrder::Big => i32::from_be_bytes(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pad4(bytes: &mut Vec<u8>) {
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
    }

    fn encode_u16(value: u16) -> [u8; 2] {
        value.to_le_bytes()
    }

    fn encode_u32(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    fn encode_i32(value: i32) -> [u8; 4] {
        value.to_le_bytes()
    }

    fn message(message_type: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let length = (NLMSG_HDR_LEN + payload.len()) as u32;
        bytes.extend_from_slice(&encode_u32(length));
        bytes.extend_from_slice(&encode_u16(message_type));
        bytes.extend_from_slice(&encode_u16(flags));
        bytes.extend_from_slice(&encode_u32(sequence));
        bytes.extend_from_slice(&encode_u32(0));
        bytes.extend_from_slice(payload);
        pad4(&mut bytes);
        bytes
    }

    fn done(sequence: u32, status: i32, flags: u16) -> Vec<u8> {
        message(NLMSG_DONE, flags, sequence, &encode_i32(status))
    }

    fn link_message(index: i32, name: &str, mtu: Option<u32>, flags: u16, sequence: u32) -> Vec<u8> {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&encode_u16(1)); // ARPHRD_ETHER for the fixture only.
        payload.extend_from_slice(&encode_i32(index));
        payload.extend_from_slice(&encode_u32(0x1 | 0x40)); // IFF_UP | IFF_RUNNING
        payload.extend_from_slice(&encode_u32(u32::MAX)); // change mask
        let mut name_value = name.as_bytes().to_vec();
        name_value.push(0);
        push_attr(&mut payload, IFLA_IFNAME, &name_value);
        if let Some(mtu) = mtu {
            push_attr(&mut payload, IFLA_MTU, &encode_u32(mtu));
        }
        message(RTM_NEWLINK, flags, sequence, &payload)
    }

    fn push_attr(payload: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        let length = (4 + value.len()) as u16;
        payload.extend_from_slice(&encode_u16(length));
        payload.extend_from_slice(&encode_u16(attr_type));
        payload.extend_from_slice(value);
        pad4(payload);
    }

    fn raw_join(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flat_map(|part| part.iter().copied()).collect()
    }

    fn attempt(raw: &[u8], sequence: u32, retry_index: u32) -> SourceAttempt {
        let mut attempt = SourceAttempt {
            target_id: "lab-router-a".to_owned(),
            boot_id: "boot-fixture-001".to_owned(),
            network_namespace_inode: 4026533001,
            request_sequence: sequence,
            byte_order: "little".to_owned(),
            retry_index,
            started_monotonic_ns: 100,
            ended_monotonic_ns: 200,
            raw_artifact_hex: raw.iter().map(|byte| format!("{byte:02x}")).collect(),
            raw_artifact_blake3: hash_raw_artifact(raw),
            canonical_semantic_blake3: None,
            enobufs_observed: false,
            msg_trunc_observed: false,
            dropped_message_count: 0,
        };
        if let Ok(parsed) = parse_link_dump(raw, sequence, ByteOrder::Little, 128, 128, &BTreeSet::from([5, 999])) {
            attempt.canonical_semantic_blake3 = Some(canonical_digest(&parsed.links));
        }
        attempt
    }

    fn envelope_with(raw_attempts: Vec<SourceAttempt>) -> Envelope {
        Envelope {
            schema_id: ENVELOPE_SCHEMA_ID.to_owned(),
            schema_version: 1,
            collection_id: "fixture-collection-0001".to_owned(),
            target: TargetIdentity {
                target_id: "lab-router-a".to_owned(),
                boot_id: "boot-fixture-001".to_owned(),
                network_namespace_inode: 4026533001,
            },
            scope: DeclaredScope {
                required_families: vec![SUPPORTED_FAMILY.to_owned()],
                resource_kinds: vec!["links".to_owned()],
            },
            collector: CollectorIdentity {
                collector_id: "fixture-collector".to_owned(),
                build_digest_blake3: "a".repeat(64),
                source_revision: "fixture-revision".to_owned(),
            },
            policy: VerificationPolicy {
                policy_id: "m1a-rtnetlink-links".to_owned(),
                policy_version: "1".to_owned(),
                max_age_ms: 60_000,
                max_source_window_ns: 10_000,
                max_total_raw_bytes: 65_536,
                max_messages_per_attempt: 128,
                max_objects_per_attempt: 64,
                max_retries: 2,
                decision_critical_link_attribute_ids: vec![5, 999],
            },
            captured_at_unix_ms: 1_000_000,
            verification_time_unix_ms: 1_000_500,
            source_families: vec![SourceFamily {
                family: SUPPORTED_FAMILY.to_owned(),
                attempts: raw_attempts,
            }],
        }
    }

    fn verify_envelope_for_test(envelope: &Envelope) -> ReceiptEnvelope {
        let bytes = serde_json::to_vec(envelope).expect("fixture serializes");
        verify_bytes(&bytes).expect("fixture envelope is well-formed JSON")
    }

    fn link_and_done(name: &str) -> Vec<u8> {
        raw_join(&[
            link_message(2, name, Some(1500), NLM_F_MULTI, 7),
            done(7, 0, NLM_F_MULTI),
        ])
    }

    #[test]
    fn valid_empty_inventory_requires_and_accepts_terminal_marker() {
        let envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::CompleteForDeclaredScope);
        assert_eq!(receipt.receipt.source_results[0].observed_object_count, 0);
        assert_eq!(receipt.receipt.ownership, Ownership::Unknown);
        assert!(!receipt.receipt.global_atomic_snapshot_claimed);
    }

    #[test]
    fn valid_single_link_is_parsed_from_raw_message_bytes() {
        let envelope = envelope_with(vec![attempt(&link_and_done("eth0"), 7, 0)]);
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::CompleteForDeclaredScope);
        assert_eq!(
            receipt.receipt.source_results[0].observed_links[0],
            LinkSummary {
                ifindex: 2,
                ifname: "eth0".to_owned(),
                link_type: 1,
                flags: 0x41,
                mtu: Some(1500),
            }
        );
    }

    #[test]
    fn missing_terminal_marker_is_incomplete_not_empty() {
        let raw = link_message(2, "eth0", None, NLM_F_MULTI, 7);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
        assert!(receipt.receipt.reasons.iter().any(|reason| reason.contains("missing_nlmsg_done")));
    }

    #[test]
    fn interrupted_intermediate_message_is_incomplete() {
        let raw = raw_join(&[
            link_message(2, "eth0", None, NLM_F_MULTI | NLM_F_DUMP_INTR, 7),
            done(7, 0, NLM_F_MULTI),
        ]);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
        assert!(receipt.receipt.source_results[0].reasons.is_empty() || receipt.receipt.source_results[0].status == "incomplete");
    }

    #[test]
    fn interrupted_terminal_message_is_incomplete() {
        let raw = done(7, 0, NLM_F_MULTI | NLM_F_DUMP_INTR);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn error_message_cannot_establish_completeness() {
        let error = message(NLMSG_ERROR, 0, 7, &encode_i32(-105));
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&error, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn negative_terminal_status_is_incomplete() {
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&done(7, -5, NLM_F_MULTI), 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn wrong_request_sequence_is_invalid() {
        let raw = done(8, 0, NLM_F_MULTI);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
        assert_eq!(receipt.receipt.integrity, Integrity::Invalid);
    }

    #[test]
    fn malformed_short_message_header_is_invalid() {
        let mut raw = vec![0; 16];
        raw[..4].copy_from_slice(&encode_u32(3));
        raw[4..6].copy_from_slice(&encode_u16(NLMSG_DONE));
        raw[8..12].copy_from_slice(&encode_u32(7));
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn external_receive_truncation_blocks_acceptance() {
        let raw = done(7, 0, NLM_F_MULTI);
        let mut item = attempt(&raw, 7, 0);
        item.msg_trunc_observed = true;
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn enobufs_or_drop_counter_blocks_acceptance() {
        let raw = done(7, 0, NLM_F_MULTI);
        let mut item = attempt(&raw, 7, 0);
        item.enobufs_observed = true;
        item.dropped_message_count = 1;
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn tampered_raw_artifact_digest_is_invalid() {
        let raw = done(7, 0, NLM_F_MULTI);
        let mut item = attempt(&raw, 7, 0);
        item.raw_artifact_blake3 = "b".repeat(64);
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn tampered_canonical_semantic_digest_is_invalid() {
        let raw = link_and_done("eth0");
        let mut item = attempt(&raw, 7, 0);
        item.canonical_semantic_blake3 = Some("b".repeat(64));
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn unknown_decision_critical_attribute_is_unsupported() {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&encode_u16(1));
        payload.extend_from_slice(&encode_i32(2));
        payload.extend_from_slice(&encode_u32(1));
        payload.extend_from_slice(&encode_u32(u32::MAX));
        let mut name = b"eth0".to_vec();
        name.push(0);
        push_attr(&mut payload, IFLA_IFNAME, &name);
        push_attr(&mut payload, 999, &[1, 2, 3, 4]);
        let raw = raw_join(&[
            message(RTM_NEWLINK, NLM_F_MULTI, 7, &payload),
            done(7, 0, NLM_F_MULTI),
        ]);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Unsupported);
    }

    #[test]
    fn unknown_noncritical_attribute_is_preserved_by_raw_digest_and_allowed() {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&encode_u16(1));
        payload.extend_from_slice(&encode_i32(2));
        payload.extend_from_slice(&encode_u32(1));
        payload.extend_from_slice(&encode_u32(u32::MAX));
        let mut name = b"eth0".to_vec();
        name.push(0);
        push_attr(&mut payload, IFLA_IFNAME, &name);
        push_attr(&mut payload, 777, &[8, 7, 6, 5]);
        let raw = raw_join(&[
            message(RTM_NEWLINK, NLM_F_MULTI, 7, &payload),
            done(7, 0, NLM_F_MULTI),
        ]);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::CompleteForDeclaredScope);
    }

    #[test]
    fn conflicting_duplicate_link_identity_is_invalid() {
        let raw = raw_join(&[
            link_message(2, "eth0", None, NLM_F_MULTI, 7),
            link_message(2, "eth1", None, NLM_F_MULTI, 7),
            done(7, 0, NLM_F_MULTI),
        ]);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn identical_duplicate_link_identity_is_counted_and_deduplicated() {
        let row = link_message(2, "eth0", None, NLM_F_MULTI, 7);
        let raw = raw_join(&[row.clone(), row, done(7, 0, NLM_F_MULTI)]);
        let receipt = verify_envelope_for_test(&envelope_with(vec![attempt(&raw, 7, 0)]));
        assert_eq!(receipt.receipt.decision, Decision::CompleteForDeclaredScope);
        assert_eq!(receipt.receipt.source_results[0].observed_object_count, 1);
        assert_eq!(receipt.receipt.source_results[0].identical_duplicate_count, 1);
    }

    #[test]
    fn successful_bounded_retry_can_recover_an_incomplete_attempt() {
        let failed = link_message(2, "eth0", None, NLM_F_MULTI, 7);
        let good = raw_join(&[
            link_message(2, "eth0", None, NLM_F_MULTI, 8),
            done(8, 0, NLM_F_MULTI),
        ]);
        let envelope = envelope_with(vec![attempt(&failed, 7, 0), attempt(&good, 8, 1)]);
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::CompleteForDeclaredScope);
        assert_eq!(receipt.receipt.source_results[0].accepted_retry_index, Some(1));
    }

    #[test]
    fn retry_budget_exhaustion_is_incomplete() {
        let failed_a = link_message(2, "eth0", None, NLM_F_MULTI, 7);
        let failed_b = link_message(2, "eth0", None, NLM_F_MULTI, 8);
        let good = done(9, 0, NLM_F_MULTI);
        let mut envelope = envelope_with(vec![
            attempt(&failed_a, 7, 0),
            attempt(&failed_b, 8, 1),
            attempt(&good, 9, 2),
        ]);
        envelope.policy.max_retries = 1;
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn missing_required_source_is_incomplete() {
        let mut envelope = envelope_with(Vec::new());
        envelope.source_families.clear();
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn source_target_substitution_is_invalid() {
        let mut item = attempt(&done(7, 0, NLM_F_MULTI), 7, 0);
        item.network_namespace_inode += 1;
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn expired_but_integral_evidence_is_expired_not_complete() {
        let mut envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        envelope.verification_time_unix_ms = envelope.captured_at_unix_ms + 60_001;
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.integrity, Integrity::Valid);
        assert_eq!(receipt.receipt.coverage, Coverage::Complete);
        assert_eq!(receipt.receipt.freshness, Freshness::Expired);
        assert_eq!(receipt.receipt.decision, Decision::Expired);
    }

    #[test]
    fn required_family_outside_m1a_profile_is_unsupported() {
        let mut envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        envelope.scope.required_families = vec!["gnmi.openconfig.interfaces.v1".to_owned()];
        envelope.source_families[0].family = "gnmi.openconfig.interfaces.v1".to_owned();
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Unsupported);
    }

    #[test]
    fn more_than_one_required_family_never_claims_cross_source_coherence() {
        let mut envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        envelope.scope.required_families.push("gnmi.openconfig.interfaces.v1".to_owned());
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Unsupported);
        assert_eq!(receipt.receipt.temporal_coherence, TemporalCoherence::NotEstablished);
    }

    #[test]
    fn future_capture_clock_is_invalid() {
        let mut envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        envelope.verification_time_unix_ms = envelope.captured_at_unix_ms - 1;
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.freshness, Freshness::Invalid);
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn receipt_payload_tampering_is_detected_before_serialization() {
        let envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        let mut receipt = verify_envelope_for_test(&envelope);
        receipt.receipt.decision = Decision::Incomplete;
        assert!(receipt.serialize_checked().unwrap_err().contains("digest does not match"));
    }

    #[test]
    fn json_unknown_fields_fail_closed() {
        let envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        let mut value = serde_json::to_value(envelope).expect("serialize fixture");
        value["complete"] = serde_json::Value::Bool(true);
        assert!(verify_bytes(&serde_json::to_vec(&value).expect("serialize JSON")).is_err());
    }

    #[test]
    fn raw_artifact_digest_is_bound_to_exact_bytes_not_hex_spelling() {
        let raw = done(7, 0, NLM_F_MULTI);
        let mut item = attempt(&raw, 7, 0);
        item.raw_artifact_hex = item.raw_artifact_hex.to_uppercase();
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Invalid);
    }

    #[test]
    fn zero_byte_artifact_is_not_a_valid_empty_dump() {
        let item = attempt(&[], 7, 0);
        let receipt = verify_envelope_for_test(&envelope_with(vec![item]));
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn message_limit_blocks_a_dump_even_when_terminal_marker_is_present() {
        let raw = link_and_done("eth0");
        let mut envelope = envelope_with(vec![attempt(&raw, 7, 0)]);
        envelope.policy.max_messages_per_attempt = 1;
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn byte_limit_blocks_oversized_raw_artifact() {
        let raw = done(7, 0, NLM_F_MULTI);
        let mut envelope = envelope_with(vec![attempt(&raw, 7, 0)]);
        envelope.policy.max_total_raw_bytes = raw.len() - 1;
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Incomplete);
    }

    #[test]
    fn decision_critical_address_attribute_is_unsupported_in_this_projection() {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&encode_u16(1));
        payload.extend_from_slice(&encode_i32(2));
        payload.extend_from_slice(&encode_u32(1));
        payload.extend_from_slice(&encode_u32(u32::MAX));
        let mut name = b"eth0".to_vec();
        name.push(0);
        push_attr(&mut payload, IFLA_IFNAME, &name);
        push_attr(&mut payload, IFLA_ADDRESS, &[0, 1, 2, 3, 4, 5]);
        let raw = raw_join(&[
            message(RTM_NEWLINK, NLM_F_MULTI, 7, &payload),
            done(7, 0, NLM_F_MULTI),
        ]);
        let mut envelope = envelope_with(vec![attempt(&raw, 7, 0)]);
        envelope.policy.decision_critical_link_attribute_ids.push(IFLA_ADDRESS);
        let receipt = verify_envelope_for_test(&envelope);
        assert_eq!(receipt.receipt.decision, Decision::Unsupported);
    }

    #[test]
    fn serialized_receipt_is_byte_deterministic_for_the_same_exact_input() {
        let envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        let input = serde_json::to_vec(&envelope).expect("fixture serializes");
        let first = verify_bytes(&input).expect("verifies");
        let second = verify_bytes(&input).expect("verifies");
        assert_eq!(first.serialize_checked().expect("receipt serializes"), second.serialize_checked().expect("receipt serializes"));
        assert_eq!(first.receipt.policy_digest_blake3, second.receipt.policy_digest_blake3);
        assert_eq!(first.receipt.verifier_source_digest_blake3.len(), 64);
    }

    #[test]
    fn envelope_digest_binds_exact_json_bytes_not_only_parsed_fields() {
        let envelope = envelope_with(vec![attempt(&done(7, 0, NLM_F_MULTI), 7, 0)]);
        let compact = serde_json::to_vec(&envelope).expect("fixture serializes");
        let pretty = serde_json::to_vec_pretty(&envelope).expect("fixture pretty-serializes");
        let compact_receipt = verify_bytes(&compact).expect("compact JSON verifies");
        let pretty_receipt = verify_bytes(&pretty).expect("pretty JSON verifies");
        assert_ne!(compact_receipt.receipt.envelope_raw_blake3, pretty_receipt.receipt.envelope_raw_blake3);
        assert_ne!(compact_receipt.receipt_blake3, pretty_receipt.receipt_blake3);
    }
}
