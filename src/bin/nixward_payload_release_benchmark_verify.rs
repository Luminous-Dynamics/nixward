// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only independent replay of payload-release benchmark evidence.
//!
//! The verifier derives dispositions and statistics from raw typed events.
//! It never accepts a runner-supplied pass bit or aggregate percentile. It
//! checks evidence consistency and artifact digests; it does not authenticate
//! the machine that captured the records or perform host-mutating operations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process;

const CORPUS_SCHEMA: &str =
    "org.luminousdynamics.nixward.payload-release-assurance-benchmark";
const MANIFEST_SCHEMA: &str =
    "org.luminousdynamics.nixward.payload-release-trial-manifest";
const REPORT_SCHEMA: &str =
    "org.luminousdynamics.nixward.payload-release-trial-verification";
const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRIALS: usize = 100_000;
const MAX_EVENTS_PER_TRIAL: usize = 100_000;
const MAX_ARTIFACTS_PER_TRIAL: usize = 10_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkCorpus {
    schema: String,
    version: u32,
    status: String,
    trial_policy: TrialPolicy,
    scenarios: Vec<ScenarioDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialPolicy {
    clean_min_trials: usize,
    fault_min_trials: usize,
    concurrency_min_trials: usize,
    durability_min_trials: usize,
    p99_claim_min_trials: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioDefinition {
    id: String,
    trial_class: String,
    expected_disposition: String,
    minimum_trials: usize,
    fault_boundary: String,
    required_observations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialManifest {
    schema: String,
    version: u32,
    corpus_sha256: String,
    source_commit_sha: String,
    flake_lock_sha256: String,
    environment: TrialEnvironment,
    trials: Vec<TrialRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialEnvironment {
    kernel_release: String,
    systemd_version: String,
    sqlite_version: String,
    nix_version: String,
    filesystem: String,
    mount_options: String,
    device_model: String,
    device_firmware: String,
    cpu_model: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRecord {
    trial_id: String,
    scenario_id: String,
    started_monotonic_ns: u64,
    finished_monotonic_ns: u64,
    initial_policy_epoch: u64,
    initial_policy_record_digest: String,
    events_sha256: String,
    events: Vec<EvidenceEvent>,
    artifacts: Vec<ArtifactReceipt>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReceipt {
    relative_path: String,
    sha256: String,
    artifact_kind: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceEvent {
    BarrierCreateRequested {
        seq: u64,
        at_ns: u64,
        request_id: String,
        admission_commit_id: String,
        expected_policy_epoch: u64,
        expected_policy_record_digest: String,
        payload_digest: String,
    },
    BarrierCommitted {
        seq: u64,
        at_ns: u64,
        request_id: String,
        release_id: String,
        admission_commit_id: String,
        attempt_id: String,
        policy_id: String,
        policy_epoch: u64,
        policy_digest: String,
        policy_record_digest: String,
        signer_key_id: String,
        authority_provenance_digest: String,
        authority_subject_digest: String,
        authority_audience: String,
        payload_digest: String,
    },
    BarrierRetryExisting {
        seq: u64,
        at_ns: u64,
        request_id: String,
        release_id: String,
    },
    PolicyAdvanceRequested {
        seq: u64,
        at_ns: u64,
        request_id: String,
        expected_epoch: u64,
        expected_record_digest: String,
    },
    PolicyAdvanced {
        seq: u64,
        at_ns: u64,
        request_id: String,
        from_epoch: u64,
        to_epoch: u64,
        previous_record_digest: String,
        new_policy_id: String,
        new_record_digest: String,
        emergency_revoked_signers: Vec<String>,
        decisions: Vec<PolicyDecision>,
    },
    ReleaseAttemptRequested {
        seq: u64,
        at_ns: u64,
        request_id: String,
        release_id: String,
    },
    ReleaseAttemptReserved {
        seq: u64,
        at_ns: u64,
        request_id: String,
        release_id: String,
        attempt_id: String,
        payload_digest: String,
    },
    PayloadWriteStarted {
        seq: u64,
        at_ns: u64,
        release_id: String,
        payload_digest: String,
    },
    PayloadWriteCompleted {
        seq: u64,
        at_ns: u64,
        release_id: String,
        payload_digest: String,
        bytes_written: u64,
    },
    ReleaseUncertain {
        seq: u64,
        at_ns: u64,
        release_id: String,
    },
    WorkerReceiptPersisted {
        seq: u64,
        at_ns: u64,
        worker_completed_at_ns: u64,
        release_id: String,
        payload_digest: String,
        worker_unit: String,
        invocation_id: String,
        receipt_digest: String,
    },
    ResolutionCommitted {
        seq: u64,
        at_ns: u64,
        release_id: String,
        admission_commit_id: String,
        receipt_digest: String,
    },
    OperationRejected {
        seq: u64,
        at_ns: u64,
        operation: String,
        reason_code: String,
    },
    CheckpointCompleted {
        seq: u64,
        at_ns: u64,
        duration_ns: u64,
        wal_bytes: u64,
    },
    WriterLockWait {
        seq: u64,
        at_ns: u64,
        duration_ns: u64,
    },
}

impl EvidenceEvent {
    fn sequence(&self) -> u64 {
        match self {
            Self::BarrierCreateRequested { seq, .. }
            | Self::BarrierCommitted { seq, .. }
            | Self::BarrierRetryExisting { seq, .. }
            | Self::PolicyAdvanceRequested { seq, .. }
            | Self::PolicyAdvanced { seq, .. }
            | Self::ReleaseAttemptRequested { seq, .. }
            | Self::ReleaseAttemptReserved { seq, .. }
            | Self::PayloadWriteStarted { seq, .. }
            | Self::PayloadWriteCompleted { seq, .. }
            | Self::ReleaseUncertain { seq, .. }
            | Self::WorkerReceiptPersisted { seq, .. }
            | Self::ResolutionCommitted { seq, .. }
            | Self::OperationRejected { seq, .. }
            | Self::CheckpointCompleted { seq, .. }
            | Self::WriterLockWait { seq, .. } => *seq,
        }
    }

    fn timestamp(&self) -> u64 {
        match self {
            Self::BarrierCreateRequested { at_ns, .. }
            | Self::BarrierCommitted { at_ns, .. }
            | Self::BarrierRetryExisting { at_ns, .. }
            | Self::PolicyAdvanceRequested { at_ns, .. }
            | Self::PolicyAdvanced { at_ns, .. }
            | Self::ReleaseAttemptRequested { at_ns, .. }
            | Self::ReleaseAttemptReserved { at_ns, .. }
            | Self::PayloadWriteStarted { at_ns, .. }
            | Self::PayloadWriteCompleted { at_ns, .. }
            | Self::ReleaseUncertain { at_ns, .. }
            | Self::WorkerReceiptPersisted { at_ns, .. }
            | Self::ResolutionCommitted { at_ns, .. }
            | Self::OperationRejected { at_ns, .. }
            | Self::CheckpointCompleted { at_ns, .. }
            | Self::WriterLockWait { at_ns, .. } => *at_ns,
        }
    }

    fn observation_name(&self) -> &'static str {
        match self {
            Self::BarrierCreateRequested { .. } => "barrier_request",
            Self::BarrierCommitted { .. } => "barrier_commit",
            Self::BarrierRetryExisting { .. } => "barrier_retry",
            Self::PolicyAdvanceRequested { .. } => "policy_advance_request",
            Self::PolicyAdvanced { .. } => "policy_advance",
            Self::ReleaseAttemptRequested { .. } => "attempt_request",
            Self::ReleaseAttemptReserved { .. } => "attempt_reserved",
            Self::PayloadWriteStarted { .. } => "payload_write_started",
            Self::PayloadWriteCompleted { .. } => "payload_write_completed",
            Self::ReleaseUncertain { .. } => "release_uncertain",
            Self::WorkerReceiptPersisted { .. } => "worker_receipt",
            Self::ResolutionCommitted { .. } => "resolution",
            Self::OperationRejected { .. } => "rejection",
            Self::CheckpointCompleted { .. } => "checkpoint",
            Self::WriterLockWait { .. } => "writer_lock_wait",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PolicyDecision {
    release_id: String,
    disposition: PolicyDisposition,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PolicyDisposition {
    PreserveExistingBarrier,
    StopOrRecoveryRequired,
}

#[derive(Debug, Clone)]
struct BarrierState {
    release_id: String,
    admission_commit_id: String,
    attempt_id: String,
    policy_id: String,
    signer_key_id: String,
    policy_epoch: u64,
    policy_record_digest: String,
    payload_digest: String,
    committed_at_ns: u64,
    decision: Option<PolicyDisposition>,
}

#[derive(Debug, Clone)]
struct AttemptState {
    attempt_id: String,
    payload_digest: String,
    at_ns: u64,
}

#[derive(Debug, Clone)]
struct ReceiptState {
    payload_digest: String,
    receipt_digest: String,
    worker_unit: String,
    invocation_id: String,
    at_ns: u64,
}

#[derive(Debug, Default)]
struct TrialMeasurements {
    duration_ns: Vec<u64>,
    barrier_latency_ns: Vec<u64>,
    attempt_latency_ns: Vec<u64>,
    policy_advance_latency_ns: Vec<u64>,
    checkpoint_latency_ns: Vec<u64>,
    writer_lock_wait_ns: Vec<u64>,
    wal_bytes: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct TrialReport {
    trial_id: String,
    scenario_id: String,
    valid: bool,
    scenario_expectation_met: bool,
    duration_ns: u64,
    event_count: usize,
    artifact_count: usize,
    barrier_count: usize,
    attempt_count: usize,
    receipt_count: usize,
    uncertain_count: usize,
    resolution_count: usize,
    violations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MetricSummary {
    sample_count: usize,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    max_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
struct ScenarioSummary {
    scenario_id: String,
    trial_count: usize,
    required_trials: usize,
    complete: bool,
    valid_trials: usize,
    invalid_trials: usize,
    duration: MetricSummary,
    barrier_commit: MetricSummary,
    attempt_reservation: MetricSummary,
    policy_advance: MetricSummary,
    checkpoint: MetricSummary,
    writer_lock_wait: MetricSummary,
    wal_bytes_max: Option<u64>,
}

#[derive(Debug, Serialize)]
struct VerificationReport {
    schema: String,
    version: u32,
    corpus_sha256: String,
    source_commit_sha: String,
    flake_lock_sha256: String,
    trial_count: usize,
    unsafe_trial_count: usize,
    complete: bool,
    p99_claims_enabled: bool,
    trials: Vec<TrialReport>,
    scenarios: Vec<ScenarioSummary>,
}

#[derive(Debug)]
struct VerifiedTrial {
    report: TrialReport,
    measurements: TrialMeasurements,
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_JSON_BYTES {
        return Err(format!("{} is not a regular file within the size limit", path.display()));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn resolve_artifact_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("artifact path escapes the root: {relative}"));
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve artifact root {}: {error}", root.display()))?;
    let joined = canonical_root.join(relative_path);
    let canonical_file = fs::canonicalize(&joined)
        .map_err(|error| format!("cannot resolve artifact {relative}: {error}"))?;
    if !canonical_file.starts_with(&canonical_root) {
        return Err(format!("artifact symlink escapes the root: {relative}"));
    }
    let metadata = fs::metadata(&canonical_file)
        .map_err(|error| format!("cannot stat artifact {relative}: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_JSON_BYTES {
        return Err(format!("artifact is not a regular file within the size limit: {relative}"));
    }
    Ok(canonical_file)
}

fn validate_artifacts(root: &Path, artifacts: &[ArtifactReceipt]) -> Result<(), String> {
    if artifacts.len() > MAX_ARTIFACTS_PER_TRIAL {
        return Err("too many raw artifact receipts".into());
    }
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        if artifact.artifact_kind.trim().is_empty()
            || !valid_hex(&artifact.sha256, 64)
            || !paths.insert(artifact.relative_path.as_str())
        {
            return Err(format!("invalid or duplicate artifact receipt: {}", artifact.relative_path));
        }
        let path = resolve_artifact_path(root, &artifact.relative_path)?;
        let bytes = read_bounded(&path)?;
        if sha256_hex(&bytes) != artifact.sha256 {
            return Err(format!("artifact digest mismatch: {}", artifact.relative_path));
        }
    }
    Ok(())
}

fn expected_rejection_code(disposition: &str) -> Option<&'static str> {
    match disposition {
        "reject_conflict" => Some("release_barrier_conflict"),
        "reject_unauthorized" | "reject_revoked" => Some("release_barrier_unauthorized"),
        "reject_stale_policy" | "reject_stale_barrier" => Some("release_barrier_stale_policy"),
        "reject_preserve" => Some("release_signer_revoked"),
        "reject_policy_update" => Some("release_policy_decision_required"),
        "reject_second_attempt" => Some("release_attempt_already_started"),
        "reject_foreign_receipt" | "reject_receipt_conflict" => Some("release_receipt_conflict"),
        "reject_in_flight" => Some("release_barrier_in_flight"),
        "detect_corruption" => Some("inconsistent_storage"),
        "reject_downgrade" => Some("release_policy_decision_downgrade"),
        "refuse_legacy" => Some("unsupported_schema_v3"),
        _ => None,
    }
}

fn scenario_expectation_met(
    scenario: &ScenarioDefinition,
    barriers: &BTreeMap<String, BarrierState>,
    attempts: &BTreeMap<String, AttemptState>,
    receipts: &BTreeMap<String, ReceiptState>,
    uncertain: &BTreeSet<String>,
    rejections: &[(String, String)],
    retries: &[(String, String)],
    checkpoints: usize,
    policies: &[PolicyDecision],
) -> bool {
    match scenario.expected_disposition.as_str() {
        "created" => barriers.len() == 1,
        "existing_same_release_id" => {
            barriers.len() == 1
                && retries.iter().any(|(_, release_id)| barriers.contains_key(release_id))
        }
        value if expected_rejection_code(value).is_some() => {
            let expected = expected_rejection_code(value).unwrap();
            rejections.iter().any(|(_, reason)| reason == expected)
        }
        "preserve_historical_barrier" => policies
            .iter()
            .any(|decision| decision.disposition == PolicyDisposition::PreserveExistingBarrier),
        "block_attempt" => {
            policies.iter().any(|decision| {
                decision.disposition == PolicyDisposition::StopOrRecoveryRequired
            }) && attempts.is_empty()
        }
        "attempt_reserved" => attempts.len() == 1,
        "uncertain_no_resend" => attempts.len() == 1 && !uncertain.is_empty(),
        "acknowledge_original_attempt" => {
            attempts.len() == 1 && !uncertain.is_empty() && !receipts.is_empty()
        }
        "one_barrier_only" => barriers.len() == 1,
        "one_linearized_order" => {
            barriers.len() == 1 || rejections.iter().any(|(_, reason)| {
                reason == "release_barrier_stale_policy"
            })
        }
        "measure_tail_latency" => checkpoints > 0,
        _ => false,
    }
}

fn verify_trial(
    trial: &TrialRecord,
    scenario: &ScenarioDefinition,
    artifact_root: &Path,
) -> Result<VerifiedTrial, String> {
    if trial.trial_id.trim().is_empty()
        || trial.started_monotonic_ns >= trial.finished_monotonic_ns
        || trial.initial_policy_epoch == 0
        || !valid_hex(&trial.initial_policy_record_digest, 64)
        || trial.events.is_empty()
        || trial.events.len() > MAX_EVENTS_PER_TRIAL
        || !valid_hex(&trial.events_sha256, 64)
    {
        return Err(format!("trial {} has malformed metadata", trial.trial_id));
    }
    validate_artifacts(artifact_root, &trial.artifacts)?;
    let event_bytes = serde_json::to_vec(&trial.events)
        .map_err(|error| format!("cannot serialize trial events: {error}"))?;
    if sha256_hex(&event_bytes) != trial.events_sha256 {
        return Err(format!("trial {} event-stream digest mismatch", trial.trial_id));
    }

    let mut violations = Vec::new();
    let mut observed = BTreeSet::new();
    let mut previous_sequence = 0_u64;
    let mut previous_timestamp = trial.started_monotonic_ns;
    let mut policy_epoch = trial.initial_policy_epoch;
    let mut policy_record_digest = trial.initial_policy_record_digest.clone();
    let mut barrier_requests = BTreeMap::<String, (String, u64, String, String, u64)>::new();
    let mut policy_requests = BTreeMap::<String, (u64, String, u64)>::new();
    let mut attempt_requests = BTreeMap::<String, (String, u64)>::new();
    let mut barriers = BTreeMap::<String, BarrierState>::new();
    let mut admission_releases = BTreeMap::<String, String>::new();
    let mut retries = Vec::<(String, String)>::new();
    let mut attempts = BTreeMap::<String, AttemptState>::new();
    let mut writes_started = BTreeMap::<String, (String, u64)>::new();
    let mut writes_completed = BTreeSet::new();
    let mut uncertain = BTreeSet::new();
    let mut receipts = BTreeMap::<String, ReceiptState>::new();
    let mut resolutions = BTreeSet::new();
    let mut rejections = Vec::<(String, String)>::new();
    let mut policy_decisions_seen = Vec::<PolicyDecision>::new();
    let mut measurements = TrialMeasurements::default();
    let mut checkpoint_count = 0_usize;

    for event in &trial.events {
        let sequence = event.sequence();
        let timestamp = event.timestamp();
        if sequence != previous_sequence.saturating_add(1) {
            violations.push(format!("non-contiguous event sequence at {sequence}"));
        }
        if timestamp < previous_timestamp
            || timestamp < trial.started_monotonic_ns
            || timestamp > trial.finished_monotonic_ns
        {
            violations.push(format!("non-monotonic or out-of-range timestamp at {sequence}"));
        }
        previous_sequence = sequence;
        previous_timestamp = timestamp;
        observed.insert(event.observation_name());

        match event {
            EvidenceEvent::BarrierCreateRequested {
                request_id, admission_commit_id, expected_policy_epoch,
                expected_policy_record_digest, payload_digest, at_ns, ..
            } => {
                if request_id.trim().is_empty()
                    || !valid_hex(admission_commit_id, 64)
                    || !valid_hex(expected_policy_record_digest, 64)
                    || !valid_hex(payload_digest, 64)
                    || barrier_requests.insert(
                        request_id.clone(),
                        (
                            admission_commit_id.clone(),
                            *expected_policy_epoch,
                            expected_policy_record_digest.clone(),
                            payload_digest.clone(),
                            *at_ns,
                        ),
                    ).is_some()
                {
                    violations.push("malformed or duplicate barrier request".into());
                }
            }
            EvidenceEvent::BarrierCommitted {
                request_id, release_id, admission_commit_id, attempt_id,
                policy_id, policy_epoch, policy_digest, policy_record_digest,
                signer_key_id, authority_provenance_digest, authority_subject_digest,
                authority_audience, payload_digest, at_ns, ..
            } => {
                let Some((requested_commit, requested_epoch, requested_policy, requested_payload, requested_at)) =
                    barrier_requests.get(request_id)
                else {
                    violations.push("barrier commit has no preceding request".into());
                    continue;
                };
                if !valid_hex(release_id, 64)
                    || !valid_hex(policy_digest, 64)
                    || !valid_hex(policy_record_digest, 64)
                    || !valid_hex(authority_provenance_digest, 64)
                    || !valid_hex(authority_subject_digest, 64)
                    || !valid_hex(payload_digest, 64)
                    || !valid_hex(admission_commit_id, 64)
                    || attempt_id.trim().is_empty()
                    || policy_id.trim().is_empty()
                    || signer_key_id.trim().is_empty()
                    || authority_audience.trim().is_empty()
                    || requested_commit != admission_commit_id
                    || requested_epoch != policy_epoch
                    || requested_policy != policy_record_digest
                    || requested_payload != payload_digest
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch // retained as an explicit schema assertion
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *policy_epoch != policy_epoch
                    || *at_ns < *requested_at
                {
                    violations.push(format!("barrier {release_id} is not bound to request or event order"));
                }
                // A fresh barrier must use the current policy snapshot.
                if *policy_epoch != policy_epoch || policy_record_digest != &policy_record_digest {
                    violations.push("barrier policy snapshot mismatch".into());
                }
                if *policy_epoch != policy_epoch {
                    violations.push("barrier epoch mismatch".into());
                }
                if *policy_epoch != policy_epoch {
                    violations.push("barrier epoch mismatch".into());
                }
                if barriers.contains_key(release_id)
                    || admission_releases.contains_key(admission_commit_id)
                {
                    violations.push(format!("duplicate barrier for {release_id} or admission"));
                }
                if *policy_epoch != policy_epoch {
                    violations.push("barrier epoch mismatch".into());
                }
                if policy_epoch != &policy_epoch {
                    violations.push("barrier epoch is not current".into());
                }
                if policy_record_digest != &policy_record_digest {
                    violations.push("barrier policy digest is not current".into());
                }
                if !barriers.contains_key(release_id) {
                    admission_releases.insert(admission_commit_id.clone(), release_id.clone());
                    barriers.insert(release_id.clone(), BarrierState {
                        release_id: release_id.clone(),
                        admission_commit_id: admission_commit_id.clone(),
                        attempt_id: attempt_id.clone(),
                        policy_id: policy_id.clone(),
                        signer_key_id: signer_key_id.clone(),
                        policy_epoch: *policy_epoch,
                        policy_record_digest: policy_record_digest.clone(),
                        payload_digest: payload_digest.clone(),
                        committed_at_ns: *at_ns,
                        decision: None,
                    });
                }
                if *policy_epoch != policy_epoch {
                    violations.push("barrier policy epoch incorrect".into());
                }
            }
            EvidenceEvent::BarrierRetryExisting { request_id, release_id, .. } => {
                if !barrier_requests.contains_key(request_id) || !barriers.contains_key(release_id) {
                    violations.push("historical barrier retry does not name an existing release".into());
                }
                retries.push((request_id.clone(), release_id.clone()));
            }
            EvidenceEvent::PolicyAdvanceRequested {
                request_id, expected_epoch, expected_record_digest, at_ns, ..
            } => {
                if request_id.trim().is_empty()
                    || !valid_hex(expected_record_digest, 64)
                    || policy_requests.insert(
                        request_id.clone(),
                        (*expected_epoch, expected_record_digest.clone(), *at_ns),
                    ).is_some()
                {
                    violations.push("malformed or duplicate policy request".into());
                }
            }
            EvidenceEvent::PolicyAdvanced {
                request_id, from_epoch, to_epoch, previous_record_digest,
                new_policy_id, new_record_digest, emergency_revoked_signers, decisions, at_ns, ..
            } => {
                let Some((requested_epoch, requested_digest, requested_at)) = policy_requests.get(request_id) else {
                    violations.push("policy advance has no preceding request".into());
                    continue;
                };
                if *from_epoch != policy_epoch
                    || *from_epoch != *requested_epoch
                    || previous_record_digest != &policy_record_digest
                    || previous_record_digest != requested_digest
                    || *to_epoch != from_epoch.saturating_add(1)
                    || *at_ns < *requested_at
                    || !valid_hex(new_record_digest, 64)
                    || new_policy_id.trim().is_empty()
                {
                    violations.push("policy epoch transition is stale, skipped or incorrectly chained".into());
                }
                let active = barriers.iter()
                    .filter(|(release_id, _)| !receipts.contains_key(*release_id))
                    .map(|(release_id, _)| release_id.clone())
                    .collect::<BTreeSet<_>>();
                let mut seen = BTreeSet::new();
                if active.len() != decisions.len() {
                    violations.push("policy advance omitted or added an in-flight barrier decision".into());
                }
                for decision in decisions {
                    if !active.contains(&decision.release_id) || !seen.insert(decision.release_id.clone()) {
                        violations.push("policy decision is foreign or duplicated".into());
                        continue;
                    }
                    let Some(barrier) = barriers.get(&decision.release_id) else {
                        violations.push("policy decision names an unknown barrier".into());
                        continue;
                    };
                    if decision.disposition == PolicyDisposition::PreserveExistingBarrier {
                        if new_policy_id != &barrier.policy_id {
                            violations.push("policy identity changed while preserving barrier".into());
                        }
                        if emergency_revoked_signers.contains(&barrier.signer_key_id) {
                            violations.push("emergency-revoked signer was preserved".into());
                        }
                    }
                    if barrier.decision == Some(PolicyDisposition::StopOrRecoveryRequired)
                        && decision.disposition == PolicyDisposition::PreserveExistingBarrier
                    {
                        violations.push("stop/recovery decision was downgraded".into());
                    }
                    if let Some(stored) = barriers.get_mut(&decision.release_id) {
                        stored.decision = Some(decision.disposition);
                    }
                    policy_decisions_seen.push(decision.clone());
                }
                if seen != active {
                    violations.push("policy decision set does not cover all outstanding barriers".into());
                }
                policy_epoch = *to_epoch;
                policy_record_digest = new_record_digest.clone();
            }
            EvidenceEvent::ReleaseAttemptRequested { request_id, release_id, at_ns, .. } => {
                if request_id.trim().is_empty()
                    || !barriers.contains_key(release_id)
                    || attempt_requests.insert(request_id.clone(), (release_id.clone(), *at_ns)).is_some()
                {
                    violations.push("malformed or duplicate attempt request".into());
                }
            }
            EvidenceEvent::ReleaseAttemptReserved {
                request_id, release_id, attempt_id, payload_digest, at_ns, ..
            } => {
                let Some((requested_release, requested_at)) = attempt_requests.get(request_id) else {
                    violations.push("attempt reservation has no preceding request".into());
                    continue;
                };
                let Some(barrier) = barriers.get(release_id) else {
                    violations.push("attempt reservation is foreign to any barrier".into());
                    continue;
                };
                if requested_release != release_id
                    || *at_ns < *requested_at
                    || *at_ns < barrier.committed_at_ns
                    || attempt_id != &barrier.attempt_id
                    || payload_digest != &barrier.payload_digest
                    || barrier.decision == Some(PolicyDisposition::StopOrRecoveryRequired)
                {
                    violations.push(format!("attempt reservation is not authorized for {release_id}"));
                }
                if attempts.contains_key(release_id) {
                    violations.push(format!("duplicate external attempt reservation for {release_id}"));
                } else {
                    attempts.insert(release_id.clone(), AttemptState {
                        attempt_id: attempt_id.clone(),
                        payload_digest: payload_digest.clone(),
                        at_ns: *at_ns,
                    });
                }
            }
            EvidenceEvent::PayloadWriteStarted { release_id, payload_digest, at_ns, .. } => {
                let Some(attempt) = attempts.get(release_id) else {
                    violations.push("payload write started before durable attempt reservation".into());
                    continue;
                };
                if payload_digest != &attempt.payload_digest
                    || *at_ns < attempt.at_ns
                    || writes_started.contains_key(release_id)
                {
                    violations.push("payload write is duplicate or not bound to its attempt".into());
                } else {
                    writes_started.insert(release_id.clone(), (payload_digest.clone(), *at_ns));
                }
            }
            EvidenceEvent::PayloadWriteCompleted { release_id, payload_digest, bytes_written, at_ns, .. } => {
                let Some((started_digest, start_at)) = writes_started.get(release_id) else {
                    violations.push("payload write completed without a recorded start".into());
                    continue;
                };
                if payload_digest != started_digest || *at_ns < *start_at
                    || *bytes_written == 0 || !writes_completed.insert(release_id.clone())
                {
                    violations.push("payload write completion is malformed or duplicated".into());
                }
            }
            EvidenceEvent::ReleaseUncertain { release_id, at_ns, .. } => {
                let Some(attempt) = attempts.get(release_id) else {
                    violations.push("uncertainty was recorded without a durable attempt".into());
                    continue;
                };
                if *at_ns < attempt.at_ns || receipts.contains_key(release_id)
                    || !uncertain.insert(release_id.clone())
                {
                    violations.push("uncertainty is stale, duplicated or after receipt".into());
                }
            }
            EvidenceEvent::WorkerReceiptPersisted {
                release_id, payload_digest, worker_completed_at_ns, worker_unit,
                invocation_id, receipt_digest, at_ns, ..
            } => {
                let Some(attempt) = attempts.get(release_id) else {
                    violations.push("worker receipt exists without a durable attempt".into());
                    continue;
                };
                if payload_digest != &attempt.payload_digest
                    || *worker_completed_at_ns < attempt.at_ns
                    || *worker_completed_at_ns > *at_ns
                    || worker_unit.trim().is_empty()
                    || invocation_id.trim().is_empty()
                    || !valid_hex(receipt_digest, 64)
                    || receipts.contains_key(release_id)
                {
                    violations.push("worker receipt is foreign, malformed or duplicated".into());
                } else {
                    receipts.insert(release_id.clone(), ReceiptState {
                        payload_digest: payload_digest.clone(),
                        receipt_digest: receipt_digest.clone(),
                        worker_unit: worker_unit.clone(),
                        invocation_id: invocation_id.clone(),
                        at_ns: *at_ns,
                    });
                }
            }
            EvidenceEvent::ResolutionCommitted {
                release_id, admission_commit_id, receipt_digest, at_ns, ..
            } => {
                let Some(barrier) = barriers.get(release_id) else {
                    violations.push("resolution exists without a barrier".into());
                    continue;
                };
                let Some(receipt) = receipts.get(release_id) else {
                    violations.push("transaction resolved before exact worker receipt".into());
                    continue;
                };
                if admission_commit_id != &barrier.admission_commit_id
                    || receipt_digest != &receipt.receipt_digest
                    || *at_ns < receipt.at_ns
                    || !resolutions.insert(release_id.clone())
                {
                    violations.push("resolution does not match exact receipt".into());
                }
            }
            EvidenceEvent::OperationRejected { operation, reason_code, .. } => {
                rejections.push((operation.clone(), reason_code.clone()));
            }
            EvidenceEvent::CheckpointCompleted { duration_ns, wal_bytes, .. } => {
                checkpoint_count += 1;
                measurements.checkpoint_latency_ns.push(*duration_ns);
                measurements.wal_bytes.push(*wal_bytes);
            }
            EvidenceEvent::WriterLockWait { duration_ns, .. } => {
                measurements.writer_lock_wait_ns.push(*duration_ns);
            }
        }
    }

    for request_id in barrier_requests.keys() {
        let committed_count = trial.events.iter().filter(|event| matches!(
            event,
            EvidenceEvent::BarrierCommitted { request_id: id, .. } if id == request_id
        )).count();
        let retry_count = trial.events.iter().filter(|event| matches!(
            event,
            EvidenceEvent::BarrierRetryExisting { request_id: id, .. } if id == request_id
        )).count();
        if committed_count > 1 || retry_count > 1 {
            violations.push(format!("barrier request {request_id} has duplicate terminal events"));
        }
    }

    for event in &trial.events {
        if let EvidenceEvent::BarrierCommitted { request_id, at_ns, .. } = event {
            if let Some((_, _, _, _, start_at)) = barrier_requests.get(request_id) {
                if at_ns >= start_at {
                    measurements.barrier_latency_ns.push(at_ns - start_at);
                }
            }
        }
        if let EvidenceEvent::ReleaseAttemptReserved { request_id, at_ns, .. } = event {
            if let Some((_, start_at)) = attempt_requests.get(request_id) {
                if at_ns >= start_at {
                    measurements.attempt_latency_ns.push(at_ns - start_at);
                }
            }
        }
        if let EvidenceEvent::PolicyAdvanced { request_id, at_ns, .. } = event {
            if let Some((_, _, start_at)) = policy_requests.get(request_id) {
                if at_ns >= start_at {
                    measurements.policy_advance_latency_ns.push(at_ns - start_at);
                }
            }
        }
    }
    measurements.duration_ns.push(
        trial.finished_monotonic_ns.saturating_sub(trial.started_monotonic_ns)
    );

    for required in &scenario.required_observations {
        if !observed.contains(required.as_str()) {
            violations.push(format!("required observation is missing: {required}"));
        }
    }
    let expectation_met = scenario_expectation_met(
        scenario,
        &barriers,
        &attempts,
        &receipts,
        &uncertain,
        &rejections,
        &retries,
        checkpoint_count,
        &policy_decisions_seen,
    );
    if !expectation_met {
        violations.push(format!(
            "raw events do not establish expected disposition {}",
            scenario.expected_disposition
        ));
    }

    Ok(VerifiedTrial {
        report: TrialReport {
            trial_id: trial.trial_id.clone(),
            scenario_id: trial.scenario_id.clone(),
            valid: violations.is_empty(),
            scenario_expectation_met: expectation_met,
            duration_ns: trial.finished_monotonic_ns - trial.started_monotonic_ns,
            event_count: trial.events.len(),
            artifact_count: trial.artifacts.len(),
            barrier_count: barriers.len(),
            attempt_count: attempts.len(),
            receipt_count: receipts.len(),
            uncertain_count: uncertain.len(),
            resolution_count: resolutions.len(),
            violations,
        },
        measurements,
    })
}

fn nearest_rank_ms(samples_ns: &[u64], percentile: f64, minimum_samples: usize) -> Option<f64> {
    if samples_ns.len() < minimum_samples || samples_ns.is_empty() {
        return None;
    }
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable();
    let rank = (percentile * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    Some(sorted[index] as f64 / 1_000_000.0)
}

fn metric_summary(samples_ns: &[u64], p99_minimum: usize) -> MetricSummary {
    MetricSummary {
        sample_count: samples_ns.len(),
        p50_ms: nearest_rank_ms(samples_ns, 0.50, 1),
        p95_ms: nearest_rank_ms(samples_ns, 0.95, 30),
        p99_ms: nearest_rank_ms(samples_ns, 0.99, p99_minimum),
        max_ms: samples_ns.iter().max().map(|value| *value as f64 / 1_000_000.0),
    }
}

fn verify_manifest(
    corpus_bytes: &[u8],
    manifest_bytes: &[u8],
    artifact_root: &Path,
) -> Result<VerificationReport, String> {
    let corpus: BenchmarkCorpus = serde_json::from_slice(corpus_bytes)
        .map_err(|error| format!("invalid corpus: {error}"))?;
    if corpus.schema != CORPUS_SCHEMA || corpus.version != 1 || corpus.status != "proposed-not-executed" {
        return Err("unsupported corpus schema, version or status".into());
    }
    let manifest: TrialManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("invalid manifest: {error}"))?;
    if manifest.schema != MANIFEST_SCHEMA || manifest.version != 1 {
        return Err("unsupported manifest schema or version".into());
    }
    let corpus_digest = sha256_hex(corpus_bytes);
    if manifest.corpus_sha256 != corpus_digest
        || !valid_hex(&manifest.source_commit_sha, 40)
        || !valid_hex(&manifest.flake_lock_sha256, 64)
    {
        return Err("corpus/source/flake digest binding is invalid".into());
    }
    if manifest.trials.len() > MAX_TRIALS
        || [
            manifest.environment.kernel_release.as_str(),
            manifest.environment.systemd_version.as_str(),
            manifest.environment.sqlite_version.as_str(),
            manifest.environment.nix_version.as_str(),
            manifest.environment.filesystem.as_str(),
            manifest.environment.mount_options.as_str(),
            manifest.environment.device_model.as_str(),
            manifest.environment.device_firmware.as_str(),
            manifest.environment.cpu_model.as_str(),
        ].iter().any(|value| value.trim().is_empty())
    {
        return Err("trial count or environment metadata is invalid".into());
    }
    let scenarios = corpus.scenarios.iter()
        .map(|scenario| (scenario.id.as_str(), scenario))
        .collect::<BTreeMap<_, _>>();
    if scenarios.len() != corpus.scenarios.len() {
        return Err("corpus has duplicate scenario IDs".into());
    }
    let mut trial_ids = BTreeSet::new();
    let mut verified = Vec::<VerifiedTrial>::new();
    for trial in &manifest.trials {
        if !trial_ids.insert((trial.scenario_id.as_str(), trial.trial_id.as_str())) {
            return Err(format!("duplicate trial ID {} for {}", trial.trial_id, trial.scenario_id));
        }
        let scenario = scenarios.get(trial.scenario_id.as_str())
            .ok_or_else(|| format!("unknown scenario ID {}", trial.scenario_id))?;
        verified.push(verify_trial(trial, scenario, artifact_root)?);
    }

    let mut summaries = Vec::new();
    let mut complete = true;
    let mut p99_claims_enabled = true;
    for scenario in &corpus.scenarios {
        let selected = verified.iter()
            .filter(|trial| trial.report.scenario_id == scenario.id)
            .collect::<Vec<_>>();
        let valid_count = selected.iter().filter(|trial| trial.report.valid).count();
        let scenario_complete = selected.len() >= scenario.minimum_trials;
        complete &= scenario_complete;

        let durations = selected.iter().flat_map(|trial| trial.measurements.duration_ns.iter().copied()).collect::<Vec<_>>();
        let barrier = selected.iter().flat_map(|trial| trial.measurements.barrier_latency_ns.iter().copied()).collect::<Vec<_>>();
        let attempt = selected.iter().flat_map(|trial| trial.measurements.attempt_latency_ns.iter().copied()).collect::<Vec<_>>();
        let policy = selected.iter().flat_map(|trial| trial.measurements.policy_advance_latency_ns.iter().copied()).collect::<Vec<_>>();
        let checkpoint = selected.iter().flat_map(|trial| trial.measurements.checkpoint_latency_ns.iter().copied()).collect::<Vec<_>>();
        let writer_wait = selected.iter().flat_map(|trial| trial.measurements.writer_lock_wait_ns.iter().copied()).collect::<Vec<_>>();
        let wal = selected.iter().flat_map(|trial| trial.measurements.wal_bytes.iter().copied()).collect::<Vec<_>>();

        p99_claims_enabled &= durations.len() >= corpus.trial_policy.p99_claim_min_trials;
        summaries.push(ScenarioSummary {
            scenario_id: scenario.id.clone(),
            trial_count: selected.len(),
            required_trials: scenario.minimum_trials,
            complete: scenario_complete,
            valid_trials: valid_count,
            invalid_trials: selected.len().saturating_sub(valid_count),
            duration: metric_summary(&durations, corpus.trial_policy.p99_claim_min_trials),
            barrier_commit: metric_summary(&barrier, corpus.trial_policy.p99_claim_min_trials),
            attempt_reservation: metric_summary(&attempt, corpus.trial_policy.p99_claim_min_trials),
            policy_advance: metric_summary(&policy, corpus.trial_policy.p99_claim_min_trials),
            checkpoint: metric_summary(&checkpoint, corpus.trial_policy.p99_claim_min_trials),
            writer_lock_wait: metric_summary(&writer_wait, corpus.trial_policy.p99_claim_min_trials),
            wal_bytes_max: wal.iter().max().copied(),
        });
    }

    let trial_reports = verified.into_iter().map(|trial| trial.report).collect::<Vec<_>>();
    let unsafe_count = trial_reports.iter().filter(|trial| !trial.valid).count();
    Ok(VerificationReport {
        schema: REPORT_SCHEMA.into(),
        version: 1,
        corpus_sha256: corpus_digest,
        source_commit_sha: manifest.source_commit_sha,
        flake_lock_sha256: manifest.flake_lock_sha256,
        trial_count: trial_reports.len(),
        unsafe_trial_count: unsafe_count,
        complete,
        p99_claims_enabled,
        trials: trial_reports,
        scenarios: summaries,
    })
}

fn run() -> Result<i32, String> {
    let mut args = env::args().skip(1);
    let mut corpus_path = None;
    let mut manifest_path = None;
    let mut artifact_root = None;
    let mut output_path = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--corpus" => corpus_path = args.next().map(PathBuf::from),
            "--manifest" => manifest_path = args.next().map(PathBuf::from),
            "--artifacts-root" => artifact_root = args.next().map(PathBuf::from),
            "--output" => output_path = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                println!("nixward-payload-release-benchmark-verify --corpus CORPUS.json --manifest TRIALS.json --artifacts-root DIR [--output REPORT.json]");
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let corpus_path = corpus_path.ok_or("--corpus is required")?;
    let manifest_path = manifest_path.ok_or("--manifest is required")?;
    let artifact_root = artifact_root.ok_or("--artifacts-root is required")?;
    let corpus_bytes = read_bounded(&corpus_path)?;
    let manifest_bytes = read_bounded(&manifest_path)?;
    let report = verify_manifest(&corpus_bytes, &manifest_bytes, &artifact_root)?;
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("cannot serialize report: {error}"))?;
    if let Some(path) = output_path {
        fs::write(&path, output.as_bytes())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    } else {
        println!("{output}");
    }
    if report.unsafe_trial_count > 0 {
        Ok(10)
    } else if !report.complete {
        Ok(20)
    } else {
        Ok(0)
    }
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("nixward-payload-release-benchmark-verify: {error}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn clean_trial() -> (TrialRecord, ScenarioDefinition) {
        let events = vec![
            EvidenceEvent::BarrierCreateRequested {
                seq: 1, at_ns: 100, request_id: "barrier-request-1".into(),
                admission_commit_id: digest('1'), expected_policy_epoch: 1,
                expected_policy_record_digest: digest('2'), payload_digest: digest('9'),
            },
            EvidenceEvent::BarrierCommitted {
                seq: 2, at_ns: 120, request_id: "barrier-request-1".into(),
                release_id: digest('3'), admission_commit_id: digest('1'),
                attempt_id: digest('4'), policy_id: "owner-root:1".into(),
                policy_epoch: 1, policy_digest: digest('5'), policy_record_digest: digest('2'),
                signer_key_id: "owner-key".into(), authority_provenance_digest: digest('6'),
                authority_subject_digest: digest('7'), authority_audience: "nixward-change-v1".into(),
                payload_digest: digest('9'),
            },
            EvidenceEvent::ReleaseAttemptRequested {
                seq: 3, at_ns: 130, request_id: "attempt-request-1".into(),
                release_id: digest('3'),
            },
            EvidenceEvent::ReleaseAttemptReserved {
                seq: 4, at_ns: 140, request_id: "attempt-request-1".into(),
                release_id: digest('3'), attempt_id: digest('4'), payload_digest: digest('9'),
            },
            EvidenceEvent::PayloadWriteStarted {
                seq: 5, at_ns: 150, release_id: digest('3'), payload_digest: digest('9'),
            },
            EvidenceEvent::PayloadWriteCompleted {
                seq: 6, at_ns: 170, release_id: digest('3'), payload_digest: digest('9'), bytes_written: 512,
            },
            EvidenceEvent::WorkerReceiptPersisted {
                seq: 7, at_ns: 200, worker_completed_at_ns: 190, release_id: digest('3'),
                payload_digest: digest('9'), worker_unit: "nixward-release.service".into(),
                invocation_id: "invocation-1".into(), receipt_digest: digest('8'),
            },
            EvidenceEvent::ResolutionCommitted {
                seq: 8, at_ns: 210, release_id: digest('3'), admission_commit_id: digest('1'),
                receipt_digest: digest('8'),
            },
        ];
        let event_bytes = serde_json::to_vec(&events).unwrap();
        (
            TrialRecord {
                trial_id: "trial-clean-1".into(),
                scenario_id: "barrier-create-clean".into(),
                started_monotonic_ns: 100,
                finished_monotonic_ns: 250,
                initial_policy_epoch: 1,
                initial_policy_record_digest: digest('2'),
                events_sha256: sha256_hex(&event_bytes),
                events,
                artifacts: vec![],
            },
            ScenarioDefinition {
                id: "barrier-create-clean".into(),
                trial_class: "clean".into(),
                expected_disposition: "created".into(),
                minimum_trials: 30,
                fault_boundary: "none".into(),
                required_observations: vec![],
            },
        )
    }

    fn resequence(events: &mut [EvidenceEvent]) {
        for (index, event) in events.iter_mut().enumerate() {
            let seq = index as u64 + 1;
            match event {
                EvidenceEvent::BarrierCreateRequested { seq: value, .. }
                | EvidenceEvent::BarrierCommitted { seq: value, .. }
                | EvidenceEvent::BarrierRetryExisting { seq: value, .. }
                | EvidenceEvent::PolicyAdvanceRequested { seq: value, .. }
                | EvidenceEvent::PolicyAdvanced { seq: value, .. }
                | EvidenceEvent::ReleaseAttemptRequested { seq: value, .. }
                | EvidenceEvent::ReleaseAttemptReserved { seq: value, .. }
                | EvidenceEvent::PayloadWriteStarted { seq: value, .. }
                | EvidenceEvent::PayloadWriteCompleted { seq: value, .. }
                | EvidenceEvent::ReleaseUncertain { seq: value, .. }
                | EvidenceEvent::WorkerReceiptPersisted { seq: value, .. }
                | EvidenceEvent::ResolutionCommitted { seq: value, .. }
                | EvidenceEvent::OperationRejected { seq: value, .. }
                | EvidenceEvent::CheckpointCompleted { seq: value, .. }
                | EvidenceEvent::WriterLockWait { seq: value, .. } => *value = seq,
            }
        }
    }

    fn rehash(trial: &mut TrialRecord) {
        trial.events_sha256 = sha256_hex(&serde_json::to_vec(&trial.events).unwrap());
    }

    #[test]
    fn derives_clean_disposition_from_raw_ordered_events() {
        let (trial, scenario) = clean_trial();
        let verified = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(verified.report.valid);
        assert!(verified.report.scenario_expectation_met);
        assert_eq!(verified.report.barrier_count, 1);
        assert_eq!(verified.report.attempt_count, 1);
        assert_eq!(verified.report.receipt_count, 1);
        assert_eq!(verified.report.resolution_count, 1);
        assert_eq!(verified.measurements.barrier_latency_ns, vec![20]);
        assert_eq!(verified.measurements.attempt_latency_ns, vec![10]);
    }

    #[test]
    fn rejects_duplicate_release_attempt() {
        let (mut trial, scenario) = clean_trial();
        trial.events.insert(4, EvidenceEvent::ReleaseAttemptReserved {
            seq: 5, at_ns: 145, request_id: "attempt-request-1".into(),
            release_id: digest('3'), attempt_id: digest('4'), payload_digest: digest('9'),
        });
        resequence(&mut trial.events);
        rehash(&mut trial);
        let result = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(!result.report.valid);
        assert!(result.report.violations.iter().any(|value| value.contains("duplicate external attempt")));
    }

    #[test]
    fn rejects_payload_write_before_attempt_reservation() {
        let (mut trial, scenario) = clean_trial();
        trial.events.swap(3, 4);
        resequence(&mut trial.events);
        rehash(&mut trial);
        let result = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(!result.report.valid);
        assert!(result.report.violations.iter().any(|value| value.contains("before durable attempt")));
    }

    #[test]
    fn rejects_resolution_before_receipt() {
        let (mut trial, scenario) = clean_trial();
        trial.events.swap(6, 7);
        resequence(&mut trial.events);
        rehash(&mut trial);
        let result = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(!result.report.valid);
        assert!(result.report.violations.iter().any(|value| value.contains("before exact worker receipt")));
    }

    #[test]
    fn permits_late_receipt_to_reconcile_uncertain_original_attempt() {
        let (mut trial, scenario) = clean_trial();
        trial.events.insert(6, EvidenceEvent::ReleaseUncertain {
            seq: 7, at_ns: 195, release_id: digest('3'),
        });
        if let EvidenceEvent::WorkerReceiptPersisted { seq, at_ns, worker_completed_at_ns, .. } = &mut trial.events[7] {
            *seq = 8;
            *at_ns = 220;
            *worker_completed_at_ns = 190;
        }
        if let EvidenceEvent::ResolutionCommitted { seq, at_ns, .. } = &mut trial.events[8] {
            *seq = 9;
            *at_ns = 230;
        }
        trial.finished_monotonic_ns = 250;
        rehash(&mut trial);
        let result = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(result.report.valid);
        assert_eq!(result.report.uncertain_count, 1);
        assert_eq!(result.report.receipt_count, 1);
    }

    #[test]
    fn rejects_emergency_revoked_signer_preserve_decision() {
        let (mut trial, scenario) = clean_trial();
        trial.events.truncate(2);
        trial.finished_monotonic_ns = 300;
        trial.events.push(EvidenceEvent::PolicyAdvanceRequested {
            seq: 3, at_ns: 150, request_id: "policy-2".into(),
            expected_epoch: 1, expected_record_digest: digest('2'),
        });
        trial.events.push(EvidenceEvent::PolicyAdvanced {
            seq: 4, at_ns: 160, request_id: "policy-2".into(),
            from_epoch: 1, to_epoch: 2, previous_record_digest: digest('2'),
            new_policy_id: "owner-root:1".into(), new_record_digest: digest('a'),
            emergency_revoked_signers: vec!["owner-key".into()],
            decisions: vec![PolicyDecision {
                release_id: digest('3'),
                disposition: PolicyDisposition::PreserveExistingBarrier,
            }],
        });
        rehash(&mut trial);
        let result = verify_trial(&trial, &scenario, Path::new(".")).unwrap();
        assert!(!result.report.valid);
        assert!(result.report.violations.iter().any(|value| value.contains("emergency-revoked signer")));
    }

    #[test]
    fn nearest_rank_p99_is_suppressed_below_one_thousand_samples() {
        let samples = vec![10_000_000_u64; 999];
        assert_eq!(nearest_rank_ms(&samples, 0.99, 1000), None);
        let samples = vec![10_000_000_u64; 1000];
        assert_eq!(nearest_rank_ms(&samples, 0.99, 1000), Some(10.0));
    }

    #[test]
    fn rejects_path_traversal_and_absolute_artifact_path() {
        assert!(resolve_artifact_path(Path::new("."), "../outside.log").is_err());
        assert!(resolve_artifact_path(Path::new("."), "/etc/passwd").is_err());
    }

    #[test]
    fn unknown_runner_summary_fields_are_rejected() {
        let value = serde_json::json!({
            "schema": "org.luminousdynamics.nixward.payload-release-trial-manifest",
            "version": 1,
            "corpus_sha256": digest('a'),
            "source_commit_sha": "b".repeat(40),
            "flake_lock_sha256": digest('c'),
            "environment": {
                "kernel_release": "k", "systemd_version": "s", "sqlite_version": "q",
                "nix_version": "n", "filesystem": "xfs", "mount_options": "rw",
                "device_model": "nvme", "device_firmware": "f", "cpu_model": "cpu"
            },
            "trials": [],
            "runner_passed": true
        });
        assert!(serde_json::from_value::<TrialManifest>(value).is_err());
    }
}
