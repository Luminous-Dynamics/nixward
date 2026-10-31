// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent, read-only semantic consistency verifier for captured systemd
//! and NixOS execution evidence. It does not connect to D-Bus, open pidfds,
//! inspect a live host, authenticate evidence producers, or execute recovery.
//! A successful result means supplied observations are internally consistent;
//! a separate capture/attestation layer must establish their authenticity.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EVIDENCE_SCHEMA: &str = "org.luminousdynamics.nixward.systemd-execution-evidence";
pub const EVIDENCE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NixosOperation { Switch, Test, Boot }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManagerEventKind { JobNew, JobRemoved }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionBinding {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub replay_key_digest: String,
    pub permit_digest: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub kernel_boot_id: String,
    pub systemd_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationPlan {
    pub operation: NixosOperation,
    pub unit_name: String,
    pub unit_start_mode: String,
    /// Service-type-specific expectation; inactive/dead can be a successful oneshot.
    pub expected_unit_active_state: String,
    pub expected_unit_sub_state: String,
    pub expected_unit_result: String,
    pub candidate_store_path: String,
    pub predecessor_store_path: String,
    pub required_health_check_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionEvidence {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub replay_key_digest: String,
    pub permit_digest: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub committed_at_ns: u64,
    pub readback_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchEvidence {
    pub subscription_boot_id: String,
    pub subscription_established_at_ns: u64,
    pub start_request_at_ns: u64,
    pub start_reply_at_ns: Option<u64>,
    /// StartUnit returns the job object path; JobNew supplies the numeric job ID.
    pub returned_job_object_path: Option<String>,
    pub requested_unit_name: String,
    pub requested_mode: String,
    pub start_call_count: u32,
    /// Timestamp of the payload-release barrier, not a systemd manager signal.
    pub payload_released_at_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagerEvent {
    pub kind: ManagerEventKind,
    pub job_id: u32,
    pub job_object_path: String,
    pub unit_name: String,
    pub result: Option<String>,
    pub manager_boot_id: String,
    pub monotonic_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub unit_name: String,
    pub invocation_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub pidfd_mapped_unit_id: String,
    pub pidfd_mapped_invocation_id: String,
    pub manager_boot_id: String,
    pub identity_observed_at_ns: u64,
    pub identity_persisted_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitSnapshot {
    pub unit_name: String,
    pub invocation_id: String,
    pub manager_boot_id: String,
    pub observed_at_ns: u64,
    pub active_state: String,
    pub sub_state: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessReceipt {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub unit_name: String,
    pub invocation_id: String,
    pub manager_boot_id: String,
    pub exit_code: i32,
    pub exited_at_ns: u64,
    pub persisted_at_ns: u64,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixosPostState {
    pub kernel_boot_id: String,
    pub observed_at_ns: u64,
    /// Selected system profile / boot target. Distinct from /run/current-system:
    /// test and boot intentionally have different semantics.
    pub selected_profile_store_path: String,
    pub running_system_store_path: String,
    pub boot_default_store_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthObservation {
    pub check_id: String,
    pub target_store_path: String,
    pub kernel_boot_id: String,
    pub observed_at_ns: u64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidence {
    pub authorized: bool,
    pub recovery_attempt_id: String,
    pub authorization_digest: String,
    pub receipt_digest: String,
    pub exit_code: i32,
    pub completed_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafetyFence {
    pub actions_fenced: bool,
    pub fenced_at_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SystemdExecutionEvidence {
    pub schema: String,
    pub version: u32,
    pub binding: TransactionBinding,
    pub plan: OperationPlan,
    pub admission: AdmissionEvidence,
    pub dispatch: DispatchEvidence,
    /// Preserve source order. Never sort a malformed or reordered event stream.
    pub manager_events: Vec<ManagerEvent>,
    pub worker_identity: Option<WorkerIdentity>,
    pub unit_snapshot: Option<UnitSnapshot>,
    pub process_receipt: Option<ProcessReceipt>,
    pub post_state: Option<NixosPostState>,
    pub health_observations: Vec<HealthObservation>,
    pub recovery: Option<RecoveryEvidence>,
    pub safety_fence: SafetyFence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalClassification {
    VerifiedSuccess,
    VerifiedRecovery,
    ReconciliationRequired,
    SafeHold,
}

impl TerminalClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedSuccess => "verified-success",
            Self::VerifiedRecovery => "verified-recovery",
            Self::ReconciliationRequired => "reconciliation-required",
            Self::SafeHold => "safe-hold",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticEvaluation {
    pub schema: String,
    pub version: u32,
    pub classification: TerminalClassification,
    pub classification_basis: String,
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub correlated_job_id: Option<u32>,
    pub correlated_job_object_path: Option<String>,
    pub violations: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub operational_qualification: String,
}

#[derive(Debug, Default)]
struct Findings { violations: Vec<String>, missing: Vec<String> }

impl Findings {
    fn violation(&mut self, value: impl Into<String>) { self.violations.push(value.into()); }
    fn missing(&mut self, value: impl Into<String>) { self.missing.push(value.into()); }
    fn sort_dedup(&mut self) {
        self.violations.sort();
        self.violations.dedup();
        self.missing.sort();
        self.missing.dedup();
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_store_path(value: &str) -> bool {
    value.starts_with("/nix/store/") && value.len() > 11
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
}
fn nonempty(value: &str) -> bool { !value.trim().is_empty() }

fn validate_binding(e: &SystemdExecutionEvidence, f: &mut Findings) {
    let b = &e.binding;
    let a = &e.admission;
    for (name, value) in [
        ("transaction_id", b.transaction_id.as_str()),
        ("attempt_id", b.attempt_id.as_str()),
        ("admission_commit_id", b.admission_commit_id.as_str()),
        ("kernel_boot_id", b.kernel_boot_id.as_str()),
        ("systemd_version", b.systemd_version.as_str()),
    ] {
        if !nonempty(value) { f.violation(format!("binding.{name} is empty")); }
    }
    for (name, value) in [
        ("replay_key_digest", b.replay_key_digest.as_str()),
        ("permit_digest", b.permit_digest.as_str()),
        ("plan_digest", b.plan_digest.as_str()),
        ("machine_binding_digest", b.machine_binding_digest.as_str()),
    ] {
        if !is_digest(value) { f.violation(format!("binding.{name} is not a lowercase 32-byte hex digest")); }
    }
    for (name, expected, actual) in [
        ("transaction_id", b.transaction_id.as_str(), a.transaction_id.as_str()),
        ("attempt_id", b.attempt_id.as_str(), a.attempt_id.as_str()),
        ("admission_commit_id", b.admission_commit_id.as_str(), a.admission_commit_id.as_str()),
        ("replay_key_digest", b.replay_key_digest.as_str(), a.replay_key_digest.as_str()),
        ("permit_digest", b.permit_digest.as_str(), a.permit_digest.as_str()),
        ("plan_digest", b.plan_digest.as_str(), a.plan_digest.as_str()),
        ("machine_binding_digest", b.machine_binding_digest.as_str(), a.machine_binding_digest.as_str()),
    ] {
        if expected != actual { f.violation(format!("admission.{name} differs from transaction binding")); }
    }
    if a.committed_at_ns == 0 || a.readback_at_ns < a.committed_at_ns {
        f.violation("admission commit/read-back timestamps are invalid or reversed");
    }
    if !valid_store_path(&e.plan.candidate_store_path)
        || !valid_store_path(&e.plan.predecessor_store_path)
        || e.plan.candidate_store_path == e.plan.predecessor_store_path
    {
        f.violation("candidate and predecessor must be distinct immutable Nix store paths");
    }
    if [
        e.plan.unit_name.as_str(), e.plan.unit_start_mode.as_str(),
        e.plan.expected_unit_active_state.as_str(), e.plan.expected_unit_sub_state.as_str(),
        e.plan.expected_unit_result.as_str(),
    ].iter().any(|value| !nonempty(value)) {
        f.violation("plan unit identity or expected lifecycle contract is incomplete");
    }
    let mut ids = BTreeSet::new();
    for id in &e.plan.required_health_check_ids {
        if !nonempty(id) || !ids.insert(id.as_str()) {
            f.violation("required health-check IDs must be non-empty and unique");
        }
    }
    if e.safety_fence.actions_fenced && e.safety_fence.fenced_at_ns.is_none() {
        f.violation("actions_fenced is true but fenced_at_ns is absent");
    }
}

#[derive(Debug)]
struct CorrelatedJob {
    id: u32,
    path: String,
    result: String,
    job_new_at_ns: u64,
    job_removed_at_ns: u64,
}

fn validate_dispatch(e: &SystemdExecutionEvidence, f: &mut Findings) -> Option<CorrelatedJob> {
    let d = &e.dispatch;
    let boot = &e.binding.kernel_boot_id;
    if d.subscription_boot_id != *boot || !nonempty(&d.subscription_boot_id) {
        f.violation("JobRemoved subscription belongs to a different or unknown manager boot");
    }
    if d.subscription_established_at_ns <= e.admission.readback_at_ns {
        f.violation("JobRemoved subscription was not established after durable admission read-back");
    }
    if d.start_request_at_ns <= d.subscription_established_at_ns {
        f.violation("StartUnit request occurred before the JobRemoved subscription was established");
    }
    if d.requested_unit_name != e.plan.unit_name || d.requested_mode != e.plan.unit_start_mode {
        f.violation("StartUnit unit or mode differs from the approved plan");
    }
    if d.start_call_count != 1 {
        f.violation(format!("at-most-once dispatch invariant violated: StartUnit call count is {}", d.start_call_count));
    }
    if d.start_reply_at_ns.is_none() {
        f.missing("StartUnit reply is absent; manager acceptance is ambiguous");
        return None;
    }
    if d.start_reply_at_ns.is_some_and(|reply| reply < d.start_request_at_ns) {
        f.violation("StartUnit reply timestamp precedes its request");
    }
    let path = match d.returned_job_object_path.as_deref() {
        Some(value) if nonempty(value) => value.to_string(),
        _ => { f.missing("StartUnit did not preserve its returned job object path"); return None; }
    };
    for pair in e.manager_events.windows(2) {
        if pair[1].monotonic_at_ns <= pair[0].monotonic_at_ns {
            f.violation("raw manager event stream is not strictly monotonic");
        }
    }
    if e.manager_events.iter().any(|event| event.manager_boot_id != *boot) {
        f.violation("manager event stream contains an event from another boot identity");
    }
    // Other systemd jobs are normal concurrent activity; correlate by the exact
    // object path returned from this StartUnit request.
    let related = e.manager_events.iter().filter(|event| event.job_object_path == path).collect::<Vec<_>>();
    let news = related.iter().copied().filter(|event| event.kind == ManagerEventKind::JobNew).collect::<Vec<_>>();
    let removed = related.iter().copied().filter(|event| event.kind == ManagerEventKind::JobRemoved).collect::<Vec<_>>();
    if news.len() != 1 {
        if news.is_empty() { f.missing("no JobNew event matches the returned StartUnit job object path"); }
        else { f.violation("multiple JobNew events match one StartUnit job object path"); }
    }
    if removed.len() != 1 {
        if removed.is_empty() { f.missing("no JobRemoved event matches the returned StartUnit job object path"); }
        else { f.violation("multiple JobRemoved events match one StartUnit job object path"); }
    }
    if news.len() != 1 || removed.len() != 1 { return None; }
    let new = news[0];
    let done = removed[0];
    if new.job_id == 0 || new.job_id != done.job_id {
        f.violation("JobNew and JobRemoved numeric job IDs do not match");
    }
    if new.job_object_path != done.job_object_path
        || new.unit_name != done.unit_name
        || new.unit_name != d.requested_unit_name
    {
        f.violation("JobNew/JobRemoved object path or unit identity is inconsistent");
    }
    if new.manager_boot_id != *boot || done.manager_boot_id != *boot {
        f.violation("correlated systemd job belongs to another manager/kernel boot");
    }
    if new.monotonic_at_ns < d.start_request_at_ns
        || done.monotonic_at_ns <= new.monotonic_at_ns
    {
        f.violation("JobNew/JobRemoved event order or timestamps are invalid");
    }
    let result = match done.result.as_deref() {
        Some(value) if nonempty(value) => value.to_string(),
        _ => { f.missing("JobRemoved result is missing"); return None; }
    };
    Some(CorrelatedJob { id: new.job_id, path, result, job_new_at_ns: new.monotonic_at_ns, job_removed_at_ns: done.monotonic_at_ns })
}

fn validate_worker_and_receipt(e: &SystemdExecutionEvidence, job_new_at_ns: u64, f: &mut Findings) -> Option<i32> {
    let worker = match e.worker_identity.as_ref() {
        Some(value) => value,
        None => { f.missing("PIDFD-derived worker identity is missing"); return None; }
    };
    let b = &e.binding;
    for (name, actual, expected) in [
        ("transaction_id", worker.transaction_id.as_str(), b.transaction_id.as_str()),
        ("attempt_id", worker.attempt_id.as_str(), b.attempt_id.as_str()),
        ("admission_commit_id", worker.admission_commit_id.as_str(), b.admission_commit_id.as_str()),
        ("plan_digest", worker.plan_digest.as_str(), b.plan_digest.as_str()),
        ("machine_binding_digest", worker.machine_binding_digest.as_str(), b.machine_binding_digest.as_str()),
    ] {
        if actual != expected { f.violation(format!("worker identity {name} is foreign to this admission")); }
    }
    if worker.unit_name != e.plan.unit_name || worker.pidfd_mapped_unit_id != e.plan.unit_name {
        f.violation("PIDFD-derived unit identity differs from the approved worker unit");
    }
    if !nonempty(&worker.invocation_id) || worker.pidfd_mapped_invocation_id != worker.invocation_id {
        f.violation("PIDFD-derived InvocationID differs from the persisted worker identity");
    }
    if worker.manager_boot_id != b.kernel_boot_id {
        f.violation("worker identity belongs to another manager/kernel boot");
    }
    if worker.pid == 0 || worker.process_start_ticks == 0 {
        f.violation("worker identity lacks a valid PID/process-start tuple");
    }
    if worker.identity_observed_at_ns < job_new_at_ns
        || worker.identity_persisted_at_ns < worker.identity_observed_at_ns
        || worker.identity_persisted_at_ns <= e.admission.readback_at_ns
    {
        f.violation("worker identity observation/persistence timestamps are invalid");
    }
    let release_at = match e.dispatch.payload_released_at_ns {
        Some(value) => value,
        None => { f.missing("payload-release barrier timestamp is missing"); return None; }
    };
    if release_at <= worker.identity_persisted_at_ns {
        f.violation("payload released before durable worker identity persistence");
    }
    let receipt = match e.process_receipt.as_ref() {
        Some(value) => value,
        None => { f.missing("durable process receipt is missing"); return None; }
    };
    for (name, actual, expected) in [
        ("transaction_id", receipt.transaction_id.as_str(), b.transaction_id.as_str()),
        ("attempt_id", receipt.attempt_id.as_str(), b.attempt_id.as_str()),
        ("admission_commit_id", receipt.admission_commit_id.as_str(), b.admission_commit_id.as_str()),
        ("plan_digest", receipt.plan_digest.as_str(), b.plan_digest.as_str()),
        ("machine_binding_digest", receipt.machine_binding_digest.as_str(), b.machine_binding_digest.as_str()),
    ] {
        if actual != expected { f.violation(format!("process receipt {name} is foreign to this admission")); }
    }
    if receipt.unit_name != worker.unit_name
        || receipt.invocation_id != worker.invocation_id
        || receipt.manager_boot_id != b.kernel_boot_id
    {
        f.violation("process receipt unit, InvocationID or boot identity differs from PIDFD attribution");
    }
    if !is_digest(&receipt.receipt_digest) {
        f.violation("process receipt digest is malformed");
    }
    if receipt.exited_at_ns <= release_at || receipt.persisted_at_ns < receipt.exited_at_ns {
        f.violation("process receipt timestamps do not follow payload release");
    }
    Some(receipt.exit_code)
}

fn validate_unit_snapshot(e: &SystemdExecutionEvidence, job: &CorrelatedJob, successful_job: bool, f: &mut Findings) {
    let snapshot = match e.unit_snapshot.as_ref() {
        Some(value) => value,
        None => { f.missing("post-job unit property snapshot is missing"); return; }
    };
    let worker = match e.worker_identity.as_ref() {
        Some(value) => value,
        None => return,
    };
    if snapshot.unit_name != e.plan.unit_name
        || snapshot.unit_name != worker.unit_name
        || snapshot.invocation_id != worker.invocation_id
        || snapshot.manager_boot_id != e.binding.kernel_boot_id
    {
        f.violation("unit property snapshot is foreign to the correlated worker invocation");
    }
    if snapshot.observed_at_ns <= job.job_removed_at_ns {
        f.violation("unit property snapshot predates or coincides with JobRemoved");
    }
    if successful_job {
        if snapshot.active_state != e.plan.expected_unit_active_state
            || snapshot.sub_state != e.plan.expected_unit_sub_state
            || snapshot.result != e.plan.expected_unit_result
        {
            f.violation("unit property snapshot differs from the approved service-type lifecycle contract");
        }
    } else if !nonempty(&snapshot.result) {
        f.missing("failed invocation unit snapshot omitted its systemd Result");
    }
}

fn expected_success_state(operation: NixosOperation, plan: &OperationPlan) -> (&str, &str, &str) {
    match operation {
        NixosOperation::Switch => (&plan.candidate_store_path, &plan.candidate_store_path, &plan.candidate_store_path),
        NixosOperation::Test => (&plan.predecessor_store_path, &plan.candidate_store_path, &plan.predecessor_store_path),
        NixosOperation::Boot => (&plan.candidate_store_path, &plan.predecessor_store_path, &plan.candidate_store_path),
    }
}

fn validate_post_state(e: &SystemdExecutionEvidence, expected_profile: &str, expected_running: &str, expected_boot: &str, not_before_ns: u64, f: &mut Findings) {
    let state = match e.post_state.as_ref() {
        Some(value) => value,
        None => { f.missing("independent NixOS post-state observation is missing"); return; }
    };
    if state.kernel_boot_id != e.binding.kernel_boot_id {
        f.violation("NixOS post-state belongs to another kernel boot");
    }
    if state.observed_at_ns <= not_before_ns {
        f.violation("NixOS post-state observation predates required lifecycle evidence");
    }
    if state.selected_profile_store_path != expected_profile
        || state.running_system_store_path != expected_running
        || state.boot_default_store_path != expected_boot
    {
        f.violation(format!(
            "NixOS {:?} post-state mismatch: selected={}, running={}, boot-default={}",
            e.plan.operation, state.selected_profile_store_path,
            state.running_system_store_path, state.boot_default_store_path
        ));
    }
}

fn validate_health(e: &SystemdExecutionEvidence, target: &str, not_before_ns: u64, f: &mut Findings) -> bool {
    let required = e.plan.required_health_check_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut observations = BTreeMap::new();
    for observation in &e.health_observations {
        if observations.insert(observation.check_id.clone(), observation).is_some() {
            f.violation(format!("duplicate runtime health observation {}", observation.check_id));
        }
    }
    for id in &required {
        let item = match observations.get(id) {
            Some(value) => value,
            None => { f.missing(format!("runtime health observation {id} is missing")); continue; }
        };
        if item.target_store_path != target
            || item.kernel_boot_id != e.binding.kernel_boot_id
            || item.observed_at_ns < not_before_ns
        {
            f.violation(format!("runtime health observation {id} is not bound to expected target/boot/time"));
        }
        if !item.passed { f.violation(format!("runtime health check {id} failed")); }
    }
    for id in observations.keys() {
        if !required.contains(id) { f.violation(format!("unexpected runtime health observation {id}")); }
    }
    required.len() == observations.len()
        && required.iter().all(|id| observations.get(id).is_some_and(|item| item.passed))
}

fn validate_recovery(e: &SystemdExecutionEvidence, job: &CorrelatedJob, f: &mut Findings) -> bool {
    let recovery = match e.recovery.as_ref() {
        Some(value) => value,
        None => { f.missing("failed activation has no separately authorized recovery evidence"); return false; }
    };
    if !recovery.authorized
        || !nonempty(&recovery.recovery_attempt_id)
        || recovery.recovery_attempt_id == e.binding.attempt_id
        || !is_digest(&recovery.authorization_digest)
        || !is_digest(&recovery.receipt_digest)
        || recovery.exit_code != 0
        || recovery.completed_at_ns <= job.job_removed_at_ns
    {
        f.violation("recovery authorization, attempt, receipt, exit status or timestamp is invalid");
        return false;
    }
    let predecessor = &e.plan.predecessor_store_path;
    validate_post_state(e, predecessor, predecessor, predecessor, recovery.completed_at_ns, f);
    validate_health(e, predecessor, recovery.completed_at_ns, f)
}

fn classify(e: &SystemdExecutionEvidence, f: &mut Findings) -> (TerminalClassification, String, Option<u32>, Option<String>) {
    validate_binding(e, f);
    let job = match validate_dispatch(e, f) {
        Some(value) => value,
        None => {
            f.sort_dedup();
            if e.safety_fence.actions_fenced && e.safety_fence.fenced_at_ns.is_some() {
                return (TerminalClassification::SafeHold,
                    "dispatch evidence is incomplete or ambiguous and further actions are explicitly fenced".into(),
                    None, e.dispatch.returned_job_object_path.clone());
            }
            return (TerminalClassification::ReconciliationRequired,
                "dispatch/job correlation is incomplete or ambiguous".into(),
                None, e.dispatch.returned_job_object_path.clone());
        }
    };

    let exit_code = validate_worker_and_receipt(e, job.job_new_at_ns, f);
    let successful_job = job.result == "done";
    validate_unit_snapshot(e, &job, successful_job, f);

    if successful_job {
        if exit_code != Some(0) {
            f.missing("JobRemoved=done requires a matching zero-exit worker receipt");
        }
        let receipt_time = e.process_receipt.as_ref().map(|value| value.persisted_at_ns).unwrap_or(job.job_removed_at_ns);
        let (profile, running, boot) = expected_success_state(e.plan.operation, &e.plan);
        validate_post_state(e, profile, running, boot, receipt_time, f);
        let post_at = e.post_state.as_ref().map(|value| value.observed_at_ns).unwrap_or(0);
        let health_ok = validate_health(e, &e.plan.candidate_store_path, post_at, f);
        f.sort_dedup();
        if f.violations.is_empty() && f.missing.is_empty() && health_ok {
            return (TerminalClassification::VerifiedSuccess,
                "exact admission, single correlated systemd job, PIDFD-derived worker identity, durable receipt, operation-specific NixOS state and required health checks agree".into(),
                Some(job.id), Some(job.path));
        }
    } else {
        if !["failed", "timeout", "canceled", "dependency", "skipped"].contains(&job.result.as_str()) {
            f.violation(format!("unknown JobRemoved result {}", job.result));
        }
        if exit_code == Some(0) { f.violation("failed systemd job has a zero-exit worker receipt"); }
        let recovered = validate_recovery(e, &job, f);
        f.sort_dedup();
        if recovered && f.violations.is_empty() && f.missing.is_empty() {
            return (TerminalClassification::VerifiedRecovery,
                "failed activation is followed by separately authorized recovery, a matching recovery receipt, verified predecessor state and passing predecessor health checks".into(),
                Some(job.id), Some(job.path));
        }
    }

    f.sort_dedup();
    if e.safety_fence.actions_fenced && e.safety_fence.fenced_at_ns.is_some() {
        (TerminalClassification::SafeHold,
            "inconsistent or incomplete execution evidence is fenced; no further mutation is authorized".into(),
            Some(job.id), Some(job.path))
    } else {
        (TerminalClassification::ReconciliationRequired,
            "execution may have occurred, but its exact terminal state is not independently established".into(),
            Some(job.id), Some(job.path))
    }
}

pub fn evaluate_json(input: &str) -> Result<SemanticEvaluation, String> {
    let evidence: SystemdExecutionEvidence =
        serde_json::from_str(input).map_err(|error| format!("invalid systemd evidence JSON: {error}"))?;
    evaluate(&evidence)
}

pub fn evaluate(evidence: &SystemdExecutionEvidence) -> Result<SemanticEvaluation, String> {
    if evidence.schema != EVIDENCE_SCHEMA || evidence.version != EVIDENCE_VERSION {
        return Err("unsupported systemd execution evidence schema/version".into());
    }
    let mut findings = Findings::default();
    let (classification, basis, correlated_job_id, correlated_job_object_path) = classify(evidence, &mut findings);
    findings.sort_dedup();
    Ok(SemanticEvaluation {
        schema: "org.luminousdynamics.nixward.systemd-semantic-evaluation".into(),
        version: 1,
        classification,
        classification_basis: basis,
        transaction_id: evidence.binding.transaction_id.clone(),
        attempt_id: evidence.binding.attempt_id.clone(),
        admission_commit_id: evidence.binding.admission_commit_id.clone(),
        correlated_job_id,
        correlated_job_object_path,
        violations: findings.violations,
        missing_evidence: findings.missing,
        operational_qualification: "semantic-consistency-only-source-authentication-unverified".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn digest(ch: char) -> String { std::iter::repeat(ch).take(64).collect() }

    fn valid_evidence(operation: NixosOperation) -> SystemdExecutionEvidence {
        let boot = "boot-id-001".to_string();
        let candidate = "/nix/store/aaaaaaaaaaaaaaaa-system".to_string();
        let predecessor = "/nix/store/bbbbbbbbbbbbbbbb-system".to_string();
        let (selected, running, boot_default) = match operation {
            NixosOperation::Switch => (candidate.clone(), candidate.clone(), candidate.clone()),
            NixosOperation::Test => (predecessor.clone(), candidate.clone(), predecessor.clone()),
            NixosOperation::Boot => (candidate.clone(), predecessor.clone(), candidate.clone()),
        };
        SystemdExecutionEvidence {
            schema: EVIDENCE_SCHEMA.into(), version: EVIDENCE_VERSION,
            binding: TransactionBinding {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(),
                admission_commit_id: "commit-1".into(), replay_key_digest: digest('1'),
                permit_digest: digest('2'), plan_digest: digest('3'), machine_binding_digest: digest('4'),
                kernel_boot_id: boot.clone(), systemd_version: "systemd-262".into(),
            },
            plan: OperationPlan {
                operation, unit_name: "nixward-worker@attempt-1.service".into(),
                unit_start_mode: "replace".into(), expected_unit_active_state: "inactive".into(),
                expected_unit_sub_state: "dead".into(), expected_unit_result: "success".into(),
                candidate_store_path: candidate.clone(), predecessor_store_path: predecessor,
                required_health_check_ids: vec!["system-health".into(), "service-health".into()],
            },
            admission: AdmissionEvidence {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(), admission_commit_id: "commit-1".into(),
                replay_key_digest: digest('1'), permit_digest: digest('2'), plan_digest: digest('3'),
                machine_binding_digest: digest('4'), committed_at_ns: 100, readback_at_ns: 110,
            },
            dispatch: DispatchEvidence {
                subscription_boot_id: boot.clone(), subscription_established_at_ns: 120,
                start_request_at_ns: 130, start_reply_at_ns: Some(145),
                returned_job_object_path: Some("/org/freedesktop/systemd1/job/77".into()),
                requested_unit_name: "nixward-worker@attempt-1.service".into(),
                requested_mode: "replace".into(), start_call_count: 1, payload_released_at_ns: Some(180),
            },
            manager_events: vec![
                ManagerEvent { kind: ManagerEventKind::JobNew, job_id: 77,
                    job_object_path: "/org/freedesktop/systemd1/job/77".into(),
                    unit_name: "nixward-worker@attempt-1.service".into(), result: None,
                    manager_boot_id: boot.clone(), monotonic_at_ns: 135 },
                ManagerEvent { kind: ManagerEventKind::JobRemoved, job_id: 77,
                    job_object_path: "/org/freedesktop/systemd1/job/77".into(),
                    unit_name: "nixward-worker@attempt-1.service".into(), result: Some("done".into()),
                    manager_boot_id: boot.clone(), monotonic_at_ns: 195 },
            ],
            worker_identity: Some(WorkerIdentity {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(), admission_commit_id: "commit-1".into(),
                plan_digest: digest('3'), machine_binding_digest: digest('4'),
                unit_name: "nixward-worker@attempt-1.service".into(), invocation_id: "invocation-77".into(),
                pid: 772, process_start_ticks: 9001, pidfd_mapped_unit_id: "nixward-worker@attempt-1.service".into(),
                pidfd_mapped_invocation_id: "invocation-77".into(), manager_boot_id: boot.clone(),
                identity_observed_at_ns: 150, identity_persisted_at_ns: 160,
            }),
            unit_snapshot: Some(UnitSnapshot {
                unit_name: "nixward-worker@attempt-1.service".into(), invocation_id: "invocation-77".into(),
                manager_boot_id: boot.clone(), observed_at_ns: 205, active_state: "inactive".into(),
                sub_state: "dead".into(), result: "success".into(),
            }),
            process_receipt: Some(ProcessReceipt {
                transaction_id: "txn-1".into(), attempt_id: "attempt-1".into(), admission_commit_id: "commit-1".into(),
                plan_digest: digest('3'), machine_binding_digest: digest('4'),
                unit_name: "nixward-worker@attempt-1.service".into(), invocation_id: "invocation-77".into(),
                manager_boot_id: boot.clone(), exit_code: 0, exited_at_ns: 190, persisted_at_ns: 200, receipt_digest: digest('5'),
            }),
            post_state: Some(NixosPostState {
                kernel_boot_id: boot.clone(), observed_at_ns: 210,
                selected_profile_store_path: selected, running_system_store_path: running, boot_default_store_path: boot_default,
            }),
            health_observations: vec![
                HealthObservation { check_id: "system-health".into(), target_store_path: candidate.clone(),
                    kernel_boot_id: boot.clone(), observed_at_ns: 220, passed: true },
                HealthObservation { check_id: "service-health".into(), target_store_path: candidate,
                    kernel_boot_id: boot, observed_at_ns: 221, passed: true },
            ],
            recovery: None, safety_fence: SafetyFence { actions_fenced: false, fenced_at_ns: None },
        }
    }

    fn eval(e: &SystemdExecutionEvidence) -> SemanticEvaluation { evaluate(e).unwrap() }

    #[test]
    fn derives_success_for_switch_test_and_boot() {
        for op in [NixosOperation::Switch, NixosOperation::Test, NixosOperation::Boot] {
            let result = eval(&valid_evidence(op));
            assert_eq!(result.classification, TerminalClassification::VerifiedSuccess);
            assert!(result.violations.is_empty());
            assert!(result.missing_evidence.is_empty());
        }
    }
    #[test]
    fn job_done_with_wrong_post_state_is_not_success() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.post_state.as_mut().unwrap().running_system_store_path = e.plan.predecessor_store_path.clone();
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
    }
    #[test]
    fn test_must_not_change_boot_default() {
        let mut e = valid_evidence(NixosOperation::Test);
        e.post_state.as_mut().unwrap().boot_default_store_path = e.plan.candidate_store_path.clone();
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
    }
    #[test]
    fn boot_must_not_activate_candidate_in_running_system() {
        let mut e = valid_evidence(NixosOperation::Boot);
        e.post_state.as_mut().unwrap().running_system_store_path = e.plan.candidate_store_path.clone();
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
    }
    #[test]
    fn lost_startunit_reply_is_reconciliation_or_safe_hold_never_success() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.dispatch.start_reply_at_ns = None;
        e.dispatch.returned_job_object_path = None;
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
        e.safety_fence = SafetyFence { actions_fenced: true, fenced_at_ns: Some(150) };
        assert_eq!(eval(&e).classification, TerminalClassification::SafeHold);
    }
    #[test]
    fn subscription_must_precede_startunit() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.dispatch.subscription_established_at_ns = 140;
        let result = eval(&e);
        assert_ne!(result.classification, TerminalClassification::VerifiedSuccess);
        assert!(result.violations.iter().any(|item| item.contains("before the JobRemoved subscription")));
    }
    #[test]
    fn mismatched_job_id_does_not_close_the_attempt() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.manager_events[1].job_id = 78;
        let result = eval(&e);
        assert_eq!(result.classification, TerminalClassification::ReconciliationRequired);
        assert!(result.violations.iter().any(|item| item.contains("numeric job IDs")));
    }
    #[test]
    fn pidfd_invocation_mismatch_cannot_prove_worker_identity() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.worker_identity.as_mut().unwrap().pidfd_mapped_invocation_id = "foreign-invocation".into();
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
    }
    #[test]
    fn foreign_worker_transaction_is_a_safety_violation() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.worker_identity.as_mut().unwrap().transaction_id = "foreign-txn".into();
        e.safety_fence = SafetyFence { actions_fenced: true, fenced_at_ns: Some(180) };
        let result = eval(&e);
        assert_eq!(result.classification, TerminalClassification::SafeHold);
        assert!(result.violations.iter().any(|item| item.contains("foreign to this admission")));
    }
    #[test]
    fn payload_release_before_persisted_worker_identity_is_never_success() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.dispatch.payload_released_at_ns = Some(155);
        assert_eq!(eval(&e).classification, TerminalClassification::ReconciliationRequired);
    }
    #[test]
    fn duplicate_startunit_calls_force_safe_hold() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.dispatch.start_call_count = 2;
        e.safety_fence = SafetyFence { actions_fenced: true, fenced_at_ns: Some(180) };
        assert_eq!(eval(&e).classification, TerminalClassification::SafeHold);
    }
    #[test]
    fn strict_json_rejects_unknown_fields() {
        let e = valid_evidence(NixosOperation::Switch);
        let mut value = serde_json::to_value(e).unwrap();
        value["unexpected_trust_me"] = serde_json::json!(true);
        assert!(evaluate_json(&serde_json::to_string(&value).unwrap()).is_err());
    }
    #[test]
    fn negative_job_result_requires_authorized_and_observed_recovery() {
        let mut e = valid_evidence(NixosOperation::Switch);
        e.manager_events[1].result = Some("failed".into());
        e.process_receipt.as_mut().unwrap().exit_code = 1;
        e.recovery = Some(RecoveryEvidence {
            authorized: true, recovery_attempt_id: "recovery-attempt-2".into(),
            authorization_digest: digest('6'), receipt_digest: digest('7'), exit_code: 0, completed_at_ns: 230,
        });
        let predecessor = e.plan.predecessor_store_path.clone();
        let state = e.post_state.as_mut().unwrap();
        state.selected_profile_store_path = predecessor.clone();
        state.running_system_store_path = predecessor.clone();
        state.boot_default_store_path = predecessor.clone();
        state.observed_at_ns = 240;
        for item in &mut e.health_observations {
            item.target_store_path = predecessor.clone();
            item.observed_at_ns = 250;
        }
        assert_eq!(eval(&e).classification, TerminalClassification::VerifiedRecovery);
    }
}
