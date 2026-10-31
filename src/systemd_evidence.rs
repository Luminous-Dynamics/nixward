// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure, read-only semantic verification of systemd-supervised NixOS changes.
//! This module checks captured evidence consistency; it does not authenticate
//! the capture source or perform D-Bus/filesystem operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EVIDENCE_SCHEMA: &str = "org.luminousdynamics.nixward.systemd-execution-evidence";
pub const EVIDENCE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode { Switch, Test, Boot }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind { JobNew, JobRemoved }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobResult {
    #[serde(rename = "done")] Done,
    #[serde(rename = "canceled")] Canceled,
    #[serde(rename = "timeout")] Timeout,
    #[serde(rename = "failed")] Failed,
    #[serde(rename = "dependency")] Dependency,
    #[serde(rename = "skipped")] Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBinding {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub replay_key: String,
    pub permit_digest: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProvenanceBinding {
    pub policy_id: String,
    pub policy_digest: String,
    pub policy_epoch: u64,
    pub issuer: String,
    pub signer_key_id: String,
    pub action: String,
    pub audience: String,
    pub subject_digest: String,
    pub challenge_digest: String,
    pub replay_key: String,
    pub evidence_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartUnitReply {
    pub job_object_path: String,
    pub unit_name: String,
    pub received_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerEvent {
    pub kind: EventKind,
    pub job_id: u64,
    pub job_object_path: String,
    pub unit_name: String,
    pub result: Option<JobResult>,
    pub monotonic_ns: u64,
    pub manager_boot_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerLookupMethod { GetUnitByPidfd, GetUnitByPid }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    pub binding: TransactionBinding,
    pub lookup_method: WorkerLookupMethod,
    pub unit_name: String,
    pub unit_object_path: String,
    pub invocation_id: String,
    pub manager_boot_id: String,
    pub kernel_boot_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub observed_monotonic_ns: u64,
    pub persisted_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSnapshot {
    pub unit_name: String,
    pub unit_object_path: String,
    pub invocation_id: String,
    pub manager_boot_id: String,
    pub service_type: String,
    pub active_state: String,
    pub sub_state: String,
    pub result: String,
    pub exec_main_status: i32,
    pub observed_monotonic_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadReceipt {
    pub binding: TransactionBinding,
    pub unit_name: String,
    pub invocation_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub released_monotonic_ns: u64,
    pub exited_monotonic_ns: u64,
    pub persisted_monotonic_ns: u64,
    pub exit_status: i32,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSource {
    pub name: String,
    pub sha256: String,
    pub boot_id: String,
    pub observed_monotonic_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth { Healthy, Unhealthy, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStateObservation {
    pub binding: TransactionBinding,
    pub boot_id: String,
    pub observed_monotonic_ns: u64,
    pub active_profile_store_path: String,
    pub running_system_store_path: String,
    pub boot_default_store_path: String,
    pub runtime_health: RuntimeHealth,
    pub sources: Vec<ObservationSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdExecutionEvidence {
    pub schema: String,
    pub version: u32,
    pub binding: TransactionBinding,
    pub authority: AuthorityProvenanceBinding,
    pub expected_authority_subject_digest: String,
    pub operation: OperationMode,
    pub expected_unit: String,
    pub candidate_store_path: String,
    pub predecessor_store_path: String,
    pub manager_boot_id: String,
    pub kernel_boot_id: String,
    pub admission_committed_monotonic_ns: u64,
    pub subscription_established_monotonic_ns: u64,
    pub start_requested_monotonic_ns: u64,
    pub start_unit_reply: Option<StartUnitReply>,
    /// Preserve capture order; the verifier never sorts manager events.
    pub manager_events: Vec<ManagerEvent>,
    pub worker_identity: Option<WorkerIdentity>,
    pub unit_snapshot: Option<UnitSnapshot>,
    pub payload_receipt: Option<PayloadReceipt>,
    pub host_state: Option<HostStateObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    VerifiedSuccess,
    VerifiedRecovery,
    ReconciliationRequired,
    SafeHold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub schema: String,
    pub version: u32,
    pub outcome: TerminalOutcome,
    pub reasons: Vec<String>,
    pub matched_job_id: Option<u64>,
    pub matched_invocation_id: Option<String>,
}

fn report(outcome: TerminalOutcome, reason: impl Into<String>, job: Option<u64>, invocation: Option<String>) -> VerificationReport {
    VerificationReport {
        schema: "org.luminousdynamics.nixward.systemd-execution-verification".into(),
        version: 1,
        outcome,
        reasons: vec![reason.into()],
        matched_job_id: job,
        matched_invocation_id: invocation,
    }
}
fn hold(reason: impl Into<String>, job: Option<u64>, invocation: Option<String>) -> VerificationReport {
    report(TerminalOutcome::SafeHold, reason, job, invocation)
}
fn reconcile(reason: impl Into<String>, job: Option<u64>, invocation: Option<String>) -> VerificationReport {
    report(TerminalOutcome::ReconciliationRequired, reason, job, invocation)
}
fn digest_ok(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn store_path_ok(value: &str) -> bool {
    value.starts_with("/nix/store/") && value.len() > 11
        && !value.split('/').any(|part| part == "." || part == "..")
        && !value.chars().any(char::is_whitespace)
}
fn binding_ok(binding: &TransactionBinding) -> bool {
    [
        binding.transaction_id.as_str(), binding.attempt_id.as_str(),
        binding.admission_commit_id.as_str(), binding.replay_key.as_str(),
        binding.permit_digest.as_str(), binding.plan_digest.as_str(),
        binding.machine_binding_digest.as_str(),
    ].into_iter().all(digest_ok)
}
fn source_set_ok(host: &HostStateObservation, boot_id: &str) -> bool {
    const REQUIRED: [&str; 4] = ["system_profile", "running_system", "boot_default", "runtime_health"];
    if host.sources.len() != REQUIRED.len() { return false; }
    let mut seen = BTreeSet::new();
    for source in &host.sources {
        if !REQUIRED.contains(&source.name.as_str()) || !seen.insert(source.name.as_str())
            || !digest_ok(&source.sha256) || source.boot_id != boot_id
            || source.observed_monotonic_ns > host.observed_monotonic_ns {
            return false;
        }
    }
    REQUIRED.iter().all(|name| seen.contains(name))
}
fn expected_paths<'a>(mode: OperationMode, candidate: &'a str, predecessor: &'a str) -> (&'a str, &'a str, &'a str) {
    match mode {
        OperationMode::Switch => (candidate, candidate, candidate),
        OperationMode::Test => (predecessor, candidate, predecessor),
        OperationMode::Boot => (candidate, predecessor, candidate),
    }
}
fn host_matches_success(host: &HostStateObservation, mode: OperationMode, candidate: &str, predecessor: &str) -> bool {
    let (profile, running, boot) = expected_paths(mode, candidate, predecessor);
    host.active_profile_store_path == profile
        && host.running_system_store_path == running
        && host.boot_default_store_path == boot
        && host.active_profile_store_path == host.boot_default_store_path
}
fn host_is_predecessor(host: &HostStateObservation, predecessor: &str) -> bool {
    host.active_profile_store_path == predecessor
        && host.running_system_store_path == predecessor
        && host.boot_default_store_path == predecessor
}

/// Derive one terminal disposition from captured evidence. This checks
/// consistency, not signature authenticity, D-Bus peer identity or host capture
/// provenance. Those require a separately trusted capture/verification layer.
pub fn verify_execution(e: &SystemdExecutionEvidence) -> VerificationReport {
    if e.schema != EVIDENCE_SCHEMA || e.version != EVIDENCE_VERSION {
        return hold("unsupported evidence schema/version", None, None);
    }
    if !binding_ok(&e.binding) {
        return hold("transaction binding contains malformed digests", None, None);
    }
    let a = &e.authority;
    if a.policy_id.trim().is_empty() || a.issuer.trim().is_empty() || a.signer_key_id.trim().is_empty()
        || a.policy_epoch == 0 || !digest_ok(&a.policy_digest) || !digest_ok(&a.subject_digest)
        || !digest_ok(&a.challenge_digest) || !digest_ok(&a.replay_key) || !digest_ok(&a.evidence_digest)
        || a.replay_key != e.binding.replay_key || a.subject_digest != e.expected_authority_subject_digest
        || !digest_ok(&e.expected_authority_subject_digest) || a.action != "change"
        || !["nixward-change-v1", "nixward-execution-intent-v1"].contains(&a.audience.as_str())
        || a.expires_at_ms <= a.issued_at_ms {
        return hold("authority provenance binding is incomplete or inconsistent", None, None);
    }
    if e.expected_unit.trim().is_empty() || e.manager_boot_id.trim().is_empty() || e.kernel_boot_id.trim().is_empty()
        || !store_path_ok(&e.candidate_store_path) || !store_path_ok(&e.predecessor_store_path)
        || e.candidate_store_path == e.predecessor_store_path {
        return hold("unit, boot identity or candidate/predecessor closure is invalid", None, None);
    }
    if e.admission_committed_monotonic_ns == 0
        || e.subscription_established_monotonic_ns <= e.admission_committed_monotonic_ns
        || e.start_requested_monotonic_ns <= e.subscription_established_monotonic_ns {
        return hold("durable admission and D-Bus subscription must precede StartUnit", None, None);
    }
    let Some(reply) = &e.start_unit_reply else {
        return reconcile("StartUnit reply missing; manager acceptance is ambiguous", None, None);
    };
    if reply.unit_name != e.expected_unit
        || !reply.job_object_path.starts_with("/org/freedesktop/systemd1/job/")
        || reply.received_monotonic_ns < e.start_requested_monotonic_ns {
        return hold("StartUnit reply is not bound to requested unit/job", None, None);
    }

    let mut prior_event_ns = None;
    for event in &e.manager_events {
        if prior_event_ns.is_some_and(|prior| event.monotonic_ns < prior) {
            return hold("manager event capture order is not monotonic", None, None);
        }
        prior_event_ns = Some(event.monotonic_ns);
        if event.manager_boot_id != e.manager_boot_id {
            return hold("manager event belongs to a different manager boot", None, None);
        }
        if event.job_object_path == reply.job_object_path && event.unit_name != e.expected_unit {
            return hold("returned job object path is attributed to a foreign unit", Some(event.job_id), None);
        }
        match (event.kind, event.result) {
            (EventKind::JobNew, None) | (EventKind::JobRemoved, Some(_)) => {}
            _ => return hold("manager event kind/result shape is invalid", None, None),
        }
    }
    let target = e.manager_events.iter().filter(|event| event.job_object_path == reply.job_object_path).collect::<Vec<_>>();
    let news = target.iter().filter(|event| event.kind == EventKind::JobNew).collect::<Vec<_>>();
    let removed = target.iter().filter(|event| event.kind == EventKind::JobRemoved).collect::<Vec<_>>();
    if news.is_empty() || removed.is_empty() {
        return reconcile("matching JobNew or JobRemoved is missing", None, None);
    }
    if news.len() != 1 || removed.len() != 1 {
        return hold("duplicate manager lifecycle events for returned job", None, None);
    }
    let new = news[0];
    let gone = removed[0];
    let job_id = new.job_id;
    let Some(job_result) = gone.result else {
        return hold("JobRemoved has no result", Some(job_id), None);
    };
    if new.job_id != gone.job_id || new.unit_name != e.expected_unit || gone.unit_name != e.expected_unit
        || new.monotonic_ns < e.start_requested_monotonic_ns || gone.monotonic_ns < new.monotonic_ns {
        return hold("JobNew/JobRemoved identity or ordering mismatch", Some(job_id), None);
    }

    let Some(worker) = &e.worker_identity else {
        return reconcile("PIDFD-derived worker identity is missing", Some(job_id), None);
    };
    let Some(receipt) = &e.payload_receipt else {
        return reconcile("durable payload receipt is missing", Some(job_id), Some(worker.invocation_id.clone()));
    };
    let Some(snapshot) = &e.unit_snapshot else {
        return reconcile("final unit snapshot is missing", Some(job_id), Some(worker.invocation_id.clone()));
    };
    let Some(host) = &e.host_state else {
        return reconcile("independent host post-state observation is missing", Some(job_id), Some(worker.invocation_id.clone()));
    };
    let invocation = Some(worker.invocation_id.clone());

    if worker.binding != e.binding || receipt.binding != e.binding || host.binding != e.binding {
        return hold("worker, receipt or host observation is bound to a foreign transaction", Some(job_id), invocation);
    }
    if worker.lookup_method != WorkerLookupMethod::GetUnitByPidfd || worker.unit_name != e.expected_unit
        || !worker.unit_object_path.starts_with("/org/freedesktop/systemd1/unit/")
        || worker.invocation_id.trim().is_empty() || worker.manager_boot_id != e.manager_boot_id
        || worker.kernel_boot_id != e.kernel_boot_id || worker.pid == 0 || worker.process_start_ticks == 0 {
        return hold("worker identity is not a valid PIDFD-to-unit attribution", Some(job_id), invocation);
    }
    if worker.observed_monotonic_ns < new.monotonic_ns
        || worker.persisted_monotonic_ns < worker.observed_monotonic_ns
        || receipt.released_monotonic_ns < worker.persisted_monotonic_ns
        || receipt.exited_monotonic_ns < receipt.released_monotonic_ns
        || receipt.persisted_monotonic_ns < receipt.exited_monotonic_ns {
        return hold("worker identity must be durably persisted before payload release/exit", Some(job_id), invocation);
    }
    if receipt.unit_name != e.expected_unit || receipt.invocation_id != worker.invocation_id
        || receipt.pid != worker.pid || receipt.process_start_ticks != worker.process_start_ticks
        || !digest_ok(&receipt.receipt_sha256) {
        return hold("payload receipt does not match the exact worker invocation", Some(job_id), invocation);
    }
    if snapshot.unit_name != e.expected_unit || snapshot.unit_object_path != worker.unit_object_path
        || snapshot.invocation_id != worker.invocation_id || snapshot.manager_boot_id != e.manager_boot_id
        || snapshot.service_type != "oneshot" || snapshot.observed_monotonic_ns < gone.monotonic_ns
        || snapshot.observed_monotonic_ns < receipt.persisted_monotonic_ns {
        return hold("unit snapshot does not describe exact completed oneshot invocation", Some(job_id), invocation);
    }
    if host.boot_id != e.kernel_boot_id
        || host.observed_monotonic_ns < snapshot.observed_monotonic_ns
        || host.observed_monotonic_ns < reply.received_monotonic_ns
        || !store_path_ok(&host.active_profile_store_path) || !store_path_ok(&host.running_system_store_path)
        || !store_path_ok(&host.boot_default_store_path) || !source_set_ok(host, &e.kernel_boot_id) {
        return hold("host observations are stale, malformed or not independently sourced", Some(job_id), invocation);
    }

    let unit_success = snapshot.active_state == "inactive" && snapshot.sub_state == "dead"
        && snapshot.result == "success" && snapshot.exec_main_status == 0;
    let worker_success = receipt.exit_status == 0;
    let host_success = host.runtime_health == RuntimeHealth::Healthy
        && host_matches_success(host, e.operation, &e.candidate_store_path, &e.predecessor_store_path);
    if job_result == JobResult::Done && unit_success && worker_success && host_success {
        return report(TerminalOutcome::VerifiedSuccess,
            "exact job, PIDFD worker, durable receipt, oneshot result and operation-specific NixOS post-state agree",
            Some(job_id), invocation);
    }
    let execution_failed = job_result != JobResult::Done || !unit_success || !worker_success;
    if execution_failed && host.runtime_health == RuntimeHealth::Healthy
        && host_is_predecessor(host, &e.predecessor_store_path) {
        return report(TerminalOutcome::VerifiedRecovery,
            "execution did not qualify as success; predecessor profile, running system and boot default are independently observed healthy",
            Some(job_id), invocation);
    }
    if host.runtime_health != RuntimeHealth::Healthy {
        return hold("runtime health is not independently verified healthy", Some(job_id), invocation);
    }
    if job_result == JobResult::Done && unit_success && worker_success && !host_success {
        return hold("systemd and worker succeeded but operation-specific NixOS post-state does not match", Some(job_id), invocation);
    }
    reconcile("manager, worker, unit and host evidence do not establish one terminal outcome", Some(job_id), invocation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(c: char) -> String { std::iter::repeat(c).take(64).collect() }
    fn source(name: &str, boot: &str, time: u64, hash: char) -> ObservationSource {
        ObservationSource { name: name.into(), sha256: digest(hash), boot_id: boot.into(), observed_monotonic_ns: time }
    }
    fn fixture(mode: OperationMode) -> SystemdExecutionEvidence {
        let binding = TransactionBinding {
            transaction_id:digest('1'), attempt_id:digest('2'), admission_commit_id:digest('3'),
            replay_key:digest('4'), permit_digest:digest('5'), plan_digest:digest('6'),
            machine_binding_digest:digest('7'),
        };
        let kernel = "kernel-boot-a".to_string();
        let manager = "systemd-boot-a".to_string();
        let unit = "nixward-transaction-abc.service".to_string();
        let unit_path = "/org/freedesktop/systemd1/unit/nixward_2dtransaction_2dabc_2eservice".to_string();
        let invocation = "invocation-a".to_string();
        let worker = WorkerIdentity {
            binding:binding.clone(), lookup_method:WorkerLookupMethod::GetUnitByPidfd,
            unit_name:unit.clone(), unit_object_path:unit_path.clone(), invocation_id:invocation.clone(),
            manager_boot_id:manager.clone(), kernel_boot_id:kernel.clone(), pid:4210,
            process_start_ticks:991122, observed_monotonic_ns:450, persisted_monotonic_ns:470,
        };
        let receipt = PayloadReceipt {
            binding:binding.clone(), unit_name:unit.clone(), invocation_id:invocation.clone(),
            pid:4210, process_start_ticks:991122, released_monotonic_ns:480,
            exited_monotonic_ns:620, persisted_monotonic_ns:640, exit_status:0, receipt_sha256:digest('8'),
        };
        let candidate="/nix/store/aaaaaaaa-system-candidate";
        let predecessor="/nix/store/bbbbbbbb-system-predecessor";
        let (profile,running,boot) = expected_paths(mode,candidate,predecessor);
        let host = HostStateObservation {
            binding:binding.clone(), boot_id:kernel.clone(), observed_monotonic_ns:800,
            active_profile_store_path:profile.into(), running_system_store_path:running.into(),
            boot_default_store_path:boot.into(), runtime_health:RuntimeHealth::Healthy,
            sources:vec![
                source("system_profile",&kernel,710,'a'), source("running_system",&kernel,720,'b'),
                source("boot_default",&kernel,730,'c'), source("runtime_health",&kernel,740,'d'),
            ],
        };
        SystemdExecutionEvidence {
            schema:EVIDENCE_SCHEMA.into(), version:EVIDENCE_VERSION, binding:binding.clone(),
            authority:AuthorityProvenanceBinding {
                policy_id:"owner-root-v1".into(), policy_digest:digest('9'), policy_epoch:4,
                issuer:"owner".into(), signer_key_id:"owner-key-1".into(), action:"change".into(),
                audience:"nixward-change-v1".into(), subject_digest:binding.plan_digest.clone(),
                challenge_digest:digest('a'), replay_key:binding.replay_key.clone(), evidence_digest:digest('b'),
                issued_at_ms:1000, expires_at_ms:2000,
            },
            expected_authority_subject_digest:binding.plan_digest.clone(), operation:mode,
            expected_unit:unit.clone(), candidate_store_path:candidate.into(), predecessor_store_path:predecessor.into(),
            manager_boot_id:manager.clone(), kernel_boot_id:kernel,
            admission_committed_monotonic_ns:100, subscription_established_monotonic_ns:200,
            start_requested_monotonic_ns:300,
            start_unit_reply:Some(StartUnitReply {
                job_object_path:"/org/freedesktop/systemd1/job/77".into(), unit_name:unit.clone(),
                received_monotonic_ns:360,
            }),
            manager_events:vec![
                ManagerEvent { kind:EventKind::JobNew, job_id:77, job_object_path:"/org/freedesktop/systemd1/job/77".into(),
                    unit_name:unit.clone(), result:None, monotonic_ns:380, manager_boot_id:manager.clone() },
                ManagerEvent { kind:EventKind::JobRemoved, job_id:77, job_object_path:"/org/freedesktop/systemd1/job/77".into(),
                    unit_name:unit.clone(), result:Some(JobResult::Done), monotonic_ns:680, manager_boot_id:manager.clone() },
            ],
            worker_identity:Some(worker.clone()),
            unit_snapshot:Some(UnitSnapshot {
                unit_name:unit.clone(), unit_object_path:unit_path, invocation_id:invocation,
                manager_boot_id:manager, service_type:"oneshot".into(), active_state:"inactive".into(),
                sub_state:"dead".into(), result:"success".into(), exec_main_status:0, observed_monotonic_ns:700,
            }),
            payload_receipt:Some(receipt), host_state:Some(host),
        }
    }

    #[test] fn switch_success_requires_complete_chain() {
        assert_eq!(verify_execution(&fixture(OperationMode::Switch)).outcome,TerminalOutcome::VerifiedSuccess);
    }
    #[test] fn test_keeps_predecessor_boot_default() {
        assert_eq!(verify_execution(&fixture(OperationMode::Test)).outcome,TerminalOutcome::VerifiedSuccess);
    }
    #[test] fn boot_keeps_predecessor_running() {
        assert_eq!(verify_execution(&fixture(OperationMode::Boot)).outcome,TerminalOutcome::VerifiedSuccess);
    }
    #[test] fn job_done_alone_does_not_prove_host_state() {
        let mut e=fixture(OperationMode::Switch);
        e.host_state.as_mut().unwrap().running_system_store_path=e.predecessor_store_path.clone();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn missing_jobremoved_requires_reconciliation() {
        let mut e=fixture(OperationMode::Switch); e.manager_events.pop();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::ReconciliationRequired);
    }
    #[test] fn returned_job_path_mapped_to_foreign_unit_is_safe_hold() {
        let mut e=fixture(OperationMode::Switch); e.manager_events[0].unit_name="foreign.service".into();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn duplicate_jobremoved_is_safe_hold() {
        let mut e=fixture(OperationMode::Switch); e.manager_events.push(e.manager_events[1].clone());
        e.manager_events[2].monotonic_ns+=1;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn subscription_must_precede_start() {
        let mut e=fixture(OperationMode::Switch); e.subscription_established_monotonic_ns=350;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn pid_only_attribution_is_rejected() {
        let mut e=fixture(OperationMode::Switch);
        e.worker_identity.as_mut().unwrap().lookup_method=WorkerLookupMethod::GetUnitByPid;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn release_before_identity_persistence_is_rejected() {
        let mut e=fixture(OperationMode::Switch); e.payload_receipt.as_mut().unwrap().released_monotonic_ns=460;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn receipt_must_match_process_start_tuple() {
        let mut e=fixture(OperationMode::Switch); e.payload_receipt.as_mut().unwrap().process_start_ticks+=1;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn snapshot_must_match_invocation() {
        let mut e=fixture(OperationMode::Switch); e.unit_snapshot.as_mut().unwrap().invocation_id="foreign".into();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn failed_job_with_healthy_predecessor_is_recovery() {
        let mut e=fixture(OperationMode::Switch);
        e.manager_events[1].result=Some(JobResult::Failed);
        e.unit_snapshot.as_mut().unwrap().result="exit-code".into();
        e.unit_snapshot.as_mut().unwrap().exec_main_status=1;
        e.payload_receipt.as_mut().unwrap().exit_status=1;
        let h=e.host_state.as_mut().unwrap();
        h.active_profile_store_path=e.predecessor_store_path.clone();
        h.running_system_store_path=e.predecessor_store_path.clone();
        h.boot_default_store_path=e.predecessor_store_path.clone();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::VerifiedRecovery);
    }
    #[test] fn failed_job_with_candidate_active_is_not_recovery() {
        let mut e=fixture(OperationMode::Switch);
        e.manager_events[1].result=Some(JobResult::Failed);
        e.unit_snapshot.as_mut().unwrap().result="exit-code".into();
        e.payload_receipt.as_mut().unwrap().exit_status=1;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::ReconciliationRequired);
    }
    #[test] fn manager_boot_mismatch_is_rejected() {
        let mut e=fixture(OperationMode::Switch); e.manager_events[0].manager_boot_id="other".into();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn missing_host_observation_requires_reconciliation() {
        let mut e=fixture(OperationMode::Switch); e.host_state=None;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::ReconciliationRequired);
    }
    #[test] fn test_boot_default_mismatch_is_rejected() {
        let mut e=fixture(OperationMode::Test);
        e.host_state.as_mut().unwrap().boot_default_store_path=e.candidate_store_path.clone();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn zero_policy_epoch_is_rejected() {
        let mut e=fixture(OperationMode::Switch); e.authority.policy_epoch=0;
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn replay_key_mismatch_is_rejected() {
        let mut e=fixture(OperationMode::Switch); e.authority.replay_key=digest('c');
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn unknown_wire_field_is_rejected() {
        let e=fixture(OperationMode::Switch);
        let mut value=serde_json::to_value(e).unwrap();
        value["unexpected_security_override"]=serde_json::json!(true);
        assert!(serde_json::from_value::<SystemdExecutionEvidence>(value).is_err());
    }
    #[test] fn bad_observation_source_digest_is_rejected() {
        let mut e=fixture(OperationMode::Switch);
        e.host_state.as_mut().unwrap().sources[0].sha256="bad".into();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn out_of_order_manager_capture_is_not_sorted() {
        let mut e=fixture(OperationMode::Switch); e.manager_events.swap(0,1);
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
    #[test] fn non_oneshot_worker_service_is_not_implicitly_accepted() {
        let mut e=fixture(OperationMode::Switch); e.unit_snapshot.as_mut().unwrap().service_type="simple".into();
        assert_eq!(verify_execution(&e).outcome,TerminalOutcome::SafeHold);
    }
}
