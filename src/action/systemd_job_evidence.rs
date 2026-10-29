// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Pure correlation contract for asynchronous systemd start-job evidence.
//!
//! This module deliberately does not talk to D-Bus or authorize host mutation.
//! It prevents callers from confusing a StartUnit acknowledgement, an
//! unrelated JobRemoved signal, or a lost reply with proof that a worker ran.
//! Production D-Bus integration must subscribe before StartUnit and feed this
//! contract the exact reply and signal values it observed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const UNIT_NAME_DOMAIN: &[u8] = b"nixward-systemd-attempt-unit-v1\0";
const JOB_OBJECT_PATH_PREFIX: &str = "/org/freedesktop/systemd1/job/";

/// Purpose is part of the derived unit identity, so activation and recovery
/// attempts cannot accidentally alias one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionWorkerPurpose {
    ProfileTransition,
    Activation,
    RecoveryProfileTransition,
    RecoveryActivation,
}

impl TransactionWorkerPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProfileTransition => "profile_transition",
            Self::Activation => "activation",
            Self::RecoveryProfileTransition => "recovery_profile_transition",
            Self::RecoveryActivation => "recovery_activation",
        }
    }
}

/// Derive the only acceptable unit name for a transaction/attempt/purpose
/// tuple. Input identifiers are never copied into a privileged unit name.
pub fn canonical_attempt_unit_name(
    transaction_id: &str,
    attempt_id: &str,
    purpose: TransactionWorkerPurpose,
) -> Result<String, String> {
    validate_identity("transaction ID", transaction_id)?;
    validate_identity("attempt ID", attempt_id)?;

    let mut hash = Sha256::new();
    hash.update(UNIT_NAME_DOMAIN);
    for field in [transaction_id, attempt_id, purpose.as_str()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let digest = format!("{:x}", hash.finalize());
    // Hex is safe as a systemd template instance; caller-controlled input
    // cannot inject unit separators, specifiers, or another unit name.
    Ok(format!("nixward-transaction@{digest}.service"))
}

fn validate_identity(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be blank"));
    }
    if value.len() > 256 {
        return Err(format!("{label} exceeds the 256-byte contract limit"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains a control character"));
    }
    Ok(())
}

/// The method-level result of asking systemd to enqueue a unit start.
///
/// Unknown is important: a dropped D-Bus connection after the request does
/// not distinguish "request never arrived" from "job enqueued, reply lost".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ManagerStartReply {
    Enqueued {
        job_id: u32,
        job_object_path: String,
    },
    Rejected {
        error_name: String,
    },
    Unknown,
}

/// Durable fields that a production adapter must bind to the exact request
/// and reply. This evidence is not itself proof of a process or post-state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdStartEvidence {
    pub transaction_id: String,
    pub attempt_id: String,
    pub purpose: TransactionWorkerPurpose,
    pub unit_name: String,
    /// Must reflect a confirmed D-Bus signal subscription before StartUnit.
    pub subscribed_before_start: bool,
    pub reply: ManagerStartReply,
}

/// The result field documented by systemd's JobRemoved signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRemovedResult {
    Done,
    Canceled,
    Timeout,
    Failed,
    Dependency,
    Skipped,
}

/// A single observed JobRemoved signal. The D-Bus adapter must preserve the
/// job ID, object path, unit name and result from the same signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRemovedEvidence {
    pub job_id: u32,
    pub job_object_path: String,
    pub unit_name: String,
    pub result: JobRemovedResult,
}

/// Correlation is deliberately not named "transaction success": even a
/// completed systemd start job does not prove process exit or desired NixOS
/// state. Later evidence gates must verify those independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartJobCorrelation {
    MatchedStartJobCompleted,
    MatchedStartJobFailed { result: JobRemovedResult },
    UnrelatedSignal,
    HoldForReconciliation { reason: String },
    RejectedEvidence { reason: String },
    ManagerRejected { error_name: String },
}

/// Classification of the method-level StartUnit response. This is useful
/// before any JobRemoved signal exists: a definite rejection is a rejection,
/// while a lost reply remains ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartReplyDisposition {
    Enqueued { job_id: u32, job_object_path: String },
    ManagerRejected { error_name: String },
    Ambiguous,
}

/// Validate the start intent and classify the direct manager response without
/// requiring a fabricated JobRemoved event.
pub fn classify_start_reply(
    start: &SystemdStartEvidence,
) -> Result<StartReplyDisposition, String> {
    if !start.subscribed_before_start {
        return Err("JobRemoved subscription was not confirmed before StartUnit".into());
    }
    let expected_unit = canonical_attempt_unit_name(
        &start.transaction_id,
        &start.attempt_id,
        start.purpose,
    )?;
    if start.unit_name != expected_unit {
        return Err("start evidence unit name is not derived from its transaction/attempt identity".into());
    }

    match &start.reply {
        ManagerStartReply::Unknown => Ok(StartReplyDisposition::Ambiguous),
        ManagerStartReply::Rejected { error_name } => {
            if error_name.trim().is_empty() {
                return Err("manager rejection is missing its D-Bus error name".into());
            }
            Ok(StartReplyDisposition::ManagerRejected {
                error_name: error_name.clone(),
            })
        }
        ManagerStartReply::Enqueued { job_id, job_object_path } => {
            if *job_id == 0 || !valid_job_object_path(job_object_path) {
                return Err("StartUnit reply has an invalid job ID or object path".into());
            }
            Ok(StartReplyDisposition::Enqueued {
                job_id: *job_id,
                job_object_path: job_object_path.clone(),
            })
        }
    }
}

/// Correlate one event with one exact StartUnit request.
///
/// Rules:
/// - the signal subscription must be established before the call;
/// - the requested unit is derived from transaction/attempt/purpose;
/// - StartUnit's returned job ID and object path must both match JobRemoved;
/// - a different job is ignored only when it cannot concern the expected unit;
/// - matching the exact job still reports only the manager's job result.
pub fn correlate_job_removed(
    start: &SystemdStartEvidence,
    signal: &JobRemovedEvidence,
) -> StartJobCorrelation {
    let reply = match classify_start_reply(start) {
        Ok(reply) => reply,
        Err(reason) => return StartJobCorrelation::RejectedEvidence { reason },
    };
    let (expected_job_id, expected_job_path) = match reply {
        StartReplyDisposition::Ambiguous => {
            return StartJobCorrelation::HoldForReconciliation {
                reason: "StartUnit reply is unknown; do not infer submission or retry the mutation".into(),
            };
        }
        StartReplyDisposition::ManagerRejected { error_name } => {
            return StartJobCorrelation::ManagerRejected { error_name };
        }
        StartReplyDisposition::Enqueued { job_id, job_object_path } => {
            (job_id, job_object_path)
        }
    };

    if signal.job_id == 0 || !valid_job_object_path(&signal.job_object_path) {
        return StartJobCorrelation::RejectedEvidence {
            reason: "JobRemoved evidence has an invalid job ID or object path".into(),
        };
    }
    if signal.unit_name.trim().is_empty() || signal.unit_name.chars().any(char::is_control) {
        return StartJobCorrelation::RejectedEvidence {
            reason: "JobRemoved evidence has an invalid unit name".into(),
        };
    }

    let (expected_job_id, expected_job_path) = match &start.reply {
        ManagerStartReply::Unknown => {
            return StartJobCorrelation::HoldForReconciliation {
                reason: "StartUnit reply is unknown; do not infer submission or retry the mutation".into(),
            };
        }
        ManagerStartReply::Rejected { error_name } => {
            if error_name.trim().is_empty() {
                return StartJobCorrelation::RejectedEvidence {
                    reason: "manager rejection is missing its D-Bus error name".into(),
                };
            }
            return StartJobCorrelation::ManagerRejected {
                error_name: error_name.clone(),
            };
        }
        ManagerStartReply::Enqueued { job_id, job_object_path } => {
            if *job_id == 0 || !valid_job_object_path(job_object_path) {
                return StartJobCorrelation::RejectedEvidence {
                    reason: "StartUnit reply has an invalid job ID or object path".into(),
                };
            }
            (*job_id, job_object_path.as_str())
        }
    };

    if signal.job_id != expected_job_id || signal.job_object_path != expected_job_path {
        if signal.unit_name == start.unit_name || signal.job_object_path == expected_job_path {
            return StartJobCorrelation::HoldForReconciliation {
                reason: "JobRemoved shares the expected unit or job object path but conflicts with the acknowledged job identity".into(),
            };
        }
        return StartJobCorrelation::UnrelatedSignal;
    }

    if signal.unit_name != start.unit_name {
        return StartJobCorrelation::HoldForReconciliation {
            reason: "acknowledged job identity was reported for a different unit name".into(),
        };
    }

    match signal.result {
        JobRemovedResult::Done => StartJobCorrelation::MatchedStartJobCompleted,
        result => StartJobCorrelation::MatchedStartJobFailed { result },
    }
}

fn valid_job_object_path(path: &str) -> bool {
    let Some(suffix) = path.strip_prefix(JOB_OBJECT_PATH_PREFIX) else {
        return false;
    };
    !suffix.is_empty()
        && !suffix.contains('/')
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(reply: ManagerStartReply) -> SystemdStartEvidence {
        SystemdStartEvidence {
            transaction_id: "tx-7f3c".into(),
            attempt_id: "attempt-0004".into(),
            purpose: TransactionWorkerPurpose::Activation,
            unit_name: canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap(),
            subscribed_before_start: true,
            reply,
        }
    }

    fn enqueued_start() -> SystemdStartEvidence {
        start(ManagerStartReply::Enqueued {
            job_id: 41,
            job_object_path: "/org/freedesktop/systemd1/job/41".into(),
        })
    }

    fn signal(result: JobRemovedResult) -> JobRemovedEvidence {
        JobRemovedEvidence {
            job_id: 41,
            job_object_path: "/org/freedesktop/systemd1/job/41".into(),
            unit_name: canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap(),
            result,
        }
    }

    #[test]
    fn unit_name_is_stable_and_bound_to_all_attempt_identity_fields() {
        let expected = canonical_attempt_unit_name(
            "tx-7f3c",
            "attempt-0004",
            TransactionWorkerPurpose::Activation,
        )
        .unwrap();
        assert_eq!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0005",
                TransactionWorkerPurpose::Activation,
            )
            .unwrap()
        );
        assert_ne!(
            expected,
            canonical_attempt_unit_name(
                "tx-7f3c",
                "attempt-0004",
                TransactionWorkerPurpose::RecoveryActivation,
            )
            .unwrap()
        );
        assert!(canonical_attempt_unit_name("", "attempt", TransactionWorkerPurpose::Activation).is_err());
        assert!(canonical_attempt_unit_name("tx", " \t ", TransactionWorkerPurpose::Activation).is_err());
        assert!(canonical_attempt_unit_name("tx\nother", "attempt", TransactionWorkerPurpose::Activation).is_err());
    }

    #[test]
    fn only_the_exact_acknowledged_job_and_unit_match() {
        let start = enqueued_start();
        assert_eq!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::MatchedStartJobCompleted
        );

        let mut other_job = signal(JobRemovedResult::Done);
        other_job.job_id += 1;
        other_job.job_object_path = "/org/freedesktop/systemd1/job/42".into();
        other_job.unit_name = "unrelated.service".into();
        assert_eq!(
            correlate_job_removed(&start, &other_job),
            StartJobCorrelation::UnrelatedSignal
        );

        let mut same_unit_wrong_job = other_job;
        same_unit_wrong_job.unit_name = start.unit_name.clone();
        assert!(matches!(
            correlate_job_removed(&start, &same_unit_wrong_job),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn every_non_done_job_result_is_not_success() {
        let start = enqueued_start();
        for result in [
            JobRemovedResult::Canceled,
            JobRemovedResult::Timeout,
            JobRemovedResult::Failed,
            JobRemovedResult::Dependency,
            JobRemovedResult::Skipped,
        ] {
            assert_eq!(
                correlate_job_removed(&start, &signal(result)),
                StartJobCorrelation::MatchedStartJobFailed { result }
            );
        }
    }

    #[test]
    fn a_lost_start_reply_stays_ambiguous_even_if_a_signal_arrives() {
        let start = start(ManagerStartReply::Unknown);
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn subscription_must_precede_the_start_call() {
        let mut start = enqueued_start();
        start.subscribed_before_start = false;
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::RejectedEvidence { .. }
        ));
    }

    #[test]
    fn identity_mismatch_and_malformed_paths_fail_closed() {
        let mut start = enqueued_start();
        start.transaction_id = "different-transaction".into();
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::RejectedEvidence { .. }
        ));

        let start = enqueued_start();
        let mut malformed = signal(JobRemovedResult::Done);
        malformed.job_object_path = "/org/freedesktop/systemd1/unit/nixward".into();
        assert!(matches!(
            correlate_job_removed(&start, &malformed),
            StartJobCorrelation::RejectedEvidence { .. }
        ));

        let mut conflicting = signal(JobRemovedResult::Done);
        conflicting.unit_name = "other.service".into();
        assert!(matches!(
            correlate_job_removed(&start, &conflicting),
            StartJobCorrelation::HoldForReconciliation { .. }
        ));
    }

    #[test]
    fn known_manager_rejection_is_not_a_success_signal() {
        let start = start(ManagerStartReply::Rejected {
            error_name: "org.freedesktop.systemd1.UnitMasked".into(),
        });
        assert_eq!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::ManagerRejected {
                error_name: "org.freedesktop.systemd1.UnitMasked".into(),
            }
        );
    }

    #[test]
    fn acknowledgement_with_zero_job_id_is_rejected() {
        let start = start(ManagerStartReply::Enqueued {
            job_id: 0,
            job_object_path: "/org/freedesktop/systemd1/job/0".into(),
        });
        assert!(matches!(
            correlate_job_removed(&start, &signal(JobRemovedResult::Done)),
            StartJobCorrelation::RejectedEvidence { .. }
        ));
    }
}
