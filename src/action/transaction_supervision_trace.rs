// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Temporal safety checks for one exact Nixward transaction worker attempt.
//!
//! This pure trace checker neither authorizes nor executes mutations. Callers
//! must validate event provenance and bind every event to the durable journal
//! before using this result in recovery.

use super::transaction_supervision::TargetObservation;

/// One event in a single transaction/worker-start attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub transaction_id: String,
    pub attempt_id: String,
    pub kind: TraceEventKind,
}

/// Events that matter to the worker-start and post-state proof boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEventKind {
    AuthorizationVerified,
    AttemptPreparedDurably,
    SubmissionBarrierPersisted,
    ManagerStartSubmitted,
    WorkerIdentityObserved,
    WorkerIdentityPersisted,
    PayloadReleased,
    PayloadExited,
    ProcessReceiptPersisted,
    TargetObserved(TargetObservation),
    LifecyclePostconditionValidated,
    TerminalSuccessRecorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceViolationKind {
    EventIdentityBindingMismatch,
    AttemptPreparedWithoutVerifiedAuthorization,
    SubmissionBarrierWithoutPreparedAttempt,
    StartSubmissionWithoutWriteAheadBarrier,
    DuplicateManagerStartSubmission,
    WorkerIdentityObservedBeforeStartSubmission,
    WorkerIdentityPersistedBeforeObservation,
    PayloadReleasedWithoutAuthorization,
    PayloadReleasedBeforeStartSubmission,
    PayloadReleasedBeforeDurableWorkerIdentity,
    PayloadExitBeforePayloadRelease,
    ReceiptBeforePayloadExit,
    ReceiptWithoutDurableWorkerIdentity,
    LifecycleValidationBeforePayloadExit,
    LifecycleValidationWithoutPostExitTargetObservation,
    LifecycleValidationWithoutCandidatePostState,
    TerminalSuccessWithoutProcessReceipt,
    TerminalSuccessWithoutCandidatePostState,
    TerminalSuccessWithoutLifecycleValidation,
    EventAfterTerminalSuccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceViolation {
    pub event_index: usize,
    pub kind: TraceViolationKind,
}

/// A safe trace may be incomplete: for example, a crash after the durable
/// submission barrier is not itself a violation. Safe does not mean successful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceValidation {
    pub violations: Vec<TraceViolation>,
    pub terminal_success_recorded: bool,
}

impl TraceValidation {
    pub fn is_safe(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Validate an event sequence against the transaction and attempt IDs taken
/// from the already-validated durable journal.
///
/// This checks event ordering and conservative success claims only. It does
/// not validate receipt cryptography, manager D-Bus provenance, the truth of
/// target observations, plan authorization, or cross-attempt retry policy.
pub fn validate_trace(
    expected_transaction_id: &str,
    expected_attempt_id: &str,
    events: &[TraceEvent],
) -> TraceValidation {
    let mut violations = Vec::new();
    let mut authorization_verified = false;
    let mut attempt_prepared = false;
    let mut submission_barrier_persisted = false;
    let mut manager_start_submitted = false;
    let mut worker_identity_observed = false;
    let mut worker_identity_persisted = false;
    let mut payload_released = false;
    let mut payload_exited = false;
    let mut process_receipt_persisted = false;
    let mut target_observed_after_exit: Option<TargetObservation> = None;
    let mut lifecycle_postcondition_validated = false;
    let mut terminal_success_recorded = false;

    for (event_index, event) in events.iter().enumerate() {
        if event.transaction_id != expected_transaction_id
            || event.attempt_id != expected_attempt_id
        {
            violations.push(TraceViolation {
                event_index,
                kind: TraceViolationKind::EventIdentityBindingMismatch,
            });
            // Foreign evidence must not advance this attempt's proof state.
            continue;
        }

        if terminal_success_recorded {
            violations.push(TraceViolation {
                event_index,
                kind: TraceViolationKind::EventAfterTerminalSuccess,
            });
            continue;
        }

        match event.kind {
            TraceEventKind::AuthorizationVerified => authorization_verified = true,
            TraceEventKind::AttemptPreparedDurably => {
                if !authorization_verified {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::AttemptPreparedWithoutVerifiedAuthorization,
                    });
                }
                attempt_prepared = true;
            }
            TraceEventKind::SubmissionBarrierPersisted => {
                if !attempt_prepared {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::SubmissionBarrierWithoutPreparedAttempt,
                    });
                }
                if !authorization_verified {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::AttemptPreparedWithoutVerifiedAuthorization,
                    });
                }
                submission_barrier_persisted = true;
            }
            TraceEventKind::ManagerStartSubmitted => {
                if !submission_barrier_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::StartSubmissionWithoutWriteAheadBarrier,
                    });
                }
                if manager_start_submitted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateManagerStartSubmission,
                    });
                }
                manager_start_submitted = true;
            }
            TraceEventKind::WorkerIdentityObserved => {
                if !manager_start_submitted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::WorkerIdentityObservedBeforeStartSubmission,
                    });
                }
                worker_identity_observed = true;
            }
            TraceEventKind::WorkerIdentityPersisted => {
                if !worker_identity_observed {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::WorkerIdentityPersistedBeforeObservation,
                    });
                }
                worker_identity_persisted = true;
            }
            TraceEventKind::PayloadReleased => {
                if !authorization_verified {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::PayloadReleasedWithoutAuthorization,
                    });
                }
                if !manager_start_submitted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::PayloadReleasedBeforeStartSubmission,
                    });
                }
                if !worker_identity_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::PayloadReleasedBeforeDurableWorkerIdentity,
                    });
                }
                payload_released = true;
            }
            TraceEventKind::PayloadExited => {
                if !payload_released {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::PayloadExitBeforePayloadRelease,
                    });
                }
                payload_exited = true;
            }
            TraceEventKind::ProcessReceiptPersisted => {
                if !payload_exited {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::ReceiptBeforePayloadExit,
                    });
                }
                if !worker_identity_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::ReceiptWithoutDurableWorkerIdentity,
                    });
                }
                process_receipt_persisted = true;
            }
            TraceEventKind::TargetObserved(observation) => {
                if payload_exited {
                    target_observed_after_exit = Some(observation);
                    // A newer target snapshot invalidates validation of an older one.
                    lifecycle_postcondition_validated = false;
                }
            }
            TraceEventKind::LifecyclePostconditionValidated => {
                let candidate_post_state = target_observed_after_exit
                    == Some(TargetObservation::CandidateRuntimeAndProfileActive);
                if !payload_exited {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::LifecycleValidationBeforePayloadExit,
                    });
                }
                if target_observed_after_exit.is_none() {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::LifecycleValidationWithoutPostExitTargetObservation,
                    });
                }
                if !candidate_post_state {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::LifecycleValidationWithoutCandidatePostState,
                    });
                }
                lifecycle_postcondition_validated = payload_exited && candidate_post_state;
            }
            TraceEventKind::TerminalSuccessRecorded => {
                if !process_receipt_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::TerminalSuccessWithoutProcessReceipt,
                    });
                }
                if target_observed_after_exit
                    != Some(TargetObservation::CandidateRuntimeAndProfileActive)
                {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::TerminalSuccessWithoutCandidatePostState,
                    });
                }
                if !lifecycle_postcondition_validated {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::TerminalSuccessWithoutLifecycleValidation,
                    });
                }
                terminal_success_recorded = true;
            }
        }
    }

    TraceValidation {
        violations,
        terminal_success_recorded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSACTION: &str = "transaction-1";
    const ATTEMPT: &str = "attempt-1";

    fn event(kind: TraceEventKind) -> TraceEvent {
        TraceEvent {
            transaction_id: TRANSACTION.to_owned(),
            attempt_id: ATTEMPT.to_owned(),
            kind,
        }
    }

    fn valid_success_trace() -> Vec<TraceEvent> {
        vec![
            event(TraceEventKind::AuthorizationVerified),
            event(TraceEventKind::AttemptPreparedDurably),
            event(TraceEventKind::SubmissionBarrierPersisted),
            event(TraceEventKind::ManagerStartSubmitted),
            event(TraceEventKind::WorkerIdentityObserved),
            event(TraceEventKind::WorkerIdentityPersisted),
            event(TraceEventKind::PayloadReleased),
            event(TraceEventKind::PayloadExited),
            event(TraceEventKind::ProcessReceiptPersisted),
            event(TraceEventKind::TargetObserved(
                TargetObservation::CandidateRuntimeAndProfileActive,
            )),
            event(TraceEventKind::LifecyclePostconditionValidated),
            event(TraceEventKind::TerminalSuccessRecorded),
        ]
    }

    #[test]
    fn accepts_only_a_fully_bound_and_reconciled_success_trace() {
        let result = validate_trace(TRANSACTION, ATTEMPT, &valid_success_trace());
        assert!(result.is_safe(), "{:?}", result.violations);
        assert!(result.terminal_success_recorded);
    }

    #[test]
    fn duplicate_manager_start_for_one_attempt_is_rejected() {
        let mut trace = valid_success_trace();
        trace.insert(4, event(TraceEventKind::ManagerStartSubmitted));
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::DuplicateManagerStartSubmission
        }));
    }

    #[test]
    fn write_ahead_barrier_must_precede_manager_submission() {
        let trace = vec![
            event(TraceEventKind::AuthorizationVerified),
            event(TraceEventKind::AttemptPreparedDurably),
            event(TraceEventKind::ManagerStartSubmitted),
            event(TraceEventKind::SubmissionBarrierPersisted),
        ];
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::StartSubmissionWithoutWriteAheadBarrier
        }));
    }

    #[test]
    fn payload_cannot_be_released_before_worker_identity_is_durable() {
        let trace = vec![
            event(TraceEventKind::AuthorizationVerified),
            event(TraceEventKind::AttemptPreparedDurably),
            event(TraceEventKind::SubmissionBarrierPersisted),
            event(TraceEventKind::ManagerStartSubmitted),
            event(TraceEventKind::WorkerIdentityObserved),
            event(TraceEventKind::PayloadReleased),
        ];
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::PayloadReleasedBeforeDurableWorkerIdentity
        }));
    }

    #[test]
    fn target_observed_before_exit_does_not_qualify_terminal_success() {
        let mut trace = valid_success_trace();
        trace.retain(|item| {
            item.kind != TraceEventKind::TargetObserved(
                TargetObservation::CandidateRuntimeAndProfileActive,
            )
        });
        trace.insert(
            7,
            event(TraceEventKind::TargetObserved(
                TargetObservation::CandidateRuntimeAndProfileActive,
            )),
        );
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::TerminalSuccessWithoutCandidatePostState
        }));
    }

    #[test]
    fn a_later_mixed_observation_invalidates_earlier_candidate_validation() {
        let mut trace = valid_success_trace();
        let terminal_index = trace
            .iter()
            .position(|item| item.kind == TraceEventKind::TerminalSuccessRecorded)
            .unwrap();
        trace.insert(
            terminal_index,
            event(TraceEventKind::TargetObserved(TargetObservation::MixedOrUnknown)),
        );
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::LifecycleValidationWithoutCandidatePostState
        }));
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::TerminalSuccessWithoutCandidatePostState
        }));
    }

    #[test]
    fn events_cannot_be_rebound_to_another_attempt() {
        let mut trace = valid_success_trace();
        trace[8].attempt_id = "attempt-2".to_owned();
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::EventIdentityBindingMismatch
                && violation.event_index == 8
        }));
    }

    #[test]
    fn ambiguous_start_prefix_is_safely_incomplete_not_successful() {
        let trace = vec![
            event(TraceEventKind::AuthorizationVerified),
            event(TraceEventKind::AttemptPreparedDurably),
            event(TraceEventKind::SubmissionBarrierPersisted),
            event(TraceEventKind::ManagerStartSubmitted),
        ];
        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert!(result.is_safe());
        assert!(!result.terminal_success_recorded);
    }

    #[test]
    fn bounded_permutation_check_rejects_every_unsafe_start_ordering() {
        fn visit(
            prefix: &mut Vec<TraceEventKind>,
            remaining: Vec<TraceEventKind>,
            checked: &mut usize,
        ) {
            if remaining.is_empty() {
                let trace: Vec<_> = prefix.iter().copied().map(event).collect();
                let required_order = [
                    TraceEventKind::AuthorizationVerified,
                    TraceEventKind::AttemptPreparedDurably,
                    TraceEventKind::SubmissionBarrierPersisted,
                    TraceEventKind::ManagerStartSubmitted,
                    TraceEventKind::WorkerIdentityObserved,
                    TraceEventKind::WorkerIdentityPersisted,
                    TraceEventKind::PayloadReleased,
                ];
                let safe_order = prefix.as_slice() == required_order;
                let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
                assert_eq!(
                    result.is_safe(),
                    safe_order,
                    "unexpected result for {:?}: {:?}",
                    prefix,
                    result.violations
                );
                *checked += 1;
                return;
            }

            for index in 0..remaining.len() {
                let mut next = remaining.clone();
                let selected = next.remove(index);
                prefix.push(selected);
                visit(prefix, next, checked);
                prefix.pop();
            }
        }

        let alphabet = vec![
            TraceEventKind::AuthorizationVerified,
            TraceEventKind::AttemptPreparedDurably,
            TraceEventKind::SubmissionBarrierPersisted,
            TraceEventKind::ManagerStartSubmitted,
            TraceEventKind::WorkerIdentityObserved,
            TraceEventKind::WorkerIdentityPersisted,
            TraceEventKind::PayloadReleased,
        ];
        let mut checked = 0;
        visit(&mut Vec::new(), alphabet, &mut checked);
        assert_eq!(checked, 5_040);
    }
}
