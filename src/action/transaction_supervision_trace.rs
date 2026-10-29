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
    EmptyExpectedTransactionId,
    EmptyExpectedAttemptId,
    DuplicateAuthorizationVerification,
    DuplicateAttemptPreparation,
    DuplicateSubmissionBarrier,
    AttemptPreparedWithoutVerifiedAuthorization,
    SubmissionBarrierWithoutPreparedAttempt,
    StartSubmissionWithoutWriteAheadBarrier,
    DuplicateManagerStartSubmission,
    WorkerIdentityObservedBeforeStartSubmission,
    DuplicateWorkerIdentityObservation,
    WorkerIdentityPersistedBeforeObservation,
    DuplicateWorkerIdentityPersistence,
    PayloadReleasedWithoutAuthorization,
    PayloadReleasedBeforeStartSubmission,
    PayloadReleasedBeforeDurableWorkerIdentity,
    DuplicatePayloadRelease,
    PayloadExitBeforePayloadRelease,
    DuplicatePayloadExit,
    ReceiptBeforePayloadExit,
    ReceiptWithoutDurableWorkerIdentity,
    DuplicateProcessReceiptPublication,
    LifecycleValidationBeforePayloadExit,
    LifecycleValidationWithoutPostExitTargetObservation,
    LifecycleValidationWithoutCandidatePostState,
    DuplicateLifecycleValidation,
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

/// Mutually exclusive classification of a validated trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDisposition {
    /// At least one invariant was violated or a required proof ordering failed.
    Rejected,
    /// No invariant has been violated yet, but terminal success is not proven.
    /// This includes prefixes ending at the ambiguous manager-call boundary.
    Incomplete,
    /// The trace has no violations and its terminal-success claim met the
    /// required process-receipt, fresh target-observation, and lifecycle gates.
    ValidatedTerminalSuccess,
}

/// A valid prefix is not a successful transaction and does not authorize retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceValidation {
    pub violations: Vec<TraceViolation>,
    pub disposition: TraceDisposition,
    /// Records that a matching-identity event claimed terminal success, even if rejected.
    pub terminal_success_claimed: bool,
}

impl TraceValidation {
    /// True means only that the observed prefix violates no modeled invariant.
    /// Callers must still inspect disposition; Incomplete is not success.
    pub fn is_valid_prefix(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn is_terminal_success(&self) -> bool {
        self.disposition == TraceDisposition::ValidatedTerminalSuccess
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
    if expected_transaction_id.trim().is_empty() {
        violations.push(TraceViolation {
            event_index: usize::MAX,
            kind: TraceViolationKind::EmptyExpectedTransactionId,
        });
    }
    if expected_attempt_id.trim().is_empty() {
        violations.push(TraceViolation {
            event_index: usize::MAX,
            kind: TraceViolationKind::EmptyExpectedAttemptId,
        });
    }
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
    let mut lifecycle_validation_seen_for_current_target = false;
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
            TraceEventKind::AuthorizationVerified => {
                if authorization_verified {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateAuthorizationVerification,
                    });
                }
                authorization_verified = true;
            }
            TraceEventKind::AttemptPreparedDurably => {
                if attempt_prepared {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateAttemptPreparation,
                    });
                }
                if !authorization_verified {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::AttemptPreparedWithoutVerifiedAuthorization,
                    });
                }
                attempt_prepared = true;
            }
            TraceEventKind::SubmissionBarrierPersisted => {
                if submission_barrier_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateSubmissionBarrier,
                    });
                }
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
                if worker_identity_observed {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateWorkerIdentityObservation,
                    });
                }
                if !manager_start_submitted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::WorkerIdentityObservedBeforeStartSubmission,
                    });
                }
                worker_identity_observed = true;
            }
            TraceEventKind::WorkerIdentityPersisted => {
                if worker_identity_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateWorkerIdentityPersistence,
                    });
                }
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
                if payload_released {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicatePayloadRelease,
                    });
                }
                payload_released = true;
            }
            TraceEventKind::PayloadExited => {
                if payload_exited {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicatePayloadExit,
                    });
                }
                if !payload_released {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::PayloadExitBeforePayloadRelease,
                    });
                }
                payload_exited = true;
            }
            TraceEventKind::ProcessReceiptPersisted => {
                if process_receipt_persisted {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateProcessReceiptPublication,
                    });
                }
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
                if payload_exited && process_receipt_persisted {
                    target_observed_after_exit = Some(observation);
                    // A newer target snapshot invalidates validation of an older one.
                    lifecycle_postcondition_validated = false;
                    lifecycle_validation_seen_for_current_target = false;
                }
            }
            TraceEventKind::LifecyclePostconditionValidated => {
                if lifecycle_validation_seen_for_current_target {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateLifecycleValidation,
                    });
                }
                lifecycle_validation_seen_for_current_target = true;
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

    let disposition = if !violations.is_empty() {
        TraceDisposition::Rejected
    } else if terminal_success_recorded {
        TraceDisposition::ValidatedTerminalSuccess
    } else {
        TraceDisposition::Incomplete
    };

    TraceValidation {
        violations,
        disposition,
        terminal_success_claimed: terminal_success_recorded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        assert!(result.is_valid_prefix(), "{:?}", result.violations);
        assert!(result.is_terminal_success());
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
        assert!(result.is_valid_prefix());
        assert!(!result.is_terminal_success());
        assert_eq!(result.disposition, TraceDisposition::Incomplete);
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
                let safe_order = prefix.as_slice() == &required_order[..];
                let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
                assert_eq!(
                    result.is_valid_prefix(),
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

    #[test]
    fn deterministic_trace_generation_never_accepts_success_without_causal_evidence() {
        fn next(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *state
        }

        fn first_position(
            trace: &[TraceEvent],
            expected: TraceEventKind,
        ) -> Option<usize> {
            trace.iter().position(|item| item.kind == expected)
        }

        // Deterministic pseudo-random generation avoids a test-only RNG dependency
        // and makes every failing seed directly reproducible.
        for seed in 0..20_000_u64 {
            let mut state = seed.wrapping_add(0x4e49_5857_4152_4401);
            let len = (next(&mut state) % 48) as usize;
            let mut trace = Vec::with_capacity(len);

            for _ in 0..len {
                let roll = next(&mut state);
                let kind = match roll % 12 {
                    0 => TraceEventKind::AuthorizationVerified,
                    1 => TraceEventKind::AttemptPreparedDurably,
                    2 => TraceEventKind::SubmissionBarrierPersisted,
                    3 => TraceEventKind::ManagerStartSubmitted,
                    4 => TraceEventKind::WorkerIdentityObserved,
                    5 => TraceEventKind::WorkerIdentityPersisted,
                    6 => TraceEventKind::PayloadReleased,
                    7 => TraceEventKind::PayloadExited,
                    8 => TraceEventKind::ProcessReceiptPersisted,
                    9 => {
                        let observation = match next(&mut state) % 6 {
                            0 => TargetObservation::NotAttempted,
                            1 => TargetObservation::CandidateRuntimeAndProfileActive,
                            2 => TargetObservation::PredecessorRuntimeAndProfileActive,
                            3 => TargetObservation::BootCandidateProfileSelected,
                            4 => TargetObservation::MixedOrUnknown,
                            _ => TargetObservation::Unavailable,
                        };
                        TraceEventKind::TargetObserved(observation)
                    }
                    10 => TraceEventKind::LifecyclePostconditionValidated,
                    _ => TraceEventKind::TerminalSuccessRecorded,
                };

                let transaction_id = if next(&mut state) % 31 == 0 {
                    "foreign-transaction"
                } else {
                    TRANSACTION
                };
                let attempt_id = if next(&mut state) % 29 == 0 {
                    "foreign-attempt"
                } else {
                    ATTEMPT
                };
                trace.push(TraceEvent {
                    transaction_id: transaction_id.to_owned(),
                    attempt_id: attempt_id.to_owned(),
                    kind,
                });
            }

            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
            if result.is_terminal_success() {
                let auth = first_position(&trace, TraceEventKind::AuthorizationVerified)
                    .expect("accepted success must have authorization");
                let prepared = first_position(&trace, TraceEventKind::AttemptPreparedDurably)
                    .expect("accepted success must have durable attempt preparation");
                let barrier = first_position(&trace, TraceEventKind::SubmissionBarrierPersisted)
                    .expect("accepted success must have the write-ahead barrier");
                let submitted = first_position(&trace, TraceEventKind::ManagerStartSubmitted)
                    .expect("accepted success must have manager submission");
                let observed = first_position(&trace, TraceEventKind::WorkerIdentityObserved)
                    .expect("accepted success must observe worker identity");
                let persisted = first_position(&trace, TraceEventKind::WorkerIdentityPersisted)
                    .expect("accepted success must persist worker identity");
                let released = first_position(&trace, TraceEventKind::PayloadReleased)
                    .expect("accepted success must release the payload");
                let exited = first_position(&trace, TraceEventKind::PayloadExited)
                    .expect("accepted success must observe payload exit");
                let receipt = first_position(&trace, TraceEventKind::ProcessReceiptPersisted)
                    .expect("accepted success must publish a receipt");
                let lifecycle = trace
                    .iter()
                    .rposition(|item| item.kind == TraceEventKind::LifecyclePostconditionValidated)
                    .expect("accepted success must validate the lifecycle postcondition");
                let terminal = first_position(&trace, TraceEventKind::TerminalSuccessRecorded)
                    .expect("accepted success must contain a terminal-success event");
                let latest_post_receipt_target = trace
                    .iter()
                    .enumerate()
                    .filter(|(index, item)| {
                        *index > receipt
                            && *index < terminal
                            && matches!(item.kind, TraceEventKind::TargetObserved(_))
                    })
                    .map(|(index, item)| (index, item.kind))
                    .last()
                    .expect("accepted success must include a post-receipt target observation");

                assert!(auth < prepared, "seed {seed}: authorization ordering");
                assert!(prepared < barrier, "seed {seed}: preparation ordering");
                assert!(barrier < submitted, "seed {seed}: write-ahead ordering");
                assert!(submitted < observed, "seed {seed}: manager observation ordering");
                assert!(observed < persisted, "seed {seed}: identity durability ordering");
                assert!(persisted < released, "seed {seed}: payload release ordering");
                assert!(released < exited, "seed {seed}: exit ordering");
                assert!(exited < receipt, "seed {seed}: receipt ordering");
                assert!(
                    receipt < latest_post_receipt_target.0,
                    "seed {seed}: target observation must be fresh"
                );
                assert!(
                    matches!(
                        latest_post_receipt_target.1,
                        TraceEventKind::TargetObserved(
                            TargetObservation::CandidateRuntimeAndProfileActive
                        )
                    ),
                    "seed {seed}: most recent target must be candidate-active"
                );
                assert!(latest_post_receipt_target.0 < lifecycle);
                assert!(lifecycle < terminal, "seed {seed}: lifecycle before terminal");
            } else if !trace
                .iter()
                .any(|item| item.kind == TraceEventKind::TerminalSuccessRecorded)
            {
                assert!(
                    !result.terminal_success_claimed,
                    "seed {seed}: terminal claim invented by validator"
                );
            }
        }
    }


    #[test]
    fn deterministic_mutations_of_valid_trace_reject_required_evidence_loss() {
        for seed in 0..20_000_u64 {
            let mutation = (seed % 10) as usize;
            let mut trace = valid_success_trace();

            match mutation {
                0 => {}
                1 => {
                    trace.remove(0); // exact authorization evidence
                }
                2 => {
                    trace.remove(2); // write-ahead barrier
                }
                3 => {
                    trace.remove(5); // durable worker identity
                }
                4 => {
                    trace.remove(8); // process receipt
                }
                5 => {
                    let target = match (seed / 10) % 5 {
                        0 => TargetObservation::NotAttempted,
                        1 => TargetObservation::PredecessorRuntimeAndProfileActive,
                        2 => TargetObservation::BootCandidateProfileSelected,
                        3 => TargetObservation::MixedOrUnknown,
                        _ => TargetObservation::Unavailable,
                    };
                    trace[9].kind = TraceEventKind::TargetObserved(target);
                }
                6 => {
                    if (seed / 10) % 2 == 0 {
                        trace[8].attempt_id = "attempt-from-another-worker".to_owned();
                    } else {
                        trace[8].transaction_id = "transaction-from-another-worker".to_owned();
                    }
                }
                7 => {
                    let position = 3 + ((seed / 10) % 4) as usize;
                    trace.insert(position, event(TraceEventKind::ManagerStartSubmitted));
                }
                8 => {
                    let trailing_kind = match (seed / 10) % 12 {
                        0 => TraceEventKind::AuthorizationVerified,
                        1 => TraceEventKind::AttemptPreparedDurably,
                        2 => TraceEventKind::SubmissionBarrierPersisted,
                        3 => TraceEventKind::ManagerStartSubmitted,
                        4 => TraceEventKind::WorkerIdentityObserved,
                        5 => TraceEventKind::WorkerIdentityPersisted,
                        6 => TraceEventKind::PayloadReleased,
                        7 => TraceEventKind::PayloadExited,
                        8 => TraceEventKind::ProcessReceiptPersisted,
                        9 => TraceEventKind::TargetObserved(
                            TargetObservation::CandidateRuntimeAndProfileActive,
                        ),
                        10 => TraceEventKind::LifecyclePostconditionValidated,
                        _ => TraceEventKind::TerminalSuccessRecorded,
                    };
                    trace.push(event(trailing_kind));
                }
                _ => {
                    let target = trace.remove(9);
                    let position = ((seed / 10) % 8) as usize;
                    trace.insert(position, target); // target snapshot predates process exit
                }
            }

            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
            if mutation == 0 {
                assert!(result.is_valid_prefix(), "seed {seed}: valid trace rejected");
                assert!(result.is_terminal_success());
            } else {
                assert!(
                    !result.is_valid_prefix(),
                    "seed {seed}, mutation {mutation}: unsafe trace accepted"
                );
                assert_eq!(result.disposition, TraceDisposition::Rejected);
            }
        }
    }


    #[test]
    fn duplicate_one_shot_milestones_are_rejected() {
        let cases = [
            (
                TraceEventKind::AuthorizationVerified,
                TraceViolationKind::DuplicateAuthorizationVerification,
            ),
            (
                TraceEventKind::AttemptPreparedDurably,
                TraceViolationKind::DuplicateAttemptPreparation,
            ),
            (
                TraceEventKind::SubmissionBarrierPersisted,
                TraceViolationKind::DuplicateSubmissionBarrier,
            ),
            (
                TraceEventKind::ManagerStartSubmitted,
                TraceViolationKind::DuplicateManagerStartSubmission,
            ),
            (
                TraceEventKind::WorkerIdentityObserved,
                TraceViolationKind::DuplicateWorkerIdentityObservation,
            ),
            (
                TraceEventKind::WorkerIdentityPersisted,
                TraceViolationKind::DuplicateWorkerIdentityPersistence,
            ),
            (
                TraceEventKind::PayloadReleased,
                TraceViolationKind::DuplicatePayloadRelease,
            ),
            (
                TraceEventKind::PayloadExited,
                TraceViolationKind::DuplicatePayloadExit,
            ),
            (
                TraceEventKind::ProcessReceiptPersisted,
                TraceViolationKind::DuplicateProcessReceiptPublication,
            ),
            (
                TraceEventKind::LifecyclePostconditionValidated,
                TraceViolationKind::DuplicateLifecycleValidation,
            ),
        ];

        for (milestone, expected_violation) in cases {
            let mut trace = valid_success_trace();
            let first = trace
                .iter()
                .position(|item| item.kind == milestone)
                .expect("milestone should exist in valid trace");
            trace.insert(first + 1, event(milestone));

            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
            assert_eq!(result.disposition, TraceDisposition::Rejected);
            assert!(
                result
                    .violations
                    .iter()
                    .any(|violation| violation.kind == expected_violation),
                "duplicate {:?} was not rejected: {:?}",
                milestone,
                result.violations
            );
        }
    }


    #[test]
    fn duplicate_failed_lifecycle_validation_is_rejected_without_new_target_evidence() {
        let mut trace = valid_success_trace();
        trace[9].kind = TraceEventKind::TargetObserved(TargetObservation::MixedOrUnknown);
        trace.insert(11, event(TraceEventKind::LifecyclePostconditionValidated));

        let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
        assert_eq!(result.disposition, TraceDisposition::Rejected);
        assert!(result.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::DuplicateLifecycleValidation
        }));
    }


    #[test]
    fn empty_expected_transaction_or_attempt_identity_can_never_validate_success() {
        let trace = valid_success_trace();
        let bad_transaction = validate_trace("", ATTEMPT, &trace);
        assert_eq!(bad_transaction.disposition, TraceDisposition::Rejected);
        assert!(bad_transaction.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::EmptyExpectedTransactionId
                && violation.event_index == usize::MAX
        }));

        let bad_attempt = validate_trace(TRANSACTION, "  ", &trace);
        assert_eq!(bad_attempt.disposition, TraceDisposition::Rejected);
        assert!(bad_attempt.violations.iter().any(|violation| {
            violation.kind == TraceViolationKind::EmptyExpectedAttemptId
                && violation.event_index == usize::MAX
        }));
    }


    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn deleting_any_mandatory_success_event_cannot_still_prove_success(index in 0usize..12) {
            let mut trace = valid_success_trace();
            trace.remove(index);
            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
            prop_assert_ne!(
                result.disposition,
                TraceDisposition::ValidatedTerminalSuccess,
                "removing event {index} must prevent terminal success"
            );
        }

        #[test]
        fn event_identity_rebinding_always_rejects_success(
            index in 0usize..12,
            foreign_transaction in any::<bool>(),
            foreign_attempt in any::<bool>()
        ) {
            let mut trace = valid_success_trace();
            if foreign_transaction {
                trace[index].transaction_id = "foreign-transaction".to_owned();
            }
            if foreign_attempt {
                trace[index].attempt_id = "foreign-attempt".to_owned();
            }

            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);
            if foreign_transaction || foreign_attempt {
                prop_assert_eq!(result.disposition, TraceDisposition::Rejected);
            } else {
                prop_assert_eq!(result.disposition, TraceDisposition::ValidatedTerminalSuccess);
            }
        }

        #[test]
        fn only_candidate_active_target_can_satisfy_terminal_state(
            observation_code in 0u8..6
        ) {
            let observation = match observation_code {
                0 => TargetObservation::NotAttempted,
                1 => TargetObservation::CandidateRuntimeAndProfileActive,
                2 => TargetObservation::PredecessorRuntimeAndProfileActive,
                3 => TargetObservation::BootCandidateProfileSelected,
                4 => TargetObservation::MixedOrUnknown,
                _ => TargetObservation::Unavailable,
            };
            let mut trace = valid_success_trace();
            trace[9].kind = TraceEventKind::TargetObserved(observation);
            let result = validate_trace(TRANSACTION, ATTEMPT, &trace);

            if observation == TargetObservation::CandidateRuntimeAndProfileActive {
                prop_assert_eq!(result.disposition, TraceDisposition::ValidatedTerminalSuccess);
            } else {
                prop_assert_eq!(result.disposition, TraceDisposition::Rejected);
            }
        }
    }


    fn fixture_event_kind(name: &str) -> TraceEventKind {
        match name {
            "authorization_verified" => TraceEventKind::AuthorizationVerified,
            "attempt_prepared_durably" => TraceEventKind::AttemptPreparedDurably,
            "submission_barrier_persisted" => TraceEventKind::SubmissionBarrierPersisted,
            "manager_start_submitted" => TraceEventKind::ManagerStartSubmitted,
            "worker_identity_observed" => TraceEventKind::WorkerIdentityObserved,
            "worker_identity_persisted" => TraceEventKind::WorkerIdentityPersisted,
            "payload_released" => TraceEventKind::PayloadReleased,
            "payload_exited" => TraceEventKind::PayloadExited,
            "process_receipt_persisted" => TraceEventKind::ProcessReceiptPersisted,
            "lifecycle_postcondition_validated" => {
                TraceEventKind::LifecyclePostconditionValidated
            }
            "terminal_success_recorded" => TraceEventKind::TerminalSuccessRecorded,
            other if other.starts_with("target_observed:") => {
                let state = other.strip_prefix("target_observed:").unwrap();
                let observation = match state {
                    "not_attempted" => TargetObservation::NotAttempted,
                    "candidate_runtime_and_profile_active" => {
                        TargetObservation::CandidateRuntimeAndProfileActive
                    }
                    "predecessor_runtime_and_profile_active" => {
                        TargetObservation::PredecessorRuntimeAndProfileActive
                    }
                    "boot_candidate_profile_selected" => {
                        TargetObservation::BootCandidateProfileSelected
                    }
                    "mixed_or_unknown" => TargetObservation::MixedOrUnknown,
                    "unavailable" => TargetObservation::Unavailable,
                    _ => panic!("unknown target observation in fixture: {state}"),
                };
                TraceEventKind::TargetObserved(observation)
            }
            other => panic!("unknown event kind in qualification fixture: {other}"),
        }
    }

    fn fixture_disposition_name(disposition: TraceDisposition) -> &'static str {
        match disposition {
            TraceDisposition::Rejected => "rejected",
            TraceDisposition::Incomplete => "incomplete",
            TraceDisposition::ValidatedTerminalSuccess => "validated_terminal_success",
        }
    }

    fn fixture_violation_name(kind: TraceViolationKind) -> &'static str {
        match kind {
            TraceViolationKind::EventIdentityBindingMismatch => "event_identity_binding_mismatch",
            TraceViolationKind::EmptyExpectedTransactionId => "empty_expected_transaction_id",
            TraceViolationKind::EmptyExpectedAttemptId => "empty_expected_attempt_id",
            TraceViolationKind::DuplicateAuthorizationVerification => {
                "duplicate_authorization_verification"
            }
            TraceViolationKind::DuplicateAttemptPreparation => "duplicate_attempt_preparation",
            TraceViolationKind::DuplicateSubmissionBarrier => "duplicate_submission_barrier",
            TraceViolationKind::AttemptPreparedWithoutVerifiedAuthorization => {
                "attempt_prepared_without_verified_authorization"
            }
            TraceViolationKind::SubmissionBarrierWithoutPreparedAttempt => {
                "submission_barrier_without_prepared_attempt"
            }
            TraceViolationKind::StartSubmissionWithoutWriteAheadBarrier => {
                "start_submission_without_write_ahead_barrier"
            }
            TraceViolationKind::DuplicateManagerStartSubmission => {
                "duplicate_manager_start_submission"
            }
            TraceViolationKind::WorkerIdentityObservedBeforeStartSubmission => {
                "worker_identity_observed_before_start_submission"
            }
            TraceViolationKind::DuplicateWorkerIdentityObservation => {
                "duplicate_worker_identity_observation"
            }
            TraceViolationKind::WorkerIdentityPersistedBeforeObservation => {
                "worker_identity_persisted_before_observation"
            }
            TraceViolationKind::DuplicateWorkerIdentityPersistence => {
                "duplicate_worker_identity_persistence"
            }
            TraceViolationKind::PayloadReleasedWithoutAuthorization => {
                "payload_released_without_authorization"
            }
            TraceViolationKind::PayloadReleasedBeforeStartSubmission => {
                "payload_released_before_start_submission"
            }
            TraceViolationKind::PayloadReleasedBeforeDurableWorkerIdentity => {
                "payload_released_before_durable_worker_identity"
            }
            TraceViolationKind::DuplicatePayloadRelease => "duplicate_payload_release",
            TraceViolationKind::PayloadExitBeforePayloadRelease => {
                "payload_exit_before_payload_release"
            }
            TraceViolationKind::DuplicatePayloadExit => "duplicate_payload_exit",
            TraceViolationKind::ReceiptBeforePayloadExit => "receipt_before_payload_exit",
            TraceViolationKind::ReceiptWithoutDurableWorkerIdentity => {
                "receipt_without_durable_worker_identity"
            }
            TraceViolationKind::DuplicateProcessReceiptPublication => {
                "duplicate_process_receipt_publication"
            }
            TraceViolationKind::LifecycleValidationBeforePayloadExit => {
                "lifecycle_validation_before_payload_exit"
            }
            TraceViolationKind::LifecycleValidationWithoutPostExitTargetObservation => {
                "lifecycle_validation_without_post_exit_target_observation"
            }
            TraceViolationKind::LifecycleValidationWithoutCandidatePostState => {
                "lifecycle_validation_without_candidate_post_state"
            }
            TraceViolationKind::DuplicateLifecycleValidation => {
                "duplicate_lifecycle_validation"
            }
            TraceViolationKind::TerminalSuccessWithoutProcessReceipt => {
                "terminal_success_without_process_receipt"
            }
            TraceViolationKind::TerminalSuccessWithoutCandidatePostState => {
                "terminal_success_without_candidate_post_state"
            }
            TraceViolationKind::TerminalSuccessWithoutLifecycleValidation => {
                "terminal_success_without_lifecycle_validation"
            }
            TraceViolationKind::EventAfterTerminalSuccess => "event_after_terminal_success",
        }
    }

    #[test]
    fn shared_json_qualification_vectors_match_the_rust_validator() {
        use std::collections::HashSet;

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../docs/fixtures/supervisor-temporal-qualification-v1.json"
        ))
        .expect("qualification fixture must parse as JSON");
        assert_eq!(
            fixture["schema"].as_str(),
            Some("org.luminousdynamics.nixward.supervisor-temporal-trace-vectors")
        );
        assert_eq!(fixture["version"].as_u64(), Some(1));
        let vectors = fixture["vectors"]
            .as_array()
            .expect("qualification vectors must be an array");
        assert_eq!(vectors.len(), 33);

        let mut ids = HashSet::new();
        for vector in vectors {
            let id = vector["id"]
                .as_str()
                .expect("every vector must have an ID");
            assert!(ids.insert(id.to_owned()), "duplicate fixture ID: {id}");

            let expected_transaction_id = vector["expected_transaction_id"]
                .as_str()
                .expect("expected transaction identity must be a string");
            let expected_attempt_id = vector["expected_attempt_id"]
                .as_str()
                .expect("expected attempt identity must be a string");
            let event_values = vector["events"]
                .as_array()
                .expect("events must be an array");
            let events = event_values
                .iter()
                .map(|value| {
                    let transaction_id = value["transaction_id"]
                        .as_str()
                        .expect("event transaction identity must be a string");
                    let attempt_id = value["attempt_id"]
                        .as_str()
                        .expect("event attempt identity must be a string");
                    let kind = value["kind"]
                        .as_str()
                        .expect("event kind must be a string");
                    TraceEvent {
                        transaction_id: transaction_id.to_owned(),
                        attempt_id: attempt_id.to_owned(),
                        kind: fixture_event_kind(kind),
                    }
                })
                .collect::<Vec<_>>();

            let actual = validate_trace(expected_transaction_id, expected_attempt_id, &events);
            let expected_disposition = vector["expected_disposition"]
                .as_str()
                .expect("expected disposition must be a string");
            assert_eq!(
                fixture_disposition_name(actual.disposition),
                expected_disposition,
                "wrong disposition for qualification vector {id}: {:?}",
                actual.violations
            );
            assert_eq!(
                actual.terminal_success_claimed,
                vector["expected_terminal_success_claimed"]
                    .as_bool()
                    .expect("terminal-success claim expectation must be Boolean"),
                "wrong terminal-success claim for qualification vector {id}"
            );

            let mut actual_violations = actual
                .violations
                .iter()
                .map(|violation| fixture_violation_name(violation.kind).to_owned())
                .collect::<Vec<_>>();
            let mut expected_violations = vector["expected_violations"]
                .as_array()
                .expect("expected violations must be an array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("expected violation name must be a string")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            actual_violations.sort_unstable();
            expected_violations.sort_unstable();
            assert_eq!(
                actual_violations, expected_violations,
                "wrong violation set for qualification vector {id}"
            );
        }
    }

}
