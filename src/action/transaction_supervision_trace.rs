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
                }
            }
            TraceEventKind::LifecyclePostconditionValidated => {
                if lifecycle_postcondition_validated {
                    violations.push(TraceViolation {
                        event_index,
                        kind: TraceViolationKind::DuplicateLifecycleValidation,
                    });
                }
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
                let safe_order = prefix.as_slice() == &required_order[..];
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
            if result.is_safe() && result.terminal_success_recorded {
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
                    !result.terminal_success_recorded,
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
                assert!(result.is_safe(), "seed {seed}: valid trace rejected");
                assert!(result.terminal_success_recorded);
            } else {
                assert!(
                    !result.is_safe(),
                    "seed {seed}, mutation {mutation}: unsafe trace accepted"
                );
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

}
