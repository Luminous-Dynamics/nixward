// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Pure, conservative triage for interrupted transaction supervision.
//!
//! This module does not execute commands, authorize mutation, or promote a
//! transaction. It answers only which observation/hold state is safe given
//! worker-identity, process-receipt, and target-observation inputs.

/// What the observer can currently establish about the exact persisted worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerIdentityStatus {
    /// The PID, boot ID, and start-time tuple still identify the persisted worker.
    ExactWorkerLive,
    /// The same process identity was observed to exit.
    ExactWorkerExited,
    /// The exact worker is no longer present; the PID may be absent or reused.
    ExactWorkerNoLongerPresent,
    /// The persisted worker's boot ID differs from the currently running host.
    PreviousBoot,
    /// Permissions, procfs, pidfd, or other evidence prevents a safe conclusion.
    Unknown,
}

/// Validation result for a process-observation sidecar.
///
/// These variants are caller-asserted classifications, not raw JSON. A caller
/// must use the receipt validator before choosing either Valid* variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessReceiptStatus {
    ValidExitCode(i32),
    ValidSignal(i32),
    Missing,
    Invalid,
}

/// Result of a separate, read-only target-side observation.
///
/// Candidate and predecessor describe observed state only. They are not
/// transaction-terminal states and do not grant permission to mutate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetObservation {
    NotAttempted,
    CandidateRuntimeAndProfileActive,
    PredecessorRuntimeAndProfileActive,
    BootCandidateProfileSelected,
    MixedOrUnknown,
    Unavailable,
}

/// Conservative next-step advice; no variant authorizes a system mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationDecision {
    /// Wait for the identified process while keeping concurrent mutation blocked.
    ContinueObservingWorker {
        receipt: ProcessReceiptStatus,
    },
    /// Process identity/liveness cannot be established safely.
    HoldForIdentityResolution,
    /// Receipt claims process termination while the exact same worker is live.
    HoldForContradictoryEvidence,
    /// An exact process is no longer live, so fresh read-only target observation is required.
    RequireReadOnlyTargetObservation {
        receipt: ProcessReceiptStatus,
    },
    /// Candidate state is observed; the transaction-domain state machine must still validate intent.
    CandidatePostStateObservedNeedsLifecycleValidation {
        receipt: ProcessReceiptStatus,
    },
    /// Predecessor state is observed; this does not itself prove no transient mutation occurred.
    PredecessorPostStateObservedNeedsLifecycleValidation {
        receipt: ProcessReceiptStatus,
    },
    /// A boot profile is selected but the candidate is not thereby proven to be running.
    BootSelectionObservedNeedsLifecycleValidation {
        receipt: ProcessReceiptStatus,
    },
    /// Read-only observation was attempted but did not establish an admissible state.
    HoldForMoreReadOnlyEvidence {
        receipt: ProcessReceiptStatus,
    },
}

/// Determine the conservative next observation step after interruption.
///
/// Safety properties:
/// - An unknown process identity never leads to a terminal classification.
/// - A receipt claiming exit while the exact worker is live is contradictory.
/// - A missing/invalid receipt never implies that the command did not run.
/// - Even a valid process receipt requires independent target observation.
/// - A target-state match never authorizes mutation or directly promotes the journal.
pub fn decide_reconciliation(
    worker: WorkerIdentityStatus,
    receipt: ProcessReceiptStatus,
    target: TargetObservation,
) -> ReconciliationDecision {
    if worker == WorkerIdentityStatus::Unknown {
        return ReconciliationDecision::HoldForIdentityResolution;
    }

    if worker == WorkerIdentityStatus::ExactWorkerLive {
        return match receipt {
            ProcessReceiptStatus::ValidExitCode(_) | ProcessReceiptStatus::ValidSignal(_) => {
                ReconciliationDecision::HoldForContradictoryEvidence
            }
            ProcessReceiptStatus::Missing | ProcessReceiptStatus::Invalid => {
                ReconciliationDecision::ContinueObservingWorker { receipt }
            }
        };
    }

    match target {
        TargetObservation::NotAttempted => {
            ReconciliationDecision::RequireReadOnlyTargetObservation { receipt }
        }
        TargetObservation::CandidateRuntimeAndProfileActive => {
            ReconciliationDecision::CandidatePostStateObservedNeedsLifecycleValidation { receipt }
        }
        TargetObservation::PredecessorRuntimeAndProfileActive => {
            ReconciliationDecision::PredecessorPostStateObservedNeedsLifecycleValidation { receipt }
        }
        TargetObservation::BootCandidateProfileSelected => {
            ReconciliationDecision::BootSelectionObservedNeedsLifecycleValidation { receipt }
        }
        TargetObservation::MixedOrUnknown | TargetObservation::Unavailable => {
            ReconciliationDecision::HoldForMoreReadOnlyEvidence { receipt }
        }
    }
}

/// Durable progress recorded around a systemd StartTransientUnit request.
///
/// SubmissionMayHaveOccurred must be persisted before the D-Bus request is sent.
/// This intentionally means a crash just before send is treated as ambiguous;
/// that sacrifices automatic retry/liveness to avoid duplicate privileged starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStartIntent {
    /// Durable state proves no start request has been submitted for this attempt.
    PreparedNotSubmitted,
    /// The pre-call barrier was persisted; the manager may have accepted the request.
    SubmissionMayHaveOccurred,
    /// The unit invocation identity was observed after manager acceptance and durably recorded.
    UnitInvocationIdentityPersisted,
}

/// Read-only result of querying the manager for this exact persisted start attempt's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerUnitObservation {
    NotQueried,
    MatchingAttemptUnit,
    ConflictingUnitIdentity,
    Absent,
    Unavailable,
}

/// Result of correlating the canonical manager unit with the persisted
/// systemd invocation identity. These are observations, not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerInvocationObservation {
    /// Invocation lookup/property validation has not been performed yet.
    NotQueried,
    /// PIDFD lookup and unit properties both bind to the expected attempt invocation.
    ExactAttemptInvocation,
    /// An invocation was found, but its unit/ID does not match the expected attempt.
    ConflictingInvocation,
    /// The canonical unit exists but currently exposes no admissible invocation ID.
    Missing,
    /// The manager/property query failed or returned malformed identity evidence.
    Unavailable,
    /// The manager predates GetUnitByPIDFD (systemd < 253).
    Unsupported,
}

/// Restart/recovery directives after both unit-name and invocation evidence
/// are considered. No variant authorizes a new mutation or terminal promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStartInvocationRecoveryDecision {
    SubmitInitialStartAfterDurablePreflight,
    QueryCanonicalManagerUnit,
    QueryUnitInvocationIdentity,
    ObserveExactAttemptInvocation,
    HoldOnUnitIdentityConflict,
    HoldOnInvocationIdentityConflict,
    HoldForInvocationIdentityResolution,
    HoldForUnsupportedManager,
    ReconcileTargetBeforeAnyNewAttempt,
}

/// Apply the strict restart gate after the name-level manager lookup.
///
/// A matching canonical unit name is only a preliminary observation. For any
/// attempt whose manager submission may have happened, observation may resume
/// only after the exact systemd invocation ID has been independently bound to
/// the expected PIDFD/unit/MainPID identity. Missing, unavailable, conflicting,
/// or unsupported invocation evidence never becomes an automatic retry.
pub fn decide_worker_start_recovery_with_invocation(
    intent: WorkerStartIntent,
    manager: ManagerUnitObservation,
    invocation: ManagerInvocationObservation,
) -> WorkerStartInvocationRecoveryDecision {
    match intent {
        WorkerStartIntent::PreparedNotSubmitted => match manager {
            ManagerUnitObservation::NotQueried | ManagerUnitObservation::Unavailable => {
                WorkerStartInvocationRecoveryDecision::QueryCanonicalManagerUnit
            }
            ManagerUnitObservation::MatchingAttemptUnit
            | ManagerUnitObservation::ConflictingUnitIdentity => {
                WorkerStartInvocationRecoveryDecision::HoldOnUnitIdentityConflict
            }
            ManagerUnitObservation::Absent => match invocation {
                ManagerInvocationObservation::NotQueried
                | ManagerInvocationObservation::Missing
                | ManagerInvocationObservation::Unavailable => {
                    WorkerStartInvocationRecoveryDecision::SubmitInitialStartAfterDurablePreflight
                }
                ManagerInvocationObservation::ExactAttemptInvocation
                | ManagerInvocationObservation::ConflictingInvocation => {
                    WorkerStartInvocationRecoveryDecision::HoldOnInvocationIdentityConflict
                }
                ManagerInvocationObservation::Unsupported => {
                    WorkerStartInvocationRecoveryDecision::HoldForUnsupportedManager
                }
            },
        },
        WorkerStartIntent::SubmissionMayHaveOccurred
        | WorkerStartIntent::UnitInvocationIdentityPersisted => match manager {
            ManagerUnitObservation::NotQueried | ManagerUnitObservation::Unavailable => {
                WorkerStartInvocationRecoveryDecision::QueryCanonicalManagerUnit
            }
            ManagerUnitObservation::ConflictingUnitIdentity => {
                WorkerStartInvocationRecoveryDecision::HoldOnUnitIdentityConflict
            }
            ManagerUnitObservation::Absent => match invocation {
                ManagerInvocationObservation::ExactAttemptInvocation
                | ManagerInvocationObservation::ConflictingInvocation => {
                    WorkerStartInvocationRecoveryDecision::HoldOnInvocationIdentityConflict
                }
                ManagerInvocationObservation::NotQueried
                    if intent == WorkerStartIntent::UnitInvocationIdentityPersisted =>
                {
                    // The canonical name lookup can miss an unloaded unit. Use
                    // the persisted InvocationID lookup before concluding it
                    // is absent and reconciling the host.
                    WorkerStartInvocationRecoveryDecision::QueryUnitInvocationIdentity
                }
                ManagerInvocationObservation::NotQueried
                | ManagerInvocationObservation::Missing
                | ManagerInvocationObservation::Unavailable => {
                    WorkerStartInvocationRecoveryDecision::ReconcileTargetBeforeAnyNewAttempt
                }
                ManagerInvocationObservation::Unsupported => {
                    WorkerStartInvocationRecoveryDecision::HoldForUnsupportedManager
                }
            },
            ManagerUnitObservation::MatchingAttemptUnit => match invocation {
                ManagerInvocationObservation::NotQueried => {
                    WorkerStartInvocationRecoveryDecision::QueryUnitInvocationIdentity
                }
                ManagerInvocationObservation::ExactAttemptInvocation => {
                    WorkerStartInvocationRecoveryDecision::ObserveExactAttemptInvocation
                }
                ManagerInvocationObservation::ConflictingInvocation => {
                    WorkerStartInvocationRecoveryDecision::HoldOnInvocationIdentityConflict
                }
                ManagerInvocationObservation::Missing | ManagerInvocationObservation::Unavailable => {
                    WorkerStartInvocationRecoveryDecision::HoldForInvocationIdentityResolution
                }
                ManagerInvocationObservation::Unsupported => {
                    WorkerStartInvocationRecoveryDecision::HoldForUnsupportedManager
                }
            },
        },
    }
}

/// Safe restart behavior for the unit-start operation.
///
/// None of these outcomes authorizes a system mutation. In particular, a lost
/// manager response followed by an absent unit requires target-state reconciliation,
/// not an automatic second StartTransientUnit call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStartRecoveryDecision {
    SubmitInitialStartAfterDurablePreflight,
    QueryCanonicalManagerUnit,
    ObserveExistingMatchingUnit,
    HoldOnUnitIdentityConflict,
    ReconcileTargetBeforeAnyNewAttempt,
}

/// Perform the name-level prefilter for a systemd worker-start attempt.
///
/// This compatibility classifier is not the final recovery gate for an
/// ambiguous submission: `ObserveExistingMatchingUnit` establishes only a
/// canonical unit-name match. Callers must additionally use
/// `decide_worker_start_recovery_with_invocation` with independently validated
/// PIDFD/unit/MainPID InvocationID evidence before resuming worker observation.
pub fn decide_worker_start_recovery(
    intent: WorkerStartIntent,
    manager: ManagerUnitObservation,
) -> WorkerStartRecoveryDecision {
    match intent {
        WorkerStartIntent::PreparedNotSubmitted => match manager {
            ManagerUnitObservation::Absent => {
                WorkerStartRecoveryDecision::SubmitInitialStartAfterDurablePreflight
            }
            ManagerUnitObservation::NotQueried | ManagerUnitObservation::Unavailable => {
                WorkerStartRecoveryDecision::QueryCanonicalManagerUnit
            }
            ManagerUnitObservation::MatchingAttemptUnit
            | ManagerUnitObservation::ConflictingUnitIdentity => {
                WorkerStartRecoveryDecision::HoldOnUnitIdentityConflict
            }
        },
        WorkerStartIntent::SubmissionMayHaveOccurred | WorkerStartIntent::UnitInvocationIdentityPersisted => {
            match manager {
                ManagerUnitObservation::MatchingAttemptUnit => {
                    WorkerStartRecoveryDecision::ObserveExistingMatchingUnit
                }
                ManagerUnitObservation::ConflictingUnitIdentity => {
                    WorkerStartRecoveryDecision::HoldOnUnitIdentityConflict
                }
                ManagerUnitObservation::Absent => {
                    WorkerStartRecoveryDecision::ReconcileTargetBeforeAnyNewAttempt
                }
                ManagerUnitObservation::NotQueried | ManagerUnitObservation::Unavailable => {
                    WorkerStartRecoveryDecision::QueryCanonicalManagerUnit
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKER_STATES: [WorkerIdentityStatus; 5] = [
        WorkerIdentityStatus::ExactWorkerLive,
        WorkerIdentityStatus::ExactWorkerExited,
        WorkerIdentityStatus::ExactWorkerNoLongerPresent,
        WorkerIdentityStatus::PreviousBoot,
        WorkerIdentityStatus::Unknown,
    ];
    const RECEIPTS: [ProcessReceiptStatus; 4] = [
        ProcessReceiptStatus::ValidExitCode(0),
        ProcessReceiptStatus::ValidExitCode(23),
        ProcessReceiptStatus::ValidSignal(9),
        ProcessReceiptStatus::Missing,
    ];
    const TARGETS: [TargetObservation; 6] = [
        TargetObservation::NotAttempted,
        TargetObservation::CandidateRuntimeAndProfileActive,
        TargetObservation::PredecessorRuntimeAndProfileActive,
        TargetObservation::BootCandidateProfileSelected,
        TargetObservation::MixedOrUnknown,
        TargetObservation::Unavailable,
    ];

    #[test]
    fn every_worker_receipt_and_target_combination_fails_closed() {
        for worker in WORKER_STATES {
            for receipt in RECEIPTS.into_iter().chain([ProcessReceiptStatus::Invalid]) {
                for target in TARGETS {
                    let actual = decide_reconciliation(worker, receipt, target);

                    match worker {
                        WorkerIdentityStatus::Unknown => {
                            assert_eq!(
                                actual,
                                ReconciliationDecision::HoldForIdentityResolution,
                                "unknown process identity must dominate all other evidence"
                            );
                        }
                        WorkerIdentityStatus::ExactWorkerLive => match receipt {
                            ProcessReceiptStatus::ValidExitCode(_)
                            | ProcessReceiptStatus::ValidSignal(_) => assert_eq!(
                                actual,
                                ReconciliationDecision::HoldForContradictoryEvidence,
                                "a valid termination receipt conflicts with the same live worker identity"
                            ),
                            ProcessReceiptStatus::Missing | ProcessReceiptStatus::Invalid => assert_eq!(
                                actual,
                                ReconciliationDecision::ContinueObservingWorker { receipt },
                                "missing/untrusted receipt must not cancel observation of a live worker"
                            ),
                        },
                        WorkerIdentityStatus::ExactWorkerExited
                        | WorkerIdentityStatus::ExactWorkerNoLongerPresent
                        | WorkerIdentityStatus::PreviousBoot => {
                            let expected = match target {
                                TargetObservation::NotAttempted => {
                                    ReconciliationDecision::RequireReadOnlyTargetObservation { receipt }
                                }
                                TargetObservation::CandidateRuntimeAndProfileActive => {
                                    ReconciliationDecision::CandidatePostStateObservedNeedsLifecycleValidation { receipt }
                                }
                                TargetObservation::PredecessorRuntimeAndProfileActive => {
                                    ReconciliationDecision::PredecessorPostStateObservedNeedsLifecycleValidation { receipt }
                                }
                                TargetObservation::BootCandidateProfileSelected => {
                                    ReconciliationDecision::BootSelectionObservedNeedsLifecycleValidation { receipt }
                                }
                                TargetObservation::MixedOrUnknown | TargetObservation::Unavailable => {
                                    ReconciliationDecision::HoldForMoreReadOnlyEvidence { receipt }
                                }
                            };
                            assert_eq!(actual, expected);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_manager_start_recovery_combination_prevents_ambiguous_replay() {
        const INTENTS: [WorkerStartIntent; 3] = [
            WorkerStartIntent::PreparedNotSubmitted,
            WorkerStartIntent::SubmissionMayHaveOccurred,
            WorkerStartIntent::UnitInvocationIdentityPersisted,
        ];
        const MANAGER_STATES: [ManagerUnitObservation; 5] = [
            ManagerUnitObservation::NotQueried,
            ManagerUnitObservation::MatchingAttemptUnit,
            ManagerUnitObservation::ConflictingUnitIdentity,
            ManagerUnitObservation::Absent,
            ManagerUnitObservation::Unavailable,
        ];

        for intent in INTENTS {
            for manager in MANAGER_STATES {
                let actual = decide_worker_start_recovery(intent, manager);
                let expected = match (intent, manager) {
                    (WorkerStartIntent::PreparedNotSubmitted, ManagerUnitObservation::Absent) => {
                        WorkerStartRecoveryDecision::SubmitInitialStartAfterDurablePreflight
                    }
                    (WorkerStartIntent::PreparedNotSubmitted, ManagerUnitObservation::NotQueried)
                    | (WorkerStartIntent::PreparedNotSubmitted, ManagerUnitObservation::Unavailable)
                    | (WorkerStartIntent::SubmissionMayHaveOccurred, ManagerUnitObservation::NotQueried)
                    | (WorkerStartIntent::SubmissionMayHaveOccurred, ManagerUnitObservation::Unavailable)
                    | (WorkerStartIntent::UnitInvocationIdentityPersisted, ManagerUnitObservation::NotQueried)
                    | (WorkerStartIntent::UnitInvocationIdentityPersisted, ManagerUnitObservation::Unavailable) => {
                        WorkerStartRecoveryDecision::QueryCanonicalManagerUnit
                    }
                    (WorkerStartIntent::PreparedNotSubmitted, ManagerUnitObservation::MatchingAttemptUnit)
                    | (WorkerStartIntent::PreparedNotSubmitted, ManagerUnitObservation::ConflictingUnitIdentity)
                    | (WorkerStartIntent::SubmissionMayHaveOccurred, ManagerUnitObservation::ConflictingUnitIdentity)
                    | (WorkerStartIntent::UnitInvocationIdentityPersisted, ManagerUnitObservation::ConflictingUnitIdentity) => {
                        WorkerStartRecoveryDecision::HoldOnUnitIdentityConflict
                    }
                    (WorkerStartIntent::SubmissionMayHaveOccurred, ManagerUnitObservation::MatchingAttemptUnit)
                    | (WorkerStartIntent::UnitInvocationIdentityPersisted, ManagerUnitObservation::MatchingAttemptUnit) => {
                        WorkerStartRecoveryDecision::ObserveExistingMatchingUnit
                    }
                    (WorkerStartIntent::SubmissionMayHaveOccurred, ManagerUnitObservation::Absent)
                    | (WorkerStartIntent::UnitInvocationIdentityPersisted, ManagerUnitObservation::Absent) => {
                        WorkerStartRecoveryDecision::ReconcileTargetBeforeAnyNewAttempt
                    }
                };
                assert_eq!(actual, expected, "unsafe start-recovery result for {intent:?} × {manager:?}");
            }
        }
    }

    #[test]
    fn persisted_invocation_is_queried_even_when_canonical_unit_lookup_is_absent() {
        assert_eq!(
            decide_worker_start_recovery_with_invocation(
                WorkerStartIntent::UnitInvocationIdentityPersisted,
                ManagerUnitObservation::Absent,
                ManagerInvocationObservation::NotQueried,
            ),
            WorkerStartInvocationRecoveryDecision::QueryUnitInvocationIdentity
        );
        assert_eq!(
            decide_worker_start_recovery_with_invocation(
                WorkerStartIntent::SubmissionMayHaveOccurred,
                ManagerUnitObservation::Absent,
                ManagerInvocationObservation::NotQueried,
            ),
            WorkerStartInvocationRecoveryDecision::ReconcileTargetBeforeAnyNewAttempt
        );
    }

    #[test]
    fn canonical_unit_match_alone_never_resumes_ambiguous_worker_observation() {
        for intent in [
            WorkerStartIntent::SubmissionMayHaveOccurred,
            WorkerStartIntent::UnitInvocationIdentityPersisted,
        ] {
            assert_eq!(
                decide_worker_start_recovery_with_invocation(
                    intent,
                    ManagerUnitObservation::MatchingAttemptUnit,
                    ManagerInvocationObservation::NotQueried,
                ),
                WorkerStartInvocationRecoveryDecision::QueryUnitInvocationIdentity,
                "unit name alone is only a prefilter, not worker-invocation identity"
            );
            assert_eq!(
                decide_worker_start_recovery_with_invocation(
                    intent,
                    ManagerUnitObservation::MatchingAttemptUnit,
                    ManagerInvocationObservation::ExactAttemptInvocation,
                ),
                WorkerStartInvocationRecoveryDecision::ObserveExactAttemptInvocation
            );
        }
    }

    #[test]
    fn invocation_conflict_missing_and_unsupported_manager_never_resume_ambiguous_worker() {
        for intent in [
            WorkerStartIntent::SubmissionMayHaveOccurred,
            WorkerStartIntent::UnitInvocationIdentityPersisted,
        ] {
            for invocation in [
                ManagerInvocationObservation::ConflictingInvocation,
                ManagerInvocationObservation::Missing,
                ManagerInvocationObservation::Unavailable,
                ManagerInvocationObservation::Unsupported,
            ] {
                let decision = decide_worker_start_recovery_with_invocation(
                    intent,
                    ManagerUnitObservation::MatchingAttemptUnit,
                    invocation,
                );
                assert_ne!(
                    decision,
                    WorkerStartInvocationRecoveryDecision::ObserveExactAttemptInvocation,
                    "non-exact invocation evidence must never resume observation: {intent:?} × {invocation:?}"
                );
                assert_ne!(
                    decision,
                    WorkerStartInvocationRecoveryDecision::SubmitInitialStartAfterDurablePreflight,
                    "ambiguous attempts must never be resubmitted: {intent:?} × {invocation:?}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_unit_and_invocation_recovery_matrix_fails_closed() {
        const INTENTS: [WorkerStartIntent; 3] = [
            WorkerStartIntent::PreparedNotSubmitted,
            WorkerStartIntent::SubmissionMayHaveOccurred,
            WorkerStartIntent::UnitInvocationIdentityPersisted,
        ];
        const MANAGER_STATES: [ManagerUnitObservation; 5] = [
            ManagerUnitObservation::NotQueried,
            ManagerUnitObservation::MatchingAttemptUnit,
            ManagerUnitObservation::ConflictingUnitIdentity,
            ManagerUnitObservation::Absent,
            ManagerUnitObservation::Unavailable,
        ];
        const INVOCATION_STATES: [ManagerInvocationObservation; 6] = [
            ManagerInvocationObservation::NotQueried,
            ManagerInvocationObservation::ExactAttemptInvocation,
            ManagerInvocationObservation::ConflictingInvocation,
            ManagerInvocationObservation::Missing,
            ManagerInvocationObservation::Unavailable,
            ManagerInvocationObservation::Unsupported,
        ];

        let mut cases = 0usize;
        for intent in INTENTS {
            for manager in MANAGER_STATES {
                for invocation in INVOCATION_STATES {
                    cases += 1;
                    let actual = decide_worker_start_recovery_with_invocation(
                        intent,
                        manager,
                        invocation,
                    );
                    if intent != WorkerStartIntent::PreparedNotSubmitted {
                        assert_ne!(
                            actual,
                            WorkerStartInvocationRecoveryDecision::SubmitInitialStartAfterDurablePreflight,
                            "ambiguous intent must never submit: {intent:?} × {manager:?} × {invocation:?}"
                        );
                    }
                    if actual == WorkerStartInvocationRecoveryDecision::ObserveExactAttemptInvocation {
                        assert_eq!(manager, ManagerUnitObservation::MatchingAttemptUnit);
                        assert_eq!(invocation, ManagerInvocationObservation::ExactAttemptInvocation);
                    }
                    if actual == WorkerStartInvocationRecoveryDecision::SubmitInitialStartAfterDurablePreflight {
                        assert_eq!(intent, WorkerStartIntent::PreparedNotSubmitted);
                        assert_eq!(manager, ManagerUnitObservation::Absent);
                        assert!(matches!(
                            invocation,
                            ManagerInvocationObservation::NotQueried
                                | ManagerInvocationObservation::Missing
                                | ManagerInvocationObservation::Unavailable
                        ));
                    }
                }
            }
        }
        assert_eq!(cases, 3 * 5 * 6);
    }

    #[test]
    fn lost_start_response_never_reissues_an_ambiguous_mutation() {
        for intent in [
            WorkerStartIntent::SubmissionMayHaveOccurred,
            WorkerStartIntent::UnitInvocationIdentityPersisted,
        ] {
            assert_eq!(
                decide_worker_start_recovery(intent, ManagerUnitObservation::Absent),
                WorkerStartRecoveryDecision::ReconcileTargetBeforeAnyNewAttempt
            );
        }
    }

    #[test]
    fn candidate_observation_is_not_terminal_success_or_mutation_authority() {
        let decision = decide_reconciliation(
            WorkerIdentityStatus::ExactWorkerNoLongerPresent,
            ProcessReceiptStatus::Missing,
            TargetObservation::CandidateRuntimeAndProfileActive,
        );
        assert_eq!(
            decision,
            ReconciliationDecision::CandidatePostStateObservedNeedsLifecycleValidation {
                receipt: ProcessReceiptStatus::Missing
            }
        );
    }

    #[test]
    fn missing_receipt_never_means_the_mutation_did_not_run() {
        let decision = decide_reconciliation(
            WorkerIdentityStatus::ExactWorkerExited,
            ProcessReceiptStatus::Missing,
            TargetObservation::NotAttempted,
        );
        assert_eq!(
            decision,
            ReconciliationDecision::RequireReadOnlyTargetObservation {
                receipt: ProcessReceiptStatus::Missing
            }
        );
    }

    #[test]
    fn live_worker_with_exit_receipt_is_a_contradiction_not_success() {
        let decision = decide_reconciliation(
            WorkerIdentityStatus::ExactWorkerLive,
            ProcessReceiptStatus::ValidExitCode(0),
            TargetObservation::CandidateRuntimeAndProfileActive,
        );
        assert_eq!(decision, ReconciliationDecision::HoldForContradictoryEvidence);
    }

    #[test]
    fn boot_profile_selection_is_not_running_candidate_evidence() {
        let decision = decide_reconciliation(
            WorkerIdentityStatus::PreviousBoot,
            ProcessReceiptStatus::ValidExitCode(0),
            TargetObservation::BootCandidateProfileSelected,
        );
        assert_eq!(
            decision,
            ReconciliationDecision::BootSelectionObservedNeedsLifecycleValidation {
                receipt: ProcessReceiptStatus::ValidExitCode(0)
            }
        );
    }
}
