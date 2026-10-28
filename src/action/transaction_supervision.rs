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
