// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Deterministic model of the Nix system-profile transition race boundary.
//!
//! This module does not claim to add a compare-and-set primitive to Nix.
//! It makes the residual observation -> nix-env --set race explicit and
//! executable as a deterministic state-machine fixture.

/// Point at which an unrelated external writer changes the system profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalWriterInterleaving {
    None,
    BeforePreStateObservation,
    AfterPreStateObservationBeforeSet,
    AfterSetBeforePostSetVerification,
    AfterPostSetVerificationBeforeActivation,
    AfterActivationBeforePostStateVerification,
}

/// Outcome that Nixward's existing exact-observation strategy can establish
/// for the modeled external-writer interleaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTransitionRaceOutcome {
    NoRace,
    AbortBeforeMutation,
    CandidateWriteMasksExternalWriter,
    DetectPostSetProfileDrift,
    DetectPreActivationProfileDrift,
    DetectPostActivationProfileDrift,
}

/// Deterministically simulate the profile transition ordering.
///
/// Prior is the exact profile closure observed and bound by the transaction.
/// Candidate is the exact immutable closure authorized for the transition.
/// Foreign represents an unrelated external writer.
///
/// The important result is CandidateWriteMasksExternalWriter: an external
/// writer can change the profile after Nixward's final pre-state observation and
/// before Nixward acquires Nix's profile mutation lock. If Nixward subsequently
/// wins the profile mutation and sets the authorized candidate, the post-state
/// evidence is indistinguishable from a clean transition. This is the residual
/// Issue #9 boundary and must not be relabeled as CAS.
pub fn simulate_external_writer_interleaving(
    interleaving: ExternalWriterInterleaving,
) -> ProfileTransitionRaceOutcome {
    match interleaving {
        ExternalWriterInterleaving::None => ProfileTransitionRaceOutcome::NoRace,

        ExternalWriterInterleaving::BeforePreStateObservation => {
            ProfileTransitionRaceOutcome::AbortBeforeMutation
        }

        ExternalWriterInterleaving::AfterPreStateObservationBeforeSet => {
            ProfileTransitionRaceOutcome::CandidateWriteMasksExternalWriter
        }

        ExternalWriterInterleaving::AfterSetBeforePostSetVerification => {
            ProfileTransitionRaceOutcome::DetectPostSetProfileDrift
        }

        ExternalWriterInterleaving::AfterPostSetVerificationBeforeActivation => {
            ProfileTransitionRaceOutcome::DetectPreActivationProfileDrift
        }

        ExternalWriterInterleaving::AfterActivationBeforePostStateVerification => {
            ProfileTransitionRaceOutcome::DetectPostActivationProfileDrift
        }
    }
}

/// Return the complete deterministic race matrix for review/receipts.
pub fn deterministic_race_matrix(
) -> &'static [(ExternalWriterInterleaving, ProfileTransitionRaceOutcome); 6] {
    &[
        (
            ExternalWriterInterleaving::None,
            ProfileTransitionRaceOutcome::NoRace,
        ),
        (
            ExternalWriterInterleaving::BeforePreStateObservation,
            ProfileTransitionRaceOutcome::AbortBeforeMutation,
        ),
        (
            ExternalWriterInterleaving::AfterPreStateObservationBeforeSet,
            ProfileTransitionRaceOutcome::CandidateWriteMasksExternalWriter,
        ),
        (
            ExternalWriterInterleaving::AfterSetBeforePostSetVerification,
            ProfileTransitionRaceOutcome::DetectPostSetProfileDrift,
        ),
        (
            ExternalWriterInterleaving::AfterPostSetVerificationBeforeActivation,
            ProfileTransitionRaceOutcome::DetectPreActivationProfileDrift,
        ),
        (
            ExternalWriterInterleaving::AfterActivationBeforePostStateVerification,
            ProfileTransitionRaceOutcome::DetectPostActivationProfileDrift,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive_race_matrix_is_deterministic() {
        let expected = deterministic_race_matrix();
        assert_eq!(expected.len(), 6);

        for (point, outcome) in expected {
            assert_eq!(simulate_external_writer_interleaving(*point), *outcome);
        }
    }

    #[test]
    fn unavoidable_observation_to_set_gap_is_explicit() {
        assert_eq!(
            simulate_external_writer_interleaving(
                ExternalWriterInterleaving::AfterPreStateObservationBeforeSet
            ),
            ProfileTransitionRaceOutcome::CandidateWriteMasksExternalWriter
        );
    }

    #[test]
    fn later_interleavings_are_detectable() {
        assert_eq!(
            simulate_external_writer_interleaving(
                ExternalWriterInterleaving::AfterSetBeforePostSetVerification
            ),
            ProfileTransitionRaceOutcome::DetectPostSetProfileDrift
        );
        assert_eq!(
            simulate_external_writer_interleaving(
                ExternalWriterInterleaving::AfterPostSetVerificationBeforeActivation
            ),
            ProfileTransitionRaceOutcome::DetectPreActivationProfileDrift
        );
        assert_eq!(
            simulate_external_writer_interleaving(
                ExternalWriterInterleaving::AfterActivationBeforePostStateVerification
            ),
            ProfileTransitionRaceOutcome::DetectPostActivationProfileDrift
        );
    }

    #[test]
    fn preflight_external_writer_is_not_attributed_to_nixward() {
        assert_eq!(
            simulate_external_writer_interleaving(
                ExternalWriterInterleaving::BeforePreStateObservation
            ),
            ProfileTransitionRaceOutcome::AbortBeforeMutation
        );
    }
}
