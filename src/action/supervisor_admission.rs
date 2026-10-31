// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Pure recovery model for the root supervisor's authority-admission boundary.
//!
//! This module is a qualification oracle, not an authorization implementation.
//! It does not parse signatures, mint permits, write journals, or submit
//! systemd jobs. The proof booleans are outputs of an independent verifier;
//! callers must never derive them from serialized "verified" claims.
//!
//! The model requires replay consumption, permit issuance, attempt reservation,
//! and canonical journal publication to share one durable commit identity.
//! A partially visible or internally conflicting snapshot is always a hold.

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(crate) struct AdmissionIntent {
    pub transaction_id: String,
    pub replay_key: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
}

impl AdmissionIntent {
    fn is_well_formed(&self) -> bool {
        valid_token(&self.transaction_id)
            && valid_digest(&self.replay_key)
            && valid_digest(&self.plan_digest)
            && valid_digest(&self.machine_binding_digest)
    }
}

/// Result bits that must be set only by an independent approval verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(crate) struct AdmissionProofAssessment {
    pub signature_valid: bool,
    pub trusted_signer: bool,
    pub exact_audience: bool,
    pub exact_subject: bool,
    pub exact_machine_binding: bool,
    pub exact_plan_binding: bool,
    pub fresh: bool,
}

impl AdmissionProofAssessment {
    fn is_satisfied(&self) -> bool {
        self.signature_valid
            && self.trusted_signer
            && self.exact_audience
            && self.exact_subject
            && self.exact_machine_binding
            && self.exact_plan_binding
            && self.fresh
    }
}

/// One durable component of a single admission commit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(crate) struct AdmissionIdentity {
    pub transaction_id: String,
    pub attempt_id: String,
    pub replay_key: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub permit_digest: String,
    pub commit_id: String,
}

impl AdmissionIdentity {
    fn is_well_formed(&self) -> bool {
        valid_token(&self.transaction_id)
            && valid_token(&self.attempt_id)
            && valid_digest(&self.replay_key)
            && valid_digest(&self.plan_digest)
            && valid_digest(&self.machine_binding_digest)
            && valid_digest(&self.permit_digest)
            && valid_digest(&self.commit_id)
    }

    fn matches_intent(&self, intent: &AdmissionIntent) -> bool {
        self.transaction_id == intent.transaction_id
            && self.replay_key == intent.replay_key
            && self.plan_digest == intent.plan_digest
            && self.machine_binding_digest == intent.machine_binding_digest
    }
}

/// Read-back of the four records that must be committed as one admission.
#[derive(Debug, Clone, Default)]
pub(crate) struct AdmissionSnapshot {
    pub replay_consumption: Option<AdmissionIdentity>,
    pub verified_permit: Option<AdmissionIdentity>,
    pub attempt_reservation: Option<AdmissionIdentity>,
    pub journal_entry: Option<AdmissionIdentity>,
    pub unresolved_attempt: bool,
}

enum SnapshotView<'a> {
    Empty,
    Complete {
        identity: &'a AdmissionIdentity,
        unresolved: bool,
    },
    Inconsistent,
}

impl AdmissionSnapshot {
    fn classify(&self) -> SnapshotView<'_> {
        let records = [
            self.replay_consumption.as_ref(),
            self.verified_permit.as_ref(),
            self.attempt_reservation.as_ref(),
            self.journal_entry.as_ref(),
        ];
        let present = records.iter().filter_map(|record| *record).collect::<Vec<_>>();

        if present.is_empty() {
            return if self.unresolved_attempt {
                SnapshotView::Inconsistent
            } else {
                SnapshotView::Empty
            };
        }

        if present.len() != records.len() {
            return SnapshotView::Inconsistent;
        }

        let first = present[0];
        if !first.is_well_formed() || !present.iter().all(|candidate| *candidate == first) {
            return SnapshotView::Inconsistent;
        }

        SnapshotView::Complete {
            identity: first,
            unresolved: self.unresolved_attempt,
        }
    }
}

/// Conservative supervisor admission outcomes. None of these values is itself
/// a permit or a capability to execute a system mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionDecision {
    RejectInvalidIntent,
    RejectInvalidProof,
    CommitAdmissionAtomically,
    ResumeExistingAttempt,
    RejectReplayConflict,
    HoldUnresolvedAttempt,
    HoldInconsistentPersistence,
}

impl AdmissionDecision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RejectInvalidIntent => "reject_invalid_intent",
            Self::RejectInvalidProof => "reject_invalid_proof",
            Self::CommitAdmissionAtomically => "commit_admission_atomically",
            Self::ResumeExistingAttempt => "resume_existing_attempt",
            Self::RejectReplayConflict => "reject_replay_conflict",
            Self::HoldUnresolvedAttempt => "hold_unresolved_attempt",
            Self::HoldInconsistentPersistence => "hold_inconsistent_persistence",
        }
    }
}

/// Decide whether the supervisor may create an admission, recover an existing
/// one, or must reject/hold.
///
/// The caller must perform real cryptographic verification and local policy
/// checks before constructing a satisfied proof assessment. The storage
/// adapter must still commit all four admission records atomically and durably
/// before any systemd submission. This function only specifies the decision.
pub(crate) fn decide_admission(
    intent: &AdmissionIntent,
    proof: &AdmissionProofAssessment,
    snapshot: &AdmissionSnapshot,
) -> AdmissionDecision {
    if !intent.is_well_formed() {
        return AdmissionDecision::RejectInvalidIntent;
    }
    if !proof.is_satisfied() {
        return AdmissionDecision::RejectInvalidProof;
    }

    match snapshot.classify() {
        SnapshotView::Empty => AdmissionDecision::CommitAdmissionAtomically,
        SnapshotView::Inconsistent => AdmissionDecision::HoldInconsistentPersistence,
        SnapshotView::Complete {
            identity,
            unresolved,
        } => {
            if identity.replay_key == intent.replay_key {
                if identity.matches_intent(intent) {
                    // An acknowledgement may be lost after the durable commit.
                    // Return the existing attempt; never mint a second one.
                    AdmissionDecision::ResumeExistingAttempt
                } else {
                    // Replay keys are globally one-shot and bound to their
                    // original transaction, plan, and machine.
                    AdmissionDecision::RejectReplayConflict
                }
            } else if identity.transaction_id == intent.transaction_id && unresolved {
                AdmissionDecision::HoldUnresolvedAttempt
            } else {
                AdmissionDecision::CommitAdmissionAtomically
            }
        }
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct QualificationCorpus {
        schema: String,
        version: u64,
        identities: BTreeMap<String, AdmissionIdentity>,
        vectors: Vec<AdmissionVector>,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AdmissionVector {
        id: String,
        intent: AdmissionIntent,
        proof: AdmissionProofAssessment,
        snapshot: AdmissionSnapshotRefs,
        expected_decision: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AdmissionSnapshotRefs {
        replay_consumption: Option<String>,
        verified_permit: Option<String>,
        attempt_reservation: Option<String>,
        journal_entry: Option<String>,
        unresolved_attempt: bool,
    }

    impl AdmissionSnapshotRefs {
        fn resolve(&self, identities: &BTreeMap<String, AdmissionIdentity>) -> AdmissionSnapshot {
            fn record(
                key: &Option<String>,
                identities: &BTreeMap<String, AdmissionIdentity>,
            ) -> Option<AdmissionIdentity> {
                key.as_ref().map(|key| {
                    identities.get(key).cloned().unwrap_or_else(|| AdmissionIdentity {
                        transaction_id: String::new(),
                        attempt_id: String::new(),
                        replay_key: String::new(),
                        plan_digest: String::new(),
                        machine_binding_digest: String::new(),
                        permit_digest: String::new(),
                        commit_id: String::new(),
                    })
                })
            }

            AdmissionSnapshot {
                replay_consumption: record(&self.replay_consumption, identities),
                verified_permit: record(&self.verified_permit, identities),
                attempt_reservation: record(&self.attempt_reservation, identities),
                journal_entry: record(&self.journal_entry, identities),
                unresolved_attempt: self.unresolved_attempt,
            }
        }
    }

    fn digest(byte: u8) -> String {
        std::iter::repeat(byte as char).take(64).collect()
    }

    fn valid_identity() -> AdmissionIdentity {
        AdmissionIdentity {
            transaction_id: "transaction-1".into(),
            attempt_id: "attempt-1".into(),
            replay_key: digest(b'a'),
            plan_digest: digest(b'b'),
            machine_binding_digest: digest(b'c'),
            permit_digest: digest(b'd'),
            commit_id: digest(b'e'),
        }
    }

    fn valid_intent() -> AdmissionIntent {
        let identity = valid_identity();
        AdmissionIntent {
            transaction_id: identity.transaction_id,
            replay_key: identity.replay_key,
            plan_digest: identity.plan_digest,
            machine_binding_digest: identity.machine_binding_digest,
        }
    }

    fn valid_proof() -> AdmissionProofAssessment {
        AdmissionProofAssessment {
            signature_valid: true,
            trusted_signer: true,
            exact_audience: true,
            exact_subject: true,
            exact_machine_binding: true,
            exact_plan_binding: true,
            fresh: true,
        }
    }

    #[test]
    fn shared_json_vectors_match_the_rust_admission_model() {
        let corpus: QualificationCorpus = serde_json::from_str(include_str!(
            "../../docs/fixtures/supervisor-admission-qualification-v1.json"
        ))
        .expect("admission qualification fixture must parse");

        assert_eq!(
            corpus.schema,
            "org.luminousdynamics.nixward.supervisor-admission-vectors"
        );
        assert_eq!(corpus.version, 1);
        assert_eq!(corpus.vectors.len(), 20);

        let mut ids = std::collections::HashSet::new();
        for vector in corpus.vectors {
            assert!(ids.insert(vector.id.clone()), "duplicate vector ID: {}", vector.id);
            let snapshot = vector.snapshot.resolve(&corpus.identities);
            let actual = decide_admission(&vector.intent, &vector.proof, &snapshot);
            assert_eq!(
                actual.as_str(),
                vector.expected_decision,
                "wrong admission result for vector {}",
                vector.id
            );
        }
    }

    #[test]
    fn every_atomic_record_subset_is_either_empty_complete_or_held() {
        let identity = valid_identity();
        let proof = valid_proof();
        let intent = valid_intent();

        for mask in 0u8..16 {
            let record = |bit| (mask & (1 << bit) != 0).then(|| identity.clone());
            let snapshot = AdmissionSnapshot {
                replay_consumption: record(0),
                verified_permit: record(1),
                attempt_reservation: record(2),
                journal_entry: record(3),
                unresolved_attempt: mask == 15,
            };

            let expected = match mask {
                0 => AdmissionDecision::CommitAdmissionAtomically,
                15 => AdmissionDecision::ResumeExistingAttempt,
                _ => AdmissionDecision::HoldInconsistentPersistence,
            };
            assert_eq!(
                decide_admission(&intent, &proof, &snapshot),
                expected,
                "unexpected decision for four-record presence mask {mask:04b}"
            );
        }
    }

    #[test]
    fn every_independent_proof_predicate_is_required() {
        let intent = valid_intent();
        let snapshot = AdmissionSnapshot::default();

        for failed in 0..7 {
            let mut proof = valid_proof();
            match failed {
                0 => proof.signature_valid = false,
                1 => proof.trusted_signer = false,
                2 => proof.exact_audience = false,
                3 => proof.exact_subject = false,
                4 => proof.exact_machine_binding = false,
                5 => proof.exact_plan_binding = false,
                6 => proof.fresh = false,
                _ => unreachable!(),
            }
            assert_eq!(
                decide_admission(&intent, &proof, &snapshot),
                AdmissionDecision::RejectInvalidProof,
                "proof predicate {failed} must be mandatory"
            );
        }
    }

    #[test]
    fn a_conflicting_commit_identity_is_never_treated_as_complete() {
        let identity = valid_identity();
        let mut conflicting = identity.clone();
        conflicting.commit_id = digest(b'f');
        let snapshot = AdmissionSnapshot {
            replay_consumption: Some(identity.clone()),
            verified_permit: Some(identity.clone()),
            attempt_reservation: Some(identity),
            journal_entry: Some(conflicting),
            unresolved_attempt: true,
        };

        assert_eq!(
            decide_admission(&valid_intent(), &valid_proof(), &snapshot),
            AdmissionDecision::HoldInconsistentPersistence
        );
    }

    #[test]
    fn malformed_intent_is_rejected_before_admission() {
        let mut intent = valid_intent();
        intent.plan_digest = "not-a-digest".into();

        assert_eq!(
            decide_admission(&intent, &valid_proof(), &AdmissionSnapshot::default()),
            AdmissionDecision::RejectInvalidIntent
        );
    }
}