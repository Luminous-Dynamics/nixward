// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure state model for policy-serialized, one-shot payload release.
//!
//! This model makes the local SQLite commit the policy/release ordering
//! linearization point. It deliberately does not claim atomicity between that
//! commit and external worker I/O. A lost acknowledgement after the durable
//! release-attempt transition is ambiguous and must never trigger a second send.

use std::collections::BTreeSet;
use thiserror::Error;

const GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const POLICY_HEAD_DOMAIN: &[u8] = b"nixward-authority-policy-head-model-v1\0";
const RELEASE_ID_DOMAIN: &[u8] = b"nixward-payload-release-id-v1\0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ReleaseBarrierError {
    #[error("release barrier input is malformed or incomplete: {0}")]
    InvalidInput(&'static str),
    #[error("admission binding differs from the committed transaction")]
    AdmissionBindingMismatch,
    #[error("authority policy epoch is stale")]
    StalePolicy,
    #[error("authority signer is revoked under the current policy")]
    RevokedSigner,
    #[error("authority provenance or payload has expired")]
    Expired,
    #[error("a different release barrier already exists for this admission")]
    BarrierConflict,
    #[error("release attempt has already been durably started; do not resend")]
    ReleaseAttemptAlreadyStarted,
    #[error("release is uncertain and requires independent reconciliation")]
    ReleaseUncertain,
    #[error("policy update has stale epoch or parent digest")]
    PolicyEpochConflict,
    #[error("in-flight barrier requires an explicit stop/recovery or preserve decision")]
    InFlightDecisionRequired,
    #[error("policy update disposition blocks a not-yet-started release")]
    StopRecoveryRequired,
    #[error("release receipt is not bound to the one-shot release attempt")]
    ReceiptConflict,
    #[error("release state transition is not permitted")]
    InvalidTransition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionBinding {
    pub transaction_id: String,
    pub attempt_id: String,
    pub admission_commit_id: String,
    pub replay_key: String,
    pub permit_digest: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub authority_provenance_digest: String,
}

impl AdmissionBinding {
    fn validate(&self) -> Result<(), ReleaseBarrierError> {
        if [
            self.transaction_id.as_str(),
            self.attempt_id.as_str(),
            self.admission_commit_id.as_str(),
            self.replay_key.as_str(),
            self.permit_digest.as_str(),
            self.plan_digest.as_str(),
            self.machine_binding_digest.as_str(),
            self.authority_provenance_digest.as_str(),
        ]
        .into_iter()
        .all(valid_digest)
        {
            Ok(())
        } else {
            Err(ReleaseBarrierError::InvalidInput("admission identity/digest"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyHead {
    pub policy_id: String,
    pub epoch: u64,
    pub policy_digest: String,
    pub record_digest: String,
    pub emergency_revoked_key_ids: BTreeSet<String>,
}

impl PolicyHead {
    pub(crate) fn genesis(
        policy_id: impl Into<String>,
        policy_digest: impl Into<String>,
        emergency_revoked_key_ids: BTreeSet<String>,
    ) -> Result<Self, ReleaseBarrierError> {
        Self::derive(
            policy_id.into(),
            1,
            policy_digest.into(),
            GENESIS_DIGEST.to_string(),
            emergency_revoked_key_ids,
        )
    }

    fn derive(
        policy_id: String,
        epoch: u64,
        policy_digest: String,
        previous_record_digest: String,
        emergency_revoked_key_ids: BTreeSet<String>,
    ) -> Result<Self, ReleaseBarrierError> {
        if policy_id.trim().is_empty()
            || epoch == 0
            || !valid_digest(&policy_digest)
            || !valid_digest(&previous_record_digest)
            || emergency_revoked_key_ids.iter().any(|key| !valid_token(key))
        {
            return Err(ReleaseBarrierError::InvalidInput("policy head"));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_HEAD_DOMAIN);
        hash_field(&mut hasher, policy_id.as_bytes());
        hash_field(&mut hasher, &epoch.to_le_bytes());
        hash_field(&mut hasher, policy_digest.as_bytes());
        hash_field(&mut hasher, previous_record_digest.as_bytes());
        for key_id in &emergency_revoked_key_ids {
            hash_field(&mut hasher, key_id.as_bytes());
        }
        let record_digest = hasher.finalize().to_hex().to_string();
        Ok(Self {
            policy_id,
            epoch,
            policy_digest,
            record_digest,
            emergency_revoked_key_ids,
        })
    }

    fn advance(
        &self,
        policy_digest: String,
        emergency_revoked_key_ids: BTreeSet<String>,
    ) -> Result<Self, ReleaseBarrierError> {
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(ReleaseBarrierError::PolicyEpochConflict)?;
        Self::derive(
            self.policy_id.clone(),
            epoch,
            policy_digest,
            self.record_digest.clone(),
            emergency_revoked_key_ids,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InFlightPolicyDecision {
    NoInFlightBarrier,
    PreserveExistingBarrier,
    RequireStopOrRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostUpdateBarrierDisposition {
    PreserveHistoricalAuthorization,
    StopOrRecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseIntent {
    pub admission: AdmissionBinding,
    pub expected_policy: PolicyHead,
    pub signer_key_id: String,
    pub payload_digest: String,
    pub expires_at_ms: u64,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReleaseState {
    BarrierCommitted,
    ReleaseAttempted { started_at_ms: u64 },
    Acknowledged {
        acknowledged_at_ms: u64,
        worker_unit: String,
        invocation_id: String,
        receipt_digest: String,
    },
    Uncertain { started_at_ms: u64, observed_at_ms: u64 },
    CancelledBeforeAttempt { cancelled_at_ms: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseBarrierRecord {
    pub release_id: String,
    pub admission: AdmissionBinding,
    pub signer_key_id: String,
    pub authority_provenance_digest: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub policy_digest: String,
    pub policy_record_digest: String,
    pub payload_digest: String,
    pub expires_at_ms: u64,
    pub barrier_committed_at_ms: u64,
    pub state: ReleaseState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReleaseBarrierOutcome {
    Created(ReleaseBarrierRecord),
    Existing(ReleaseBarrierRecord),
}

impl ReleaseBarrierOutcome {
    pub(crate) fn record(&self) -> &ReleaseBarrierRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }

    pub(crate) fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseBarrierLedger {
    admission: AdmissionBinding,
    current_policy: PolicyHead,
    barrier: Option<ReleaseBarrierRecord>,
    /// Separate policy-decision metadata; never mutates the historical barrier record.
    in_flight_disposition: Option<PostUpdateBarrierDisposition>,
}

impl ReleaseBarrierLedger {
    pub(crate) fn new(
        admission: AdmissionBinding,
        current_policy: PolicyHead,
    ) -> Result<Self, ReleaseBarrierError> {
        admission.validate()?;
        Ok(Self {
            admission,
            current_policy,
            barrier: None,
            in_flight_disposition: None,
        })
    }

    pub(crate) fn current_policy(&self) -> &PolicyHead {
        &self.current_policy
    }

    pub(crate) fn barrier(&self) -> Option<&ReleaseBarrierRecord> {
        self.barrier.as_ref()
    }

    pub(crate) fn in_flight_disposition(&self) -> Option<PostUpdateBarrierDisposition> {
        self.in_flight_disposition
    }

    /// Model of BEGIN IMMEDIATE. The expected policy pointer is checked in the
    /// same state transition that commits the unique release barrier.
    pub(crate) fn create_barrier(
        &mut self,
        intent: &ReleaseIntent,
    ) -> Result<ReleaseBarrierOutcome, ReleaseBarrierError> {
        intent.admission.validate()?;
        if intent.admission != self.admission {
            return Err(ReleaseBarrierError::AdmissionBindingMismatch);
        }
        if !valid_token(&intent.signer_key_id) || !valid_digest(&intent.payload_digest) {
            return Err(ReleaseBarrierError::InvalidInput("signer or payload digest"));
        }
        let expected_policy = &intent.expected_policy;
        let release_id = derive_release_id(
            &intent.admission,
            &intent.signer_key_id,
            &intent.payload_digest,
            expected_policy,
            intent.expires_at_ms,
        );
        let proposed = ReleaseBarrierRecord {
            release_id,
            admission: intent.admission.clone(),
            signer_key_id: intent.signer_key_id.clone(),
            authority_provenance_digest: intent.admission.authority_provenance_digest.clone(),
            policy_id: expected_policy.policy_id.clone(),
            policy_epoch: expected_policy.epoch,
            policy_digest: expected_policy.policy_digest.clone(),
            policy_record_digest: expected_policy.record_digest.clone(),
            payload_digest: intent.payload_digest.clone(),
            expires_at_ms: intent.expires_at_ms,
            barrier_committed_at_ms: intent.now_ms,
            state: ReleaseState::BarrierCommitted,
        };

        // Idempotent retry is a read of the immutable historical barrier. It
        // remains available after policy advancement or expiry, but cannot
        // change its disposition or authorize another attempt.
        if let Some(existing) = &self.barrier {
            if same_release_intent(existing, &proposed) {
                return Ok(ReleaseBarrierOutcome::Existing(existing.clone()));
            }
            return Err(ReleaseBarrierError::BarrierConflict);
        }

        if expected_policy != &self.current_policy {
            return Err(ReleaseBarrierError::StalePolicy);
        }
        if intent.expires_at_ms == 0 || intent.now_ms > intent.expires_at_ms {
            return Err(ReleaseBarrierError::Expired);
        }
        if self.current_policy.emergency_revoked_key_ids.contains(&intent.signer_key_id) {
            return Err(ReleaseBarrierError::RevokedSigner);
        }

        self.barrier = Some(proposed.clone());
        Ok(ReleaseBarrierOutcome::Created(proposed))
    }

    /// Policy advancement serializes with barrier creation. If a barrier already
    /// exists, the update must explicitly preserve it or require stop/recovery.
    pub(crate) fn advance_policy(
        &mut self,
        expected_current_epoch: u64,
        expected_current_record_digest: &str,
        next_policy_digest: String,
        next_emergency_revoked_key_ids: BTreeSet<String>,
        in_flight_decision: InFlightPolicyDecision,
    ) -> Result<PolicyHead, ReleaseBarrierError> {
        if self.current_policy.epoch != expected_current_epoch
            || self.current_policy.record_digest != expected_current_record_digest
        {
            return Err(ReleaseBarrierError::PolicyEpochConflict);
        }
        match (&self.barrier, in_flight_decision) {
            (None, InFlightPolicyDecision::NoInFlightBarrier) => {}
            (None, _) => return Err(ReleaseBarrierError::InFlightDecisionRequired),
            (Some(_), InFlightPolicyDecision::NoInFlightBarrier) => {
                return Err(ReleaseBarrierError::InFlightDecisionRequired);
            }
            (Some(_), InFlightPolicyDecision::PreserveExistingBarrier)
            | (Some(_), InFlightPolicyDecision::RequireStopOrRecovery) => {}
        }

        let next = self
            .current_policy
            .advance(next_policy_digest, next_emergency_revoked_key_ids)?;
        if self.barrier.is_some() {
            self.in_flight_disposition = Some(match in_flight_decision {
                InFlightPolicyDecision::PreserveExistingBarrier => {
                    PostUpdateBarrierDisposition::PreserveHistoricalAuthorization
                }
                InFlightPolicyDecision::RequireStopOrRecovery => {
                    PostUpdateBarrierDisposition::StopOrRecoveryRequired
                }
                InFlightPolicyDecision::NoInFlightBarrier => unreachable!(),
            });
        }
        self.current_policy = next.clone();
        Ok(next)
    }

    /// Durably reserve the sole external release attempt before writing bytes.
    /// A crash afterwards is ambiguous and cannot authorize another attempt.
    pub(crate) fn begin_release_attempt(
        &mut self,
        release_id: &str,
        now_ms: u64,
    ) -> Result<(), ReleaseBarrierError> {
        let barrier = self
            .barrier
            .as_mut()
            .ok_or(ReleaseBarrierError::InvalidTransition)?;
        if barrier.release_id != release_id {
            return Err(ReleaseBarrierError::BarrierConflict);
        }
        if !matches!(&barrier.state, ReleaseState::BarrierCommitted) {
            return Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted);
        }
        if now_ms > barrier.expires_at_ms {
            barrier.state = ReleaseState::CancelledBeforeAttempt {
                cancelled_at_ms: now_ms,
            };
            return Err(ReleaseBarrierError::Expired);
        }
        if self.in_flight_disposition
            == Some(PostUpdateBarrierDisposition::StopOrRecoveryRequired)
        {
            barrier.state = ReleaseState::CancelledBeforeAttempt {
                cancelled_at_ms: now_ms,
            };
            return Err(ReleaseBarrierError::StopRecoveryRequired);
        }
        barrier.state = ReleaseState::ReleaseAttempted {
            started_at_ms: now_ms,
        };
        Ok(())
    }

    /// A lost acknowledgement after the durable attempt becomes uncertain.
    /// No second release attempt is permitted.
    pub(crate) fn mark_release_uncertain(
        &mut self,
        release_id: &str,
        observed_at_ms: u64,
    ) -> Result<(), ReleaseBarrierError> {
        let barrier = self
            .barrier
            .as_mut()
            .ok_or(ReleaseBarrierError::InvalidTransition)?;
        if barrier.release_id != release_id {
            return Err(ReleaseBarrierError::BarrierConflict);
        }
        match &barrier.state {
            ReleaseState::ReleaseAttempted { started_at_ms } => {
                let started_at_ms = *started_at_ms;
                if observed_at_ms < started_at_ms {
                    return Err(ReleaseBarrierError::InvalidTransition);
                }
                barrier.state = ReleaseState::Uncertain {
                    started_at_ms,
                    observed_at_ms,
                };
                Ok(())
            }
            ReleaseState::Uncertain { .. } => Err(ReleaseBarrierError::ReleaseUncertain),
            _ => Err(ReleaseBarrierError::InvalidTransition),
        }
    }

    /// A late exact receipt may reconcile an uncertain release. It never starts
    /// another send; it only records evidence about the original one-shot attempt.
    pub(crate) fn acknowledge_release(
        &mut self,
        release_id: &str,
        payload_digest: &str,
        worker_unit: &str,
        invocation_id: &str,
        receipt_digest: &str,
        acknowledged_at_ms: u64,
    ) -> Result<(), ReleaseBarrierError> {
        if !valid_digest(payload_digest)
            || !valid_token(worker_unit)
            || !valid_token(invocation_id)
            || !valid_digest(receipt_digest)
        {
            return Err(ReleaseBarrierError::InvalidInput("release receipt"));
        }
        let barrier = self
            .barrier
            .as_mut()
            .ok_or(ReleaseBarrierError::InvalidTransition)?;
        if barrier.release_id != release_id || barrier.payload_digest != payload_digest {
            return Err(ReleaseBarrierError::ReceiptConflict);
        }
        match &barrier.state {
            ReleaseState::ReleaseAttempted { started_at_ms }
            | ReleaseState::Uncertain { started_at_ms, .. }
                if acknowledged_at_ms >= *started_at_ms =>
            {
                barrier.state = ReleaseState::Acknowledged {
                    acknowledged_at_ms,
                    worker_unit: worker_unit.to_string(),
                    invocation_id: invocation_id.to_string(),
                    receipt_digest: receipt_digest.to_string(),
                };
                Ok(())
            }
            ReleaseState::Acknowledged {
                acknowledged_at_ms: existing_at,
                worker_unit: existing_unit,
                invocation_id: existing_invocation,
                receipt_digest: existing_digest,
            } if *existing_at == acknowledged_at_ms
                && existing_unit == worker_unit
                && existing_invocation == invocation_id
                && existing_digest == receipt_digest =>
            {
                Ok(())
            }
            _ => Err(ReleaseBarrierError::InvalidTransition),
        }
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn derive_release_id(
    admission: &AdmissionBinding,
    signer_key_id: &str,
    payload_digest: &str,
    policy: &PolicyHead,
    expires_at_ms: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_ID_DOMAIN);
    let epoch_bytes = policy.epoch.to_le_bytes();
    let expiry_bytes = expires_at_ms.to_le_bytes();
    for value in [
        admission.transaction_id.as_bytes(),
        admission.attempt_id.as_bytes(),
        admission.admission_commit_id.as_bytes(),
        admission.replay_key.as_bytes(),
        admission.permit_digest.as_bytes(),
        admission.plan_digest.as_bytes(),
        admission.machine_binding_digest.as_bytes(),
        admission.authority_provenance_digest.as_bytes(),
        signer_key_id.as_bytes(),
        payload_digest.as_bytes(),
        policy.policy_id.as_bytes(),
        epoch_bytes.as_slice(),
        policy.policy_digest.as_bytes(),
        policy.record_digest.as_bytes(),
        expiry_bytes.as_slice(),
    ] {
        hash_field(&mut hasher, value);
    }
    hasher.finalize().to_hex().to_string()
}

fn same_release_intent(existing: &ReleaseBarrierRecord, proposed: &ReleaseBarrierRecord) -> bool {
    existing.release_id == proposed.release_id
        && existing.admission == proposed.admission
        && existing.signer_key_id == proposed.signer_key_id
        && existing.authority_provenance_digest == proposed.authority_provenance_digest
        && existing.policy_id == proposed.policy_id
        && existing.policy_epoch == proposed.policy_epoch
        && existing.policy_digest == proposed.policy_digest
        && existing.policy_record_digest == proposed.policy_record_digest
        && existing.payload_digest == proposed.payload_digest
        && existing.expires_at_ms == proposed.expires_at_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn admission() -> AdmissionBinding {
        AdmissionBinding {
            transaction_id: digest('1'),
            attempt_id: digest('2'),
            admission_commit_id: digest('3'),
            replay_key: digest('4'),
            permit_digest: digest('5'),
            plan_digest: digest('6'),
            machine_binding_digest: digest('7'),
            authority_provenance_digest: digest('8'),
        }
    }

    fn policy(epoch: u64, revoked: &[&str]) -> PolicyHead {
        let mut current = PolicyHead::genesis("owner-root:one", digest('a'), BTreeSet::new()).unwrap();
        let mut previous_record_digest = GENESIS_DIGEST.to_string();
        for next_epoch in 2..=epoch {
            previous_record_digest = current.record_digest.clone();
            current = current
                .advance(
                    digest(if next_epoch % 2 == 0 { 'b' } else { 'c' }),
                    BTreeSet::new(),
                )
                .unwrap();
        }
        if !revoked.is_empty() {
            current = PolicyHead::derive(
                current.policy_id,
                current.epoch,
                current.policy_digest,
                previous_record_digest,
                revoked.iter().map(|value| (*value).to_string()).collect(),
            ).unwrap();
        }
        current
    }

    fn intent(policy: &PolicyHead) -> ReleaseIntent {
        ReleaseIntent {
            admission: admission(),
            expected_policy: policy.clone(),
            signer_key_id: "owner-key-1".into(),
            payload_digest: digest('b'),
            expires_at_ms: 5_000,
            now_ms: 1_000,
        }
    }

    fn ledger() -> ReleaseBarrierLedger {
        ReleaseBarrierLedger::new(admission(), policy(1, &[])).unwrap()
    }

    #[test]
    fn creates_one_barrier_bound_to_exact_admission_policy_and_payload() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        assert!(created.was_created());
        let record = created.record();
        assert_eq!(record.admission, admission());
        assert_eq!(record.policy_epoch, 1);
        assert_eq!(record.payload_digest, digest('b'));
        assert_eq!(record.state, ReleaseState::BarrierCommitted);
    }

    #[test]
    fn identical_barrier_retry_returns_existing_record() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let first = ledger.create_barrier(&request).unwrap();
        let mut retry = request;
        retry.now_ms = 1_100;
        let second = ledger.create_barrier(&retry).unwrap();
        assert!(first.was_created());
        assert!(!second.was_created());
        assert_eq!(first.record(), second.record());
    }


    #[test]
    fn exact_barrier_retry_remains_readable_after_policy_advancement() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let first = ledger.create_barrier(&request).unwrap();
        let immutable = first.record().clone();
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::PreserveExistingBarrier,
        ).unwrap();
        let retry = ledger.create_barrier(&request).unwrap();
        assert!(!retry.was_created());
        assert_eq!(retry.record(), &immutable);
        ledger.begin_release_attempt(&immutable.release_id, 1_200).unwrap();
    }

    #[test]
    fn exact_barrier_retry_after_stop_decision_is_readable_but_not_releasable() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let first = ledger.create_barrier(&request).unwrap();
        let immutable = first.record().clone();
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::RequireStopOrRecovery,
        ).unwrap();
        let retry = ledger.create_barrier(&request).unwrap();
        assert_eq!(retry.record(), &immutable);
        assert!(matches!(
            ledger.begin_release_attempt(&immutable.release_id, 1_200),
            Err(ReleaseBarrierError::StopRecoveryRequired)
        ));
    }

    #[test]
    fn changed_payload_for_same_admission_is_a_conflict() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let first = ledger.create_barrier(&request).unwrap();
        let mut changed = intent(ledger.current_policy());
        changed.payload_digest = digest('c');
        assert!(matches!(ledger.create_barrier(&changed), Err(ReleaseBarrierError::BarrierConflict)));
        assert_eq!(ledger.barrier().unwrap(), first.record());
    }

    #[test]
    fn policy_advance_wins_race_and_stale_barrier_is_rejected() {
        let mut ledger = ledger();
        let stale_request = intent(ledger.current_policy());
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('b'),
            BTreeSet::new(),
            InFlightPolicyDecision::NoInFlightBarrier,
        ).unwrap();
        assert!(matches!(
            ledger.create_barrier(&stale_request),
            Err(ReleaseBarrierError::StalePolicy)
        ));
    }

    #[test]
    fn barrier_commit_wins_race_and_historical_authorization_is_preserved_explicitly() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let barrier = ledger.create_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        let old_epoch = barrier.record().policy_epoch;
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::PreserveExistingBarrier,
        ).unwrap();
        assert_eq!(ledger.barrier().unwrap().policy_epoch, old_epoch);
        assert_eq!(
            ledger.in_flight_disposition(),
            Some(PostUpdateBarrierDisposition::PreserveHistoricalAuthorization)
        );
        ledger.begin_release_attempt(&release_id, 1_200).unwrap();
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::ReleaseAttempted { .. }));
    }

    #[test]
    fn policy_advance_that_requires_stop_blocks_a_not_yet_started_release() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let barrier = ledger.create_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::RequireStopOrRecovery,
        ).unwrap();
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_200),
            Err(ReleaseBarrierError::StopRecoveryRequired)
        ));
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::CancelledBeforeAttempt { .. }));
    }

    #[test]
    fn policy_update_with_barrier_requires_an_explicit_inflight_decision() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let barrier = ledger.create_barrier(&request).unwrap();
        let current = ledger.current_policy().clone();
        assert!(matches!(
            ledger.advance_policy(
                current.epoch,
                &current.record_digest,
                digest('c'),
                BTreeSet::new(),
                InFlightPolicyDecision::NoInFlightBarrier,
            ),
            Err(ReleaseBarrierError::InFlightDecisionRequired)
        ));
        assert_eq!(ledger.barrier().unwrap().release_id, barrier.record().release_id);
    }

    #[test]
    fn same_epoch_with_wrong_policy_record_digest_is_rejected() {
        let mut ledger = ledger();
        let mut request = intent(ledger.current_policy());
        request.expected_policy_record_digest = digest('f');
        assert!(matches!(
            ledger.create_barrier(&request),
            Err(ReleaseBarrierError::StalePolicy)
        ));
    }

    #[test]
    fn barrier_cannot_be_created_after_signer_is_revoked() {
        let admission = admission();
        let mut ledger = ReleaseBarrierLedger::new(admission, policy(1, &["owner-key-1"])).unwrap();
        let request = intent(ledger.current_policy());
        assert!(matches!(
            ledger.create_barrier(&request),
            Err(ReleaseBarrierError::RevokedSigner)
        ));
    }

    #[test]
    fn barrier_cannot_be_created_after_expiry() {
        let mut ledger = ledger();
        let mut request = intent(ledger.current_policy());
        request.now_ms = 5_001;
        assert!(matches!(ledger.create_barrier(&request), Err(ReleaseBarrierError::Expired)));
    }

    #[test]
    fn barrier_requires_exact_admission_identity() {
        let mut ledger = ledger();
        let mut request = intent(ledger.current_policy());
        request.admission.attempt_id = digest('f');
        assert!(matches!(
            ledger.create_barrier(&request),
            Err(ReleaseBarrierError::AdmissionBindingMismatch)
        ));
    }

    #[test]
    fn one_release_attempt_is_reserved_before_external_io() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_200),
            Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted)
        ));
    }

    #[test]
    fn lost_ack_after_attempt_becomes_uncertain_and_never_resends() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        ledger.mark_release_uncertain(&release_id, 1_500).unwrap();
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_600),
            Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted)
        ));
        assert_eq!(
            ledger.mark_release_uncertain(&release_id, 1_700),
            Err(ReleaseBarrierError::ReleaseUncertain)
        );
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::Uncertain { .. }));
    }


    #[test]
    fn policy_update_never_mutates_the_committed_barrier_record() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let barrier = ledger.create_barrier(&request).unwrap();
        let immutable_before = barrier.record().clone();
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::PreserveExistingBarrier,
        ).unwrap();
        assert_eq!(ledger.barrier().unwrap(), &immutable_before);
        assert_eq!(
            ledger.in_flight_disposition(),
            Some(PostUpdateBarrierDisposition::PreserveHistoricalAuthorization)
        );
    }

    #[test]
    fn exact_late_receipt_can_reconcile_uncertain_attempt_without_resending() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        ledger.mark_release_uncertain(&release_id, 1_500).unwrap();
        // Receipt time may predate local timeout observation: the worker may
        // have completed and persisted it before the supervisor timed out.
        ledger.acknowledge_release(
            &release_id, &digest('b'), "nixward-tx.service",
            "invocation-1", &digest('c'), 1_300,
        ).unwrap();
        assert!(matches!(
            ledger.barrier().unwrap().state,
            ReleaseState::Acknowledged { acknowledged_at_ms: 1_300, .. }
        ));
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_600),
            Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted)
        ));
    }

    #[test]
    fn exact_worker_receipt_acknowledges_release_and_duplicate_ack_is_idempotent() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        ledger.acknowledge_release(
            &release_id, &digest('b'), "nixward-tx.service", "invocation-1",
            &digest('c'), 1_300,
        ).unwrap();
        ledger.acknowledge_release(
            &release_id, &digest('b'), "nixward-tx.service", "invocation-1",
            &digest('c'), 1_300,
        ).unwrap();
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::Acknowledged { .. }));
    }

    #[test]
    fn foreign_payload_or_changed_receipt_cannot_acknowledge_release() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        assert!(matches!(
            ledger.acknowledge_release(&release_id, &digest('d'), "nixward-tx.service",
                "invocation-1", &digest('c'), 1_300),
            Err(ReleaseBarrierError::ReceiptConflict)
        ));
        assert!(matches!(
            ledger.acknowledge_release(&release_id, &digest('b'), "nixward-tx.service",
                "invocation-2", &digest('c'), 1_300),
            Err(ReleaseBarrierError::InvalidTransition)
        ));
    }

    #[test]
    fn late_exact_receipt_can_reconcile_uncertainty_without_resending() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        ledger.mark_release_uncertain(&release_id, 1_200).unwrap();
        ledger.acknowledge_release(
            &release_id, &digest('b'), "nixward-tx.service", "invocation-1",
            &digest('c'), 1_300,
        ).unwrap();
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::Acknowledged { .. }));
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_400),
            Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted)
        ));
    }

    #[test]
    fn expiry_after_barrier_but_before_attempt_cancels_without_external_io() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        assert_eq!(
            ledger.begin_release_attempt(&release_id, 5_001),
            Err(ReleaseBarrierError::Expired)
        );
        assert!(matches!(&ledger.barrier().unwrap().state, ReleaseState::CancelledBeforeAttempt { .. }));
    }

    #[test]
    fn stale_policy_parent_and_epoch_cannot_advance() {
        let mut ledger = ledger();
        let current = ledger.current_policy().clone();
        assert!(matches!(
            ledger.advance_policy(current.epoch, &digest('f'), digest('b'),
                BTreeSet::new(), InFlightPolicyDecision::NoInFlightBarrier),
            Err(ReleaseBarrierError::PolicyEpochConflict)
        ));
        assert!(matches!(
            ledger.advance_policy(0, &current.record_digest, digest('b'),
                BTreeSet::new(), InFlightPolicyDecision::NoInFlightBarrier),
            Err(ReleaseBarrierError::PolicyEpochConflict)
        ));
    }

    #[test]
    fn policy_epoch_advance_without_barrier_uses_no_inflight_decision() {
        let mut ledger = ledger();
        let current = ledger.current_policy().clone();
        assert!(ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('b'),
            BTreeSet::new(),
            InFlightPolicyDecision::NoInFlightBarrier,
        ).is_ok());
    }

    #[test]
    fn policy_update_after_attempt_never_releases_payload_a_second_time() {
        let mut ledger = ledger();
        let request = intent(ledger.current_policy());
        let created = ledger.create_barrier(&request).unwrap();
        let release_id = created.record().release_id.clone();
        ledger.begin_release_attempt(&release_id, 1_100).unwrap();
        let current = ledger.current_policy().clone();
        ledger.advance_policy(
            current.epoch,
            &current.record_digest,
            digest('c'),
            BTreeSet::from(["owner-key-1".to_string()]),
            InFlightPolicyDecision::RequireStopOrRecovery,
        ).unwrap();
        assert!(matches!(
            ledger.begin_release_attempt(&release_id, 1_200),
            Err(ReleaseBarrierError::ReleaseAttemptAlreadyStarted)
        ));
    }
}
