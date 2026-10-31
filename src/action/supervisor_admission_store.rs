// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Experimental, non-privileged SQLite prototype for supervisor admission.
//!
//! This module is deliberately not wired to a daemon, D-Bus method, systemd
//! unit, approval verifier, or mutation executor. It accepts already-assessed
//! opaque approval/permit material and proves only the storage protocol:
//! replay consumption, permit record, attempt reservation, and admission event
//! are committed in one SQLite transaction.
//!
//! The root supervisor must independently verify the original approval proof
//! and mint the permit before exposing an admission result to a worker. This
//! store is not itself an authorization boundary.

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params,
};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const SCHEMA_VERSION: i64 = 4;
const APPLICATION_ID: i64 = 0x4e58_5744; // "NXWD"
const MAX_APPROVAL_BYTES: usize = 1024 * 1024;
const MAX_AUTHORITY_PROVENANCE_BYTES: usize = 64 * 1024;
const MAX_AUTHORITY_POLICY_BYTES: usize = 1024 * 1024;
const MAX_POLICY_UPDATE_PROVENANCE_BYTES: usize = 64 * 1024;
const MAX_EMERGENCY_REVOCATION_IDS: usize = 4096;
const MAX_EMERGENCY_REVOCATION_BYTES: usize = 64 * 1024;
const MAX_PERMIT_BYTES: usize = 1024 * 1024;
const MAX_EVENT_BYTES: usize = 1024 * 1024;
const AUTHORITY_POLICY_SCHEMA_VERSION: u64 = 1;
const AUTHORITY_POLICY_KIND: &str = "symthaea-authority-trust-policy-v1";
const AUTHORITY_POLICY_DIGEST_DOMAIN: &[u8] = b"symthaea-authority-policy-v1\0";
const POLICY_EMERGENCY_REVOCATION_DOMAIN: &[u8] =
    b"nixward-authority-emergency-revocations-v1\0";
const POLICY_UPDATE_PROVENANCE_DOMAIN: &[u8] =
    b"nixward-authority-policy-update-provenance-v1\0";
const POLICY_EPOCH_RECORD_DOMAIN: &[u8] = b"nixward-authority-policy-epoch-record-v1\0";
const GENESIS_POLICY_RECORD_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admission_commits (
    commit_id TEXT PRIMARY KEY NOT NULL,
    transaction_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    replay_key TEXT NOT NULL UNIQUE,
    plan_digest TEXT NOT NULL,
    machine_binding_digest TEXT NOT NULL,
    approval_proof_digest TEXT NOT NULL,
    approval_material BLOB NOT NULL CHECK(length(approval_material) > 0),
    authority_provenance_digest TEXT NOT NULL CHECK(length(authority_provenance_digest) = 64),
    authority_provenance BLOB NOT NULL CHECK(length(authority_provenance) > 0),
    permit_digest TEXT NOT NULL UNIQUE,
    permit_wire BLOB NOT NULL CHECK(length(permit_wire) > 0),
    event_digest TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
);

CREATE TABLE IF NOT EXISTS authority_replays (
    replay_key TEXT PRIMARY KEY NOT NULL,
    commit_id TEXT NOT NULL UNIQUE
        REFERENCES admission_commits(commit_id) ON DELETE RESTRICT,
    transaction_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    machine_binding_digest TEXT NOT NULL,
    approval_proof_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS supervisor_permits (
    permit_digest TEXT PRIMARY KEY NOT NULL,
    commit_id TEXT NOT NULL UNIQUE
        REFERENCES admission_commits(commit_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS transaction_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    transaction_id TEXT NOT NULL,
    commit_id TEXT NOT NULL UNIQUE
        REFERENCES admission_commits(commit_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('unresolved', 'resolved')),
    resolution_digest TEXT,
    resolved_at_ms INTEGER,
    CHECK (
        (state = 'unresolved' AND resolution_digest IS NULL AND resolved_at_ms IS NULL)
        OR
        (state = 'resolved' AND resolution_digest IS NOT NULL AND resolved_at_ms IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_attempt_per_transaction
ON transaction_attempts(transaction_id)
WHERE state = 'unresolved';

CREATE TABLE IF NOT EXISTS admission_events (
    commit_id TEXT PRIMARY KEY NOT NULL
        REFERENCES admission_commits(commit_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL
        CHECK(event_kind = 'supervisor_admission_committed'),
    event_digest TEXT NOT NULL,
    event_payload BLOB NOT NULL CHECK(length(event_payload) > 0)
);

CREATE TRIGGER IF NOT EXISTS admission_commits_immutable_update
BEFORE UPDATE ON admission_commits
BEGIN
    SELECT RAISE(ABORT, 'admission commit rows are immutable');
END;
CREATE TRIGGER IF NOT EXISTS admission_commits_immutable_delete
BEFORE DELETE ON admission_commits
BEGIN
    SELECT RAISE(ABORT, 'admission commit rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS authority_replays_immutable_update
BEFORE UPDATE ON authority_replays
BEGIN
    SELECT RAISE(ABORT, 'authority replay rows are immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_replays_immutable_delete
BEFORE DELETE ON authority_replays
BEGIN
    SELECT RAISE(ABORT, 'authority replay rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS supervisor_permits_immutable_update
BEFORE UPDATE ON supervisor_permits
BEGIN
    SELECT RAISE(ABORT, 'supervisor permit rows are immutable');
END;
CREATE TRIGGER IF NOT EXISTS supervisor_permits_immutable_delete
BEFORE DELETE ON supervisor_permits
BEGIN
    SELECT RAISE(ABORT, 'supervisor permit rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_events_immutable_update
BEFORE UPDATE ON admission_events
BEGIN
    SELECT RAISE(ABORT, 'admission event rows are immutable');
END;
CREATE TRIGGER IF NOT EXISTS admission_events_immutable_delete
BEFORE DELETE ON admission_events
BEGIN
    SELECT RAISE(ABORT, 'admission event rows are immutable');
END;

CREATE TRIGGER IF NOT EXISTS transaction_attempts_one_way_resolution
BEFORE UPDATE ON transaction_attempts
WHEN OLD.state <> 'unresolved'
  OR NEW.state <> 'resolved'
  OR NEW.attempt_id <> OLD.attempt_id
  OR NEW.transaction_id <> OLD.transaction_id
  OR NEW.commit_id <> OLD.commit_id
  OR NEW.resolution_digest IS NULL
  OR NEW.resolved_at_ms IS NULL
BEGIN
    SELECT RAISE(ABORT, 'transaction attempt resolution is a one-way transition');
END;
CREATE TRIGGER IF NOT EXISTS transaction_attempts_no_delete
BEFORE DELETE ON transaction_attempts
BEGIN
    SELECT RAISE(ABORT, 'transaction attempt rows are immutable');
END;

CREATE TABLE IF NOT EXISTS authority_policy_epochs (
    epoch INTEGER PRIMARY KEY NOT NULL CHECK(epoch > 0),
    policy_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
    policy_json BLOB NOT NULL CHECK(length(policy_json) > 0),
    emergency_revocation_digest TEXT NOT NULL CHECK(length(emergency_revocation_digest) = 64),
    emergency_revoked_key_ids_json BLOB NOT NULL CHECK(length(emergency_revoked_key_ids_json) > 0),
    previous_record_digest TEXT NOT NULL CHECK(length(previous_record_digest) = 64),
    update_provenance_digest TEXT NOT NULL CHECK(length(update_provenance_digest) = 64),
    update_provenance BLOB NOT NULL CHECK(length(update_provenance) > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    record_digest TEXT NOT NULL UNIQUE CHECK(length(record_digest) = 64),
    UNIQUE(epoch, record_digest)
);

CREATE TABLE IF NOT EXISTS authority_policy_current (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    epoch INTEGER NOT NULL UNIQUE,
    record_digest TEXT NOT NULL UNIQUE,
    FOREIGN KEY(epoch, record_digest)
        REFERENCES authority_policy_epochs(epoch, record_digest) ON DELETE RESTRICT
);

CREATE TRIGGER IF NOT EXISTS authority_policy_epochs_immutable_update
BEFORE UPDATE ON authority_policy_epochs
BEGIN
    SELECT RAISE(ABORT, 'authority policy epoch records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS authority_policy_epochs_no_delete
BEFORE DELETE ON authority_policy_epochs
BEGIN
    SELECT RAISE(ABORT, 'authority policy epoch records are immutable');
END;

CREATE TRIGGER IF NOT EXISTS authority_policy_epochs_monotonic_insert
BEFORE INSERT ON authority_policy_epochs
WHEN
    (NEW.epoch = 1 AND NEW.previous_record_digest <> '0000000000000000000000000000000000000000000000000000000000000000')
    OR
    (NEW.epoch > 1 AND NOT EXISTS (
        SELECT 1 FROM authority_policy_epochs AS prior
        WHERE prior.epoch = NEW.epoch - 1
          AND prior.record_digest = NEW.previous_record_digest
    ))
    OR
    EXISTS (SELECT 1 FROM authority_policy_epochs WHERE epoch >= NEW.epoch)
BEGIN
    SELECT RAISE(ABORT, 'authority policy epochs must extend the immutable contiguous history');
END;

CREATE TRIGGER IF NOT EXISTS authority_policy_current_initial_only
BEFORE INSERT ON authority_policy_current
WHEN NEW.singleton <> 1
  OR NEW.epoch <> 1
  OR NOT EXISTS (
      SELECT 1 FROM authority_policy_epochs
      WHERE epoch = NEW.epoch AND record_digest = NEW.record_digest
        AND previous_record_digest = '0000000000000000000000000000000000000000000000000000000000000000'
  )
BEGIN
    SELECT RAISE(ABORT, 'authority policy current pointer must begin at verified genesis epoch 1');
END;

CREATE TRIGGER IF NOT EXISTS authority_policy_current_only_advance
BEFORE UPDATE ON authority_policy_current
WHEN NEW.singleton <> OLD.singleton
  OR NEW.epoch <> OLD.epoch + 1
  OR NOT EXISTS (
      SELECT 1 FROM authority_policy_epochs
      WHERE epoch = NEW.epoch AND record_digest = NEW.record_digest
        AND previous_record_digest = OLD.record_digest
  )
BEGIN
    SELECT RAISE(ABORT, 'authority policy current pointer may only advance one verified epoch');
END;

CREATE TRIGGER IF NOT EXISTS authority_policy_current_no_delete
BEFORE DELETE ON authority_policy_current
BEGIN
    SELECT RAISE(ABORT, 'authority policy current pointer cannot be deleted');
END;


CREATE TABLE IF NOT EXISTS payload_release_barriers (
    release_id TEXT PRIMARY KEY NOT NULL CHECK(length(release_id) = 64),
    commit_id TEXT NOT NULL UNIQUE REFERENCES admission_commits(commit_id) ON DELETE RESTRICT,
    transaction_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    replay_key TEXT NOT NULL UNIQUE,
    permit_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    machine_binding_digest TEXT NOT NULL,
    authority_provenance_digest TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_epoch INTEGER NOT NULL CHECK(policy_epoch > 0),
    policy_digest TEXT NOT NULL,
    policy_record_digest TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    authority_subject_digest TEXT NOT NULL,
    authority_audience TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    barrier_committed_at_ms INTEGER NOT NULL CHECK(barrier_committed_at_ms >= 0),
    barrier_digest TEXT NOT NULL UNIQUE CHECK(length(barrier_digest) = 64),
    FOREIGN KEY(policy_epoch, policy_record_digest)
        REFERENCES authority_policy_epochs(epoch, record_digest) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS payload_release_attempts (
    release_id TEXT PRIMARY KEY NOT NULL REFERENCES payload_release_barriers(release_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE,
    started_at_ms INTEGER NOT NULL CHECK(started_at_ms >= 0),
    attempt_digest TEXT NOT NULL UNIQUE CHECK(length(attempt_digest) = 64)
);

CREATE TABLE IF NOT EXISTS payload_release_uncertain (
    release_id TEXT PRIMARY KEY NOT NULL REFERENCES payload_release_attempts(release_id) ON DELETE RESTRICT,
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    uncertainty_digest TEXT NOT NULL UNIQUE CHECK(length(uncertainty_digest) = 64)
);

CREATE TABLE IF NOT EXISTS payload_release_receipts (
    release_id TEXT PRIMARY KEY NOT NULL REFERENCES payload_release_attempts(release_id) ON DELETE RESTRICT,
    payload_digest TEXT NOT NULL,
    worker_unit TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    receipt_digest TEXT NOT NULL CHECK(length(receipt_digest) = 64),
    acknowledged_at_ms INTEGER NOT NULL CHECK(acknowledged_at_ms >= 0),
    receipt_record_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_record_digest) = 64)
);

CREATE TABLE IF NOT EXISTS payload_release_policy_decisions (
    decision_id TEXT PRIMARY KEY NOT NULL CHECK(length(decision_id) = 64),
    release_id TEXT NOT NULL REFERENCES payload_release_barriers(release_id) ON DELETE RESTRICT,
    policy_epoch INTEGER NOT NULL CHECK(policy_epoch > 0),
    policy_record_digest TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('preserve_existing_barrier', 'stop_or_recovery_required')),
    decision_digest TEXT NOT NULL UNIQUE CHECK(length(decision_digest) = 64),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    UNIQUE(release_id, policy_epoch),
    FOREIGN KEY(policy_epoch, policy_record_digest)
        REFERENCES authority_policy_epochs(epoch, record_digest) ON DELETE RESTRICT
);

CREATE TRIGGER IF NOT EXISTS payload_release_barriers_immutable_update
BEFORE UPDATE ON payload_release_barriers BEGIN
    SELECT RAISE(ABORT, 'payload release barrier records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_barriers_no_delete
BEFORE DELETE ON payload_release_barriers BEGIN
    SELECT RAISE(ABORT, 'payload release barrier records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_attempts_immutable_update
BEFORE UPDATE ON payload_release_attempts BEGIN
    SELECT RAISE(ABORT, 'payload release attempt records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_attempts_no_delete
BEFORE DELETE ON payload_release_attempts BEGIN
    SELECT RAISE(ABORT, 'payload release attempt records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_uncertain_immutable_update
BEFORE UPDATE ON payload_release_uncertain BEGIN
    SELECT RAISE(ABORT, 'payload release uncertainty records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_uncertain_no_delete
BEFORE DELETE ON payload_release_uncertain BEGIN
    SELECT RAISE(ABORT, 'payload release uncertainty records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_receipts_immutable_update
BEFORE UPDATE ON payload_release_receipts BEGIN
    SELECT RAISE(ABORT, 'payload release receipt records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_receipts_no_delete
BEFORE DELETE ON payload_release_receipts BEGIN
    SELECT RAISE(ABORT, 'payload release receipt records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_policy_decisions_immutable_update
BEFORE UPDATE ON payload_release_policy_decisions BEGIN
    SELECT RAISE(ABORT, 'payload release policy decisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_policy_decisions_no_delete
BEFORE DELETE ON payload_release_policy_decisions BEGIN
    SELECT RAISE(ABORT, 'payload release policy decisions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS payload_release_policy_decisions_no_downgrade
BEFORE INSERT ON payload_release_policy_decisions
WHEN NEW.disposition = 'preserve_existing_barrier'
  AND EXISTS (
      SELECT 1 FROM payload_release_policy_decisions AS prior
      WHERE prior.release_id = NEW.release_id
        AND prior.disposition = 'stop_or_recovery_required'
  )
BEGIN
    SELECT RAISE(ABORT, 'stop/recovery disposition cannot be downgraded');
END;


"#;

const SELECT_ADMISSION_BY_COMMIT: &str = r#"
SELECT
    a.commit_id, a.transaction_id, a.attempt_id, a.replay_key,
    a.plan_digest, a.machine_binding_digest, a.approval_proof_digest,
    a.approval_material, a.permit_digest, a.permit_wire, a.event_digest,
    e.event_payload, a.created_at_ms, t.state, t.resolution_digest,
    t.resolved_at_ms,
    a.authority_provenance_digest, a.authority_provenance
FROM admission_commits AS a
JOIN authority_replays AS r ON r.commit_id = a.commit_id
JOIN supervisor_permits AS p ON p.commit_id = a.commit_id
JOIN transaction_attempts AS t ON t.commit_id = a.commit_id
JOIN admission_events AS e ON e.commit_id = a.commit_id
WHERE a.commit_id = ?1
"#;

const SELECT_ADMISSION_BY_REPLAY: &str = r#"
SELECT
    a.commit_id, a.transaction_id, a.attempt_id, a.replay_key,
    a.plan_digest, a.machine_binding_digest, a.approval_proof_digest,
    a.approval_material, a.permit_digest, a.permit_wire, a.event_digest,
    e.event_payload, a.created_at_ms, t.state, t.resolution_digest,
    t.resolved_at_ms,
    a.authority_provenance_digest, a.authority_provenance
FROM authority_replays AS r
JOIN admission_commits AS a ON a.commit_id = r.commit_id
JOIN supervisor_permits AS p ON p.commit_id = a.commit_id
JOIN transaction_attempts AS t ON t.commit_id = a.commit_id
JOIN admission_events AS e ON e.commit_id = a.commit_id
WHERE r.replay_key = ?1
"#;

const SELECT_UNRESOLVED_BY_TRANSACTION: &str = r#"
SELECT
    a.commit_id, a.transaction_id, a.attempt_id, a.replay_key,
    a.plan_digest, a.machine_binding_digest, a.approval_proof_digest,
    a.approval_material, a.permit_digest, a.permit_wire, a.event_digest,
    e.event_payload, a.created_at_ms, t.state, t.resolution_digest,
    t.resolved_at_ms,
    a.authority_provenance_digest, a.authority_provenance
FROM transaction_attempts AS t
JOIN admission_commits AS a ON a.commit_id = t.commit_id
JOIN authority_replays AS r ON r.commit_id = a.commit_id
JOIN supervisor_permits AS p ON p.commit_id = a.commit_id
JOIN admission_events AS e ON e.commit_id = a.commit_id
WHERE t.transaction_id = ?1 AND t.state = 'unresolved'
"#;

/// A request to persist a fully prepared admission.
///
/// The approval and permit bytes are opaque to this module. Their digests are
/// calculated here, but their signatures and policy bindings must be verified
/// by a separate trusted component. attempt_id must be generated once by the
/// supervisor and reused for retry after an ambiguous acknowledgement.
#[derive(Debug, Clone)]
pub(crate) struct AdmissionRequest {
    pub transaction_id: String,
    pub attempt_id: String,
    pub replay_key: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub approval_material: Vec<u8>,
    /// Serialized verifier provenance. This module stores/hashes it but does not trust or verify it.
    pub authority_provenance: Vec<u8>,
    pub permit_wire: Vec<u8>,
    pub event_payload: Vec<u8>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionState {
    Unresolved,
    Resolved {
        resolution_digest: String,
        resolved_at_ms: u64,
    },
}

/// The immutable identity and material returned only after commit/read-back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionRecord {
    pub commit_id: String,
    pub transaction_id: String,
    pub attempt_id: String,
    pub replay_key: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub approval_proof_digest: String,
    pub approval_material: Vec<u8>,
    pub authority_provenance_digest: String,
    pub authority_provenance: Vec<u8>,
    pub permit_digest: String,
    pub permit_wire: Vec<u8>,
    pub event_digest: String,
    pub event_payload: Vec<u8>,
    pub created_at_ms: u64,
    pub state: AdmissionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionOutcome {
    Created(AdmissionRecord),
    Existing(AdmissionRecord),
}

impl AdmissionOutcome {
    pub(crate) fn record(&self) -> &AdmissionRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }

    pub(crate) fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Debug, Error)]
pub(crate) enum AdmissionStoreError {
    #[error("invalid supervisor admission input: {0}")]
    InvalidInput(&'static str),
    #[error("admission replay key is already bound to a different intent")]
    ReplayConflict,
    #[error("transaction already has unresolved attempt {attempt_id}")]
    UnresolvedAttempt { attempt_id: String },
    #[error("admission storage contains partial, conflicting, or corrupt records")]
    InconsistentStorage,
    #[error("admission resolution conflicts with the persisted terminal receipt")]
    ResolutionConflict,
    #[error("admission not found")]
    NotFound,
    #[error("authority policy epoch archive has not been initialized")]
    PolicyEpochNotInitialized,
    #[error("authority policy epoch does not match the expected current state")]
    PolicyEpochConflict,
    #[error("authority policy epoch record is invalid or corrupt")]
    InvalidPolicyEpochRecord,
    #[error("payload release barrier conflicts with the committed admission or existing barrier")]
    ReleaseBarrierConflict,
    #[error("payload release request uses a stale authority policy snapshot")]
    ReleaseBarrierStalePolicy,
    #[error("payload release signer, audience, subject or provenance is not authorized by the archived policy")]
    ReleaseBarrierUnauthorized,
    #[error("payload release barrier or admission has expired")]
    ReleaseBarrierExpired,
    #[error("payload release attempt has already been durably reserved; resend is forbidden")]
    ReleaseAttemptAlreadyStarted,
    #[error("payload release attempt has already been marked uncertain")]
    ReleaseAttemptAlreadyUncertain,
    #[error("payload release is blocked by a stop/recovery policy decision")]
    ReleaseAttemptBlocked,
    #[error("payload release attempt has no committed barrier")]
    ReleaseBarrierNotFound,
    #[error("transaction cannot be resolved while a release barrier has no exact worker receipt")]
    ReleaseBarrierInFlight,
    #[error("payload release receipt conflicts with the unique release attempt")]
    ReleaseReceiptConflict,
    #[error("payload release policy decisions are missing, duplicated or foreign")]
    ReleasePolicyDecisionRequired,
    #[error("policy release decision cannot downgrade stop/recovery to preserve")]
    ReleasePolicyDecisionDowngrade,
    #[error("authority policy epoch {epoch} may be durable but read-back failed: {detail}")]
    PolicyEpochReadBackUncertain { epoch: u64, detail: String },
    #[error("unsupported supervisor admission schema version {0}")]
    UnsupportedSchema(i64),
    #[error("admission commit {commit_id} may be durable but read-back failed: {detail}")]
    ReadBackUncertain { commit_id: String, detail: String },
    #[error("admission store path is not absolute")]
    RelativePath,
    #[error("admission store path traverses a symlink: {0}")]
    SymlinkPath(String),
    #[error("admission store directory permissions are too broad: {0}")]
    InsecureDirectory(String),
    #[error("admission store file permissions are too broad: {0}")]
    InsecureFile(String),
    #[error("SQLite application ID does not identify a Nixward admission store")]
    WrongApplicationId,
    #[error("SQLite admission storage error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("admission store filesystem error: {0}")]
    Filesystem(#[from] std::io::Error),
    #[cfg(test)]
    #[error("injected admission-store failure at {0}")]
    InjectedFailure(&'static str),
}


/// Policy update input. Its provenance bytes must be produced by the trusted
/// supervisor after verifying owner authority under the existing current policy.
/// This storage layer hashes and retains those bytes; it does not verify them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityPolicyEpochRequest {
    pub policy_id: String,
    pub epoch: u64,
    /// Exact serde_json::to_vec bytes of AuthorityTrustPolicy, including its epoch.
    pub policy_json: Vec<u8>,
    /// Sorted, unique emergency-revocation key IDs active at this epoch.
    pub emergency_revoked_key_ids: Vec<String>,
    /// Serialized update/bootstrapping proof or verifier provenance.
    pub update_provenance: Vec<u8>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityPolicyEpochRecord {
    pub policy_id: String,
    pub epoch: u64,
    pub policy_digest: String,
    pub policy_json: Vec<u8>,
    pub emergency_revocation_digest: String,
    pub emergency_revoked_key_ids: Vec<String>,
    pub previous_record_digest: String,
    pub update_provenance_digest: String,
    pub update_provenance: Vec<u8>,
    pub created_at_ms: u64,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorityPolicyEpochOutcome {
    Created(AuthorityPolicyEpochRecord),
    Existing(AuthorityPolicyEpochRecord),
}

impl AuthorityPolicyEpochOutcome {
    pub(crate) fn record(&self) -> &AuthorityPolicyEpochRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredReleaseDisposition {
    PreserveExistingBarrier,
    StopOrRecoveryRequired,
}
impl StoredReleaseDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreserveExistingBarrier => "preserve_existing_barrier",
            Self::StopOrRecoveryRequired => "stop_or_recovery_required",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredReleasePolicyDecision {
    pub release_id: String,
    pub disposition: StoredReleaseDisposition,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadReleaseBarrierRequest {
    pub commit_id: String,
    pub expected_policy_epoch: u64,
    pub expected_policy_record_digest: String,
    pub signer_key_id: String,
    pub expected_authority_subject_digest: String,
    pub expected_authority_audience: String,
    pub payload_digest: String,
    pub expires_at_ms: u64,
    pub now_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadReleaseBarrierRecord {
    pub release_id: String,
    pub commit_id: String,
    pub transaction_id: String,
    pub attempt_id: String,
    pub replay_key: String,
    pub permit_digest: String,
    pub plan_digest: String,
    pub machine_binding_digest: String,
    pub authority_provenance_digest: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub policy_digest: String,
    pub policy_record_digest: String,
    pub signer_key_id: String,
    pub authority_subject_digest: String,
    pub authority_audience: String,
    pub payload_digest: String,
    pub expires_at_ms: u64,
    pub barrier_committed_at_ms: u64,
    pub barrier_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PayloadReleaseBarrierOutcome {
    Created(PayloadReleaseBarrierRecord),
    Existing(PayloadReleaseBarrierRecord),
}
impl PayloadReleaseBarrierOutcome {
    pub(crate) fn record(&self) -> &PayloadReleaseBarrierRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
    pub(crate) fn was_created(&self) -> bool { matches!(self, Self::Created(_)) }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PayloadReleaseStoreState {
    BarrierCommitted(PayloadReleaseBarrierRecord),
    Attempted {
        barrier: PayloadReleaseBarrierRecord,
        started_at_ms: u64,
        uncertain_at_ms: Option<u64>,
    },
    Acknowledged {
        barrier: PayloadReleaseBarrierRecord,
        started_at_ms: u64,
        acknowledged_at_ms: u64,
        worker_unit: String,
        invocation_id: String,
        receipt_digest: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SupervisorAdmissionStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStage {
    CommitRow,
    ReplayRow,
    PermitRow,
    AttemptRow,
    EventRow,
    BeforeCommit,
    AfterCommit,
}

impl WriteStage {
    #[cfg(test)]
    fn name(self) -> &'static str {
        match self {
            Self::CommitRow => "commit_row",
            Self::ReplayRow => "replay_row",
            Self::PermitRow => "permit_row",
            Self::AttemptRow => "attempt_row",
            Self::EventRow => "event_row",
            Self::BeforeCommit => "before_commit",
            Self::AfterCommit => "after_commit",
        }
    }
}

impl SupervisorAdmissionStore {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn reject_symlink_components(path: &Path) -> Result<(), AdmissionStoreError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir | Component::ParentDir | Component::Normal(_) => {
                    current.push(component.as_os_str());
                }
                Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            }
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(AdmissionStoreError::SymlinkPath(
                        current.display().to_string(),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(AdmissionStoreError::Filesystem(error)),
            }
        }
        Ok(())
    }

    fn prepare_path(&self) -> Result<(), AdmissionStoreError> {
        if !self.path.is_absolute() {
            return Err(AdmissionStoreError::RelativePath);
        }
        if self.path.file_name().is_none()
            || self.path.components().any(|component| {
                matches!(component, Component::CurDir | Component::ParentDir)
            })
        {
            return Err(AdmissionStoreError::InvalidInput(
                "database path must be normalized and include a file name",
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or(AdmissionStoreError::InvalidInput("database path has no parent"))?;
        Self::reject_symlink_components(parent)?;
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let parent_metadata = std::fs::metadata(parent)?;
        if !parent_metadata.is_dir() {
            return Err(AdmissionStoreError::InvalidInput(
                "database parent is not a directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if parent_metadata.permissions().mode() & 0o077 != 0 {
                return Err(AdmissionStoreError::InsecureDirectory(
                    parent.display().to_string(),
                ));
            }
        }

        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(AdmissionStoreError::SymlinkPath(
                        self.path.display().to_string(),
                    ));
                }
                if !metadata.file_type().is_file() {
                    return Err(AdmissionStoreError::InvalidInput(
                        "database path is not a regular file",
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(AdmissionStoreError::InsecureFile(
                            self.path.display().to_string(),
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(AdmissionStoreError::Filesystem(error)),
        }
        Ok(())
    }

    fn connect(&self) -> Result<Connection, AdmissionStoreError> {
        self.prepare_path()?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &self.path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(AdmissionStoreError::InvalidInput(
                "SQLite refused WAL journal mode",
            ));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;

        let synchronous: i64 =
            connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let foreign_keys: i64 =
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        let trusted_schema: i64 =
            connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
        if synchronous != 2 || foreign_keys != 1 || trusted_schema != 0 {
            return Err(AdmissionStoreError::InvalidInput(
                "SQLite FULL synchronous, foreign-key, and trusted-schema settings are not active",
            ));
        }

        let application_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        if application_id != 0 && application_id != APPLICATION_ID {
            return Err(AdmissionStoreError::WrongApplicationId);
        }

        let version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != 0 && version != SCHEMA_VERSION {
            return Err(AdmissionStoreError::UnsupportedSchema(version));
        }
        if application_id == 0 {
            let existing_objects: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if version != 0 || existing_objects != 0 {
                return Err(AdmissionStoreError::WrongApplicationId);
            }
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        }

        let mut connection = connection;
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        Self::check_schema_objects(&connection)?;

        Ok(connection)
    }

    fn check_schema_objects(connection: &Connection) -> Result<(), AdmissionStoreError> {
        const REQUIRED: [(&str, &str); 40] = [
            ("table", "admission_commits"),
            ("table", "authority_replays"),
            ("table", "supervisor_permits"),
            ("table", "transaction_attempts"),
            ("table", "admission_events"),
            ("index", "one_unresolved_attempt_per_transaction"),
            ("trigger", "admission_commits_immutable_update"),
            ("trigger", "admission_commits_immutable_delete"),
            ("trigger", "authority_replays_immutable_update"),
            ("trigger", "authority_replays_immutable_delete"),
            ("trigger", "supervisor_permits_immutable_update"),
            ("trigger", "supervisor_permits_immutable_delete"),
            ("trigger", "admission_events_immutable_update"),
            ("trigger", "admission_events_immutable_delete"),
            ("trigger", "transaction_attempts_one_way_resolution"),
            ("trigger", "transaction_attempts_no_delete"),
            ("table", "authority_policy_epochs"),
            ("table", "authority_policy_current"),
            ("trigger", "authority_policy_epochs_immutable_update"),
            ("trigger", "authority_policy_epochs_no_delete"),
            ("trigger", "authority_policy_epochs_monotonic_insert"),
            ("trigger", "authority_policy_current_initial_only"),
            ("trigger", "authority_policy_current_only_advance"),
            ("trigger", "authority_policy_current_no_delete"),
            ("table", "payload_release_barriers"),
            ("table", "payload_release_attempts"),
            ("table", "payload_release_uncertain"),
            ("table", "payload_release_receipts"),
            ("table", "payload_release_policy_decisions"),
            ("trigger", "payload_release_barriers_immutable_update"),
            ("trigger", "payload_release_barriers_no_delete"),
            ("trigger", "payload_release_attempts_immutable_update"),
            ("trigger", "payload_release_attempts_no_delete"),
            ("trigger", "payload_release_uncertain_immutable_update"),
            ("trigger", "payload_release_uncertain_no_delete"),
            ("trigger", "payload_release_receipts_immutable_update"),
            ("trigger", "payload_release_receipts_no_delete"),
            ("trigger", "payload_release_policy_decisions_immutable_update"),
            ("trigger", "payload_release_policy_decisions_no_delete"),
            ("trigger", "payload_release_policy_decisions_no_downgrade"),
        ];

        for (kind, name) in REQUIRED {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            if count != 1 {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }

        let user_object_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if user_object_count != REQUIRED.len() as i64 {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        let mut columns = connection.prepare("PRAGMA table_info(admission_commits)")?;
        let column_rows = columns.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
        })?;
        let mut names = std::collections::BTreeMap::new();
        for column in column_rows {
            let (name, not_null) = column?;
            names.insert(name, not_null);
        }
        if names.get("authority_provenance_digest") != Some(&1)
            || names.get("authority_provenance") != Some(&1)
        {
            return Err(AdmissionStoreError::InconsistentStorage);
        }

        let mut policy_columns = connection.prepare("PRAGMA table_info(authority_policy_epochs)")?;
        let policy_rows = policy_columns.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
        })?;
        let mut policy_names = std::collections::BTreeMap::new();
        for column in policy_rows {
            let (name, not_null) = column?;
            policy_names.insert(name, not_null);
        }
        for required in [
            "epoch",
            "policy_id",
            "policy_digest",
            "policy_json",
            "emergency_revocation_digest",
            "emergency_revoked_key_ids_json",
            "previous_record_digest",
            "update_provenance_digest",
            "update_provenance",
            "created_at_ms",
            "record_digest",
        ] {
            if policy_names.get(required) != Some(&1) {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }

        let mut current_columns = connection.prepare("PRAGMA table_info(authority_policy_current)")?;
        let current_rows = current_columns.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
        })?;
        let mut current_names = std::collections::BTreeMap::new();
        for column in current_rows {
            let (name, not_null) = column?;
            current_names.insert(name, not_null);
        }
        for required in ["singleton", "epoch", "record_digest"] {
            if current_names.get(required) != Some(&1) {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }
        Ok(())
    }

    fn digest_domain(domain: &[u8], bytes: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        hasher.finalize().to_hex().to_string()
    }

    fn derive_policy_epoch_record_digest(record: &AuthorityPolicyEpochRecord) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_EPOCH_RECORD_DOMAIN);
        let epoch = record.epoch.to_le_bytes();
        let created_at = record.created_at_ms.to_le_bytes();
        for value in [
            epoch.as_slice(),
            record.policy_id.as_bytes(),
            record.policy_digest.as_bytes(),
            record.emergency_revocation_digest.as_bytes(),
            record.previous_record_digest.as_bytes(),
            record.update_provenance_digest.as_bytes(),
            created_at.as_slice(),
        ] {
            Self::update_hash_field(&mut hasher, value);
        }
        hasher.finalize().to_hex().to_string()
    }

    fn derive_policy_epoch_record(
        request: &AuthorityPolicyEpochRequest,
        previous_record_digest: &str,
    ) -> Result<AuthorityPolicyEpochRecord, AdmissionStoreError> {
        if !Self::valid_token(&request.policy_id)
            || request.epoch == 0
            || !Self::valid_digest(previous_record_digest)
            || request.policy_json.is_empty()
            || request.policy_json.len() > MAX_AUTHORITY_POLICY_BYTES
            || request.update_provenance.is_empty()
            || request.update_provenance.len() > MAX_POLICY_UPDATE_PROVENANCE_BYTES
        {
            return Err(AdmissionStoreError::InvalidInput("authority policy epoch request"));
        }
        let _epoch_sql = i64::try_from(request.epoch)
            .map_err(|_| AdmissionStoreError::InvalidInput("authority policy epoch"))?;
        let created_at_ms = i64::try_from(request.created_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("authority policy creation timestamp"))?;
        if request.emergency_revoked_key_ids.len() > MAX_EMERGENCY_REVOCATION_IDS {
            return Err(AdmissionStoreError::InvalidInput("emergency revocation count"));
        }

        let policy: serde_json::Value = serde_json::from_slice(&request.policy_json)
            .map_err(|_| AdmissionStoreError::InvalidInput("authority policy JSON"))?;
        if policy.get("schema_version").and_then(serde_json::Value::as_u64)
                != Some(AUTHORITY_POLICY_SCHEMA_VERSION)
            || policy.get("kind").and_then(serde_json::Value::as_str)
                != Some(AUTHORITY_POLICY_KIND)
            || policy.get("policy_id").and_then(serde_json::Value::as_str)
                != Some(request.policy_id.as_str())
            || policy.get("policy_epoch").and_then(serde_json::Value::as_u64)
                != Some(request.epoch)
        {
            return Err(AdmissionStoreError::InvalidInput("authority policy identity/epoch binding"));
        }

        let mut prior_key: Option<&str> = None;
        for key_id in &request.emergency_revoked_key_ids {
            if !Self::valid_token(key_id)
                || prior_key.is_some_and(|prior| prior >= key_id.as_str())
            {
                return Err(AdmissionStoreError::InvalidInput(
                    "emergency revocation IDs must be sorted, unique tokens",
                ));
            }
            prior_key = Some(key_id);
        }

        let emergency_json = serde_json::to_vec(&request.emergency_revoked_key_ids)
            .map_err(|_| AdmissionStoreError::InvalidInput("emergency revocation JSON"))?;
        if emergency_json.len() > MAX_EMERGENCY_REVOCATION_BYTES {
            return Err(AdmissionStoreError::InvalidInput("emergency revocation bytes"));
        }
        let policy_digest =
            Self::digest_domain(AUTHORITY_POLICY_DIGEST_DOMAIN, &request.policy_json);
        let emergency_revocation_digest =
            Self::digest_domain(POLICY_EMERGENCY_REVOCATION_DOMAIN, &emergency_json);
        let update_provenance_digest =
            Self::digest_domain(POLICY_UPDATE_PROVENANCE_DOMAIN, &request.update_provenance);

        let mut record = AuthorityPolicyEpochRecord {
            policy_id: request.policy_id.clone(),
            epoch: request.epoch,
            policy_digest,
            policy_json: request.policy_json.clone(),
            emergency_revocation_digest,
            emergency_revoked_key_ids: request.emergency_revoked_key_ids.clone(),
            previous_record_digest: previous_record_digest.to_string(),
            update_provenance_digest,
            update_provenance: request.update_provenance.clone(),
            created_at_ms: request.created_at_ms,
            record_digest: String::new(),
        };
        record.record_digest = Self::derive_policy_epoch_record_digest(&record);
        // Keep the signed timestamp range check above; the conversion also rejects
        // impossible SQLite timestamps before the record is returned.
        let _ = created_at_ms;
        Ok(record)
    }

    fn validate_policy_epoch_record(
        record: &AuthorityPolicyEpochRecord,
    ) -> Result<(), AdmissionStoreError> {
        let request = AuthorityPolicyEpochRequest {
            policy_id: record.policy_id.clone(),
            epoch: record.epoch,
            policy_json: record.policy_json.clone(),
            emergency_revoked_key_ids: record.emergency_revoked_key_ids.clone(),
            update_provenance: record.update_provenance.clone(),
            created_at_ms: record.created_at_ms,
        };
        let expected =
            Self::derive_policy_epoch_record(&request, &record.previous_record_digest)?;
        if expected != *record || !Self::valid_digest(&record.record_digest) {
            return Err(AdmissionStoreError::InvalidPolicyEpochRecord);
        }
        Ok(())
    }

    fn map_policy_epoch_record(row: &Row<'_>) -> rusqlite::Result<AuthorityPolicyEpochRecord> {
        let epoch_raw: i64 = row.get(0)?;
        let emergency_json: Vec<u8> = row.get(5)?;
        let created_at_raw: i64 = row.get(9)?;
        if epoch_raw <= 0 || created_at_raw < 0 {
            return Err(rusqlite::Error::IntegralValueOutOfRange(0, epoch_raw));
        }
        let emergency_revoked_key_ids: Vec<String> =
            serde_json::from_slice(&emergency_json).map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    5,
                    "emergency_revoked_key_ids_json".into(),
                    rusqlite::types::Type::Blob,
                )
            })?;
        Ok(AuthorityPolicyEpochRecord {
            epoch: epoch_raw as u64,
            policy_id: row.get(1)?,
            policy_digest: row.get(2)?,
            policy_json: row.get(3)?,
            emergency_revocation_digest: row.get(4)?,
            emergency_revoked_key_ids,
            previous_record_digest: row.get(6)?,
            update_provenance_digest: row.get(7)?,
            update_provenance: row.get(8)?,
            created_at_ms: created_at_raw as u64,
            record_digest: row.get(10)?,
        })
    }

    fn load_policy_epoch_by_number(
        connection: &Connection,
        epoch: u64,
    ) -> Result<Option<AuthorityPolicyEpochRecord>, AdmissionStoreError> {
        let epoch = i64::try_from(epoch)
            .map_err(|_| AdmissionStoreError::InvalidInput("authority policy epoch"))?;
        let record = connection
            .query_row(
                r#"
                SELECT epoch, policy_id, policy_digest, policy_json,
                       emergency_revocation_digest, emergency_revoked_key_ids_json,
                       previous_record_digest, update_provenance_digest,
                       update_provenance, created_at_ms, record_digest
                FROM authority_policy_epochs
                WHERE epoch = ?1
                "#,
                [epoch],
                Self::map_policy_epoch_record,
            )
            .optional()?;
        if let Some(record) = &record {
            Self::validate_policy_epoch_record(record)?;
        }
        Ok(record)
    }

    fn load_current_policy_epoch_from(
        connection: &Connection,
    ) -> Result<Option<AuthorityPolicyEpochRecord>, AdmissionStoreError> {
        let pointer: Option<(i64, String)> = connection
            .query_row(
                "SELECT epoch, record_digest FROM authority_policy_current WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((epoch, expected_digest)) = pointer else {
            let history_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM authority_policy_epochs",
                [],
                |row| row.get(0),
            )?;
            if history_count != 0 {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
            return Ok(None);
        };
        if epoch <= 0 {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        let record = Self::load_policy_epoch_by_number(connection, epoch as u64)?
            .ok_or(AdmissionStoreError::InconsistentStorage)?;
        let maximum_epoch: Option<i64> = connection.query_row(
            "SELECT MAX(epoch) FROM authority_policy_epochs",
            [],
            |row| row.get(0),
        )?;
        if maximum_epoch != Some(epoch) || record.record_digest != expected_digest {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Ok(Some(record))
    }

    fn check_policy_epoch_pointer(connection: &Connection) -> Result<(), AdmissionStoreError> {
        let _ = Self::load_current_policy_epoch_from(connection)?;
        Ok(())
    }

    fn insert_policy_epoch_record(
        transaction: &rusqlite::Transaction<'_>,
        record: &AuthorityPolicyEpochRecord,
    ) -> Result<(), AdmissionStoreError> {
        let emergency_json = serde_json::to_vec(&record.emergency_revoked_key_ids)
            .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?;
        let created_at_ms = i64::try_from(record.created_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?;
        transaction.execute(
            r#"
            INSERT INTO authority_policy_epochs (
                epoch, policy_id, policy_digest, policy_json,
                emergency_revocation_digest, emergency_revoked_key_ids_json,
                previous_record_digest, update_provenance_digest,
                update_provenance, created_at_ms, record_digest
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                i64::try_from(record.epoch)
                    .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?,
                record.policy_id,
                record.policy_digest,
                record.policy_json,
                record.emergency_revocation_digest,
                emergency_json,
                record.previous_record_digest,
                record.update_provenance_digest,
                record.update_provenance,
                created_at_ms,
                record.record_digest,
            ],
        )?;
        Ok(())
    }

    fn verify_policy_epoch_history(
        connection: &Connection,
    ) -> Result<(), AdmissionStoreError> {
        let mut statement =
            connection.prepare("SELECT epoch FROM authority_policy_epochs ORDER BY epoch")?;
        let epochs = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        let mut expected_epoch = 1_i64;
        let mut previous_digest = GENESIS_POLICY_RECORD_DIGEST.to_string();
        for epoch in epochs {
            if epoch != expected_epoch || epoch <= 0 {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
            let record = Self::load_policy_epoch_by_number(connection, epoch as u64)?
                .ok_or(AdmissionStoreError::InconsistentStorage)?;
            if record.previous_record_digest != previous_digest {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
            previous_digest = record.record_digest;
            expected_epoch = expected_epoch
                .checked_add(1)
                .ok_or(AdmissionStoreError::InconsistentStorage)?;
        }
        Self::check_policy_epoch_pointer(connection)?;
        Ok(())
    }

    /// Initialize the local policy archive at epoch 1. The caller is responsible
    /// for performing the trusted owner-enrollment/bootstrap ceremony first.
    pub(crate) fn initialize_authority_policy_epoch(
        &self,
        request: &AuthorityPolicyEpochRequest,
    ) -> Result<AuthorityPolicyEpochOutcome, AdmissionStoreError> {
        if request.epoch != 1 {
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }
        let record =
            Self::derive_policy_epoch_record(request, GENESIS_POLICY_RECORD_DIGEST)?;
        let connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        Self::verify_policy_epoch_history(&transaction)?;

        if let Some(existing) = Self::load_current_policy_epoch_from(&transaction)? {
            let historical = Self::load_policy_epoch_by_number(&transaction, 1)?
                .ok_or(AdmissionStoreError::InconsistentStorage)?;
            if historical.record_digest == record.record_digest {
                transaction.commit()?;
                return Ok(AuthorityPolicyEpochOutcome::Existing(historical));
            }
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }

        let existing_history: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM authority_policy_epochs",
            [],
            |row| row.get(0),
        )?;
        if existing_history != 0 {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Self::insert_policy_epoch_record(&transaction, &record)?;
        transaction.execute(
            "INSERT INTO authority_policy_current (singleton, epoch, record_digest) VALUES (1, 1, ?1)",
            [&record.record_digest],
        )?;
        transaction.commit()?;

        let stored = Self::load_policy_epoch_by_number(&connection, 1)?
            .ok_or_else(|| AdmissionStoreError::PolicyEpochReadBackUncertain {
                epoch: 1,
                detail: "epoch 1 is not visible after commit".into(),
            })?;
        if stored != record {
            return Err(AdmissionStoreError::PolicyEpochReadBackUncertain {
                epoch: 1,
                detail: "epoch 1 differs from the committed policy snapshot".into(),
            });
        }
        Ok(AuthorityPolicyEpochOutcome::Created(stored))
    }

    /// Advance exactly one epoch from the expected current record. The policy
    /// update proof must already have been verified by the trusted supervisor.
    pub(crate) fn advance_authority_policy_epoch(
        &self,
        expected_current_epoch: u64,
        expected_current_record_digest: &str,
        request: &AuthorityPolicyEpochRequest,
    ) -> Result<AuthorityPolicyEpochOutcome, AdmissionStoreError> {
        self.advance_authority_policy_epoch_with_release_decisions(
            expected_current_epoch,
            expected_current_record_digest,
            request,
            &[],
        )
    }

    pub(crate) fn advance_authority_policy_epoch_with_release_decisions(
        &self,
        expected_current_epoch: u64,
        expected_current_record_digest: &str,
        request: &AuthorityPolicyEpochRequest,
        decisions: &[StoredReleasePolicyDecision],
    ) -> Result<AuthorityPolicyEpochOutcome, AdmissionStoreError> {
        if !Self::valid_digest(expected_current_record_digest)
            || request.epoch != expected_current_epoch.checked_add(1)
                .ok_or(AdmissionStoreError::PolicyEpochConflict)?
        {
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }
        let connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        Self::verify_policy_epoch_history(&transaction)?;

        if let Some(existing) =
            Self::load_policy_epoch_by_number(&transaction, request.epoch)?
        {
            let expected = Self::derive_policy_epoch_record(
                request,
                expected_current_record_digest,
            )?;
            if existing == expected {
                Self::verify_existing_release_policy_decisions(
                    &transaction,
                    &existing,
                    decisions,
                    request.created_at_ms,
                )?;
                transaction.commit()?;
                return Ok(AuthorityPolicyEpochOutcome::Existing(existing));
            }
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }

        let current = Self::load_current_policy_epoch_from(&transaction)?
            .ok_or(AdmissionStoreError::PolicyEpochNotInitialized)?;
        if current.epoch != expected_current_epoch
            || current.record_digest != expected_current_record_digest
        {
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }
        let record =
            Self::derive_policy_epoch_record(request, &current.record_digest)?;
        Self::insert_policy_epoch_record(&transaction, &record)?;
        Self::append_release_policy_decisions(
            &transaction,
            &record,
            decisions,
            request.created_at_ms,
        )?;
        let changed = transaction.execute(
            r#"
            UPDATE authority_policy_current
            SET epoch = ?2, record_digest = ?3
            WHERE singleton = 1 AND epoch = ?1 AND record_digest = ?4
            "#,
            params![
                i64::try_from(expected_current_epoch)
                    .map_err(|_| AdmissionStoreError::PolicyEpochConflict)?,
                i64::try_from(record.epoch)
                    .map_err(|_| AdmissionStoreError::PolicyEpochConflict)?,
                record.record_digest,
                current.record_digest,
            ],
        )?;
        if changed != 1 {
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }
        transaction.commit()?;

        let stored = Self::load_policy_epoch_by_number(&connection, record.epoch)?
            .ok_or_else(|| AdmissionStoreError::PolicyEpochReadBackUncertain {
                epoch: record.epoch,
                detail: "advanced policy epoch is not visible after commit".into(),
            })?;
        if stored != record {
            return Err(AdmissionStoreError::PolicyEpochReadBackUncertain {
                epoch: record.epoch,
                detail: "advanced policy epoch differs from the committed record".into(),
            });
        }
        Ok(AuthorityPolicyEpochOutcome::Created(stored))
    }


    fn derive_payload_release_id(
        admission: &AdmissionRecord,
        policy: &AuthorityPolicyEpochRecord,
        signer_key_id: &str,
        authority_subject_digest: &str,
        authority_audience: &str,
        payload_digest: &str,
        expires_at_ms: u64,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nixward-payload-release-id-v1\\0");
        let epoch_bytes = policy.epoch.to_le_bytes();
        let expiry_bytes = expires_at_ms.to_le_bytes();
        for value in [
            admission.transaction_id.as_bytes(),
            admission.attempt_id.as_bytes(),
            admission.commit_id.as_bytes(),
            admission.replay_key.as_bytes(),
            admission.permit_digest.as_bytes(),
            admission.plan_digest.as_bytes(),
            admission.machine_binding_digest.as_bytes(),
            admission.authority_provenance_digest.as_bytes(),
            signer_key_id.as_bytes(),
            authority_subject_digest.as_bytes(),
            authority_audience.as_bytes(),
            payload_digest.as_bytes(),
            policy.policy_id.as_bytes(),
            epoch_bytes.as_slice(),
            policy.policy_digest.as_bytes(),
            policy.record_digest.as_bytes(),
            expiry_bytes.as_slice(),
        ] {
            Self::update_hash_field(&mut hasher, value);
        }
        hasher.finalize().to_hex().to_string()
    }

    fn derive_payload_barrier_digest(record: &PayloadReleaseBarrierRecord) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nixward-payload-release-barrier-record-v1\\0");
        let epoch = record.policy_epoch.to_le_bytes();
        let expiry = record.expires_at_ms.to_le_bytes();
        let committed = record.barrier_committed_at_ms.to_le_bytes();
        for value in [
            record.release_id.as_bytes(),
            record.commit_id.as_bytes(),
            record.transaction_id.as_bytes(),
            record.attempt_id.as_bytes(),
            record.replay_key.as_bytes(),
            record.permit_digest.as_bytes(),
            record.plan_digest.as_bytes(),
            record.machine_binding_digest.as_bytes(),
            record.authority_provenance_digest.as_bytes(),
            record.policy_id.as_bytes(),
            epoch.as_slice(),
            record.policy_digest.as_bytes(),
            record.policy_record_digest.as_bytes(),
            record.signer_key_id.as_bytes(),
            record.authority_subject_digest.as_bytes(),
            record.authority_audience.as_bytes(),
            record.payload_digest.as_bytes(),
            expiry.as_slice(),
            committed.as_slice(),
        ] {
            Self::update_hash_field(&mut hasher, value);
        }
        hasher.finalize().to_hex().to_string()
    }

    fn validate_release_authority_provenance(
        admission: &AdmissionRecord,
        policy: &AuthorityPolicyEpochRecord,
        request: &PayloadReleaseBarrierRequest,
    ) -> Result<(), AdmissionStoreError> {
        let provenance: serde_json::Value =
            serde_json::from_slice(&admission.authority_provenance)
                .map_err(|_| AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let policy_json: serde_json::Value =
            serde_json::from_slice(&policy.policy_json)
                .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?;

        let string_field = |object: &serde_json::Value, key: &str| {
            object.get(key).and_then(serde_json::Value::as_str)
        };
        let integer_field = |object: &serde_json::Value, key: &str| {
            object.get(key).and_then(serde_json::Value::as_u64)
        };

        let policy_id = string_field(&provenance, "policy_id")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let policy_digest = string_field(&provenance, "policy_digest")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let signer_key_id = string_field(&provenance, "signer_key_id")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let issuer = string_field(&provenance, "issuer")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let action = string_field(&provenance, "action")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let audience = string_field(&provenance, "audience")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let subject = string_field(&provenance, "subject_blake3")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let replay_key = string_field(&provenance, "replay_key")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let holon_id = string_field(&provenance, "holon_id")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let signature_evidence = string_field(&provenance, "signature_evidence_blake3")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let signed_proof_digest = string_field(&provenance, "signed_proof_blake3")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let issued_at_ms = integer_field(&provenance, "issued_at_ms")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let expires_at_ms = integer_field(&provenance, "expires_at_ms")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let verified_at_ms = integer_field(&provenance, "verified_at_ms")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        let policy_epoch = integer_field(&provenance, "policy_epoch")
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;

        if integer_field(&provenance, "schema_version") != Some(1)
            || string_field(&provenance, "kind") != Some("nixward-authority-provenance-v1")
            || policy_id != policy.policy_id
            || policy_digest != policy.policy_digest
            || policy_epoch != policy.epoch
            || policy_epoch != request.expected_policy_epoch
            || signer_key_id != request.signer_key_id
            || action != "change"
            || audience != request.expected_authority_audience
            || subject != request.expected_authority_subject_digest
            || (audience == "nixward-change-v1" && subject != admission.plan_digest)
            || replay_key != admission.replay_key
            || !Self::valid_digest(holon_id)
            || !Self::valid_digest(signature_evidence)
            || !Self::valid_digest(signed_proof_digest)
            || issued_at_ms > request.now_ms
            || verified_at_ms < issued_at_ms
            || verified_at_ms > request.now_ms
            || request.now_ms > expires_at_ms
            || expires_at_ms != request.expires_at_ms
        {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        if ![
            "nixward-change-v1",
            "nixward-execution-intent-v1",
        ]
        .contains(&audience)
        {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        let signed_proof_json = provenance
            .get("signed_proof_json")
            .and_then(serde_json::Value::as_array)
            .ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        if signed_proof_json.is_empty() || signed_proof_json.len() > 64 * 1024 {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }

        let keys = policy_json.get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or(AdmissionStoreError::InvalidPolicyEpochRecord)?;
        let trusted_key = keys.iter().find(|key| {
            string_field(key, "key_id") == Some(signer_key_id)
                && string_field(key, "issuer") == Some(issuer)
        }).ok_or(AdmissionStoreError::ReleaseBarrierUnauthorized)?;
        if trusted_key.get("revoked").and_then(serde_json::Value::as_bool) != Some(false) {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        let allowed_actions = trusted_key.get("allowed_actions")
            .and_then(serde_json::Value::as_array)
            .ok_or(AdmissionStoreError::InvalidPolicyEpochRecord)?;
        if !allowed_actions.iter().any(|value| value.as_str() == Some("change")) {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        let claims_holon = trusted_key.get("claims")
            .and_then(|claims| claims.get("holon_id"))
            .and_then(serde_json::Value::as_str);
        if claims_holon != Some(holon_id) {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        let allowed_audiences = policy_json.get("allowed_audiences")
            .and_then(serde_json::Value::as_array)
            .ok_or(AdmissionStoreError::InvalidPolicyEpochRecord)?;
        if !allowed_audiences.iter().any(|value| value.as_str() == Some(audience)) {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        if policy.emergency_revoked_key_ids.iter().any(|key| key == signer_key_id) {
            return Err(AdmissionStoreError::ReleaseBarrierUnauthorized);
        }
        Ok(())
    }

    fn map_payload_release_barrier(row: &Row<'_>) -> rusqlite::Result<PayloadReleaseBarrierRecord> {
        let epoch: i64 = row.get(10)?;
        let expires_at_ms: i64 = row.get(17)?;
        let committed_at_ms: i64 = row.get(18)?;
        if epoch <= 0 || expires_at_ms <= 0 || committed_at_ms < 0 {
            return Err(rusqlite::Error::IntegralValueOutOfRange(10, epoch));
        }
        Ok(PayloadReleaseBarrierRecord {
            release_id: row.get(0)?,
            commit_id: row.get(1)?,
            transaction_id: row.get(2)?,
            attempt_id: row.get(3)?,
            replay_key: row.get(4)?,
            permit_digest: row.get(5)?,
            plan_digest: row.get(6)?,
            machine_binding_digest: row.get(7)?,
            authority_provenance_digest: row.get(8)?,
            policy_id: row.get(9)?,
            policy_epoch: epoch as u64,
            policy_digest: row.get(11)?,
            policy_record_digest: row.get(12)?,
            signer_key_id: row.get(13)?,
            authority_subject_digest: row.get(14)?,
            authority_audience: row.get(15)?,
            payload_digest: row.get(16)?,
            expires_at_ms: expires_at_ms as u64,
            barrier_committed_at_ms: committed_at_ms as u64,
            barrier_digest: row.get(19)?,
        })
    }

    fn validate_payload_release_barrier(
        record: &PayloadReleaseBarrierRecord,
    ) -> Result<(), AdmissionStoreError> {
        for digest in [
            record.release_id.as_str(),
            record.replay_key.as_str(),
            record.permit_digest.as_str(),
            record.plan_digest.as_str(),
            record.machine_binding_digest.as_str(),
            record.authority_provenance_digest.as_str(),
            record.policy_digest.as_str(),
            record.policy_record_digest.as_str(),
            record.authority_subject_digest.as_str(),
            record.payload_digest.as_str(),
            record.barrier_digest.as_str(),
        ] {
            if !Self::valid_digest(digest) {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }
        if !Self::valid_token(&record.transaction_id)
            || !Self::valid_token(&record.attempt_id)
            || !Self::valid_token(&record.policy_id)
            || !Self::valid_token(&record.signer_key_id)
            || !Self::valid_token(&record.authority_audience)
            || Self::derive_payload_barrier_digest(record) != record.barrier_digest
        {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Ok(())
    }

    fn load_payload_release_barrier(
        connection: &Connection,
        release_id: &str,
    ) -> Result<Option<PayloadReleaseBarrierRecord>, AdmissionStoreError> {
        let record = connection.query_row(
            r#"
            SELECT release_id, commit_id, transaction_id, attempt_id, replay_key,
                   permit_digest, plan_digest, machine_binding_digest,
                   authority_provenance_digest, policy_id, policy_epoch,
                   policy_digest, policy_record_digest, signer_key_id,
                   authority_subject_digest, authority_audience, payload_digest,
                   expires_at_ms, barrier_committed_at_ms, barrier_digest
            FROM payload_release_barriers WHERE release_id = ?1
            "#,
            [release_id],
            Self::map_payload_release_barrier,
        ).optional()?;
        if let Some(record) = &record {
            Self::validate_payload_release_barrier(record)?;
        }
        Ok(record)
    }

    fn load_payload_release_barrier_by_commit(
        connection: &Connection,
        commit_id: &str,
    ) -> Result<Option<PayloadReleaseBarrierRecord>, AdmissionStoreError> {
        let record = connection.query_row(
            r#"
            SELECT release_id, commit_id, transaction_id, attempt_id, replay_key,
                   permit_digest, plan_digest, machine_binding_digest,
                   authority_provenance_digest, policy_id, policy_epoch,
                   policy_digest, policy_record_digest, signer_key_id,
                   authority_subject_digest, authority_audience, payload_digest,
                   expires_at_ms, barrier_committed_at_ms, barrier_digest
            FROM payload_release_barriers WHERE commit_id = ?1
            "#,
            [commit_id],
            Self::map_payload_release_barrier,
        ).optional()?;
        if let Some(record) = &record {
            Self::validate_payload_release_barrier(record)?;
        }
        Ok(record)
    }


    fn validate_payload_release_cross_bindings(
        connection: &Connection,
        barrier: &PayloadReleaseBarrierRecord,
    ) -> Result<(), AdmissionStoreError> {
        Self::validate_payload_release_barrier(barrier)?;
        let admission = Self::load_by_commit(connection, &barrier.commit_id)?
            .ok_or(AdmissionStoreError::InconsistentStorage)?;
        let policy = Self::load_policy_epoch_by_number(connection, barrier.policy_epoch)?
            .ok_or(AdmissionStoreError::InconsistentStorage)?;

        if admission.transaction_id != barrier.transaction_id
            || admission.attempt_id != barrier.attempt_id
            || admission.replay_key != barrier.replay_key
            || admission.permit_digest != barrier.permit_digest
            || admission.plan_digest != barrier.plan_digest
            || admission.machine_binding_digest != barrier.machine_binding_digest
            || admission.authority_provenance_digest != barrier.authority_provenance_digest
            || policy.policy_id != barrier.policy_id
            || policy.policy_digest != barrier.policy_digest
            || policy.record_digest != barrier.policy_record_digest
        {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        let expected_release_id = Self::derive_payload_release_id(
            &admission,
            &policy,
            &barrier.signer_key_id,
            &barrier.authority_subject_digest,
            &barrier.authority_audience,
            &barrier.payload_digest,
            barrier.expires_at_ms,
        );
        if expected_release_id != barrier.release_id {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        let provenance: serde_json::Value =
            serde_json::from_slice(&admission.authority_provenance)
                .map_err(|_| AdmissionStoreError::InconsistentStorage)?;
        let get_str = |key: &str| provenance.get(key).and_then(serde_json::Value::as_str);
        let get_u64 = |key: &str| provenance.get(key).and_then(serde_json::Value::as_u64);
        if get_str("policy_id") != Some(barrier.policy_id.as_str())
            || get_str("policy_digest") != Some(barrier.policy_digest.as_str())
            || get_u64("policy_epoch") != Some(barrier.policy_epoch)
            || get_str("signer_key_id") != Some(barrier.signer_key_id.as_str())
            || get_str("subject_blake3") != Some(barrier.authority_subject_digest.as_str())
            || get_str("audience") != Some(barrier.authority_audience.as_str())
            || get_str("replay_key") != Some(barrier.replay_key.as_str())
            || get_str("action") != Some("change")
        {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Ok(())
    }

    fn release_barrier_matches_request(
        record: &PayloadReleaseBarrierRecord,
        admission: &AdmissionRecord,
        policy: &AuthorityPolicyEpochRecord,
        request: &PayloadReleaseBarrierRequest,
    ) -> bool {
        record.commit_id == admission.commit_id
            && record.transaction_id == admission.transaction_id
            && record.attempt_id == admission.attempt_id
            && record.replay_key == admission.replay_key
            && record.permit_digest == admission.permit_digest
            && record.plan_digest == admission.plan_digest
            && record.machine_binding_digest == admission.machine_binding_digest
            && record.authority_provenance_digest == admission.authority_provenance_digest
            && record.policy_id == policy.policy_id
            && record.policy_epoch == policy.epoch
            && record.policy_digest == policy.policy_digest
            && record.policy_record_digest == policy.record_digest
            && record.signer_key_id == request.signer_key_id
            && record.authority_subject_digest == request.expected_authority_subject_digest
            && record.authority_audience == request.expected_authority_audience
            && record.payload_digest == request.payload_digest
            && record.expires_at_ms == request.expires_at_ms
    }

    fn release_decision_digest(
        release_id: &str,
        policy_epoch: u64,
        policy_record_digest: &str,
        disposition: StoredReleaseDisposition,
        created_at_ms: u64,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nixward-payload-release-policy-decision-v1\\0");
        let epoch = policy_epoch.to_le_bytes();
        let created = created_at_ms.to_le_bytes();
        for value in [
            release_id.as_bytes(),
            epoch.as_slice(),
            policy_record_digest.as_bytes(),
            disposition.as_str().as_bytes(),
            created.as_slice(),
        ] {
            Self::update_hash_field(&mut hasher, value);
        }
        hasher.finalize().to_hex().to_string()
    }

    fn verify_existing_release_policy_decisions(
        connection: &Connection,
        policy: &AuthorityPolicyEpochRecord,
        decisions: &[StoredReleasePolicyDecision],
        created_at_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT release_id, disposition, decision_digest
            FROM payload_release_policy_decisions
            WHERE policy_epoch = ?1 AND policy_record_digest = ?2
            ORDER BY release_id
            "#,
        )?;
        let rows = statement.query_map(
            params![
                i64::try_from(policy.epoch)
                    .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?,
                policy.record_digest,
            ],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            )),
        )?;
        let stored = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if stored.len() != decisions.len() {
            return Err(AdmissionStoreError::ReleasePolicyDecisionRequired);
        }
        for decision in decisions {
            let Some((_, disposition, digest)) =
                stored.iter().find(|(release_id, _, _)| release_id == &decision.release_id)
            else {
                return Err(AdmissionStoreError::ReleasePolicyDecisionRequired);
            };
            let expected = Self::release_decision_digest(
                &decision.release_id,
                policy.epoch,
                &policy.record_digest,
                decision.disposition,
                created_at_ms,
            );
            if disposition != decision.disposition.as_str() || digest != &expected {
                return Err(AdmissionStoreError::ReleasePolicyDecisionRequired);
            }
        }
        Ok(())
    }

    fn append_release_policy_decisions(
        transaction: &rusqlite::Transaction<'_>,
        next_policy: &AuthorityPolicyEpochRecord,
        decisions: &[StoredReleasePolicyDecision],
        created_at_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        let mut statement = transaction.prepare(
            r#"
            SELECT b.release_id
            FROM payload_release_barriers AS b
            LEFT JOIN payload_release_receipts AS r ON r.release_id = b.release_id
            WHERE r.release_id IS NULL
            ORDER BY b.release_id
            "#,
        )?;
        let active = statement.query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        if active.len() != decisions.len() {
            return Err(AdmissionStoreError::ReleasePolicyDecisionRequired);
        }
        let active_set = active.iter().cloned().collect::<std::collections::BTreeSet<_>>();
        let mut seen = std::collections::BTreeSet::new();
        for decision in decisions {
            if !active_set.contains(&decision.release_id) || !seen.insert(decision.release_id.clone()) {
                return Err(AdmissionStoreError::ReleasePolicyDecisionRequired);
            }
            let prior_stop: bool = transaction.query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM payload_release_policy_decisions
                    WHERE release_id = ?1 AND disposition = 'stop_or_recovery_required'
                )
                "#,
                [&decision.release_id],
                |row| row.get(0),
            )?;
            if prior_stop && decision.disposition == StoredReleaseDisposition::PreserveExistingBarrier {
                return Err(AdmissionStoreError::ReleasePolicyDecisionDowngrade);
            }
            let digest = Self::release_decision_digest(
                &decision.release_id,
                next_policy.epoch,
                &next_policy.record_digest,
                decision.disposition,
                created_at_ms,
            );
            transaction.execute(
                r#"
                INSERT INTO payload_release_policy_decisions (
                    decision_id, release_id, policy_epoch, policy_record_digest,
                    disposition, decision_digest, created_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    digest,
                    decision.release_id,
                    i64::try_from(next_policy.epoch)
                        .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?,
                    next_policy.record_digest,
                    decision.disposition.as_str(),
                    digest,
                    i64::try_from(created_at_ms)
                        .map_err(|_| AdmissionStoreError::InvalidPolicyEpochRecord)?,
                ],
            )?;
        }
        Ok(())
    }

    /// Create one immutable release barrier. Existing barriers are returned
    /// read-only on an exact retry, even after policy advancement, so a lost
    /// acknowledgement cannot accidentally authorize a second barrier.
    pub(crate) fn create_payload_release_barrier(
        &self,
        request: &PayloadReleaseBarrierRequest,
    ) -> Result<PayloadReleaseBarrierOutcome, AdmissionStoreError> {
        if !Self::valid_digest(&request.commit_id)
            || !Self::valid_digest(&request.expected_policy_record_digest)
            || !Self::valid_token(&request.signer_key_id)
            || !Self::valid_digest(&request.expected_authority_subject_digest)
            || !Self::valid_digest(&request.payload_digest)
            || request.expected_policy_epoch == 0
            || !["nixward-change-v1", "nixward-execution-intent-v1"]
                .contains(&request.expected_authority_audience.as_str())
            || request.expires_at_ms == 0
        {
            return Err(AdmissionStoreError::InvalidInput("payload release barrier request"));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        Self::verify_policy_epoch_history(&transaction)?;
        let admission = Self::load_by_commit(&transaction, &request.commit_id)?
            .ok_or(AdmissionStoreError::NotFound)?;
        let policy = Self::load_policy_epoch_by_number(&transaction, request.expected_policy_epoch)?
            .ok_or(AdmissionStoreError::PolicyEpochConflict)?;
        if policy.record_digest != request.expected_policy_record_digest {
            return Err(AdmissionStoreError::ReleaseBarrierStalePolicy);
        }

        if let Some(existing) =
            Self::load_payload_release_barrier_by_commit(&transaction, &request.commit_id)?
        {
            if !Self::release_barrier_matches_request(&existing, &admission, &policy, request) {
                return Err(AdmissionStoreError::ReleaseBarrierConflict);
            }
            Self::validate_payload_release_cross_bindings(&transaction, &existing)?;
            transaction.commit()?;
            return Ok(PayloadReleaseBarrierOutcome::Existing(existing));
        }

        let current = Self::load_current_policy_epoch_from(&transaction)?
            .ok_or(AdmissionStoreError::PolicyEpochNotInitialized)?;
        if current.epoch != request.expected_policy_epoch
            || current.record_digest != request.expected_policy_record_digest
        {
            return Err(AdmissionStoreError::ReleaseBarrierStalePolicy);
        }
        if admission.state != AdmissionState::Unresolved {
            return Err(AdmissionStoreError::ReleaseBarrierConflict);
        }
        if request.now_ms > request.expires_at_ms {
            return Err(AdmissionStoreError::ReleaseBarrierExpired);
        }
        if request.now_ms > request.expires_at_ms {
            return Err(AdmissionStoreError::ReleaseBarrierExpired);
        }
        Self::validate_release_authority_provenance(&admission, &current, request)?;

        let release_id = Self::derive_payload_release_id(
            &admission,
            &current,
            &request.signer_key_id,
            &request.expected_authority_subject_digest,
            &request.expected_authority_audience,
            &request.payload_digest,
            request.expires_at_ms,
        );
        let mut record = PayloadReleaseBarrierRecord {
            release_id,
            commit_id: admission.commit_id.clone(),
            transaction_id: admission.transaction_id.clone(),
            attempt_id: admission.attempt_id.clone(),
            replay_key: admission.replay_key.clone(),
            permit_digest: admission.permit_digest.clone(),
            plan_digest: admission.plan_digest.clone(),
            machine_binding_digest: admission.machine_binding_digest.clone(),
            authority_provenance_digest: admission.authority_provenance_digest.clone(),
            policy_id: current.policy_id.clone(),
            policy_epoch: current.epoch,
            policy_digest: current.policy_digest.clone(),
            policy_record_digest: current.record_digest.clone(),
            signer_key_id: request.signer_key_id.clone(),
            authority_subject_digest: request.expected_authority_subject_digest.clone(),
            authority_audience: request.expected_authority_audience.clone(),
            payload_digest: request.payload_digest.clone(),
            expires_at_ms: request.expires_at_ms,
            barrier_committed_at_ms: request.now_ms,
            barrier_digest: String::new(),
        };
        record.barrier_digest = Self::derive_payload_barrier_digest(&record);
        Self::validate_payload_release_barrier(&record)?;
        transaction.execute(
            r#"
            INSERT INTO payload_release_barriers (
                release_id, commit_id, transaction_id, attempt_id, replay_key,
                permit_digest, plan_digest, machine_binding_digest,
                authority_provenance_digest, policy_id, policy_epoch, policy_digest,
                policy_record_digest, signer_key_id, authority_subject_digest,
                authority_audience, payload_digest, expires_at_ms,
                barrier_committed_at_ms, barrier_digest
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
            params![
                record.release_id, record.commit_id, record.transaction_id, record.attempt_id,
                record.replay_key, record.permit_digest, record.plan_digest,
                record.machine_binding_digest, record.authority_provenance_digest,
                record.policy_id, i64::try_from(record.policy_epoch)
                    .map_err(|_| AdmissionStoreError::InvalidInput("policy epoch"))?,
                record.policy_digest, record.policy_record_digest, record.signer_key_id,
                record.authority_subject_digest, record.authority_audience,
                record.payload_digest, i64::try_from(record.expires_at_ms)
                    .map_err(|_| AdmissionStoreError::InvalidInput("release expiry"))?,
                i64::try_from(record.barrier_committed_at_ms)
                    .map_err(|_| AdmissionStoreError::InvalidInput("barrier timestamp"))?,
                record.barrier_digest,
            ],
        )?;
        transaction.commit()?;
        let stored = Self::load_payload_release_barrier(&connection, &record.release_id)?
            .ok_or_else(|| AdmissionStoreError::ReadBackUncertain {
                commit_id: record.release_id.clone(),
                detail: "release barrier not visible after commit".into(),
            })?;
        if stored != record {
            return Err(AdmissionStoreError::ReadBackUncertain {
                commit_id: record.release_id.clone(),
                detail: "release barrier differs from committed record".into(),
            });
        }
        Ok(PayloadReleaseBarrierOutcome::Created(stored))
    }

    /// Reserve the unique external release attempt. The caller MUST write no
    /// worker payload bytes until this method has committed successfully.
    pub(crate) fn begin_payload_release_attempt(
        &self,
        release_id: &str,
        now_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        if !Self::valid_digest(release_id) {
            return Err(AdmissionStoreError::InvalidInput("release ID"));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        let barrier = Self::load_payload_release_barrier(&transaction, release_id)?
            .ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        Self::validate_payload_release_cross_bindings(&transaction, &barrier)?;
        let admission_state: String = transaction.query_row(
            "SELECT state FROM transaction_attempts WHERE commit_id = ?1",
            [&barrier.commit_id],
            |row| row.get(0),
        )?;
        if admission_state != "unresolved" {
            return Err(AdmissionStoreError::ReleaseAttemptBlocked);
        }
        let existing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM payload_release_attempts WHERE release_id = ?1)",
            [release_id],
            |row| row.get(0),
        )?;
        if existing {
            return Err(AdmissionStoreError::ReleaseAttemptAlreadyStarted);
        }
        let stop_required: bool = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM payload_release_policy_decisions
                WHERE release_id = ?1 AND disposition = 'stop_or_recovery_required'
            )
            "#,
            [release_id],
            |row| row.get(0),
        )?;
        if stop_required {
            return Err(AdmissionStoreError::ReleaseAttemptBlocked);
        }
        if now_ms > barrier.expires_at_ms {
            return Err(AdmissionStoreError::ReleaseBarrierExpired);
        }
        let started_at_ms = i64::try_from(now_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("release attempt timestamp"))?;
        let attempt_digest = Self::digest_domain(
            b"nixward-payload-release-attempt-v1\\0",
            format!("{release_id}:{}:{now_ms}", barrier.attempt_id).as_bytes(),
        );
        transaction.execute(
            "INSERT INTO payload_release_attempts (release_id, attempt_id, started_at_ms, attempt_digest) VALUES (?1, ?2, ?3, ?4)",
            params![release_id, barrier.attempt_id, started_at_ms, attempt_digest],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Mark a started attempt as ambiguous. A receipt may still arrive later;
    /// this marker never authorizes another send.
    pub(crate) fn mark_payload_release_uncertain(
        &self,
        release_id: &str,
        observed_at_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        if !Self::valid_digest(release_id) {
            return Err(AdmissionStoreError::InvalidInput("release ID"));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        let started: Option<i64> = transaction.query_row(
            "SELECT started_at_ms FROM payload_release_attempts WHERE release_id = ?1",
            [release_id],
            |row| row.get(0),
        ).optional()?;
        let started = started.ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        let barrier = Self::load_payload_release_barrier(&transaction, release_id)?
            .ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        Self::validate_payload_release_cross_bindings(&transaction, &barrier)?;
        if observed_at_ms < started as u64 {
            return Err(AdmissionStoreError::InvalidInput("uncertainty timestamp"));
        }
        let existing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM payload_release_uncertain WHERE release_id = ?1)",
            [release_id],
            |row| row.get(0),
        )?;
        if existing {
            return Err(AdmissionStoreError::ReleaseAttemptAlreadyUncertain);
        }
        let has_receipt: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM payload_release_receipts WHERE release_id = ?1)",
            [release_id],
            |row| row.get(0),
        )?;
        if has_receipt {
            return Err(AdmissionStoreError::InvalidTransition);
        }
        let digest = Self::digest_domain(
            b"nixward-payload-release-uncertain-v1\\0",
            format!("{release_id}:{observed_at_ms}").as_bytes(),
        );
        transaction.execute(
            "INSERT INTO payload_release_uncertain (release_id, observed_at_ms, uncertainty_digest) VALUES (?1, ?2, ?3)",
            params![
                release_id,
                i64::try_from(observed_at_ms)
                    .map_err(|_| AdmissionStoreError::InvalidInput("uncertainty timestamp"))?,
                digest
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Persist the one exact worker receipt. It may reconcile an uncertain
    /// attempt, but it never creates or retries a release attempt.
    pub(crate) fn acknowledge_payload_release(
        &self,
        release_id: &str,
        payload_digest: &str,
        worker_unit: &str,
        invocation_id: &str,
        receipt_digest: &str,
        acknowledged_at_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        if !Self::valid_digest(release_id)
            || !Self::valid_digest(payload_digest)
            || !Self::valid_digest(receipt_digest)
            || !Self::valid_token(worker_unit)
            || !Self::valid_token(invocation_id)
        {
            return Err(AdmissionStoreError::InvalidInput("payload release receipt"));
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        let barrier = Self::load_payload_release_barrier(&transaction, release_id)?
            .ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        Self::validate_payload_release_cross_bindings(&transaction, &barrier)?;
        if barrier.payload_digest != payload_digest {
            return Err(AdmissionStoreError::ReleaseReceiptConflict);
        }
        let started: Option<i64> = transaction.query_row(
            "SELECT started_at_ms FROM payload_release_attempts WHERE release_id = ?1",
            [release_id],
            |row| row.get(0),
        ).optional()?;
        let started = started.ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        if acknowledged_at_ms < started as u64 {
            return Err(AdmissionStoreError::ReleaseReceiptConflict);
        }
        let acknowledged_at_i64 = i64::try_from(acknowledged_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("receipt timestamp"))?;
        let existing: Option<(String, String, String, String, i64)> = transaction.query_row(
            "SELECT payload_digest, worker_unit, invocation_id, receipt_digest, acknowledged_at_ms FROM payload_release_receipts WHERE release_id = ?1",
            [release_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        if let Some((old_payload, old_unit, old_invocation, old_receipt_digest, old_at)) = existing {
            if old_payload == payload_digest && old_unit == worker_unit
                && old_invocation == invocation_id && old_receipt_digest == receipt_digest
                && old_at == acknowledged_at_i64
            {
                transaction.commit()?;
                return Ok(());
            }
            return Err(AdmissionStoreError::ReleaseReceiptConflict);
        }
        let receipt_record_digest = Self::digest_domain(
            b"nixward-payload-release-receipt-v1\\0",
            format!("{release_id}:{payload_digest}:{worker_unit}:{invocation_id}:{receipt_digest}:{acknowledged_at_ms}").as_bytes(),
        );
        transaction.execute(
            r#"
            INSERT INTO payload_release_receipts (
                release_id, payload_digest, worker_unit, invocation_id,
                receipt_digest, acknowledged_at_ms, receipt_record_digest
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                release_id, payload_digest, worker_unit, invocation_id, receipt_digest,
                acknowledged_at_i64,
                receipt_record_digest,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn payload_release_state(
        &self,
        release_id: &str,
    ) -> Result<PayloadReleaseStoreState, AdmissionStoreError> {
        let connection = self.connect()?;
        Self::check_join_invariants(&connection)?;
        let barrier = Self::load_payload_release_barrier(&connection, release_id)?
            .ok_or(AdmissionStoreError::ReleaseBarrierNotFound)?;
        Self::validate_payload_release_cross_bindings(&connection, &barrier)?;
        let attempt: Option<(i64, Option<i64>)> = connection.query_row(
            r#"
            SELECT a.started_at_ms, u.observed_at_ms
            FROM payload_release_attempts AS a
            LEFT JOIN payload_release_uncertain AS u ON u.release_id = a.release_id
            WHERE a.release_id = ?1
            "#,
            [release_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((started_at, uncertain_at)) = attempt else {
            return Ok(PayloadReleaseStoreState::BarrierCommitted(barrier));
        };
        let receipt: Option<(i64, String, String, String)> = connection.query_row(
            r#"
            SELECT acknowledged_at_ms, worker_unit, invocation_id, receipt_digest
            FROM payload_release_receipts WHERE release_id = ?1
            "#,
            [release_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some((ack, unit, invocation, digest)) = receipt {
            return Ok(PayloadReleaseStoreState::Acknowledged {
                barrier,
                started_at_ms: started_at as u64,
                acknowledged_at_ms: ack as u64,
                worker_unit: unit,
                invocation_id: invocation,
                receipt_digest: digest,
            });
        }
        Ok(PayloadReleaseStoreState::Attempted {
            barrier,
            started_at_ms: started_at as u64,
            uncertain_at_ms: uncertain_at.map(|value| value as u64),
        })
    }

    /// Return the current trusted-store snapshot as audit/configuration data.
    /// The caller must still enforce policy trust and signature semantics.
    pub(crate) fn current_authority_policy_epoch(
        &self,
    ) -> Result<Option<AuthorityPolicyEpochRecord>, AdmissionStoreError> {
        let connection = self.connect()?;
        Self::check_join_invariants(&connection)?;
        Self::verify_policy_epoch_history(&connection)?;
        Self::load_current_policy_epoch_from(&connection)
    }

    /// Load an exact historical policy snapshot by epoch and record digest.
    /// This returns data, never an authority capability.
    pub(crate) fn historical_authority_policy_epoch(
        &self,
        epoch: u64,
        expected_record_digest: &str,
    ) -> Result<Option<AuthorityPolicyEpochRecord>, AdmissionStoreError> {
        if !Self::valid_digest(expected_record_digest) {
            return Err(AdmissionStoreError::InvalidInput("authority policy record digest"));
        }
        let connection = self.connect()?;
        Self::check_join_invariants(&connection)?;
        Self::verify_policy_epoch_history(&connection)?;
        let record = Self::load_policy_epoch_by_number(&connection, epoch)?;
        if record.as_ref().is_some_and(|value| value.record_digest != expected_record_digest) {
            return Err(AdmissionStoreError::PolicyEpochConflict);
        }
        Ok(record)
    }

    fn digest(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
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

    fn update_hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    fn derive_commit_id(
        transaction_id: &str,
        attempt_id: &str,
        replay_key: &str,
        plan_digest: &str,
        machine_binding_digest: &str,
        approval_proof_digest: &str,
        authority_provenance_digest: &str,
        permit_digest: &str,
        event_digest: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nixward-supervisor-admission-commit-v2\0");
        for value in [
            transaction_id.as_bytes(),
            attempt_id.as_bytes(),
            replay_key.as_bytes(),
            plan_digest.as_bytes(),
            machine_binding_digest.as_bytes(),
            approval_proof_digest.as_bytes(),
            authority_provenance_digest.as_bytes(),
            permit_digest.as_bytes(),
            event_digest.as_bytes(),
        ] {
            Self::update_hash_field(&mut hasher, value);
        }
        hasher.finalize().to_hex().to_string()
    }

    fn validate_record_content(record: &AdmissionRecord) -> Result<(), AdmissionStoreError> {
        if !Self::valid_token(&record.transaction_id)
            || !Self::valid_token(&record.attempt_id)
            || !Self::valid_digest(&record.replay_key)
            || !Self::valid_digest(&record.plan_digest)
            || !Self::valid_digest(&record.machine_binding_digest)
            || !Self::valid_digest(&record.approval_proof_digest)
            || !Self::valid_digest(&record.authority_provenance_digest)
            || record.authority_provenance.is_empty()
            || record.authority_provenance.len() > MAX_AUTHORITY_PROVENANCE_BYTES
            || Self::digest(&record.authority_provenance) != record.authority_provenance_digest
            || !Self::valid_digest(&record.permit_digest)
            || !Self::valid_digest(&record.event_digest)
            || !Self::valid_digest(&record.commit_id)
            || Self::digest(&record.approval_material) != record.approval_proof_digest
            || Self::digest(&record.permit_wire) != record.permit_digest
            || Self::digest(&record.event_payload) != record.event_digest
            || Self::derive_commit_id(
                &record.transaction_id,
                &record.attempt_id,
                &record.replay_key,
                &record.plan_digest,
                &record.machine_binding_digest,
                &record.approval_proof_digest,
                &record.authority_provenance_digest,
                &record.permit_digest,
                &record.event_digest,
            ) != record.commit_id
        {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        if let AdmissionState::Resolved { resolution_digest, .. } = &record.state {
            if !Self::valid_digest(resolution_digest) {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }
        Ok(())
    }

    fn validate_request(request: &AdmissionRequest) -> Result<DerivedBindings, AdmissionStoreError> {
        if !Self::valid_token(&request.transaction_id) {
            return Err(AdmissionStoreError::InvalidInput("transaction ID"));
        }
        if !Self::valid_token(&request.attempt_id) {
            return Err(AdmissionStoreError::InvalidInput("attempt ID"));
        }
        for (name, value) in [
            ("replay key", request.replay_key.as_str()),
            ("plan digest", request.plan_digest.as_str()),
            ("machine-binding digest", request.machine_binding_digest.as_str()),
        ] {
            if !Self::valid_digest(value) {
                return Err(AdmissionStoreError::InvalidInput(name));
            }
        }
        if request.approval_material.is_empty()
            || request.approval_material.len() > MAX_APPROVAL_BYTES
        {
            return Err(AdmissionStoreError::InvalidInput("approval material length"));
        }
        if request.authority_provenance.is_empty()
            || request.authority_provenance.len() > MAX_AUTHORITY_PROVENANCE_BYTES
        {
            return Err(AdmissionStoreError::InvalidInput("authority provenance length"));
        }
        if request.permit_wire.is_empty() || request.permit_wire.len() > MAX_PERMIT_BYTES {
            return Err(AdmissionStoreError::InvalidInput("permit wire length"));
        }
        if request.event_payload.is_empty() || request.event_payload.len() > MAX_EVENT_BYTES {
            return Err(AdmissionStoreError::InvalidInput("admission event length"));
        }
        let created_at_ms = i64::try_from(request.created_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("creation timestamp"))?;

        let approval_proof_digest = Self::digest(&request.approval_material);
        let authority_provenance_digest = Self::digest(&request.authority_provenance);
        let permit_digest = Self::digest(&request.permit_wire);
        let event_digest = Self::digest(&request.event_payload);

        let commit_id = Self::derive_commit_id(
            &request.transaction_id,
            &request.attempt_id,
            &request.replay_key,
            &request.plan_digest,
            &request.machine_binding_digest,
            &approval_proof_digest,
            &authority_provenance_digest,
            &permit_digest,
            &event_digest,
        );

        Ok(DerivedBindings {
            approval_proof_digest,
            authority_provenance_digest,
            permit_digest,
            event_digest,
            commit_id,
            created_at_ms,
        })
    }


    fn verify_payload_release_integrity(
        connection: &Connection,
    ) -> Result<(), AdmissionStoreError> {
        let mut statement =
            connection.prepare("SELECT release_id FROM payload_release_barriers ORDER BY release_id")?;
        let release_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        for release_id in release_ids {
            let barrier = Self::load_payload_release_barrier(connection, &release_id)?
                .ok_or(AdmissionStoreError::InconsistentStorage)?;
            Self::validate_payload_release_cross_bindings(connection, &barrier)?;

            let attempt: Option<(String, i64, String)> = connection.query_row(
                "SELECT attempt_id, started_at_ms, attempt_digest FROM payload_release_attempts WHERE release_id = ?1",
                [&release_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            if let Some((attempt_id, started_at_ms, attempt_digest)) = attempt {
                if attempt_id != barrier.attempt_id || started_at_ms < 0 {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
                let expected = Self::digest_domain(
                    b"nixward-payload-release-attempt-v1\\0",
                    format!("{release_id}:{attempt_id}:{started_at_ms}").as_bytes(),
                );
                if expected != attempt_digest {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }

                let uncertain: Option<(i64, String)> = connection.query_row(
                    "SELECT observed_at_ms, uncertainty_digest FROM payload_release_uncertain WHERE release_id = ?1",
                    [&release_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).optional()?;
                if let Some((observed_at_ms, uncertainty_digest)) = uncertain {
                    if observed_at_ms < started_at_ms {
                        return Err(AdmissionStoreError::InconsistentStorage);
                    }
                    let expected = Self::digest_domain(
                        b"nixward-payload-release-uncertain-v1\\0",
                        format!("{release_id}:{observed_at_ms}").as_bytes(),
                    );
                    if expected != uncertainty_digest {
                        return Err(AdmissionStoreError::InconsistentStorage);
                    }
                }

                let receipt: Option<(String, String, String, String, i64, String)> = connection.query_row(
                    r#"
                    SELECT payload_digest, worker_unit, invocation_id, receipt_digest,
                           acknowledged_at_ms, receipt_record_digest
                    FROM payload_release_receipts WHERE release_id = ?1
                    "#,
                    [&release_id],
                    |row| Ok((
                        row.get(0)?, row.get(1)?, row.get(2)?,
                        row.get(3)?, row.get(4)?, row.get(5)?,
                    )),
                ).optional()?;
                if let Some((payload, unit, invocation, receipt_digest, ack_at, record_digest)) = receipt {
                    if payload != barrier.payload_digest
                        || !Self::valid_token(&unit)
                        || !Self::valid_token(&invocation)
                        || !Self::valid_digest(&receipt_digest)
                        || ack_at < started_at_ms
                    {
                        return Err(AdmissionStoreError::InconsistentStorage);
                    }
                    let expected = Self::digest_domain(
                        b"nixward-payload-release-receipt-v1\\0",
                        format!("{release_id}:{payload}:{unit}:{invocation}:{receipt_digest}:{ack_at}").as_bytes(),
                    );
                    if expected != record_digest {
                        return Err(AdmissionStoreError::InconsistentStorage);
                    }
                }
            } else {
                let child_exists: bool = connection.query_row(
                    r#"
                    SELECT EXISTS(SELECT 1 FROM payload_release_uncertain WHERE release_id = ?1)
                        OR EXISTS(SELECT 1 FROM payload_release_receipts WHERE release_id = ?1)
                    "#,
                    [&release_id],
                    |row| row.get(0),
                )?;
                if child_exists {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
            }

            let mut decisions = connection.prepare(
                r#"
                SELECT policy_epoch, policy_record_digest, disposition,
                       decision_digest, created_at_ms
                FROM payload_release_policy_decisions
                WHERE release_id = ?1 ORDER BY policy_epoch
                "#,
            )?;
            let rows = decisions.query_map([&release_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            let stored_decisions = rows.collect::<Result<Vec<_>, _>>()?;
            drop(decisions);
            let mut stop_seen = false;
            for (epoch_raw, policy_digest, disposition, digest, created_at_raw) in stored_decisions {
                if epoch_raw <= 0 || created_at_raw < 0 {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
                let policy = Self::load_policy_epoch_by_number(connection, epoch_raw as u64)?
                    .ok_or(AdmissionStoreError::InconsistentStorage)?;
                if policy.record_digest != policy_digest {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
                let disposition_value = match disposition.as_str() {
                    "preserve_existing_barrier" => StoredReleaseDisposition::PreserveExistingBarrier,
                    "stop_or_recovery_required" => StoredReleaseDisposition::StopOrRecoveryRequired,
                    _ => return Err(AdmissionStoreError::InconsistentStorage),
                };
                if stop_seen && disposition_value == StoredReleaseDisposition::PreserveExistingBarrier {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
                if disposition_value == StoredReleaseDisposition::StopOrRecoveryRequired {
                    stop_seen = true;
                }
                let expected = Self::release_decision_digest(
                    &release_id,
                    epoch_raw as u64,
                    &policy_digest,
                    disposition_value,
                    created_at_raw as u64,
                );
                if expected != digest {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
            }
        }
        Ok(())
    }

    fn check_join_invariants(connection: &Connection) -> Result<(), AdmissionStoreError> {
        let inconsistent: i64 = connection.query_row(
            r#"
            SELECT COUNT(*)
            FROM admission_commits AS a
            LEFT JOIN authority_replays AS r ON r.commit_id = a.commit_id
            LEFT JOIN supervisor_permits AS p ON p.commit_id = a.commit_id
            LEFT JOIN transaction_attempts AS t ON t.commit_id = a.commit_id
            LEFT JOIN admission_events AS e ON e.commit_id = a.commit_id
            WHERE
                r.commit_id IS NULL
                OR p.commit_id IS NULL
                OR t.commit_id IS NULL
                OR e.commit_id IS NULL
                OR r.replay_key <> a.replay_key
                OR r.transaction_id <> a.transaction_id
                OR r.plan_digest <> a.plan_digest
                OR r.machine_binding_digest <> a.machine_binding_digest
                OR r.approval_proof_digest <> a.approval_proof_digest
                OR p.permit_digest <> a.permit_digest
                OR p.attempt_id <> a.attempt_id
                OR t.attempt_id <> a.attempt_id
                OR t.transaction_id <> a.transaction_id
                OR e.event_digest <> a.event_digest
                OR e.event_kind <> 'supervisor_admission_committed'
            "#,
            [],
            |row| row.get(0),
        )?;
        if inconsistent != 0 {
            return Err(AdmissionStoreError::InconsistentStorage);
        }

        let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
        let mut rows = foreign_keys.query([])?;
        if rows.next()?.is_some() {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Self::check_policy_epoch_pointer(connection)?;
        Self::verify_payload_release_integrity(connection)?;
        Ok(())
    }

    fn map_record(row: &Row<'_>) -> rusqlite::Result<AdmissionRecord> {
        let created_at_raw: i64 = row.get(12)?;
        let state_text: String = row.get(13)?;
        let resolution_digest: Option<String> = row.get(14)?;
        let resolved_at_raw: Option<i64> = row.get(15)?;
        let state = match state_text.as_str() {
            "unresolved" if resolution_digest.is_none() && resolved_at_raw.is_none() => {
                AdmissionState::Unresolved
            }
            "resolved" => {
                let digest = resolution_digest.ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        14,
                        "resolution_digest".into(),
                        rusqlite::types::Type::Null,
                    )
                })?;
                let at_ms = resolved_at_raw.ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        15,
                        "resolved_at_ms".into(),
                        rusqlite::types::Type::Null,
                    )
                })?;
                if at_ms < 0 {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(15, at_ms));
                }
                if !Self::valid_digest(&digest) {
                    return Err(rusqlite::Error::InvalidColumnType(
                        14,
                        "resolution_digest".into(),
                        rusqlite::types::Type::Text,
                    ));
                }
                if !Self::valid_digest(&digest) {
                    return Err(rusqlite::Error::InvalidColumnType(
                        14,
                        "resolution_digest".into(),
                        rusqlite::types::Type::Text,
                    ));
                }
                AdmissionState::Resolved {
                    resolution_digest: digest,
                    resolved_at_ms: at_ms as u64,
                }
            }
            _ => {
                return Err(rusqlite::Error::InvalidColumnType(
                    13,
                    "state".into(),
                    rusqlite::types::Type::Text,
                ));
            }
        };
        if created_at_raw < 0 {
            return Err(rusqlite::Error::IntegralValueOutOfRange(12, created_at_raw));
        }
        Ok(AdmissionRecord {
            commit_id: row.get(0)?,
            transaction_id: row.get(1)?,
            attempt_id: row.get(2)?,
            replay_key: row.get(3)?,
            plan_digest: row.get(4)?,
            machine_binding_digest: row.get(5)?,
            approval_proof_digest: row.get(6)?,
            approval_material: row.get(7)?,
            permit_digest: row.get(8)?,
            permit_wire: row.get(9)?,
            event_digest: row.get(10)?,
            event_payload: row.get(11)?,
            created_at_ms: created_at_raw as u64,
            state,
            authority_provenance_digest: row.get(16)?,
            authority_provenance: row.get(17)?,
        })
    }

    fn load_by_commit(
        connection: &Connection,
        commit_id: &str,
    ) -> Result<Option<AdmissionRecord>, AdmissionStoreError> {
        let record = connection
            .query_row(SELECT_ADMISSION_BY_COMMIT, [commit_id], Self::map_record)
            .optional()?;
        if let Some(record) = &record {
            Self::validate_record_content(record)?;
        }
        Ok(record)
    }

    fn load_by_replay(
        connection: &Connection,
        replay_key: &str,
    ) -> Result<Option<AdmissionRecord>, AdmissionStoreError> {
        let record = connection
            .query_row(SELECT_ADMISSION_BY_REPLAY, [replay_key], Self::map_record)
            .optional()?;
        if let Some(record) = &record {
            Self::validate_record_content(record)?;
        }
        Ok(record)
    }

    fn load_unresolved_by_transaction(
        connection: &Connection,
        transaction_id: &str,
    ) -> Result<Option<AdmissionRecord>, AdmissionStoreError> {
        let record = connection
            .query_row(SELECT_UNRESOLVED_BY_TRANSACTION, [transaction_id], Self::map_record)
            .optional()?;
        if let Some(record) = &record {
            Self::validate_record_content(record)?;
        }
        Ok(record)
    }

    fn matches_request(
        record: &AdmissionRecord,
        request: &AdmissionRequest,
        bindings: &DerivedBindings,
    ) -> bool {
        record.transaction_id == request.transaction_id
            && record.replay_key == request.replay_key
            && record.plan_digest == request.plan_digest
            && record.machine_binding_digest == request.machine_binding_digest
            && record.approval_proof_digest == bindings.approval_proof_digest
            && record.authority_provenance_digest == bindings.authority_provenance_digest
    }

    fn admit_inner<F>(
        &self,
        request: &AdmissionRequest,
        mut checkpoint: F,
    ) -> Result<AdmissionOutcome, AdmissionStoreError>
    where
        F: FnMut(WriteStage) -> Result<(), AdmissionStoreError>,
    {
        let bindings = Self::validate_request(request)?;
        let mut connection = self.connect()?;
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        Self::check_join_invariants(&transaction)?;

        let by_replay = Self::load_by_replay(&transaction, &request.replay_key)?;
        let by_transaction =
            Self::load_unresolved_by_transaction(&transaction, &request.transaction_id)?;

        if let (Some(replay), Some(unresolved)) = (&by_replay, &by_transaction) {
            if replay.commit_id != unresolved.commit_id {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }

        if let Some(existing) = by_replay {
            if !Self::matches_request(&existing, request, &bindings) {
                return Err(AdmissionStoreError::ReplayConflict);
            }
            if let Some(unresolved) = by_transaction {
                if unresolved.commit_id != existing.commit_id {
                    return Err(AdmissionStoreError::InconsistentStorage);
                }
            }
            transaction.commit()?;
            return Ok(AdmissionOutcome::Existing(existing));
        }

        if let Some(unresolved) = by_transaction {
            return Err(AdmissionStoreError::UnresolvedAttempt {
                attempt_id: unresolved.attempt_id,
            });
        }

        transaction.execute(
            r#"
            INSERT INTO admission_commits (
                commit_id, transaction_id, attempt_id, replay_key,
                plan_digest, machine_binding_digest, approval_proof_digest,
                approval_material, permit_digest, permit_wire, event_digest,
                created_at_ms, authority_provenance_digest, authority_provenance
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                bindings.commit_id,
                request.transaction_id,
                request.attempt_id,
                request.replay_key,
                request.plan_digest,
                request.machine_binding_digest,
                bindings.approval_proof_digest,
                request.approval_material,
                bindings.permit_digest,
                request.permit_wire,
                bindings.event_digest,
                bindings.created_at_ms,
                bindings.authority_provenance_digest,
                request.authority_provenance,
            ],
        )?;
        checkpoint(WriteStage::CommitRow)?;

        transaction.execute(
            r#"
            INSERT INTO authority_replays (
                replay_key, commit_id, transaction_id, plan_digest,
                machine_binding_digest, approval_proof_digest
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                request.replay_key,
                bindings.commit_id,
                request.transaction_id,
                request.plan_digest,
                request.machine_binding_digest,
                bindings.approval_proof_digest,
            ],
        )?;
        checkpoint(WriteStage::ReplayRow)?;

        transaction.execute(
            "INSERT INTO supervisor_permits (permit_digest, commit_id, attempt_id) VALUES (?1, ?2, ?3)",
            params![bindings.permit_digest, bindings.commit_id, request.attempt_id],
        )?;
        checkpoint(WriteStage::PermitRow)?;

        transaction.execute(
            r#"
            INSERT INTO transaction_attempts (
                attempt_id, transaction_id, commit_id, state,
                resolution_digest, resolved_at_ms
            ) VALUES (?1, ?2, ?3, 'unresolved', NULL, NULL)
            "#,
            params![request.attempt_id, request.transaction_id, bindings.commit_id],
        )?;
        checkpoint(WriteStage::AttemptRow)?;

        transaction.execute(
            r#"
            INSERT INTO admission_events (commit_id, event_kind, event_digest, event_payload)
            VALUES (?1, 'supervisor_admission_committed', ?2, ?3)
            "#,
            params![bindings.commit_id, bindings.event_digest, request.event_payload],
        )?;
        checkpoint(WriteStage::EventRow)?;
        checkpoint(WriteStage::BeforeCommit)?;

        let commit_id = bindings.commit_id.clone();
        if let Err(error) = transaction.commit() {
            // COMMIT errors can be ambiguous at the storage boundary. Do not
            // hand out the permit or retry with a new attempt. The caller must
            // reopen and reconcile using the same replay key and intent.
            return Err(AdmissionStoreError::ReadBackUncertain {
                commit_id,
                detail: format!("SQLite COMMIT returned an error: {error}"),
            });
        }
        checkpoint(WriteStage::AfterCommit)?;

        let record = Self::load_by_commit(&connection, &commit_id).map_err(|error| {
            AdmissionStoreError::ReadBackUncertain {
                commit_id: commit_id.clone(),
                detail: error.to_string(),
            }
        })?;
        let Some(record) = record else {
            return Err(AdmissionStoreError::ReadBackUncertain {
                commit_id,
                detail: "committed admission was not visible on read-back".into(),
            });
        };
        if record.commit_id != commit_id
            || record.transaction_id != request.transaction_id
            || record.attempt_id != request.attempt_id
            || record.replay_key != request.replay_key
            || record.plan_digest != request.plan_digest
            || record.machine_binding_digest != request.machine_binding_digest
            || record.approval_proof_digest != bindings.approval_proof_digest
            || record.authority_provenance_digest != bindings.authority_provenance_digest
            || record.authority_provenance != request.authority_provenance
            || record.permit_digest != bindings.permit_digest
            || record.event_digest != bindings.event_digest
            || record.approval_material != request.approval_material
            || record.permit_wire != request.permit_wire
            || record.event_payload != request.event_payload
        {
            return Err(AdmissionStoreError::ReadBackUncertain {
                commit_id,
                detail: "committed admission identity or payload differs from request".into(),
            });
        }

        Ok(AdmissionOutcome::Created(record))
    }

    /// Atomically create or recover one admission.
    ///
    /// A matching replay key returns the original record, including its original
    /// attempt and permit bytes. The caller must not use newly prepared bytes
    /// from a retry. A committed result is returned only after a read-back join
    /// verifies the four durable records.
    pub(crate) fn admit(
        &self,
        request: &AdmissionRequest,
    ) -> Result<AdmissionOutcome, AdmissionStoreError> {
        self.admit_inner(request, |_| Ok(()))
    }

    /// Record an independently verified terminal disposition for an attempt.
    ///
    /// The caller is responsible for proving the process receipt and fresh
    /// target post-state before invoking this method. This store only persists
    /// the one-way resolution and its evidence digest.
    pub(crate) fn record_resolution(
        &self,
        commit_id: &str,
        resolution_digest: &str,
        resolved_at_ms: u64,
    ) -> Result<(), AdmissionStoreError> {
        if !Self::valid_digest(commit_id) || !Self::valid_digest(resolution_digest) {
            return Err(AdmissionStoreError::InvalidInput("commit or resolution digest"));
        }
        let resolved_at_ms = i64::try_from(resolved_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("resolution timestamp"))?;
        let mut connection = self.connect()?;
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::check_join_invariants(&transaction)?;
        let Some(existing) = Self::load_by_commit(&transaction, commit_id)? else {
            return Err(AdmissionStoreError::NotFound);
        };
        let unreceipted_release: bool = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM payload_release_barriers AS b
                LEFT JOIN payload_release_receipts AS r ON r.release_id = b.release_id
                WHERE b.commit_id = ?1 AND r.release_id IS NULL
            )
            "#,
            [commit_id],
            |row| row.get(0),
        )?;
        if unreceipted_release {
            return Err(AdmissionStoreError::ReleaseBarrierInFlight);
        }
        match existing.state {
            AdmissionState::Resolved {
                resolution_digest: existing_digest,
                ..
            } => {
                if existing_digest != resolution_digest {
                    return Err(AdmissionStoreError::ResolutionConflict);
                }
                transaction.commit()?;
                return Ok(());
            }
            AdmissionState::Unresolved => {}
        }
        let changed = transaction.execute(
            r#"
            UPDATE transaction_attempts
            SET state = 'resolved', resolution_digest = ?2, resolved_at_ms = ?3
            WHERE commit_id = ?1 AND state = 'unresolved'
            "#,
            params![commit_id, resolution_digest, resolved_at_ms],
        )?;
        if changed != 1 {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Verify SQLite page consistency, foreign keys, and all four record joins.
    /// This is not a proof of power-loss behavior on a particular storage stack.
    pub(crate) fn verify_integrity(&self) -> Result<(), AdmissionStoreError> {
        let connection = self.connect()?;
        let quick_check: String =
            connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if quick_check != "ok" {
            return Err(AdmissionStoreError::InconsistentStorage);
        }
        Self::check_join_invariants(&connection)?;

        let mut statement = connection.prepare(
            "SELECT commit_id FROM admission_commits ORDER BY commit_id"
        )?;
        let commit_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for commit_id in commit_ids {
            if Self::load_by_commit(&connection, &commit_id)?.is_none() {
                return Err(AdmissionStoreError::InconsistentStorage);
            }
        }
        Self::verify_policy_epoch_history(&connection)?;
        Ok(())
    }

    #[cfg(test)]
    fn admit_with_failpoint(
        &self,
        request: &AdmissionRequest,
        fail_at: WriteStage,
    ) -> Result<AdmissionOutcome, AdmissionStoreError> {
        self.admit_inner(request, |stage| {
            if stage == fail_at {
                Err(AdmissionStoreError::InjectedFailure(stage.name()))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Debug)]
struct DerivedBindings {
    approval_proof_digest: String,
    authority_provenance_digest: String,
    permit_digest: String,
    event_digest: String,
    commit_id: String,
    created_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn request(
        transaction_id: &str,
        attempt_id: &str,
        replay_byte: u8,
        plan_byte: u8,
        machine_byte: u8,
    ) -> AdmissionRequest {
        AdmissionRequest {
            transaction_id: transaction_id.into(),
            attempt_id: attempt_id.into(),
            replay_key: (0..32).map(|_| format!("{replay_byte:02x}")).collect(),
            plan_digest: (0..32).map(|_| format!("{plan_byte:02x}")).collect(),
            machine_binding_digest: (0..32).map(|_| format!("{machine_byte:02x}")).collect(),
            approval_material: format!("signed-approval:{transaction_id}:{replay_byte}").into_bytes(),
            authority_provenance: format!("authority-provenance-v1:{transaction_id}:{replay_byte}").into_bytes(),
            permit_wire: format!("permit:{attempt_id}").into_bytes(),
            event_payload: format!(
                "{{\"kind\":\"supervisor_admission_committed\",\"transaction\":\"{transaction_id}\",\"attempt\":\"{attempt_id}\"}}"
            )
            .into_bytes(),
            created_at_ms: 1_800_000_000_000,
        }
    }

    fn store_in(temp: &tempfile::TempDir) -> SupervisorAdmissionStore {
        SupervisorAdmissionStore::new(temp.path().join("supervisor/admission.sqlite3"))
    }


    fn release_ready_fixture(
        temp: &tempfile::TempDir,
        revoked: Vec<String>,
    ) -> (
        SupervisorAdmissionStore,
        AdmissionRecord,
        AuthorityPolicyEpochRecord,
        PayloadReleaseBarrierRequest,
    ) {
        let store = store_in(temp);
        let policy_request = policy_request(1, revoked);
        let policy = store
            .initialize_authority_policy_epoch(&policy_request)
            .unwrap()
            .record()
            .clone();

        let mut admission_request = request(
            "tx-payload-release",
            "attempt-payload-release",
            0x81,
            0x82,
            0x83,
        );
        admission_request.authority_provenance = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "nixward-authority-provenance-v1",
            "policy_id": policy.policy_id,
            "policy_digest": policy.policy_digest,
            "policy_epoch": policy.epoch,
            "issuer": "owner-root",
            "signer_key_id": "owner-1",
            "action": "change",
            "audience": "nixward-change-v1",
            "subject_blake3": admission_request.plan_digest,
            "holon_id": "33".repeat(32),
            "challenge_blake3": "44".repeat(32),
            "replay_key": admission_request.replay_key,
            "signature_evidence_blake3": "55".repeat(32),
            "signed_proof_blake3": "66".repeat(32),
            "signed_proof_json": [1, 2, 3, 4],
            "issued_at_ms": 1000,
            "expires_at_ms": 5000,
            "verified_at_ms": 1100
        })).unwrap();

        let admission = store
            .admit(&admission_request)
            .unwrap()
            .record()
            .clone();
        let barrier_request = PayloadReleaseBarrierRequest {
            commit_id: admission.commit_id.clone(),
            expected_policy_epoch: policy.epoch,
            expected_policy_record_digest: policy.record_digest.clone(),
            signer_key_id: "owner-1".into(),
            expected_authority_subject_digest: admission.plan_digest.clone(),
            expected_authority_audience: "nixward-change-v1".into(),
            payload_digest: "99".repeat(32),
            expires_at_ms: 5000,
            now_ms: 1200,
        };
        (store, admission, policy, barrier_request)
    }



    #[test]
    fn creates_and_reloads_release_barrier_bound_to_admission_and_policy() {
        let temp = tempfile::tempdir().unwrap();
        let (store, admission, policy, request) = release_ready_fixture(&temp, vec![]);
        let result = store.create_payload_release_barrier(&request).unwrap();
        assert!(result.was_created());
        let record = result.record().clone();
        assert_eq!(record.commit_id, admission.commit_id);
        assert_eq!(record.attempt_id, admission.attempt_id);
        assert_eq!(record.policy_epoch, policy.epoch);
        assert_eq!(record.policy_record_digest, policy.record_digest);
        assert_eq!(record.authority_provenance_digest, admission.authority_provenance_digest);
        assert_eq!(record.authority_subject_digest, admission.plan_digest);
        assert_eq!(record.payload_digest, request.payload_digest);
        assert!(matches!(
            store.payload_release_state(&record.release_id).unwrap(),
            PayloadReleaseStoreState::BarrierCommitted(_)
        ));
        store.verify_integrity().unwrap();
    }

    #[test]
    fn exact_barrier_retry_after_lost_ack_returns_existing_historical_record() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let first = store.create_payload_release_barrier(&request).unwrap();
        let retry = store.create_payload_release_barrier(&request).unwrap();
        assert!(first.was_created());
        assert!(!retry.was_created());
        assert_eq!(first.record(), retry.record());
    }

    #[test]
    fn changed_payload_or_authority_binding_on_existing_barrier_is_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let first = store.create_payload_release_barrier(&request).unwrap();

        let mut changed = request.clone();
        changed.payload_digest = "aa".repeat(32);
        assert!(matches!(
            store.create_payload_release_barrier(&changed),
            Err(AdmissionStoreError::ReleaseBarrierConflict)
        ));

        let mut changed_subject = request;
        changed_subject.expected_authority_subject_digest = "bb".repeat(32);
        assert!(matches!(
            store.create_payload_release_barrier(&changed_subject),
            Err(AdmissionStoreError::ReleaseBarrierConflict)
        ));
        assert_eq!(
            store.payload_release_state(&first.record().release_id).unwrap(),
            PayloadReleaseStoreState::BarrierCommitted(first.record().clone())
        );
    }

    #[test]
    fn stale_policy_epoch_or_record_digest_cannot_create_new_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, policy, request) = release_ready_fixture(&temp, vec![]);
        store
            .advance_authority_policy_epoch(
                1,
                &policy.record_digest,
                &policy_request(2, vec![]),
            )
            .unwrap();
        assert!(matches!(
            store.create_payload_release_barrier(&request),
            Err(AdmissionStoreError::ReleaseBarrierStalePolicy)
        ));
    }

    #[test]
    fn emergency_revoked_signer_cannot_create_release_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) =
            release_ready_fixture(&temp, vec!["owner-1".into()]);
        assert!(matches!(
            store.create_payload_release_barrier(&request),
            Err(AdmissionStoreError::ReleaseBarrierUnauthorized)
        ));
    }

    #[test]
    fn expired_authority_cannot_create_release_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, mut request) = release_ready_fixture(&temp, vec![]);
        request.now_ms = request.expires_at_ms + 1;
        assert!(matches!(
            store.create_payload_release_barrier(&request),
            Err(AdmissionStoreError::ReleaseBarrierExpired)
        ));
    }

    #[test]
    fn unbound_authority_subject_cannot_create_release_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, mut request) = release_ready_fixture(&temp, vec![]);
        request.expected_authority_subject_digest = "cc".repeat(32);
        assert!(matches!(
            store.create_payload_release_barrier(&request),
            Err(AdmissionStoreError::ReleaseBarrierUnauthorized)
        ));
    }

    #[test]
    fn release_attempt_is_at_most_once_across_store_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        store.begin_payload_release_attempt(&release_id, 1300).unwrap();

        let reopened = SupervisorAdmissionStore::new(store.path().to_path_buf());
        assert!(matches!(
            reopened.begin_payload_release_attempt(&release_id, 1400),
            Err(AdmissionStoreError::ReleaseAttemptAlreadyStarted)
        ));
        assert!(matches!(
            reopened.payload_release_state(&release_id).unwrap(),
            PayloadReleaseStoreState::Attempted {
                started_at_ms: 1300,
                uncertain_at_ms: None,
                ..
            }
        ));
        reopened.verify_integrity().unwrap();
    }

    #[test]
    fn uncertain_attempt_never_resends_and_late_exact_receipt_reconciles() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        store.begin_payload_release_attempt(&release_id, 1300).unwrap();
        store.mark_payload_release_uncertain(&release_id, 1600).unwrap();

        let reopened = SupervisorAdmissionStore::new(store.path().to_path_buf());
        assert!(matches!(
            reopened.begin_payload_release_attempt(&release_id, 1700),
            Err(AdmissionStoreError::ReleaseAttemptAlreadyStarted)
        ));
        assert!(matches!(
            reopened.mark_payload_release_uncertain(&release_id, 1700),
            Err(AdmissionStoreError::ReleaseAttemptAlreadyUncertain)
        ));

        // The worker receipt was durably produced before the supervisor's
        // timeout observation, so its timestamp may be earlier than 1600.
        reopened.acknowledge_payload_release(
            &release_id,
            &request.payload_digest,
            "nixward-payload-release.service",
            "invocation-1",
            &"dd".repeat(32),
            1500,
        ).unwrap();
        assert!(matches!(
            reopened.payload_release_state(&release_id).unwrap(),
            PayloadReleaseStoreState::Acknowledged {
                started_at_ms: 1300,
                acknowledged_at_ms: 1500,
                ..
            }
        ));
        assert!(matches!(
            reopened.begin_payload_release_attempt(&release_id, 1800),
            Err(AdmissionStoreError::ReleaseAttemptAlreadyStarted)
        ));
        reopened.verify_integrity().unwrap();
    }

    #[test]
    fn foreign_payload_receipt_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        store.begin_payload_release_attempt(&release_id, 1300).unwrap();
        assert!(matches!(
            store.acknowledge_payload_release(
                &release_id,
                &"ee".repeat(32),
                "nixward-payload-release.service",
                "invocation-1",
                &"dd".repeat(32),
                1500,
            ),
            Err(AdmissionStoreError::ReleaseReceiptConflict)
        ));
    }

    #[test]
    fn policy_update_with_outstanding_barrier_requires_explicit_disposition() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, policy, request) = release_ready_fixture(&temp, vec![]);
        store.create_payload_release_barrier(&request).unwrap();
        assert!(matches!(
            store.advance_authority_policy_epoch(
                1,
                &policy.record_digest,
                &policy_request(2, vec![]),
            ),
            Err(AdmissionStoreError::ReleasePolicyDecisionRequired)
        ));
        assert_eq!(
            store.current_authority_policy_epoch().unwrap().unwrap(),
            policy
        );
    }

    #[test]
    fn preserve_decision_and_policy_advance_commit_atomically_with_existing_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let decision = StoredReleasePolicyDecision {
            release_id: barrier.record().release_id.clone(),
            disposition: StoredReleaseDisposition::PreserveExistingBarrier,
        };
        store.advance_authority_policy_epoch_with_release_decisions(
            1,
            &policy.record_digest,
            &policy_request(2, vec!["owner-2".into()]),
            &[decision],
        ).unwrap();

        // The exact old barrier remains retrievable, but no new policy epoch
        // can be silently substituted into its immutable identity.
        let retry = store.create_payload_release_barrier(&request).unwrap();
        assert!(!retry.was_created());
        assert_eq!(retry.record(), barrier.record());
        store.begin_payload_release_attempt(&barrier.record().release_id, 1300).unwrap();
    }

    #[test]
    fn stop_recovery_decision_blocks_release_and_cannot_be_downgraded() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();

        store.advance_authority_policy_epoch_with_release_decisions(
            1,
            &policy.record_digest,
            &policy_request(2, vec!["owner-1".into()]),
            &[StoredReleasePolicyDecision {
                release_id: release_id.clone(),
                disposition: StoredReleaseDisposition::StopOrRecoveryRequired,
            }],
        ).unwrap();

        assert!(matches!(
            store.begin_payload_release_attempt(&release_id, 1300),
            Err(AdmissionStoreError::ReleaseAttemptBlocked)
        ));
        let current = store.current_authority_policy_epoch().unwrap().unwrap();
        assert!(matches!(
            store.advance_authority_policy_epoch_with_release_decisions(
                current.epoch,
                &current.record_digest,
                &policy_request(3, vec![]),
                &[StoredReleasePolicyDecision {
                    release_id,
                    disposition: StoredReleaseDisposition::PreserveExistingBarrier,
                }],
            ),
            Err(AdmissionStoreError::ReleasePolicyDecisionDowngrade)
        ));
        assert_eq!(store.current_authority_policy_epoch().unwrap().unwrap(), current);
    }

    #[test]
    fn policy_advance_wins_before_barrier_and_stale_barrier_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, policy, request) = release_ready_fixture(&temp, vec![]);
        store.advance_authority_policy_epoch(
            1,
            &policy.record_digest,
            &policy_request(2, vec![]),
        ).unwrap();
        assert!(matches!(
            store.create_payload_release_barrier(&request),
            Err(AdmissionStoreError::ReleaseBarrierStalePolicy)
        ));
    }

    #[test]
    fn transaction_resolution_is_blocked_until_exact_release_receipt_exists() {
        let temp = tempfile::tempdir().unwrap();
        let (store, admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        assert!(matches!(
            store.record_resolution(&admission.commit_id, &"ff".repeat(32), 1500),
            Err(AdmissionStoreError::ReleaseBarrierInFlight)
        ));
        store.begin_payload_release_attempt(&barrier.record().release_id, 1300).unwrap();
        assert!(matches!(
            store.record_resolution(&admission.commit_id, &"ff".repeat(32), 1500),
            Err(AdmissionStoreError::ReleaseBarrierInFlight)
        ));
        store.acknowledge_payload_release(
            &barrier.record().release_id,
            &request.payload_digest,
            "nixward-payload-release.service",
            "invocation-1",
            &"dd".repeat(32),
            1400,
        ).unwrap();
        assert!(store.record_resolution(
            &admission.commit_id,
            &"ff".repeat(32),
            1500
        ).is_ok());
    }

    #[test]
    fn resolved_admission_cannot_start_a_reserved_release() {
        let temp = tempfile::tempdir().unwrap();
        let (store, admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        store.record_resolution(
            &admission.commit_id,
            &"ff".repeat(32),
            1250,
        ).unwrap();
        assert!(matches!(
            store.begin_payload_release_attempt(&barrier.record().release_id, 1300),
            Err(AdmissionStoreError::ReleaseAttemptBlocked)
        ));
    }

    #[test]
    fn exact_receipt_retry_requires_the_same_receipt_digest() {
        let temp = tempfile::tempdir().unwrap();
        let (store, _admission, _policy, request) = release_ready_fixture(&temp, vec![]);
        let barrier = store.create_payload_release_barrier(&request).unwrap();
        let release_id = barrier.record().release_id.clone();
        store.begin_payload_release_attempt(&release_id, 1300).unwrap();
        store.acknowledge_payload_release(
            &release_id, &request.payload_digest, "nixward-payload-release.service",
            "invocation-1", &"dd".repeat(32), 1500,
        ).unwrap();
        assert!(matches!(
            store.acknowledge_payload_release(
                &release_id, &request.payload_digest, "nixward-payload-release.service",
                "invocation-1", &"ee".repeat(32), 1500,
            ),
            Err(AdmissionStoreError::ReleaseReceiptConflict)
        ));
    }

    #[test]
    fn refuses_schema_v1_database_without_authority_provenance_migration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("supervisor/admission.sqlite3");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let legacy = Connection::open(&path).unwrap();
        legacy.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
        legacy.pragma_update(None, "user_version", 1_i64).unwrap();
        drop(legacy);

        let store = SupervisorAdmissionStore::new(path);
        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::UnsupportedSchema(1))
        ));
    }


    fn policy_request(epoch: u64, key_ids: Vec<String>) -> AuthorityPolicyEpochRequest {
        let policy_json = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "symthaea-authority-trust-policy-v1",
            "policy_id": "owner-root:policy-1",
            "policy_epoch": epoch,
            "keys": [{
                "key_id": "owner-1",
                "issuer": "owner-root",
                "public_key_hex": "11".repeat(32),
                "allowed_actions": ["change"],
                "revoked": false,
                "claims": { "holon_id": "33".repeat(32) }
            }],
            "max_ttl_ms": 900000,
            "allowed_audiences": ["nixward-change-v1"]
        })).unwrap();
        AuthorityPolicyEpochRequest {
            policy_id: "owner-root:policy-1".into(),
            epoch,
            policy_json,
            emergency_revoked_key_ids: key_ids,
            update_provenance: format!("verified-policy-update-proof-epoch-{epoch}").into_bytes(),
            created_at_ms: 1_800_000_000_000 + epoch,
        }
    }

    #[test]
    fn schema_v3_database_is_refused_without_release_barrier_v4_migration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("supervisor/admission.sqlite3");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = Connection::open(&path).unwrap();
        legacy.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
        legacy.pragma_update(None, "user_version", 3_i64).unwrap();
        drop(legacy);
        let store = SupervisorAdmissionStore::new(path);
        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::UnsupportedSchema(3))
        ));
    }

    #[test]
    fn schema_v2_database_is_refused_without_policy_epoch_archive_migration() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("supervisor/admission.sqlite3");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = Connection::open(&path).unwrap();
        legacy.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
        legacy.pragma_update(None, "user_version", 2_i64).unwrap();
        drop(legacy);
        let store = SupervisorAdmissionStore::new(path);
        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::UnsupportedSchema(2))
        ));
    }

    #[test]
    fn initializes_epoch_one_and_loads_exact_policy_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let request = policy_request(1, vec![]);
        let outcome = store.initialize_authority_policy_epoch(&request).unwrap();
        assert!(matches!(&outcome, AuthorityPolicyEpochOutcome::Created(_)));
        let created = outcome.record();
        assert_eq!(created.epoch, 1);
        assert_eq!(created.previous_record_digest, GENESIS_POLICY_RECORD_DIGEST);
        assert_eq!(created.emergency_revoked_key_ids, Vec::<String>::new());

        let current = store.current_authority_policy_epoch().unwrap().unwrap();
        assert_eq!(&current, created);
        let historical = store
            .historical_authority_policy_epoch(1, &created.record_digest)
            .unwrap()
            .unwrap();
        assert_eq!(&historical, created);
        assert!(matches!(
            store.historical_authority_policy_epoch(1, &"f".repeat(64)),
            Err(AdmissionStoreError::PolicyEpochConflict)
        ));
    }

    #[test]
    fn repeated_genesis_initialization_is_idempotent_but_replacement_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let request = policy_request(1, vec![]);
        let first = store.initialize_authority_policy_epoch(&request).unwrap();
        let second = store.initialize_authority_policy_epoch(&request).unwrap();
        assert!(matches!(first, AuthorityPolicyEpochOutcome::Created(_)));
        assert!(matches!(second, AuthorityPolicyEpochOutcome::Existing(_)));

        let mut replacement = policy_request(1, vec!["owner-1".into()]);
        replacement.update_provenance.push(b'!');
        assert!(matches!(
            store.initialize_authority_policy_epoch(&replacement),
            Err(AdmissionStoreError::PolicyEpochConflict)
        ));
    }

    #[test]
    fn policy_epoch_advances_once_and_preserves_historical_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap();
        let first_record = first.record().clone();
        let second = store
            .advance_authority_policy_epoch(1, &first_record.record_digest, &policy_request(2, vec![]))
            .unwrap();
        let second_record = second.record().clone();
        assert!(matches!(second, AuthorityPolicyEpochOutcome::Created(_)));
        assert_eq!(second_record.epoch, 2);
        assert_eq!(second_record.previous_record_digest, first_record.record_digest);
        assert_eq!(store.current_authority_policy_epoch().unwrap().unwrap(), second_record);
        assert_eq!(
            store.historical_authority_policy_epoch(1, &first_record.record_digest).unwrap().unwrap(),
            first_record
        );
        store.verify_integrity().unwrap();
    }

    #[test]
    fn stale_epoch_skipped_epoch_and_wrong_parent_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap();
        let first_record = first.record().clone();

        assert!(matches!(
            store.advance_authority_policy_epoch(1, &"a".repeat(64), &policy_request(2, vec![])),
            Err(AdmissionStoreError::PolicyEpochConflict)
        ));
        assert!(matches!(
            store.advance_authority_policy_epoch(1, &first_record.record_digest, &policy_request(3, vec![])),
            Err(AdmissionStoreError::PolicyEpochConflict)
        ));
        assert!(matches!(
            store.advance_authority_policy_epoch(0, &first_record.record_digest, &policy_request(1, vec![])),
            Err(AdmissionStoreError::PolicyEpochConflict)
        ));
        assert_eq!(store.current_authority_policy_epoch().unwrap().unwrap(), first_record);
    }

    #[test]
    fn policy_epoch_advance_is_idempotent_after_lost_ack() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap();
        let first_record = first.record().clone();
        let request = policy_request(2, vec!["owner-1".into()]);
        let created = store.advance_authority_policy_epoch(1, &first_record.record_digest, &request).unwrap();
        let retried = store.advance_authority_policy_epoch(1, &first_record.record_digest, &request).unwrap();
        assert!(matches!(&created, AuthorityPolicyEpochOutcome::Created(_)));
        assert!(matches!(&retried, AuthorityPolicyEpochOutcome::Existing(_)));
        assert_eq!(created.record(), retried.record());
    }

    #[test]
    fn emergency_revocation_is_versioned_with_the_policy_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap();
        let first_record = first.record().clone();
        let second = store
            .advance_authority_policy_epoch(1, &first_record.record_digest, &policy_request(2, vec!["owner-1".into()]))
            .unwrap();
        let record = second.record();
        assert_eq!(record.emergency_revoked_key_ids, vec!["owner-1".to_string()]);
        assert_ne!(record.emergency_revocation_digest, first_record.emergency_revocation_digest);
        assert_ne!(record.record_digest, first_record.record_digest);
    }

    #[test]
    fn policy_epoch_rejects_unsorted_duplicate_or_invalid_revocation_ids() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        assert!(matches!(
            store.initialize_authority_policy_epoch(&policy_request(
                1,
                vec!["owner-b".into(), "owner-a".into()]
            )),
            Err(AdmissionStoreError::InvalidInput(_))
        ));
        assert!(matches!(
            store.initialize_authority_policy_epoch(&policy_request(
                1,
                vec!["owner-a".into(), "owner-a".into()]
            )),
            Err(AdmissionStoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn policy_epoch_rejects_zero_or_policy_json_epoch_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        assert!(matches!(
            store.initialize_authority_policy_epoch(&policy_request(0, vec![])),
            Err(AdmissionStoreError::InvalidInput(_))
        ));
        let mut mismatched = policy_request(1, vec![]);
        mismatched.policy_json = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "symthaea-authority-trust-policy-v1",
            "policy_id": "owner-root:policy-1",
            "policy_epoch": 2,
            "keys": [],
            "max_ttl_ms": 900000,
            "allowed_audiences": []
        })).unwrap();
        assert!(matches!(
            store.initialize_authority_policy_epoch(&mismatched),
            Err(AdmissionStoreError::InvalidInput("authority policy identity/epoch binding"))
        ));
    }

    #[test]
    fn update_provenance_must_not_be_empty() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let mut request = policy_request(1, vec![]);
        request.update_provenance.clear();
        assert!(matches!(
            store.initialize_authority_policy_epoch(&request),
            Err(AdmissionStoreError::InvalidInput("authority policy epoch request"))
        ));
    }

    #[test]
    fn corrupt_policy_snapshot_is_detected_by_integrity_scan() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let record = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap().record().clone();
        let connection = store.connect().unwrap();
        connection.execute(
            "DROP TRIGGER authority_policy_epochs_immutable_update",
            [],
        ).unwrap();
        connection.execute(
            "UPDATE authority_policy_epochs SET policy_json = ?1 WHERE epoch = 1",
            [&b"corrupt policy json"[..]],
        ).unwrap();
        drop(connection);
        assert!(matches!(
            store.verify_integrity(),
            Err(AdmissionStoreError::InvalidInput(_))
                | Err(AdmissionStoreError::InvalidPolicyEpochRecord)
                | Err(AdmissionStoreError::InconsistentStorage)
        ));
        assert_ne!(record.record_digest, GENESIS_POLICY_RECORD_DIGEST);
    }

    #[test]
    fn current_policy_pointer_cannot_be_deleted_or_rolled_back() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.initialize_authority_policy_epoch(&policy_request(1, vec![])).unwrap();
        let record = first.record().clone();
        let connection = store.connect().unwrap();
        assert!(connection.execute(
            "UPDATE authority_policy_current SET epoch = 0 WHERE singleton = 1",
            [],
        ).is_err());
        assert!(connection.execute(
            "DELETE FROM authority_policy_current WHERE singleton = 1",
            [],
        ).is_err());
        drop(connection);
        assert_eq!(store.current_authority_policy_epoch().unwrap().unwrap(), record);
    }

    #[test]
    fn admission_rejects_missing_authority_provenance() {
        let mut req = request("tx-empty-authority", "attempt-empty-authority", 0x51, 0x52, 0x53);
        req.authority_provenance.clear();
        assert!(matches!(
            SupervisorAdmissionStore::validate_request(&req),
            Err(AdmissionStoreError::InvalidInput("authority provenance length"))
        ));
    }

    #[test]
    fn same_replay_with_changed_authority_provenance_is_a_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = request("tx-authority-replay", "attempt-authority-first", 0x61, 0x62, 0x63);
        store.admit(&first).unwrap();

        let mut changed = first.clone();
        changed.authority_provenance.push(b'!');
        changed.attempt_id = "attempt-authority-second".into();
        changed.permit_wire = b"new-permit".to_vec();
        assert!(matches!(store.admit(&changed), Err(AdmissionStoreError::ReplayConflict)));
    }

    #[test]
    fn integrity_scan_detects_authority_provenance_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let req = request("tx-authority-tamper", "attempt-authority-tamper", 0x71, 0x72, 0x73);
        let record = store.admit(&req).unwrap().record().clone();

        let connection = store.connect().unwrap();
        connection.execute("DROP TRIGGER admission_commits_immutable_update", []).unwrap();
        connection.execute(
            "UPDATE admission_commits SET authority_provenance = ?1 WHERE commit_id = ?2",
            params![b"tampered-authority-provenance".as_slice(), record.commit_id],
        ).unwrap();
        drop(connection);
        assert!(matches!(store.verify_integrity(), Err(AdmissionStoreError::InconsistentStorage)));
    }

    #[test]
    fn creates_four_bound_records_and_reads_back_exact_commit() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let request = request("tx-a", "attempt-a1", 0x11, 0x22, 0x33);

        let outcome = store.admit(&request).unwrap();
        assert!(outcome.was_created());
        let record = outcome.record();
        assert_eq!(record.transaction_id, "tx-a");
        assert_eq!(record.attempt_id, "attempt-a1");
        assert_eq!(record.replay_key, request.replay_key);
        assert_eq!(
            record.approval_proof_digest,
            SupervisorAdmissionStore::digest(&request.approval_material)
        );
        assert_eq!(
            record.permit_digest,
            SupervisorAdmissionStore::digest(&request.permit_wire)
        );
        assert_eq!(
            record.event_digest,
            SupervisorAdmissionStore::digest(&request.event_payload)
        );
        assert_eq!(record.approval_material, request.approval_material);
        assert_eq!(record.authority_provenance, request.authority_provenance);
        assert_eq!(
            record.authority_provenance_digest,
            SupervisorAdmissionStore::digest(&request.authority_provenance)
        );
        assert_eq!(record.permit_wire, request.permit_wire);
        assert_eq!(record.event_payload, request.event_payload);
        assert_eq!(record.state, AdmissionState::Unresolved);
        store.verify_integrity().unwrap();
    }

    #[test]
    fn same_replay_after_lost_ack_returns_the_original_attempt_and_permit() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let original = request("tx-a", "attempt-original", 0x11, 0x22, 0x33);
        let first = store.admit(&original).unwrap();
        let retry = request("tx-a", "attempt-newly-proposed", 0x11, 0x22, 0x33);
        let second = store.admit(&retry).unwrap();

        assert!(first.was_created());
        assert!(!second.was_created());
        assert_eq!(first.record().commit_id, second.record().commit_id);
        assert_eq!(second.record().attempt_id, "attempt-original");
        assert_eq!(second.record().permit_wire, original.permit_wire);
        assert_eq!(second.record().approval_material, original.approval_material);
    }

    #[test]
    fn retry_with_changed_plan_or_machine_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let changed_plan = request("tx-a", "attempt-a2", 0x11, 0x44, 0x33);
        assert!(matches!(store.admit(&changed_plan), Err(AdmissionStoreError::ReplayConflict)));

        let changed_machine = request("tx-a", "attempt-a3", 0x11, 0x22, 0x55);
        assert!(matches!(store.admit(&changed_machine), Err(AdmissionStoreError::ReplayConflict)));
    }

    #[test]
    fn new_replay_cannot_overlap_an_unresolved_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        assert!(matches!(
            store.admit(&request("tx-a", "attempt-a2", 0x44, 0x22, 0x33)),
            Err(AdmissionStoreError::UnresolvedAttempt { .. })
        ));
    }

    #[test]
    fn a_resolved_attempt_allows_a_new_replay_but_not_reopening_the_old_one() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let first = store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();
        let digest = "a".repeat(64);
        store.record_resolution(&first.record().commit_id, &digest, 1_800_000_000_100).unwrap();

        let second = store.admit(&request("tx-a", "attempt-a2", 0x44, 0x22, 0x33)).unwrap();
        assert!(second.was_created());
        assert_eq!(second.record().state, AdmissionState::Unresolved);

        let connection = store.connect().unwrap();
        let state: String = connection.query_row(
            "SELECT state FROM transaction_attempts WHERE attempt_id = 'attempt-a1'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(state, "resolved");

        assert!(matches!(
            store.record_resolution(&first.record().commit_id, &"b".repeat(64), 1_800_000_000_200),
            Err(AdmissionStoreError::ResolutionConflict)
        ));
        store.verify_integrity().unwrap();
    }

    #[test]
    fn every_precommit_failure_rolls_back_all_four_records() {
        let stages = [
            WriteStage::CommitRow,
            WriteStage::ReplayRow,
            WriteStage::PermitRow,
            WriteStage::AttemptRow,
            WriteStage::EventRow,
            WriteStage::BeforeCommit,
        ];

        for (index, stage) in stages.into_iter().enumerate() {
            let temp = tempfile::tempdir().unwrap();
            let store = store_in(&temp);
            let request = request("tx-a", &format!("attempt-{index}"), 0x11, 0x22, 0x33);
            assert!(matches!(
                store.admit_with_failpoint(&request, stage),
                Err(AdmissionStoreError::InjectedFailure(_))
            ));

            let reopened = store_in(&temp);
            reopened.verify_integrity().unwrap();
            let retry = reopened.admit(&request).unwrap();
            assert!(retry.was_created(), "pre-commit failure must leave no admission");
        }
    }

    #[test]
    fn lost_ack_after_commit_recovers_the_same_admission() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let request = request("tx-a", "attempt-a1", 0x11, 0x22, 0x33);
        assert!(matches!(
            store.admit_with_failpoint(&request, WriteStage::AfterCommit),
            Err(AdmissionStoreError::InjectedFailure("after_commit"))
        ));

        let reopened = store_in(&temp);
        reopened.verify_integrity().unwrap();
        let recovered = reopened.admit(&request).unwrap();
        assert!(!recovered.was_created());
        assert_eq!(recovered.record().attempt_id, "attempt-a1");
    }

    #[test]
    fn concurrent_same_replay_has_one_commit_and_one_existing_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(store_in(&temp));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let request = request("tx-a", &format!("attempt-race-{index}"), 0x11, 0x22, 0x33);
                barrier.wait();
                store.admit(&request).unwrap()
            }));
        }

        let outcomes = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.was_created()).count(), 1);
        assert_eq!(outcomes[0].record().commit_id, outcomes[1].record().commit_id);
        assert_eq!(outcomes[0].record().attempt_id, outcomes[1].record().attempt_id);
        store.verify_integrity().unwrap();
    }

    #[test]
    fn concurrent_different_replays_for_one_transaction_have_one_winner() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(store_in(&temp));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let request = request(
                    "tx-a",
                    &format!("attempt-transaction-race-{index}"),
                    if index == 0 { 0x11 } else { 0x44 },
                    0x22,
                    0x33,
                );
                barrier.wait();
                store.admit(&request)
            }));
        }

        let outcomes = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        assert_eq!(
            outcomes.iter().filter(|outcome| matches!(outcome, Ok(value) if value.was_created())).count(),
            1
        );
        assert_eq!(
            outcomes.iter().filter(|outcome| matches!(outcome, Err(AdmissionStoreError::UnresolvedAttempt { .. }))).count(),
            1
        );
        store.verify_integrity().unwrap();
    }

    #[test]
    fn independent_transactions_can_be_admitted_concurrently() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(store_in(&temp));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let request = request(
                    &format!("tx-independent-{index}"),
                    &format!("attempt-independent-{index}"),
                    if index == 0 { 0x11 } else { 0x44 },
                    0x22,
                    0x33,
                );
                barrier.wait();
                store.admit(&request).unwrap()
            }));
        }

        let outcomes = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        assert!(outcomes.iter().all(AdmissionOutcome::was_created));
        assert_ne!(outcomes[0].record().commit_id, outcomes[1].record().commit_id);
        store.verify_integrity().unwrap();
    }

    #[test]
    fn refuses_to_adopt_an_unidentified_existing_sqlite_schema() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("supervisor/admission.sqlite3");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(
            "CREATE TABLE unrelated_state (id INTEGER PRIMARY KEY);",
        ).unwrap();
        drop(connection);

        let store = SupervisorAdmissionStore::new(path);
        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::WrongApplicationId)
        ));
    }

    #[test]
    fn rejects_missing_or_unexpected_schema_objects() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let connection = store.connect().unwrap();
        connection.execute_batch(
            "DROP TRIGGER admission_events_immutable_update;",
        ).unwrap();
        drop(connection);

        // Reopening recreates the required trigger from the pinned schema.
        // The store does not silently accept arbitrary extra schema objects.
        let reopened = store.connect().unwrap();
        reopened.execute_batch(
            "CREATE TABLE unexpected_extension (value TEXT);",
        ).unwrap();
        drop(reopened);

        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::InconsistentStorage)
        ));
    }

    #[test]
    fn wal_full_sync_foreign_keys_and_private_file_mode_are_enabled() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let connection = store.connect().unwrap();
        let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
        let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0)).unwrap();
        let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0)).unwrap();
        let trusted_schema: i64 = connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0)).unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);
        assert_eq!(trusted_schema, 0);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn detects_payload_tampering_even_when_joined_rows_still_match() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let record = store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let connection = store.connect().unwrap();
        connection.execute_batch(
            "DROP TRIGGER admission_events_immutable_update;",
        ).unwrap();
        connection.execute(
            "UPDATE admission_events SET event_payload = ?2 WHERE commit_id = ?1",
            params![record.record().commit_id, &b"tampered event"[..]],
        ).unwrap();

        assert!(matches!(
            store.admit(&request("tx-a", "attempt-a2", 0x44, 0x22, 0x33)),
            Err(AdmissionStoreError::InconsistentStorage)
        ));
        assert!(matches!(
            store.verify_integrity(),
            Err(AdmissionStoreError::InconsistentStorage)
        ));
    }

    #[test]
    fn detects_a_missing_child_record_instead_of_accepting_partial_admission() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let record = store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let connection = store.connect().unwrap();
        connection.execute_batch(
            "DROP TRIGGER authority_replays_immutable_delete;",
        ).unwrap();
        connection.execute(
            "DELETE FROM authority_replays WHERE replay_key = ?1",
            [&record.record().replay_key],
        ).unwrap();

        assert!(matches!(
            store.verify_integrity(),
            Err(AdmissionStoreError::InconsistentStorage)
        ));
        assert!(matches!(
            store.admit(&request("tx-b", "attempt-b1", 0x44, 0x55, 0x66)),
            Err(AdmissionStoreError::InconsistentStorage)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_dangling_symlink_database_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let parent = store.path().parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        let link = parent.join("admission.sqlite3");
        let missing_target = parent.join("missing-target.sqlite3");
        symlink(&missing_target, &link).unwrap();

        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::SymlinkPath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_database_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        let parent = store.path().parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        let target = parent.join("real.sqlite3");
        std::fs::write(&target, b"not a database").unwrap();
        let link = parent.join("admission.sqlite3");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            store.connect(),
            Err(AdmissionStoreError::SymlinkPath(_))
        ));
    }
}