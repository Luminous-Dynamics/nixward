// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Crash-durable local journal for verified OCI observer checkpoints.
//!
//! This module implements only the relying-party PREPARED and
//! RECONCILIATION_REQUIRED states. It deliberately has no public operation
//! that marks a checkpoint witness-confirmed: that operation must accept an
//! opaque proof produced by a separately implemented witness verifier.
//!
//! SQLite protects against ordinary process crashes when configured with WAL
//! and synchronous=FULL. It is not a remote anti-rollback anchor against a
//! privileged local attacker who can restore the database and WAL together.

use super::signed_checkpoint::{TrustedOciObserverKey, VerifiedOciObserverCheckpoint};
use super::witness_transparency::{
    empty_merkle_root_sha256, OciObserverWitnessRequest, TrustedOciWitnessKey,
    VerifiedOciWitnessQuorum,
};
use std::collections::BTreeSet;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const STORE_SCHEMA_VERSION: i64 = 2;
const MAX_WITNESS_REQUEST_BYTES: usize = 1024 * 1024;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"nixward:oci-observer-witness-request-digest:v1\0";
const IDEMPOTENCY_DOMAIN: &[u8] = b"nixward:oci-observer-witness-idempotency:v1\0";

const CHECKPOINT_HISTORY_V2_DDL: &str = "
CREATE TABLE checkpoint_history (
    observer_id TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    parent_digest TEXT,
    snapshot_digest TEXT NOT NULL,
    chain_head_digest TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
    expires_at_ms INTEGER NOT NULL,
    request_digest TEXT NOT NULL,
    request_bytes BLOB NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'reconciliation_required', 'quarantined', 'witness_quorum_confirmed')
    ),
    created_at_ms INTEGER NOT NULL,
    witness_quorum_digest TEXT,
    witness_quorum_required INTEGER,
    witness_receipt_count INTEGER,
    witness_confirmed_at_ms INTEGER,
    PRIMARY KEY (observer_id, checkpoint_digest),
    UNIQUE (observer_id, sequence),
    CHECK (
        state != 'witness_quorum_confirmed'
        OR (
            witness_quorum_digest IS NOT NULL
            AND witness_quorum_required IS NOT NULL
            AND witness_receipt_count IS NOT NULL
            AND witness_confirmed_at_ms IS NOT NULL
        )
    )
);";

const OBSERVER_STATE_DDL: &str = "
CREATE TABLE observer_state (
    observer_id TEXT PRIMARY KEY NOT NULL,
    machine_id TEXT NOT NULL,
    accepted_checkpoint_digest TEXT,
    accepted_boot_id TEXT,
    accepted_sequence INTEGER,
    pending_checkpoint_digest TEXT,
    pending_boot_id TEXT,
    pending_sequence INTEGER,
    pending_parent_digest TEXT,
    pending_idempotency_key TEXT,
    pending_request_digest TEXT,
    pending_request BLOB,
    pending_state TEXT,
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)),
    updated_at_ms INTEGER NOT NULL,
    CHECK (
        (pending_checkpoint_digest IS NULL
            AND pending_boot_id IS NULL
            AND pending_sequence IS NULL
            AND pending_parent_digest IS NULL
            AND pending_idempotency_key IS NULL
            AND pending_request_digest IS NULL
            AND pending_request IS NULL
            AND pending_state IS NULL)
        OR
        (pending_checkpoint_digest IS NOT NULL
            AND pending_boot_id IS NOT NULL
            AND pending_sequence IS NOT NULL
            AND pending_idempotency_key IS NOT NULL
            AND pending_request_digest IS NOT NULL
            AND pending_request IS NOT NULL
            AND pending_state IS NOT NULL)
    )
);";
const WITNESS_TABLES_DDL: &str = "
CREATE TABLE witness_checkpoint_receipts (
    observer_id TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    trust_domain_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    root_hash_sha256 TEXT NOT NULL,
    receipt_digest_blake3 TEXT NOT NULL,
    receipt_bytes BLOB NOT NULL,
    PRIMARY KEY (observer_id, checkpoint_digest, witness_id),
    FOREIGN KEY (observer_id, checkpoint_digest)
        REFERENCES checkpoint_history(observer_id, checkpoint_digest)
        ON DELETE RESTRICT
);

CREATE TABLE observer_witness_state (
    observer_id TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    trust_domain_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    root_hash_sha256 TEXT NOT NULL,
    receipt_digest_blake3 TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (observer_id, witness_id)
);";

#[derive(Debug, Error)]
pub enum OciObserverCheckpointStoreError {
    #[error("checkpoint store path is invalid or unsafe")]
    UnsafePath,
    #[error("checkpoint store directory must be owner-only")]
    InsecureDirectory,
    #[error("checkpoint store file is a symlink or is not a regular file")]
    UnsafeDatabaseFile,
    #[error("checkpoint store database permissions are broader than owner-only")]
    InsecureDatabasePermissions,
    #[error("checkpoint store schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("checkpoint store SQLite configuration is not WAL/FULL")]
    UnsafeSqliteConfiguration,
    #[error("checkpoint store digest encoding is invalid")]
    InvalidDigest,
    #[error("checkpoint request is empty or exceeds the size limit")]
    InvalidRequestSize,
    #[error("witness request is not the canonical request for this verified checkpoint")]
    WitnessRequestMismatch,
    #[error("checkpoint expiry is not in the future")]
    CheckpointExpired,
    #[error("checkpoint integer exceeds SQLite's signed integer range")]
    IntegerOutOfRange,
    #[error("observer identity or machine identity changed")]
    ObserverIdentityMismatch,
    #[error("checkpoint does not extend the durable accepted parent")]
    ParentCheckpointMismatch,
    #[error("checkpoint sequence did not increase")]
    SequenceRollback,
    #[error("another checkpoint is already pending reconciliation")]
    PendingCheckpointExists,
    #[error("same checkpoint was prepared with different request bytes")]
    ConflictingPreparedRequest,
    #[error("observer is quarantined")]
    Quarantined,
    #[error("no matching pending checkpoint exists")]
    PendingCheckpointNotFound,
    #[error("SQLite integrity_check reported corruption")]
    IntegrityCheckFailed,
    #[error("verified witness quorum does not match the pending checkpoint request")]
    WitnessQuorumMismatch,
    #[error("observer key is not currently valid for checkpoint finalization")]
    ObserverKeyNotCurrentlyValid,
    #[error("witness key is not currently valid for checkpoint finalization")]
    WitnessKeyNotCurrentlyValid,
    #[error("witness tree-head evidence is too old or from the future")]
    WitnessTreeHeadStale,
    #[error("witness tree head does not extend the locally retained witness head")]
    WitnessTreeHeadMismatch,
    #[error("witness receipt conflicts with an already persisted receipt")]
    WitnessReceiptConflict,
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointPrepareOutcome {
    Prepared,
    AlreadyPrepared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointFinalizeOutcome {
    Finalized,
    AlreadyFinalized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedOciWitnessTreeHead {
    pub witness_id: String,
    pub trust_domain_id: String,
    pub key_id: String,
    pub key_generation: u64,
    pub tree_size: u64,
    pub root_hash_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointPendingState {
    Prepared,
    ReconciliationRequired,
}

impl CheckpointPendingState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    fn parse(value: &str) -> Result<Self, OciObserverCheckpointStoreError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            _ => Err(OciObserverCheckpointStoreError::Quarantined),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOciObserverCheckpoint {
    pub observer_id_blake3: String,
    pub machine_id_blake3: String,
    pub checkpoint_digest_blake3: String,
    pub boot_id: String,
    pub sequence: u64,
    pub previous_checkpoint_blake3: Option<String>,
    pub request_digest_blake3: String,
    pub idempotency_key_blake3: String,
    pub request_bytes: Vec<u8>,
    pub state: CheckpointPendingState,
    pub updated_at_ms: u64,
}

#[derive(Debug)]
pub struct OciObserverCheckpointStore {
    connection: Connection,
}

fn validate_digest(value: &str) -> Result<(), OciObserverCheckpointStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(OciObserverCheckpointStoreError::InvalidDigest)
    }
}

fn to_sql_integer(value: u64) -> Result<i64, OciObserverCheckpointStoreError> {
    i64::try_from(value).map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)
}

fn request_digest(request_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(&(request_bytes.len() as u64).to_le_bytes());
    hasher.update(request_bytes);
    hasher.finalize().to_hex().to_string()
}

fn idempotency_key(checkpoint_digest: &str, request_digest: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDEMPOTENCY_DOMAIN);
    hasher.update(&(checkpoint_digest.len() as u64).to_le_bytes());
    hasher.update(checkpoint_digest.as_bytes());
    hasher.update(&(request_digest.len() as u64).to_le_bytes());
    hasher.update(request_digest.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Resolve the parent directory before opening the DB, require an owner-only
/// directory, reject a symlink target, and create new DB files with mode 0600.
/// The caller must also ensure the directory is outside candidate/observer
/// namespaces. This path check is not a defense against a hostile root user.
fn prepare_database_path(path: &Path) -> Result<PathBuf, OciObserverCheckpointStoreError> {
    let file_name = path
        .file_name()
        .ok_or(OciObserverCheckpointStoreError::UnsafePath)?;
    let parent = path\n        .parent()\n        .filter(|parent| !parent.as_os_str().is_empty())\n        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)?;
    let parent_metadata = fs::metadata(&canonical_parent)?;
    if !parent_metadata.is_dir() {
        return Err(OciObserverCheckpointStoreError::UnsafePath);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(OciObserverCheckpointStoreError::InsecureDirectory);
        }
    }

    let database_path = canonical_parent.join(file_name);
    match fs::symlink_metadata(&database_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(OciObserverCheckpointStoreError::UnsafeDatabaseFile);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(OciObserverCheckpointStoreError::InsecureDatabasePermissions);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&database_path) {
                Ok(file) => drop(file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(&database_path)?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(OciObserverCheckpointStoreError::UnsafeDatabaseFile);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(database_path)
}

impl OciObserverCheckpointStore {
    /// Open a local relying-party journal. The parent directory must already
    /// exist and be owner-only (0700 or stricter on Unix).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OciObserverCheckpointStoreError> {
        let database_path = prepare_database_path(path.as_ref())?;
        let connection = Connection::open(database_path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;

        let journal_mode: String =
            connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let synchronous: i64 =
            connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        let foreign_keys: i64 =
            connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 || foreign_keys != 1 {
            return Err(OciObserverCheckpointStoreError::UnsafeSqliteConfiguration);
        }

        let schema_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema_version == 0 {
            let create_schema = format!(
                "BEGIN EXCLUSIVE; {observer_state} {history} {witness} PRAGMA user_version=2; COMMIT;",
                observer_state = OBSERVER_STATE_DDL,
                history = CHECKPOINT_HISTORY_V2_DDL,
                witness = WITNESS_TABLES_DDL,
            );
            connection.execute_batch(&create_schema)?;

        } else if schema_version == 1 {
            let migration = format!(
                "BEGIN EXCLUSIVE;
                 ALTER TABLE checkpoint_history RENAME TO checkpoint_history_v1;
                 {history_ddl}
                 INSERT INTO checkpoint_history (
                    observer_id, checkpoint_digest, machine_id, boot_id, sequence,
                    parent_digest, snapshot_digest, chain_head_digest, key_id,
                    key_generation, expires_at_ms, request_digest, request_bytes,
                    state, created_at_ms
                 )
                 SELECT observer_id, checkpoint_digest, machine_id, boot_id, sequence,
                        parent_digest, snapshot_digest, chain_head_digest, key_id,
                        key_generation, expires_at_ms, request_digest, request_bytes,
                        state, created_at_ms
                 FROM checkpoint_history_v1;
                 DROP TABLE checkpoint_history_v1;
                 {witness_tables}
                 PRAGMA user_version=2;
                 COMMIT;",
                history_ddl = CHECKPOINT_HISTORY_V2_DDL,
                witness_tables = WITNESS_TABLES_DDL,
            );
            connection.execute_batch(&migration)?;
        } else if schema_version != STORE_SCHEMA_VERSION {
            return Err(OciObserverCheckpointStoreError::UnsupportedSchemaVersion);
        }

        Ok(Self { connection })
    }

    /// Persist the exact checkpoint and witness request before any network I/O.
    /// A second distinct checkpoint cannot replace a pending one.
    pub fn prepare_checkpoint(
        &mut self,
        checkpoint: &VerifiedOciObserverCheckpoint,
        witness_request: &OciObserverWitnessRequest,
        now_ms: u64,
    ) -> Result<CheckpointPrepareOutcome, OciObserverCheckpointStoreError> {
        if !witness_request.matches_checkpoint(checkpoint) {
            return Err(OciObserverCheckpointStoreError::WitnessRequestMismatch);
        }
        let request_bytes = witness_request
            .canonical_bytes()
            .map_err(|_| OciObserverCheckpointStoreError::WitnessRequestMismatch)?;
        if request_bytes.is_empty() || request_bytes.len() > MAX_WITNESS_REQUEST_BYTES {
            return Err(OciObserverCheckpointStoreError::InvalidRequestSize);
        }
        let declared_request_digest = witness_request
            .request_digest_blake3()
            .map_err(|_| OciObserverCheckpointStoreError::WitnessRequestMismatch)?;
        let declared_idempotency_key = witness_request
            .idempotency_key_blake3()
            .map_err(|_| OciObserverCheckpointStoreError::WitnessRequestMismatch)?;
        if checkpoint.expires_at_ms() <= now_ms {
            return Err(OciObserverCheckpointStoreError::CheckpointExpired);
        }

        validate_digest(checkpoint.observer_id_blake3())?;
        validate_digest(checkpoint.machine_id_blake3())?;
        validate_digest(checkpoint.checkpoint_digest_blake3())?;
        validate_digest(checkpoint.snapshot_digest_blake3())?;
        validate_digest(checkpoint.chain_head_blake3())?;
        if let Some(parent) = checkpoint.previous_checkpoint_blake3() {
            validate_digest(parent)?;
        }

        let sequence = to_sql_integer(checkpoint.sequence())?;
        let expires_at = to_sql_integer(checkpoint.expires_at_ms())?;
        let updated_at = to_sql_integer(now_ms)?;
        let request_digest = request_digest(&request_bytes);
        let idempotency_key = idempotency_key(
            checkpoint.checkpoint_digest_blake3(),
            &request_digest,
        );
        if declared_request_digest != request_digest || declared_idempotency_key != idempotency_key {
            return Err(OciObserverCheckpointStoreError::WitnessRequestMismatch);
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        type StateRow = (
            String,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<String>,
            i64,
        );

        let state: Option<StateRow> = tx
            .query_row(
                "SELECT machine_id, accepted_checkpoint_digest, accepted_sequence,
                        pending_checkpoint_digest, pending_boot_id, pending_sequence,
                        pending_parent_digest, pending_idempotency_key,
                        pending_request, pending_state, quarantined
                 FROM observer_state WHERE observer_id = ?1",
                [checkpoint.observer_id_blake3()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;

        if let Some((
            machine_id,
            accepted_digest,
            accepted_sequence,
            pending_digest,
            _pending_boot,
            _pending_sequence,
            _pending_parent,
            pending_key,
            pending_request,
            _pending_state,
            quarantined,
        )) = state
        {
            if quarantined != 0 {
                return Err(OciObserverCheckpointStoreError::Quarantined);
            }
            if machine_id != checkpoint.machine_id_blake3() {
                tx.execute(
                    "UPDATE observer_state SET quarantined = 1, updated_at_ms = ?2
                     WHERE observer_id = ?1",
                    params![checkpoint.observer_id_blake3(), updated_at],
                )?;
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::ObserverIdentityMismatch);
            }

            if let Some(existing_digest) = pending_digest {
                if existing_digest == checkpoint.checkpoint_digest_blake3() {
                    let exact_retry = pending_key.as_deref() == Some(idempotency_key.as_str())
                        && pending_request.as_deref() == Some(request_bytes.as_slice());
                    if exact_retry {
                        tx.commit()?;
                        return Ok(CheckpointPrepareOutcome::AlreadyPrepared);
                    }

                    tx.execute(
                        "UPDATE observer_state SET quarantined = 1, pending_state = 'quarantined',
                                updated_at_ms = ?2
                         WHERE observer_id = ?1",
                        params![checkpoint.observer_id_blake3(), updated_at],
                    )?;
                    tx.execute(
                        "UPDATE checkpoint_history SET state = 'quarantined'
                         WHERE observer_id = ?1 AND checkpoint_digest = ?2",
                        params![
                            checkpoint.observer_id_blake3(),
                            checkpoint.checkpoint_digest_blake3()
                        ],
                    )?;
                    tx.commit()?;
                    return Err(OciObserverCheckpointStoreError::ConflictingPreparedRequest);
                }

                // A different checkpoint cannot supersede an unresolved one.
                // Preserve the original pending request so recovery can retry it.
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::PendingCheckpointExists);
            }

            if accepted_digest.as_deref() != checkpoint.previous_checkpoint_blake3() {
                tx.execute(
                    "UPDATE observer_state SET quarantined = 1, updated_at_ms = ?2
                     WHERE observer_id = ?1",
                    params![checkpoint.observer_id_blake3(), updated_at],
                )?;
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::ParentCheckpointMismatch);
            }
            if accepted_sequence.is_some_and(|last| sequence <= last) {
                tx.execute(
                    "UPDATE observer_state SET quarantined = 1, updated_at_ms = ?2
                     WHERE observer_id = ?1",
                    params![checkpoint.observer_id_blake3(), updated_at],
                )?;
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::SequenceRollback);
            }
        } else {
            if checkpoint.previous_checkpoint_blake3().is_some() {
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::ParentCheckpointMismatch);
            }
            tx.execute(
                "INSERT INTO observer_state (
                    observer_id, machine_id, accepted_checkpoint_digest,
                    accepted_boot_id, accepted_sequence, quarantined, updated_at_ms
                 ) VALUES (?1, ?2, NULL, NULL, NULL, 0, ?3)",
                params![
                    checkpoint.observer_id_blake3(),
                    checkpoint.machine_id_blake3(),
                    updated_at
                ],
            )?;
        }

        tx.execute(
            "INSERT INTO checkpoint_history (
                observer_id, checkpoint_digest, machine_id, boot_id, sequence,
                parent_digest, snapshot_digest, chain_head_digest, key_id,
                key_generation, expires_at_ms, request_digest, request_bytes,
                state, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'prepared', ?14)",
            params![
                checkpoint.observer_id_blake3(),
                checkpoint.checkpoint_digest_blake3(),
                checkpoint.machine_id_blake3(),
                checkpoint.boot_id(),
                sequence,
                checkpoint.previous_checkpoint_blake3(),
                checkpoint.snapshot_digest_blake3(),
                checkpoint.chain_head_blake3(),
                checkpoint.key_id(),
                to_sql_integer(checkpoint.key_generation())?,
                expires_at,
                request_digest,
                &request_bytes,
                updated_at
            ],
        )?;

        tx.execute(
            "UPDATE observer_state
             SET pending_checkpoint_digest = ?2,
                 pending_boot_id = ?3,
                 pending_sequence = ?4,
                 pending_parent_digest = ?5,
                 pending_idempotency_key = ?6,
                 pending_request_digest = ?7,
                 pending_request = ?8,
                 pending_state = 'prepared',
                 updated_at_ms = ?9
             WHERE observer_id = ?1",
            params![
                checkpoint.observer_id_blake3(),
                checkpoint.checkpoint_digest_blake3(),
                checkpoint.boot_id(),
                sequence,
                checkpoint.previous_checkpoint_blake3(),
                idempotency_key,
                request_digest,
                &request_bytes,
                updated_at
            ],
        )?;

        tx.commit()?;
        Ok(CheckpointPrepareOutcome::Prepared)
    }

    /// Mark a sent witness request as uncertain. This is idempotent and never
    /// grants admission; recovery must retry/query the exact stored request.
    pub fn mark_reconciliation_required(
        &mut self,
        observer_id_blake3: &str,
        checkpoint_digest_blake3: &str,
        now_ms: u64,
    ) -> Result<(), OciObserverCheckpointStoreError> {
        validate_digest(observer_id_blake3)?;
        validate_digest(checkpoint_digest_blake3)?;
        let updated_at = to_sql_integer(now_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE observer_state
             SET pending_state = 'reconciliation_required', updated_at_ms = ?3
             WHERE observer_id = ?1 AND pending_checkpoint_digest = ?2
                   AND quarantined = 0",
            params![observer_id_blake3, checkpoint_digest_blake3, updated_at],
        )?;
        if changed != 1 {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::PendingCheckpointNotFound);
        }
        tx.execute(
            "UPDATE checkpoint_history SET state = 'reconciliation_required'
             WHERE observer_id = ?1 AND checkpoint_digest = ?2",
            params![observer_id_blake3, checkpoint_digest_blake3],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Return the exact pending request so recovery can resend its identical
    /// bytes. The method does not infer whether a remote witness appended it.
    pub fn pending_checkpoint(
        &self,
        observer_id_blake3: &str,
    ) -> Result<Option<PendingOciObserverCheckpoint>, OciObserverCheckpointStoreError> {
        validate_digest(observer_id_blake3)?;
        type PendingRow = (
            String,
            String,
            String,
            i64,
            Option<String>,
            String,
            String,
            Vec<u8>,
            String,
            i64,
        );
        let row: Option<PendingRow> = self
            .connection
            .query_row(
                "SELECT machine_id, pending_checkpoint_digest, pending_boot_id,
                        pending_sequence, pending_parent_digest, pending_request_digest,
                        pending_idempotency_key, pending_request, pending_state,
                        updated_at_ms
                 FROM observer_state
                 WHERE observer_id = ?1 AND quarantined = 0
                       AND pending_checkpoint_digest IS NOT NULL",
                [observer_id_blake3],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()?;

        row.map(
            |(
                machine_id,
                checkpoint_digest,
                boot_id,
                sequence,
                parent_digest,
                request_digest,
                idempotency_key,
                request_bytes,
                state,
                updated_at,
            )| {
                let sequence = u64::try_from(sequence)
                    .map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)?;
                let updated_at = u64::try_from(updated_at)
                    .map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)?;
                Ok(PendingOciObserverCheckpoint {
                    observer_id_blake3: observer_id_blake3.to_owned(),
                    machine_id_blake3: machine_id,
                    checkpoint_digest_blake3: checkpoint_digest,
                    boot_id,
                    sequence,
                    previous_checkpoint_blake3: parent_digest,
                    request_digest_blake3: request_digest,
                    idempotency_key_blake3: idempotency_key,
                    request_bytes,
                    state: CheckpointPendingState::parse(&state)?,
                    updated_at_ms: updated_at,
                })
            },
        )
        .transpose()
    }

    /// Return the locally retained head for one witness. An absent row is
    /// the RFC 9162 empty tree (size zero and SHA-256 of the empty string).
    /// The caller must use this exact value as the prior-head expectation when
    /// verifying the next receipt from that witness.
    pub fn witness_tree_head(
        &self,
        observer_id_blake3: &str,
        witness_id: &str,
    ) -> Result<RetainedOciWitnessTreeHead, OciObserverCheckpointStoreError> {
        validate_digest(observer_id_blake3)?;
        if witness_id.is_empty()
            || witness_id.len() > 128
            || !witness_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
        {
            return Err(OciObserverCheckpointStoreError::InvalidDigest);
        }
        let row: Option<(String, String, i64, i64, String)> = self
            .connection
            .query_row(
                "SELECT trust_domain_id, key_id, key_generation, tree_size, root_hash_sha256
                 FROM observer_witness_state
                 WHERE observer_id = ?1 AND witness_id = ?2",
                params![observer_id_blake3, witness_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        if let Some((trust_domain_id, key_id, key_generation, tree_size, root_hash_sha256)) = row {
            Ok(RetainedOciWitnessTreeHead {
                witness_id: witness_id.to_owned(),
                trust_domain_id,
                key_id,
                key_generation: u64::try_from(key_generation)
                    .map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)?,
                tree_size: u64::try_from(tree_size)
                    .map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)?,
                root_hash_sha256,
            })
        } else {
            Ok(RetainedOciWitnessTreeHead {
                witness_id: witness_id.to_owned(),
                trust_domain_id: String::new(),
                key_id: String::new(),
                key_generation: 0,
                tree_size: 0,
                root_hash_sha256: empty_merkle_root_sha256(),
            })
        }
    }

    /// Finalize a prepared checkpoint only after a separately verified
    /// witness-quorum token is supplied. Current observer and witness trust
    /// records are rechecked immediately before the durable commit. This
    /// closes the revocation-between-proof-and-commit window at the RP.
    pub fn finalize_witness_quorum(
        &mut self,
        quorum: &VerifiedOciWitnessQuorum,
        observer_key: &TrustedOciObserverKey,
        witness_keys: &[TrustedOciWitnessKey],
        now_ms: u64,
        max_witness_receipt_age_ms: u64,
    ) -> Result<CheckpointFinalizeOutcome, OciObserverCheckpointStoreError> {
        validate_digest(quorum.checkpoint_digest_blake3())
            .map_err(|_| OciObserverCheckpointStoreError::InvalidDigest)?;
        validate_digest(quorum.request_digest_blake3())
            .map_err(|_| OciObserverCheckpointStoreError::InvalidDigest)?;
        validate_digest(quorum.idempotency_key_blake3())
            .map_err(|_| OciObserverCheckpointStoreError::InvalidDigest)?;
        let now = to_sql_integer(now_ms)?;

        if witness_keys.len() != quorum.receipts().len()
            || quorum.receipts().len() < quorum.required_trust_domains()
        {
            return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        type ObserverRow = (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            i64,
        );
        let observer_state: Option<ObserverRow> = tx
            .query_row(
                "SELECT machine_id, pending_checkpoint_digest, pending_request_digest,
                        pending_idempotency_key, pending_state, quarantined
                 FROM observer_state WHERE observer_id = ?1",
                [observer_key.observer_id_blake3.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            machine_id,
            pending_checkpoint,
            pending_request_digest,
            pending_idempotency,
            pending_state,
            quarantined,
        )) = observer_state
        else {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::PendingCheckpointNotFound);
        };

        if quarantined != 0 {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::Quarantined);
        }

        type HistoryRow = (String, i64, i64, String, String, Option<String>);
        let history: Option<HistoryRow> = tx
            .query_row(
                "SELECT state, key_generation, expires_at_ms, machine_id, key_id,
                        witness_quorum_digest
                 FROM checkpoint_history
                 WHERE observer_id = ?1 AND checkpoint_digest = ?2",
                params![
                    observer_key.observer_id_blake3,
                    quorum.checkpoint_digest_blake3()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            history_state,
            observer_key_generation,
            expires_at_ms,
            history_machine_id,
            history_key_id,
            existing_quorum_digest,
        )) = history
        else {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::PendingCheckpointNotFound);
        };

        let observer_key_valid = observer_key.machine_id_blake3 == machine_id
            && observer_key.machine_id_blake3 == history_machine_id
            && observer_key.key_id == history_key_id
            && i64::try_from(observer_key.key_generation).ok() == Some(observer_key_generation)
            && now_ms >= observer_key.valid_from_ms
            && now_ms < observer_key.valid_until_ms
            && !observer_key
                .revoked_at_ms
                .is_some_and(|revoked_at| now_ms >= revoked_at)
            && expires_at_ms > now;
        if !observer_key_valid {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::ObserverKeyNotCurrentlyValid);
        }

        // Re-appraise witness trust and freshness at the final commit boundary.
        // The quorum token proves that the receipts passed verification earlier;
        // this check prevents a later revocation or stale tree head from being
        // converted into current admission authority.
        let mut witness_ids = BTreeSet::new();
        let mut trust_domains = BTreeSet::new();
        for key in witness_keys {
            if !witness_ids.insert(key.witness_id.clone())
                || !trust_domains.insert(key.trust_domain_id.clone())
            {
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
            }
        }

        for verified in quorum.receipts() {
            let trusted = witness_keys
                .iter()
                .find(|key| key.witness_id == verified.witness_id());
            let Some(trusted) = trusted else {
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::WitnessKeyNotCurrentlyValid);
            };
            let witness_valid = trusted.trust_domain_id == verified.trust_domain_id()
                && trusted.key_id == verified.key_id()
                && trusted.key_generation == verified.key_generation()
                && now_ms >= trusted.valid_from_ms
                && now_ms < trusted.valid_until_ms
                && !trusted
                    .revoked_at_ms
                    .is_some_and(|revoked_at| now_ms >= revoked_at);
            if !witness_valid {
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::WitnessKeyNotCurrentlyValid);
            }
            let head_time = verified.tree_head_timestamp_ms();
            if head_time > now_ms || now_ms.saturating_sub(head_time) > max_witness_receipt_age_ms {
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::WitnessTreeHeadStale);
            }
        }

        // Exact retry after the transaction committed but the caller lost its
        // response is safe only when the persisted quorum digest is identical.
        if history_state == "witness_quorum_confirmed" {
            if existing_quorum_digest.as_deref()
                == Some(quorum.evidence_digest_blake3())
            {
                tx.commit()?;
                return Ok(CheckpointFinalizeOutcome::AlreadyFinalized);
            }
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
        }

        if !matches!(history_state.as_str(), "prepared" | "reconciliation_required")
            || pending_checkpoint.as_deref() != Some(quorum.checkpoint_digest_blake3())
            || pending_request_digest.as_deref() != Some(quorum.request_digest_blake3())
            || pending_idempotency.as_deref() != Some(quorum.idempotency_key_blake3())
            || !matches!(
                pending_state.as_deref(),
                Some("prepared") | Some("reconciliation_required")
            )
        {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
        }

        for verified in quorum.receipts() {
            let stored_head: Option<(String, i64, String)> = tx
                .query_row(
                    "SELECT trust_domain_id, tree_size, root_hash_sha256
                     FROM observer_witness_state
                     WHERE observer_id = ?1 AND witness_id = ?2",
                    params![observer_key.observer_id_blake3, verified.witness_id()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (stored_domain, stored_size, stored_root) =
                if let Some((domain, size, root)) = stored_head {
                    (Some(domain), size, root)
                } else {
                    (None, 0, empty_merkle_root_sha256())
                };
            let expected_previous_size = i64::try_from(verified.previous_tree_size())
                .map_err(|_| OciObserverCheckpointStoreError::IntegerOutOfRange)?;
            if stored_size != expected_previous_size
                || stored_root != verified.previous_root_sha256()
                || stored_domain
                    .as_deref()
                    .is_some_and(|domain| domain != verified.trust_domain_id())
            {
                tx.execute(
                    "UPDATE observer_state
                     SET quarantined = 1, pending_state = 'quarantined', updated_at_ms = ?2
                     WHERE observer_id = ?1",
                    params![observer_key.observer_id_blake3, now],
                )?;
                tx.execute(
                    "UPDATE checkpoint_history SET state = 'quarantined'
                     WHERE observer_id = ?1 AND checkpoint_digest = ?2",
                    params![observer_key.observer_id_blake3, quorum.checkpoint_digest_blake3()],
                )?;
                tx.commit()?;
                return Err(OciObserverCheckpointStoreError::WitnessTreeHeadMismatch);
            }
        }

        for verified in quorum.receipts() {
            let key = witness_keys
                .iter()
                .find(|candidate| candidate.witness_id == verified.witness_id())
                .ok_or(OciObserverCheckpointStoreError::WitnessKeyNotCurrentlyValid)?;

            tx.execute(
                "INSERT INTO witness_checkpoint_receipts (
                    observer_id, checkpoint_digest, witness_id, trust_domain_id,
                    key_id, key_generation, tree_size, root_hash_sha256,
                    receipt_digest_blake3, receipt_bytes
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    observer_key.observer_id_blake3,
                    quorum.checkpoint_digest_blake3(),
                    verified.witness_id(),
                    verified.trust_domain_id(),
                    verified.key_id(),
                    to_sql_integer(verified.key_generation())?,
                    to_sql_integer(verified.tree_size())?,
                    verified.root_hash_sha256(),
                    verified.receipt_digest_blake3(),
                    verified.receipt_bytes()
                ],
            )?;

            tx.execute(
                "INSERT INTO observer_witness_state (
                    observer_id, witness_id, trust_domain_id, key_id, key_generation,
                    tree_size, root_hash_sha256, receipt_digest_blake3, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(observer_id, witness_id) DO UPDATE SET
                    trust_domain_id = excluded.trust_domain_id,
                    key_id = excluded.key_id,
                    key_generation = excluded.key_generation,
                    tree_size = excluded.tree_size,
                    root_hash_sha256 = excluded.root_hash_sha256,
                    receipt_digest_blake3 = excluded.receipt_digest_blake3,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    observer_key.observer_id_blake3,
                    verified.witness_id(),
                    verified.trust_domain_id(),
                    verified.key_id(),
                    to_sql_integer(verified.key_generation())?,
                    to_sql_integer(verified.tree_size())?,
                    verified.root_hash_sha256(),
                    verified.receipt_digest_blake3(),
                    now
                ],
            )?;
        }

        let changed_history = tx.execute(
            "UPDATE checkpoint_history
             SET state = 'witness_quorum_confirmed',
                 witness_quorum_digest = ?3,
                 witness_quorum_required = ?4,
                 witness_receipt_count = ?5,
                 witness_confirmed_at_ms = ?6
             WHERE observer_id = ?1 AND checkpoint_digest = ?2
                   AND state IN ('prepared', 'reconciliation_required')",
            params![
                observer_key.observer_id_blake3,
                quorum.checkpoint_digest_blake3(),
                quorum.evidence_digest_blake3(),
                to_sql_integer(quorum.required_trust_domains() as u64)?,
                to_sql_integer(quorum.receipts().len() as u64)?,
                now
            ],
        )?;
        if changed_history != 1 {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
        }

        let changed_state = tx.execute(
            "UPDATE observer_state
             SET accepted_checkpoint_digest = pending_checkpoint_digest,
                 accepted_boot_id = pending_boot_id,
                 accepted_sequence = pending_sequence,
                 pending_checkpoint_digest = NULL,
                 pending_boot_id = NULL,
                 pending_sequence = NULL,
                 pending_parent_digest = NULL,
                 pending_idempotency_key = NULL,
                 pending_request_digest = NULL,
                 pending_request = NULL,
                 pending_state = NULL,
                 updated_at_ms = ?2
             WHERE observer_id = ?1
                   AND pending_checkpoint_digest = ?3
                   AND quarantined = 0",
            params![
                observer_key.observer_id_blake3,
                now,
                quorum.checkpoint_digest_blake3()
            ],
        )?;
        if changed_state != 1 {
            tx.commit()?;
            return Err(OciObserverCheckpointStoreError::WitnessQuorumMismatch);
        }

        tx.commit()?;
        Ok(CheckpointFinalizeOutcome::Finalized)
    }

    /// Run SQLite's integrity_check before an admission decision. This only
    /// checks database consistency; it cannot detect replacement with an old,
    /// internally consistent database image.
    pub fn integrity_check(&self) -> Result<(), OciObserverCheckpointStoreError> {
        let result: String =
            self.connection
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(OciObserverCheckpointStoreError::IntegrityCheckFailed)
        }
    }

    #[cfg(test)]
    fn journal_configuration(&self) -> Result<(String, i64), OciObserverCheckpointStoreError> {
        let journal_mode: String =
            self.connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let synchronous: i64 =
            self.connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        Ok((journal_mode, synchronous))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::signed_checkpoint::{
        observer_challenge_digest, sign_observer_checkpoint, verify_observer_checkpoint,
        OciObserverCheckpointExpectation, OciObserverCheckpointPayload,
        TrustedOciObserverKey, OCI_OBSERVER_CHECKPOINT_KIND,
        OCI_OBSERVER_CHECKPOINT_SCHEMA_VERSION,
    };
    use crate::observe::witness_transparency::{
        make_test_witness_quorum_for_request, OciObserverWitnessRequest,
    };
    use ed25519_dalek::SigningKey;

    fn verified_checkpoint(
        sequence: u64,
        parent: Option<String>,
    ) -> VerifiedOciObserverCheckpoint {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [9u8; 32];
        let payload = OciObserverCheckpointPayload {
            schema_version: OCI_OBSERVER_CHECKPOINT_SCHEMA_VERSION,
            kind: OCI_OBSERVER_CHECKPOINT_KIND.to_owned(),
            observer_id_blake3: "a1".repeat(32),
            key_id: "observer-primary".to_owned(),
            key_generation: 7,
            machine_id_blake3: "b2".repeat(32),
            boot_id: "11111111-2222-3333-4444-555555555555".to_owned(),
            sequence,
            snapshot_digest_blake3: "c3".repeat(32),
            chain_head_blake3: format!("{:064x}", sequence),
            previous_checkpoint_blake3: parent.clone(),
            challenge_blake3: observer_challenge_digest(&nonce),
            issued_at_ms: 900,
            expires_at_ms: 1_900,
        };
        let signed = sign_observer_checkpoint(payload, &signing_key).unwrap();
        let trusted_key = TrustedOciObserverKey {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            key_id: "observer-primary".to_owned(),
            key_generation: 7,
            public_key_hex: {
                let bytes = signing_key.verifying_key().to_bytes();
                bytes.iter().map(|byte| format!("{byte:02x}")).collect()
            },
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        };
        let expectation = OciObserverCheckpointExpectation {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            challenge_nonce: nonce,
            expected_snapshot_digest_blake3: "c3".repeat(32),
            expected_chain_head_blake3: format!("{:064x}", sequence),
            expected_boot_id: "11111111-2222-3333-4444-555555555555".to_owned(),
            expected_sequence: sequence,
            expected_previous_checkpoint_blake3: parent,
            min_sequence_exclusive: 0,
            now_ms: 1_000,
            max_validity_ms: 2_000,
        };
        verify_observer_checkpoint(&signed, &trusted_key, &expectation).unwrap()
    }

    fn trusted_observer_key() -> TrustedOciObserverKey {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        TrustedOciObserverKey {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            key_id: "observer-primary".to_owned(),
            key_generation: 7,
            public_key_hex: {
                let bytes = signing_key.verifying_key().to_bytes();
                bytes.iter().map(|byte| format!("{byte:02x}")).collect()
            },
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        }
    }

    fn open_store(temp: &tempfile::TempDir) -> OciObserverCheckpointStore {
        OciObserverCheckpointStore::open(temp.path().join("observer-checkpoints.sqlite"))
            .unwrap()
    }

    #[test]
    fn finalizes_checkpoint_only_after_two_distinct_witness_domains() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let (witness_keys, quorum) = make_test_witness_quorum_for_request(&request, 2).unwrap();
        let observer_key = trusted_observer_key();
        let mut store = open_store(&temp);

        store.prepare_checkpoint(&checkpoint, &request, 1_100).unwrap();
        assert_eq!(
            store
                .finalize_witness_quorum(&quorum, &observer_key, &witness_keys, 1_200, 500)
                .unwrap(),
            CheckpointFinalizeOutcome::Finalized
        );

        let head_a = store.witness_tree_head("a1".repeat(32).as_str(), "witness-a").unwrap();
        let head_b = store.witness_tree_head("a1".repeat(32).as_str(), "witness-b").unwrap();
        assert_eq!(head_a.tree_size, 1);
        assert_eq!(head_b.tree_size, 1);
        assert_eq!(head_a.trust_domain_id, "operator-a");
        assert_eq!(head_b.trust_domain_id, "operator-b");
        assert!(store.pending_checkpoint(&"a1".repeat(32)).unwrap().is_none());
        store.integrity_check().unwrap();

        assert_eq!(
            store
                .finalize_witness_quorum(&quorum, &observer_key, &witness_keys, 1_200, 500)
                .unwrap(),
            CheckpointFinalizeOutcome::AlreadyFinalized
        );
    }

    #[test]
    fn rejects_witness_key_revoked_after_receipt_verification() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let (mut witness_keys, quorum) =
            make_test_witness_quorum_for_request(&request, 2).unwrap();
        witness_keys[0].revoked_at_ms = Some(1_150);
        let observer_key = trusted_observer_key();
        let mut store = open_store(&temp);
        store.prepare_checkpoint(&checkpoint, &request, 1_100).unwrap();

        assert!(matches!(
            store.finalize_witness_quorum(&quorum, &observer_key, &witness_keys, 1_200, 500),
            Err(OciObserverCheckpointStoreError::WitnessKeyNotCurrentlyValid)
        ));
        assert!(store.pending_checkpoint(&"a1".repeat(32)).unwrap().is_some());
    }

    #[test]
    fn quarantines_when_local_witness_high_water_mark_was_rolled_back() {
        let temp = tempfile::tempdir().unwrap();
        let first = verified_checkpoint(10, None);
        let first_request = OciObserverWitnessRequest::from_verified_checkpoint(&first).unwrap();
        let (witness_keys, first_quorum) =
            make_test_witness_quorum_for_request(&first_request, 2).unwrap();
        let observer_key = trusted_observer_key();
        let mut store = open_store(&temp);
        store.prepare_checkpoint(&first, &first_request, 1_100).unwrap();
        store
            .finalize_witness_quorum(&first_quorum, &observer_key, &witness_keys, 1_200, 500)
            .unwrap();

        let second = verified_checkpoint(
            20,
            Some(first.checkpoint_digest_blake3().to_owned()),
        );
        let second_request = OciObserverWitnessRequest::from_verified_checkpoint(&second).unwrap();
        let (stale_witness_keys, stale_genesis_quorum) =
            make_test_witness_quorum_for_request(&second_request, 2).unwrap();
        store.prepare_checkpoint(&second, &second_request, 1_300).unwrap();

        assert!(matches!(
            store.finalize_witness_quorum(
                &stale_genesis_quorum,
                &observer_key,
                &stale_witness_keys,
                1_400,
                500
            ),
            Err(OciObserverCheckpointStoreError::WitnessTreeHeadMismatch)
        ));
        assert!(store.pending_checkpoint(&"a1".repeat(32)).unwrap().is_none());
        assert!(matches!(
            store.prepare_checkpoint(&second, &second_request, 1_500),
            Err(OciObserverCheckpointStoreError::Quarantined)
        ));
    }

    #[test]
    fn opens_with_wal_and_full_synchronous_mode() {
        let temp = tempfile::tempdir().unwrap();
        let store = open_store(&temp);
        let (journal_mode, synchronous) = store.journal_configuration().unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        store.integrity_check().unwrap();
    }

    #[test]
    fn persists_exact_pending_request_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let request_bytes = request.canonical_bytes().unwrap();
        let digest = checkpoint.checkpoint_digest_blake3().to_owned();
        {
            let mut store = open_store(&temp);
            assert_eq!(
                store.prepare_checkpoint(&checkpoint, &request, 1_100).unwrap(),
                CheckpointPrepareOutcome::Prepared
            );
            store.mark_reconciliation_required("a1".repeat(32).as_str(), &digest, 1_101).unwrap();
        }
        let store = open_store(&temp);
        let pending = store.pending_checkpoint(&"a1".repeat(32)).unwrap().unwrap();
        assert_eq!(pending.checkpoint_digest_blake3, digest);
        assert_eq!(pending.request_bytes, request_bytes);
        assert_eq!(pending.state, CheckpointPendingState::ReconciliationRequired);
        assert_eq!(pending.sequence, 10);
    }

    #[test]
    fn exact_retry_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut store = open_store(&temp);
        assert_eq!(
            store.prepare_checkpoint(&checkpoint, &request, 1_100).unwrap(),
            CheckpointPrepareOutcome::Prepared
        );
        assert_eq!(
            store.prepare_checkpoint(&checkpoint, &request, 1_101).unwrap(),
            CheckpointPrepareOutcome::AlreadyPrepared
        );
    }

    #[test]
    fn exact_checkpoint_request_replay_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let mut store = open_store(&temp);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        store.prepare_checkpoint(&checkpoint, &request, 1_100).unwrap();
        assert_eq!(
            store.prepare_checkpoint(&checkpoint, &request, 1_101).unwrap(),
            CheckpointPrepareOutcome::AlreadyPrepared
        );
    }

    #[test]
    fn a_distinct_checkpoint_cannot_replace_pending_request() {
        let temp = tempfile::tempdir().unwrap();
        let first = verified_checkpoint(10, None);
        let second = verified_checkpoint(20, None);
        let mut store = open_store(&temp);
        let first_request = OciObserverWitnessRequest::from_verified_checkpoint(&first).unwrap();
        let second_request = OciObserverWitnessRequest::from_verified_checkpoint(&second).unwrap();
        store.prepare_checkpoint(&first, &first_request, 1_100).unwrap();
        assert!(matches!(
            store.prepare_checkpoint(&second, &second_request, 1_101),
            Err(OciObserverCheckpointStoreError::PendingCheckpointExists)
        ));
        let pending = store.pending_checkpoint(&"a1".repeat(32)).unwrap().unwrap();
        assert_eq!(pending.checkpoint_digest_blake3, first.checkpoint_digest_blake3());
        assert_eq!(pending.request_bytes, first_request.canonical_bytes().unwrap());
    }

    #[test]
    fn rejects_non_genesis_parent_without_retained_head() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, Some("ff".repeat(32)));
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut store = open_store(&temp);
        assert!(matches!(
            store.prepare_checkpoint(&checkpoint, &request, 1_100),
            Err(OciObserverCheckpointStoreError::ParentCheckpointMismatch)
        ));
        assert!(store.pending_checkpoint(&"a1".repeat(32)).unwrap().is_none());
    }

    #[test]
    fn rejects_witness_request_derived_from_another_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let other_checkpoint = verified_checkpoint(20, None);
        let wrong_request =
            OciObserverWitnessRequest::from_verified_checkpoint(&other_checkpoint).unwrap();
        let mut store = open_store(&temp);
        assert!(matches!(
            store.prepare_checkpoint(&checkpoint, &wrong_request, 1_100),
            Err(OciObserverCheckpointStoreError::WitnessRequestMismatch)
        ));
        assert!(store.pending_checkpoint(&"a1".repeat(32)).unwrap().is_none());
    }

    #[test]
    fn canonical_witness_request_is_nonempty_bounded_and_digest_bound() {
        let temp = tempfile::tempdir().unwrap();
        let checkpoint = verified_checkpoint(10, None);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let request_bytes = request.canonical_bytes().unwrap();
        assert!(!request_bytes.is_empty());
        assert!(request_bytes.len() <= MAX_WITNESS_REQUEST_BYTES);
        assert_eq!(
            request.request_digest_blake3().unwrap(),
            request_digest(&request_bytes)
        );
        assert_eq!(
            request.idempotency_key_blake3().unwrap(),
            idempotency_key(
                checkpoint.checkpoint_digest_blake3(),
                &request_digest(&request_bytes)
            )
        );
        let mut store = open_store(&temp);
        assert!(store.prepare_checkpoint(&checkpoint, &request, 1_100).is_ok());
    }
}
