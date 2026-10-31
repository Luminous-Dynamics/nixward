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

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4e58_5744; // "NXWD"
const MAX_APPROVAL_BYTES: usize = 1024 * 1024;
const MAX_PERMIT_BYTES: usize = 1024 * 1024;
const MAX_EVENT_BYTES: usize = 1024 * 1024;

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
"#;

const SELECT_ADMISSION_BY_COMMIT: &str = r#"
SELECT
    a.commit_id, a.transaction_id, a.attempt_id, a.replay_key,
    a.plan_digest, a.machine_binding_digest, a.approval_proof_digest,
    a.approval_material, a.permit_digest, a.permit_wire, a.event_digest,
    e.event_payload, a.created_at_ms, t.state, t.resolution_digest,
    t.resolved_at_ms
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
    t.resolved_at_ms
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
    t.resolved_at_ms
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

        let synchronous: i64 =
            connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let foreign_keys: i64 =
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        if synchronous != 2 || foreign_keys != 1 {
            return Err(AdmissionStoreError::InvalidInput(
                "SQLite FULL synchronous / foreign-key settings are not active",
            ));
        }

        let application_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        if application_id != 0 && application_id != APPLICATION_ID {
            return Err(AdmissionStoreError::WrongApplicationId);
        }
        if application_id == 0 {
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        }

        let version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(AdmissionStoreError::UnsupportedSchema(version));
        }

        let mut connection = connection;
        let transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;

        Ok(connection)
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
        permit_digest: &str,
        event_digest: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nixward-supervisor-admission-commit-v1\0");
        for value in [
            transaction_id.as_bytes(),
            attempt_id.as_bytes(),
            replay_key.as_bytes(),
            plan_digest.as_bytes(),
            machine_binding_digest.as_bytes(),
            approval_proof_digest.as_bytes(),
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
        if request.permit_wire.is_empty() || request.permit_wire.len() > MAX_PERMIT_BYTES {
            return Err(AdmissionStoreError::InvalidInput("permit wire length"));
        }
        if request.event_payload.is_empty() || request.event_payload.len() > MAX_EVENT_BYTES {
            return Err(AdmissionStoreError::InvalidInput("admission event length"));
        }
        let created_at_ms = i64::try_from(request.created_at_ms)
            .map_err(|_| AdmissionStoreError::InvalidInput("creation timestamp"))?;

        let approval_proof_digest = Self::digest(&request.approval_material);
        let permit_digest = Self::digest(&request.permit_wire);
        let event_digest = Self::digest(&request.event_payload);

        let commit_id = Self::derive_commit_id(
            &request.transaction_id,
            &request.attempt_id,
            &request.replay_key,
            &request.plan_digest,
            &request.machine_binding_digest,
            &approval_proof_digest,
            &permit_digest,
            &event_digest,
        );

        Ok(DerivedBindings {
            approval_proof_digest,
            permit_digest,
            event_digest,
            commit_id,
            created_at_ms,
        })
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
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
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
        transaction.commit()?;
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
    fn wal_full_sync_foreign_keys_and_private_file_mode_are_enabled() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(&temp);
        store.admit(&request("tx-a", "attempt-a1", 0x11, 0x22, 0x33)).unwrap();

        let connection = store.connect().unwrap();
        let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
        let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0)).unwrap();
        let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0)).unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        assert_eq!(foreign_keys, 1);

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
            params![record.record().commit_id, b"tampered event".as_slice()],
        ).unwrap();

        assert!(matches!(
            store.admit(&request("tx-b", "attempt-b1", 0x44, 0x55, 0x66)),
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