// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persistent one-shot consumption of verified authority challenges.
//!
//! Signature verification is intentionally read-only. A privileged mutation
//! must additionally burn the verified replay key immediately before command
//! execution. A crash after the burn is fail-safe: the operator must authorize
//! a fresh challenge rather than reusing an ambiguous approval.

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const DEFAULT_AUTHORITY_REPLAY_DB: &str = "/var/lib/nixward/authority-replay.sqlite3";

#[derive(Debug, Error)]
pub enum AuthorityReplayError {
    #[error("authority replay key was already consumed")]
    AlreadyConsumed,
    #[error("invalid authority replay evidence: {0}")]
    InvalidEvidence(&'static str),
    #[error("authority replay path traverses a symlink: {0}")]
    SymlinkPath(String),
    #[error("authority replay directory permissions are too broad: {0}")]
    InsecurePermissions(String),
    #[error("authority replay storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("authority replay filesystem error: {0}")]
    Filesystem(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct AuthorityReplayLedger {
    path: PathBuf,
}

impl Default for AuthorityReplayLedger {
    fn default() -> Self {
        Self::system_default()
    }
}

impl AuthorityReplayLedger {
    pub fn system_default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_AUTHORITY_REPLAY_DB),
        }
    }

    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn valid_digest(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn hex_32(value: &[u8; 32]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn reject_symlink_components(path: &Path) -> Result<(), AuthorityReplayError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if !current.exists() {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() {
                return Err(AuthorityReplayError::SymlinkPath(
                    current.display().to_string(),
                ));
            }
        }
        Ok(())
    }

    fn prepare_storage(&self) -> Result<(), AuthorityReplayError> {
        let parent = self
            .path
            .parent()
            .ok_or(AuthorityReplayError::InvalidEvidence(
                "database path has no parent",
            ))?;
        Self::reject_symlink_components(parent)?;
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        Self::reject_symlink_components(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let default_parent = Path::new(DEFAULT_AUTHORITY_REPLAY_DB).parent();
            if !parent_existed || Some(parent) == default_parent {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            } else {
                let mode = std::fs::metadata(parent)?.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(AuthorityReplayError::InsecurePermissions(
                        parent.display().to_string(),
                    ));
                }
            }
        }
        if self.path.exists() {
            let metadata = std::fs::symlink_metadata(&self.path)?;
            if metadata.file_type().is_symlink() {
                return Err(AuthorityReplayError::SymlinkPath(
                    self.path.display().to_string(),
                ));
            }
        }
        Ok(())
    }

    fn open(&self) -> Result<Connection, AuthorityReplayError> {
        self.prepare_storage()?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;\
             PRAGMA synchronous=FULL;\
             PRAGMA foreign_keys=ON;\
             PRAGMA busy_timeout=5000;\
             CREATE TABLE IF NOT EXISTS authority_replay_v1 (\
               replay_key TEXT PRIMARY KEY NOT NULL,\
               challenge_blake3 TEXT NOT NULL,\
               evidence_blake3 TEXT NOT NULL,\
               subject_blake3 TEXT NOT NULL,\
               consumed_at_ms INTEGER NOT NULL\
             );",
        )?;
        Ok(connection)
    }

    /// Atomically burn one verified challenge replay key.
    pub fn consume(
        &self,
        replay_key: &str,
        challenge_blake3: &str,
        evidence_blake3: [u8; 32],
        subject_blake3: &str,
        consumed_at_ms: u64,
    ) -> Result<(), AuthorityReplayError> {
        if !Self::valid_digest(replay_key) {
            return Err(AuthorityReplayError::InvalidEvidence("replay key"));
        }
        if !Self::valid_digest(challenge_blake3) {
            return Err(AuthorityReplayError::InvalidEvidence("challenge digest"));
        }
        if !Self::valid_digest(subject_blake3) {
            return Err(AuthorityReplayError::InvalidEvidence("subject digest"));
        }
        let consumed_at_ms = i64::try_from(consumed_at_ms)
            .map_err(|_| AuthorityReplayError::InvalidEvidence("consumption time"))?;
        let evidence_blake3 = Self::hex_32(&evidence_blake3);
        let mut connection = self.open()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO authority_replay_v1 \
             (replay_key, challenge_blake3, evidence_blake3, subject_blake3, consumed_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                replay_key,
                challenge_blake3,
                evidence_blake3,
                subject_blake3,
                consumed_at_ms
            ],
        )?;
        if inserted != 1 {
            transaction.rollback()?;
            return Err(AuthorityReplayError::AlreadyConsumed);
        }
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_key_is_one_shot_and_persistent() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = AuthorityReplayLedger::new(tmp.path().join("nixward/replay.sqlite3"));
        let key = "11".repeat(32);
        let challenge = "22".repeat(32);
        let subject = "33".repeat(32);
        ledger
            .consume(&key, &challenge, [0x44; 32], &subject, 1000)
            .unwrap();
        assert!(matches!(
            ledger.consume(&key, &challenge, [0x44; 32], &subject, 1001),
            Err(AuthorityReplayError::AlreadyConsumed)
        ));
        let reopened = AuthorityReplayLedger::new(ledger.path().to_path_buf());
        assert!(matches!(
            reopened.consume(&key, &challenge, [0x44; 32], &subject, 1002),
            Err(AuthorityReplayError::AlreadyConsumed)
        ));
        reopened
            .consume(&"55".repeat(32), &challenge, [0x44; 32], &subject, 1003)
            .unwrap();
    }
}
