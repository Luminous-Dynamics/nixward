// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Durable one-branch witness signing ledger.
//!
//! A high-assurance 3-of-4 quorum only has the intended intersection property
//! when each honest witness refuses to endorse two checkpoint digests for the
//! same observer parent/sequence. This native-only ledger persists that vote
//! before returning its Ed25519 signature. It does not operate a network API,
//! transparency log, or cross-client gossip transport.

use super::signed_checkpoint::VerifiedOciObserverCheckpoint;
use super::witness_transparency::{
    OciObserverWitnessRequest, TrustedOciWitnessKey, VerifiedOciWitnessQuorum,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const WITNESS_BRANCH_SCHEMA_VERSION: i64 = 1;
const BRANCH_SIGNING_DOMAIN: &[u8] = b"nixward:oci-witness-branch-endorsement:v1\0";
const MAX_ENDORSEMENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum OciWitnessBranchLedgerError {
    #[error("witness ledger path is invalid or unsafe")]
    UnsafePath,
    #[error("witness ledger directory must be owner-only")]
    InsecureDirectory,
    #[error("witness ledger file is a symlink or is not a regular file")]
    UnsafeDatabaseFile,
    #[error("witness ledger database permissions are broader than owner-only")]
    InsecureDatabasePermissions,
    #[error("witness ledger schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("witness signing identity differs from the provisioned ledger identity")]
    WitnessIdentityMismatch,
    #[error("the signing key does not match the provisioned public key bytes")]
    SigningKeyMismatch,
    #[error("current witness trust attempts to expand the provisioned validity window or clear a latched revocation")]
    TrustRecordExpanded,
    #[error("witness signing key is not currently valid")]
    KeyNotCurrentlyValid,
    #[error("witness signing key has been revoked")]
    KeyRevoked,
    #[error("witness request is not derived from the supplied verified checkpoint")]
    WitnessRequestMismatch,
    #[error("witness endorsement has expired")]
    CheckpointExpired,
    #[error("observer sequence is not strictly increasing")]
    SequenceRollback,
    #[error("checkpoint does not extend the witness's retained observer head")]
    ParentCheckpointMismatch,
    #[error("observer branch is quarantined after a conflicting checkpoint attempt")]
    ObserverBranchQuarantined,
    #[error("a different checkpoint already occupies this observer parent/sequence slot")]
    ConflictingBranch,
    #[error("witness endorsement is malformed")]
    InvalidShape,
    #[error("witness endorsement signature is invalid")]
    InvalidSignature,
    #[error("witness endorsement does not match the verified checkpoint/request")]
    SubjectMismatch,
    #[error("SQLite integrity_check reported corruption")]
    IntegrityCheckFailed,
    #[error("integer exceeds SQLite's signed integer range")]
    IntegerOutOfRange,
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessBranchOutcome {
    Signed,
    AlreadySigned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OciWitnessBranchEndorsement {
    pub schema_version: u32,
    pub kind: String,
    pub witness_id: String,
    pub trust_domain_id: String,
    pub key_id: String,
    pub key_generation: u64,
    pub observer_id_blake3: String,
    pub machine_id_blake3: String,
    pub boot_id: String,
    pub sequence: u64,
    pub checkpoint_digest_blake3: String,
    pub request_digest_blake3: String,
    pub idempotency_key_blake3: String,
    pub previous_checkpoint_blake3: Option<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature_hex: String,
}

impl OciWitnessBranchEndorsement {
    fn signing_bytes(&self) -> Result<Vec<u8>, OciWitnessBranchLedgerError> {
        if self.schema_version != 1
            || self.kind != "nixward-oci-witness-branch-endorsement-v1"
            || self.key_generation == 0
            || self.sequence == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(OciWitnessBranchLedgerError::InvalidShape);
        }
        for value in [
            &self.observer_id_blake3,
            &self.machine_id_blake3,
            &self.checkpoint_digest_blake3,
            &self.request_digest_blake3,
            &self.idempotency_key_blake3,
        ] {
            validate_digest(value)?;
        }
        if let Some(parent) = &self.previous_checkpoint_blake3 {
            validate_digest(parent)?;
        }
        for value in [
            &self.witness_id,
            &self.trust_domain_id,
            &self.key_id,
            &self.boot_id,
        ] {
            validate_identifier(value)?;
        }

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(BRANCH_SIGNING_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        push_string(&mut out, &self.kind);
        push_string(&mut out, &self.witness_id);
        push_string(&mut out, &self.trust_domain_id);
        push_string(&mut out, &self.key_id);
        out.extend_from_slice(&self.key_generation.to_le_bytes());
        push_string(&mut out, &self.observer_id_blake3);
        push_string(&mut out, &self.machine_id_blake3);
        push_string(&mut out, &self.boot_id);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        push_string(&mut out, &self.checkpoint_digest_blake3);
        push_string(&mut out, &self.request_digest_blake3);
        push_string(&mut out, &self.idempotency_key_blake3);
        match &self.previous_checkpoint_blake3 {
            Some(parent) => {
                out.push(1);
                push_string(&mut out, parent);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciWitnessBranchEndorsement {
    witness_id: String,
    trust_domain_id: String,
    observer_id_blake3: String,
    sequence: u64,
    checkpoint_digest_blake3: String,
    request_digest_blake3: String,
    endorsement_digest_blake3: String,
    key_id: String,
    key_generation: u64,
    signer_public_key_hex: String,
    endorsement_bytes: Vec<u8>,
}

impl VerifiedOciWitnessBranchEndorsement {
    pub fn witness_id(&self) -> &str { &self.witness_id }
    pub fn trust_domain_id(&self) -> &str { &self.trust_domain_id }
    pub fn observer_id_blake3(&self) -> &str { &self.observer_id_blake3 }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn checkpoint_digest_blake3(&self) -> &str { &self.checkpoint_digest_blake3 }
    pub fn request_digest_blake3(&self) -> &str { &self.request_digest_blake3 }
    pub fn endorsement_digest_blake3(&self) -> &str { &self.endorsement_digest_blake3 }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub fn key_generation(&self) -> u64 { self.key_generation }
    pub fn signer_public_key_hex(&self) -> &str { &self.signer_public_key_hex }
    pub fn endorsement_bytes(&self) -> &[u8] { &self.endorsement_bytes }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciWitnessBranchQuorum {
    witness_quorum: VerifiedOciWitnessQuorum,
    branch_endorsements: Vec<VerifiedOciWitnessBranchEndorsement>,
    evidence_digest_blake3: String,
}

impl VerifiedOciWitnessBranchQuorum {
    /// Bind one independently verified single-branch endorsement to every
    /// exact witness receipt in the transparency quorum.
    pub fn bind(
        witness_quorum: VerifiedOciWitnessQuorum,
        branch_endorsements: Vec<VerifiedOciWitnessBranchEndorsement>,
    ) -> Result<Self, OciWitnessBranchLedgerError> {
        if branch_endorsements.len() != witness_quorum.receipts().len() {
            return Err(OciWitnessBranchLedgerError::SubjectMismatch);
        }
        let mut witness_ids = std::collections::BTreeSet::new();
        let mut trust_domains = std::collections::BTreeSet::new();
        for endorsement in &branch_endorsements {
            if !witness_ids.insert(endorsement.witness_id().to_owned())
                || !trust_domains.insert(endorsement.trust_domain_id().to_owned())
                || endorsement.checkpoint_digest_blake3()
                    != witness_quorum.checkpoint_digest_blake3()
                || endorsement.request_digest_blake3()
                    != witness_quorum.request_digest_blake3()
            {
                return Err(OciWitnessBranchLedgerError::SubjectMismatch);
            }
        }
        for receipt in witness_quorum.receipts() {
            let endorsement = branch_endorsements
                .iter()
                .find(|item| item.witness_id() == receipt.witness_id())
                .ok_or(OciWitnessBranchLedgerError::SubjectMismatch)?;
            if endorsement.trust_domain_id() != receipt.trust_domain_id()
                || endorsement.checkpoint_digest_blake3()
                    != receipt.checkpoint_digest_blake3()
                || endorsement.request_digest_blake3()
                    != receipt.request_digest_blake3()
                || endorsement.key_id() != receipt.key_id()
                || endorsement.key_generation() != receipt.key_generation()
                || endorsement.signer_public_key_hex() != receipt.signer_public_key_hex()
                || endorsement.endorsement_digest_blake3()
                    != receipt.branch_endorsement_digest_blake3()
            {
                return Err(OciWitnessBranchLedgerError::SubjectMismatch);
            }
        }
        let mut ordered: Vec<_> = branch_endorsements.iter().collect();
        ordered.sort_by(|left, right| left.witness_id().cmp(right.witness_id()));
        let mut digest = blake3::Hasher::new();
        digest.update(b"nixward:oci-witness-branch-quorum:v2\0");
        digest.update(witness_quorum.evidence_digest_blake3().as_bytes());
        for endorsement in ordered {
            digest.update(&(endorsement.endorsement_digest_blake3().len() as u64).to_le_bytes());
            digest.update(endorsement.endorsement_digest_blake3().as_bytes());
        }
        Ok(Self {
            witness_quorum,
            branch_endorsements,
            evidence_digest_blake3: digest.finalize().to_hex().to_string(),
        })
    }

    pub fn checkpoint_digest_blake3(&self) -> &str {
        self.witness_quorum.checkpoint_digest_blake3()
    }
    pub fn request_digest_blake3(&self) -> &str {
        self.witness_quorum.request_digest_blake3()
    }
    pub fn idempotency_key_blake3(&self) -> &str {
        self.witness_quorum.idempotency_key_blake3()
    }
    pub fn evidence_digest_blake3(&self) -> &str {
        &self.evidence_digest_blake3
    }
    pub fn required_trust_domains(&self) -> usize {
        self.witness_quorum.required_trust_domains()
    }
    pub fn receipts(&self) -> &[super::witness_transparency::VerifiedOciWitnessReceipt] {
        self.witness_quorum.receipts()
    }
    pub fn branch_endorsements(&self) -> &[VerifiedOciWitnessBranchEndorsement] {
        &self.branch_endorsements
    }
    pub fn branch_endorsement_for(
        &self,
        witness_id: &str,
    ) -> Option<&VerifiedOciWitnessBranchEndorsement> {
        self.branch_endorsements
            .iter()
            .find(|item| item.witness_id() == witness_id)
    }
}

fn validate_digest(value: &str) -> Result<(), OciWitnessBranchLedgerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OciWitnessBranchLedgerError::InvalidShape);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), OciWitnessBranchLedgerError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(OciWitnessBranchLedgerError::InvalidShape);
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn to_sql_integer(value: u64) -> Result<i64, OciWitnessBranchLedgerError> {
    i64::try_from(value).map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], OciWitnessBranchLedgerError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OciWitnessBranchLedgerError::InvalidShape);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = (value.as_bytes()[index * 2] as char)
            .to_digit(16)
            .ok_or(OciWitnessBranchLedgerError::InvalidShape)?;
        let low = (value.as_bytes()[index * 2 + 1] as char)
            .to_digit(16)
            .ok_or(OciWitnessBranchLedgerError::InvalidShape)?;
        *slot = ((high << 4) | low) as u8;
    }
    Ok(out)
}

fn prepare_database_path(path: &Path) -> Result<PathBuf, OciWitnessBranchLedgerError> {
    let file_name = path.file_name().ok_or(OciWitnessBranchLedgerError::UnsafePath)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)?;
    let parent_metadata = fs::metadata(&canonical_parent)?;
    if !parent_metadata.is_dir() {
        return Err(OciWitnessBranchLedgerError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(OciWitnessBranchLedgerError::InsecureDirectory);
        }
    }

    let database_path = canonical_parent.join(file_name);
    match fs::symlink_metadata(&database_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(OciWitnessBranchLedgerError::UnsafeDatabaseFile);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(OciWitnessBranchLedgerError::InsecureDatabasePermissions);
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
                        return Err(OciWitnessBranchLedgerError::UnsafeDatabaseFile);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(database_path)
}

pub struct OciWitnessBranchLedger {
    connection: Connection,
    witness_id: String,
    trust_domain_id: String,
    key_id: String,
    key_generation: u64,
    public_key_hex: String,
    valid_from_ms: u64,
    valid_until_ms: u64,
    revoked_at_ms: Option<u64>,
}

impl OciWitnessBranchLedger {
    /// Open a witness signing ledger bound to one operator-provisioned
    /// identity. Private key material is never stored by this module.
    pub fn open(
        path: impl AsRef<Path>,
        trusted_identity: &TrustedOciWitnessKey,
    ) -> Result<Self, OciWitnessBranchLedgerError> {
        validate_identifier(&trusted_identity.witness_id)?;
        validate_identifier(&trusted_identity.key_id)?;
        validate_identifier(&trusted_identity.trust_domain_id)?;
        decode_hex::<32>(&trusted_identity.public_key_hex)?;
        if trusted_identity.key_generation == 0
            || trusted_identity.valid_until_ms <= trusted_identity.valid_from_ms
        {
            return Err(OciWitnessBranchLedgerError::InvalidShape);
        }

        let database_path = prepare_database_path(path.as_ref())?;
        let mut connection = Connection::open(database_path)?;
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
            return Err(OciWitnessBranchLedgerError::InvalidShape);
        }

        let schema_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema_version == 0 {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
            tx.execute_batch(
                "CREATE TABLE witness_identity (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    witness_id TEXT NOT NULL,
                    trust_domain_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
                    public_key_hex TEXT NOT NULL,
                    valid_from_ms INTEGER NOT NULL,
                    valid_until_ms INTEGER NOT NULL,
                    revoked_at_ms INTEGER
                 );
                 CREATE TABLE witness_observer_head (
                    observer_id TEXT PRIMARY KEY NOT NULL,
                    machine_id TEXT NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)),
                    updated_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE witness_branch_lock (
                    observer_id TEXT NOT NULL,
                    parent_checkpoint_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    checkpoint_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    endorsement_json BLOB NOT NULL,
                    endorsement_digest_blake3 TEXT NOT NULL,
                    issued_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (observer_id, parent_checkpoint_digest, sequence),
                    UNIQUE (observer_id, checkpoint_digest)
                 );
                 CREATE TABLE witness_branch_conflict (
                    conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observer_id TEXT NOT NULL,
                    parent_checkpoint_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    retained_checkpoint_digest TEXT NOT NULL,
                    attempted_checkpoint_digest TEXT NOT NULL,
                    attempted_request_digest TEXT NOT NULL,
                    detected_at_ms INTEGER NOT NULL
                 );",
            )?;
            tx.execute(
                "INSERT INTO witness_identity (
                    singleton, witness_id, trust_domain_id, key_id, key_generation,
                    public_key_hex, valid_from_ms, valid_until_ms, revoked_at_ms
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    trusted_identity.witness_id,
                    trusted_identity.trust_domain_id,
                    trusted_identity.key_id,
                    to_sql_integer(trusted_identity.key_generation)?,
                    trusted_identity.public_key_hex,
                    to_sql_integer(trusted_identity.valid_from_ms)?,
                    to_sql_integer(trusted_identity.valid_until_ms)?,
                    trusted_identity.revoked_at_ms.map(to_sql_integer).transpose()?
                ],
            )?;
            tx.execute_batch("PRAGMA user_version=1;")?;
            tx.commit()?;
        } else if schema_version != WITNESS_BRANCH_SCHEMA_VERSION {
            return Err(OciWitnessBranchLedgerError::UnsupportedSchemaVersion);
        }

        let stored: (String, String, String, i64, String, i64, i64, Option<i64>) =
            connection.query_row(
                "SELECT witness_id, trust_domain_id, key_id, key_generation,
                        public_key_hex, valid_from_ms, valid_until_ms, revoked_at_ms
                 FROM witness_identity WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                        row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?
                    ))
                },
            )?;
        connection.execute(
            "UPDATE witness_identity
             SET valid_from_ms = MAX(valid_from_ms, ?1),
                 valid_until_ms = MIN(valid_until_ms, ?2),
                 revoked_at_ms = CASE
                     WHEN revoked_at_ms IS NULL THEN ?3
                     WHEN ?3 IS NULL THEN revoked_at_ms
                     ELSE MIN(revoked_at_ms, ?3)
                 END
             WHERE singleton = 1",
            params![
                to_sql_integer(trusted_identity.valid_from_ms)?,
                to_sql_integer(trusted_identity.valid_until_ms)?,
                trusted_identity.revoked_at_ms.map(to_sql_integer).transpose()?
            ],
        )?;
        let effective: (i64, i64, Option<i64>) = connection.query_row(
            "SELECT valid_from_ms, valid_until_ms, revoked_at_ms
             FROM witness_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let effective_valid_from = u64::try_from(effective.0)
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        let effective_valid_until = u64::try_from(effective.1)
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        let effective_revoked_at = effective.2
            .map(u64::try_from)
            .transpose()
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        if effective_valid_until <= effective_valid_from {
            return Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid);
        }

        Ok(Self {
            connection,
            witness_id: trusted_identity.witness_id.clone(),
            trust_domain_id: trusted_identity.trust_domain_id.clone(),
            key_id: trusted_identity.key_id.clone(),
            key_generation: trusted_identity.key_generation,
            public_key_hex: trusted_identity.public_key_hex.clone(),
            valid_from_ms: effective_valid_from,
            valid_until_ms: effective_valid_until,
            revoked_at_ms: effective_revoked_at,
        })
    }

    /// Sign only one checkpoint digest for each observer parent/sequence.
    /// The durable branch lock and updated observer head commit before the
    /// endorsement is returned. An exact retry returns the same stored bytes.
    pub fn endorse_checkpoint_branch(
        &mut self,
        checkpoint: &VerifiedOciObserverCheckpoint,
        request: &OciObserverWitnessRequest,
        current_trust: &TrustedOciWitnessKey,
        signing_key: &SigningKey,
        now_ms: u64,
    ) -> Result<(WitnessBranchOutcome, OciWitnessBranchEndorsement), OciWitnessBranchLedgerError> {
        if !request.matches_checkpoint(checkpoint) {
            return Err(OciWitnessBranchLedgerError::WitnessRequestMismatch);
        }
        if current_trust.witness_id != self.witness_id
            || current_trust.trust_domain_id != self.trust_domain_id
            || current_trust.key_id != self.key_id
            || current_trust.key_generation != self.key_generation
            || current_trust.public_key_hex != self.public_key_hex
            || encode_hex(signing_key.verifying_key().as_bytes()) != self.public_key_hex
        {
            return Err(OciWitnessBranchLedgerError::SigningKeyMismatch);
        }
        // The live trust record may tighten the durable provisioning but
        // must never broaden it. Revocation and validity reductions are
        // latched before any signature is returned, including when the key
        // remains temporarily valid before a future revocation timestamp.
        let revocation_was_weakened = match (self.revoked_at_ms, current_trust.revoked_at_ms) {
            (Some(provisioned), Some(current)) => current > provisioned,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if current_trust.valid_from_ms < self.valid_from_ms
            || current_trust.valid_until_ms > self.valid_until_ms
            || revocation_was_weakened
        {
            return Err(OciWitnessBranchLedgerError::TrustRecordExpanded);
        }
        // The durable row is intersected atomically below, inside the same
        // IMMEDIATE transaction as the branch lock. This is authoritative
        // when another live handle has tightened the trust after this handle
        // was opened.
        let request_bytes = request
            .canonical_bytes()
            .map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?;
        if request_bytes.len() > MAX_ENDORSEMENT_BYTES {
            return Err(OciWitnessBranchLedgerError::InvalidShape);
        }
        let request_digest = request
            .request_digest_blake3()
            .map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?;
        let idempotency_key = request
            .idempotency_key_blake3()
            .map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?;
        let parent_digest = checkpoint
            .previous_checkpoint_blake3()
            .unwrap_or("")
            .to_owned();
        let sequence = to_sql_integer(checkpoint.sequence())?;
        let now = to_sql_integer(now_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Atomic database-side intersection: MAX/MIN and the revocation
        // latch are evaluated against the latest committed row, not this
        // handle's potentially stale in-memory snapshot.
        tx.execute(
            "UPDATE witness_identity
             SET valid_from_ms = MAX(valid_from_ms, ?1),
                 valid_until_ms = MIN(valid_until_ms, ?2),
                 revoked_at_ms = CASE
                     WHEN revoked_at_ms IS NULL THEN ?3
                     WHEN ?3 IS NULL THEN revoked_at_ms
                     ELSE MIN(revoked_at_ms, ?3)
                 END
             WHERE singleton = 1",
            params![
                to_sql_integer(current_trust.valid_from_ms)?,
                to_sql_integer(current_trust.valid_until_ms)?,
                current_trust.revoked_at_ms.map(to_sql_integer).transpose()?
            ],
        )?;
        let effective: (i64, i64, Option<i64>) = tx.query_row(
            "SELECT valid_from_ms, valid_until_ms, revoked_at_ms
             FROM witness_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let effective_valid_from = u64::try_from(effective.0)
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        let effective_valid_until = u64::try_from(effective.1)
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        let effective_revoked_at = effective.2
            .map(u64::try_from)
            .transpose()
            .map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?;
        if effective_valid_until <= effective_valid_from {
            tx.commit()?;
            return Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid);
        }
        if now_ms < effective_valid_from || now_ms >= effective_valid_until {
            tx.commit()?;
            return Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid);
        }
        if effective_revoked_at.is_some_and(|revoked_at| now_ms >= revoked_at) {
            tx.commit()?;
            return Err(OciWitnessBranchLedgerError::KeyRevoked);
        }
        let existing: Option<(String, String, Vec<u8>)> = tx
            .query_row(
                "SELECT checkpoint_digest, request_digest, endorsement_json
                 FROM witness_branch_lock
                 WHERE observer_id = ?1 AND parent_checkpoint_digest = ?2 AND sequence = ?3",
                params![checkpoint.observer_id_blake3(), parent_digest, sequence],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        if let Some((existing_checkpoint, existing_request, endorsement_json)) = existing {
            if existing_checkpoint == checkpoint.checkpoint_digest_blake3()
                && existing_request == request_digest
            {
                let quarantined: Option<i64> = tx
                    .query_row(
                        "SELECT quarantined FROM witness_observer_head WHERE observer_id = ?1",
                        [checkpoint.observer_id_blake3()],
                        |row| row.get(0),
                    )
                    .optional()?;
                if quarantined.unwrap_or(0) != 0 {
                    tx.commit()?;
                    return Err(OciWitnessBranchLedgerError::ObserverBranchQuarantined);
                }
                let endorsement: OciWitnessBranchEndorsement =
                    serde_json::from_slice(&endorsement_json)
                        .map_err(|_| OciWitnessBranchLedgerError::InvalidShape)?;
                tx.commit()?;
                return Ok((WitnessBranchOutcome::AlreadySigned, endorsement));
            }

            tx.execute(
                "INSERT INTO witness_branch_conflict (
                    observer_id, parent_checkpoint_digest, sequence,
                    retained_checkpoint_digest, attempted_checkpoint_digest,
                    attempted_request_digest, detected_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    checkpoint.observer_id_blake3(),
                    parent_digest,
                    sequence,
                    existing_checkpoint,
                    checkpoint.checkpoint_digest_blake3(),
                    request_digest,
                    now
                ],
            )?;
            tx.execute(
                "UPDATE witness_observer_head
                 SET quarantined = 1, updated_at_ms = ?2
                 WHERE observer_id = ?1",
                params![checkpoint.observer_id_blake3(), now],
            )?;
            tx.commit()?;
            return Err(OciWitnessBranchLedgerError::ConflictingBranch);
        }

        let head: Option<(String, String, i64, i64)> = tx
            .query_row(
                "SELECT machine_id, checkpoint_digest, sequence, quarantined
                 FROM witness_observer_head WHERE observer_id = ?1",
                [checkpoint.observer_id_blake3()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        if let Some((machine_id, accepted_digest, accepted_sequence, quarantined)) = head {
            if quarantined != 0 {
                tx.commit()?;
                return Err(OciWitnessBranchLedgerError::ObserverBranchQuarantined);
            }
            if machine_id != checkpoint.machine_id_blake3()
                || accepted_digest != parent_digest
            {
                tx.commit()?;
                return Err(OciWitnessBranchLedgerError::ParentCheckpointMismatch);
            }
            if sequence <= accepted_sequence {
                tx.commit()?;
                return Err(OciWitnessBranchLedgerError::SequenceRollback);
            }
        } else if checkpoint.previous_checkpoint_blake3().is_some() {
            tx.commit()?;
            return Err(OciWitnessBranchLedgerError::ParentCheckpointMismatch);
        }

        let mut endorsement = OciWitnessBranchEndorsement {
            schema_version: 1,
            kind: "nixward-oci-witness-branch-endorsement-v1".to_owned(),
            witness_id: self.witness_id.clone(),
            trust_domain_id: self.trust_domain_id.clone(),
            key_id: self.key_id.clone(),
            key_generation: self.key_generation,
            observer_id_blake3: checkpoint.observer_id_blake3().to_owned(),
            machine_id_blake3: checkpoint.machine_id_blake3().to_owned(),
            boot_id: checkpoint.boot_id().to_owned(),
            sequence: checkpoint.sequence(),
            checkpoint_digest_blake3: checkpoint.checkpoint_digest_blake3().to_owned(),
            request_digest_blake3: request_digest.clone(),
            idempotency_key_blake3: idempotency_key,
            previous_checkpoint_blake3: checkpoint.previous_checkpoint_blake3().map(str::to_owned),
            issued_at_ms: now_ms,
            expires_at_ms: checkpoint.expires_at_ms(),
            signature_hex: String::new(),
        };
        let signing_bytes = endorsement.signing_bytes()?;
        endorsement.signature_hex = encode_hex(&signing_key.sign(&signing_bytes).to_bytes());
        let endorsement_json = serde_json::to_vec(&endorsement)
            .map_err(|_| OciWitnessBranchLedgerError::InvalidShape)?;
        if endorsement_json.len() > MAX_ENDORSEMENT_BYTES {
            return Err(OciWitnessBranchLedgerError::InvalidShape);
        }

        tx.execute(
            "INSERT INTO witness_branch_lock (
                observer_id, parent_checkpoint_digest, sequence, checkpoint_digest,
                request_digest, idempotency_key, endorsement_json,
                endorsement_digest_blake3, issued_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                checkpoint.observer_id_blake3(),
                parent_digest,
                sequence,
                checkpoint.checkpoint_digest_blake3(),
                request_digest,
                endorsement.idempotency_key_blake3,
                endorsement_json,
                {
                    let mut digest = blake3::Hasher::new();
                    digest.update(&signing_bytes);
                    digest.update(&decode_hex::<64>(&endorsement.signature_hex)?);
                    digest.finalize().to_hex().to_string()
                },
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO witness_observer_head (
                observer_id, machine_id, checkpoint_digest, boot_id, sequence,
                quarantined, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
             ON CONFLICT(observer_id) DO UPDATE SET
                machine_id = excluded.machine_id,
                checkpoint_digest = excluded.checkpoint_digest,
                boot_id = excluded.boot_id,
                sequence = excluded.sequence,
                updated_at_ms = excluded.updated_at_ms",
            params![
                checkpoint.observer_id_blake3(),
                checkpoint.machine_id_blake3(),
                checkpoint.checkpoint_digest_blake3(),
                checkpoint.boot_id(),
                sequence,
                now
            ],
        )?;
        tx.commit()?;
        Ok((WitnessBranchOutcome::Signed, endorsement))
    }

    pub fn integrity_check(&self) -> Result<(), OciWitnessBranchLedgerError> {
        let result: String =
            self.connection
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result == "ok" {
            Ok(())
        } else {
            Err(OciWitnessBranchLedgerError::IntegrityCheckFailed)
        }
    }

    #[cfg(test)]
    fn accepted_head(
        &self,
        observer_id_blake3: &str,
    ) -> Result<Option<(String, u64, bool)>, OciWitnessBranchLedgerError> {
        let row: Option<(String, i64, i64)> = self.connection
            .query_row(
                "SELECT checkpoint_digest, sequence, quarantined
                 FROM witness_observer_head WHERE observer_id = ?1",
                [observer_id_blake3],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(digest, sequence, quarantined)| {
            Ok((
                digest,
                u64::try_from(sequence).map_err(|_| OciWitnessBranchLedgerError::IntegerOutOfRange)?,
                quarantined != 0
            ))
        }).transpose()
    }
}

/// Verify a persisted witness branch endorsement against the current trusted
/// key and the exact opaque observer checkpoint/request pair.
pub fn verify_witness_branch_endorsement(
    endorsement: &OciWitnessBranchEndorsement,
    trusted_key: &TrustedOciWitnessKey,
    checkpoint: &VerifiedOciObserverCheckpoint,
    request: &OciObserverWitnessRequest,
    now_ms: u64,
) -> Result<VerifiedOciWitnessBranchEndorsement, OciWitnessBranchLedgerError> {
    if !request.matches_checkpoint(checkpoint)
        || endorsement.witness_id != trusted_key.witness_id
        || endorsement.trust_domain_id != trusted_key.trust_domain_id
        || endorsement.key_id != trusted_key.key_id
        || endorsement.key_generation != trusted_key.key_generation
        || endorsement.observer_id_blake3 != checkpoint.observer_id_blake3()
        || endorsement.machine_id_blake3 != checkpoint.machine_id_blake3()
        || endorsement.boot_id != checkpoint.boot_id()
        || endorsement.sequence != checkpoint.sequence()
        || endorsement.checkpoint_digest_blake3 != checkpoint.checkpoint_digest_blake3()
        || endorsement.previous_checkpoint_blake3.as_deref()
            != checkpoint.previous_checkpoint_blake3()
        || endorsement.request_digest_blake3
            != request.request_digest_blake3().map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?
        || endorsement.idempotency_key_blake3
            != request.idempotency_key_blake3().map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?
        || endorsement.expires_at_ms != checkpoint.expires_at_ms()
        || endorsement.issued_at_ms < trusted_key.valid_from_ms
        || endorsement.issued_at_ms >= trusted_key.valid_until_ms
        || now_ms < trusted_key.valid_from_ms
        || now_ms >= trusted_key.valid_until_ms
        || now_ms < endorsement.issued_at_ms
        || now_ms >= endorsement.expires_at_ms
    {
        return Err(OciWitnessBranchLedgerError::SubjectMismatch);
    }
    if trusted_key
        .revoked_at_ms
        .is_some_and(|revoked_at| now_ms >= revoked_at)
    {
        return Err(OciWitnessBranchLedgerError::KeyRevoked);
    }

    let signing_bytes = endorsement.signing_bytes()?;
    let public_key = decode_hex::<32>(&trusted_key.public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| OciWitnessBranchLedgerError::InvalidShape)?;
    let signature_bytes = decode_hex::<64>(&endorsement.signature_hex)?;
    verifying_key
        .verify_strict(&signing_bytes, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| OciWitnessBranchLedgerError::InvalidSignature)?;

    let mut digest = blake3::Hasher::new();
    digest.update(b"nixward:oci-witness-branch-endorsement-digest:v1\0");
    digest.update(&(signing_bytes.len() as u64).to_le_bytes());
    digest.update(&signing_bytes);
    digest.update(&signature_bytes);

    Ok(VerifiedOciWitnessBranchEndorsement {
        witness_id: endorsement.witness_id.clone(),
        trust_domain_id: endorsement.trust_domain_id.clone(),
        observer_id_blake3: endorsement.observer_id_blake3.clone(),
        sequence: endorsement.sequence,
        checkpoint_digest_blake3: endorsement.checkpoint_digest_blake3.clone(),
        request_digest_blake3: endorsement.request_digest_blake3.clone(),
        endorsement_digest_blake3: digest.finalize().to_hex().to_string(),
        key_id: endorsement.key_id.clone(),
        key_generation: endorsement.key_generation,
        signer_public_key_hex: trusted_key.public_key_hex.clone(),
        endorsement_bytes: serde_json::to_vec(endorsement)
            .map_err(|_| OciWitnessBranchLedgerError::InvalidShape)?,
    })
}

#[cfg(test)]
pub(crate) fn make_test_verified_branch_endorsements(
    checkpoint: &VerifiedOciObserverCheckpoint,
    request: &OciObserverWitnessRequest,
    trusted_keys: &[TrustedOciWitnessKey],
) -> Result<Vec<VerifiedOciWitnessBranchEndorsement>, OciWitnessBranchLedgerError> {
    make_test_verified_branch_endorsements_after_parent(checkpoint, request, trusted_keys, None)
}

#[cfg(test)]
pub(crate) fn make_test_verified_branch_endorsements_after_parent(
    checkpoint: &VerifiedOciObserverCheckpoint,
    request: &OciObserverWitnessRequest,
    trusted_keys: &[TrustedOciWitnessKey],
    parent_checkpoint: Option<&VerifiedOciObserverCheckpoint>,
) -> Result<Vec<VerifiedOciWitnessBranchEndorsement>, OciWitnessBranchLedgerError> {
    let mut verified = Vec::with_capacity(trusted_keys.len());
    for (index, trust) in trusted_keys.iter().enumerate() {
        let seed = 41u8 + index as u8;
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let temp = tempfile::tempdir().map_err(|_| OciWitnessBranchLedgerError::InvalidShape)?;
        let mut ledger = OciWitnessBranchLedger::open(
            temp.path().join("witness-branch.sqlite"),
            trust,
        )?;
        if let Some(parent) = parent_checkpoint {
            let parent_request = OciObserverWitnessRequest::from_verified_checkpoint(parent)
                .map_err(|_| OciWitnessBranchLedgerError::WitnessRequestMismatch)?;
            ledger.endorse_checkpoint_branch(parent, &parent_request, trust, &signing_key, 1_150)?;
        }
        let (_, endorsement) =
            ledger.endorse_checkpoint_branch(checkpoint, request, trust, &signing_key, 1_200)?;
        verified.push(verify_witness_branch_endorsement(
            &endorsement,
            trust,
            checkpoint,
            request,
            1_200,
        )?);
    }
    Ok(verified)
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

    fn trusted_witness(signing: &SigningKey) -> TrustedOciWitnessKey {
        TrustedOciWitnessKey {
            trust_domain_id: "operator-a".to_owned(),
            witness_id: "witness-a".to_owned(),
            key_id: "witness-a-primary".to_owned(),
            key_generation: 4,
            public_key_hex: encode_hex(signing.verifying_key().as_bytes()),
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        }
    }

    fn verified_checkpoint(
        sequence: u64,
        parent: Option<String>,
        nonce_byte: u8,
    ) -> VerifiedOciObserverCheckpoint {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [nonce_byte; 32];
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
        let signed = sign_observer_checkpoint(payload, &signing).unwrap();
        let trusted = TrustedOciObserverKey {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            key_id: "observer-primary".to_owned(),
            key_generation: 7,
            public_key_hex: encode_hex(signing.verifying_key().as_bytes()),
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        };
        let expected = OciObserverCheckpointExpectation {
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
        verify_observer_checkpoint(&signed, &trusted, &expected).unwrap()
    }

    fn open_ledger(
        temp: &tempfile::TempDir,
        trust: &TrustedOciWitnessKey,
    ) -> OciWitnessBranchLedger {
        OciWitnessBranchLedger::open(temp.path().join("witness-branch.sqlite"), trust).unwrap()
    }

    #[test]
    fn persists_one_branch_before_returning_a_signature_and_retries_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let endorsement = {
            let mut ledger = open_ledger(&temp, &trust);
            let (outcome, endorsement) = ledger
                .endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_100)
                .unwrap();
            assert_eq!(outcome, WitnessBranchOutcome::Signed);
            ledger.integrity_check().unwrap();
            endorsement
        };

        let mut ledger = open_ledger(&temp, &trust);
        let (outcome, retry) = ledger
            .endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_200)
            .unwrap();
        assert_eq!(outcome, WitnessBranchOutcome::AlreadySigned);
        assert_eq!(retry, endorsement);
        let verified =
            verify_witness_branch_endorsement(&retry, &trust, &checkpoint, &request, 1_200)
                .unwrap();
        assert_eq!(verified.witness_id(), "witness-a");
        assert_eq!(verified.sequence(), 10);
    }

    #[test]
    fn refuses_a_conflicting_checkpoint_digest_for_same_parent_and_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let first = verified_checkpoint(10, None, 9);
        let second = verified_checkpoint(10, None, 8);
        assert_ne!(
            first.checkpoint_digest_blake3(),
            second.checkpoint_digest_blake3()
        );
        let first_request = OciObserverWitnessRequest::from_verified_checkpoint(&first).unwrap();
        let second_request = OciObserverWitnessRequest::from_verified_checkpoint(&second).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        ledger
            .endorse_checkpoint_branch(&first, &first_request, &trust, &signing, 1_100)
            .unwrap();
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&second, &second_request, &trust, &signing, 1_200),
            Err(OciWitnessBranchLedgerError::ConflictingBranch)
        ));
        assert_eq!(
            ledger.accepted_head("a1".repeat(32).as_str()).unwrap(),
            Some((first.checkpoint_digest_blake3().to_owned(), 10, true))
        );
    }

    #[test]
    fn accepts_only_the_exact_next_checkpoint_parent() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let first = verified_checkpoint(10, None, 9);
        let first_request = OciObserverWitnessRequest::from_verified_checkpoint(&first).unwrap();
        let second = verified_checkpoint(
            20,
            Some(first.checkpoint_digest_blake3().to_owned()),
            8,
        );
        let second_request = OciObserverWitnessRequest::from_verified_checkpoint(&second).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        ledger
            .endorse_checkpoint_branch(&first, &first_request, &trust, &signing, 1_100)
            .unwrap();
        ledger
            .endorse_checkpoint_branch(&second, &second_request, &trust, &signing, 1_200)
            .unwrap();
        assert_eq!(
            ledger.accepted_head("a1".repeat(32).as_str()).unwrap(),
            Some((second.checkpoint_digest_blake3().to_owned(), 20, false))
        );
    }

    #[test]
    fn rejects_stale_parent_and_reused_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let first = verified_checkpoint(10, None, 9);
        let first_request = OciObserverWitnessRequest::from_verified_checkpoint(&first).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        ledger
            .endorse_checkpoint_branch(&first, &first_request, &trust, &signing, 1_100)
            .unwrap();

        let stale_parent = verified_checkpoint(20, None, 8);
        let stale_request =
            OciObserverWitnessRequest::from_verified_checkpoint(&stale_parent).unwrap();
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&stale_parent, &stale_request, &trust, &signing, 1_150),
            Err(OciWitnessBranchLedgerError::ParentCheckpointMismatch)
        ));
    }

    #[test]
    fn rejects_signing_key_substitution_even_with_same_identity_labels() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let wrong_signing = SigningKey::from_bytes(&[44u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&checkpoint, &request, &trust, &wrong_signing, 1_100),
            Err(OciWitnessBranchLedgerError::SigningKeyMismatch)
        ));
    }

    #[test]
    fn observes_revocation_after_ledger_is_opened() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        let mut current_trust = trust.clone();
        current_trust.revoked_at_ms = Some(1_150);
        assert!(matches!(
            ledger.endorse_checkpoint_branch(
                &checkpoint,
                &request,
                &current_trust,
                &signing,
                1_200
            ),
            Err(OciWitnessBranchLedgerError::KeyRevoked)
        ));
        assert_eq!(
            ledger.accepted_head("a1".repeat(32).as_str()).unwrap(),
            None
        );
    }

    #[test]
    fn rejects_revoked_or_expired_witness_key() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let mut trust = trusted_witness(&signing);
        trust.revoked_at_ms = Some(1_150);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_200),
            Err(OciWitnessBranchLedgerError::KeyRevoked)
        ));
    }
    #[test]
    fn rejects_current_trust_that_expands_provisioned_validity_window() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);

        let mut backdated = trust.clone();
        backdated.valid_from_ms = 50;
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&checkpoint, &request, &backdated, &signing, 1_100),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));

        let mut extended = trust.clone();
        extended.valid_until_ms = 20_000;
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&checkpoint, &request, &extended, &signing, 1_100),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));

        assert_eq!(ledger.accepted_head("a1".repeat(32).as_str()).unwrap(), None);
    }

    #[test]
    fn rejects_clearing_a_latched_revocation_for_the_same_key_generation() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let mut trust = trusted_witness(&signing);
        trust.revoked_at_ms = Some(1_150);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);

        let mut unrevoked = trust.clone();
        unrevoked.revoked_at_ms = None;
        assert!(matches!(
            ledger.endorse_checkpoint_branch(&checkpoint, &request, &unrevoked, &signing, 1_100),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));
        assert_eq!(ledger.accepted_head("a1".repeat(32).as_str()).unwrap(), None);
    }

    #[test]
    fn accepts_monotonic_tightening_of_current_trust_record() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();
        let mut ledger = open_ledger(&temp, &trust);

        let mut tightened = trust.clone();
        tightened.valid_from_ms = 200;
        tightened.valid_until_ms = 9_000;
        tightened.revoked_at_ms = Some(8_000);
        let result = ledger.endorse_checkpoint_branch(
            &checkpoint, &request, &tightened, &signing, 1_100
        );
        assert!(result.is_ok());
        drop(ledger);

        // The on-disk restrictions survive reopen even when the caller has
        // only the older, broader provisioning snapshot.
        let mut reopened = open_ledger(&temp, &trust);
        assert!(matches!(
            reopened.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_200),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));
    }

    #[test]
    fn latches_dynamic_revocation_across_calls_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();

        {
            let mut ledger = open_ledger(&temp, &trust);
            let mut revoked = trust.clone();
            revoked.revoked_at_ms = Some(1_150);
            let signed = ledger.endorse_checkpoint_branch(
                &checkpoint, &request, &revoked, &signing, 1_100
            );
            assert!(signed.is_ok());

            // A later stale trust snapshot cannot clear the revocation.
            assert!(matches!(
                ledger.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_120),
                Ok((WitnessBranchOutcome::AlreadySigned, _))
            ));
        }

        // The durable revocation survives process restart and cannot be
        // cleared by reopening with the original, unrevoked provisioning.
        let mut reopened = open_ledger(&temp, &trust);
        assert!(matches!(
            reopened.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_120),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));

        let mut revoked = trust.clone();
        revoked.revoked_at_ms = Some(1_150);
        assert!(matches!(
            reopened.endorse_checkpoint_branch(&checkpoint, &request, &revoked, &signing, 1_160),
            Err(OciWitnessBranchLedgerError::KeyRevoked)
        ));
    }
    #[test]
    fn persists_invalid_tightened_window_and_rejects_stale_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();

        {
            let mut ledger = open_ledger(&temp, &trust);
            let mut invalid_tightening = trust.clone();
            invalid_tightening.valid_from_ms = 9_000;
            invalid_tightening.valid_until_ms = 8_000;
            assert!(matches!(
                ledger.endorse_checkpoint_branch(
                    &checkpoint, &request, &invalid_tightening, &signing, 1_100
                ),
                Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid)
            ));
        }

        // A caller presenting the old broad trust record after restart must
        // not restore the interval invalidated by the stricter update.
        assert!(matches!(
            OciWitnessBranchLedger::open(temp.path().join("witness-branch.sqlite"), &trust),
            Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid)
        ));
    }

    #[test]
    fn stale_open_handles_cannot_widen_persisted_trust_restrictions() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();

        // Both handles cache the broad original trust before either changes it.
        let mut restrictive = open_ledger(&temp, &trust);
        let mut stale = open_ledger(&temp, &trust);

        let mut shortened = trust.clone();
        shortened.valid_until_ms = 1_500;
        restrictive
            .endorse_checkpoint_branch(&checkpoint, &request, &shortened, &signing, 1_100)
            .unwrap();

        // The stale handle still has a 10_000ms in-memory upper bound and
        // receives the older broad trust snapshot. SQLite must retain 1_500.
        assert!(matches!(
            stale.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_600),
            Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid)
        ));

        // A third fresh handle using the original snapshot must also fail.
        drop(restrictive);
        drop(stale);
        assert!(matches!(
            OciWitnessBranchLedger::open(temp.path().join("witness-branch.sqlite"), &trust),
            Err(OciWitnessBranchLedgerError::KeyNotCurrentlyValid)
        ));
    }

    #[test]
    fn stale_open_handle_cannot_clear_a_revocation_latched_by_another_handle() {
        let temp = tempfile::tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted_witness(&signing);
        let checkpoint = verified_checkpoint(10, None, 9);
        let request = OciObserverWitnessRequest::from_verified_checkpoint(&checkpoint).unwrap();

        let mut revoker = open_ledger(&temp, &trust);
        let mut stale = open_ledger(&temp, &trust);
        let mut revoked = trust.clone();
        revoked.revoked_at_ms = Some(1_150);
        revoker
            .endorse_checkpoint_branch(&checkpoint, &request, &revoked, &signing, 1_100)
            .unwrap();

        assert!(matches!(
            stale.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_160),
            Err(OciWitnessBranchLedgerError::KeyRevoked)
        ));
        drop(revoker);
        drop(stale);
        // The old trust snapshot may reopen the ledger, but it cannot clear
        // the persisted future revocation; current signing still fails.
        let mut reopened = open_ledger(&temp, &trust);
        assert!(matches!(
            reopened.endorse_checkpoint_branch(&checkpoint, &request, &trust, &signing, 1_160),
            Err(OciWitnessBranchLedgerError::TrustRecordExpanded)
        ));
        assert!(matches!(
            reopened.endorse_checkpoint_branch(&checkpoint, &request, &revoked, &signing, 1_160),
            Err(OciWitnessBranchLedgerError::KeyRevoked)
        ));
    }


}
