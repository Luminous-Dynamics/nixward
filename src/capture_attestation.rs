// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capture-origin attestation for benchmark evidence.
//!
//! This module is deliberately separate from owner deployment authority.
//! It verifies DSSE signatures with a verifier-selected capture trust policy,
//! binds an in-toto Statement v1 to the exact trial subject set, and consumes
//! a one-use verifier challenge in a separate control-plane SQLite ledger.
//!
//! The first implementation supports software-held Ed25519 capture keys only.
//! A TPM claim is rejected until a quote, AIK chain, PCR selection and event-log
//! replay adapter has been independently implemented and qualified.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CAPTURE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const CAPTURE_PREDICATE_TYPE: &str =
    "https://nixward.dev/attestation/payload-release-capture/v1";
const TRUST_POLICY_SCHEMA: &str = "org.luminousdynamics.nixward.capture-trust-policy";
const CHALLENGE_SCHEMA: &str = "org.luminousdynamics.nixward.capture-challenge";
const REPORT_SCHEMA: &str = "org.luminousdynamics.nixward.capture-verification";
const LEDGER_APPLICATION_ID: i64 = 0x4e58_4341; // NXCA
const LEDGER_SCHEMA_VERSION: i64 = 1;
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_CHALLENGE_BYTES: usize = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURES: usize = 32;
const MAX_SIGNERS: usize = 64;
const MAX_CHALLENGE_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum CaptureAttestationError {
    #[error("capture trust policy is malformed: {0}")]
    InvalidPolicy(String),
    #[error("capture policy digest differs from the issued challenge")]
    PolicyDigestMismatch,
    #[error("capture challenge is malformed, expired, mismatched or was not issued by this verifier")]
    InvalidChallenge,
    #[error("capture challenge has already been consumed")]
    ChallengeReplay,
    #[error("DSSE envelope is malformed or does not authenticate the expected payload type")]
    InvalidEnvelope,
    #[error("DSSE signature threshold was not met by distinct configured capture keys")]
    SignatureThreshold,
    #[error("capture signer {0} is revoked, outside validity, or outside machine/scenario scope")]
    SignerNotAuthorized(String),
    #[error("in-toto Statement does not bind the exact trial evidence subject set")]
    SubjectSetMismatch,
    #[error("capture predicate does not match the verifier-issued challenge and trial")]
    PredicateMismatch,
    #[error("TPM-backed evidence was supplied, but TPM quote verification is not qualified")]
    UnsupportedMachineAttestation,
    #[error("capture challenge ledger is invalid or insecure: {0}")]
    InvalidLedger(String),
    #[error("capture evidence input is invalid: {0}")]
    InvalidInput(String),
    #[error("capture evidence serialization failed: {0}")]
    Serialization(String),
}

pub type CaptureResult<T> = Result<T, CaptureAttestationError>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureTrustPolicy {
    pub schema: String,
    pub version: u32,
    pub policy_id: String,
    pub threshold: usize,
    pub signers: Vec<CaptureSigner>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSigner {
    pub key_id: String,
    pub issuer: String,
    pub public_key_hex: String,
    pub revoked: bool,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub allowed_machine_bindings: Vec<String>,
    pub allowed_scenarios: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureChallenge {
    pub schema: String,
    pub version: u32,
    pub challenge_id: String,
    pub nonce: String,
    pub corpus_sha256: String,
    pub source_commit_sha: String,
    pub flake_lock_sha256: String,
    pub capture_policy_sha256: String,
    pub trial_id: String,
    pub scenario_ids: Vec<String>,
    pub machine_binding_digest: String,
    pub capture_tool_sha256: String,
    pub evidence_set_sha256: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CaptureChallengeBody<'a> {
    nonce: &'a str,
    corpus_sha256: &'a str,
    source_commit_sha: &'a str,
    flake_lock_sha256: &'a str,
    capture_policy_sha256: &'a str,
    trial_id: &'a str,
    scenario_ids: &'a [String],
    machine_binding_digest: &'a str,
    capture_tool_sha256: &'a str,
    evidence_set_sha256: &'a str,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureSubject {
    pub name: String,
    pub digest: StrictDigestMap,
}

/// A duplicate-key rejecting JSON digest map. Ordinary BTreeMap deserialization
/// silently replaces duplicate JSON keys, which is undesirable for signed data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StrictDigestMap(pub BTreeMap<String, String>);

impl<'de> Deserialize<'de> for StrictDigestMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestMapVisitor;
        impl<'de> Visitor<'de> for DigestMapVisitor {
            type Value = StrictDigestMap;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object with unique digest algorithm keys")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!("duplicate digest key {key}")));
                    }
                }
                Ok(StrictDigestMap(values))
            }
        }
        deserializer.deserialize_map(DigestMapVisitor)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub type_uri: String,
    pub subject: Vec<CaptureSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: CapturePredicate,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapturePredicate {
    pub schema_version: u32,
    pub kind: String,
    pub trial_id: String,
    pub scenario_id: String,
    pub source_commit_sha: String,
    pub flake_lock_sha256: String,
    pub corpus_sha256: String,
    pub boot_id: String,
    pub machine_binding_digest: String,
    pub capture_tool_sha256: String,
    pub started_monotonic_ns: u64,
    pub finished_monotonic_ns: u64,
    pub captured_at_ms: u64,
    pub challenge_id: String,
    pub challenge_nonce: String,
    pub evidence_set_sha256: String,
    pub assurance_mode: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub keyid: Option<String>,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureVerificationReport {
    pub schema: String,
    pub version: u32,
    pub challenge_id: String,
    pub trial_id: String,
    pub scenario_id: String,
    pub envelope_sha256: String,
    pub trust_policy_sha256: String,
    pub evidence_set_sha256: String,
    pub integrity_verified: bool,
    pub capture_signature_verified: bool,
    pub challenge_nonce_verified: bool,
    pub machine_attestation_verified: bool,
    pub freshness_witness_verified: bool,
    pub assurance_mode: String,
    pub verified_signer_key_ids: Vec<String>,
    pub limitations: Vec<String>,
}

fn now_unix_ms() -> CaptureResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CaptureAttestationError::InvalidInput(format!("system clock: {error}")))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| CaptureAttestationError::InvalidInput("system time overflow".into()))
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_32(value: &str) -> CaptureResult<[u8; 32]> {
    if !valid_hex(value, 64) {
        return Err(CaptureAttestationError::InvalidInput("expected 32-byte lowercase hex".into()));
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CaptureAttestationError::InvalidInput("invalid hex".into()))?;
    }
    Ok(output)
}

fn decode_canonical_base64(value: &str) -> CaptureResult<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_ENVELOPE_BYTES {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| CaptureAttestationError::InvalidEnvelope)?;
    if BASE64_STANDARD.encode(&decoded) != value {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }
    Ok(decoded)
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload_type.len() + payload.len() + 64);
    output.extend_from_slice(b"DSSEv1 ");
    output.extend_from_slice(payload_type.as_bytes().len().to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload_type.as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload.len().to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload);
    output
}

pub fn validate_capture_trust_policy(policy: &CaptureTrustPolicy) -> CaptureResult<()> {
    if policy.schema != TRUST_POLICY_SCHEMA
        || policy.version != 1
        || policy.policy_id.trim().is_empty()
        || policy.threshold == 0
        || policy.signers.is_empty()
        || policy.signers.len() > MAX_SIGNERS
        || policy.threshold > policy.signers.len()
    {
        return Err(CaptureAttestationError::InvalidPolicy("schema, version, identity, threshold or signer count".into()));
    }
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut usable = 0usize;
    for signer in &policy.signers {
        if signer.key_id.trim().is_empty()
            || signer.issuer.trim().is_empty()
            || signer.not_before_ms >= signer.not_after_ms
            || !valid_hex(&signer.public_key_hex, 64)
            || signer.allowed_machine_bindings.is_empty()
            || signer.allowed_scenarios.is_empty()
            || signer.allowed_machine_bindings.iter().any(|value| !valid_hex(value, 64))
            || signer.allowed_scenarios.iter().any(|value| value.trim().is_empty())
            || signer.allowed_machine_bindings.iter().collect::<BTreeSet<_>>().len()
                != signer.allowed_machine_bindings.len()
            || signer.allowed_scenarios.iter().collect::<BTreeSet<_>>().len()
                != signer.allowed_scenarios.len()
            || !key_ids.insert(signer.key_id.as_str())
            || !public_keys.insert(signer.public_key_hex.as_str())
        {
            return Err(CaptureAttestationError::InvalidPolicy(
                "duplicate key identity or malformed signer scope".into(),
            ));
        }
        VerifyingKey::from_bytes(
            &parse_hex_32(&signer.public_key_hex)
                .map_err(|_| CaptureAttestationError::InvalidPolicy("malformed Ed25519 public key".into()))?,
        )
        .map_err(|_| CaptureAttestationError::InvalidPolicy("invalid Ed25519 public key".into()))?;
        if !signer.revoked {
            usable += 1;
        }
    }
    if policy.threshold > usable {
        return Err(CaptureAttestationError::InvalidPolicy(
            "threshold exceeds non-revoked signer count".into(),
        ));
    }
    Ok(())
}

pub fn verify_dsse_statement(
    envelope_bytes: &[u8],
    policy: &CaptureTrustPolicy,
    machine_binding_digest: &str,
    scenario_id: &str,
    captured_at_ms: u64,
) -> CaptureResult<(InTotoStatement, Vec<String>)> {
    validate_capture_trust_policy(policy)?;
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }
    let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|_| CaptureAttestationError::InvalidEnvelope)?;
    if envelope.payload_type != CAPTURE_PAYLOAD_TYPE
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > MAX_SIGNATURES
    {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }
    let payload = decode_canonical_base64(&envelope.payload)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }
    let pre_auth = dsse_pae(&envelope.payload_type, &payload);
    let statement: InTotoStatement = serde_json::from_slice(&payload)
        .map_err(|_| CaptureAttestationError::InvalidEnvelope)?;
    if statement.type_uri != IN_TOTO_STATEMENT_V1
        || statement.predicate_type != CAPTURE_PREDICATE_TYPE
        || statement.subject.is_empty()
    {
        return Err(CaptureAttestationError::InvalidEnvelope);
    }

    let predicate = &statement.predicate;
    if predicate.schema_version != 1
        || predicate.kind != "nixward-payload-release-capture-v1"
        || predicate.assurance_mode != "software_only"
    {
        return Err(if predicate.assurance_mode == "tpm2_quote" {
            CaptureAttestationError::UnsupportedMachineAttestation
        } else {
            CaptureAttestationError::PredicateMismatch
        });
    }
    if !valid_hex(machine_binding_digest, 64)
        || predicate.machine_binding_digest != machine_binding_digest
        || predicate.scenario_id != scenario_id
    {
        return Err(CaptureAttestationError::PredicateMismatch);
    }

    let mut verified_signers = BTreeSet::new();
    for signature_entry in &envelope.signatures {
        let signature_bytes = decode_canonical_base64(&signature_entry.sig)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| CaptureAttestationError::InvalidEnvelope)?;
        let mut matched = None;
        for signer in &policy.signers {
            let public_key = VerifyingKey::from_bytes(
                &parse_hex_32(&signer.public_key_hex)
                    .map_err(|_| CaptureAttestationError::InvalidPolicy("public key hex".into()))?,
            )
            .map_err(|_| CaptureAttestationError::InvalidPolicy("public key encoding".into()))?;
            if public_key.verify_strict(&pre_auth, &signature).is_ok() {
                matched = Some(signer);
                break;
            }
        }
        // Untrusted, invalid signatures do not contribute to threshold. The
        // keyid is deliberately not used as a trust filter: it is unauthenticated.
        let Some(signer) = matched else {
            continue;
        };
        if signer.revoked
            || captured_at_ms < signer.not_before_ms
            || captured_at_ms > signer.not_after_ms
            || !signer.allowed_machine_bindings.iter().any(|value| value == machine_binding_digest)
            || !signer.allowed_scenarios.iter().any(|value| value == scenario_id)
        {
            return Err(CaptureAttestationError::SignerNotAuthorized(signer.key_id.clone()));
        }
        verified_signers.insert(signer.key_id.clone());
    }
    if verified_signers.len() < policy.threshold {
        return Err(CaptureAttestationError::SignatureThreshold);
    }
    Ok((statement, verified_signers.into_iter().collect()))
}

fn challenge_body(challenge: &CaptureChallenge) -> CaptureChallengeBody<'_> {
    CaptureChallengeBody {
        nonce: &challenge.nonce,
        corpus_sha256: &challenge.corpus_sha256,
        source_commit_sha: &challenge.source_commit_sha,
        flake_lock_sha256: &challenge.flake_lock_sha256,
        capture_policy_sha256: &challenge.capture_policy_sha256,
        trial_id: &challenge.trial_id,
        scenario_ids: &challenge.scenario_ids,
        machine_binding_digest: &challenge.machine_binding_digest,
        capture_tool_sha256: &challenge.capture_tool_sha256,
        evidence_set_sha256: &challenge.evidence_set_sha256,
        issued_at_ms: challenge.issued_at_ms,
        expires_at_ms: challenge.expires_at_ms,
    }
}

fn derive_challenge_id(challenge: &CaptureChallenge) -> CaptureResult<String> {
    let bytes = serde_json::to_vec(&challenge_body(challenge))
        .map_err(|error| CaptureAttestationError::Serialization(error.to_string()))?;
    Ok(hash_domain(b"nixward-capture-challenge-v1\0", &bytes))
}

pub fn validate_capture_challenge(challenge: &CaptureChallenge, now_ms: u64) -> CaptureResult<()> {
    if challenge.schema != CHALLENGE_SCHEMA
        || challenge.version != 1
        || !valid_hex(&challenge.challenge_id, 64)
        || !valid_hex(&challenge.nonce, 64)
        || !valid_hex(&challenge.corpus_sha256, 64)
        || !valid_hex(&challenge.source_commit_sha, 40)
        || !valid_hex(&challenge.flake_lock_sha256, 64)
        || !valid_hex(&challenge.capture_policy_sha256, 64)
        || challenge.trial_id.trim().is_empty()
        || challenge.scenario_ids.is_empty()
        || challenge.scenario_ids.iter().any(|value| value.trim().is_empty())
        || challenge.scenario_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || !valid_hex(&challenge.machine_binding_digest, 64)
        || !valid_hex(&challenge.capture_tool_sha256, 64)
        || !valid_hex(&challenge.evidence_set_sha256, 64)
        || challenge.expires_at_ms <= challenge.issued_at_ms
        || challenge.expires_at_ms - challenge.issued_at_ms > MAX_CHALLENGE_TTL_MS
        || now_ms < challenge.issued_at_ms
        || now_ms > challenge.expires_at_ms
    {
        return Err(CaptureAttestationError::InvalidChallenge);
    }
    if derive_challenge_id(challenge)? != challenge.challenge_id {
        return Err(CaptureAttestationError::InvalidChallenge);
    }
    Ok(())
}

fn ensure_private_ledger_path(path: &Path) -> CaptureResult<()> {
    if !path.is_absolute() {
        return Err(CaptureAttestationError::InvalidLedger("ledger path must be absolute".into()));
    }
    let parent = path.parent()
        .ok_or_else(|| CaptureAttestationError::InvalidLedger("ledger path has no parent".into()))?;
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|error| CaptureAttestationError::InvalidLedger(format!("ledger parent: {error}")))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(CaptureAttestationError::InvalidLedger("ledger parent must be a real directory".into()));
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(CaptureAttestationError::InvalidLedger("ledger must be a regular non-symlink file".into()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if parent_meta.mode() & 0o077 != 0 {
            return Err(CaptureAttestationError::InvalidLedger(
                "ledger parent permissions must be private (no group/other access)".into(),
            ));
        }
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.mode() & 0o077 != 0 {
                return Err(CaptureAttestationError::InvalidLedger(
                    "ledger file permissions must be private (0600 or stricter)".into(),
                ));
            }
        }
    }
    Ok(())
}

pub struct CaptureChallengeLedger {
    path: PathBuf,
}

impl CaptureChallengeLedger {
    pub fn new(path: impl Into<PathBuf>) -> CaptureResult<Self> {
        let path = path.into();
        ensure_private_ledger_path(&path)?;
        let ledger = Self { path };
        let connection = ledger.connect()?;
        ledger.initialize_schema(&connection)?;
        Ok(ledger)
    }

    fn connect(&self) -> CaptureResult<Connection> {
        ensure_private_ledger_path(&self.path)?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        connection.pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        connection.pragma_update(None, "synchronous", "FULL")
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        connection.pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        connection.pragma_update(None, "trusted_schema", "OFF")
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        }
        Ok(connection)
    }

    fn initialize_schema(&self, connection: &Connection) -> CaptureResult<()> {
        let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        let user_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        if application_id == 0 && user_version == 0 {
            let objects: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            ).map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            if objects != 0 {
                return Err(CaptureAttestationError::InvalidLedger("unidentified database has user objects".into()));
            }
            connection.pragma_update(None, "application_id", LEDGER_APPLICATION_ID)
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            connection.pragma_update(None, "user_version", LEDGER_SCHEMA_VERSION)
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            connection.execute_batch(
                r#"
                CREATE TABLE issued_capture_challenges (
                    challenge_id TEXT PRIMARY KEY NOT NULL,
                    nonce_sha256 TEXT NOT NULL UNIQUE,
                    challenge_sha256 TEXT NOT NULL UNIQUE,
                    capture_policy_sha256 TEXT NOT NULL,
                    corpus_sha256 TEXT NOT NULL,
                    source_commit_sha TEXT NOT NULL,
                    trial_id TEXT NOT NULL,
                    scenario_id TEXT NOT NULL,
                    machine_binding_digest TEXT NOT NULL,
                    evidence_set_sha256 TEXT NOT NULL,
                    issued_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    consumed_at_ms INTEGER,
                    envelope_sha256 TEXT UNIQUE
                );
                CREATE TRIGGER issued_capture_challenges_no_delete
                BEFORE DELETE ON issued_capture_challenges
                BEGIN
                    SELECT RAISE(ABORT, 'capture challenges cannot be deleted');
                END;
                CREATE TRIGGER issued_capture_challenges_consume_once
                BEFORE UPDATE ON issued_capture_challenges
                WHEN OLD.consumed_at_ms IS NOT NULL
                  OR NEW.challenge_id != OLD.challenge_id
                  OR NEW.nonce_sha256 != OLD.nonce_sha256
                  OR NEW.challenge_sha256 != OLD.challenge_sha256
                  OR NEW.capture_policy_sha256 != OLD.capture_policy_sha256
                  OR NEW.corpus_sha256 != OLD.corpus_sha256
                  OR NEW.source_commit_sha != OLD.source_commit_sha
                  OR NEW.trial_id != OLD.trial_id
                  OR NEW.scenario_id != OLD.scenario_id
                  OR NEW.machine_binding_digest != OLD.machine_binding_digest
                  OR NEW.evidence_set_sha256 != OLD.evidence_set_sha256
                  OR NEW.issued_at_ms != OLD.issued_at_ms
                  OR NEW.expires_at_ms != OLD.expires_at_ms
                  OR NEW.consumed_at_ms IS NULL
                  OR NEW.envelope_sha256 IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'capture challenge is immutable and one-use');
                END;
                "#,
            ).map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                    .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            }
            return Ok(());
        }
        if application_id != LEDGER_APPLICATION_ID || user_version != LEDGER_SCHEMA_VERSION {
            return Err(CaptureAttestationError::InvalidLedger("unknown application ID or schema version".into()));
        }
        let objects: BTreeSet<(String, String)> = {
            let mut statement = connection.prepare("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
            rows.collect::<Result<_, _>>()
                .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?
        };
        let expected = BTreeSet::from([
            ("table".to_string(), "issued_capture_challenges".to_string()),
            ("trigger".to_string(), "issued_capture_challenges_no_delete".to_string()),
            ("trigger".to_string(), "issued_capture_challenges_consume_once".to_string()),
        ]);
        if objects != expected {
            return Err(CaptureAttestationError::InvalidLedger("challenge ledger schema inventory mismatch".into()));
        }
        Ok(())
    }

    pub fn issue(&self, challenge: &CaptureChallenge) -> CaptureResult<()> {
        let _now = now_unix_ms()?;
        if challenge.schema != CHALLENGE_SCHEMA
            || challenge.version != 1
            || derive_challenge_id(challenge)? != challenge.challenge_id
        {
            return Err(CaptureAttestationError::InvalidChallenge);
        }
        let challenge_json = serde_json::to_vec(challenge)
            .map_err(|error| CaptureAttestationError::Serialization(error.to_string()))?;
        let nonce_digest = sha256_hex(challenge.nonce.as_bytes());
        let connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        transaction.execute(
            r#"
            INSERT INTO issued_capture_challenges (
                challenge_id, nonce_sha256, challenge_sha256, capture_policy_sha256,
                corpus_sha256, source_commit_sha, trial_id, scenario_id,
                machine_binding_digest, evidence_set_sha256, issued_at_ms, expires_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                challenge.challenge_id,
                nonce_digest,
                sha256_hex(&challenge_json),
                challenge.capture_policy_sha256,
                challenge.corpus_sha256,
                challenge.source_commit_sha,
                challenge.trial_id,
                challenge.scenario_ids.first().cloned().unwrap_or_default(),
                challenge.machine_binding_digest,
                challenge.evidence_set_sha256,
                i64::try_from(challenge.issued_at_ms).map_err(|_| CaptureAttestationError::InvalidChallenge)?,
                i64::try_from(challenge.expires_at_ms).map_err(|_| CaptureAttestationError::InvalidChallenge)?,
            ],
        ).map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        transaction.commit().map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        Ok(())
    }

    pub fn consume(
        &self,
        challenge: &CaptureChallenge,
        envelope_sha256: &str,
        now_ms: u64,
    ) -> CaptureResult<()> {
        validate_capture_challenge(challenge, now_ms)?;
        if !valid_hex(envelope_sha256, 64) {
            return Err(CaptureAttestationError::InvalidInput("envelope digest".into()));
        }
        let challenge_json = serde_json::to_vec(challenge)
            .map_err(|error| CaptureAttestationError::Serialization(error.to_string()))?;
        let nonce_digest = sha256_hex(challenge.nonce.as_bytes());
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        let stored: Option<(String, String, String, String, String, String, String, String, i64, i64, Option<i64>)> =
            transaction.query_row(
                r#"
                SELECT nonce_sha256, challenge_sha256, capture_policy_sha256, corpus_sha256,
                       source_commit_sha, trial_id, scenario_id, machine_binding_digest,
                       issued_at_ms, expires_at_ms, consumed_at_ms
                FROM issued_capture_challenges WHERE challenge_id = ?1
                "#,
                [&challenge.challenge_id],
                |row| Ok((
                    row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,
                    row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?
                )),
            ).optional().map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        let Some((stored_nonce, stored_sha, policy_sha, corpus_sha, source_sha, trial_id, scenario_id, machine, issued, expires, consumed)) = stored else {
            return Err(CaptureAttestationError::InvalidChallenge);
        };
        if stored_nonce != nonce_digest
            || stored_sha != sha256_hex(&challenge_json)
            || policy_sha != challenge.capture_policy_sha256
            || corpus_sha != challenge.corpus_sha256
            || source_sha != challenge.source_commit_sha
            || trial_id != challenge.trial_id
            || scenario_id != challenge.scenario_ids.first().cloned().unwrap_or_default()
            || machine != challenge.machine_binding_digest
            || issued != i64::try_from(challenge.issued_at_ms).unwrap_or(-1)
            || expires != i64::try_from(challenge.expires_at_ms).unwrap_or(-1)
        {
            return Err(CaptureAttestationError::InvalidChallenge);
        }
        if consumed.is_some() {
            return Err(CaptureAttestationError::ChallengeReplay);
        }
        transaction.execute(
            "UPDATE issued_capture_challenges SET consumed_at_ms = ?1, envelope_sha256 = ?2 WHERE challenge_id = ?3",
            params![
                i64::try_from(now_ms).map_err(|_| CaptureAttestationError::InvalidChallenge)?,
                envelope_sha256,
                challenge.challenge_id,
            ],
        ).map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        transaction.commit().map_err(|error| CaptureAttestationError::InvalidLedger(error.to_string()))?;
        Ok(())
    }
}

pub fn new_capture_challenge(
    corpus_sha256: String,
    source_commit_sha: String,
    flake_lock_sha256: String,
    capture_policy_sha256: String,
    trial_id: String,
    scenario_id: String,
    machine_binding_digest: String,
    capture_tool_sha256: String,
    evidence_set_sha256: String,
    issued_at_ms: u64,
    ttl_ms: u64,
) -> CaptureResult<CaptureChallenge> {
    if !valid_hex(&corpus_sha256, 64)
        || !valid_hex(&source_commit_sha, 40)
        || !valid_hex(&flake_lock_sha256, 64)
        || !valid_hex(&capture_policy_sha256, 64)
        || !valid_hex(&machine_binding_digest, 64)
        || !valid_hex(&capture_tool_sha256, 64)
        || !valid_hex(&evidence_set_sha256, 64)
        || trial_id.trim().is_empty()
        || scenario_id.trim().is_empty()
        || ttl_ms == 0
        || ttl_ms > MAX_CHALLENGE_TTL_MS
    {
        return Err(CaptureAttestationError::InvalidInput("challenge request".into()));
    }
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| CaptureAttestationError::InvalidInput(format!("secure random source: {error}")))?;
    let nonce_hex = nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let expires_at_ms = issued_at_ms.checked_add(ttl_ms)
        .ok_or(CaptureAttestationError::InvalidInput("challenge expiry overflow".into()))?;
    let mut challenge = CaptureChallenge {
        schema: CHALLENGE_SCHEMA.into(),
        version: 1,
        challenge_id: "0".repeat(64),
        nonce: nonce_hex,
        corpus_sha256,
        source_commit_sha,
        flake_lock_sha256,
        capture_policy_sha256,
        trial_id,
        scenario_ids: vec![scenario_id],
        machine_binding_digest,
        capture_tool_sha256,
        evidence_set_sha256,
        issued_at_ms,
        expires_at_ms,
    };
    challenge.challenge_id = derive_challenge_id(&challenge)?;
    Ok(challenge)
}

pub fn compute_evidence_set_sha256(subjects: &[CaptureSubject]) -> CaptureResult<String> {
    let mut sorted = subjects.to_vec();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    if sorted.is_empty()
        || sorted.iter().any(|subject| {
            subject.name.trim().is_empty()
                || subject.digest.0.get("sha256").is_none_or(|value| !valid_hex(value, 64))
                || subject.digest.0.len() != 1
        })
        || sorted.windows(2).any(|pair| pair[0].name == pair[1].name)
    {
        return Err(CaptureAttestationError::InvalidInput("evidence subject set".into()));
    }
    let encoded = serde_json::to_vec(&sorted)
        .map_err(|error| CaptureAttestationError::Serialization(error.to_string()))?;
    Ok(hash_domain(b"nixward-capture-evidence-subject-set-v1\0", &encoded))
}

pub fn verify_capture_attestation(
    envelope_bytes: &[u8],
    trust_policy_bytes: &[u8],
    challenge: &CaptureChallenge,
    expected_subjects: &[CaptureSubject],
    expected: &CapturePredicate,
    ledger: &CaptureChallengeLedger,
    now_ms: u64,
) -> CaptureResult<CaptureVerificationReport> {
    if trust_policy_bytes.len() > MAX_POLICY_BYTES {
        return Err(CaptureAttestationError::InvalidPolicy("policy size limit".into()));
    }
    let trust_policy: CaptureTrustPolicy = serde_json::from_slice(trust_policy_bytes)
        .map_err(|error| CaptureAttestationError::InvalidPolicy(error.to_string()))?;
    validate_capture_trust_policy(&trust_policy)?;
    let policy_sha = sha256_hex(trust_policy_bytes);
    validate_capture_challenge(challenge, now_ms)?;
    if challenge.capture_policy_sha256 != policy_sha {
        return Err(CaptureAttestationError::PolicyDigestMismatch);
    }
    let evidence_digest = compute_evidence_set_sha256(expected_subjects)?;
    if evidence_digest != challenge.evidence_set_sha256 {
        return Err(CaptureAttestationError::InvalidChallenge);
    }
    let (statement, verified_signer_key_ids) = verify_dsse_statement(
        envelope_bytes,
        &trust_policy,
        &challenge.machine_binding_digest,
        &challenge.scenario_ids[0],
        now_ms,
    )?;
    let predicate = &statement.predicate;
    let mut subjects = statement.subject.clone();
    subjects.sort_by(|left, right| left.name.cmp(&right.name));
    let mut expected_sorted = expected_subjects.to_vec();
    expected_sorted.sort_by(|left, right| left.name.cmp(&right.name));
    if subjects != expected_sorted {
        return Err(CaptureAttestationError::SubjectSetMismatch);
    }
    if predicate.trial_id != challenge.trial_id
        || predicate.scenario_id != challenge.scenario_ids[0]
        || predicate.source_commit_sha != challenge.source_commit_sha
        || predicate.flake_lock_sha256 != challenge.flake_lock_sha256
        || predicate.corpus_sha256 != challenge.corpus_sha256
        || predicate.machine_binding_digest != challenge.machine_binding_digest
        || predicate.capture_tool_sha256 != challenge.capture_tool_sha256
        || predicate.challenge_id != challenge.challenge_id
        || predicate.challenge_nonce != challenge.nonce
        || predicate.evidence_set_sha256 != evidence_digest
        || predicate.started_monotonic_ns >= predicate.finished_monotonic_ns
        || predicate.captured_at_ms < challenge.issued_at_ms
        || predicate.captured_at_ms > challenge.expires_at_ms
        || predicate.captured_at_ms > now_ms
        || !valid_hex(&predicate.source_commit_sha, 40)
        || !valid_hex(&predicate.flake_lock_sha256, 64)
        || !valid_hex(&predicate.corpus_sha256, 64)
        || !valid_hex(&predicate.boot_id, 36)
        || !valid_hex(&predicate.machine_binding_digest, 64)
        || !valid_hex(&predicate.capture_tool_sha256, 64)
    {
        return Err(CaptureAttestationError::PredicateMismatch);
    }
    let envelope_sha = sha256_hex(envelope_bytes);
    // Consume only after all signature, subject, predicate and trust checks have
    // succeeded. The ledger uses BEGIN IMMEDIATE and a unique challenge ID.
    ledger.consume(challenge, &envelope_sha, now_ms)?;
    Ok(CaptureVerificationReport {
        schema: REPORT_SCHEMA.into(),
        version: 1,
        challenge_id: challenge.challenge_id.clone(),
        trial_id: challenge.trial_id.clone(),
        scenario_id: challenge.scenario_ids[0].clone(),
        envelope_sha256: envelope_sha,
        trust_policy_sha256: policy_sha,
        evidence_set_sha256: evidence_digest,
        integrity_verified: true,
        capture_signature_verified: true,
        challenge_nonce_verified: true,
        machine_attestation_verified: false,
        freshness_witness_verified: false,
        assurance_mode: "software_only".into(),
        verified_signer_key_ids,
        limitations: vec![
            "DSSE verifies the configured capture key signature, not that the signing host was uncompromised.".into(),
            "Software-held capture keys do not constitute hardware-backed machine attestation.".into(),
            "No remote transparency or trusted timestamp witness was supplied.".into(),
            "The local one-use challenge ledger is not a TPM or remote anti-rollback anchor.".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn signer(seed: u8, key_id: &str) -> (SigningKey, CaptureSigner) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let capture = CaptureSigner {
            key_id: key_id.into(),
            issuer: "capture-team".into(),
            public_key_hex: hex(signing.verifying_key().as_bytes()),
            revoked: false,
            not_before_ms: 1_000,
            not_after_ms: 9_000,
            allowed_machine_bindings: vec![digest('a')],
            allowed_scenarios: vec!["barrier-create-clean".into()],
        };
        (signing, capture)
    }

    fn policy(signers: Vec<CaptureSigner>, threshold: usize) -> CaptureTrustPolicy {
        CaptureTrustPolicy {
            schema: TRUST_POLICY_SCHEMA.into(),
            version: 1,
            policy_id: "capture-root-2026-01".into(),
            threshold,
            signers,
        }
    }

    fn context_subjects() -> Vec<CaptureSubject> {
        vec![
            CaptureSubject { name: "events.json".into(), digest: StrictDigestMap(BTreeMap::from([("sha256".into(), digest('b'))])) },
            CaptureSubject { name: "snapshot.sqlite3".into(), digest: StrictDigestMap(BTreeMap::from([("sha256".into(), digest('c'))])) },
        ]
    }

    fn statement(challenge: &CaptureChallenge, subjects: Vec<CaptureSubject>) -> InTotoStatement {
        InTotoStatement {
            type_uri: IN_TOTO_STATEMENT_V1.into(),
            subject: subjects,
            predicate_type: CAPTURE_PREDICATE_TYPE.into(),
            predicate: CapturePredicate {
                schema_version: 1,
                kind: "nixward-payload-release-capture-v1".into(),
                trial_id: challenge.trial_id.clone(),
                scenario_id: challenge.scenario_ids[0].clone(),
                source_commit_sha: challenge.source_commit_sha.clone(),
                flake_lock_sha256: challenge.flake_lock_sha256.clone(),
                corpus_sha256: challenge.corpus_sha256.clone(),
                boot_id: "00000000-0000-0000-0000-000000000001".into(),
                machine_binding_digest: challenge.machine_binding_digest.clone(),
                capture_tool_sha256: challenge.capture_tool_sha256.clone(),
                started_monotonic_ns: 100,
                finished_monotonic_ns: 200,
                captured_at_ms: 2_000,
                challenge_id: challenge.challenge_id.clone(),
                challenge_nonce: challenge.nonce.clone(),
                evidence_set_sha256: challenge.evidence_set_sha256.clone(),
                assurance_mode: "software_only".into(),
            },
        }
    }

    fn envelope(statement: &InTotoStatement, signers: &[(&str, &SigningKey)]) -> Vec<u8> {
        let payload = serde_json::to_vec(statement).unwrap();
        let pae = dsse_pae(CAPTURE_PAYLOAD_TYPE, &payload);
        let signatures = signers.iter().map(|(key_id, signing)| DsseSignature {
            keyid: Some((*key_id).into()),
            sig: BASE64_STANDARD.encode(signing.sign(&pae).to_bytes()),
        }).collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "payloadType": CAPTURE_PAYLOAD_TYPE,
            "payload": BASE64_STANDARD.encode(payload),
            "signatures": signatures
        })).unwrap()
    }

    fn challenge(subjects: &[CaptureSubject]) -> CaptureChallenge {
        let subjects_digest = compute_evidence_set_sha256(subjects).unwrap();
        let policy_sha = digest('d');
        new_capture_challenge(
            digest('e'),
            "f".repeat(40),
            digest('1'),
            policy_sha,
            "trial-1".into(),
            "barrier-create-clean".into(),
            digest('a'),
            digest('2'),
            subjects_digest,
            1_500,
            5_000,
        ).unwrap()
    }

    #[test]
    fn dsse_pae_uses_byte_lengths_and_binds_payload_type() {
        let payload_type = "application/vnd.in-toto+json";
        let payload = "{"snow":"☃"}".as_bytes();
        let pae = dsse_pae(payload_type, payload);
        let expected = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len());
        assert!(pae.starts_with(expected.as_bytes()));
        assert!(pae.ends_with(payload));
        assert_ne!(dsse_pae("application/vnd.other+json", payload), pae);
    }

    #[test]
    fn trust_policy_rejects_duplicate_public_key_aliases() {
        let (_, first) = signer(7, "capture-a");
        let mut second = first.clone();
        second.key_id = "capture-b".into();
        assert!(validate_capture_trust_policy(&policy(vec![first, second], 2)).is_err());
    }

    #[test]
    fn dsse_threshold_counts_distinct_keys_not_signature_entries() {
        let (signing, trusted) = signer(7, "capture-a");
        let trust = policy(vec![trusted], 2);
        let statement = statement(&challenge(&context_subjects()), context_subjects());
        let bytes = envelope(&statement, &[("capture-a", &signing), ("capture-a", &signing)]);
        assert!(matches!(
            verify_dsse_statement(&bytes, &trust, &digest('a'), "barrier-create-clean", 2_000),
            Err(CaptureAttestationError::SignatureThreshold)
        ));
    }

    #[test]
    fn wrong_keyid_is_only_a_hint_and_does_not_exclude_valid_signature() {
        let (signing, trusted) = signer(7, "capture-a");
        let trust = policy(vec![trusted], 1);
        let statement = statement(&challenge(&context_subjects()), context_subjects());
        let bytes = envelope(&statement, &[("attacker-controlled-key-hint", &signing)]);
        let (_, accepted) = verify_dsse_statement(&bytes, &trust, &digest('a'), "barrier-create-clean", 2_000).unwrap();
        assert_eq!(accepted, vec!["capture-a"]);
    }

    #[test]
    fn changed_payload_type_or_signature_bytes_is_rejected() {
        let (signing, trusted) = signer(7, "capture-a");
        let trust = policy(vec![trusted], 1);
        let statement = statement(&challenge(&context_subjects()), context_subjects());
        let mut value: serde_json::Value = serde_json::from_slice(&envelope(&statement, &[("capture-a", &signing)])).unwrap();
        value["payloadType"] = serde_json::Value::String("application/json".into());
        assert!(verify_dsse_statement(&serde_json::to_vec(&value).unwrap(), &trust, &digest('a'), "barrier-create-clean", 2_000).is_err());
    }

    #[test]
    fn revoked_or_out_of_scope_signer_cannot_satisfy_threshold() {
        let (signing, mut trusted) = signer(7, "capture-a");
        trusted.revoked = true;
        let trust = policy(vec![trusted], 1);
        let statement = statement(&challenge(&context_subjects()), context_subjects());
        let bytes = envelope(&statement, &[("capture-a", &signing)]);
        assert!(matches!(
            verify_dsse_statement(&bytes, &trust, &digest('a'), "barrier-create-clean", 2_000),
            Err(CaptureAttestationError::SignerNotAuthorized(_))
        ));
    }

    #[test]
    fn challenge_id_changes_when_nonce_or_evidence_set_changes() {
        let subjects = context_subjects();
        let first = challenge(&subjects);
        let mut tampered = first.clone();
        tampered.nonce = digest('f');
        assert!(validate_capture_challenge(&tampered, 2_000).is_err());
        assert_ne!(first.challenge_id, derive_challenge_id(&tampered).unwrap());
    }

    #[test]
    fn tpm_claim_fails_closed_instead_of_claiming_hardware_attestation() {
        let (signing, trusted) = signer(7, "capture-a");
        let trust = policy(vec![trusted], 1);
        let mut statement = statement(&challenge(&context_subjects()), context_subjects());
        statement.predicate.assurance_mode = "tpm2_quote".into();
        let bytes = envelope(&statement, &[("capture-a", &signing)]);
        assert!(matches!(
            verify_dsse_statement(&bytes, &trust, &digest('a'), "barrier-create-clean", 2_000),
            Err(CaptureAttestationError::UnsupportedMachineAttestation)
        ));
    }

    #[test]
    fn duplicate_digest_keys_are_rejected_in_statement_subject() {
        let json = br#"{"name":"x","digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        assert!(serde_json::from_slice::<CaptureSubject>(json).is_err());
    }

    #[test]
    fn challenge_ledger_consumes_nonce_once() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capture-ledger/challenges.sqlite3");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ledger = CaptureChallengeLedger::new(path).unwrap();
        let subjects = context_subjects();
        let mut challenge = challenge(&subjects);
        // Ledger-issued challenge ID and payload are deterministic for this fixture.
        challenge.challenge_id = derive_challenge_id(&challenge).unwrap();
        ledger.issue(&challenge).unwrap();
        ledger.consume(&challenge, &digest('9'), 2_000).unwrap();
        assert!(matches!(
            ledger.consume(&challenge, &digest('8'), 2_001),
            Err(CaptureAttestationError::ChallengeReplay)
        ));
    }
}
