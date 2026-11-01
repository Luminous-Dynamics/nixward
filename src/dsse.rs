// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline DSSE v1 and in-toto Statement v1 verification.
//!
//! Trust anchors are supplied by the caller from a separately pinned local
//! policy. No key discovery or network access occurs. DSSE signature key IDs
//! are unauthenticated hints and are never treated as proof of signer identity.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const DSSE_IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const TRUST_POLICY_SCHEMA: &str = "org.luminousdynamics.nixward.dsse-trust-policy";
pub const NIXWARD_SOURCE_EVIDENCE_PREDICATE_TYPE: &str =
    "https://luminousdynamics.io/attestations/nixward-source-evidence/v1";
pub const NIXWARD_SOURCE_SUBJECT_DIGEST_ALGORITHM: &str = "sha256";
const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 12 * 1024 * 1024;
const MAX_SIGNATURES: usize = 64;
const MAX_TRUSTED_KEYS: usize = 64;
const MAX_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DsseVerificationError {
    #[error("the separately pinned trust-policy digest does not match")]
    TrustPolicyDigestMismatch,
    #[error("trust policy is malformed, unsupported or internally inconsistent")]
    InvalidTrustPolicy,
    #[error("trust policy is not currently valid")]
    TrustPolicyExpired,
    #[error("DSSE envelope is malformed or exceeds a configured limit")]
    InvalidEnvelope,
    #[error("DSSE payload type is not the exact expected in-toto JSON type")]
    UnsupportedPayloadType,
    #[error("DSSE payload is malformed or exceeds a configured limit")]
    InvalidPayload,
    #[error("no trusted, non-revoked key verified the DSSE PAE")]
    InvalidSignature,
    #[error("the distinct trusted signer threshold was not met")]
    InsufficientSignatures,
    #[error("the signed payload is not the expected in-toto Statement v1")]
    InvalidStatement,
    #[error("the signed predicate type is not allowed by the local policy and request")]
    UnsupportedPredicateType,
    #[error("the signed Statement does not bind the expected subject name and digest")]
    SubjectMismatch,
    #[error("the source repository, commit, flake-lock or corpus claims do not match expected inputs")]
    SourceProvenanceMismatch,
    #[error("the source attestation names an unexpected builder identity")]
    SourceBuilderMismatch,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseTrustPolicy {
    pub schema: String,
    pub version: u32,
    pub policy_id: String,
    pub epoch: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub signature_threshold: usize,
    pub allowed_payload_types: Vec<String>,
    pub allowed_predicate_types: Vec<String>,
    pub keys: Vec<DsseTrustedKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseTrustedKey {
    /// SHA-256 of the raw 32-byte Ed25519 public key, lowercase hexadecimal.
    /// This is a local trust-policy identifier, not the envelope keyid hint.
    pub key_id: String,
    /// Base64 of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    pub revoked: bool,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub allowed_predicate_types: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct InTotoExpectation<'a> {
    pub payload_type: &'a str,
    pub predicate_type: &'a str,
    pub subject_name: &'a str,
    pub subject_digest_algorithm: &'a str,
    pub subject_digest: &'a str,
}

/// Runtime-only result. It is deliberately not serializable/deserializable:
/// callers cannot reconstruct verified status from JSON or a database row.
#[derive(Debug, Clone)]
pub struct VerifiedDsseAttestation {
    payload_type: String,
    payload_bytes: Vec<u8>,
    statement: Value,
    predicate_type: String,
    subject_name: String,
    subject_digest_algorithm: String,
    subject_digest: String,
    verified_key_ids: Vec<String>,
    trust_policy_id: String,
    trust_policy_epoch: u64,
    trust_policy_sha256: String,
}

impl VerifiedDsseAttestation {
    pub fn payload_type(&self) -> &str { &self.payload_type }
    /// Exact bytes whose PAE was verified and then parsed into statement.
    pub fn payload_bytes(&self) -> &[u8] { &self.payload_bytes }
    pub fn statement(&self) -> &Value { &self.statement }
    pub fn predicate_type(&self) -> &str { &self.predicate_type }
    pub fn subject_name(&self) -> &str { &self.subject_name }
    pub fn subject_digest_algorithm(&self) -> &str { &self.subject_digest_algorithm }
    pub fn subject_digest(&self) -> &str { &self.subject_digest }
    /// Identities of trusted keys that actually verified a distinct signature.
    /// Envelope keyid hints are deliberately not returned.
    pub fn verified_key_ids(&self) -> &[String] { &self.verified_key_ids }
    pub fn trust_policy_id(&self) -> &str { &self.trust_policy_id }
    pub fn trust_policy_epoch(&self) -> u64 { self.trust_policy_epoch }
    pub fn trust_policy_sha256(&self) -> &str { &self.trust_policy_sha256 }
}


#[derive(Debug, Clone, Copy)]
pub struct NixwardSourceEvidenceExpectation<'a> {
    /// Exact in-toto subject name for the produced artifact or closure manifest.
    pub subject_name: &'a str,
    /// SHA-256 of the exact produced artifact or closure-manifest bytes.
    pub subject_digest_sha256: &'a str,
    pub repository_uri: &'a str,
    pub source_commit_sha: &'a str,
    pub flake_lock_sha256: &'a str,
    pub corpus_sha256: &'a str,
    pub builder_id: &'a str,
}

/// Runtime-only typed view. The wrapped attestation is non-serializable and
/// contains the exact payload bytes whose DSSE signature was verified.
#[derive(Debug, Clone)]
pub struct VerifiedNixwardSourceEvidence {
    attestation: VerifiedDsseAttestation,
}

impl VerifiedNixwardSourceEvidence {
    pub fn attestation(&self) -> &VerifiedDsseAttestation {
        &self.attestation
    }

    pub fn repository_uri(&self) -> &str {
        self.attestation.statement["predicate"]["source"]["repository_uri"]
            .as_str().unwrap_or_default()
    }

    pub fn source_commit_sha(&self) -> &str {
        self.attestation.statement["predicate"]["source"]["commit_sha"]
            .as_str().unwrap_or_default()
    }

    pub fn flake_lock_sha256(&self) -> &str {
        self.attestation.statement["predicate"]["materials"]["flake_lock_sha256"]
            .as_str().unwrap_or_default()
    }

    pub fn corpus_sha256(&self) -> &str {
        self.attestation.statement["predicate"]["materials"]["corpus_sha256"]
            .as_str().unwrap_or_default()
    }

    pub fn builder_id(&self) -> &str {
        self.attestation.statement["predicate"]["builder"]["id"]
            .as_str().unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsseEnvelope {
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

// DSSE envelope parsers tolerate extension fields. The optional keyid is
// intentionally parsed but never used to authorize or identify the signer.
#[derive(Debug, Deserialize)]
struct DsseSignature {
    sig: String,
    #[allow(dead_code)]
    keyid: Option<String>,
}


#[derive(Debug)]
struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> serde::de::Visitor<'de> for UniqueVisitor {
            type Value = UniqueJsonValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON with no duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(UniqueJsonValue(Value::Number(number)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    let value = map.next_value::<UniqueJsonValue>()?;
                    values.insert(key, value.0);
                }
                Ok(UniqueJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, DsseVerificationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| DsseVerificationError::InvalidStatement)?;
    deserializer.end().map_err(|_| DsseVerificationError::InvalidStatement)?;
    Ok(parsed.0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, DsseVerificationError> {
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(value) { return Ok(bytes); }
    }
    Err(DsseVerificationError::InvalidEnvelope)
}

/// DSSE v1 Pre-Authentication Encoding. Lengths count bytes, not characters.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let mut encoded = Vec::with_capacity(
        6 + 1 + 20 + 1 + type_bytes.len() + 1 + 20 + 1 + payload.len(),
    );
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(type_bytes.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(type_bytes);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_public_key(key: &DsseTrustedKey) -> Result<VerifyingKey, DsseVerificationError> {
    let raw = decode_base64(&key.public_key).map_err(|_| DsseVerificationError::InvalidTrustPolicy)?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| DsseVerificationError::InvalidTrustPolicy)?;
    if !valid_hex(&key.key_id, 64) || sha256_hex(&raw) != key.key_id {
        return Err(DsseVerificationError::InvalidTrustPolicy);
    }
    VerifyingKey::from_bytes(&raw).map_err(|_| DsseVerificationError::InvalidTrustPolicy)
}

fn validate_policy(
    policy: &DsseTrustPolicy,
    now_ms: u64,
) -> Result<Vec<(String, VerifyingKey, &DsseTrustedKey)>, DsseVerificationError> {
    if policy.schema != TRUST_POLICY_SCHEMA
        || policy.version != 1
        || policy.policy_id.trim().is_empty()
        || policy.epoch == 0
        || policy.not_before_ms >= policy.not_after_ms
        || now_ms < policy.not_before_ms
        || now_ms > policy.not_after_ms
        || policy.signature_threshold == 0
        || policy.keys.is_empty()
        || policy.keys.len() > MAX_TRUSTED_KEYS
        || policy.allowed_payload_types.is_empty()
        || policy.allowed_predicate_types.is_empty()
    {
        return Err(if now_ms < policy.not_before_ms || now_ms > policy.not_after_ms {
            DsseVerificationError::TrustPolicyExpired
        } else {
            DsseVerificationError::InvalidTrustPolicy
        });
    }

    let mut key_ids = BTreeSet::new();
    let mut public_key_ids = BTreeSet::new();
    let mut payload_types = BTreeSet::new();
    let mut predicate_types = BTreeSet::new();
    for value in &policy.allowed_payload_types {
        if value.trim().is_empty() || !payload_types.insert(value.as_str()) {
            return Err(DsseVerificationError::InvalidTrustPolicy);
        }
    }
    for value in &policy.allowed_predicate_types {
        if value.trim().is_empty() || !predicate_types.insert(value.as_str()) {
            return Err(DsseVerificationError::InvalidTrustPolicy);
        }
    }

    let mut validated = Vec::with_capacity(policy.keys.len());
    let mut eligible = 0_usize;
    for key in &policy.keys {
        if key.not_before_ms >= key.not_after_ms
            || key.key_id.trim().is_empty()
            || key.allowed_predicate_types.is_empty()
            || key.allowed_predicate_types.iter().any(|value| {
                value.trim().is_empty() || !predicate_types.contains(value.as_str())
            })
            || !key_ids.insert(key.key_id.as_str())
        {
            return Err(DsseVerificationError::InvalidTrustPolicy);
        }
        let verifying_key = decode_public_key(key)?;
        if !public_key_ids.insert(key.key_id.as_str()) {
            return Err(DsseVerificationError::InvalidTrustPolicy);
        }
        if !key.revoked && now_ms >= key.not_before_ms && now_ms <= key.not_after_ms {
            eligible += 1;
        }
        validated.push((key.key_id.clone(), verifying_key, key));
    }
    if policy.signature_threshold > eligible {
        return Err(DsseVerificationError::InvalidTrustPolicy);
    }
    Ok(validated)
}

/// Verify a DSSE envelope containing an in-toto Statement v1.
///
/// The trust-policy digest must come from an independent local pin. The policy
/// is not accepted from the artifact root and no network discovery occurs.
/// The threshold counts distinct locally trusted Ed25519 keys only.
pub fn verify_in_toto_dsse(
    envelope_bytes: &[u8],
    trust_policy_bytes: &[u8],
    trust_policy_sha256: &str,
    now_ms: u64,
    expected: InTotoExpectation<'_>,
) -> Result<VerifiedDsseAttestation, DsseVerificationError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(DsseVerificationError::InvalidEnvelope);
    }
    if trust_policy_bytes.is_empty() || trust_policy_bytes.len() > MAX_POLICY_BYTES
        || !valid_hex(trust_policy_sha256, 64)
        || sha256_hex(trust_policy_bytes) != trust_policy_sha256
    {
        return Err(DsseVerificationError::TrustPolicyDigestMismatch);
    }

    let policy: DsseTrustPolicy = serde_json::from_slice(trust_policy_bytes)
        .map_err(|_| DsseVerificationError::InvalidTrustPolicy)?;
    let keys = validate_policy(&policy, now_ms)?;
    if expected.payload_type != DSSE_IN_TOTO_PAYLOAD_TYPE
        || !policy.allowed_payload_types.iter().any(|value| value == expected.payload_type)
    {
        return Err(DsseVerificationError::UnsupportedPayloadType);
    }
    if expected.predicate_type.trim().is_empty()
        || expected.subject_name.trim().is_empty()
        || expected.subject_digest_algorithm != "sha256"
        || !valid_hex(expected.subject_digest, 64)
        || !policy.allowed_predicate_types.iter().any(|value| value == expected.predicate_type)
    {
        return Err(DsseVerificationError::UnsupportedPredicateType);
    }

    let envelope: DsseEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|_| DsseVerificationError::InvalidEnvelope)?;
    if envelope.payload_type != expected.payload_type
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > MAX_SIGNATURES
    {
        return Err(DsseVerificationError::UnsupportedPayloadType);
    }
    let payload = decode_base64(&envelope.payload).map_err(|_| DsseVerificationError::InvalidPayload)?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DsseVerificationError::InvalidPayload);
    }
    let pre_auth = pae(&envelope.payload_type, &payload);
    let mut verified_key_ids = BTreeSet::new();
    for entry in &envelope.signatures {
        let signature_bytes = decode_base64(&entry.sig).map_err(|_| DsseVerificationError::InvalidEnvelope)?;
        if signature_bytes.len() != 64 {
            return Err(DsseVerificationError::InvalidEnvelope);
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| DsseVerificationError::InvalidEnvelope)?;
        for (key_id, verifying_key, trusted_key) in &keys {
            if trusted_key.revoked
                || now_ms < trusted_key.not_before_ms
                || now_ms > trusted_key.not_after_ms
                || !trusted_key.allowed_predicate_types.iter()
                    .any(|value| value == expected.predicate_type)
            {
                continue;
            }
            if verifying_key.verify_strict(&pre_auth, &signature).is_ok() {
                verified_key_ids.insert(key_id.clone());
            }
        }
    }
    if verified_key_ids.is_empty() {
        return Err(DsseVerificationError::InvalidSignature);
    }
    if verified_key_ids.len() < policy.signature_threshold {
        return Err(DsseVerificationError::InsufficientSignatures);
    }

    // Parse the exact bytes whose PAE was verified. Never re-read the envelope
    // to obtain an application-level payload after signature verification.
    let statement = parse_unique_json(&payload)?;
    if statement.get("_type").and_then(Value::as_str) != Some(IN_TOTO_STATEMENT_V1) {
        return Err(DsseVerificationError::InvalidStatement);
    }
    if statement.get("predicateType").and_then(Value::as_str) != Some(expected.predicate_type) {
        return Err(DsseVerificationError::UnsupportedPredicateType);
    }
    let subjects = statement.get("subject").and_then(Value::as_array)
        .ok_or(DsseVerificationError::InvalidStatement)?;
    let matching = subjects.iter().filter(|subject| {
        subject.get("name").and_then(Value::as_str) == Some(expected.subject_name)
            && subject.get("digest")
                .and_then(|digest| digest.get(expected.subject_digest_algorithm))
                .and_then(Value::as_str) == Some(expected.subject_digest)
    }).count();
    if matching != 1 {
        return Err(DsseVerificationError::SubjectMismatch);
    }
    if statement.get("predicate").and_then(Value::as_object).is_none() {
        return Err(DsseVerificationError::InvalidStatement);
    }

    Ok(VerifiedDsseAttestation {
        payload_type: envelope.payload_type,
        payload_bytes: payload,
        statement,
        predicate_type: expected.predicate_type.to_string(),
        subject_name: expected.subject_name.to_string(),
        subject_digest_algorithm: expected.subject_digest_algorithm.to_string(),
        subject_digest: expected.subject_digest.to_string(),
        verified_key_ids: verified_key_ids.into_iter().collect(),
        trust_policy_id: policy.policy_id,
        trust_policy_epoch: policy.epoch,
        trust_policy_sha256: trust_policy_sha256.to_string(),
    })
}


/// Deterministic subject digest for the exact source/build inputs. The
/// domain-separated, length-prefixed encoding prevents concatenation ambiguity.
pub fn nixward_source_inputs_digest_sha256(
    repository_uri: &str,
    source_commit_sha: &str,
    flake_lock_sha256: &str,
    corpus_sha256: &str,
) -> Result<String, DsseVerificationError> {
    if repository_uri.trim().is_empty()
        || !(valid_hex(source_commit_sha, 40) || valid_hex(source_commit_sha, 64))
        || !valid_hex(flake_lock_sha256, 64)
        || !valid_hex(corpus_sha256, 64)
    {
        return Err(DsseVerificationError::SourceProvenanceMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"nixward-source-inputs-subject-v1\0");
    for field in [
        repository_uri.as_bytes(),
        source_commit_sha.as_bytes(),
        flake_lock_sha256.as_bytes(),
        corpus_sha256.as_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Verify the signed Nixward-specific source-evidence predicate after generic
/// DSSE and in-toto Statement verification. All values are checked against
/// independent caller-provided expectations.
pub fn verify_nixward_source_evidence(
    envelope_bytes: &[u8],
    trust_policy_bytes: &[u8],
    trust_policy_sha256: &str,
    now_ms: u64,
    expected: NixwardSourceEvidenceExpectation<'_>,
) -> Result<VerifiedNixwardSourceEvidence, DsseVerificationError> {
    if expected.subject_name.trim().is_empty()
        || !valid_hex(expected.subject_digest_sha256, 64)
        || expected.repository_uri.trim().is_empty()
        || !(valid_hex(expected.source_commit_sha, 40) || valid_hex(expected.source_commit_sha, 64))
        || !valid_hex(expected.flake_lock_sha256, 64)
        || !valid_hex(expected.corpus_sha256, 64)
        || expected.builder_id.trim().is_empty()
    {
        return Err(DsseVerificationError::SourceProvenanceMismatch);
    }
    let source_inputs_digest = nixward_source_inputs_digest_sha256(
        expected.repository_uri,
        expected.source_commit_sha,
        expected.flake_lock_sha256,
        expected.corpus_sha256,
    )?;
    let attestation = verify_in_toto_dsse(
        envelope_bytes,
        trust_policy_bytes,
        trust_policy_sha256,
        now_ms,
        InTotoExpectation {
            payload_type: DSSE_IN_TOTO_PAYLOAD_TYPE,
            predicate_type: NIXWARD_SOURCE_EVIDENCE_PREDICATE_TYPE,
            subject_name: expected.subject_name,
            subject_digest_algorithm: NIXWARD_SOURCE_SUBJECT_DIGEST_ALGORITHM,
            subject_digest: expected.subject_digest_sha256,
        },
    )?;
    let subjects = attestation.statement.get("subject")
        .and_then(Value::as_array)
        .ok_or(DsseVerificationError::InvalidStatement)?;
    if subjects.len() != 1
        || subjects[0].get("name").and_then(Value::as_str) != Some(expected.subject_name)
    {
        return Err(DsseVerificationError::SubjectMismatch);
    }
    let predicate = attestation.statement.get("predicate")
        .ok_or(DsseVerificationError::InvalidStatement)?;
    let source = predicate.get("source").ok_or(DsseVerificationError::InvalidStatement)?;
    let materials = predicate.get("materials").ok_or(DsseVerificationError::InvalidStatement)?;
    let builder = predicate.get("builder").ok_or(DsseVerificationError::InvalidStatement)?;

    if source.get("repository_uri").and_then(Value::as_str) != Some(expected.repository_uri)
        || source.get("commit_sha").and_then(Value::as_str) != Some(expected.source_commit_sha)
        || materials.get("flake_lock_sha256").and_then(Value::as_str)
            != Some(expected.flake_lock_sha256)
        || materials.get("corpus_sha256").and_then(Value::as_str) != Some(expected.corpus_sha256)
        || materials.get("source_inputs_sha256").and_then(Value::as_str)
            != Some(source_inputs_digest.as_str())
    {
        return Err(DsseVerificationError::SourceProvenanceMismatch);
    }
    if builder.get("id").and_then(Value::as_str) != Some(expected.builder_id) {
        return Err(DsseVerificationError::SourceBuilderMismatch);
    }
    Ok(VerifiedNixwardSourceEvidence { attestation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    const PREDICATE: &str = "https://luminousdynamics.io/attestations/nixward-source-evidence/v1";
    const SUBJECT_NAME: &str = "nixward-source-and-flake-lock";
    const SUBJECT_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";


    const SOURCE_REPOSITORY: &str = "https://github.com/Luminous-Dynamics/nixward";
    const OUTPUT_SUBJECT_NAME: &str = "nixward-benchmark-verifier-closure-manifest";
    const OUTPUT_SUBJECT_SHA256: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const SOURCE_COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FLAKE_LOCK: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const CORPUS: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const BUILDER: &str = "https://github.com/actions/runner";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted_key(key: &SigningKey) -> DsseTrustedKey {
        let public_key = key.verifying_key().to_bytes();
        DsseTrustedKey {
            key_id: sha256_hex(&public_key),
            public_key: STANDARD.encode(public_key),
            revoked: false,
            not_before_ms: 100,
            not_after_ms: 9_000,
            allowed_predicate_types: vec![PREDICATE.into()],
        }
    }


    fn source_statement(
        subject_name: &str,
        subject_digest: &str,
        repository_uri: &str,
        source_commit_sha: &str,
        flake_lock_sha256: &str,
        corpus_sha256: &str,
        builder_id: &str,
    ) -> Vec<u8> {
        let source_inputs_digest = nixward_source_inputs_digest_sha256(
            repository_uri, source_commit_sha, flake_lock_sha256, corpus_sha256
        ).unwrap();
        serde_json::to_vec(&serde_json::json!({
            "_type": IN_TOTO_STATEMENT_V1,
            "subject": [{
                "name": subject_name,
                "digest": { "sha256": subject_digest }
            }],
            "predicateType": NIXWARD_SOURCE_EVIDENCE_PREDICATE_TYPE,
            "predicate": {
                "source": {
                    "repository_uri": repository_uri,
                    "commit_sha": source_commit_sha
                },
                "materials": {
                    "flake_lock_sha256": flake_lock_sha256,
                    "corpus_sha256": corpus_sha256,
                    "source_inputs_sha256": source_inputs_digest
                },
                "builder": { "id": builder_id }
            }
        })).unwrap()
    }

    fn source_expectation() -> NixwardSourceEvidenceExpectation<'static> {
        NixwardSourceEvidenceExpectation {
            subject_name: OUTPUT_SUBJECT_NAME,
            subject_digest_sha256: OUTPUT_SUBJECT_SHA256,
            repository_uri: SOURCE_REPOSITORY,
            source_commit_sha: SOURCE_COMMIT,
            flake_lock_sha256: FLAKE_LOCK,
            corpus_sha256: CORPUS,
            builder_id: BUILDER,
        }
    }

    fn statement(subject_digest: &str, predicate_type: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "_type": IN_TOTO_STATEMENT_V1,
            "subject": [{
                "name": SUBJECT_NAME,
                "digest": { "sha256": subject_digest }
            }],
            "predicateType": predicate_type,
            "predicate": {
                "source": {
                    "repository": "https://github.com/Luminous-Dynamics/nixward",
                    "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                },
                "materials": {
                    "flake_lock_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "corpus_sha256": SUBJECT_SHA256
                },
                "builder": { "id": "https://github.com/actions/runner" }
            }
        })).unwrap()
    }

    fn policy_bytes(keys: Vec<DsseTrustedKey>, threshold: usize) -> Vec<u8> {
        serde_json::to_vec(&DsseTrustPolicy {
            schema: TRUST_POLICY_SCHEMA.into(),
            version: 1,
            policy_id: "nixward-supply-chain-root".into(),
            epoch: 1,
            not_before_ms: 100,
            not_after_ms: 10_000,
            signature_threshold: threshold,
            allowed_payload_types: vec![DSSE_IN_TOTO_PAYLOAD_TYPE.into()],
            allowed_predicate_types: vec![PREDICATE.into()],
            keys,
        }).unwrap()
    }

    fn envelope(payload: &[u8], keys: &[SigningKey], payload_type: &str) -> Vec<u8> {
        let pre_auth = pae(payload_type, payload);
        let signatures = keys.iter().map(|key| {
            serde_json::json!({
                "sig": STANDARD.encode(key.sign(&pre_auth).to_bytes()),
                "keyid": "untrusted-envelope-hint"
            })
        }).collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "payloadType": payload_type,
            "payload": STANDARD.encode(payload),
            "signatures": signatures,
            "extension_field": "ignored-by-dsse-envelope-parser"
        })).unwrap()
    }

    fn expectation() -> InTotoExpectation<'static> {
        InTotoExpectation {
            payload_type: DSSE_IN_TOTO_PAYLOAD_TYPE,
            predicate_type: PREDICATE,
            subject_name: SUBJECT_NAME,
            subject_digest_algorithm: "sha256",
            subject_digest: SUBJECT_SHA256,
        }
    }

    fn verify(
        payload: &[u8],
        signing_keys: &[SigningKey],
        trusted_keys: Vec<DsseTrustedKey>,
        threshold: usize,
    ) -> Result<VerifiedDsseAttestation, DsseVerificationError> {
        let envelope = envelope(payload, signing_keys, DSSE_IN_TOTO_PAYLOAD_TYPE);
        let policy = policy_bytes(trusted_keys, threshold);
        let digest = sha256_hex(&policy);
        verify_in_toto_dsse(&envelope, &policy, &digest, 1_000, expectation())
    }


    #[test]
    fn verifies_signed_nixward_source_repository_commit_flake_corpus_and_builder_claims() {
        let key = signing_key(23);
        let payload = source_statement(
            OUTPUT_SUBJECT_NAME, OUTPUT_SUBJECT_SHA256,
            SOURCE_REPOSITORY, SOURCE_COMMIT, FLAKE_LOCK, CORPUS, BUILDER
        );
        let envelope = envelope(&payload, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE);
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        let verified = verify_nixward_source_evidence(
            &envelope, &policy, &sha256_hex(&policy), 1_000, source_expectation()
        ).unwrap();
        assert_eq!(verified.repository_uri(), SOURCE_REPOSITORY);
        assert_eq!(verified.source_commit_sha(), SOURCE_COMMIT);
        assert_eq!(verified.flake_lock_sha256(), FLAKE_LOCK);
        assert_eq!(verified.corpus_sha256(), CORPUS);
        assert_eq!(verified.builder_id(), BUILDER);
    }

    #[test]
    fn signed_but_foreign_source_materials_do_not_pass_the_predicate_profile() {
        let key = signing_key(24);
        let payload = source_statement(
            OUTPUT_SUBJECT_NAME, OUTPUT_SUBJECT_SHA256,
            SOURCE_REPOSITORY, SOURCE_COMMIT, &"e".repeat(64), CORPUS, BUILDER
        );
        let envelope = envelope(&payload, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE);
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        assert!(matches!(
            verify_nixward_source_evidence(
                &envelope, &policy, &sha256_hex(&policy), 1_000, source_expectation()
            ),
            Err(DsseVerificationError::SubjectMismatch)
        ));
    }

    #[test]
    fn signed_foreign_repository_or_builder_is_rejected_after_signature() {
        let key = signing_key(25);
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        let foreign_repository = source_statement(
            OUTPUT_SUBJECT_NAME, OUTPUT_SUBJECT_SHA256,
            "https://example.invalid/other", SOURCE_COMMIT, FLAKE_LOCK, CORPUS, BUILDER
        );
        let foreign_repository_envelope = envelope(
            &foreign_repository, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE
        );
        assert!(matches!(
            verify_nixward_source_evidence(
                &foreign_repository_envelope, &policy, &sha256_hex(&policy), 1_000, source_expectation()
            ),
            Err(DsseVerificationError::SubjectMismatch)
                | Err(DsseVerificationError::SourceProvenanceMismatch)
        ));

        let foreign_builder = source_statement(
            OUTPUT_SUBJECT_NAME, OUTPUT_SUBJECT_SHA256,
            SOURCE_REPOSITORY, SOURCE_COMMIT, FLAKE_LOCK, CORPUS,
            "https://example.invalid/builder"
        );
        let foreign_builder_envelope = envelope(
            &foreign_builder, &[key], DSSE_IN_TOTO_PAYLOAD_TYPE
        );
        assert!(matches!(
            verify_nixward_source_evidence(
                &foreign_builder_envelope, &policy, &sha256_hex(&policy), 1_000, source_expectation()
            ),
            Err(DsseVerificationError::SourceBuilderMismatch)
        ));
    }

    #[test]
    fn source_subject_digest_changes_when_any_input_changes() {
        let original = nixward_source_inputs_digest_sha256(
            SOURCE_REPOSITORY, SOURCE_COMMIT, FLAKE_LOCK, CORPUS
        ).unwrap();
        let changed_commit = nixward_source_inputs_digest_sha256(
            SOURCE_REPOSITORY, &"a".repeat(40), FLAKE_LOCK, CORPUS
        ).unwrap();
        let changed_flake = nixward_source_inputs_digest_sha256(
            SOURCE_REPOSITORY, SOURCE_COMMIT, &"e".repeat(64), CORPUS
        ).unwrap();
        let changed_corpus = nixward_source_inputs_digest_sha256(
            SOURCE_REPOSITORY, SOURCE_COMMIT, FLAKE_LOCK, &"f".repeat(64)
        ).unwrap();
        assert_ne!(original, changed_commit);
        assert_ne!(original, changed_flake);
        assert_ne!(original, changed_corpus);
    }

    #[test]
    fn pae_uses_byte_lengths_and_authenticates_payload_type() {
        assert_eq!(
            pae("application/vnd.in-toto+json", b"{}"),
            b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
        );
        let mut expected = b"DSSEv1 2 ".to_vec();
        expected.extend_from_slice(&[0xc3, 0xa9]);
        expected.extend_from_slice(b" 1 x");
        assert_eq!(pae("\u{e9}", b"x"), expected);
    }


    #[test]
    fn rejects_duplicate_json_keys_even_when_the_duplicate_payload_is_signed() {
        let key = signing_key(26);
        let payload = format!(
            r#"{{"_type":"{}","subject":[{{"name":"{}","digest":{{"sha256":"{}"}}}}],"predicateType":"{}","predicateType":"{}","predicate":{{}}}}"#,
            IN_TOTO_STATEMENT_V1,
            SUBJECT_NAME,
            SUBJECT_SHA256,
            PREDICATE,
            PREDICATE
        );
        assert!(parse_unique_json(payload.as_bytes()).is_err());
        assert!(matches!(
            verify(payload.as_bytes(), &[key.clone()], vec![trusted_key(&key)], 1),
            Err(DsseVerificationError::InvalidStatement)
        ));
    }

    #[test]
    fn verifies_exact_payload_and_reports_the_actual_trusted_key() {
        let key = signing_key(7);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let verified = verify(&payload, &[key.clone()], vec![trusted_key(&key)], 1).unwrap();
        assert_eq!(verified.payload_bytes(), payload);
        assert_eq!(verified.predicate_type(), PREDICATE);
        assert_eq!(verified.subject_name(), SUBJECT_NAME);
        assert_eq!(verified.subject_digest(), SUBJECT_SHA256);
        assert_eq!(verified.verified_key_ids(), &[sha256_hex(&key.verifying_key().to_bytes())]);
        assert_eq!(verified.trust_policy_epoch(), 1);
    }

    #[test]
    fn envelope_keyid_hint_does_not_override_verified_signer() {
        let key = signing_key(8);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let verified = verify(&payload, &[key.clone()], vec![trusted_key(&key)], 1).unwrap();
        assert_eq!(verified.verified_key_ids(), &[sha256_hex(&key.verifying_key().to_bytes())]);
    }

    #[test]
    fn changed_payload_bytes_invalidate_the_signature() {
        let key = signing_key(9);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let mut parsed: Value = serde_json::from_slice(
            &envelope(&payload, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE)
        ).unwrap();
        parsed["payload"] = Value::String(STANDARD.encode(statement(&"d".repeat(64), PREDICATE)));
        let changed_envelope = serde_json::to_vec(&parsed).unwrap();
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        let result = verify_in_toto_dsse(
            &changed_envelope, &policy, &sha256_hex(&policy), 1_000, expectation()
        );
        assert!(matches!(result, Err(DsseVerificationError::InvalidSignature)));
    }

    #[test]
    fn payload_type_confusion_is_rejected() {
        let key = signing_key(10);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let envelope = envelope(&payload, &[key.clone()], "application/json");
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        assert!(matches!(
            verify_in_toto_dsse(&envelope, &policy, &sha256_hex(&policy), 1_000, expectation()),
            Err(DsseVerificationError::UnsupportedPayloadType)
        ));
    }

    #[test]
    fn trust_policy_digest_must_match_independent_pin() {
        let key = signing_key(11);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let envelope = envelope(&payload, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE);
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        assert!(matches!(
            verify_in_toto_dsse(&envelope, &policy, &"f".repeat(64), 1_000, expectation()),
            Err(DsseVerificationError::TrustPolicyDigestMismatch)
        ));
    }

    #[test]
    fn untrusted_signer_does_not_meet_threshold() {
        let trusted = signing_key(12);
        let attacker = signing_key(13);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        assert!(matches!(
            verify(&payload, &[attacker], vec![trusted_key(&trusted)], 1),
            Err(DsseVerificationError::InvalidSignature)
        ));
    }

    #[test]
    fn duplicate_signature_from_one_key_does_not_meet_two_of_two_threshold() {
        let first = signing_key(14);
        let second = signing_key(15);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        assert!(matches!(
            verify(
                &payload,
                &[first.clone(), first.clone()],
                vec![trusted_key(&first), trusted_key(&second)],
                2
            ),
            Err(DsseVerificationError::InsufficientSignatures)
        ));
    }

    #[test]
    fn threshold_requires_distinct_trusted_signers() {
        let first = signing_key(16);
        let second = signing_key(17);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let verified = verify(
            &payload,
            &[first.clone(), second.clone()],
            vec![trusted_key(&first), trusted_key(&second)],
            2,
        ).unwrap();
        assert_eq!(verified.verified_key_ids().len(), 2);
    }

    #[test]
    fn revoked_signer_cannot_authenticate_an_attestation() {
        let key = signing_key(18);
        let mut trusted = trusted_key(&key);
        trusted.revoked = true;
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        assert!(matches!(
            verify(&payload, &[key], vec![trusted], 1),
            Err(DsseVerificationError::InvalidTrustPolicy)
        ));
    }

    #[test]
    fn expired_or_not_yet_valid_trust_policy_is_rejected() {
        let key = signing_key(19);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let envelope = envelope(&payload, &[key.clone()], DSSE_IN_TOTO_PAYLOAD_TYPE);
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        assert!(matches!(
            verify_in_toto_dsse(&envelope, &policy, &sha256_hex(&policy), 10_001, expectation()),
            Err(DsseVerificationError::TrustPolicyExpired)
        ));
        assert!(matches!(
            verify_in_toto_dsse(&envelope, &policy, &sha256_hex(&policy), 50, expectation()),
            Err(DsseVerificationError::TrustPolicyExpired)
        ));
    }

    #[test]
    fn wrong_predicate_or_subject_is_rejected() {
        let key = signing_key(20);
        let wrong_subject = statement(&"d".repeat(64), PREDICATE);
        assert!(matches!(
            verify(&wrong_subject, &[key.clone()], vec![trusted_key(&key)], 1),
            Err(DsseVerificationError::SubjectMismatch)
        ));
        let wrong_predicate = statement(SUBJECT_SHA256, "https://example.invalid/other/v1");
        assert!(matches!(
            verify(&wrong_predicate, &[key.clone()], vec![trusted_key(&key)], 1),
            Err(DsseVerificationError::UnsupportedPredicateType)
        ));
    }

    #[test]
    fn key_policy_cannot_allow_a_predicate_outside_global_allowlist() {
        let key = signing_key(21);
        let mut trusted = trusted_key(&key);
        trusted.allowed_predicate_types = vec!["https://example.invalid/other/v1".into()];
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        assert!(matches!(
            verify(&payload, &[key], vec![trusted], 1),
            Err(DsseVerificationError::InvalidTrustPolicy)
        ));
    }

    #[test]
    fn accepts_url_safe_unpadded_payload_and_signature_base64() {
        let key = signing_key(22);
        let payload = statement(SUBJECT_SHA256, PREDICATE);
        let pre_auth = pae(DSSE_IN_TOTO_PAYLOAD_TYPE, &payload);
        let envelope = serde_json::to_vec(&serde_json::json!({
            "payloadType": DSSE_IN_TOTO_PAYLOAD_TYPE,
            "payload": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload),
            "signatures": [{
                "sig": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(&pre_auth).to_bytes())
            }]
        })).unwrap();
        let policy = policy_bytes(vec![trusted_key(&key)], 1);
        assert!(verify_in_toto_dsse(
            &envelope, &policy, &sha256_hex(&policy), 1_000, expectation()
        ).is_ok());
    }
}
