// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Challenge-bound Ed25519 signatures for OCI observer checkpoints.
//!
//! This authenticates the observer key and the exact checkpoint bytes. It does
//! not prove that a compromised kernel reported truthful measurements, does
//! not persist sequence state, and does not provide an external witness. The
//! verifier must supply a provisioned trust record and its independently
//! retained previous-checkpoint digest/sequence on every admission decision.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OCI_OBSERVER_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const OCI_OBSERVER_CHECKPOINT_KIND: &str = "nixward-oci-observer-checkpoint-v1";
pub const OCI_OBSERVER_CHECKPOINT_ALGORITHM: &str = "ed25519";

const CHECKPOINT_DOMAIN: &[u8] = b"nixward:oci-observer-checkpoint-signature:v1\0";
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"nixward:oci-observer-checkpoint-digest:v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"nixward:oci-observer-checkpoint-challenge:v1\0";

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], OciObserverCheckpointError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OciObserverCheckpointError::InvalidEncoding);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = (value.as_bytes()[index * 2] as char)
            .to_digit(16)
            .ok_or(OciObserverCheckpointError::InvalidEncoding)?;
        let low = (value.as_bytes()[index * 2 + 1] as char)
            .to_digit(16)
            .ok_or(OciObserverCheckpointError::InvalidEncoding)?;
        *slot = ((high << 4) | low) as u8;
    }
    Ok(out)
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

fn validate_digest(value: &str) -> Result<(), OciObserverCheckpointError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(OciObserverCheckpointError::InvalidEncoding)
    }
}

fn validate_key_id(value: &str) -> Result<(), OciObserverCheckpointError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(OciObserverCheckpointError::InvalidShape);
    }
    Ok(())
}

fn validate_boot_id(value: &str) -> Result<(), OciObserverCheckpointError> {
    if value != value.to_ascii_lowercase() {
        return Err(OciObserverCheckpointError::InvalidBootId);
    }
    let parts: Vec<&str> = value.split('-').collect();
    let expected = [8, 4, 4, 4, 12];
    if parts.len() == 5
        && parts.iter().map(|part| part.len()).eq(expected)
        && parts.concat().bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(OciObserverCheckpointError::InvalidBootId)
    }
}

/// Hash a fresh 32-byte verifier challenge with a dedicated domain separator.
/// The verifier must generate the nonce with an OS CSPRNG and consume it once.
pub fn observer_challenge_digest(nonce: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(&(nonce.len() as u64).to_le_bytes());
    hasher.update(nonce);
    hasher.finalize().to_hex().to_string()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OciObserverCheckpointError {
    #[error("observer checkpoint fields are invalid")]
    InvalidShape,
    #[error("observer checkpoint encoding is invalid")]
    InvalidEncoding,
    #[error("observer checkpoint boot ID is not canonical")]
    InvalidBootId,
    #[error("observer checkpoint signature is invalid")]
    InvalidSignature,
    #[error("observer signing key is invalid")]
    InvalidPublicKey,
    #[error("observer identity does not match the trusted key")]
    ObserverMismatch,
    #[error("machine identity does not match the trusted key")]
    MachineMismatch,
    #[error("observer key ID or generation does not match the trusted key")]
    KeyIdentityMismatch,
    #[error("observer key has been revoked for new admissions")]
    KeyRevoked,
    #[error("observer key is not yet valid")]
    KeyNotYetValid,
    #[error("observer key has expired")]
    KeyExpired,
    #[error("checkpoint has not yet been issued")]
    CheckpointNotYetIssued,
    #[error("checkpoint has expired")]
    CheckpointExpired,
    #[error("checkpoint validity interval exceeds the verifier maximum")]
    CheckpointTtlExceeded,
    #[error("checkpoint does not bind the verifier's current challenge")]
    ChallengeMismatch,
    #[error("checkpoint does not extend the independently retained checkpoint")]
    PreviousCheckpointMismatch,
    #[error("checkpoint snapshot digest does not match the independently observed snapshot")]
    SnapshotMismatch,
    #[error("checkpoint chain head does not match the independently verified chain")]
    ChainHeadMismatch,
    #[error("observer sequence is not strictly increasing")]
    SequenceRollback,
}

/// Signed facts claimed by an observer. These fields are authenticated, not
/// independently proven true by the signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OciObserverCheckpointPayload {
    pub schema_version: u32,
    pub kind: String,
    pub observer_id_blake3: String,
    pub key_id: String,
    pub key_generation: u64,
    pub machine_id_blake3: String,
    pub boot_id: String,
    pub sequence: u64,
    pub snapshot_digest_blake3: String,
    pub chain_head_blake3: String,
    pub previous_checkpoint_blake3: Option<String>,
    pub challenge_blake3: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl OciObserverCheckpointPayload {
    /// Deterministic, domain-separated signing bytes. Field order is fixed by
    /// this encoder; JSON serialization is never used as the signed format.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, OciObserverCheckpointError> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(CHECKPOINT_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_le_bytes());

        fn push_string(out: &mut Vec<u8>, value: &str) {
            out.extend_from_slice(&(value.len() as u64).to_le_bytes());
            out.extend_from_slice(value.as_bytes());
        }

        push_string(&mut out, &self.kind);
        push_string(&mut out, &self.observer_id_blake3);
        push_string(&mut out, &self.key_id);
        out.extend_from_slice(&self.key_generation.to_le_bytes());
        push_string(&mut out, &self.machine_id_blake3);
        push_string(&mut out, &self.boot_id);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        push_string(&mut out, &self.snapshot_digest_blake3);
        push_string(&mut out, &self.chain_head_blake3);
        match &self.previous_checkpoint_blake3 {
            Some(previous) => {
                out.push(1);
                push_string(&mut out, previous);
            }
            None => out.push(0),
        }
        push_string(&mut out, &self.challenge_blake3);
        out.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        Ok(out)
    }

    fn validate_shape(&self) -> Result<(), OciObserverCheckpointError> {
        if self.schema_version != OCI_OBSERVER_CHECKPOINT_SCHEMA_VERSION
            || self.kind != OCI_OBSERVER_CHECKPOINT_KIND
            || self.key_generation == 0
            || self.sequence == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(OciObserverCheckpointError::InvalidShape);
        }
        validate_digest(&self.observer_id_blake3)?;
        validate_digest(&self.machine_id_blake3)?;
        validate_digest(&self.snapshot_digest_blake3)?;
        validate_digest(&self.chain_head_blake3)?;
        validate_digest(&self.challenge_blake3)?;
        validate_key_id(&self.key_id)?;
        validate_boot_id(&self.boot_id)?;
        if let Some(previous) = &self.previous_checkpoint_blake3 {
            validate_digest(previous)?;
        }
        Ok(())
    }
}

/// Serialized signature envelope. Unknown fields are rejected so that a
/// consumer cannot silently ignore metadata outside the signed payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOciObserverCheckpoint {
    pub kind: String,
    pub algorithm: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
    pub payload: OciObserverCheckpointPayload,
}

/// A provisioned trust record supplied by the relying party, never by the
/// candidate workload. The record should be protected by the owner/control
/// plane and updated atomically during key rotation or revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedOciObserverKey {
    pub observer_id_blake3: String,
    pub machine_id_blake3: String,
    pub key_id: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

/// Verifier-owned expectations. expected_previous_checkpoint_blake3 and
/// min_sequence_exclusive must come from independently retained state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciObserverCheckpointExpectation {
    pub observer_id_blake3: String,
    pub machine_id_blake3: String,
    pub challenge_nonce: [u8; 32],
    pub expected_snapshot_digest_blake3: String,
    pub expected_chain_head_blake3: String,
    pub expected_previous_checkpoint_blake3: Option<String>,
    pub min_sequence_exclusive: u64,
    pub now_ms: u64,
    pub max_validity_ms: u64,
}

/// Opaque proof that a particular checkpoint's signature and verifier
/// expectations were accepted. It is not an owner authorization or runtime
/// enforcement token and intentionally has no Deserialize implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciObserverCheckpoint {
    checkpoint_digest_blake3: String,
    observer_id_blake3: String,
    machine_id_blake3: String,
    key_id: String,
    key_generation: u64,
    boot_id: String,
    sequence: u64,
    snapshot_digest_blake3: String,
    chain_head_blake3: String,
    expires_at_ms: u64,
}

impl VerifiedOciObserverCheckpoint {
    pub fn checkpoint_digest_blake3(&self) -> &str {
        &self.checkpoint_digest_blake3
    }
    pub fn observer_id_blake3(&self) -> &str {
        &self.observer_id_blake3
    }
    pub fn machine_id_blake3(&self) -> &str {
        &self.machine_id_blake3
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn snapshot_digest_blake3(&self) -> &str {
        &self.snapshot_digest_blake3
    }
    pub fn chain_head_blake3(&self) -> &str {
        &self.chain_head_blake3
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Sign with a key held by an operator-controlled observer service or
/// hardware-backed key provider. This function does not load, create or store
/// private keys.
pub fn sign_observer_checkpoint(
    payload: OciObserverCheckpointPayload,
    signing_key: &SigningKey,
) -> Result<SignedOciObserverCheckpoint, OciObserverCheckpointError> {
    let bytes = payload.signing_bytes()?;
    let signature = signing_key.sign(&bytes);
    Ok(SignedOciObserverCheckpoint {
        kind: OCI_OBSERVER_CHECKPOINT_KIND.to_owned(),
        algorithm: OCI_OBSERVER_CHECKPOINT_ALGORITHM.to_owned(),
        signer_public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: encode_hex(&signature.to_bytes()),
        payload,
    })
}

/// Verify the signature against an externally provisioned key and bind it to
/// a fresh challenge plus the verifier's last accepted checkpoint/sequence.
/// Persist the returned checkpoint digest outside the workload before relying
/// on it for the next admission decision.
pub fn verify_observer_checkpoint(
    signed: &SignedOciObserverCheckpoint,
    trusted_key: &TrustedOciObserverKey,
    expectation: &OciObserverCheckpointExpectation,
) -> Result<VerifiedOciObserverCheckpoint, OciObserverCheckpointError> {
    if signed.kind != OCI_OBSERVER_CHECKPOINT_KIND
        || signed.algorithm != OCI_OBSERVER_CHECKPOINT_ALGORITHM
    {
        return Err(OciObserverCheckpointError::InvalidShape);
    }
    let payload = &signed.payload;
    let signing_bytes = payload.signing_bytes()?;

    validate_digest(&trusted_key.observer_id_blake3)?;
    validate_digest(&trusted_key.machine_id_blake3)?;
    validate_key_id(&trusted_key.key_id)?;
    if trusted_key.key_generation == 0 || trusted_key.valid_until_ms <= trusted_key.valid_from_ms {
        return Err(OciObserverCheckpointError::InvalidShape);
    }

    if payload.observer_id_blake3 != trusted_key.observer_id_blake3
        || payload.observer_id_blake3 != expectation.observer_id_blake3
    {
        return Err(OciObserverCheckpointError::ObserverMismatch);
    }
    if payload.machine_id_blake3 != trusted_key.machine_id_blake3
        || payload.machine_id_blake3 != expectation.machine_id_blake3
    {
        return Err(OciObserverCheckpointError::MachineMismatch);
    }
    if payload.key_id != trusted_key.key_id || payload.key_generation != trusted_key.key_generation {
        return Err(OciObserverCheckpointError::KeyIdentityMismatch);
    }
    if expectation.now_ms < trusted_key.valid_from_ms
        || payload.issued_at_ms < trusted_key.valid_from_ms
    {
        return Err(OciObserverCheckpointError::KeyNotYetValid);
    }
    if expectation.now_ms >= trusted_key.valid_until_ms
        || payload.expires_at_ms > trusted_key.valid_until_ms
    {
        return Err(OciObserverCheckpointError::KeyExpired);
    }
    if trusted_key
        .revoked_at_ms
        .is_some_and(|revoked_at| expectation.now_ms >= revoked_at)
    {
        return Err(OciObserverCheckpointError::KeyRevoked);
    }
    if expectation.now_ms < payload.issued_at_ms {
        return Err(OciObserverCheckpointError::CheckpointNotYetIssued);
    }
    if expectation.now_ms >= payload.expires_at_ms {
        return Err(OciObserverCheckpointError::CheckpointExpired);
    }
    if expectation.max_validity_ms == 0
        || payload.expires_at_ms - payload.issued_at_ms > expectation.max_validity_ms
    {
        return Err(OciObserverCheckpointError::CheckpointTtlExceeded);
    }
    if payload.challenge_blake3 != observer_challenge_digest(&expectation.challenge_nonce) {
        return Err(OciObserverCheckpointError::ChallengeMismatch);
    }
    if payload.snapshot_digest_blake3 != expectation.expected_snapshot_digest_blake3 {
        return Err(OciObserverCheckpointError::SnapshotMismatch);
    }
    if payload.chain_head_blake3 != expectation.expected_chain_head_blake3 {
        return Err(OciObserverCheckpointError::ChainHeadMismatch);
    }
    if payload.previous_checkpoint_blake3 != expectation.expected_previous_checkpoint_blake3 {
        return Err(OciObserverCheckpointError::PreviousCheckpointMismatch);
    }
    if payload.sequence <= expectation.min_sequence_exclusive {
        return Err(OciObserverCheckpointError::SequenceRollback);
    }

    let trusted_public_key = decode_hex::<32>(&trusted_key.public_key_hex)?;
    if signed.signer_public_key_hex != encode_hex(&trusted_public_key) {
        return Err(OciObserverCheckpointError::InvalidPublicKey);
    }
    let verifying_key = VerifyingKey::from_bytes(&trusted_public_key)
        .map_err(|_| OciObserverCheckpointError::InvalidPublicKey)?;
    let signature_bytes = decode_hex::<64>(&signed.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| OciObserverCheckpointError::InvalidSignature)?;

    let mut digest = blake3::Hasher::new();
    digest.update(CHECKPOINT_DIGEST_DOMAIN);
    digest.update(&(signing_bytes.len() as u64).to_le_bytes());
    digest.update(&signing_bytes);
    digest.update(&trusted_public_key);
    digest.update(&signature_bytes);

    Ok(VerifiedOciObserverCheckpoint {
        checkpoint_digest_blake3: digest.finalize().to_hex().to_string(),
        observer_id_blake3: payload.observer_id_blake3.clone(),
        machine_id_blake3: payload.machine_id_blake3.clone(),
        key_id: payload.key_id.clone(),
        key_generation: payload.key_generation,
        boot_id: payload.boot_id.clone(),
        sequence: payload.sequence,
        snapshot_digest_blake3: payload.snapshot_digest_blake3.clone(),
        chain_head_blake3: payload.chain_head_blake3.clone(),
        expires_at_ms: payload.expires_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn trusted(signing: &SigningKey) -> TrustedOciObserverKey {
        TrustedOciObserverKey {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            key_id: "observer-primary".into(),
            key_generation: 7,
            public_key_hex: encode_hex(signing.verifying_key().as_bytes()),
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        }
    }

    fn expectation(previous: Option<String>, min_sequence: u64) -> OciObserverCheckpointExpectation {
        OciObserverCheckpointExpectation {
            observer_id_blake3: "a1".repeat(32),
            machine_id_blake3: "b2".repeat(32),
            challenge_nonce: [9u8; 32],
            expected_snapshot_digest_blake3: "c3".repeat(32),
            expected_chain_head_blake3: "d4".repeat(32),
            expected_previous_checkpoint_blake3: previous,
            min_sequence_exclusive: min_sequence,
            now_ms: 1_000,
            max_validity_ms: 2_000,
        }
    }

    fn payload(previous: Option<String>, sequence: u64) -> OciObserverCheckpointPayload {
        OciObserverCheckpointPayload {
            schema_version: OCI_OBSERVER_CHECKPOINT_SCHEMA_VERSION,
            kind: OCI_OBSERVER_CHECKPOINT_KIND.into(),
            observer_id_blake3: "a1".repeat(32),
            key_id: "observer-primary".into(),
            key_generation: 7,
            machine_id_blake3: "b2".repeat(32),
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            sequence,
            snapshot_digest_blake3: "c3".repeat(32),
            chain_head_blake3: "d4".repeat(32),
            previous_checkpoint_blake3: previous,
            challenge_blake3: observer_challenge_digest(&[9u8; 32]),
            issued_at_ms: 900,
            expires_at_ms: 1_900,
        }
    }

    fn signed(previous: Option<String>, sequence: u64) -> (SigningKey, SignedOciObserverCheckpoint) {
        let signing = seed();
        let signed = sign_observer_checkpoint(payload(previous, sequence), &signing).unwrap();
        (signing, signed)
    }

    #[test]
    fn accepts_fresh_checkpoint_with_trusted_key_and_parent() {
        let (signing, signed) = signed(None, 10);
        let verified = verify_observer_checkpoint(
            &signed,
            &trusted(&signing),
            &expectation(None, 0),
        )
        .unwrap();
        assert_eq!(verified.sequence(), 10);
        assert_eq!(verified.key_generation(), 7);
        assert_eq!(verified.chain_head_blake3(), "d4".repeat(32));
        assert_eq!(verified.expires_at_ms(), 1_900);
    }

    #[test]
    fn rejects_payload_mutation_after_signing() {
        let (signing, mut signed) = signed(None, 10);
        signed.payload.snapshot_digest_blake3 = "e5".repeat(32);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expectation(None, 0)),
            Err(OciObserverCheckpointError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_different_verifier_challenge() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.challenge_nonce = [8u8; 32];
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_revoked_key_even_when_signature_is_cryptographically_valid() {
        let (signing, signed) = signed(None, 10);
        let mut key = trusted(&signing);
        key.revoked_at_ms = Some(950);
        assert_eq!(
            verify_observer_checkpoint(&signed, &key, &expectation(None, 0)),
            Err(OciObserverCheckpointError::KeyRevoked)
        );
    }

    #[test]
    fn rejects_checkpoint_after_expiry() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.now_ms = 1_900;
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::CheckpointExpired)
        );
    }

    #[test]
    fn rejects_checkpoint_from_a_future_time() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.now_ms = 800;
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::CheckpointNotYetIssued)
        );
    }

    #[test]
    fn rejects_snapshot_digest_substitution() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.expected_snapshot_digest_blake3 = "ee".repeat(32);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::SnapshotMismatch)
        );
    }

    #[test]
    fn rejects_chain_head_substitution() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.expected_chain_head_blake3 = "ee".repeat(32);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::ChainHeadMismatch)
        );
    }

    #[test]
    fn rejects_previous_checkpoint_rollback_or_fork() {
        let (signing, signed) = signed(Some("11".repeat(32)), 10);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expectation(None, 0)),
            Err(OciObserverCheckpointError::PreviousCheckpointMismatch)
        );
    }

    #[test]
    fn rejects_non_increasing_observer_sequence() {
        let (signing, signed) = signed(None, 10);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expectation(None, 10)),
            Err(OciObserverCheckpointError::SequenceRollback)
        );
    }

    #[test]
    fn rejects_changed_key_generation() {
        let (signing, signed) = signed(None, 10);
        let mut key = trusted(&signing);
        key.key_generation = 8;
        assert_eq!(
            verify_observer_checkpoint(&signed, &key, &expectation(None, 0)),
            Err(OciObserverCheckpointError::KeyIdentityMismatch)
        );
    }

    #[test]
    fn rejects_machine_identity_substitution() {
        let (signing, signed) = signed(None, 10);
        let mut expected = expectation(None, 0);
        expected.machine_id_blake3 = "ff".repeat(32);
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expected),
            Err(OciObserverCheckpointError::MachineMismatch)
        );
    }

    #[test]
    fn rejects_unknown_envelope_and_payload_fields() {
        let (signing, signed) = signed(None, 10);
        let mut envelope = serde_json::to_value(&signed).unwrap();
        envelope
            .as_object_mut()
            .unwrap()
            .insert("uncommitted".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SignedOciObserverCheckpoint>(envelope).is_err());

        let mut payload_only = serde_json::to_value(&signed).unwrap();
        payload_only
            .get_mut("payload")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert("uncommitted".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SignedOciObserverCheckpoint>(payload_only).is_err());

        // Keep the signer referenced in this test so it is clear this was a
        // validly signed receipt before the unknown fields were introduced.
        assert_eq!(signed.signer_public_key_hex, encode_hex(signing.verifying_key().as_bytes()));
    }

    #[test]
    fn rejects_expiry_beyond_key_validity() {
        let (signing, mut signed) = signed(None, 10);
        signed.payload.expires_at_ms = 10_001;
        let signed = sign_observer_checkpoint(signed.payload, &signing).unwrap();
        let mut key = trusted(&signing);
        key.valid_until_ms = 10_000;
        assert_eq!(
            verify_observer_checkpoint(&signed, &key, &expectation(None, 0)),
            Err(OciObserverCheckpointError::KeyExpired)
        );
    }

    #[test]
    fn rejects_validity_window_above_verifier_policy() {
        let (signing, mut signed) = signed(None, 10);
        signed.payload.expires_at_ms = 5_000;
        let signed = sign_observer_checkpoint(signed.payload, &signing).unwrap();
        assert_eq!(
            verify_observer_checkpoint(&signed, &trusted(&signing), &expectation(None, 0)),
            Err(OciObserverCheckpointError::CheckpointTtlExceeded)
        );
    }
}
