// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached cryptographic authority for consequential machine transformations.
//!
//! V31 makes authority a cryptographic statement over an exact subject rather
//! than a boolean supplied by an outer caller.  A signature is only accepted
//! when its key is already present in an explicit trust policy, its action and
//! audience are permitted, and its challenge is fresh and bound to the exact
//! Holon + plan digest.
//!
//! Verification does **not** consume replay state.  The privileged host must
//! atomically consume [`AuthorityChallenge::replay_key`] immediately before a
//! destructive operation.  Keeping verification and replay consumption
//! separate allows read-only review without accidentally burning an approval.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;
pub const AUTHORITY_POLICY_KIND: &str = "symthaea-authority-trust-policy-v1";
pub const AUTHORITY_CHALLENGE_KIND: &str = "symthaea-authority-challenge-v1";
pub const AUTHORITY_SIGNATURE_KIND: &str = "symthaea-detached-authority-signature-v1";
pub const AUTHORITY_PROVENANCE_SCHEMA_VERSION: u32 = 1;
pub const AUTHORITY_PROVENANCE_KIND: &str = "nixward-authority-provenance-v1";
const CHALLENGE_DOMAIN: &[u8] = b"symthaea-authority-challenge-v1\0";
const POLICY_DOMAIN: &[u8] = b"symthaea-authority-policy-v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"symthaea-authority-evidence-v1\0";
const REPLAY_DOMAIN: &[u8] = b"symthaea-authority-replay-v1\0";
const SIGNED_PROOF_DOMAIN: &[u8] = b"nixward-authority-signed-proof-v1\0";
const DEFAULT_MAX_TTL_MS: u64 = 15 * 60 * 1000;
const MAX_AUTHORITY_PROOF_BYTES: usize = 64 * 1024;
const MAX_CLOCK_SKEW_MS: u64 = 2 * 60 * 1000;

fn valid_blake3_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn push_field(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn decode_hex<const N: usize>(label: &'static str, value: &str) -> Result<[u8; N], AuthorityError> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthorityError::InvalidEncoding(label));
    }
    let mut out = [0u8; N];
    let bytes = value.as_bytes();
    for i in 0..N {
        let hi = (bytes[i * 2] as char)
            .to_digit(16)
            .ok_or(AuthorityError::InvalidEncoding(label))?;
        let lo = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or(AuthorityError::InvalidEncoding(label))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn hash_bytes_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("authority evidence serialization is infallible");
    hash_bytes_domain(domain, &bytes)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    #[error("invalid authority digest")]
    InvalidDigest,
    #[error("invalid authority encoding for {0}")]
    InvalidEncoding(&'static str),
    #[error("authority challenge is expired or not yet valid")]
    InvalidFreshness,
    #[error("authority challenge TTL exceeds policy")]
    ExcessiveTtl,
    #[error("authority subject does not match the requested operation")]
    SubjectMismatch,
    #[error("authority Holon identity does not match")]
    HolonMismatch,
    #[error("authority action does not match")]
    ActionMismatch,
    #[error("authority audience is not trusted")]
    AudienceMismatch,
    #[error("authority signer is not trusted")]
    UntrustedSigner,
    #[error("authority signer is revoked")]
    RevokedSigner,
    #[error("authority signer is not permitted for this action")]
    ActionNotPermitted,
    #[error("authority public key does not match trusted policy")]
    PublicKeyMismatch,
    #[error("authority signature verification failed")]
    InvalidSignature,
    #[error("a non-zero authority policy epoch is required for durable admission")]
    MissingPolicyEpoch,
    #[error("authority policy epoch does not match the verified provenance")]
    PolicyEpochMismatch,
    #[error("authority provenance record is inconsistent or malformed")]
    InvalidProvenance,
    #[error("detached authority proof exceeds the maximum accepted size")]
    ProofTooLarge,
    #[error("authority policy epoch must be non-zero")]
    InvalidPolicyEpoch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityAction {
    Genesis,
    Reconstitute,
    Update,
    Change,
    GuestRealize,
    NetworkActivate,
    SecurityEnrollment,
}

impl AuthorityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Reconstitute => "reconstitute",
            Self::Update => "update",
            Self::Change => "change",
            Self::GuestRealize => "guest-realize",
            Self::NetworkActivate => "network-activate",
            Self::SecurityEnrollment => "security-enrollment",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedAuthorityKey {
    pub key_id: String,
    pub issuer: String,
    /// Ed25519 public key as exactly 32 bytes of lowercase/uppercase hex.
    pub public_key_hex: String,
    pub allowed_actions: Vec<AuthorityAction>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTrustPolicy {
    pub schema_version: u32,
    pub kind: String,
    pub policy_id: String,
    /// Monotonically managed by the machine-local authority-policy owner.
    /// Legacy policies may omit it for read-only verification, but no durable
    /// admission receipt may be minted without a non-zero epoch.
    #[serde(default)]
    pub policy_epoch: Option<u64>,
    pub keys: Vec<TrustedAuthorityKey>,
    #[serde(default = "default_max_ttl_ms")]
    pub max_ttl_ms: u64,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
}

fn default_max_ttl_ms() -> u64 {
    DEFAULT_MAX_TTL_MS
}

impl AuthorityTrustPolicy {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.policy_epoch == Some(0) {
            return Err(AuthorityError::InvalidPolicyEpoch);
        }
        if self.schema_version != AUTHORITY_SCHEMA_VERSION
            || self.kind != AUTHORITY_POLICY_KIND
            || self.policy_id.trim().is_empty()
            || self.max_ttl_ms == 0
        {
            return Err(AuthorityError::UntrustedSigner);
        }
        let mut key_ids = std::collections::BTreeSet::new();
        for key in &self.keys {
            if key.key_id.trim().is_empty()
                || key.issuer.trim().is_empty()
                || key.allowed_actions.is_empty()
                || !key_ids.insert(key.key_id.as_str())
            {
                return Err(AuthorityError::UntrustedSigner);
            }
            let _ = decode_hex::<32>("public key", &key.public_key_hex)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AuthorityError> {
        self.validate()?;
        Ok(hash_serialized(POLICY_DOMAIN, self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityChallenge {
    pub schema_version: u32,
    pub kind: String,
    pub action: AuthorityAction,
    pub subject_blake3: String,
    pub holon_id: String,
    pub audience: String,
    pub nonce_blake3: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl AuthorityChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action: AuthorityAction,
        subject_blake3: impl Into<String>,
        holon_id: impl Into<String>,
        audience: impl Into<String>,
        nonce_entropy: [u8; 32],
        issued_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, AuthorityError> {
        let subject_blake3 = subject_blake3.into();
        let holon_id = holon_id.into();
        if !valid_blake3_hex(&subject_blake3) || !valid_blake3_hex(&holon_id) {
            return Err(AuthorityError::InvalidDigest);
        }
        if ttl_ms == 0 {
            return Err(AuthorityError::InvalidFreshness);
        }
        let expires_at_ms = issued_at_ms
            .checked_add(ttl_ms)
            .ok_or(AuthorityError::InvalidFreshness)?;
        let mut nonce = blake3::Hasher::new();
        nonce.update(CHALLENGE_DOMAIN);
        nonce.update(&nonce_entropy);
        nonce.update(subject_blake3.as_bytes());
        nonce.update(holon_id.as_bytes());
        nonce.update(action.as_str().as_bytes());
        Ok(Self {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_CHALLENGE_KIND.into(),
            action,
            subject_blake3,
            holon_id,
            audience: audience.into(),
            nonce_blake3: nonce.finalize().to_hex().to_string(),
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Canonical signing payload. This intentionally does not use serde JSON so
    /// signature semantics cannot change with JSON formatting or map ordering.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        if self.schema_version != AUTHORITY_SCHEMA_VERSION
            || self.kind != AUTHORITY_CHALLENGE_KIND
            || !valid_blake3_hex(&self.subject_blake3)
            || !valid_blake3_hex(&self.holon_id)
            || !valid_blake3_hex(&self.nonce_blake3)
        {
            return Err(AuthorityError::InvalidDigest);
        }
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CHALLENGE_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        push_field(&mut out, self.action.as_str());
        push_field(&mut out, &self.subject_blake3);
        push_field(&mut out, &self.holon_id);
        push_field(&mut out, &self.audience);
        push_field(&mut out, &self.nonce_blake3);
        out.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        Ok(out)
    }

    pub fn digest(&self) -> Result<String, AuthorityError> {
        let bytes = self.signing_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(CHALLENGE_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Stable key consumed atomically by the privileged host before mutation.
    pub fn replay_key(&self) -> Result<String, AuthorityError> {
        let digest = self.digest()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REPLAY_DOMAIN);
        hasher.update(digest.as_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DetachedAuthoritySignature {
    pub schema_version: u32,
    pub kind: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub challenge: AuthorityChallenge,
}

/// Result returned only by successful cryptographic verification. Private
/// fields make it an actual Rust capability rather than a public-field DTO.
#[derive(Debug, Clone)]
pub struct VerifiedSignatureEvidence {
    issuer: String,
    signer_key_id: String,
    evidence_blake3: String,
    subject_blake3: String,
    challenge_blake3: String,
    replay_key: String,
    claims: BTreeMap<String, String>,
    policy_id: String,
    policy_digest: String,
    policy_epoch: Option<u64>,
    action: AuthorityAction,
    audience: String,
    holon_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    verified_at_ms: u64,
}

impl VerifiedSignatureEvidence {
    pub fn issuer(&self) -> &str { &self.issuer }
    pub fn signer_key_id(&self) -> &str { &self.signer_key_id }
    pub fn evidence_blake3(&self) -> &str { &self.evidence_blake3 }
    pub fn subject_blake3(&self) -> &str { &self.subject_blake3 }
    pub fn challenge_blake3(&self) -> &str { &self.challenge_blake3 }
    pub fn replay_key(&self) -> &str { &self.replay_key }
    pub fn claims(&self) -> &BTreeMap<String, String> { &self.claims }
    pub fn policy_id(&self) -> &str { &self.policy_id }
    pub fn policy_digest(&self) -> &str { &self.policy_digest }
    pub fn policy_epoch(&self) -> Option<u64> { self.policy_epoch }
    pub fn action(&self) -> AuthorityAction { self.action }
    pub fn audience(&self) -> &str { &self.audience }
    pub fn holon_id(&self) -> &str { &self.holon_id }
    pub fn issued_at_ms(&self) -> u64 { self.issued_at_ms }
    pub fn expires_at_ms(&self) -> u64 { self.expires_at_ms }
    pub fn verified_at_ms(&self) -> u64 { self.verified_at_ms }
}

/// Durable, untrusted audit data. Deserialization never creates an authority
/// capability; a journal copy must be re-verified under the exact historical
/// policy snapshot before a new runtime receipt can be minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProvenanceRecord {
    pub schema_version: u32,
    pub kind: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub policy_epoch: u64,
    pub issuer: String,
    pub signer_key_id: String,
    pub action: AuthorityAction,
    pub audience: String,
    pub subject_blake3: String,
    pub holon_id: String,
    pub challenge_blake3: String,
    pub replay_key: String,
    pub signature_evidence_blake3: String,
    pub signed_proof_blake3: String,
    /// Exact UTF-8 JSON bytes received by the verifier, not a reconstructed DTO.
    pub signed_proof_json: Vec<u8>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub verified_at_ms: u64,
}

impl AuthorityProvenanceRecord {
    /// Check that retained proof bytes and all duplicated digests/bindings agree.
    /// This is integrity validation, not signer trust.
    pub fn validate_integrity(&self) -> Result<(), AuthorityError> {
        if self.schema_version != AUTHORITY_PROVENANCE_SCHEMA_VERSION
            || self.kind != AUTHORITY_PROVENANCE_KIND
            || self.policy_id.trim().is_empty()
            || self.policy_epoch == 0
            || self.issuer.trim().is_empty()
            || self.signer_key_id.trim().is_empty()
            || self.audience.trim().is_empty()
            || !valid_blake3_hex(&self.policy_digest)
            || !valid_blake3_hex(&self.subject_blake3)
            || !valid_blake3_hex(&self.holon_id)
            || !valid_blake3_hex(&self.challenge_blake3)
            || !valid_blake3_hex(&self.replay_key)
            || !valid_blake3_hex(&self.signature_evidence_blake3)
            || !valid_blake3_hex(&self.signed_proof_blake3)
            || self.signed_proof_json.is_empty()
            || self.signed_proof_json.len() > MAX_AUTHORITY_PROOF_BYTES
            || self.expires_at_ms < self.issued_at_ms
            || self.verified_at_ms > self.expires_at_ms
            || self.verified_at_ms.saturating_add(MAX_CLOCK_SKEW_MS) < self.issued_at_ms
        {
            return Err(AuthorityError::InvalidProvenance);
        }

        let signed: DetachedAuthoritySignature =
            serde_json::from_slice(&self.signed_proof_json)
                .map_err(|_| AuthorityError::InvalidProvenance)?;
        let challenge = &signed.challenge;
        if hash_bytes_domain(SIGNED_PROOF_DOMAIN, &self.signed_proof_json)
                != self.signed_proof_blake3
            || hash_serialized(EVIDENCE_DOMAIN, &signed) != self.signature_evidence_blake3
            || challenge.digest()? != self.challenge_blake3
            || challenge.replay_key()? != self.replay_key
            || signed.key_id != self.signer_key_id
            || challenge.action != self.action
            || challenge.audience != self.audience
            || challenge.subject_blake3 != self.subject_blake3
            || challenge.holon_id != self.holon_id
            || challenge.issued_at_ms != self.issued_at_ms
            || challenge.expires_at_ms != self.expires_at_ms
        {
            return Err(AuthorityError::InvalidProvenance);
        }
        Ok(())
    }

    /// Fail closed before payload release if the policy changed, the signer was
    /// emergency-revoked, or the original approval window has expired.
    fn validate_release_at(
        &self,
        current_policy_epoch: u64,
        emergency_revoked_key_ids: &std::collections::BTreeSet<String>,
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        self.validate_integrity()?;
        if current_policy_epoch != self.policy_epoch {
            return Err(AuthorityError::PolicyEpochMismatch);
        }
        if emergency_revoked_key_ids.contains(&self.signer_key_id) {
            return Err(AuthorityError::RevokedSigner);
        }
        if now_ms > self.expires_at_ms {
            return Err(AuthorityError::InvalidFreshness);
        }
        Ok(())
    }
}

/// Runtime-only capability minted by successful verification. It has no
/// Serialize or Deserialize implementation.
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityReceipt {
    provenance: AuthorityProvenanceRecord,
}

impl VerifiedAuthorityReceipt {
    pub fn provenance(&self) -> &AuthorityProvenanceRecord { &self.provenance }
    pub fn into_provenance(self) -> AuthorityProvenanceRecord { self.provenance }
    pub fn issuer(&self) -> &str { &self.provenance.issuer }
    pub fn signer_key_id(&self) -> &str { &self.provenance.signer_key_id }
    pub fn evidence_blake3(&self) -> &str { &self.provenance.signature_evidence_blake3 }
    pub fn subject_blake3(&self) -> &str { &self.provenance.subject_blake3 }
    pub fn challenge_blake3(&self) -> &str { &self.provenance.challenge_blake3 }
    pub fn replay_key(&self) -> &str { &self.provenance.replay_key }
    pub fn policy_id(&self) -> &str { &self.provenance.policy_id }
    pub fn policy_digest(&self) -> &str { &self.provenance.policy_digest }
    pub fn policy_epoch(&self) -> u64 { self.provenance.policy_epoch }
    pub fn action(&self) -> AuthorityAction { self.provenance.action }
    pub fn audience(&self) -> &str { &self.provenance.audience }
    pub fn holon_id(&self) -> &str { &self.provenance.holon_id }
    pub fn issued_at_ms(&self) -> u64 { self.provenance.issued_at_ms }
    pub fn expires_at_ms(&self) -> u64 { self.provenance.expires_at_ms }
    pub fn verified_at_ms(&self) -> u64 { self.provenance.verified_at_ms }

    pub fn validate_release_at(
        &self,
        current_policy_epoch: u64,
        emergency_revoked_key_ids: &std::collections::BTreeSet<String>,
        now_ms: u64,
    ) -> Result<(), AuthorityError> {
        self.provenance.validate_release_at(
            current_policy_epoch,
            emergency_revoked_key_ids,
            now_ms,
        )
    }
}

pub struct AuthorityVerifier<'a> {
    policy: &'a AuthorityTrustPolicy,
}

impl<'a> AuthorityVerifier<'a> {
    pub fn new(policy: &'a AuthorityTrustPolicy) -> Result<Self, AuthorityError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    /// Verify exact JSON proof bytes and mint a durable-admission receipt.
    /// This path requires a non-zero machine-managed policy epoch.
    pub fn verify_json(
        &self,
        signed_proof_json: &[u8],
        expected_action: AuthorityAction,
        expected_subject_blake3: &str,
        expected_holon_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedAuthorityReceipt, AuthorityError> {
        if signed_proof_json.len() > MAX_AUTHORITY_PROOF_BYTES {
            return Err(AuthorityError::ProofTooLarge);
        }
        let signed: DetachedAuthoritySignature =
            serde_json::from_slice(signed_proof_json)
                .map_err(|_| AuthorityError::InvalidEncoding("signed authority JSON"))?;
        let evidence = self.verify(
            &signed,
            expected_action,
            expected_subject_blake3,
            expected_holon_id,
            now_ms,
        )?;
        let policy_epoch = self.policy.policy_epoch.ok_or(AuthorityError::MissingPolicyEpoch)?;
        if policy_epoch == 0 {
            return Err(AuthorityError::InvalidPolicyEpoch);
        }
        let provenance = AuthorityProvenanceRecord {
            schema_version: AUTHORITY_PROVENANCE_SCHEMA_VERSION,
            kind: AUTHORITY_PROVENANCE_KIND.into(),
            policy_id: self.policy.policy_id.clone(),
            policy_digest: self.policy.digest()?,
            policy_epoch,
            issuer: evidence.issuer.clone(),
            signer_key_id: evidence.signer_key_id.clone(),
            action: evidence.action,
            audience: evidence.audience.clone(),
            subject_blake3: evidence.subject_blake3.clone(),
            holon_id: evidence.holon_id.clone(),
            challenge_blake3: evidence.challenge_blake3.clone(),
            replay_key: evidence.replay_key.clone(),
            signature_evidence_blake3: evidence.evidence_blake3.clone(),
            signed_proof_blake3: hash_bytes_domain(SIGNED_PROOF_DOMAIN, signed_proof_json),
            signed_proof_json: signed_proof_json.to_vec(),
            issued_at_ms: evidence.issued_at_ms,
            expires_at_ms: evidence.expires_at_ms,
            verified_at_ms: evidence.verified_at_ms,
        };
        provenance.validate_integrity()?;
        Ok(VerifiedAuthorityReceipt { provenance })
    }

    /// Typed convenience wrapper. Use verify_json at ingress when preserving
    /// original transport bytes is required.
    pub fn verify_receipt(
        &self,
        signed: &DetachedAuthoritySignature,
        expected_action: AuthorityAction,
        expected_subject_blake3: &str,
        expected_holon_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedAuthorityReceipt, AuthorityError> {
        let bytes = serde_json::to_vec(signed)
            .map_err(|_| AuthorityError::InvalidEncoding("signed authority JSON"))?;
        self.verify_json(
            &bytes,
            expected_action,
            expected_subject_blake3,
            expected_holon_id,
            now_ms,
        )
    }

    /// Reconstruct historical validity under the exact archived policy.
    /// The caller must load the immutable policy matching the recorded digest.
    pub fn reverify_historical_provenance(
        &self,
        record: &AuthorityProvenanceRecord,
    ) -> Result<VerifiedAuthorityReceipt, AuthorityError> {
        record.validate_integrity()?;
        if self.policy.policy_epoch != Some(record.policy_epoch)
            || self.policy.digest()? != record.policy_digest
            || self.policy.policy_id != record.policy_id
        {
            return Err(AuthorityError::PolicyEpochMismatch);
        }
        let receipt = self.verify_json(
            &record.signed_proof_json,
            record.action,
            &record.subject_blake3,
            &record.holon_id,
            record.verified_at_ms,
        )?;
        if receipt.provenance != *record {
            return Err(AuthorityError::InvalidProvenance);
        }
        Ok(receipt)
    }

    pub fn verify(
        &self,
        signed: &DetachedAuthoritySignature,
        expected_action: AuthorityAction,
        expected_subject_blake3: &str,
        expected_holon_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedSignatureEvidence, AuthorityError> {
        if signed.schema_version != AUTHORITY_SCHEMA_VERSION
            || signed.kind != AUTHORITY_SIGNATURE_KIND
            || signed.algorithm != "ed25519"
        {
            return Err(AuthorityError::InvalidSignature);
        }
        let challenge = &signed.challenge;
        if challenge.subject_blake3 != expected_subject_blake3 {
            return Err(AuthorityError::SubjectMismatch);
        }
        if challenge.holon_id != expected_holon_id {
            return Err(AuthorityError::HolonMismatch);
        }
        if challenge.action != expected_action {
            return Err(AuthorityError::ActionMismatch);
        }
        if challenge.expires_at_ms < challenge.issued_at_ms
            || challenge.expires_at_ms - challenge.issued_at_ms > self.policy.max_ttl_ms
        {
            return Err(AuthorityError::ExcessiveTtl);
        }
        if now_ms.saturating_add(MAX_CLOCK_SKEW_MS) < challenge.issued_at_ms
            || now_ms > challenge.expires_at_ms
        {
            return Err(AuthorityError::InvalidFreshness);
        }
        if !self.policy.allowed_audiences.is_empty()
            && !self
                .policy
                .allowed_audiences
                .iter()
                .any(|a| a == &challenge.audience)
        {
            return Err(AuthorityError::AudienceMismatch);
        }
        let trusted = self
            .policy
            .keys
            .iter()
            .find(|key| key.key_id == signed.key_id)
            .ok_or(AuthorityError::UntrustedSigner)?;
        if trusted.revoked {
            return Err(AuthorityError::RevokedSigner);
        }
        if !trusted.allowed_actions.contains(&expected_action) {
            return Err(AuthorityError::ActionNotPermitted);
        }
        if trusted.public_key_hex != signed.public_key_hex {
            return Err(AuthorityError::PublicKeyMismatch);
        }
        if let Some(bound_holon) = trusted.claims.get("holon_id") {
            if bound_holon != expected_holon_id {
                return Err(AuthorityError::HolonMismatch);
            }
        }

        let public_key_bytes = decode_hex::<32>("public key", &signed.public_key_hex)?;
        let signature_bytes = decode_hex::<64>("signature", &signed.signature_hex)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| AuthorityError::InvalidEncoding("public key"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let signing_bytes = challenge.signing_bytes()?;
        verifying_key
            .verify_strict(&signing_bytes, &signature)
            .map_err(|_| AuthorityError::InvalidSignature)?;

        let challenge_blake3 = challenge.digest()?;
        let replay_key = challenge.replay_key()?;
        let evidence_blake3 = hash_serialized(EVIDENCE_DOMAIN, signed);
        let mut claims = trusted.claims.clone();
        claims.insert("authority_policy_blake3".into(), self.policy.digest()?);
        claims.insert("authority_action".into(), expected_action.as_str().into());
        claims.insert("authority_audience".into(), challenge.audience.clone());
        claims.insert("challenge_blake3".into(), challenge_blake3.clone());
        claims.insert("replay_key".into(), replay_key.clone());
        claims.insert("signature_algorithm".into(), "ed25519".into());
        Ok(VerifiedSignatureEvidence {
            issuer: trusted.issuer.clone(),
            signer_key_id: trusted.key_id.clone(),
            evidence_blake3,
            subject_blake3: challenge.subject_blake3.clone(),
            challenge_blake3,
            replay_key,
            claims,
            policy_id: self.policy.policy_id.clone(),
            policy_digest: self.policy.digest()?,
            policy_epoch: self.policy.policy_epoch,
            action: expected_action,
            audience: challenge.audience.clone(),
            holon_id: challenge.holon_id.clone(),
            issued_at_ms: challenge.issued_at_ms,
            expires_at_ms: challenge.expires_at_ms,
            verified_at_ms: now_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn policy(signing: &SigningKey) -> AuthorityTrustPolicy {
        AuthorityTrustPolicy {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_POLICY_KIND.into(),
            policy_id: "owner-root-v1".into(),
            policy_epoch: Some(1),
            keys: vec![TrustedAuthorityKey {
                key_id: "owner-1".into(),
                issuer: "owner".into(),
                public_key_hex: hex(signing.verifying_key().as_bytes()),
                allowed_actions: vec![AuthorityAction::Genesis, AuthorityAction::Reconstitute],
                revoked: false,
                claims: BTreeMap::new(),
            }],
            max_ttl_ms: 60_000,
            allowed_audiences: vec!["spore.local".into()],
        }
    }

    fn signed(signing: &SigningKey, challenge: AuthorityChallenge) -> DetachedAuthoritySignature {
        let signature = signing.sign(&challenge.signing_bytes().unwrap());
        DetachedAuthoritySignature {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            key_id: "owner-1".into(),
            public_key_hex: hex(signing.verifying_key().as_bytes()),
            signature_hex: hex(&signature.to_bytes()),
            challenge,
        }
    }

    #[test]
    fn exact_subject_signature_verifies() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [3u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let verified = AuthorityVerifier::new(&policy(&signing))
            .unwrap()
            .verify(
                &signed,
                AuthorityAction::Genesis,
                &"11".repeat(32),
                &"22".repeat(32),
                1_010_000,
            )
            .unwrap();
        assert_eq!(verified.signer_key_id(), "owner-1");
        assert_eq!(verified.subject_blake3(), "11".repeat(32));
        assert!(valid_blake3_hex(verified.replay_key()));
    }

    #[test]
    fn signature_cannot_authorize_another_subject() {
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [4u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let err = AuthorityVerifier::new(&policy(&signing))
            .unwrap()
            .verify(
                &signed,
                AuthorityAction::Genesis,
                &"33".repeat(32),
                &"22".repeat(32),
                1_010_000,
            )
            .unwrap_err();
        assert_eq!(err, AuthorityError::SubjectMismatch);
    }

    #[test]
    fn authority_wire_types_reject_unrecognized_fields() {
        let signing = SigningKey::from_bytes(&[10u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [6u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let mut signed_json = serde_json::to_value(&signed).unwrap();

        // The outer signature envelope is an untrusted wire DTO. Unknown
        // metadata is rejected rather than silently ignored.
        signed_json["unrecognized"] = serde_json::json!("must-reject");
        assert!(serde_json::from_value::<DetachedAuthoritySignature>(signed_json).is_err());

        // Nested challenge data is equally strict.
        let mut challenge_json = serde_json::to_value(&signed.challenge).unwrap();
        challenge_json["future_security_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuthorityChallenge>(challenge_json).is_err());

        // The local trust policy and each trusted key are strict configuration
        // records; a typo must not be ignored and silently fall back to a default.
        let mut policy_json = serde_json::to_value(policy(&signing)).unwrap();
        policy_json["allow_all"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuthorityTrustPolicy>(policy_json).is_err());

        let mut key_json = serde_json::to_value(policy(&signing).keys[0].clone()).unwrap();
        key_json["privileged"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TrustedAuthorityKey>(key_json).is_err());
    }


    #[test]
    fn provenance_receipt_preserves_exact_proof_and_reverifies_after_serialization() {
        let signing = SigningKey::from_bytes(&[17u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [18u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let compact = serde_json::to_string(&signed).unwrap();
        let exact_wire = format!(" \n{compact}\t ").into_bytes();
        let policy = policy(&signing);
        let verifier = AuthorityVerifier::new(&policy).unwrap();
        let receipt = verifier
            .verify_json(
                &exact_wire,
                AuthorityAction::Genesis,
                &"11".repeat(32),
                &"22".repeat(32),
                1_010_000,
            )
            .unwrap();

        assert_eq!(receipt.provenance().signed_proof_json, exact_wire);
        assert_eq!(receipt.policy_epoch(), 1);
        assert_eq!(receipt.verified_at_ms(), 1_010_000);

        let durable = serde_json::to_vec(receipt.provenance()).unwrap();
        let recovered: AuthorityProvenanceRecord = serde_json::from_slice(&durable).unwrap();
        let reverified = verifier.reverify_historical_provenance(&recovered).unwrap();
        assert_eq!(reverified.provenance(), &recovered);
        reverified
            .validate_release_at(1, &std::collections::BTreeSet::new(), 1_020_000)
            .unwrap();
    }

    #[test]
    fn policy_epoch_is_covered_by_the_policy_digest() {
        let signing = SigningKey::from_bytes(&[25u8; 32]);
        let mut first = policy(&signing);
        let first_digest = first.digest().unwrap();
        first.policy_epoch = Some(2);
        let second_digest = first.digest().unwrap();
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn admission_receipt_requires_a_nonzero_local_policy_epoch() {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [20u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let mut legacy_policy = policy(&signing);
        legacy_policy.policy_epoch = None;
        let verifier = AuthorityVerifier::new(&legacy_policy).unwrap();
        let bytes = serde_json::to_vec(&signed).unwrap();
        assert_eq!(
            verifier
                .verify_json(
                    &bytes,
                    AuthorityAction::Genesis,
                    &"11".repeat(32),
                    &"22".repeat(32),
                    1_010_000,
                )
                .unwrap_err(),
            AuthorityError::MissingPolicyEpoch
        );
    }

    #[test]
    fn release_rejects_policy_drift_emergency_revocation_and_expiry() {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [22u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let receipt = AuthorityVerifier::new(&policy(&signing))
            .unwrap()
            .verify_receipt(
                &signed,
                AuthorityAction::Genesis,
                &"11".repeat(32),
                &"22".repeat(32),
                1_010_000,
            )
            .unwrap();

        assert_eq!(
            receipt.validate_release_at(2, &std::collections::BTreeSet::new(), 1_020_000),
            Err(AuthorityError::PolicyEpochMismatch)
        );
        let revoked = std::collections::BTreeSet::from(["owner-1".to_string()]);
        assert_eq!(
            receipt.validate_release_at(1, &revoked, 1_020_000),
            Err(AuthorityError::RevokedSigner)
        );
        assert_eq!(
            receipt.validate_release_at(1, &std::collections::BTreeSet::new(), 1_040_000),
            Err(AuthorityError::InvalidFreshness)
        );
    }

    #[test]
    fn provenance_integrity_rejects_tampered_raw_proof_bytes() {
        let signing = SigningKey::from_bytes(&[23u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [24u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let receipt = AuthorityVerifier::new(&policy(&signing))
            .unwrap()
            .verify_receipt(
                &signed,
                AuthorityAction::Genesis,
                &"11".repeat(32),
                &"22".repeat(32),
                1_010_000,
            )
            .unwrap();
        let mut record = receipt.provenance().clone();
        record.signed_proof_json[0] ^= 1;
        assert_eq!(record.validate_integrity(), Err(AuthorityError::InvalidProvenance));
        assert_eq!(
            AuthorityVerifier::new(&policy(&signing))
                .unwrap()
                .reverify_historical_provenance(&record)
                .unwrap_err(),
            AuthorityError::InvalidProvenance
        );
    }

    #[test]
    fn expired_signature_is_rejected() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let challenge = AuthorityChallenge::new(
            AuthorityAction::Reconstitute,
            "11".repeat(32),
            "22".repeat(32),
            "spore.local",
            [5u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap();
        let signed = signed(&signing, challenge);
        let err = AuthorityVerifier::new(&policy(&signing))
            .unwrap()
            .verify(
                &signed,
                AuthorityAction::Reconstitute,
                &"11".repeat(32),
                &"22".repeat(32),
                1_100_000,
            )
            .unwrap_err();
        assert_eq!(err, AuthorityError::InvalidFreshness);
    }
}
