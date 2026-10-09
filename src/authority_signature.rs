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
const CHALLENGE_DOMAIN: &[u8] = b"symthaea-authority-challenge-v1\0";
const POLICY_DOMAIN: &[u8] = b"symthaea-authority-policy-v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"symthaea-authority-evidence-v1\0";
const REPLAY_DOMAIN: &[u8] = b"symthaea-authority-replay-v1\0";
const DEFAULT_MAX_TTL_MS: u64 = 15 * 60 * 1000;
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

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("authority evidence serialization is infallible");
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    hasher.finalize().to_hex().to_string()
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
    #[error("authority trust policy has no explicit audience")]
    InvalidAudiencePolicy,
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
pub struct AuthorityTrustPolicy {
    pub schema_version: u32,
    pub kind: String,
    pub policy_id: String,
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
        if self.schema_version != AUTHORITY_SCHEMA_VERSION
            || self.kind != AUTHORITY_POLICY_KIND
            || self.policy_id.trim().is_empty()
            || self.max_ttl_ms == 0
        {
            return Err(AuthorityError::UntrustedSigner);
        }
        if self.allowed_audiences.is_empty()
            || self
                .allowed_audiences
                .iter()
                .any(|audience| audience.trim().is_empty())
        {
            return Err(AuthorityError::InvalidAudiencePolicy);
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
        let audience = audience.into();
        if !valid_blake3_hex(&subject_blake3) || !valid_blake3_hex(&holon_id) {
            return Err(AuthorityError::InvalidDigest);
        }
        if audience.trim().is_empty() {
            return Err(AuthorityError::InvalidAudiencePolicy);
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
            audience,
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
pub struct DetachedAuthoritySignature {
    pub schema_version: u32,
    pub kind: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub challenge: AuthorityChallenge,
}

/// Result returned only by successful cryptographic verification. It is not
/// deserializable and therefore cannot be materialized from an untrusted JSON
/// payload as an authority capability.
#[derive(Debug, Clone)]
pub struct VerifiedSignatureEvidence {
    pub issuer: String,
    pub signer_key_id: String,
    pub evidence_blake3: String,
    pub subject_blake3: String,
    pub challenge_blake3: String,
    pub replay_key: String,
    pub claims: BTreeMap<String, String>,
}

pub struct AuthorityVerifier<'a> {
    policy: &'a AuthorityTrustPolicy,
}

impl<'a> AuthorityVerifier<'a> {
    pub fn new(policy: &'a AuthorityTrustPolicy) -> Result<Self, AuthorityError> {
        policy.validate()?;
        Ok(Self { policy })
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
        assert_eq!(verified.signer_key_id, "owner-1");
        assert_eq!(verified.subject_blake3, "11".repeat(32));
        assert!(valid_blake3_hex(&verified.replay_key));
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
    fn empty_policy_audience_is_rejected() {
        let signing = SigningKey::from_bytes(&[6u8; 32]);
        let mut trust = policy(&signing);
        trust.allowed_audiences.clear();
        assert!(matches!(
            AuthorityVerifier::new(&trust),
            Err(AuthorityError::InvalidAudiencePolicy)
        ));
    }

    #[test]
    fn empty_challenge_audience_is_rejected() {
        let err = AuthorityChallenge::new(
            AuthorityAction::Genesis,
            "11".repeat(32),
            "22".repeat(32),
            "   ",
            [5u8; 32],
            1_000_000,
            30_000,
        )
        .unwrap_err();
        assert_eq!(err, AuthorityError::InvalidAudiencePolicy);
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
