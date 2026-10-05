// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public owner-root enrollment for sovereign Holons.
//!
//! The long-lived signing secret is deliberately outside this module. A Holon
//! persists only public trust material, an enrollment receipt, and recovery /
//! rotation metadata. Owner authority and software-release authority are
//! intentionally separate roots.

use crate::authority_signature::{
    AUTHORITY_POLICY_KIND, AUTHORITY_SCHEMA_VERSION, AuthorityAction, AuthorityTrustPolicy,
    TrustedAuthorityKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const OWNER_ROOT_SCHEMA_VERSION: u32 = 1;
pub const OWNER_ROOT_KIND: &str = "symthaea-owner-root-v1";
pub const OWNER_ENROLLMENT_KIND: &str = "symthaea-owner-root-enrollment-v1";
const OWNER_ROOT_DOMAIN: &[u8] = b"symthaea-owner-root-v1\0";
const OWNER_ENROLLMENT_DOMAIN: &[u8] = b"symthaea-owner-root-enrollment-v1\0";

fn valid_digest(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_key(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("owner-root serialization is infallible");
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
    h.finalize().to_hex().to_string()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OwnerRootError {
    #[error("invalid owner public key")]
    InvalidPublicKey,
    #[error("invalid Holon or release digest")]
    InvalidDigest,
    #[error("owner key identifier is empty")]
    InvalidKeyId,
    #[error("owner enrollment policy is invalid")]
    InvalidPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRecoveryPolicy {
    /// Human-readable policy label. No recovery secret is stored here.
    pub mode: String,
    /// Minimum independent recovery authorities required when a threshold
    /// recovery mechanism is eventually configured.
    pub threshold: u8,
    /// Public recovery/key-rotation descriptors only.
    #[serde(default)]
    pub descriptors: Vec<String>,
}

impl Default for OwnerRecoveryPolicy {
    fn default() -> Self {
        Self {
            mode: "owner-device-plus-offline-recovery-v1".into(),
            threshold: 1,
            descriptors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRootPublicIdentity {
    pub schema_version: u32,
    pub kind: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub display_name: String,
    pub created_at_ms: u64,
    /// Release identity under which the enrollment ceremony UI/relay was
    /// verified. This does not grant the release key owner authority.
    pub enrollment_release_manifest_blake3: String,
    pub recovery: OwnerRecoveryPolicy,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

impl OwnerRootPublicIdentity {
    pub fn new(
        key_id: impl Into<String>,
        public_key_hex: impl Into<String>,
        display_name: impl Into<String>,
        created_at_ms: u64,
        enrollment_release_manifest_blake3: impl Into<String>,
        recovery: OwnerRecoveryPolicy,
    ) -> Result<Self, OwnerRootError> {
        let identity = Self {
            schema_version: OWNER_ROOT_SCHEMA_VERSION,
            kind: OWNER_ROOT_KIND.into(),
            key_id: key_id.into(),
            public_key_hex: public_key_hex.into(),
            display_name: display_name.into(),
            created_at_ms,
            enrollment_release_manifest_blake3: enrollment_release_manifest_blake3.into(),
            recovery,
            claims: BTreeMap::new(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), OwnerRootError> {
        if self.schema_version != OWNER_ROOT_SCHEMA_VERSION || self.kind != OWNER_ROOT_KIND {
            return Err(OwnerRootError::InvalidPolicy);
        }
        if self.key_id.trim().is_empty() {
            return Err(OwnerRootError::InvalidKeyId);
        }
        if !valid_key(&self.public_key_hex) {
            return Err(OwnerRootError::InvalidPublicKey);
        }
        if !valid_digest(&self.enrollment_release_manifest_blake3) {
            return Err(OwnerRootError::InvalidDigest);
        }
        if self.recovery.threshold == 0 {
            return Err(OwnerRootError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, OwnerRootError> {
        self.validate()?;
        Ok(hash_serialized(OWNER_ROOT_DOMAIN, self))
    }

    pub fn short_fingerprint(&self) -> Result<String, OwnerRootError> {
        let digest = self.digest()?;
        Ok(format!(
            "{}-{}-{}-{}",
            &digest[0..4],
            &digest[4..8],
            &digest[8..12],
            &digest[12..16]
        ))
    }

    /// Produce the initial owner authority trust policy. The release root is
    /// intentionally not included; release and owner authority are separate.
    pub fn authority_policy(
        &self,
        holon_id: &str,
        audience: impl Into<String>,
    ) -> Result<AuthorityTrustPolicy, OwnerRootError> {
        self.validate()?;
        if !valid_digest(holon_id) {
            return Err(OwnerRootError::InvalidDigest);
        }
        let mut claims = self.claims.clone();
        claims.insert("role".into(), "owner-root".into());
        claims.insert("holon_id".into(), holon_id.into());
        claims.insert("owner_root_blake3".into(), self.digest()?);
        let policy = AuthorityTrustPolicy {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            kind: AUTHORITY_POLICY_KIND.into(),
            policy_id: format!("owner-root:{}", self.key_id),
            keys: vec![TrustedAuthorityKey {
                key_id: self.key_id.clone(),
                issuer: "owner-root".into(),
                public_key_hex: self.public_key_hex.clone(),
                allowed_actions: vec![
                    AuthorityAction::Genesis,
                    AuthorityAction::Reconstitute,
                    AuthorityAction::Update,
                    AuthorityAction::Change,
                    AuthorityAction::GuestRealize,
                    AuthorityAction::NetworkActivate,
                    AuthorityAction::SecurityEnrollment,
                ],
                revoked: false,
                claims,
            }],
            max_ttl_ms: 15 * 60 * 1000,
            allowed_audiences: {
                let mut audiences = std::collections::BTreeSet::from([
                    "symthaea-spore-genesis-v1".to_string(),
                    "symthaea-spore-reconstitution-v1".to_string(),
                    "symthaea-spore-guest-realize-v1".to_string(),
                    "symthaea-spore-network-activate-v1".to_string(),
                    "symthaea-spore-update-v1".to_string(),
                    "symthaea-spore-change-v1".to_string(),
                    "symthaea-spore-security-enrollment-v1".to_string(),
                    "nixward-change-v1".to_string(),
                    "nixward-execution-intent-v1".to_string(),
                ]);
                audiences.insert(audience.into());
                audiences.into_iter().collect()
            },
        };
        policy
            .validate()
            .map_err(|_| OwnerRootError::InvalidPolicy)?;
        Ok(policy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnerRootEnrollmentIntent {
    pub schema_version: u32,
    pub kind: String,
    pub holon_id: String,
    pub owner_root: OwnerRootPublicIdentity,
    pub release_manifest_blake3: String,
    pub nonce_blake3: String,
    pub issued_at_ms: u64,
}

impl OwnerRootEnrollmentIntent {
    pub fn new(
        holon_id: impl Into<String>,
        owner_root: OwnerRootPublicIdentity,
        release_manifest_blake3: impl Into<String>,
        nonce_entropy: [u8; 32],
        issued_at_ms: u64,
    ) -> Result<Self, OwnerRootError> {
        owner_root.validate()?;
        let holon_id = holon_id.into();
        let release_manifest_blake3 = release_manifest_blake3.into();
        if !valid_digest(&holon_id) || !valid_digest(&release_manifest_blake3) {
            return Err(OwnerRootError::InvalidDigest);
        }
        if owner_root.enrollment_release_manifest_blake3 != release_manifest_blake3 {
            return Err(OwnerRootError::InvalidPolicy);
        }
        let mut h = blake3::Hasher::new();
        h.update(OWNER_ENROLLMENT_DOMAIN);
        h.update(&nonce_entropy);
        h.update(holon_id.as_bytes());
        h.update(owner_root.digest()?.as_bytes());
        Ok(Self {
            schema_version: OWNER_ROOT_SCHEMA_VERSION,
            kind: OWNER_ENROLLMENT_KIND.into(),
            holon_id,
            owner_root,
            release_manifest_blake3,
            nonce_blake3: h.finalize().to_hex().to_string(),
            issued_at_ms,
        })
    }

    pub fn digest(&self) -> Result<String, OwnerRootError> {
        if self.schema_version != OWNER_ROOT_SCHEMA_VERSION
            || self.kind != OWNER_ENROLLMENT_KIND
            || !valid_digest(&self.holon_id)
            || !valid_digest(&self.release_manifest_blake3)
            || !valid_digest(&self.nonce_blake3)
        {
            return Err(OwnerRootError::InvalidDigest);
        }
        Ok(hash_serialized(OWNER_ENROLLMENT_DOMAIN, self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_root_produces_scoped_authority_policy() {
        let root = OwnerRootPublicIdentity::new(
            "owner-1",
            "11".repeat(32),
            "Primary owner",
            1000,
            "22".repeat(32),
            OwnerRecoveryPolicy::default(),
        )
        .unwrap();
        let policy = root
            .authority_policy(&"33".repeat(32), "spore.local")
            .unwrap();
        assert_eq!(policy.keys.len(), 1);
        assert!(
            policy.keys[0]
                .allowed_actions
                .contains(&AuthorityAction::Genesis)
        );
        assert!(
            policy
                .allowed_audiences
                .iter()
                .any(|v| v == "symthaea-spore-reconstitution-v1")
        );
        assert!(
            policy
                .allowed_audiences
                .iter()
                .any(|v| v == "symthaea-spore-guest-realize-v1")
        );
        assert!(
            policy
                .allowed_audiences
                .iter()
                .any(|v| v == "symthaea-spore-network-activate-v1")
        );
        assert_eq!(
            policy.keys[0].claims.get("holon_id").unwrap(),
            &"33".repeat(32)
        );
    }

    #[test]
    fn release_identity_is_bound_but_never_becomes_owner_key() {
        let root = OwnerRootPublicIdentity::new(
            "owner-1",
            "11".repeat(32),
            "Primary owner",
            1000,
            "22".repeat(32),
            OwnerRecoveryPolicy::default(),
        )
        .unwrap();
        let policy = root
            .authority_policy(&"33".repeat(32), "spore.local")
            .unwrap();
        assert_ne!(
            policy.keys[0].public_key_hex,
            root.enrollment_release_manifest_blake3
        );
    }
}
