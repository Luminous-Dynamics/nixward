// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed release-manifest verification for Spore/Nixward artifacts.
//!
//! Release authority is deliberately separate from owner authority. This module
//! verifies an Ed25519 signature over a canonical manifest and then verifies the
//! bytes of every declared artifact. It never grants machine-mutation authority.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RELEASE_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_MANIFEST_KIND: &str = "symthaea-release-manifest-v1";
pub const RELEASE_SIGNATURE_KIND: &str = "symthaea-release-signature-v1";
const RELEASE_DOMAIN: &[u8] = b"symthaea-release-manifest-v1\0";

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ReleaseIntegrityError> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ReleaseIntegrityError::InvalidEncoding);
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (value.as_bytes()[i * 2] as char)
            .to_digit(16)
            .ok_or(ReleaseIntegrityError::InvalidEncoding)?;
        let lo = (value.as_bytes()[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or(ReleaseIntegrityError::InvalidEncoding)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains("..")
        && !path.contains('\\')
        && path.split('/').all(|part| !part.is_empty() && part != ".")
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReleaseIntegrityError {
    #[error("invalid release manifest")]
    InvalidManifest,
    #[error("invalid release encoding")]
    InvalidEncoding,
    #[error("release signature is invalid")]
    InvalidSignature,
    #[error("release signer does not match the trusted release root")]
    UntrustedReleaseRoot,
    #[error("release artifact is missing: {0}")]
    MissingArtifact(String),
    #[error("release artifact digest mismatch: {0}")]
    ArtifactDigestMismatch(String),
    #[error("release artifact size mismatch: {0}")]
    ArtifactSizeMismatch(String),
    #[error("release artifact executable mode mismatch: {0}")]
    ArtifactModeMismatch(String),
    #[error("unsafe release artifact path: {0}")]
    UnsafePath(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseArtifact {
    pub path: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub kind: String,
    pub release_id: String,
    pub created_at_ms: u64,
    pub source_revision: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<(), ReleaseIntegrityError> {
        if self.schema_version != RELEASE_SCHEMA_VERSION
            || self.kind != RELEASE_MANIFEST_KIND
            || self.release_id.trim().is_empty()
            || self.source_revision.trim().is_empty()
            || self.artifacts.is_empty()
        {
            return Err(ReleaseIntegrityError::InvalidManifest);
        }
        let mut seen = std::collections::BTreeSet::new();
        for artifact in &self.artifacts {
            if !safe_relative_path(&artifact.path) {
                return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
            }
            if artifact.blake3.len() != 64
                || !artifact.blake3.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(ReleaseIntegrityError::InvalidManifest);
            }
            if !seen.insert(&artifact.path) {
                return Err(ReleaseIntegrityError::InvalidManifest);
            }
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ReleaseIntegrityError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(RELEASE_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        fn push(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        push(&mut out, &self.release_id);
        out.extend_from_slice(&self.created_at_ms.to_le_bytes());
        push(&mut out, &self.source_revision);
        out.extend_from_slice(&(self.artifacts.len() as u64).to_le_bytes());
        for a in &self.artifacts {
            push(&mut out, &a.path);
            push(&mut out, &a.blake3.to_ascii_lowercase());
            out.extend_from_slice(&a.size_bytes.to_le_bytes());
            out.push(u8::from(a.executable));
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<String, ReleaseIntegrityError> {
        let bytes = self.signing_bytes()?;
        let mut h = blake3::Hasher::new();
        h.update(RELEASE_DOMAIN);
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        Ok(h.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedReleaseManifest {
    pub kind: String,
    pub algorithm: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
    pub manifest: ReleaseManifest,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerifiedReleaseManifest {
    pub release_id: String,
    pub manifest_blake3: String,
    pub signer_public_key_hex: String,
    pub artifact_count: usize,
}

pub fn verify_release_signature(
    signed: &SignedReleaseManifest,
    trusted_release_public_key_hex: &str,
) -> Result<VerifiedReleaseManifest, ReleaseIntegrityError> {
    if signed.kind != RELEASE_SIGNATURE_KIND || signed.algorithm != "ed25519" {
        return Err(ReleaseIntegrityError::InvalidSignature);
    }
    if signed.signer_public_key_hex != trusted_release_public_key_hex {
        return Err(ReleaseIntegrityError::UntrustedReleaseRoot);
    }
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(&signed.signer_public_key_hex)?)
        .map_err(|_| ReleaseIntegrityError::InvalidEncoding)?;
    let signature = Signature::from_bytes(&decode_hex::<64>(&signed.signature_hex)?);
    let bytes = signed.manifest.signing_bytes()?;
    key.verify_strict(&bytes, &signature)
        .map_err(|_| ReleaseIntegrityError::InvalidSignature)?;
    Ok(VerifiedReleaseManifest {
        release_id: signed.manifest.release_id.clone(),
        manifest_blake3: signed.manifest.digest()?,
        signer_public_key_hex: signed.signer_public_key_hex.clone(),
        artifact_count: signed.manifest.artifacts.len(),
    })
}

#[cfg(feature = "native")]
pub fn verify_release_tree(
    root: &std::path::Path,
    signed: &SignedReleaseManifest,
    trusted_release_public_key_hex: &str,
) -> Result<VerifiedReleaseManifest, ReleaseIntegrityError> {
    let verified = verify_release_signature(signed, trusted_release_public_key_hex)?;
    let canonical_root = root
        .canonicalize()
        .map_err(|_| ReleaseIntegrityError::MissingArtifact("release-root".into()))?;
    for artifact in &signed.manifest.artifacts {
        let path = root.join(&artifact.path);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| ReleaseIntegrityError::MissingArtifact(artifact.path.clone()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
        }
        let canonical = path
            .canonicalize()
            .map_err(|_| ReleaseIntegrityError::MissingArtifact(artifact.path.clone()))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let actual_executable = metadata.permissions().mode() & 0o111 != 0;
            if actual_executable != artifact.executable {
                return Err(ReleaseIntegrityError::ArtifactModeMismatch(
                    artifact.path.clone(),
                ));
            }
        }
        let bytes = std::fs::read(&canonical)
            .map_err(|_| ReleaseIntegrityError::MissingArtifact(artifact.path.clone()))?;
        if bytes.len() as u64 != artifact.size_bytes {
            return Err(ReleaseIntegrityError::ArtifactSizeMismatch(
                artifact.path.clone(),
            ));
        }
        if blake3::hash(&bytes).to_hex().to_string() != artifact.blake3.to_ascii_lowercase() {
            return Err(ReleaseIntegrityError::ArtifactDigestMismatch(
                artifact.path.clone(),
            ));
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn signed_manifest_verifies_against_separate_release_root() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let manifest = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "spore-v33-test".into(),
            created_at_ms: 1,
            source_revision: "deadbeef".into(),
            artifacts: vec![ReleaseArtifact {
                path: "www/installer.html".into(),
                blake3: "11".repeat(32),
                size_bytes: 123,
                executable: false,
            }],
        };
        let signature = signing.sign(&manifest.signing_bytes().unwrap());
        let signed = SignedReleaseManifest {
            kind: RELEASE_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            signer_public_key_hex: hex(signing.verifying_key().as_bytes()),
            signature_hex: hex(&signature.to_bytes()),
            manifest,
        };
        let verified = verify_release_signature(&signed, &signed.signer_public_key_hex).unwrap();
        assert_eq!(verified.artifact_count, 1);
    }
}
