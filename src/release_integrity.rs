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
    #[error("release tree contains an unlisted artifact: {0}")]
    UnlistedArtifact(String),
    #[error("unsafe release artifact path: {0}")]
    UnsafePath(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub path: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
fn collect_release_tree_files(
    root: &std::path::Path,
    directory: &std::path::Path,
    files: &mut std::collections::BTreeSet<String>,
) -> Result<(), ReleaseIntegrityError> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|_| ReleaseIntegrityError::MissingArtifact(directory.display().to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ReleaseIntegrityError::MissingArtifact(directory.display().to_string()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| ReleaseIntegrityError::MissingArtifact(path.display().to_string()))?;
        if metadata.file_type().is_symlink() {
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(|value| value.to_str())
                .unwrap_or("<non-utf8-path>")
                .replace('\\', "/");
            return Err(ReleaseIntegrityError::UnsafePath(relative));
        }

        if metadata.is_dir() {
            collect_release_tree_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ReleaseIntegrityError::UnsafePath(path.display().to_string()))?
                .to_str()
                .ok_or_else(|| ReleaseIntegrityError::UnsafePath(path.display().to_string()))?
                .replace('\\', "/");
            if !safe_relative_path(&relative) {
                return Err(ReleaseIntegrityError::UnsafePath(relative));
            }
            files.insert(relative);
        } else {
            return Err(ReleaseIntegrityError::UnsafePath(path.display().to_string()));
        }
    }

    Ok(())
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

    // A signed release is a closed-world tree: extra files and symlinks must
    // not be allowed to appear after signing but before verification.
    let mut actual_files = std::collections::BTreeSet::new();
    collect_release_tree_files(&canonical_root, &canonical_root, &mut actual_files)?;
    let expected_files = signed
        .manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(unlisted) = actual_files
        .iter()
        .find(|path| !expected_files.contains(path.as_str()))
    {
        return Err(ReleaseIntegrityError::UnlistedArtifact(unlisted.clone()));
    }

    for artifact in &signed.manifest.artifacts {
        // Inspect each component, not just the leaf. Checking only the final
        // file would allow an intermediate symlink to redirect a manifest path
        // to another location within the release root.
        let components = std::path::Path::new(&artifact.path)
            .components()
            .collect::<Vec<_>>();
        if components.is_empty() {
            return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
        }

        // Use the same canonical root that was enumerated above, rather than
        // re-traversing the caller's possibly aliased root path.
        let mut path = canonical_root.to_path_buf();
        let mut leaf_metadata = None;
        for (index, component) in components.iter().enumerate() {
            match component {
                std::path::Component::Normal(part) => path.push(part),
                _ => return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone())),
            }

            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|_| ReleaseIntegrityError::MissingArtifact(artifact.path.clone()))?;
            if metadata.file_type().is_symlink() {
                return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
            }

            let is_leaf = index + 1 == components.len();
            if is_leaf {
                if !metadata.is_file() {
                    return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
                }
                leaf_metadata = Some(metadata);
            } else if !metadata.is_dir() {
                return Err(ReleaseIntegrityError::UnsafePath(artifact.path.clone()));
            }
        }
        let metadata = leaf_metadata
            .ok_or_else(|| ReleaseIntegrityError::UnsafePath(artifact.path.clone()))?;
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
    fn release_manifest_wire_types_reject_unknown_fields() {
        let artifact = r#"{
            "path":"artifact.bin",
            "blake3":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size_bytes":1,
            "executable":false,
            "unrepresented":true
        }"#;
        assert!(serde_json::from_str::<ReleaseArtifact>(artifact).is_err());

        let manifest = r#"{
            "schema_version":1,
            "kind":"symthaea-release-manifest-v1",
            "release_id":"strict-schema-test",
            "created_at_ms":1,
            "source_revision":"test-revision",
            "artifacts":[],
            "unrepresented":true
        }"#;
        assert!(serde_json::from_str::<ReleaseManifest>(manifest).is_err());

        let signed = r#"{
            "kind":"symthaea-release-signature-v1",
            "algorithm":"ed25519",
            "signer_public_key_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "signature_hex":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "manifest":{
                "schema_version":1,
                "kind":"symthaea-release-manifest-v1",
                "release_id":"strict-schema-test",
                "created_at_ms":1,
                "source_revision":"test-revision",
                "artifacts":[]
            },
            "unrepresented":true
        }"#;
        assert!(serde_json::from_str::<SignedReleaseManifest>(signed).is_err());
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

    fn test_artifact(path: &str, bytes: &[u8], executable: bool) -> ReleaseArtifact {
        ReleaseArtifact {
            path: path.into(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            size_bytes: bytes.len() as u64,
            executable,
        }
    }

    #[cfg(feature = "native")]
    fn sign_test_tree(
        signing: &SigningKey,
        artifacts: Vec<ReleaseArtifact>,
    ) -> SignedReleaseManifest {
        let manifest = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "nixward-release-integrity-tree-test".into(),
            created_at_ms: 1,
            source_revision: "test-source-revision".into(),
            artifacts,
        };
        let signature = signing.sign(&manifest.signing_bytes().unwrap());
        SignedReleaseManifest {
            kind: RELEASE_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            signer_public_key_hex: hex(signing.verifying_key().as_bytes()),
            signature_hex: hex(&signature.to_bytes()),
            manifest,
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn release_tree_accepts_matching_signed_file_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let payload = b"verified release artifact";
        std::fs::write(temp.path().join("artifact.bin"), payload).unwrap();

        let signing = SigningKey::from_bytes(&[43u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        let verified = verify_release_tree(temp.path(), &signed, &trusted).unwrap();
        assert_eq!(verified.release_id, "nixward-release-integrity-tree-test");
        assert_eq!(verified.artifact_count, 1);
    }

    #[cfg(all(feature = "native", unix))]
    #[test]
    fn release_tree_rejects_executable_mode_mismatch() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let payload = b"mode-bound artifact";
        let path = temp.path().join("artifact.bin");
        std::fs::write(&path, payload).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();

        let signing = SigningKey::from_bytes(&[50u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::ArtifactModeMismatch(path))
                if path == "artifact.bin"
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn release_tree_rejects_same_size_modified_artifact_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let expected = b"good";
        let actual = b"evil";
        assert_eq!(expected.len(), actual.len());
        std::fs::write(temp.path().join("artifact.bin"), actual).unwrap();

        let signing = SigningKey::from_bytes(&[44u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", expected, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::ArtifactDigestMismatch(path))
                if path == "artifact.bin"
        ));
    }

    #[cfg(all(feature = "native", unix))]
    #[test]
    fn release_tree_rejects_symlinked_parent_directories_inside_release_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let payload = b"intermediate directory must not be a symlink";
        let linked_dir = temp.path().join("linked");
        let target_dir = temp.path().join("payload");
        std::fs::create_dir_all(linked_dir.join("nested")).unwrap();
        std::fs::create_dir_all(target_dir.join("nested")).unwrap();
        std::fs::write(linked_dir.join("nested/artifact.bin"), payload).unwrap();
        std::fs::write(target_dir.join("nested/artifact.bin"), payload).unwrap();

        let signing = SigningKey::from_bytes(&[47u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("linked/nested/artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        // Replace a previously ordinary parent directory with an in-root symlink.
        std::fs::remove_dir_all(&linked_dir).unwrap();
        symlink(&target_dir, &linked_dir).unwrap();

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::UnsafePath(path))
                if path == "linked"
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn release_tree_rejects_unlisted_files_added_after_signing() {
        let temp = tempfile::tempdir().unwrap();
        let payload = b"listed release payload";
        std::fs::write(temp.path().join("artifact.bin"), payload).unwrap();
        std::fs::write(temp.path().join("unlisted.bin"), b"late extra file").unwrap();

        let signing = SigningKey::from_bytes(&[48u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::UnlistedArtifact(path))
                if path == "unlisted.bin"
        ));
    }

    #[cfg(all(feature = "native", unix))]
    #[test]
    fn release_tree_rejects_unlisted_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let payload = b"declared release payload";
        std::fs::write(temp.path().join("artifact.bin"), payload).unwrap();

        let signing = SigningKey::from_bytes(&[49u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        // This path is not in the manifest, so its link must still be rejected
        // by the closed-world tree scan.
        symlink(
            temp.path().join("artifact.bin"),
            temp.path().join("unlisted-link"),
        )
        .unwrap();

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::UnsafePath(path))
                if path == "unlisted-link"
        ));
    }

    #[cfg(all(feature = "native", unix))]
    #[test]
    fn release_tree_rejects_symlinked_artifacts_even_when_target_bytes_match() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let payload = b"symlink must not be a release artifact";
        std::fs::write(temp.path().join("actual.bin"), payload).unwrap();
        symlink(
            temp.path().join("actual.bin"),
            temp.path().join("artifact.bin"),
        )
        .unwrap();

        let signing = SigningKey::from_bytes(&[45u8; 32]);
        let signed = sign_test_tree(
            &signing,
            vec![test_artifact("artifact.bin", payload, false)],
        );
        let trusted = hex(signing.verifying_key().as_bytes());

        assert!(matches!(
            verify_release_tree(temp.path(), &signed, &trusted),
            Err(ReleaseIntegrityError::UnsafePath(path))
                if path == "artifact.bin"
        ));
    }

    #[test]
    fn release_manifest_rejects_parent_segments_and_duplicate_paths() {
        let traversal = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "traversal-test".into(),
            created_at_ms: 1,
            source_revision: "test-source-revision".into(),
            artifacts: vec![test_artifact("../outside.bin", b"x", false)],
        };
        assert!(matches!(
            traversal.validate(),
            Err(ReleaseIntegrityError::UnsafePath(path)) if path == "../outside.bin"
        ));

        let duplicate_artifact = test_artifact("same.bin", b"x", false);
        let duplicate = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "duplicate-path-test".into(),
            created_at_ms: 1,
            source_revision: "test-source-revision".into(),
            artifacts: vec![duplicate_artifact.clone(), duplicate_artifact],
        };
        assert_eq!(duplicate.validate(), Err(ReleaseIntegrityError::InvalidManifest));

    }

}
