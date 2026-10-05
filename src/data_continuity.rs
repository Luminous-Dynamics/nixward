// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content-addressed data-continuity evidence for Holon reconstitution.
//!
//! Reproducible NixOS state is not evidence that user/application data exists.
//! V32 therefore models backup identity, restore intent, and post-restore
//! verification separately from system continuity. No secret key material is
//! stored in these structures; manifests bind encrypted content identities and
//! recovery-key identifiers only.

use crate::genesis_covenant::HolonIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DATA_CONTINUITY_SCHEMA_VERSION: u32 = 2;
pub const DATA_CONTINUITY_LEGACY_SCHEMA_VERSION: u32 = 1;
pub const BACKUP_MANIFEST_KIND_V1: &str = "symthaea-data-backup-manifest-v1";
pub const BACKUP_MANIFEST_KIND: &str = "symthaea-data-backup-manifest-v2";
pub const RESTORE_PLAN_KIND: &str = "symthaea-data-restore-plan-v2";
pub const DATA_RECEIPT_KIND: &str = "symthaea-data-continuity-receipt-v2";
pub const RESTORE_VERIFICATION_KIND: &str = "symthaea-data-restore-verification-v2";
const BACKUP_DOMAIN: &[u8] = b"symthaea-data-backup-manifest-v1\0";
const RESTORE_DOMAIN: &[u8] = b"symthaea-data-restore-plan-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"symthaea-data-continuity-receipt-v1\0";

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hash_serialized<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("data-continuity serialization is infallible");
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    hasher.finalize().to_hex().to_string()
}

fn safe_logical_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && !path.contains('\0')
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DataContinuityError {
    #[error("invalid data-continuity digest")]
    InvalidDigest,
    #[error("invalid or unsafe logical backup path")]
    InvalidPath,
    #[error("duplicate logical backup path")]
    DuplicatePath,
    #[error("backup byte/object totals are inconsistent")]
    InvalidTotals,
    #[error("backup manifest belongs to another Holon")]
    HolonMismatch,
    #[error("restore receipt does not match the planned backup")]
    RestoreMismatch,
    #[error("data restore is incomplete")]
    IncompleteRestore,
    #[error("restore verification report does not prove the exact manifest contents")]
    VerificationMismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackupEntryType {
    #[default]
    RegularFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupObject {
    /// Relative logical path within the owner/application data namespace.
    pub logical_path: String,
    /// Plaintext content identity. Reveals equality, not content; deployments
    /// that consider equality sensitive may use a keyed manifest layer later.
    pub content_blake3: String,
    /// Identity of the encrypted object actually stored/transferred.
    pub ciphertext_blake3: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub entry_type: BackupEntryType,
    /// Permission bits only (0o0000..0o7777), not file-type bits.
    #[serde(default)]
    pub unix_mode: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupDirectory {
    pub logical_path: String,
    pub unix_mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataProtection {
    pub scheme: String,
    pub key_id: String,
    pub recipient_set_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub snapshot_id: String,
    pub source_toplevel: String,
    /// Verified system-continuity lineage at the moment this backup was captured.
    /// Legacy v1 manifests may leave this empty.
    #[serde(default)]
    pub continuity_anchor_blake3: String,
    /// Evidence truth for consistency semantics. V34 initially emits
    /// `live-file-stream-v1`; future snapshot/quiesce backends can strengthen it.
    #[serde(default)]
    pub capture_semantics: String,
    pub objects: Vec<BackupObject>,
    #[serde(default)]
    pub directories: Vec<BackupDirectory>,
    pub object_count: u64,
    pub total_bytes: u64,
    pub protection: DataProtection,
    pub created_at_ms: u64,
}

impl BackupManifest {
    pub fn validate(&self) -> Result<(), DataContinuityError> {
        if !matches!(
            self.schema_version,
            DATA_CONTINUITY_LEGACY_SCHEMA_VERSION | DATA_CONTINUITY_SCHEMA_VERSION
        ) || (self.schema_version == DATA_CONTINUITY_LEGACY_SCHEMA_VERSION
            && self.kind != BACKUP_MANIFEST_KIND_V1)
            || (self.schema_version == DATA_CONTINUITY_SCHEMA_VERSION
                && self.kind != BACKUP_MANIFEST_KIND)
            || self.snapshot_id.trim().is_empty()
            || !self.source_toplevel.starts_with("/nix/store/")
            || self.protection.scheme.trim().is_empty()
            || self.protection.key_id.trim().is_empty()
            || !valid_digest(&self.protection.recipient_set_blake3)
        {
            return Err(DataContinuityError::InvalidDigest);
        }
        if self.schema_version >= 2
            && (!valid_digest(&self.continuity_anchor_blake3)
                || !matches!(
                    self.capture_semantics.as_str(),
                    "live-file-stream-v1" | "filesystem-snapshot-v1" | "application-quiesced-v1"
                ))
        {
            return Err(DataContinuityError::InvalidDigest);
        }
        let mut bytes = 0u64;
        let mut logical_paths = std::collections::BTreeSet::new();
        for object in &self.objects {
            if !safe_logical_path(&object.logical_path) {
                return Err(DataContinuityError::InvalidPath);
            }
            if !logical_paths.insert(object.logical_path.as_str()) {
                return Err(DataContinuityError::DuplicatePath);
            }
            if !valid_digest(&object.content_blake3) || !valid_digest(&object.ciphertext_blake3) {
                return Err(DataContinuityError::InvalidDigest);
            }
            if self.schema_version >= 2 && object.unix_mode > 0o7777 {
                return Err(DataContinuityError::InvalidPath);
            }
            bytes = bytes
                .checked_add(object.size_bytes)
                .ok_or(DataContinuityError::InvalidTotals)?;
        }
        if self.schema_version >= 2 {
            for directory in &self.directories {
                if !safe_logical_path(&directory.logical_path) || directory.unix_mode > 0o7777 {
                    return Err(DataContinuityError::InvalidPath);
                }
                if !logical_paths.insert(directory.logical_path.as_str()) {
                    return Err(DataContinuityError::DuplicatePath);
                }
            }
        }
        if self.object_count != self.objects.len() as u64 || self.total_bytes != bytes {
            return Err(DataContinuityError::InvalidTotals);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, DataContinuityError> {
        self.validate()?;
        Ok(hash_serialized(BACKUP_DOMAIN, self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataRestorePlan {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub backup_manifest_blake3: String,
    pub snapshot_id: String,
    pub protection_key_id: String,
    pub expected_object_count: u64,
    pub expected_total_bytes: u64,
    pub target_namespace: String,
    pub nonce_blake3: String,
}

impl DataRestorePlan {
    pub fn new(
        holon: &HolonIdentity,
        manifest: &BackupManifest,
        target_namespace: impl Into<String>,
        nonce_entropy: [u8; 32],
    ) -> Result<Self, DataContinuityError> {
        manifest.validate()?;
        if &manifest.holon != holon {
            return Err(DataContinuityError::HolonMismatch);
        }
        let target_namespace = target_namespace.into();
        if target_namespace != "owner-data-v1" && target_namespace != "application-data-v1" {
            return Err(DataContinuityError::InvalidPath);
        }
        let backup_manifest_blake3 = manifest.digest()?;
        let mut nonce = blake3::Hasher::new();
        nonce.update(RESTORE_DOMAIN);
        nonce.update(&nonce_entropy);
        nonce.update(holon.id.as_bytes());
        nonce.update(backup_manifest_blake3.as_bytes());
        Ok(Self {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: RESTORE_PLAN_KIND.into(),
            holon: holon.clone(),
            backup_manifest_blake3,
            snapshot_id: manifest.snapshot_id.clone(),
            protection_key_id: manifest.protection.key_id.clone(),
            expected_object_count: manifest.object_count,
            expected_total_bytes: manifest.total_bytes,
            target_namespace,
            nonce_blake3: nonce.finalize().to_hex().to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), DataContinuityError> {
        if self.schema_version != DATA_CONTINUITY_SCHEMA_VERSION
            || self.kind != RESTORE_PLAN_KIND
            || !valid_digest(&self.backup_manifest_blake3)
            || self.snapshot_id.trim().is_empty()
            || self.protection_key_id.trim().is_empty()
            || !matches!(
                self.target_namespace.as_str(),
                "owner-data-v1" | "application-data-v1"
            )
            || !valid_digest(&self.nonce_blake3)
        {
            return Err(DataContinuityError::RestoreMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        hash_serialized(RESTORE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RestoredObjectEvidence {
    pub logical_path: String,
    pub content_blake3: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub entry_type: BackupEntryType,
    #[serde(default)]
    pub unix_mode: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RestoredDirectoryEvidence {
    pub logical_path: String,
    pub unix_mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreVerificationReport {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub restore_plan_blake3: String,
    pub backup_manifest_blake3: String,
    pub objects: Vec<RestoredObjectEvidence>,
    #[serde(default)]
    pub directories: Vec<RestoredDirectoryEvidence>,
    pub diagnostics: Vec<String>,
    pub verified_at_ms: u64,
}

impl RestoreVerificationReport {
    pub fn digest(&self) -> String {
        hash_serialized(b"symthaea-data-restore-verification-v2\0", self)
    }

    pub fn validate_exact(
        &self,
        plan: &DataRestorePlan,
        manifest: &BackupManifest,
    ) -> Result<(), DataContinuityError> {
        manifest.validate()?;
        if manifest.schema_version != DATA_CONTINUITY_SCHEMA_VERSION {
            return Err(DataContinuityError::VerificationMismatch);
        }
        if self.schema_version != DATA_CONTINUITY_SCHEMA_VERSION
            || self.kind != RESTORE_VERIFICATION_KIND
            || self.holon != plan.holon
            || self.holon != manifest.holon
            || self.restore_plan_blake3 != plan.digest()
            || self.backup_manifest_blake3 != manifest.digest()?
            || self.backup_manifest_blake3 != plan.backup_manifest_blake3
            || !self.diagnostics.is_empty()
        {
            return Err(DataContinuityError::VerificationMismatch);
        }
        let expected = manifest
            .objects
            .iter()
            .map(|o| RestoredObjectEvidence {
                logical_path: o.logical_path.clone(),
                content_blake3: o.content_blake3.clone(),
                size_bytes: o.size_bytes,
                entry_type: o.entry_type,
                unix_mode: o.unix_mode,
                uid: o.uid,
                gid: o.gid,
            })
            .collect::<std::collections::BTreeSet<_>>();
        let observed = self
            .objects
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if observed.len() != self.objects.len() || observed != expected {
            return Err(DataContinuityError::VerificationMismatch);
        }
        let expected_dirs = manifest
            .directories
            .iter()
            .map(|d| RestoredDirectoryEvidence {
                logical_path: d.logical_path.clone(),
                unix_mode: d.unix_mode,
                uid: d.uid,
                gid: d.gid,
            })
            .collect::<std::collections::BTreeSet<_>>();
        let observed_dirs = self
            .directories
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if observed_dirs.len() != self.directories.len() || observed_dirs != expected_dirs {
            return Err(DataContinuityError::VerificationMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DataContinuityStatus {
    Verified,
    Partial,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataContinuityReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub holon: HolonIdentity,
    pub restore_plan_blake3: String,
    pub backup_manifest_blake3: String,
    pub restored_object_count: u64,
    pub restored_total_bytes: u64,
    /// Digest of the deterministic post-restore verification report.
    pub verification_blake3: String,
    pub status: DataContinuityStatus,
    pub diagnostics: Vec<String>,
    pub verified_at_ms: u64,
}

impl DataContinuityReceipt {
    pub fn verify_report(
        plan: &DataRestorePlan,
        manifest: &BackupManifest,
        report: &RestoreVerificationReport,
    ) -> Result<Self, DataContinuityError> {
        report.validate_exact(plan, manifest)?;
        let restored_object_count = report.objects.len() as u64;
        let restored_total_bytes = report.objects.iter().try_fold(0u64, |acc, o| {
            acc.checked_add(o.size_bytes)
                .ok_or(DataContinuityError::InvalidTotals)
        })?;
        if restored_object_count != plan.expected_object_count
            || restored_total_bytes != plan.expected_total_bytes
        {
            return Err(DataContinuityError::IncompleteRestore);
        }
        Ok(Self {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: DATA_RECEIPT_KIND.into(),
            holon: plan.holon.clone(),
            restore_plan_blake3: plan.digest(),
            backup_manifest_blake3: manifest.digest()?,
            restored_object_count,
            restored_total_bytes,
            verification_blake3: report.digest(),
            status: DataContinuityStatus::Verified,
            diagnostics: Vec::new(),
            verified_at_ms: report.verified_at_ms,
        })
    }

    #[deprecated(
        note = "V34: use verify_report so content identity, not counts alone, proves data continuity"
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        plan: &DataRestorePlan,
        backup_manifest_blake3: impl Into<String>,
        restored_object_count: u64,
        restored_total_bytes: u64,
        verification_blake3: impl Into<String>,
        diagnostics: Vec<String>,
        verified_at_ms: u64,
    ) -> Result<Self, DataContinuityError> {
        let backup_manifest_blake3 = backup_manifest_blake3.into();
        let verification_blake3 = verification_blake3.into();
        if backup_manifest_blake3 != plan.backup_manifest_blake3
            || !valid_digest(&verification_blake3)
        {
            return Err(DataContinuityError::RestoreMismatch);
        }
        let complete = restored_object_count == plan.expected_object_count
            && restored_total_bytes == plan.expected_total_bytes
            && diagnostics.is_empty();
        let status = if complete {
            DataContinuityStatus::Verified
        } else if restored_object_count <= plan.expected_object_count
            && restored_total_bytes <= plan.expected_total_bytes
        {
            DataContinuityStatus::Partial
        } else {
            DataContinuityStatus::Rejected
        };
        Ok(Self {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: DATA_RECEIPT_KIND.into(),
            holon: plan.holon.clone(),
            restore_plan_blake3: plan.digest(),
            backup_manifest_blake3,
            restored_object_count,
            restored_total_bytes,
            verification_blake3,
            status,
            diagnostics,
            verified_at_ms,
        })
    }

    pub fn is_verified(&self) -> bool {
        self.status == DataContinuityStatus::Verified
    }

    pub fn digest(&self) -> String {
        hash_serialized(RECEIPT_DOMAIN, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> BackupManifest {
        BackupManifest {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: BACKUP_MANIFEST_KIND.into(),
            holon: HolonIdentity::from_entropy([1; 32]),
            snapshot_id: "snapshot-1".into(),
            source_toplevel: "/nix/store/aaaaaaaa-system".into(),
            continuity_anchor_blake3: "aa".repeat(32),
            capture_semantics: "live-file-stream-v1".into(),
            objects: vec![BackupObject {
                logical_path: "home/alice/document.txt".into(),
                content_blake3: "11".repeat(32),
                ciphertext_blake3: "22".repeat(32),
                size_bytes: 42,
                entry_type: BackupEntryType::RegularFile,
                unix_mode: 0o600,
                uid: 1000,
                gid: 100,
            }],
            directories: vec![BackupDirectory {
                logical_path: "home/alice".into(),
                unix_mode: 0o700,
                uid: 1000,
                gid: 100,
            }],
            object_count: 1,
            total_bytes: 42,
            protection: DataProtection {
                scheme: "age-x25519-v1".into(),
                key_id: "recovery-key-1".into(),
                recipient_set_blake3: "33".repeat(32),
            },
            created_at_ms: 1,
        }
    }

    #[test]
    fn restore_plan_binds_exact_manifest_and_holon() {
        let m = manifest();
        let plan = DataRestorePlan::new(&m.holon, &m, "owner-data-v1", [4; 32]).unwrap();
        assert_eq!(plan.backup_manifest_blake3, m.digest().unwrap());
        assert_eq!(plan.expected_object_count, 1);
    }

    #[test]
    fn traversal_path_is_rejected() {
        let mut m = manifest();
        m.objects[0].logical_path = "home/alice/../../etc/shadow".into();
        assert_eq!(m.validate().unwrap_err(), DataContinuityError::InvalidPath);
    }

    #[test]
    fn verified_receipt_requires_exact_counts() {
        let m = manifest();
        let plan = DataRestorePlan::new(&m.holon, &m, "owner-data-v1", [5; 32]).unwrap();
        let receipt = DataContinuityReceipt::verify(
            &plan,
            m.digest().unwrap(),
            1,
            42,
            "44".repeat(32),
            Vec::new(),
            2,
        )
        .unwrap();
        assert!(receipt.is_verified());
    }

    #[test]
    fn exact_restore_report_rejects_wrong_content_with_same_size() {
        let m = manifest();
        let plan = DataRestorePlan::new(&m.holon, &m, "owner-data-v1", [7; 32]).unwrap();
        let report = RestoreVerificationReport {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: RESTORE_VERIFICATION_KIND.into(),
            holon: m.holon.clone(),
            restore_plan_blake3: plan.digest(),
            backup_manifest_blake3: m.digest().unwrap(),
            objects: vec![RestoredObjectEvidence {
                logical_path: m.objects[0].logical_path.clone(),
                content_blake3: "99".repeat(32),
                size_bytes: m.objects[0].size_bytes,
                entry_type: m.objects[0].entry_type,
                unix_mode: m.objects[0].unix_mode,
                uid: m.objects[0].uid,
                gid: m.objects[0].gid,
            }],
            directories: vec![RestoredDirectoryEvidence {
                logical_path: m.directories[0].logical_path.clone(),
                unix_mode: m.directories[0].unix_mode,
                uid: m.directories[0].uid,
                gid: m.directories[0].gid,
            }],
            diagnostics: Vec::new(),
            verified_at_ms: 3,
        };
        assert_eq!(
            DataContinuityReceipt::verify_report(&plan, &m, &report).unwrap_err(),
            DataContinuityError::VerificationMismatch
        );
    }

    #[test]
    fn exact_restore_report_proves_content_identity() {
        let m = manifest();
        let plan = DataRestorePlan::new(&m.holon, &m, "owner-data-v1", [8; 32]).unwrap();
        let report = RestoreVerificationReport {
            schema_version: DATA_CONTINUITY_SCHEMA_VERSION,
            kind: RESTORE_VERIFICATION_KIND.into(),
            holon: m.holon.clone(),
            restore_plan_blake3: plan.digest(),
            backup_manifest_blake3: m.digest().unwrap(),
            objects: vec![RestoredObjectEvidence {
                logical_path: m.objects[0].logical_path.clone(),
                content_blake3: m.objects[0].content_blake3.clone(),
                size_bytes: m.objects[0].size_bytes,
                entry_type: m.objects[0].entry_type,
                unix_mode: m.objects[0].unix_mode,
                uid: m.objects[0].uid,
                gid: m.objects[0].gid,
            }],
            directories: vec![RestoredDirectoryEvidence {
                logical_path: m.directories[0].logical_path.clone(),
                unix_mode: m.directories[0].unix_mode,
                uid: m.directories[0].uid,
                gid: m.directories[0].gid,
            }],
            diagnostics: Vec::new(),
            verified_at_ms: 3,
        };
        assert!(
            DataContinuityReceipt::verify_report(&plan, &m, &report)
                .unwrap()
                .is_verified()
        );
    }
}
