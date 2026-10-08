// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Native transaction semantics for configuration source commits and NixOS activation.
//!
//! This module deliberately models two different transactional domains:
//! durable configuration source state and the running NixOS generation.
//! It contains no privileged mutation itself. It only provides typed state,
//! immutable source snapshots, and fail-closed classification helpers.

use super::executor::SystemActivation;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SOURCE_DOMAIN: &[u8] = b"nixward-frozen-config-source-v1\0";
const ENTRY_DOMAIN: &[u8] = b"nixward-frozen-config-entry-v1\0";
const TX_DOMAIN: &[u8] = b"nixward-config-transaction-v1\0";

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigTransactionPhase {
    Prepared,
    InputFrozen,
    CandidateBuilt,
    SourceCommitted,
    ActivationStarted,
    Activated,
    FailedBeforeActivation,
    IndeterminateActivation,
    RecoveryObservation,
    RecoveryRequired,
    Recovered,
}

impl ConfigTransactionPhase {
    /// Durable-source rollback is only valid before activation starts.
    pub fn permits_source_rollback(self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::InputFrozen
                | Self::CandidateBuilt
                | Self::SourceCommitted
                | Self::FailedBeforeActivation
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RecoveryObservation {
    PredecessorProvenActive {
        runtime_closure: String,
        profile_closure: String,
    },
    CandidateProvenActive {
        runtime_closure: String,
        profile_closure: String,
    },
    MixedOrUnknown {
        runtime_closure: Option<String>,
        profile_closure: Option<String>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ActivationDisposition {
    Activated {
        process_exit_status: Option<i32>,
        observation: RecoveryObservation,
    },
    FailedBeforeActivation {
        process_exit_status: Option<i32>,
        reason: String,
    },
    IndeterminateActivation {
        process_exit_status: Option<i32>,
        observation: RecoveryObservation,
    },
    RecoveryRequired {
        process_exit_status: Option<i32>,
        observation: RecoveryObservation,
    },
}

/// Runtime/profile evidence outranks child exit status.
pub fn classify_activation_post_state(
    activation_started: bool,
    process_exit_status: Option<i32>,
    observed_runtime: Option<&str>,
    observed_profile: Option<&str>,
    candidate_runtime: &str,
    candidate_profile: &str,
    predecessor_runtime: &str,
    predecessor_profile: &str,
    action: SystemActivation,
) -> ActivationDisposition {
    let observation = match (observed_runtime, observed_profile) {
        (Some(runtime), Some(profile)) => {
            let candidate = runtime == candidate_runtime && profile == candidate_profile;
            let predecessor = match action {
                SystemActivation::Boot => {
                    runtime == predecessor_runtime
                        && (profile == predecessor_profile || profile == candidate_profile)
                }
                SystemActivation::Switch | SystemActivation::Test => {
                    runtime == predecessor_runtime
                        && (profile == predecessor_profile || profile == candidate_profile)
                }
            };

            if candidate {
                RecoveryObservation::CandidateProvenActive {
                    runtime_closure: runtime.to_string(),
                    profile_closure: profile.to_string(),
                }
            } else if predecessor {
                RecoveryObservation::PredecessorProvenActive {
                    runtime_closure: runtime.to_string(),
                    profile_closure: profile.to_string(),
                }
            } else {
                RecoveryObservation::MixedOrUnknown {
                    runtime_closure: Some(runtime.to_string()),
                    profile_closure: Some(profile.to_string()),
                    reason: "observed runtime/profile pair is outside the transaction state set".into(),
                }
            }
        }
        (runtime, profile) => RecoveryObservation::MixedOrUnknown {
            runtime_closure: runtime.map(str::to_string),
            profile_closure: profile.map(str::to_string),
            reason: "authoritative runtime or system-profile observation was unavailable".into(),
        },
    };

    match (&observation, activation_started) {
        (RecoveryObservation::CandidateProvenActive { .. }, _) => {
            ActivationDisposition::Activated {
                process_exit_status,
                observation,
            }
        }
        (RecoveryObservation::PredecessorProvenActive { .. }, false) => {
            ActivationDisposition::FailedBeforeActivation {
                process_exit_status,
                reason: "activation did not begin and predecessor state remains proven active".into(),
            }
        }
        (RecoveryObservation::PredecessorProvenActive { .. }, true) => {
            ActivationDisposition::IndeterminateActivation {
                process_exit_status,
                observation,
            }
        }
        (RecoveryObservation::MixedOrUnknown { .. }, false) => {
            ActivationDisposition::FailedBeforeActivation {
                process_exit_status,
                reason: "activation was not started".into(),
            }
        }
        (RecoveryObservation::MixedOrUnknown { .. }, true) => {
            ActivationDisposition::RecoveryRequired {
                process_exit_status,
                observation,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceManifestEntry {
    pub relative_path: String,
    pub kind: SourceEntryKind,
    pub mode: u32,
    pub size: u64,
    pub digest: String,
}

/// Digest-addressed snapshot of the complete intended Nix source tree.
///
/// This is a source snapshot, not yet a Nix store realization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenConfigSource {
    pub root_digest: String,
    pub entrypoint: String,
    pub manifest: Vec<SourceManifestEntry>,
}

impl FrozenConfigSource {
    pub fn capture(root: impl AsRef<Path>, entrypoint: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().canonicalize().map_err(|error| {
            format!("failed to canonicalize config source root: {error}")
        })?;
        if !root.is_dir() {
            return Err("config source root must be a directory".into());
        }

        let entrypoint = {
            let path = entrypoint.as_ref();
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        };
        let entrypoint = entrypoint
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize config entrypoint: {error}"))?;
        let relative_entrypoint = entrypoint
            .strip_prefix(&root)
            .map_err(|_| "config entrypoint escapes source root".to_string())?;

        let mut manifest = Vec::new();
        Self::walk(&root, &root, &mut manifest)?;
        manifest.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        let mut hasher = blake3::Hasher::new();
        hasher.update(SOURCE_DOMAIN);
        for entry in &manifest {
            hasher.update(entry.relative_path.as_bytes());
            hasher.update(&[0]);
            hasher.update(match entry.kind {
                SourceEntryKind::File => b"file\0".as_slice(),
                SourceEntryKind::Directory => b"dir\0".as_slice(),
            });
            hasher.update(&entry.mode.to_le_bytes());
            hasher.update(&entry.size.to_le_bytes());
            hasher.update(&decode_digest(&entry.digest)?);
        }

        Ok(Self {
            root_digest: digest_hex(hasher.finalize().as_bytes()),
            entrypoint: relative_entrypoint.to_string_lossy().replace('\\', "/"),
            manifest,
        })
    }

    fn walk(root: &Path, current: &Path, manifest: &mut Vec<SourceManifestEntry>) -> Result<(), String> {
        let entries = std::fs::read_dir(current)
            .map_err(|error| format!("failed to enumerate {}: {error}", current.display()))?;

        let mut paths = Vec::new();
        for entry in entries {
            paths.push(
                entry
                    .map_err(|error| format!("failed to read source entry: {error}"))?
                    .path(),
            );
        }
        paths.sort();

        for path in paths {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("source path {} escaped root", path.display()))?;
            let relative_path = relative.to_string_lossy().replace('\\', "/");
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;

            if metadata.file_type().is_symlink() {
                return Err(format!("symbolic link {} is not admissible in a frozen source tree", path.display()));
            }

            let mode = file_mode(&metadata);
            if metadata.is_dir() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(ENTRY_DOMAIN);
                hasher.update(b"dir\0");
                hasher.update(relative_path.as_bytes());
                hasher.update(&mode.to_le_bytes());
                let digest = *hasher.finalize().as_bytes();
                manifest.push(SourceManifestEntry {
                    relative_path,
                    kind: SourceEntryKind::Directory,
                    mode,
                    size: 0,
                    digest: digest_hex(&digest),
                });
                Self::walk(root, &path, manifest)?;
            } else if metadata.is_file() {
                let bytes = std::fs::read(&path)
                    .map_err(|error| format!("failed to read source file {}: {error}", path.display()))?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(ENTRY_DOMAIN);
                hasher.update(relative_path.as_bytes());
                hasher.update(&[0]);
                hasher.update(&mode.to_le_bytes());
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(&bytes);
                manifest.push(SourceManifestEntry {
                    relative_path,
                    kind: SourceEntryKind::File,
                    mode,
                    size: bytes.len() as u64,
                    digest: digest_hex(&hasher.finalize().as_bytes()),
                });
            } else {
                return Err(format!("unsupported filesystem object {} in source tree", path.display()));
            }
        }
        Ok(())
    }

    pub fn verify_unchanged(&self, root: impl AsRef<Path>) -> Result<(), String> {
        let observed = Self::capture(root, &self.entrypoint)?;
        if observed.root_digest != self.root_digest
            || observed.entrypoint != self.entrypoint
            || observed.manifest != self.manifest
        {
            return Err("frozen Nix source tree changed after snapshot".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigTransaction {
    pub schema: String,
    pub version: u16,
    pub transaction_id: String,
    pub source_digest: String,
    pub candidate_store_path: Option<String>,
    pub phase: ConfigTransactionPhase,
    pub process_exit_status: Option<i32>,
    pub observed_runtime_closure: Option<String>,
    pub observed_profile_closure: Option<String>,
}

impl ConfigTransaction {
    pub const SCHEMA: &'static str = "luminous-nixward-config-transaction-v1";
    pub const VERSION: u16 = 1;

    pub fn new(plan_digest: [u8; 32], nonce: [u8; 32], source_digest: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TX_DOMAIN);
        hasher.update(&plan_digest);
        hasher.update(&nonce);
        hasher.update(&source_digest);
        Self {
            schema: Self::SCHEMA.into(),
            version: Self::VERSION,
            transaction_id: digest_hex(hasher.finalize().as_bytes()),
            source_digest: digest_hex(&source_digest),
            candidate_store_path: None,
            phase: ConfigTransactionPhase::Prepared,
            process_exit_status: None,
            observed_runtime_closure: None,
            observed_profile_closure: None,
        }
    }
}

fn decode_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        return Err("digest must be 64 lowercase hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| "digest is not UTF-8".to_string())?,
            16,
        )
        .map_err(|_| "digest contains invalid hexadecimal".to_string())?;
    }
    Ok(out)
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-candidate";
    const CANDIDATE_PROFILE: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-profile";
    const PREDECESSOR: &str = "/nix/store/cccccccccccccccccccccccccccccccc-prior";
    const PREDECESSOR_PROFILE: &str = "/nix/store/dddddddddddddddddddddddddddddddd-profile";

    #[test]
    fn source_rollback_is_forbidden_after_activation() {
        assert!(ConfigTransactionPhase::SourceCommitted.permits_source_rollback());
        assert!(!ConfigTransactionPhase::ActivationStarted.permits_source_rollback());
        assert!(!ConfigTransactionPhase::IndeterminateActivation.permits_source_rollback());
        assert!(!ConfigTransactionPhase::RecoveryRequired.permits_source_rollback());
    }

    #[test]
    fn candidate_observation_dominates_nonzero_exit_status() {
        let result = classify_activation_post_state(
            true,
            Some(1),
            Some(CANDIDATE),
            Some(CANDIDATE_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Switch,
        );
        assert!(matches!(result, ActivationDisposition::Activated { .. }));
    }

    #[test]
    fn predecessor_after_started_activation_is_indeterminate() {
        let result = classify_activation_post_state(
            true,
            Some(1),
            Some(PREDECESSOR),
            Some(PREDECESSOR_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Switch,
        );
        assert!(matches!(
            result,
            ActivationDisposition::IndeterminateActivation {
                observation: RecoveryObservation::PredecessorProvenActive { .. },
                ..
            }
        ));
    }

    #[test]
    fn mixed_state_requires_recovery() {
        let result = classify_activation_post_state(
            true,
            None,
            Some("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-unknown"),
            Some(PREDECESSOR_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Switch,
        );
        assert!(matches!(result, ActivationDisposition::RecoveryRequired { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn frozen_source_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("configuration.nix"),
            dir.path().join("linked.nix"),
        )
        .unwrap();
        assert!(FrozenConfigSource::capture(dir.path(), "configuration.nix").is_err());
    }

    #[test]
    fn frozen_source_detects_drift() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        std::fs::write(
            dir.path().join("configuration.nix"),
            "{ config = { drift = true; }; }\n",
        )
        .unwrap();
        assert!(source.verify_unchanged(dir.path()).is_err());
    }

    #[test]
    fn transaction_id_binds_source_plan_and_nonce() {
        let first = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        let second = ConfigTransaction::new([1; 32], [2; 32], [4; 32]);
        assert_ne!(first.transaction_id, second.transaction_id);
    }
}
