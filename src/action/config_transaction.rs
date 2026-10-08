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
use std::io::Write;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SOURCE_DOMAIN: &[u8] = b"nixward-frozen-config-source-v1\0";
const ENTRY_DOMAIN: &[u8] = b"nixward-frozen-config-entry-v1\0";
const TX_DOMAIN: &[u8] = b"nixward-config-transaction-v2\0";

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
    ProfileTransitionStarted,
    ProfileCommitted,
    IndeterminateProfileTransition,
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
    /// For `boot`, the selected system profile is proven while the current
    /// running closure is expected to remain the predecessor until reboot.
    BootCandidateProven {
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
pub enum ProfileTransitionDisposition {
    /// The exact requested profile is proven active after the profile command.
    /// This remains true even when the child returned a nonzero status.
    Committed {
        process_exit_status: Option<i32>,
        observed_profile: String,
    },
    /// The profile outcome cannot be proven safe from post-state evidence.
    Indeterminate {
        process_exit_status: Option<i32>,
        observed_profile: Option<String>,
        reason: String,
    },
}

pub fn classify_profile_transition_post_state(
    process_exit_status: Option<i32>,
    observed_profile: Option<&str>,
    candidate_profile: &str,
) -> ProfileTransitionDisposition {
    match observed_profile {
        Some(observed) if observed == candidate_profile => {
            ProfileTransitionDisposition::Committed {
                process_exit_status,
                observed_profile: observed.to_string(),
            }
        }
        Some(observed) => ProfileTransitionDisposition::Indeterminate {
            process_exit_status,
            observed_profile: Some(observed.to_string()),
            reason: "system profile did not resolve to the requested immutable candidate".into(),
        },
        None => ProfileTransitionDisposition::Indeterminate {
            process_exit_status,
            observed_profile: None,
            reason: "system profile post-state could not be observed".into(),
        },
    }
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
        (Some(runtime), Some(profile)) => match action {
            SystemActivation::Switch | SystemActivation::Test => {
                if runtime == candidate_runtime && profile == candidate_profile {
                    RecoveryObservation::CandidateProvenActive { runtime_closure: runtime.to_string(), profile_closure: profile.to_string() }
                } else if runtime == predecessor_runtime && (profile == predecessor_profile || profile == candidate_profile) {
                    RecoveryObservation::PredecessorProvenActive { runtime_closure: runtime.to_string(), profile_closure: profile.to_string() }
                } else {
                    RecoveryObservation::MixedOrUnknown {
                        runtime_closure: Some(runtime.to_string()),
                        profile_closure: Some(profile.to_string()),
                        reason: "observed runtime/profile pair is outside the transaction state set".into(),
                    }
                }
            }
            SystemActivation::Boot => {
                if runtime == predecessor_runtime && profile == candidate_profile {
                    RecoveryObservation::BootCandidateProven { runtime_closure: runtime.to_string(), profile_closure: profile.to_string() }
                } else if runtime == predecessor_runtime && profile == predecessor_profile {
                    RecoveryObservation::PredecessorProvenActive { runtime_closure: runtime.to_string(), profile_closure: profile.to_string() }
                } else {
                    RecoveryObservation::MixedOrUnknown {
                        runtime_closure: Some(runtime.to_string()),
                        profile_closure: Some(profile.to_string()),
                        reason: "boot activation observed an unexpected runtime/profile pair".into(),
                    }
                }
            }
        },
        (runtime, profile) => RecoveryObservation::MixedOrUnknown {
            runtime_closure: runtime.map(str::to_string),
            profile_closure: profile.map(str::to_string),
            reason: "authoritative runtime or system-profile observation was unavailable".into(),
        },
    };

    match (&observation, activation_started) {
        (
            RecoveryObservation::CandidateProvenActive { .. }
            | RecoveryObservation::BootCandidateProven { .. },
            true,
        ) => ActivationDisposition::Activated {
            process_exit_status,
            observation,
        },
        (
            RecoveryObservation::CandidateProvenActive { .. }
            | RecoveryObservation::BootCandidateProven { .. },
            false,
        ) => ActivationDisposition::RecoveryRequired {
            process_exit_status,
            observation,
        },
        (RecoveryObservation::PredecessorProvenActive { .. }, false) =>
            ActivationDisposition::FailedBeforeActivation { process_exit_status, reason: "activation did not begin and predecessor state remains proven active".into() },
        (RecoveryObservation::PredecessorProvenActive { .. }, true) =>
            ActivationDisposition::IndeterminateActivation { process_exit_status, observation },
        (RecoveryObservation::MixedOrUnknown { .. }, false) =>
            ActivationDisposition::FailedBeforeActivation { process_exit_status, reason: "activation was not started".into() },
        (RecoveryObservation::MixedOrUnknown { .. }, true) =>
            ActivationDisposition::RecoveryRequired { process_exit_status, observation },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
        #[cfg(unix)]
        {
            let (mut root_dir, root_stat) = Self::open_source_root(&root)?;
            Self::walk_descriptor_bound(&mut root_dir, Path::new(""), &mut manifest)?;
            let after_root = Self::fstat_directory(&root_dir, &root)?;
            if !Self::directory_stat_stable(&root_stat, &after_root) {
                return Err("config source root changed while being snapshotted".into());
            }
        }
        #[cfg(not(unix))]
        {
            Self::walk_portable(&root, &root, &mut manifest)?;
        }
        manifest.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        let relative_entrypoint_string = relative_entrypoint.to_string_lossy().replace('\\', "/");
        if !manifest.iter().any(|entry| {
            entry.relative_path == relative_entrypoint_string
                && matches!(entry.kind, SourceEntryKind::File)
        }) {
            return Err("config entrypoint is not a regular file in the frozen source tree".into());
        }

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

    #[cfg(not(unix))]
    fn walk_portable(
        root: &Path,
        current: &Path,
        manifest: &mut Vec<SourceManifestEntry>,
    ) -> Result<(), String> {
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
                Self::walk_portable(root, &path, manifest)?;
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


    #[cfg(unix)]
    fn source_directory_names(
        dir: &mut nix::dir::Dir,
    ) -> Result<Vec<std::ffi::CString>, String> {
        use std::ffi::CString;

        let mut names = Vec::new();
        for result in dir.iter() {
            let entry = result.map_err(|error| format!("failed to read source directory entry: {error}"))?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = CString::new(bytes)
                .map_err(|_| "source directory entry contains an embedded NUL".to_string())?;
            names.push(name);
        }
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(names)
    }

    #[cfg(unix)]
    fn same_stat(before: &nix::sys::stat::FileStat, after: &nix::sys::stat::FileStat) -> bool {
        before.st_dev == after.st_dev
            && before.st_ino == after.st_ino
            && before.st_mode == after.st_mode
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_mtime_nsec == after.st_mtime_nsec
            && before.st_ctime == after.st_ctime
            && before.st_ctime_nsec == after.st_ctime_nsec
    }

    #[cfg(unix)]
    fn directory_stat_stable(
        before: &nix::sys::stat::FileStat,
        after: &nix::sys::stat::FileStat,
    ) -> bool {
        Self::same_stat(before, after)
    }

    #[cfg(unix)]
    fn fstat_directory(
        dir: &nix::dir::Dir,
        display: &Path,
    ) -> Result<nix::sys::stat::FileStat, String> {
        use std::os::fd::AsRawFd;
        nix::sys::stat::fstat(dir.as_raw_fd())
            .map_err(|error| format!("failed to inspect source directory {}: {error}", display.display()))
    }

    #[cfg(unix)]
    fn open_source_root(
        root: &Path,
    ) -> Result<(nix::dir::Dir, nix::sys::stat::FileStat), String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        let expected = std::fs::symlink_metadata(root)
            .map_err(|error| format!("failed to inspect config source root: {error}"))?;
        if !expected.is_dir() {
            return Err("config source root must be a directory".into());
        }

        let dir = nix::dir::Dir::open(
            root,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|error| format!("failed to securely open config source root: {error}"))?;
        let observed = nix::sys::stat::fstat(dir.as_raw_fd())
            .map_err(|error| format!("failed to inspect opened config source root: {error}"))?;

        let expected_mode = expected.mode();
        if expected.dev() != observed.st_dev
            || expected.ino() != observed.st_ino
            || expected_mode != (observed.st_mode & 0o7777) as u32
        {
            return Err("config source root changed during descriptor acquisition".into());
        }

        Ok((dir, observed))
    }

    #[cfg(unix)]
    fn walk_descriptor_bound(
        dir: &mut nix::dir::Dir,
        relative: &Path,
        manifest: &mut Vec<SourceManifestEntry>,
    ) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        use nix::dir::Dir;
        use nix::errno::Errno;
        use nix::fcntl::{openat, OFlag};
        use nix::sys::stat::{fstat, Mode, SFlag};
        use nix::unistd::{close, read};

        let names = Self::source_directory_names(dir)?;

        for name in &names {
            let filename = OsStr::from_bytes(name.as_bytes());
            let child_relative = relative.join(filename);
            let display_path = Path::new(name.as_c_str().to_string_lossy().as_ref());

            match Dir::openat(
                dir.as_raw_fd(),
                name.as_c_str(),
                OFlag::O_RDONLY
                    | OFlag::O_DIRECTORY
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) {
                Ok(mut child_dir) => {
                    let before = fstat(child_dir.as_raw_fd()).map_err(|error| {
                        format!("failed to inspect source directory {}: {error}", child_relative.display())
                    })?;
                    if !SFlag::from_bits_truncate(before.st_mode).contains(SFlag::S_IFDIR) {
                        return Err(format!("source directory {} is not a directory", child_relative.display()));
                    }

                    let relative_path = child_relative.to_string_lossy().replace('\\', "/");
                    let mode = (before.st_mode & 0o7777) as u32;
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

                    Self::walk_descriptor_bound(&mut child_dir, &child_relative, manifest)?;

                    let after = fstat(child_dir.as_raw_fd()).map_err(|error| {
                        format!("failed to re-inspect source directory {}: {error}", child_relative.display())
                    })?;
                    if !Self::directory_stat_stable(&before, &after) {
                        return Err(format!(
                            "source directory {} changed while being snapshotted",
                            child_relative.display()
                        ));
                    }

                    let reopened = Dir::openat(
                        dir.as_raw_fd(),
                        name.as_c_str(),
                        OFlag::O_RDONLY
                            | OFlag::O_DIRECTORY
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| {
                        format!(
                            "source directory {} disappeared or changed after traversal: {error}",
                            child_relative.display()
                        )
                    })?;
                    let reopened_stat = fstat(reopened.as_raw_fd()).map_err(|error| {
                        format!("failed to inspect reopened source directory {}: {error}", child_relative.display())
                    })?;
                    if !Self::same_stat(&before, &reopened_stat) {
                        return Err(format!(
                            "source directory {} was replaced during snapshot",
                            child_relative.display()
                        ));
                    }
                }
                Err(Errno::ENOTDIR) => {
                    let fd = openat(
                        dir.as_raw_fd(),
                        name.as_c_str(),
                        OFlag::O_RDONLY
                            | OFlag::O_NONBLOCK
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| {
                        format!("failed to securely open source file {}: {error}", child_relative.display())
                    })?;
                    let before = fstat(fd).map_err(|error| {
                        let _ = close(fd);
                        format!("failed to inspect source file {}: {error}", child_relative.display())
                    })?;
                    if !SFlag::from_bits_truncate(before.st_mode).contains(SFlag::S_IFREG) {
                        let _ = close(fd);
                        return Err(format!("unsupported filesystem object {} in source tree", child_relative.display()));
                    }

                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 8192];
                    loop {
                        match read(fd, &mut buffer) {
                            Ok(0) => break,
                            Ok(len) => bytes.extend_from_slice(&buffer[..len]),
                            Err(Errno::EINTR) => continue,
                            Err(error) => {
                                let _ = close(fd);
                                return Err(format!("failed to read source file {}: {error}", child_relative.display()));
                            }
                        }
                    }
                    let after = fstat(fd).map_err(|error| {
                        let _ = close(fd);
                        format!("failed to re-inspect source file {}: {error}", child_relative.display())
                    })?;
                    let close_result = close(fd);
                    if !Self::same_stat(&before, &after) {
                        return Err(format!(
                            "source file {} changed while being snapshotted",
                            child_relative.display()
                        ));
                    }
                    close_result.map_err(|error| {
                        format!("failed to close source file {} after snapshot: {error}", child_relative.display())
                    })?;

                    let relative_path = child_relative.to_string_lossy().replace('\\', "/");
                    let mode = (before.st_mode & 0o7777) as u32;
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

                    let reopened = openat(
                        dir.as_raw_fd(),
                        name.as_c_str(),
                        OFlag::O_RDONLY
                            | OFlag::O_NONBLOCK
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| {
                        format!(
                            "source file {} disappeared or changed after traversal: {error}",
                            child_relative.display()
                        )
                    })?;
                    let reopened_stat = fstat(reopened).map_err(|error| {
                        let _ = close(reopened);
                        format!("failed to inspect reopened source file {}: {error}", child_relative.display())
                    })?;
                    let close_reopened = close(reopened);
                    if !Self::same_stat(&before, &reopened_stat) {
                        return Err(format!(
                            "source file {} was replaced during snapshot",
                            child_relative.display()
                        ));
                    }
                    close_reopened.map_err(|error| {
                        format!("failed to close reopened source file {}: {error}", child_relative.display())
                    })?;
                }
                Err(Errno::ELOOP) => {
                    return Err(format!(
                        "symbolic link {} is not admissible in a frozen source tree",
                        child_relative.display()
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "failed to inspect source entry {}: {error}",
                        child_relative.display()
                    ));
                }
            }
        }

        let after_names = Self::source_directory_names(dir)?;
        if names != after_names {
            return Err(format!(
                "source directory {} changed while being snapshotted",
                if relative.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    relative
                }
                .display()
            ));
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
#[serde(deny_unknown_fields)]
pub struct ConfigTransaction {
    schema: String,
    version: u16,
    transaction_id: String,
    plan_digest: String,
    nonce: String,
    source_digest: String,
    candidate_store_path: Option<String>,
    phase: ConfigTransactionPhase,
    process_exit_status: Option<i32>,
    observed_runtime_closure: Option<String>,
    observed_profile_closure: Option<String>,
}

impl ConfigTransaction {
    pub const SCHEMA: &'static str = "luminous-nixward-config-transaction-v2";
    pub const VERSION: u16 = 2;

    fn compute_transaction_id(
        plan_digest: &[u8; 32],
        nonce: &[u8; 32],
        source_digest: &[u8; 32],
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TX_DOMAIN);
        hasher.update(plan_digest);
        hasher.update(nonce);
        hasher.update(source_digest);
        digest_hex(hasher.finalize().as_bytes())
    }

    pub fn new(plan_digest: [u8; 32], nonce: [u8; 32], source_digest: [u8; 32]) -> Self {
        Self {
            schema: Self::SCHEMA.into(),
            version: Self::VERSION,
            transaction_id: Self::compute_transaction_id(&plan_digest, &nonce, &source_digest),
            plan_digest: digest_hex(&plan_digest),
            nonce: digest_hex(&nonce),
            source_digest: digest_hex(&source_digest),
            candidate_store_path: None,
            phase: ConfigTransactionPhase::Prepared,
            process_exit_status: None,
            observed_runtime_closure: None,
            observed_profile_closure: None,
        }
    }

    pub fn phase(&self) -> ConfigTransactionPhase { self.phase }
    pub fn source_digest(&self) -> &str { &self.source_digest }
    pub fn transaction_id(&self) -> &str { &self.transaction_id }
    pub fn candidate_store_path(&self) -> Option<&str> { self.candidate_store_path.as_deref() }

    pub fn permits_source_rollback(&self) -> bool { self.phase.permits_source_rollback() }

    pub fn advance(&mut self, next: ConfigTransactionPhase) -> Result<(), String> {
        let allowed = match (self.phase, next) {
            (ConfigTransactionPhase::Prepared, ConfigTransactionPhase::InputFrozen) => true,
            (ConfigTransactionPhase::InputFrozen, ConfigTransactionPhase::CandidateBuilt) => self.candidate_store_path.is_some(),
            (ConfigTransactionPhase::InputFrozen, ConfigTransactionPhase::FailedBeforeActivation) => true,
            (ConfigTransactionPhase::CandidateBuilt, ConfigTransactionPhase::SourceCommitted) => self.candidate_store_path.is_some(),
            (ConfigTransactionPhase::CandidateBuilt, ConfigTransactionPhase::FailedBeforeActivation) => true,
            (ConfigTransactionPhase::SourceCommitted, ConfigTransactionPhase::ProfileTransitionStarted) => self.candidate_store_path.is_some(),
            (ConfigTransactionPhase::SourceCommitted, ConfigTransactionPhase::FailedBeforeActivation) => true,
            (ConfigTransactionPhase::ProfileTransitionStarted, ConfigTransactionPhase::ProfileCommitted) => true,
            (ConfigTransactionPhase::ProfileTransitionStarted, ConfigTransactionPhase::IndeterminateProfileTransition) => true,
            (ConfigTransactionPhase::ProfileCommitted, ConfigTransactionPhase::ActivationStarted) => true,
            (ConfigTransactionPhase::ActivationStarted, ConfigTransactionPhase::Activated) => self.observed_runtime_closure.is_some() && self.observed_profile_closure.is_some(),
            (ConfigTransactionPhase::ActivationStarted, ConfigTransactionPhase::IndeterminateActivation) => true,
            (ConfigTransactionPhase::IndeterminateProfileTransition, ConfigTransactionPhase::RecoveryObservation) => self.observed_runtime_closure.is_some() || self.observed_profile_closure.is_some(),
            (ConfigTransactionPhase::IndeterminateActivation, ConfigTransactionPhase::RecoveryObservation) => self.observed_runtime_closure.is_some() || self.observed_profile_closure.is_some(),
            (ConfigTransactionPhase::RecoveryObservation, ConfigTransactionPhase::RecoveryRequired) => true,
            (ConfigTransactionPhase::RecoveryObservation, ConfigTransactionPhase::Recovered) => self.observed_runtime_closure.is_some() && self.observed_profile_closure.is_some(),
            (ConfigTransactionPhase::RecoveryRequired, ConfigTransactionPhase::Recovered) => self.observed_runtime_closure.is_some() && self.observed_profile_closure.is_some(),
            _ => false,
        };
        if !allowed {
            return Err(format!("illegal config transaction transition: {:?} -> {:?}", self.phase, next));
        }
        self.phase = next;
        Ok(())
    }

    pub fn record_process_exit_status(&mut self, status: Option<i32>) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::ActivationStarted
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::RecoveryRequired
                | ConfigTransactionPhase::Recovered
        ) {
            return Err("activation process status cannot be recorded outside activation/recovery".into());
        }
        self.process_exit_status = status;
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        runtime_closure: Option<String>,
        profile_closure: Option<String>,
    ) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::IndeterminateProfileTransition
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::RecoveryRequired
                | ConfigTransactionPhase::Recovered
        ) {
            return Err("runtime/profile observation belongs to an indeterminate activation or recovery phase".into());
        }
        self.observed_runtime_closure = runtime_closure;
        self.observed_profile_closure = profile_closure;
        Ok(())
    }

    pub fn record_profile_transition(
        &mut self,
        disposition: &ProfileTransitionDisposition,
    ) -> Result<(), String> {
        if self.phase != ConfigTransactionPhase::ProfileTransitionStarted {
            return Err("profile transition evidence must be recorded from ProfileTransitionStarted".into());
        }
        match disposition {
            ProfileTransitionDisposition::Committed { process_exit_status, observed_profile } => {
                self.process_exit_status = *process_exit_status;
                self.observed_profile_closure = Some(observed_profile.clone());
                self.advance(ConfigTransactionPhase::ProfileCommitted)
            }
            ProfileTransitionDisposition::Indeterminate { process_exit_status, observed_profile, .. } => {
                self.process_exit_status = *process_exit_status;
                self.observed_profile_closure = observed_profile.clone();
                self.advance(ConfigTransactionPhase::IndeterminateProfileTransition)
            }
        }
    }

    pub fn set_candidate_store_path(&mut self, candidate_store_path: impl Into<String>) -> Result<(), String> {
        let path = candidate_store_path.into();
        if !super::execution_intent::is_valid_nix_store_path(&path) {
            return Err("candidate store path is not a canonical immutable Nix store path".into());
        }
        if !matches!(self.phase, ConfigTransactionPhase::InputFrozen | ConfigTransactionPhase::CandidateBuilt) {
            return Err("candidate store path can only be bound before source commit".into());
        }
        if let Some(existing) = &self.candidate_store_path {
            if existing != &path {
                return Err("candidate store identity is immutable once bound; refusing replacement".into());
            }
            return Ok(());
        }
        self.candidate_store_path = Some(path);
        Ok(())
    }

    pub fn persist_atomic(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(|| "transaction journal path has no parent".to_string())?;
        std::fs::create_dir_all(parent).map_err(|error| format!("failed to create transaction journal directory: {error}"))?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| format!("failed to serialize transaction journal: {error}"))?;
        let filename = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| "transaction journal filename is invalid UTF-8".to_string())?;
        let temp_path = parent.join(format!(".{filename}.tmp-{}", std::process::id()));
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path).map_err(|error| format!("failed to create transaction journal candidate: {error}"))?;
            file.write_all(&encoded).map_err(|error| format!("failed to write transaction journal candidate: {error}"))?;
            file.sync_all().map_err(|error| format!("failed to sync transaction journal candidate: {error}"))?;
        }
        if let Err(error) = std::fs::rename(&temp_path, path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(format!("failed to commit transaction journal: {error}"));
        }
        let parent_dir = std::fs::File::open(parent).map_err(|error| format!("failed to open transaction journal directory: {error}"))?;
        parent_dir.sync_all().map_err(|error| format!("failed to sync transaction journal directory: {error}"))?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let encoded = std::fs::read(path.as_ref()).map_err(|error| format!("failed to read transaction journal: {error}"))?;
        let transaction: Self = serde_json::from_slice(&encoded).map_err(|error| format!("invalid transaction journal: {error}"))?;
        if transaction.schema != Self::SCHEMA || transaction.version != Self::VERSION {
            return Err("transaction journal schema/version mismatch".into());
        }
        decode_digest(&transaction.transaction_id).map_err(|_| "transaction journal has an invalid transaction id".to_string())?;
        let plan_digest = decode_digest(&transaction.plan_digest)
            .map_err(|_| "transaction journal has an invalid plan digest".to_string())?;
        let nonce = decode_digest(&transaction.nonce)
            .map_err(|_| "transaction journal has an invalid nonce".to_string())?;
        let source_digest = decode_digest(&transaction.source_digest)
            .map_err(|_| "transaction journal has an invalid source digest".to_string())?;
        let recomputed_id = Self::compute_transaction_id(&plan_digest, &nonce, &source_digest);
        if transaction.transaction_id != recomputed_id {
            return Err("transaction journal transaction id does not match its persisted preimage".into());
        }
        if let Some(candidate) = transaction.candidate_store_path.as_deref() {
            if !super::execution_intent::is_valid_nix_store_path(candidate) {
                return Err("transaction journal has an invalid candidate store path".into());
            }
        }
        Ok(transaction)
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
    fn candidate_state_without_activation_start_requires_recovery() {
        let result = classify_activation_post_state(
            false,
            Some(1),
            Some(CANDIDATE),
            Some(CANDIDATE_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Switch,
        );
        assert!(matches!(result, ActivationDisposition::RecoveryRequired { .. }));
    }

    #[test]
    fn boot_candidate_without_activation_start_requires_recovery() {
        let result = classify_activation_post_state(
            false,
            Some(1),
            Some(PREDECESSOR),
            Some(CANDIDATE_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Boot,
        );
        assert!(matches!(result, ActivationDisposition::RecoveryRequired { .. }));
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
    fn profile_candidate_post_state_dominates_exit_status() {
        let result = classify_profile_transition_post_state(
            Some(1),
            Some(CANDIDATE_PROFILE),
            CANDIDATE_PROFILE,
        );
        assert!(matches!(
            result,
            ProfileTransitionDisposition::Committed {
                process_exit_status: Some(1),
                ..
            }
        ));
    }

    #[test]
    fn profile_mismatch_is_indeterminate_even_on_success() {
        let result = classify_profile_transition_post_state(
            Some(0),
            Some(PREDECESSOR_PROFILE),
            CANDIDATE_PROFILE,
        );
        assert!(matches!(
            result,
            ProfileTransitionDisposition::Indeterminate {
                process_exit_status: Some(0),
                ..
            }
        ));
    }

    #[test]
    fn boot_candidate_is_profile_proven_not_runtime_candidate() {
        let result = classify_activation_post_state(
            true,
            Some(1),
            Some(PREDECESSOR),
            Some(CANDIDATE_PROFILE),
            CANDIDATE,
            CANDIDATE_PROFILE,
            PREDECESSOR,
            PREDECESSOR_PROFILE,
            SystemActivation::Boot,
        );
        assert!(matches!(
            result,
            ActivationDisposition::Activated {
                observation: RecoveryObservation::BootCandidateProven { .. },
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

    #[cfg(unix)]
    #[test]
    fn frozen_source_rejects_symlink_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/allowed.nix"), "{}\n").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("nested"),
            dir.path().join("linked-dir"),
        )
        .unwrap();

        assert!(
            FrozenConfigSource::capture(dir.path(), "configuration.nix")
                .expect_err("directory symlink must fail closed")
                .contains("symbolic link")
        );
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
    fn transaction_graph_rejects_phase_skip() {
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        assert!(transaction.advance(ConfigTransactionPhase::CandidateBuilt).is_err());
        assert_eq!(transaction.phase(), ConfigTransactionPhase::Prepared);
        transaction
            .advance(ConfigTransactionPhase::InputFrozen)
            .unwrap();
        transaction
            .set_candidate_store_path(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test",
            )
            .unwrap();
        transaction
            .advance(ConfigTransactionPhase::CandidateBuilt)
            .unwrap();
        transaction
            .advance(ConfigTransactionPhase::SourceCommitted)
            .unwrap();
        transaction
            .advance(ConfigTransactionPhase::ProfileTransitionStarted)
            .unwrap();
        transaction
            .record_profile_transition(&ProfileTransitionDisposition::Committed {
                process_exit_status: Some(0),
                observed_profile:
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test".into(),
            })
            .unwrap();
        transaction
            .advance(ConfigTransactionPhase::ActivationStarted)
            .unwrap();
        assert!(transaction
            .advance(ConfigTransactionPhase::FailedBeforeActivation)
            .is_err());
    }

    #[test]
    fn profile_transition_is_the_source_rollback_boundary() {
        assert!(ConfigTransactionPhase::SourceCommitted.permits_source_rollback());
        assert!(!ConfigTransactionPhase::ProfileTransitionStarted.permits_source_rollback());
        assert!(!ConfigTransactionPhase::ProfileCommitted.permits_source_rollback());
        assert!(!ConfigTransactionPhase::IndeterminateProfileTransition.permits_source_rollback());
    }

    #[test]
    fn indeterminate_profile_cannot_activate() {
        let mut tx = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        tx.advance(ConfigTransactionPhase::InputFrozen).unwrap();
        tx.set_candidate_store_path("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test").unwrap();
        tx.advance(ConfigTransactionPhase::CandidateBuilt).unwrap();
        tx.advance(ConfigTransactionPhase::SourceCommitted).unwrap();
        tx.advance(ConfigTransactionPhase::ProfileTransitionStarted).unwrap();
        tx.record_profile_transition(&ProfileTransitionDisposition::Indeterminate {
            process_exit_status: Some(1),
            observed_profile: None,
            reason: "observation unavailable".into(),
        }).unwrap();
        assert!(tx.advance(ConfigTransactionPhase::ActivationStarted).is_err());
        assert_eq!(tx.phase(), ConfigTransactionPhase::IndeterminateProfileTransition);
    }
    #[test]
    fn transaction_journal_round_trips_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction.persist_atomic(&path).unwrap();
        let loaded = ConfigTransaction::load(&path).unwrap();
        assert_eq!(loaded.transaction_id(), transaction.transaction_id());
        assert_eq!(loaded.phase(), ConfigTransactionPhase::Prepared);
    }

    #[test]
    fn transaction_load_rejects_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        let mut value = serde_json::to_value(transaction).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(ConfigTransaction::load(&path).is_err());
    }

    #[test]
    fn transaction_load_validates_core_identity_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction.transaction_id = "BAD".into();
        transaction.persist_atomic(&path).unwrap();
        assert!(ConfigTransaction::load(&path).is_err());
    }

    #[test]
    fn transaction_load_rejects_tampered_persisted_preimage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.json");
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction.source_digest = digest_hex(&[9; 32]);
        transaction.persist_atomic(&path).unwrap();
        assert!(
            ConfigTransaction::load(&path)
                .expect_err("tampered source preimage must fail closed")
                .contains("does not match its persisted preimage")
        );
    }

    #[test]
    fn transaction_candidate_identity_requires_immutable_store_path() {
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction
            .advance(ConfigTransactionPhase::InputFrozen)
            .unwrap();
        assert!(transaction.set_candidate_store_path("/tmp/not-nix").is_err());
        transaction
            .set_candidate_store_path(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test",
            )
            .unwrap();
        assert_eq!(
            transaction.candidate_store_path(),
            Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test")
        );
    }

    #[test]
    fn transaction_id_binds_source_plan_and_nonce() {
        let first = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        let second = ConfigTransaction::new([1; 32], [2; 32], [4; 32]);
        assert_ne!(first.transaction_id, second.transaction_id);
    }
}
