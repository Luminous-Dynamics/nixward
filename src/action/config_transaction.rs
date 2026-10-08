// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Native transaction semantics for configuration source commits and NixOS activation.
//!
//! This module deliberately models two different transactional domains:
//! durable configuration source state and the running NixOS generation.
//! The baseline transaction types contain no activation authority; the native
//! feature additionally provides the narrowly scoped Nix source
//! realization and retention primitive.

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

fn nix_normalized_mode(kind: &SourceEntryKind, source_mode: u32) -> u32 {
    #[cfg(unix)]
    {
        match kind {
            SourceEntryKind::Directory => 0o555,
            SourceEntryKind::File => {
                if source_mode & 0o111 != 0 { 0o555 } else { 0o444 }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = kind;
        source_mode
    }
}

fn verify_gc_root_target(store_path: &str, gc_root_path: &str) -> Result<(), String> {
    validate_gc_root_path(gc_root_path)?;
    if !super::execution_intent::is_valid_nix_store_path(store_path) {
        return Err("GC root target is not a canonical Nix store path".into());
    }
    let gc_root = std::path::Path::new(gc_root_path);
    let before = std::fs::symlink_metadata(gc_root)
        .map_err(|error| format!("failed to inspect GC root: {error}"))?;
    if !before.file_type().is_symlink() {
        return Err("GC root exists but is not a symlink".into());
    }
    let target = std::fs::read_link(gc_root)
        .map_err(|error| format!("failed to read GC root target: {error}"))?;
    let resolved = if target.is_absolute() {
        target.clone()
    } else {
        gc_root
            .parent()
            .ok_or_else(|| "GC root has no parent".to_string())?
            .join(&target)
    };
    let resolved = resolved
        .canonicalize()
        .map_err(|error| format!("failed to resolve GC root target: {error}"))?;
    if resolved != std::path::Path::new(store_path) {
        return Err("GC root does not target the exact declared store path".into());
    }
    let after = std::fs::symlink_metadata(gc_root)
        .map_err(|error| format!("failed to re-inspect GC root: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err("GC root changed during observation".into());
        }
    }
    let final_target = std::fs::read_link(gc_root)
        .map_err(|error| format!("failed to reread GC root target: {error}"))?;
    if final_target != target {
        return Err("GC root target changed during observation".into());
    }
    Ok(())
}

fn installable_selector_is_valid(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(".#") else {
        return false;
    };
    !suffix.is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn manifest_relative_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("source path {} is not valid UTF-8", path.display()))?;
    #[cfg(unix)]
    if value.contains('\\') {
        return Err(format!(
            "source path {} contains '\\', which is ambiguous in the portable manifest",
            path.display()
        ));
    }
    Ok(value.replace('\\', "/"))
}

impl FrozenConfigSource {
    pub fn capture(root: impl AsRef<Path>, entrypoint: impl AsRef<Path>) -> Result<Self, String> {
        let root_input = root.as_ref();
        let root_metadata = std::fs::symlink_metadata(root_input)
            .map_err(|error| format!("failed to inspect config source root: {error}"))?;
        if root_metadata.file_type().is_symlink() {
            return Err("config source root may not be a symbolic link".into());
        }
        if !root_metadata.is_dir() {
            return Err("config source root must be a directory".into());
        }

        let root = root_input.canonicalize().map_err(|error| {
            format!("failed to canonicalize config source root: {error}")
        })?;

        let entrypoint_path = {
            let path = entrypoint.as_ref();
            if path.is_absolute() {
                if !path.starts_with(&root) {
                    return Err("config entrypoint escapes source root".into());
                }
                path.to_path_buf()
            } else {
                root.join(path)
            }
        };
        let entrypoint_metadata = std::fs::symlink_metadata(&entrypoint_path)
            .map_err(|error| format!("failed to inspect config entrypoint: {error}"))?;
        if entrypoint_metadata.file_type().is_symlink() {
            return Err("config entrypoint may not be a symbolic link".into());
        }
        if !entrypoint_metadata.is_file() {
            return Err("config entrypoint must be a regular file".into());
        }
        let entrypoint = entrypoint_path
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize config entrypoint: {error}"))?;
        let relative_entrypoint = entrypoint
            .strip_prefix(&root)
            .map_err(|_| "config entrypoint escapes source root".to_string())?;

        let mut manifest = Vec::new();
        #[cfg(unix)]
        {
            let (mut root_dir, root_stat) = Self::open_source_root(&root, &root_metadata)?;
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

        let relative_entrypoint_string = manifest_relative_path(relative_entrypoint)?;
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
            entrypoint: manifest_relative_path(relative_entrypoint)?,
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
            let relative_path = manifest_relative_path(relative)?;
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
                let normalized_mode = nix_normalized_mode(&SourceEntryKind::Directory, mode);
                hasher.update(&normalized_mode.to_le_bytes());
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
                let normalized_mode = nix_normalized_mode(&SourceEntryKind::File, mode);
                hasher.update(&normalized_mode.to_le_bytes());
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
        expected: &std::fs::Metadata,
    ) -> Result<(nix::dir::Dir, nix::sys::stat::FileStat), String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        if expected.file_type().is_symlink() || !expected.is_dir() {
            return Err("config source root identity is not a stable directory".into());
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

                    let relative_path = manifest_relative_path(&child_relative)?;
                    let mode = (before.st_mode & 0o7777) as u32;
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(ENTRY_DOMAIN);
                    hasher.update(b"dir\0");
                    hasher.update(relative_path.as_bytes());
                    let normalized_mode = nix_normalized_mode(&SourceEntryKind::Directory, mode);
                    hasher.update(&normalized_mode.to_le_bytes());
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
                    let normalized_mode = nix_normalized_mode(&SourceEntryKind::File, mode);
                    hasher.update(&normalized_mode.to_le_bytes());
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

    /// Verify that an immutable realization root has exactly the same source
    /// manifest as this frozen source snapshot.
    ///
    /// The frozen manifest is deliberately compared directly; it is not treated
    /// as interchangeable with Nix's NAR hash, which is a separate canonical
    /// whole-tree fingerprint.
    pub fn verify_realization_at(&self, realized_root: impl AsRef<Path>) -> Result<(), String> {
        let realized_root = realized_root.as_ref();
        let metadata = std::fs::symlink_metadata(realized_root)
            .map_err(|error| format!("failed to inspect Nix realization root: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Nix realization root must not be a symlink alias".into());
        }
        if !metadata.is_dir() {
            return Err("Nix realization root must be a directory".into());
        }
        let canonical = realized_root
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize Nix realization root: {error}"))?;
        if canonical != realized_root {
            return Err("Nix realization root is not the declared canonical store path".into());
        }

        let observed = Self::capture(realized_root, Path::new(&self.entrypoint))?;
        if observed.entrypoint != self.entrypoint
            || observed.manifest.len() != self.manifest.len()
        {
            return Err("realized Nix store tree does not match frozen source shape".into());
        }

        for (expected, actual) in self.manifest.iter().zip(observed.manifest.iter()) {
            if expected.relative_path != actual.relative_path
                || expected.kind != actual.kind
                || expected.size != actual.size
                || expected.digest != actual.digest
            {
                return Err(format!(
                    "realized Nix store entry differs from frozen source: {}",
                    expected.relative_path
                ));
            }

            #[cfg(unix)]
            {
                let expected_mode = match expected.kind {
                    SourceEntryKind::Directory => 0o555,
                    SourceEntryKind::File => {
                        if expected.mode & 0o111 != 0 { 0o555 } else { 0o444 }
                    }
                };
                if actual.mode != expected_mode {
                    return Err(format!(
                        "realized Nix store entry {} has unexpected normalized mode {:04o}; expected {:04o}",
                        expected.relative_path, actual.mode, expected_mode
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Native Nix realization boundary for a frozen configuration source.
///
/// The returned store path is Nix's immutable object identity; the frozen-source
/// digest remains a separate semantic identity and is verified against the realized
/// tree before the retention lease becomes executable.
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub struct NixSourceRealizer {
    nix_executable: String,
}

#[cfg(feature = "native")]
impl NixSourceRealizer {
    fn verify_executable_identity_for_test(&self) -> Result<(), String> {
        let canonical = std::path::Path::new(&self.nix_executable);
        Self::validate_nix_executable_path(canonical)
    }

    fn validate_nix_executable_path(canonical: &std::path::Path) -> Result<(), String> {
        let value = canonical
            .to_str()
            .ok_or_else(|| "trusted Nix executable path is not valid UTF-8".to_string())?;
        if !value.starts_with("/nix/store/")
            || canonical.file_name().and_then(|name| name.to_str()) != Some("nix")
        {
            return Err("trusted Nix executable did not resolve to an immutable Nix store executable".into());
        }
        let metadata = std::fs::symlink_metadata(canonical)
            .map_err(|error| format!("failed to inspect trusted Nix executable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("trusted Nix executable is not a regular file".into());
        }
        Ok(())
    }

    pub fn new() -> Result<Self, String> {
        let link = std::path::Path::new("/run/current-system/sw/bin/nix");
        let canonical = std::fs::canonicalize(link)
            .map_err(|error| format!("failed to resolve trusted Nix executable: {error}"))?;
        let value = canonical
            .to_str()
            .ok_or_else(|| "trusted Nix executable path is not valid UTF-8".to_string())?;
        Self::validate_nix_executable_path(&canonical)?;
        Ok(Self {
            nix_executable: value.to_string(),
        })
    }

    fn parse_store_path(stdout: &str) -> Result<String, String> {
        let paths: Vec<String> = stdout
            .lines()
            .map(str::trim)
            .filter(|line| super::execution_intent::is_valid_nix_store_path(line))
            .map(ToOwned::to_owned)
            .collect();
        match paths.as_slice() {
            [path] => Ok(path.clone()),
            [] => Err("nix store add did not emit a canonical immutable store path".into()),
            _ => Err("nix store add emitted multiple canonical immutable store paths".into()),
        }
    }

    /// Realize the complete frozen source tree and retain it with a transaction-scoped
    /// GC root. The source tree is rechecked immediately before `nix store add`; the
    /// resulting Nix store tree is then compared byte-for-byte and metadata-for-metadata
    /// against the frozen manifest.
    pub fn realize(
        &self,
        source_root: &std::path::Path,
        source: &FrozenConfigSource,
        transaction_id: &str,
    ) -> Result<SourceRealizationLease, String> {
        if decode_digest(transaction_id).is_err() {
            return Err("source realization transaction id is invalid".into());
        }
        if !source_root.is_dir() {
            return Err("source realization root must be a directory".into());
        }
        source.verify_unchanged(source_root)?;

        let name = format!(
            "nixward-frozen-source-{}",
            transaction_id.get(..16).unwrap_or(transaction_id)
        );
        let output = std::process::Command::new(&self.nix_executable)
            .env_clear()
            .env("HOME", "/root")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args(["store", "add", "--name", &name])
            .arg(source_root)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|error| format!("failed to execute trusted nix store add: {error}"))?;

        if !output.status.success() {
            return Err(format!(
                "nix store add failed with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let store_path = Self::parse_store_path(&stdout)?;


        let gc_root_path = format!(
            "/nix/var/nix/gcroots/nixward/{transaction_id}",
        );
        let mut lease = SourceRealizationLease::new(source, store_path, gc_root_path)?;
        if let Err(error) = lease.establish_root() {
            return Err(error);
        }
        if let Err(error) = lease.verify_source_realization(source) {
            let _ = lease.release_root();
            return Err(error);
        }
        lease.verify_rooted()?;
        Ok(lease)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRealizationLeaseState {
    Pending,
    Rooted,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRealizationLease {
    pub source_digest: String,
    pub store_path: String,
    pub gc_root_path: String,
    pub state: SourceRealizationLeaseState,
}

impl SourceRealizationLease {
    fn validate_gc_root_path(gc_root_path: &str) -> Result<(), String> {
        let gc_root = std::path::Path::new(gc_root_path);
        let namespace = std::path::Path::new("/nix/var/nix/gcroots/nixward");
        let relative = gc_root
            .strip_prefix(namespace)
            .map_err(|_| "source GC root must be under /nix/var/nix/gcroots/nixward".to_string())?;
        if !gc_root.is_absolute()
            || relative.as_os_str().is_empty()
            || relative.components().count() != 1
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err("source GC root must be exactly one stable child of /nix/var/nix/gcroots/nixward".into());
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        if decode_digest(&self.source_digest).is_err() {
            return Err("source realization source digest is invalid".into());
        }
        if !super::execution_intent::is_valid_nix_store_path(&self.store_path) {
            return Err("source realization store path is not a canonical immutable Nix store path".into());
        }
        Self::validate_gc_root_path(&self.gc_root_path)
    }
    pub fn new(source: &FrozenConfigSource, store_path: impl Into<String>, gc_root_path: impl Into<String>) -> Result<Self, String> {
        let store_path = store_path.into();
        let gc_root_path = gc_root_path.into();
        if !super::execution_intent::is_valid_nix_store_path(&store_path) {
            return Err("source realization is not bound to a canonical immutable Nix store path".into());
        }
        Self::validate_gc_root_path(&gc_root_path)?;
        Ok(Self {
            source_digest: source.root_digest.clone(),
            store_path,
            gc_root_path,
            state: SourceRealizationLeaseState::Pending,
        })
    }

    fn verify_source_realization(&self, source: &FrozenConfigSource) -> Result<(), String> {
        self.validate_identity()?;
        if source.root_digest != self.source_digest {
            return Err("source realization lease digest does not match supplied frozen source".into());
        }
        source.verify_realization_at(&self.store_path)
    }

    fn observe_root_target(&self) -> Result<(), String> {
        self.validate_identity()?;

        let gc_root = std::path::Path::new(&self.gc_root_path);
        let before = std::fs::symlink_metadata(gc_root)
            .map_err(|error| format!("failed to inspect source GC root: {error}"))?;
        if !before.file_type().is_symlink() {
            return Err("source GC root exists but is not a symlink".into());
        }

        let target = std::fs::read_link(gc_root)
            .map_err(|error| format!("failed to read source GC root target: {error}"))?;

        let after = std::fs::symlink_metadata(gc_root)
            .map_err(|error| format!("failed to re-inspect source GC root: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.mode() != after.mode()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err("source GC root changed while being observed".into());
            }
        }

        let resolved = if target.is_absolute() {
            target
        } else {
            gc_root
                .parent()
                .ok_or_else(|| "source GC root has no parent".to_string())?
                .join(target)
        };
        let resolved = resolved
            .canonicalize()
            .map_err(|error| format!("failed to resolve source GC root target: {error}"))?;

        let final_metadata = std::fs::symlink_metadata(gc_root)
            .map_err(|error| format!("failed to re-inspect source GC root after resolution: {error}"))?;
        if !final_metadata.file_type().is_symlink() {
            return Err("source GC root ceased to be a symlink during observation".into());
        }
        let final_target = std::fs::read_link(gc_root)
            .map_err(|error| format!("failed to reread source GC root target: {error}"))?;
        if final_target != target {
            return Err("source GC root target changed during resolution".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != final_metadata.dev()
                || before.ino() != final_metadata.ino()
                || before.mode() != final_metadata.mode()
                || before.len() != final_metadata.len()
                || before.mtime() != final_metadata.mtime()
                || before.mtime_nsec() != final_metadata.mtime_nsec()
                || before.ctime() != final_metadata.ctime()
                || before.ctime_nsec() != final_metadata.ctime_nsec()
            {
                return Err("source GC root changed during target resolution".into());
            }
        }
        if resolved != std::path::Path::new(&self.store_path) {
            return Err("source GC root does not target the bound immutable store path".into());
        }

        Ok(())
    }

    #[cfg(feature = "native")]
    /// Establish the dedicated GC root and only mark the lease rooted after
    /// independently observing that the root resolves to the exact store path.
    ///
    /// This is intentionally separate from nix store add: Nix store objects are
    /// immutable, but materialization alone does not retain the object against GC.
    /// The lease therefore creates a dedicated root under Nixward's GC-root namespace
    /// and then verifies the live root target before granting the Rooted state.
    pub fn establish_root(&mut self) -> Result<(), String> {
        if self.state != SourceRealizationLeaseState::Pending {
            return Err("source realization lease is not pending root establishment".into());
        }
        self.validate_identity()?;
        let gc_root = std::path::Path::new(&self.gc_root_path);
        let namespace = gc_root
            .parent()
            .ok_or_else(|| "source GC root has no namespace parent".to_string())?;

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;

            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            options.custom_flags(
                nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            );
            let namespace_dir = options.open(namespace).map_err(|error| {
                format!(
                    "failed to securely open source GC-root namespace {}: {error}",
                    namespace.display()
                )
            })?;

            let name = gc_root
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "source GC root filename is not valid UTF-8".to_string())?;
            let name = CString::new(name)
                .map_err(|_| "source GC root filename contains NUL".to_string())?;
            let target = CString::new(self.store_path.as_str())
                .map_err(|_| "source store path contains NUL".to_string())?;

            let result = unsafe {
                nix::libc::symlinkat(
                    target.as_ptr(),
                    namespace_dir.as_raw_fd(),
                    name.as_ptr(),
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(format!("failed to create source GC root atomically: {error}"));
                }
                // Existing roots are not accepted on creation alone; the exact
                // target is independently re-observed below. This permits crash
                // recovery without turning a journal record into authority.
            } else {
                namespace_dir
                    .sync_all()
                    .map_err(|error| format!("failed to persist source GC root: {error}"))?;
            }
        }

        #[cfg(not(unix))]
        {
            return Err("source GC-root establishment is unsupported on this platform".into());
        }

        self.observe_root_target()?;
        self.state = SourceRealizationLeaseState::Rooted;
        Ok(())
    }
    /// Prove the lease is rooted from live GC-root filesystem evidence.
    pub fn prove_rooted(&mut self) -> Result<(), String> {
        if self.state != SourceRealizationLeaseState::Pending {
            return Err("source realization lease is not pending root proof".into());
        }
        self.observe_root_target()?;
        self.state = SourceRealizationLeaseState::Rooted;
        Ok(())
    }

    /// Re-verify a previously rooted lease from live GC-root filesystem evidence.
    pub fn verify_rooted(&self) -> Result<(), String> {
        if self.state != SourceRealizationLeaseState::Rooted {
            return Err("source realization lease is not rooted".into());
        }
        self.observe_root_target()
    }

    /// Remove the transaction-scoped GC root through the exact namespace
    /// descriptor, synchronize the namespace, and only then mark the lease released.
    #[cfg(feature = "native")]
    pub fn release_root(&mut self) -> Result<(), String> {
        if self.state != SourceRealizationLeaseState::Rooted {
            return Err("source realization lease must be rooted before release".into());
        }
        self.observe_root_target()?;

        let gc_root = std::path::Path::new(&self.gc_root_path);
        let namespace = gc_root
            .parent()
            .ok_or_else(|| "source GC root has no namespace parent".to_string())?;

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;

            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            options.custom_flags(
                nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            );
            let namespace_dir = options.open(namespace).map_err(|error| {
                format!(
                    "failed to securely open source GC-root namespace {}: {error}",
                    namespace.display()
                )
            })?;
            let name = gc_root
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "source GC root filename is not valid UTF-8".to_string())?;
            let name = CString::new(name)
                .map_err(|_| "source GC root filename contains NUL".to_string())?;

            let result = unsafe {
                nix::libc::unlinkat(
                    namespace_dir.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(format!("failed to remove source GC root: {error}"));
                }
            } else {
                namespace_dir
                    .sync_all()
                    .map_err(|error| format!("failed to persist source GC-root removal: {error}"))?;
            }
        }

        #[cfg(not(unix))]
        {
            return Err("source GC-root release is unsupported on this platform".into());
        }

        self.release()
    }

    /// Mark the lease released only after independent observation that the GC root is gone.
    pub fn release(&mut self) -> Result<(), String> {
        match self.state {
            SourceRealizationLeaseState::Pending => {
                Err("cannot release an unrooted source realization lease".into())
            }
            SourceRealizationLeaseState::Rooted => {
                let gc_root = std::path::Path::new(&self.gc_root_path);
                match std::fs::symlink_metadata(gc_root) {
                    Ok(_) => Err("source GC root still exists; refusing false release".into()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.state = SourceRealizationLeaseState::Released;
                        Ok(())
                    }
                    Err(error) => Err(format!(
                        "failed to inspect source GC root for release: {error}"
                    )),
                }
            }
            SourceRealizationLeaseState::Released => {
                Err("source realization lease already released".into())
            }
        }
    }

    pub fn is_rooted(&self) -> bool {
        matches!(self.state, SourceRealizationLeaseState::Rooted)
    }
}
/// Native candidate-build boundary. The build input is the immutable
/// source store object held by a rooted SourceRealizationLease; the mutable
/// working tree is never passed to the builder.
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub struct NixCandidateBuilder {
    nix_executable: String,
}

#[cfg(feature = "native")]
#[cfg(unix)]
fn establish_candidate_gc_root(store_path: &str, gc_root_path: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    validate_gc_root_path(gc_root_path)?;
    if !super::execution_intent::is_valid_nix_store_path(store_path) {
        return Err("candidate GC root target is not a canonical Nix store path".into());
    }
    let gc_root = std::path::Path::new(gc_root_path);
    let namespace = gc_root.parent().ok_or_else(|| "candidate GC root has no namespace parent".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let namespace_dir = options.open(namespace).map_err(|error| format!("failed to securely open candidate GC-root namespace: {error}"))?;
    let name = gc_root.file_name().and_then(|v| v.to_str()).ok_or_else(|| "candidate GC root filename is invalid UTF-8".to_string())?;
    let name = CString::new(name).map_err(|_| "candidate GC root filename contains NUL".to_string())?;
    let target = CString::new(store_path).map_err(|_| "candidate store path contains NUL".to_string())?;
    let result = unsafe { nix::libc::symlinkat(target.as_ptr(), namespace_dir.as_raw_fd(), name.as_ptr()) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!("failed to create candidate GC root: {error}"));
        }
    } else {
        namespace_dir.sync_all().map_err(|error| format!("failed to persist candidate GC root: {error}"))?;
    }
    verify_gc_root_target(store_path, gc_root_path)?;
    Ok(())
}

impl NixCandidateBuilder {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            nix_executable: NixSourceRealizer::new()?.nix_executable,
        })
    }

    fn exact_installable(
        source_store_path: &str,
        installable: &str,
    ) -> Result<String, String> {
        if !super::execution_intent::is_valid_nix_store_path(source_store_path) {
            return Err("candidate build source is not a canonical immutable Nix store path".into());
        }
        let suffix = installable
            .strip_prefix(".#")
            .ok_or_else(|| "candidate build installable must be rooted at .#".to_string())?;
        if suffix.is_empty()
            || installable
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err("candidate build installable contains invalid characters".into());
        }
        Ok(format!("{source_store_path}#{suffix}"))
    }

    /// Build exactly one candidate from an immutable source store object and
    /// require its output to equal the expected immutable system closure.
    pub fn build(
        &self,
        source: &FrozenConfigSource,
        lease: &SourceRealizationLease,
        installable: &str,
        expected_out_path: &str,
        transaction_id: &str,
        realization_plan_digest: &str,
    ) -> Result<CandidateBuildReceipt, String> {
        if !lease.is_rooted() {
            return Err("candidate build requires a rooted source realization".into());
        }
        lease.verify_rooted()?;
        lease.verify_source_realization(source)?;

        if !super::execution_intent::is_valid_nix_store_path(expected_out_path) {
            return Err("candidate build expected output is not a canonical immutable Nix store path".into());
        }
        if expected_out_path == lease.store_path {
            return Err("candidate build output must differ from retained source realization".into());
        }
        if decode_digest(realization_plan_digest).is_err() {
            return Err("candidate build realization-plan digest is invalid".into());
        }

        let installable_selector = installable.to_string();
        let installable = Self::exact_installable(&lease.store_path, installable)?;

        let output = std::process::Command::new(&self.nix_executable)
            .env_clear()
            .env("HOME", "/root")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args([
                "build",
                "--no-link",
                "--print-out-paths",
                "--no-update-lock-file",
            ])
            .arg(&installable)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|error| format!("failed to execute trusted nix build: {error}"))?;

        if !output.status.success() {
            return Err(format!(
                "nix build failed with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let candidate_store_path = NixSourceRealizer::parse_store_path(&stdout)?;
        let transaction_id = transaction_id.to_string();
        if decode_digest(&transaction_id).is_err() {
            return Err("candidate build transaction id is invalid".into());
        }
        let candidate_gc_root = format!(
            "/nix/var/nix/gcroots/nixward/{}-candidate",
            transaction_id
        );
        #[cfg(unix)]
        establish_candidate_gc_root(&candidate_store_path, &candidate_gc_root)?;
        #[cfg(not(unix))]
        return Err("candidate retention is unsupported on this platform".into());

        if candidate_store_path != expected_out_path {
            return Err(format!(
                "nix build output differs from authorized expected path: observed {candidate_store_path}, expected {expected_out_path}"
            ));
        }

        source.verify_realization_at(&lease.store_path)?;
        lease.verify_rooted()?;

        let metadata = std::fs::symlink_metadata(&candidate_store_path)
            .map_err(|error| format!("failed to inspect candidate store path: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("candidate output must be a canonical immutable directory".into());
        }

        CandidateBuildReceipt::new(
            source,
            lease.store_path.clone(),
            installable_selector,
            candidate_store_path,
            candidate_gc_root,
            realization_plan_digest.to_string(),
        )
    }

    #[cfg(test)]
    fn parse_installable_for_test(
        source_store_path: &str,
        installable: &str,
    ) -> Result<String, String> {
        Self::exact_installable(source_store_path, installable)
    }
}

/// Exact receipt for building one immutable system candidate from one
/// retained Nix source realization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBuildReceipt {
    pub source_digest: String,
    pub source_store_path: String,
    pub installable: String,
    pub candidate_store_path: String,
    pub gc_root_path: String,
    pub realization_plan_digest: String,
}

impl CandidateBuildReceipt {
    pub fn new(
        source: &FrozenConfigSource,
        source_store_path: impl Into<String>,
        installable: impl Into<String>,
        candidate_store_path: impl Into<String>,
        gc_root_path: impl Into<String>,
        realization_plan_digest: impl Into<String>,
    ) -> Result<Self, String> {
        let source_store_path = source_store_path.into();
        let installable = installable.into();
        let candidate_store_path = candidate_store_path.into();
        let gc_root_path = gc_root_path.into();
        let realization_plan_digest = realization_plan_digest.into();
        if !installable_selector_is_valid(&installable) {
            return Err("candidate build installable is not an exact .# selector".into());
        }
        if !super::execution_intent::is_valid_nix_store_path(&source_store_path) {
            return Err("candidate build source is not a canonical immutable Nix store path".into());
        }
        if !super::execution_intent::is_valid_nix_store_path(&candidate_store_path) {
            return Err("candidate build output is not a canonical immutable Nix store path".into());
        }
        validate_gc_root_path(&gc_root_path)?;
        if source_store_path == candidate_store_path {
            return Err("candidate build output must differ from retained source realization".into());
        }
        if decode_digest(&realization_plan_digest).is_err() {
            return Err("candidate build realization-plan digest is invalid".into());
        }
        Ok(Self {
            source_digest: source.root_digest.clone(),
            source_store_path,
            installable,
            candidate_store_path,
            gc_root_path,
            realization_plan_digest,
        })
    }

    /// Independently prove that the candidate retention root still points to
    /// the exact immutable candidate store object.
    pub fn verify_retention(&self) -> Result<(), String> {
        verify_gc_root_target(&self.candidate_store_path, &self.gc_root_path)
    }

    fn validate_identity(&self) -> Result<(), String> {
        if !installable_selector_is_valid(&self.installable) {
            return Err("candidate build installable is invalid".into());
        }
        validate_gc_root_path(&self.gc_root_path)?;
        if decode_digest(&self.source_digest).is_err() {
            return Err("candidate build source digest is invalid".into());
        }
        if !super::execution_intent::is_valid_nix_store_path(&self.source_store_path) {
            return Err("candidate build source store path is invalid".into());
        }
        if !super::execution_intent::is_valid_nix_store_path(&self.candidate_store_path) {
            return Err("candidate build output store path is invalid".into());
        }
        if decode_digest(&self.realization_plan_digest).is_err() {
            return Err("candidate build realization-plan digest is invalid".into());
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
    #[serde(default)]
    frozen_source: Option<FrozenConfigSource>,
    #[serde(default)]
    candidate_store_path: Option<String>,
    #[serde(default)]
    candidate_build: Option<CandidateBuildReceipt>,
    phase: ConfigTransactionPhase,
    process_exit_status: Option<i32>,
    observed_runtime_closure: Option<String>,
    observed_profile_closure: Option<String>,
    source_realization: Option<SourceRealizationLease>,
    /// False after journal load until an authoritative recovery observation is refreshed.
    #[serde(skip)]
    recovery_observed: bool,
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
            frozen_source: None,
            candidate_store_path: None,
            candidate_build: None,
            phase: ConfigTransactionPhase::Prepared,
            process_exit_status: None,
            observed_runtime_closure: None,
            observed_profile_closure: None,
            source_realization: None,
            recovery_observed: true,
        }
    }

    pub fn phase(&self) -> ConfigTransactionPhase { self.phase }
    pub fn source_digest(&self) -> &str { &self.source_digest }
    pub fn plan_digest(&self) -> Result<[u8; 32], String> { decode_digest(&self.plan_digest) }
    pub fn transaction_id(&self) -> &str { &self.transaction_id }
    pub fn recovery_observation_confirmed(&self) -> bool { self.recovery_observed }
    /// Return the candidate store path only when it is bound by the exact
    /// candidate-build receipt. Legacy journal-only candidate paths are not
    /// execution authority.
    pub fn candidate_store_path(&self) -> Option<&str> {
        self.candidate_build
            .as_ref()
            .map(|receipt| receipt.candidate_store_path.as_str())
    }

    pub fn permits_source_rollback(&self) -> bool { self.phase.permits_source_rollback() }

    pub fn advance(&mut self, next: ConfigTransactionPhase) -> Result<(), String> {
        if !self.recovery_observed
            && !matches!(self.phase, ConfigTransactionPhase::Prepared | ConfigTransactionPhase::InputFrozen)
        {
            return Err("loaded transaction requires fresh recovery observation before further execution".into());
        }
        let allowed = match (self.phase, next) {
            (ConfigTransactionPhase::Prepared, ConfigTransactionPhase::InputFrozen) => true,
            (ConfigTransactionPhase::InputFrozen, ConfigTransactionPhase::CandidateBuilt) => {
                let Some(lease) = self.source_realization.as_ref() else {
                    return Err("candidate realization requires a retained source realization".into());
                };
                if self.candidate_build.is_none() {
                    return Err(
                        "candidate realization requires an exact retained-source build receipt".into(),
                    );
                }
                true
            },
            (ConfigTransactionPhase::InputFrozen, ConfigTransactionPhase::FailedBeforeActivation) => true,
            (ConfigTransactionPhase::CandidateBuilt, ConfigTransactionPhase::SourceCommitted) => self.candidate_build.is_some(),
            (ConfigTransactionPhase::CandidateBuilt, ConfigTransactionPhase::FailedBeforeActivation) => true,
            (ConfigTransactionPhase::SourceCommitted, ConfigTransactionPhase::ProfileTransitionStarted) => {
                self.candidate_build.is_some()
            },
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

    /// Record activation process status and post-state atomically in the typed
    /// lifecycle. Runtime/profile evidence outranks the child exit status.
    pub fn record_activation_post_state(
        &mut self,
        process_exit_status: Option<i32>,
        runtime_closure: Option<String>,
        profile_closure: Option<String>,
    ) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::ActivationStarted
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::RecoveryRequired
        ) {
            return Err("activation post-state must be recorded from an activation or recovery phase".into());
        }
        self.process_exit_status = process_exit_status;
        self.observed_runtime_closure = runtime_closure.clone();
        self.observed_profile_closure = profile_closure.clone();
        let Some(candidate) = self.candidate_store_path() else {
            return Err("activation post-state requires a bound candidate build receipt".into());
        };
        if runtime_closure.as_deref() == Some(candidate)
            && profile_closure.as_deref() == Some(candidate)
        {
            self.phase = ConfigTransactionPhase::Activated;
        } else {
            self.phase = ConfigTransactionPhase::IndeterminateActivation;
        }
        Ok(())
    }

    /// Enter the explicit recovery domain from any activation/profile-transition
    /// uncertainty. The observation is recorded before the phase becomes
    /// RecoveryRequired so the durable journal never claims recovery without
    /// preserving the evidence that triggered it.
    pub fn enter_recovery_required(
        &mut self,
        observation: &RecoveryObservation,
    ) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::ProfileTransitionStarted
                | ConfigTransactionPhase::ProfileCommitted
                | ConfigTransactionPhase::IndeterminateProfileTransition
                | ConfigTransactionPhase::ActivationStarted
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::RecoveryRequired,
        ) {
            return Err("transaction is not in a recoverable uncertainty phase".into());
        }
        match observation {
            RecoveryObservation::PredecessorProvenActive { runtime_closure, profile_closure }
            | RecoveryObservation::CandidateProvenActive { runtime_closure, profile_closure }
            | RecoveryObservation::BootCandidateProven { runtime_closure, profile_closure } => {
                self.observed_runtime_closure = Some(runtime_closure.clone());
                self.observed_profile_closure = Some(profile_closure.clone());
            }
            RecoveryObservation::MixedOrUnknown { runtime_closure, profile_closure, .. } => {
                self.observed_runtime_closure = runtime_closure.clone();
                self.observed_profile_closure = profile_closure.clone();
            }
        }
        self.phase = ConfigTransactionPhase::RecoveryRequired;
        Ok(())
    }
    /// Record recovery post-state and close the transaction only when the exact
    /// authorized predecessor runtime and profile are both observed.
    pub fn record_recovery_post_state(
        &mut self,
        expected_runtime_closure: &str,
        expected_profile_closure: &str,
        process_exit_status: Option<i32>,
        observed_runtime_closure: Option<String>,
        observed_profile_closure: Option<String>,
    ) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::RecoveryRequired
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::IndeterminateProfileTransition,
        ) {
            return Err("recovery post-state cannot be recorded from the current transaction phase".into());
        }
        self.process_exit_status = process_exit_status;
        self.observed_runtime_closure = observed_runtime_closure.clone();
        self.observed_profile_closure = observed_profile_closure.clone();
        if observed_runtime_closure.as_deref() == Some(expected_runtime_closure)
            && observed_profile_closure.as_deref() == Some(expected_profile_closure)
        {
            self.phase = ConfigTransactionPhase::Recovered;
        } else {
            self.phase = ConfigTransactionPhase::RecoveryRequired;
        }
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

    /// Re-establish execution significance from the source snapshot already
    /// persisted in this journal. This is the restart-safe recovery boundary:
    /// callers do not get to substitute a mutable working-tree snapshot.
    pub fn confirm_recovery_observation_from_journal(
        &mut self,
        expected_phase: ConfigTransactionPhase,
        observation: &RecoveryObservation,
    ) -> Result<(), String> {
        let source = self
            .frozen_source
            .as_ref()
            .ok_or_else(|| "transaction journal has no persisted frozen source snapshot".to_string())?
            .clone();
        let observed_source_store_path = self
            .source_realization
            .as_ref()
            .map(|realization| {
                realization.verify_rooted()?;
                Ok::<String, String>(realization.store_path.clone())
            })
            .transpose()?;
        self.confirm_recovery_observation(
            &source,
            expected_phase,
            observed_source_store_path.as_deref(),
            observation,
        )
    }

    /// Re-establish execution significance after loading a journal.
    /// The expected phase is supplied by authoritative execution context, not
    /// trusted from the journal record itself.
    pub fn confirm_recovery_observation(
        &mut self,
        source: &FrozenConfigSource,
        expected_phase: ConfigTransactionPhase,
        observed_source_store_path: Option<&str>,
        observation: &RecoveryObservation,
    ) -> Result<(), String> {
        if self.recovery_observed {
            return Err("recovery observation has already been confirmed".into());
        }
        if self.phase != expected_phase {
            return Err("journal phase does not match authoritative recovery context".into());
        }
        if matches!(observation, RecoveryObservation::MixedOrUnknown { .. }) {
            return Err("mixed or unknown recovery observation cannot restore execution significance".into());
        }
        if let Some(realization) = self.source_realization.as_mut() {
            if realization.state == SourceRealizationLeaseState::Released {
                return Err("released source realization cannot be re-established from a journal".into());
            }
            let observed = observed_source_store_path
                .ok_or_else(|| "fresh source GC-root observation is required".to_string())?;
            realization.verify_source_realization(source)?;
            match realization.state {
                SourceRealizationLeaseState::Pending => realization.prove_rooted()?,
                SourceRealizationLeaseState::Rooted => realization.verify_rooted()?,
                SourceRealizationLeaseState::Released => {
                    return Err("released source realization cannot be re-established from a journal".into());
                }
            }
            if observed != realization.store_path {
                return Err("fresh source realization observation does not match the bound store path".into());
            }
        }
        self.recovery_observed = true;
        Ok(())
    }
    /// Bind and durably retain the exact frozen source snapshot used by this
    /// transaction. The snapshot is part of the journal evidence, not a
    /// mutable working-tree reference.
    pub fn bind_frozen_source(&mut self, source: &FrozenConfigSource) -> Result<(), String> {
        if self.phase != ConfigTransactionPhase::InputFrozen {
            return Err("frozen source can only be bound at InputFrozen".into());
        }
        if source.root_digest != self.source_digest {
            return Err("frozen source digest does not match transaction source digest".into());
        }
        if let Some(existing) = &self.frozen_source {
            if existing != source {
                return Err("frozen source snapshot is immutable once bound".into());
            }
            return Ok(());
        }
        self.frozen_source = Some(source.clone());
        Ok(())
    }

    pub fn frozen_source(&self) -> Option<&FrozenConfigSource> {
        self.frozen_source.as_ref()
    }

    pub fn bind_source_realization(
        &mut self,
        source: &FrozenConfigSource,
        realization: SourceRealizationLease,
    ) -> Result<(), String> {
        if self.source_realization.is_some() {
            return Err("source realization is already bound to this transaction".into());
        }
        if realization.source_digest != self.source_digest {
            return Err("source realization digest does not match transaction source digest".into());
        }
        self.bind_frozen_source(source)?;
        if !realization.is_rooted() {
            return Err("source realization lease must be rooted before binding".into());
        }
        realization.verify_rooted()?;
        realization.verify_source_realization(source)?;
        self.source_realization = Some(realization);
        Ok(())
    }

    pub fn source_realization(&self) -> Option<&SourceRealizationLease> {
        self.source_realization.as_ref()
    }

    pub fn release_source_realization(&mut self) -> Result<(), String> {
        let realization = self
            .source_realization
            .as_mut()
            .ok_or_else(|| "transaction has no source realization lease".to_string())?;
        if matches!(
            self.phase,
            ConfigTransactionPhase::ProfileTransitionStarted
                | ConfigTransactionPhase::ProfileCommitted
                | ConfigTransactionPhase::IndeterminateProfileTransition
                | ConfigTransactionPhase::ActivationStarted
                | ConfigTransactionPhase::IndeterminateActivation
                | ConfigTransactionPhase::RecoveryObservation
                | ConfigTransactionPhase::RecoveryRequired
        ) {
            return Err("source realization lease cannot be released while execution/recovery authority is live".into());
        }
        #[cfg(feature = "native")]
        {
            realization.release_root()
        }
        #[cfg(not(feature = "native"))]
        {
            realization.release()
        }
    }
    /// Bind the exact immutable source realization, candidate output, and
    /// realization-plan identity to this transaction.
    pub fn bind_candidate_build(
        &mut self,
        receipt: CandidateBuildReceipt,
    ) -> Result<(), String> {
        if !matches!(
            self.phase,
            ConfigTransactionPhase::InputFrozen | ConfigTransactionPhase::CandidateBuilt
        ) {
            return Err("candidate build receipt can only be bound before source commit".into());
        }
        receipt.validate_identity()?;
        if receipt.source_digest != self.source_digest {
            return Err("candidate build source digest does not match transaction source digest".into());
        }
        let realization = self
            .source_realization
            .as_ref()
            .ok_or_else(|| "candidate build requires a retained source realization".to_string())?;
        if !realization.is_rooted() {
            return Err("candidate build requires a rooted source realization".into());
        }
        if receipt.source_store_path != realization.store_path {
            return Err("candidate build source store path does not match the retained source realization".into());
        }
        receipt.verify_retention()?;
        if let Some(existing) = &self.candidate_build {
            if existing != &receipt {
                return Err("candidate build receipt is immutable once bound; refusing replacement".into());
            }
            return Ok(());
        }
        if let Some(existing) = &self.candidate_store_path {
            if existing != &receipt.candidate_store_path {
                return Err("candidate build output does not match the legacy candidate identity".into());
            }
        }
        self.candidate_store_path = Some(receipt.candidate_store_path.clone());
        self.candidate_build = Some(receipt);
        Ok(())
    }

    pub fn candidate_build(&self) -> Option<&CandidateBuildReceipt> {
        self.candidate_build.as_ref()
    }

    /// Legacy journal compatibility setter. This field is deliberately not
    /// authoritative for execution; bind_candidate_build is required before
    /// CandidateBuilt can be reached.
    pub fn set_candidate_store_path(&mut self, candidate_store_path: impl Into<String>) -> Result<(), String> {
        if !matches!(self.phase, ConfigTransactionPhase::InputFrozen | ConfigTransactionPhase::CandidateBuilt) {
            return Err("candidate store path can only be set before source commit".into());
        }
        let candidate_store_path = candidate_store_path.into();
        if !super::execution_intent::is_valid_nix_store_path(&candidate_store_path) {
            return Err("candidate store path must be a canonical immutable Nix store path".into());
        }
        if let Some(receipt) = &self.candidate_build {
            if receipt.candidate_store_path != candidate_store_path {
                return Err("candidate store path conflicts with the bound candidate-build receipt".into());
            }
        }
        self.candidate_store_path = Some(candidate_store_path);
        Ok(())
    }

    pub fn persist_atomic(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or_else(|| "transaction journal path has no parent".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create transaction journal directory: {error}"))?;

        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to serialize transaction journal: {error}"))?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "transaction journal filename is invalid UTF-8".to_string())?;
        let temp_name = format!(".{filename}.tmp-{}", std::process::id());

        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;

            use nix::errno::Errno;
            use nix::fcntl::{openat, renameat, OFlag};
            use nix::sys::stat::Mode;
            use nix::unistd::{close, fsync, unlinkat, write, UnlinkatFlags};

            let parent = parent
                .canonicalize()
                .map_err(|error| format!("failed to canonicalize transaction journal directory: {error}"))?;
            let mut parent_options = std::fs::OpenOptions::new();
            parent_options.read(true);
            parent_options.custom_flags(
                nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            );
            let parent_dir = parent_options.open(&parent).map_err(|error| {
                format!(
                    "failed to securely open transaction journal directory {}: {error}",
                    parent.display()
                )
            })?;
            let parent_fd = parent_dir.as_raw_fd();

            let filename_c = CString::new(filename.as_bytes())
                .map_err(|_| "transaction journal filename contains an embedded NUL".to_string())?;
            let temp_name_c = CString::new(temp_name.as_bytes())
                .map_err(|_| "transaction journal temporary filename contains an embedded NUL".to_string())?;

            let temp_fd = openat(
                parent_fd,
                temp_name_c.as_c_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| {
                format!(
                    "failed to create descriptor-bound transaction journal candidate: {error}"
                )
            })?;

            let write_result = (|| -> Result<(), String> {
                let mut written = 0usize;
                while written < encoded.len() {
                    match write(temp_fd, &encoded[written..]) {
                        Ok(0) => {
                            return Err(
                                "descriptor-bound transaction journal write made no progress"
                                    .into(),
                            );
                        }
                        Ok(count) => written += count,
                        Err(Errno::EINTR) => continue,
                        Err(error) => {
                            return Err(format!(
                                "failed to write descriptor-bound transaction journal candidate: {error}"
                            ));
                        }
                    }
                }
                fsync(temp_fd).map_err(|error| {
                    format!(
                        "failed to sync descriptor-bound transaction journal candidate: {error}"
                    )
                })?;
                Ok(())
            })();

            let close_result = close(temp_fd);
            if let Err(error) = write_result {
                let _ = unlinkat(parent_fd, temp_name_c.as_c_str(), UnlinkatFlags::NoRemoveDir);
                let _ = close_result;
                return Err(error);
            }
            close_result.map_err(|error| {
                let _ = unlinkat(parent_fd, temp_name_c.as_c_str(), UnlinkatFlags::NoRemoveDir);
                format!(
                    "failed to close descriptor-bound transaction journal candidate: {error}"
                )
            })?;

            if let Err(error) = renameat(
                Some(parent_fd),
                temp_name_c.as_c_str(),
                Some(parent_fd),
                filename_c.as_c_str(),
            ) {
                let _ = unlinkat(parent_fd, temp_name_c.as_c_str(), UnlinkatFlags::NoRemoveDir);
                return Err(format!(
                    "failed to commit descriptor-bound transaction journal: {error}"
                ));
            }

            fsync(parent_fd).map_err(|error| {
                format!(
                    "failed to sync transaction journal directory after rename: {error}"
                )
            })?;

            return Ok(());
        }

        #[cfg(not(unix))]
        {
            let temp_path = parent.join(&temp_name);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options
                .open(&temp_path)
                .map_err(|error| {
                    format!("failed to create transaction journal candidate: {error}")
                })?;
            file.write_all(&encoded).map_err(|error| {
                format!("failed to write transaction journal candidate: {error}")
            })?;
            file.sync_all().map_err(|error| {
                format!("failed to sync transaction journal candidate: {error}")
            })?;
            if let Err(error) = std::fs::rename(&temp_path, path) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(format!("failed to commit transaction journal: {error}"));
            }
            let parent_dir = std::fs::File::open(parent)
                .map_err(|error| format!("failed to open transaction journal directory: {error}"))?;
            parent_dir.sync_all().map_err(|error| {
                format!("failed to sync transaction journal directory: {error}")
            })?;
            Ok(())
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let encoded = {
            #[cfg(unix)]
            {
                let expected = std::fs::symlink_metadata(path)
                    .map_err(|error| format!("failed to inspect transaction journal: {error}"))?;
                super::secure_boot_signature::read_regular_file_no_follow_stable(path, &expected)
                    .map_err(|error| format!("failed to securely read transaction journal: {error}"))?
            }
            #[cfg(not(unix))]
            {
                std::fs::read(path)
                    .map_err(|error| format!("failed to read transaction journal: {error}"))?
            }
        };
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
        if !matches!(
            transaction.phase,
            ConfigTransactionPhase::Prepared | ConfigTransactionPhase::InputFrozen
        ) && transaction.frozen_source.is_none()
        {
            return Err("transaction journal at executable phase is missing its frozen source snapshot".into());
        }
        if let Some(source) = transaction.frozen_source.as_ref() {
            if source.root_digest != transaction.source_digest {
                return Err("transaction journal frozen source digest mismatch".into());
            }
        }

        if let Some(receipt) = transaction.candidate_build.as_ref() {
            receipt.validate_identity()?;
            if receipt.source_digest != transaction.source_digest {
                return Err("transaction journal candidate build source digest mismatch".into());
            }
            if let Some(realization) = transaction.source_realization.as_ref() {
                if receipt.source_store_path != realization.store_path {
                    return Err("transaction journal candidate build source store mismatch".into());
                }
            }
            if let Some(candidate) = transaction.candidate_store_path.as_deref() {
                if candidate != receipt.candidate_store_path {
                    return Err("transaction journal candidate identities disagree".into());
                }
            }
        }

        if let Some(candidate) = transaction.candidate_store_path.as_deref() {
            if !super::execution_intent::is_valid_nix_store_path(candidate) {
                return Err("transaction journal has an invalid candidate store path".into());
            }
        }

        if let Some(realization) = transaction.source_realization.as_ref() {
            if realization.source_digest != transaction.source_digest {
                return Err("transaction journal source realization digest mismatch".into());
            }
            if !super::execution_intent::is_valid_nix_store_path(&realization.store_path) {
                return Err("transaction journal contains an invalid source realization store path".into());
            }
            realization.validate_identity()?;

        }
        let mut transaction = transaction;
        if let Some(realization) = transaction.source_realization.as_mut() {
            if realization.state == SourceRealizationLeaseState::Rooted {
                realization.state = SourceRealizationLeaseState::Pending;
            }
        }
        transaction.recovery_observed = false;
        Ok(transaction)    }
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
    fn frozen_source_rejects_external_entrypoint_symlink_alias() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        let alias = outside.path().join("entrypoint.nix");
        std::os::unix::fs::symlink(root.path().join("configuration.nix"), &alias).unwrap();

        assert!(
            FrozenConfigSource::capture(root.path(), &alias)
                .expect_err("external entrypoint symlink must fail closed")
                .contains("escapes source root")
        );
    }

    #[cfg(unix)]
    #[test]
    fn frozen_source_rejects_ambiguous_manifest_path_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();

        let invalid_utf8 = std::ffi::OsString::from_vec(vec![0xff, b'.', b'n', b'i', b'x']);
        std::fs::write(root.path().join(&invalid_utf8), b"{}\n").unwrap();
        let utf8_error = FrozenConfigSource::capture(root.path(), "configuration.nix")
            .expect_err("non-UTF-8 manifest path must fail closed");
        assert!(utf8_error.contains("not valid UTF-8"));

        std::fs::remove_file(root.path().join(&invalid_utf8)).unwrap();
        std::fs::write(root.path().join("foo\\bar.nix"), b"{}\n").unwrap();
        let slash_error = FrozenConfigSource::capture(root.path(), "configuration.nix")
            .expect_err("backslash manifest path must fail closed");
        assert!(slash_error.contains("contains '\\'"));
    }

    #[cfg(unix)]
    #[test]
    fn open_source_root_rejects_replaced_identity() {
        let parent = tempfile::tempdir().unwrap();
        let original = parent.path().join("source");
        let replacement = parent.path().join("replacement");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(
            original.join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        let expected = std::fs::symlink_metadata(&original).unwrap();

        std::fs::rename(&original, &replacement).unwrap();
        std::fs::create_dir(&original).unwrap();

        let error = FrozenConfigSource::open_source_root(&original, &expected)
            .expect_err("replacement root must fail closed");
        assert!(error.contains("changed during descriptor acquisition"));
    }

    #[cfg(unix)]
    #[test]
    fn frozen_source_rejects_symlink_root_alias() {
        let source = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();

        let alias = parent.path().join("source-alias");
        std::os::unix::fs::symlink(source.path(), &alias).unwrap();
        assert!(
            FrozenConfigSource::capture(&alias, "configuration.nix")
                .expect_err("source root symlink must fail closed")
                .contains("config source root may not be a symbolic link")
        );
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

    #[cfg(unix)]
    #[test]
    fn realized_root_rejects_symlink_alias() {
        let source_dir = tempfile::tempdir().unwrap();
        let realized_dir = tempfile::tempdir().unwrap();
        let alias_dir = tempfile::tempdir().unwrap();

        std::fs::write(
            source_dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        std::fs::write(
            realized_dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(realized_dir.path(), alias_dir.path().join("store-alias")).unwrap();

        let source = FrozenConfigSource::capture(source_dir.path(), "configuration.nix").unwrap();
        assert!(source
            .verify_realization_at(alias_dir.path().join("store-alias"))
            .expect_err("store symlink alias must fail closed")
            .contains("must not be a symlink alias"));
    }

    #[cfg(unix)]
    #[test]
    fn frozen_source_accepts_nix_normalized_modes() {
        use std::os::unix::fs::PermissionsExt;

        let source_dir = tempfile::tempdir().unwrap();
        let realized_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            source_dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        std::fs::write(
            realized_dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();

        std::fs::set_permissions(
            source_dir.path().join("configuration.nix"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::set_permissions(
            realized_dir.path().join("configuration.nix"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::fs::set_permissions(
            realized_dir.path(),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();

        let source =
            FrozenConfigSource::capture(source_dir.path(), "configuration.nix").unwrap();
        source
            .verify_realization_at(realized_dir.path())
            .expect("Nix-normalized permissions must be accepted");
    }

    #[test]
    fn frozen_source_verifies_exact_realization() {
        let source_dir = tempfile::tempdir().unwrap();
        let realized_dir = tempfile::tempdir().unwrap();

        for root in [source_dir.path(), realized_dir.path()] {
            std::fs::write(
                root.join("configuration.nix"),
                "{ config = {}; }\n",
            )
            .unwrap();
            std::fs::create_dir(root.join("nested")).unwrap();
            std::fs::write(root.join("nested/value.nix"), "value = 1;\n").unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                realized_dir.path().join("configuration.nix"),
                std::fs::Permissions::from_mode(0o444),
            )
            .unwrap();
            std::fs::set_permissions(
                realized_dir.path().join("nested"),
                std::fs::Permissions::from_mode(0o555),
            )
            .unwrap();
            std::fs::set_permissions(
                realized_dir.path().join("nested/value.nix"),
                std::fs::Permissions::from_mode(0o444),
            )
            .unwrap();
        }

        let source = FrozenConfigSource::capture(source_dir.path(), "configuration.nix").unwrap();
        source.verify_realization_at(realized_dir.path()).unwrap();

        std::fs::write(
            realized_dir.path().join("nested/value.nix"),
            "value = 2;\n",
        )
        .unwrap();
        assert!(source.verify_realization_at(realized_dir.path()).is_err());
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

    #[cfg(feature = "native")]
    #[test]
    fn nix_source_realizer_requires_regular_nix_executable() {
        let realizer = NixSourceRealizer {
            nix_executable: "/tmp/not-nix".into(),
        };
        assert!(realizer
            .verify_executable_identity_for_test()
            .is_err());
    }

    #[cfg(feature = "native")]
    #[test]
    fn nix_source_realizer_parses_only_canonical_store_output() {
        let stdout = "warning: copied source\n/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward-frozen-source-test\n";
        assert_eq!(
            NixSourceRealizer::parse_store_path(stdout).unwrap(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward-frozen-source-test"
        );

        assert!(NixSourceRealizer::parse_store_path("not-a-store-path\n").is_err());
        assert!(NixSourceRealizer::parse_store_path("/nix/store/NOT-A-VALID-PATH\n").is_err());
        assert!(
            NixSourceRealizer::parse_store_path(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first\n/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second\n"
            )
            .expect_err("multiple store paths must fail closed")
            .contains("multiple canonical immutable store paths")
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn candidate_builder_binds_installable_to_immutable_source() {
        let source = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
        assert_eq!(
            NixCandidateBuilder::parse_installable_for_test(
                source,
                ".#nixosConfigurations.test.config.system.build.toplevel"
            )
            .unwrap(),
            format!("{source}#nixosConfigurations.test.config.system.build.toplevel")
        );
        assert!(NixCandidateBuilder::parse_installable_for_test(source, "/tmp/escape").is_err());
        assert!(NixCandidateBuilder::parse_installable_for_test(source, ".#bad target").is_err());
        assert!(NixCandidateBuilder::parse_installable_for_test("/tmp/source", ".#ok").is_err());
    }

    #[cfg(feature = "native")]
    #[test]
    fn nix_source_realizer_rejects_malformed_transaction_identity() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        std::fs::create_dir(&source_root).unwrap();
        std::fs::write(source_root.join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(&source_root, "configuration.nix").unwrap();
        let realizer = NixSourceRealizer {
            nix_executable: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nix/bin/nix".into(),
        };

        assert!(realizer
            .realize(&source_root, &source, "not-a-transaction-id")
            .is_err());
    }

    fn test_candidate_receipt() -> CandidateBuildReceipt {
        CandidateBuildReceipt {
            source_digest: digest_hex(&[3; 32]),
            source_store_path:
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixward-frozen-config".into(),
            installable:
                ".#nixosConfigurations.test.config.system.build.toplevel".into(),
            candidate_store_path:
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test".into(),
            gc_root_path:
                "/nix/var/nix/gcroots/nixward/test-candidate".into(),
            realization_plan_digest: digest_hex(&[4; 32]),
        }
    }

    fn bind_test_candidate(transaction: &mut ConfigTransaction) {
        transaction.source_realization = Some(SourceRealizationLease {
            source_digest: digest_hex(&[3; 32]),
            store_path:
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixward-frozen-config".into(),
            gc_root_path: format!(
                "/nix/var/nix/gcroots/nixward/{}",
                transaction.transaction_id()
            ),
            state: SourceRealizationLeaseState::Rooted,
        });
        transaction.candidate_store_path = Some(test_candidate_receipt().candidate_store_path.clone());
        transaction.candidate_build = Some(test_candidate_receipt());
    }

    #[test]
    fn transaction_graph_rejects_phase_skip() {
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        assert!(transaction.advance(ConfigTransactionPhase::CandidateBuilt).is_err());
        assert_eq!(transaction.phase(), ConfigTransactionPhase::Prepared);
        transaction
            .advance(ConfigTransactionPhase::InputFrozen)
            .unwrap();
        bind_test_candidate(&mut transaction);
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
    fn mixed_recovery_observation_requires_recovery() {
        let mut tx = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        tx.phase = ConfigTransactionPhase::ActivationStarted;
        let observation = RecoveryObservation::MixedOrUnknown {
            runtime_closure: Some("runtime".into()),
            profile_closure: Some("profile".into()),
            reason: "unexpected state".into(),
        };
        tx.enter_recovery_required(&observation).unwrap();
        assert_eq!(tx.phase(), ConfigTransactionPhase::RecoveryRequired);
        assert_eq!(tx.observed_runtime_closure.as_deref(), Some("runtime"));
        assert_eq!(tx.observed_profile_closure.as_deref(), Some("profile"));
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
        bind_test_candidate(&mut tx);
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
    fn transaction_journal_persists_frozen_source_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let source_root = dir.path().join("source");
        std::fs::create_dir(&source_root).unwrap();
        std::fs::write(
            source_root.join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        let source =
            FrozenConfigSource::capture(&source_root, "configuration.nix").unwrap();
        let source_digest = decode_digest(&source.root_digest).unwrap();
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], source_digest);
        transaction
            .advance(ConfigTransactionPhase::InputFrozen)
            .unwrap();
        transaction.bind_frozen_source(&source).unwrap();

        let journal = dir.path().join("transaction.json");
        transaction.persist_atomic(&journal).unwrap();
        let loaded = ConfigTransaction::load(&journal).unwrap();

        assert_eq!(loaded.frozen_source(), Some(&source));
    }

    #[test]
    fn executable_transaction_journal_rejects_missing_frozen_source() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("transaction.json");
        let mut transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction.phase = ConfigTransactionPhase::SourceCommitted;
        transaction.persist_atomic(&journal).unwrap();

        assert!(
            ConfigTransaction::load(&journal)
                .expect_err("executable journal without frozen source must fail closed")
                .contains("missing its frozen source snapshot")
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_load_rejects_symlink_path() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("transaction.json");
        let link = dir.path().join("transaction-link.json");
        let transaction = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        transaction.persist_atomic(&journal).unwrap();
        std::os::unix::fs::symlink(&journal, &link).unwrap();

        assert!(
            ConfigTransaction::load(&link)
                .expect_err("journal symlink must fail closed")
                .contains("securely read transaction journal")
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_persist_replaces_final_symlink_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("transaction.json");
        let target = dir.path().join("redirect-target.json");
        std::fs::write(&target, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&target, &journal).unwrap();

        ConfigTransaction::new([1; 32], [2; 32], [3; 32])
            .persist_atomic(&journal)
            .unwrap();

        let metadata = std::fs::symlink_metadata(&journal).unwrap();
        assert!(metadata.is_file());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "sentinel");
        assert!(ConfigTransaction::load(&journal).is_ok());
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
    fn candidate_build_receipt_rejects_same_source_and_output() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("configuration.nix"),
            "{ config = {}; }\n",
        )
        .unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        let path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-same";
        assert!(CandidateBuildReceipt::new(
            &source,
            path,
            ".#nixosConfigurations.test.config.system.build.toplevel",
            path,
            "/nix/var/nix/gcroots/nixward/test-candidate",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .is_err());
    }

    #[test]
    fn source_realization_lease_binds_digest_store_and_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        let mut lease = SourceRealizationLease::new(
            &source,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-frozen-config",
            "/nix/var/nix/gcroots/nixward/txn-001",
        )
        .unwrap();
        assert_eq!(lease.source_digest, source.root_digest);
        assert!(!lease.is_rooted());
    }

    #[test]
    fn source_realization_lease_refuses_false_release() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        let mut lease = SourceRealizationLease::new(
            &source,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-frozen-config",
            "/nix/var/nix/gcroots/nixward/txn-001",
        )
        .unwrap();
        assert!(lease.release().is_err());
    }

    #[test]
    fn source_realization_rejects_gc_root_escaping_namespace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        assert!(SourceRealizationLease::new(
            &source,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-frozen-config",
            "/tmp/nixward-root",
        ).is_err());
    }

    #[test]
    fn candidate_built_rejects_stale_source_gc_root() {
        let mut tx = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        tx.advance(ConfigTransactionPhase::InputFrozen).unwrap();
        tx.set_candidate_store_path(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-test",
        )
        .unwrap();
        tx.source_realization = Some(SourceRealizationLease {
            source_digest: "0000000000000000000000000000000000000000000000000000000000000003".into(),
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-frozen-config".into(),
            gc_root_path: "/nix/var/nix/gcroots/nixward/txn-001".into(),
            state: SourceRealizationLeaseState::Rooted,
        });
        assert!(tx.bind_candidate_build(test_candidate_receipt()).is_err());
        assert!(tx.advance(ConfigTransactionPhase::CandidateBuilt).is_err());
    }

    #[test]
    fn candidate_built_requires_retained_source_realization() {
        let mut tx = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        tx.advance(ConfigTransactionPhase::InputFrozen).unwrap();
        assert!(tx.bind_candidate_build(test_candidate_receipt()).is_err());
        assert!(tx.advance(ConfigTransactionPhase::CandidateBuilt).is_err());
    }
    #[test]
    fn journal_load_downgrades_historical_root_proof() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), "{ config = {}; }\n").unwrap();
        let source = FrozenConfigSource::capture(dir.path(), "configuration.nix").unwrap();
        let mut lease = SourceRealizationLease::new(
            &source,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-frozen-config",
            "/nix/var/nix/gcroots/nixward/txn-001",
        ).unwrap();
        // Unit-test the historical state transition without requiring a live GC root.
        lease.state = SourceRealizationLeaseState::Rooted;
        let mut tx = ConfigTransaction::new([1; 32], [2; 32], [3; 32]);
        tx.source_realization = Some(lease);
        let path = dir.path().join("transaction.json");
        tx.persist_atomic(&path).unwrap();
        let loaded = ConfigTransaction::load(&path).unwrap();
        assert_eq!(loaded.source_realization().unwrap().state, SourceRealizationLeaseState::Pending);
        assert!(!loaded.recovery_observed);
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
