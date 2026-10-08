// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! NixOS Configuration Writer — Atomic Authorized Source Mutation
//!
//! Provides safe, atomic configuration file modifications:
//! - Reads existing config via the parser layer
//! - Commits only exact authorized source bytes
//! - Writes atomically via descriptor-relative temporary file + rename
//! - Validates syntax with `nix-instantiate --parse` before committing
//!
//! This module does NOT execute system commands. Real writes require a
//! `ChangePlan` plus approval evidence bound to the exact machine and file
//! pre/post-state; subsequent system-changing commands are routed through the
//! capability-authorized executor under the same covenant.

use super::change_covenant::{ChangeAuthorization, ChangePlan, MachineBinding};
use super::config_transaction::ConfigTransactionPhase;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs::OpenOptions;
#[cfg(not(unix))]
use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::fd::AsRawFd;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct OwnedConfigFd(i32);

#[cfg(unix)]
impl Drop for OwnedConfigFd {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.0);
    }
}

/// Semantic state of the durable source replacement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCommitState {
    /// No durable replacement was attempted (noop or dry-run).
    NotAttempted,
    /// The replacement was atomically installed and post-state was proven.
    Committed,
    /// A replacement was attempted and the final durable/observed state cannot be proven.
    Indeterminate,
}

/// Result of a config write operation.
#[derive(Debug, Clone)]
pub struct WriteResult {
    /// Path that was written.
    pub path: PathBuf,
    /// Backup path (if created).
    pub backup_path: Option<PathBuf>,
    /// Whether the content was actually changed.
    pub changed: bool,
    /// Diff between old and new content (unified format).
    pub diff: String,
    /// Durable source commit state. Never infer this from `Result::Err` alone.
    pub commit_state: WriteCommitState,
}

/// A pending config modification (not yet applied).
#[derive(Debug, Clone)]
pub struct ConfigPatch {
    /// Target file path.
    pub target: PathBuf,
    /// Original content.
    pub original: String,
    /// Modified content.
    pub modified: String,
    /// Human-readable description of the change.
    pub description: String,
}

impl ConfigPatch {
    /// Compute a unified diff between original and modified.
    pub fn diff(&self) -> String {
        let old_lines: Vec<&str> = self.original.lines().collect();
        let new_lines: Vec<&str> = self.modified.lines().collect();

        let mut diff = String::new();
        diff.push_str(&format!("--- {}\n", self.target.display()));
        diff.push_str(&format!("+++ {}\n", self.target.display()));

        // Simple line-by-line diff (not a full unified diff algorithm)
        let max_len = old_lines.len().max(new_lines.len());
        for i in 0..max_len {
            let old = old_lines.get(i).copied().unwrap_or("");
            let new = new_lines.get(i).copied().unwrap_or("");
            if old != new {
                if !old.is_empty() {
                    diff.push_str(&format!("-{old}\n"));
                }
                if !new.is_empty() {
                    diff.push_str(&format!("+{new}\n"));
                }
            } else {
                diff.push_str(&format!(" {old}\n"));
            }
        }

        diff
    }

    /// Whether this patch actually changes anything.
    pub fn is_noop(&self) -> bool {
        self.original == self.modified
    }
}

/// Writes and modifies NixOS configuration files with atomic operations.
pub struct ConfigWriter {
    /// Root directory for NixOS config (default: /etc/nixos).
    config_root: PathBuf,
    /// Whether to validate syntax before writing.
    validate: bool,
    /// Dry-run mode: produce patches without writing.
    dry_run: bool,
    /// Optional explicit machine identity for staging/tests. Production callers
    /// normally bind to `/etc/machine-id` via `MachineBinding::local()`.
    machine_binding_override: Option<MachineBinding>,
}

impl ConfigWriter {
    /// Create a new config writer with default settings.
    pub fn new() -> Self {
        Self {
            config_root: PathBuf::from("/etc/nixos"),
            validate: true,
            dry_run: false,
            machine_binding_override: None,
        }
    }

    /// Set the config root directory.
    pub fn with_config_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config_root = root.into();
        self
    }

    /// Legacy compatibility no-op.
    ///
    /// Git commits are deliberately outside the authoritative source mutation
    /// primitive. A git backup is an independent history mechanism and cannot
    /// participate in the NixOS activation transaction.
    pub fn with_git_backup(self, _enabled: bool) -> Self {
        self
    }

    /// Enable or disable dry-run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Override the local machine binding. Intended for staging roots and
    /// deterministic tests; production mutation paths should normally use the
    /// host's `/etc/machine-id`.
    pub fn with_machine_binding(mut self, machine: MachineBinding) -> Self {
        self.machine_binding_override = Some(machine);
        self
    }

    fn current_machine_binding(&self) -> Result<MachineBinding, std::io::Error> {
        match &self.machine_binding_override {
            Some(machine) => Ok(machine.clone()),
            None => MachineBinding::local(),
        }
    }

    /// Add a package to `environment.systemPackages`.
    ///
    /// Returns a patch that, when applied, adds the package to the config.
    pub fn add_system_package(&self, package: &str) -> Result<ConfigPatch, std::io::Error> {
        let config_path = self.config_root.join("configuration.nix");
        let original = std::fs::read_to_string(&config_path)?;

        let pkg_entry = format!("    pkgs.{package}");

        // Check if already present
        if original.contains(&format!("pkgs.{package}")) {
            return Ok(ConfigPatch {
                target: config_path,
                original: original.clone(),
                modified: original,
                description: format!("{package} is already in systemPackages"),
            });
        }

        // Find the systemPackages list and insert
        let modified = if let Some(pos) = original.find("environment.systemPackages") {
            if let Some(bracket_pos) = original[pos..].find('[') {
                let insert_at = pos + bracket_pos + 1;
                let mut result = String::with_capacity(original.len() + pkg_entry.len() + 2);
                result.push_str(&original[..insert_at]);
                result.push('\n');
                result.push_str(&pkg_entry);
                result.push_str(&original[insert_at..]);
                result
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Could not find systemPackages list bracket",
                ));
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not find environment.systemPackages in configuration.nix",
            ));
        };

        Ok(ConfigPatch {
            target: config_path,
            original,
            modified,
            description: format!("Add pkgs.{package} to environment.systemPackages"),
        })
    }

    /// Remove a package from `environment.systemPackages`.
    pub fn remove_system_package(&self, package: &str) -> Result<ConfigPatch, std::io::Error> {
        let config_path = self.config_root.join("configuration.nix");
        let original = std::fs::read_to_string(&config_path)?;

        let patterns = [
            format!("    pkgs.{package}\n"),
            format!("    pkgs.{package}"),
            format!("pkgs.{package}\n"),
            format!("pkgs.{package}"),
        ];

        let mut modified = original.clone();
        for pattern in &patterns {
            modified = modified.replace(pattern, "");
        }

        Ok(ConfigPatch {
            target: config_path,
            original,
            modified,
            description: format!("Remove pkgs.{package} from environment.systemPackages"),
        })
    }

    /// Set a NixOS option to a value.
    ///
    /// This is a simple text-based approach — for complex modifications,
    /// use the parser layer to produce a proper AST edit.
    pub fn set_option(
        &self,
        option_path: &str,
        value: &str,
    ) -> Result<ConfigPatch, std::io::Error> {
        let config_path = self.config_root.join("configuration.nix");
        let original = std::fs::read_to_string(&config_path)?;

        let option_line = format!("  {option_path} = {value};");

        let modified = if let Some(pos) = original.find(option_path) {
            // Find the end of this line (semicolon)
            if let Some(semi) = original[pos..].find(';') {
                let line_start = original[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
                let line_end = pos + semi + 1;
                let mut result = String::with_capacity(original.len());
                result.push_str(&original[..line_start]);
                result.push_str(&option_line);
                result.push_str(&original[line_end..]);
                result
            } else {
                original.clone()
            }
        } else {
            // Option not found — insert before the closing brace
            if let Some(pos) = original.rfind('}') {
                let mut result = String::with_capacity(original.len() + option_line.len() + 2);
                result.push_str(&original[..pos]);
                result.push_str(&option_line);
                result.push('\n');
                result.push_str(&original[pos..]);
                result
            } else {
                original.clone()
            }
        };

        Ok(ConfigPatch {
            target: config_path,
            original,
            modified,
            description: format!("Set {option_path} = {value}"),
        })
    }

    /// Validate that content has balanced braces and doesn't remove critical patterns.
    fn validate_content_structure(original: &str, modified: &str) -> Result<(), std::io::Error> {
        // Check balanced braces in modified content
        let open_braces = modified.chars().filter(|&c| c == '{').count();
        let close_braces = modified.chars().filter(|&c| c == '}').count();
        if open_braces != close_braces {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unbalanced braces in modified content: {} open, {} close",
                    open_braces, close_braces
                ),
            ));
        }

        let open_brackets = modified.chars().filter(|&c| c == '[').count();
        let close_brackets = modified.chars().filter(|&c| c == ']').count();
        if open_brackets != close_brackets {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unbalanced brackets in modified content: {} open, {} close",
                    open_brackets, close_brackets
                ),
            ));
        }

        // Detect removal of critical NixOS module imports
        let critical_patterns = ["boot.loader", "fileSystems", "networking.hostName"];

        for pattern in &critical_patterns {
            if original.contains(pattern) && !modified.contains(pattern) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Refusing to remove critical config line containing '{}'",
                        pattern
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Apply a patch under an approval bound to the exact ChangePlan.
    ///
    /// This checks the target machine, plan freshness, exact patch digests, and
    /// current on-disk pre-state before the write. The post-state is read back
    /// and verified after the atomic rename.
    pub fn apply_patch_authorized(
        &self,
        patch: &ConfigPatch,
        plan: &ChangePlan,
        authorization: &ChangeAuthorization,
    ) -> Result<WriteResult, std::io::Error> {
        authorization
            .validate_plan(plan)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let machine = self.current_machine_binding()?;
        plan.validate_machine(&machine)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        plan.validate_patch(patch)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;

        let current = std::fs::read_to_string(&patch.target)?;
        if current != patch.original {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "configuration changed after plan creation; refusing stale authorized patch",
            ));
        }

        self.apply_patch_unchecked(patch)
    }

    /// Restore the exact pre-state only while the transaction is still before activation.
    ///
    /// Once NixOS activation begins, changing the durable source file cannot
    /// roll back the running system and is therefore rejected at this API boundary.
    pub fn restore_patch_original_pre_activation_authorized(
        &self,
        patch: &ConfigPatch,
        plan: &ChangePlan,
        authorization: &ChangeAuthorization,
        phase: ConfigTransactionPhase,
    ) -> Result<WriteCommitState, std::io::Error> {
        if !phase.permits_source_rollback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "source rollback is forbidden once NixOS activation has started",
            ));
        }
        authorization
            .validate_plan_binding(plan)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let machine = self.current_machine_binding()?;
        plan.validate_machine(&machine)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        plan.validate_patch(patch)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;

        let expected_restore = *blake3::hash(patch.original.as_bytes()).as_bytes();
        if plan.rollback().config_restore_digest() != Some(expected_restore) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "change plan does not bind this configuration rollback state",
            ));
        }

        if self.dry_run {
            return Ok(());
        }

        match self.atomic_replace_config(&patch.target, &patch.modified, &patch.original)? {
            WriteCommitState::Committed => Ok(()),
            WriteCommitState::NotAttempted => Err(std::io::Error::other(
                "rollback source replacement was not attempted",
            )),
            WriteCommitState::Indeterminate => Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "rollback source replacement became indeterminate after mutation attempt",
            )),
        }
    }

    /// Validate and render the result of a patch without mutating disk.
    pub fn preview_patch(&self, patch: &ConfigPatch) -> Result<WriteResult, std::io::Error> {
        if patch.is_noop() {
            return Ok(WriteResult {
                path: patch.target.clone(),
                backup_path: None,
                changed: false,
                diff: String::new(),
                commit_state: WriteCommitState::NotAttempted,
            });
        }
        Self::validate_content_structure(&patch.original, &patch.modified)?;
        Ok(WriteResult {
            path: patch.target.clone(),
            backup_path: None,
            changed: true,
            diff: patch.diff(),
        })
    }

    /// Low-level write primitive. Deliberately private: production callers must
    /// pass through `apply_patch_authorized`, which binds the write to a
    /// ChangePlan and verified approval evidence.
    fn apply_patch_unchecked(&self, patch: &ConfigPatch) -> Result<WriteResult, std::io::Error> {
        if patch.is_noop() {
            return Ok(WriteResult {
                path: patch.target.clone(),
                backup_path: None,
                changed: false,
                diff: String::new(),
                commit_state: WriteCommitState::NotAttempted,
            });
        }

        // Structural validation (always runs, even in dry-run)
        Self::validate_content_structure(&patch.original, &patch.modified)?;

        if self.dry_run {
            return Ok(WriteResult {
                path: patch.target.clone(),
                backup_path: None,
                changed: true,
                diff: patch.diff(),
                commit_state: WriteCommitState::NotAttempted,
            });
        }

        if self.validate {
            Self::validate_nix_syntax(&patch.modified)?;
        }

        // The file mutation primitive has no git, shell, or NixOS activation
        // side effects. Those belong to separate transactional domains.
        let commit_state =
            self.atomic_replace_config(&patch.target, &patch.original, &patch.modified)?;

        Ok(WriteResult {
            path: patch.target.clone(),
            backup_path: None,
            changed: true,
            diff: patch.diff(),
            commit_state,
        })
    }

    /// Replace one configuration file using a descriptor-anchored source-root
    /// directory, no-follow target access, an exclusive candidate created through
    /// openat, durable candidate data, renameat, parent-directory synchronization,
    /// and read-back verification.
    ///
    /// The compare-and-set remains advisory against writers that bypass
    /// Nixward's own coordination lock; that external-writer gap stays explicit.
    fn atomic_replace_config(
        &self,
        target: &Path,
        expected: &str,
        replacement: &str,
    ) -> Result<(), std::io::Error> {
        let parent = target.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration target has no parent",
            )
        })?;

        // ConfigWriter only has authority over direct children of its configured
        // source root. Reject a caller-supplied patch that points elsewhere,
        // even when its ChangePlan digest and approval are otherwise valid.
        let configured_root = self.config_root.canonicalize()?;
        let target_parent = parent.canonicalize()?;
        if target_parent != configured_root {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "configuration target is outside the configured authority root",
            ));
        }

        let name = target.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration target has no filename",
            )
        })?;

        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".nixward-config-{}-{}-{}.tmp",
            std::process::id(),
            counter,
            name.to_string_lossy()
        );

        #[cfg(unix)]
        {
            use nix::fcntl::{flock, openat, renameat, FlockArg, OFlag};
            use nix::sys::stat::Mode;
            use nix::unistd::{fsync, read, unlinkat, write, UnlinkatFlags};

            let mut parent_options = OpenOptions::new();
            parent_options.read(true);
            parent_options.custom_flags(
                nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            );
            let parent_file = parent_options.open(&parent)?;
            let configured_stat = std::fs::metadata(&configured_root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let opened_parent_stat = parent_file.metadata()?;
                if configured_stat.dev() != opened_parent_stat.dev()
                    || configured_stat.ino() != opened_parent_stat.ino()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "configuration authority root changed during descriptor acquisition",
                    ));
                }
            }
            let parent_fd = parent_file.as_raw_fd();

            // The lock is also opened through the authorized parent descriptor,
            // preventing a second path-resolution domain for Nixward writers.
            let lock_fd = openat(
                parent_fd,
                ".nixward-config-write.lock",
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to create descriptor-bound config lock: {error}"
                ))
            })?;

            let lock_fd = OwnedConfigFd(lock_fd);
            flock(lock_fd.0, FlockArg::LockExclusive).map_err(|error| {
                std::io::Error::other(format!(
                    "failed to acquire config mutation lock: {error}"
                ))
            })?;

            let target_fd = openat(
                parent_fd,
                name,
                OFlag::O_RDONLY
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to open configuration target through authority descriptor: {error}"
                ))
            })?;
            let target_fd = OwnedConfigFd(target_fd);
            let target_stat = nix::sys::stat::fstat(target_fd.0).map_err(|error| {
                std::io::Error::other(format!(
                    "failed to stat configuration target descriptor: {error}"
                ))
            })?;
            if target_stat.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configuration target is not a regular file",
                ));
            }

            let mut current_bytes = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                match read(target_fd.0, &mut buffer) {
                    Ok(0) => break,
                    Ok(count) => current_bytes.extend_from_slice(&buffer[..count]),
                    Err(error) => {
                        return Err(std::io::Error::other(format!(
                            "failed to read configuration target descriptor: {error}"
                        )))
                    }
                }
            }
            let current = std::str::from_utf8(&current_bytes).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("configuration target is not valid UTF-8: {error}"),
                )
            })?;
            if current != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "configuration changed during transaction; refusing stale replacement",
                ));
            }

            let temp_fd = openat(
                parent_fd,
                &temp_name,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to create descriptor-bound config candidate: {error}"
                ))
            })?;
            let temp_fd = OwnedConfigFd(temp_fd);

            let mut offset = 0;
            let bytes = replacement.as_bytes();
            while offset < bytes.len() {
                let written = write(temp_fd.0, &bytes[offset..]).map_err(|error| {
                    std::io::Error::other(format!(
                        "failed to write descriptor-bound config candidate: {error}"
                    ))
                })?;
                if written == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "descriptor-bound config candidate write made no progress",
                    ));
                }
                offset += written;
            }

            fsync(temp_fd.0).map_err(|error| {
                std::io::Error::other(format!(
                    "failed to sync descriptor-bound config candidate: {error}"
                ))
            })?;
            nix::sys::stat::fchmod(
                temp_fd.0,
                Mode::from_bits_truncate(target_stat.st_mode & 0o7777),
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "failed to preserve configuration permissions: {error}"
                ))
            })?;
            fsync(temp_fd.0).map_err(|error| {
                std::io::Error::other(format!(
                    "failed to resync descriptor-bound config candidate: {error}"
                ))
            })?;

            renameat(
                Some(parent_fd),
                &temp_name,
                Some(parent_fd),
                name,
            )
            .map_err(|error| {
                let _ = unlinkat(
                    Some(parent_fd),
                    &temp_name,
                    UnlinkatFlags::NoRemoveDir,
                );
                std::io::Error::other(format!(
                    "descriptor-bound config rename failed: {error}"
                ))
            })?;

            if fsync(parent_fd).is_err() {
                return Ok(WriteCommitState::Indeterminate);
            }

            let verify_fd = openat(
                parent_fd,
                name,
                OFlag::O_RDONLY
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
.map_err(|_error| {
                std::io::Error::other(
                    "configuration replacement committed but post-state observation could not be established",
                )
            })?;
            let verify_fd = OwnedConfigFd(verify_fd);
            let mut observed_bytes = Vec::new();
            loop {
                match read(verify_fd.0, &mut buffer) {
                    Ok(0) => break,
                    Ok(count) => observed_bytes.extend_from_slice(&buffer[..count]),
                    Err(_error) => {
                        return Ok(WriteCommitState::Indeterminate);
                    }
                }
            }
            if observed_bytes != bytes {
                return Ok(WriteCommitState::Indeterminate);
            }
            Ok(WriteCommitState::Committed)
        }

        #[cfg(not(unix))]
        {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            let temp_path = parent.join(&temp_name);
            let mut temp = options.open(&temp_path)?;
            temp.write_all(replacement.as_bytes())?;
            temp.flush()?;
            temp.sync_all()?;
            std::fs::rename(&temp_path, target)?;
            let parent_file = File::open(parent)?;
            if parent_file.sync_all().is_err() {
                return Ok(WriteCommitState::Indeterminate);
            }
            Ok(WriteCommitState::Committed)
        }
    }

    fn trusted_system_executable(name: &str) -> Result<String, std::io::Error> {
        if name.is_empty() || name.contains(std::path::MAIN_SEPARATOR) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "trusted system executable name is invalid",
            ));
        }
        let path = Path::new("/run/current-system/sw/bin").join(name);
        let canonical = std::fs::canonicalize(&path)?;
        let value = canonical.to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted system executable path is not valid UTF-8",
            )
        })?;
        if !value.starts_with("/nix/store/")
            || canonical.file_name().and_then(|v| v.to_str()) != Some(name)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "system executable did not resolve into an immutable Nix store object",
            ));
        }
        Ok(value.to_string())
    }

    /// Validate Nix syntax using nix-instantiate --parse.
    fn validate_nix_syntax(content: &str) -> Result<(), std::io::Error> {
        let executable = Self::trusted_system_executable("nix-instantiate")?;
        let mut child = Command::new(executable)
            .args(["--parse", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(content.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Nix syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(())
    }
}

impl Default for ConfigWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_temp_config(content: &str) -> (tempfile::TempDir, ConfigWriter) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("configuration.nix"), content).unwrap();
        let writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_git_backup(false)
            .with_dry_run(true);
        (dir, writer)
    }

    const SAMPLE_CONFIG: &str = r#"{ config, pkgs, ... }:
{
  environment.systemPackages = with pkgs; [
    vim
    git
    firefox
  ];

  services.openssh.enable = true;
  networking.firewall.enable = true;
}
"#;

    #[test]
    fn test_add_package_patch() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = writer.add_system_package("htop").unwrap();
        assert!(!patch.is_noop());
        assert!(patch.modified.contains("pkgs.htop"));
        assert!(patch.description.contains("htop"));
    }

    #[test]
    fn test_add_existing_package_noop() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = writer.add_system_package("firefox").unwrap();
        // "pkgs.firefox" doesn't appear in the "with pkgs; [" style,
        // but the content does contain "firefox" — the add_system_package
        // checks for "pkgs.firefox" specifically.
        assert!(!patch.modified.contains("pkgs.firefox\n    pkgs.firefox"));
    }

    #[test]
    fn test_remove_package_patch() {
        let config = r#"{ config, pkgs, ... }:
{
  environment.systemPackages = [
    pkgs.vim
    pkgs.git
    pkgs.firefox
  ];
}
"#;
        let (_dir, writer) = setup_temp_config(config);
        let patch = writer.remove_system_package("git").unwrap();
        assert!(!patch.modified.contains("pkgs.git"));
        assert!(patch.modified.contains("pkgs.vim"));
        assert!(patch.modified.contains("pkgs.firefox"));
    }

    #[test]
    fn test_set_option_existing() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = writer
            .set_option("services.openssh.enable", "false")
            .unwrap();
        assert!(patch.modified.contains("services.openssh.enable = false;"));
        assert!(!patch.modified.contains("services.openssh.enable = true;"));
    }

    #[test]
    fn test_set_option_new() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = writer.set_option("services.nginx.enable", "true").unwrap();
        assert!(patch.modified.contains("services.nginx.enable = true;"));
    }

    #[test]
    fn test_dry_run_apply() {
        let (dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = writer.add_system_package("htop").unwrap();
        let result = writer.apply_patch_unchecked(&patch).unwrap();
        assert!(result.changed);
        assert!(!result.diff.is_empty());
        assert_eq!(result.commit_state, WriteCommitState::NotAttempted);

        // Original file should be unchanged in dry-run
        let content = fs::read_to_string(dir.path().join("configuration.nix")).unwrap();
        assert!(!content.contains("pkgs.htop"));
    }

    #[test]
    fn test_validate_content_balanced_braces() {
        let original = "{ config }: { foo = 1; }";
        let modified = "{ config }: { foo = 1;"; // missing closing brace
        let result = ConfigWriter::validate_content_structure(original, modified);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unbalanced braces")
        );
    }

    #[test]
    fn test_validate_content_balanced_brackets() {
        let original = "[ a b c ]";
        let modified = "[ a b c"; // missing closing bracket
        let result = ConfigWriter::validate_content_structure(original, modified);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unbalanced brackets")
        );
    }

    #[test]
    fn test_validate_content_critical_removal_blocked() {
        let original = "{ boot.loader.grub.enable = true; networking.hostName = \"box\"; }";
        let modified = "{ networking.hostName = \"box\"; }"; // removed boot.loader
        let result = ConfigWriter::validate_content_structure(original, modified);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("boot.loader"));
    }

    #[test]
    fn test_validate_content_critical_hostname_removal_blocked() {
        let original = "{ networking.hostName = \"box\"; foo = 1; }";
        let modified = "{ foo = 1; }";
        let result = ConfigWriter::validate_content_structure(original, modified);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("networking.hostName")
        );
    }

    #[test]
    fn test_validate_content_ok() {
        let original = "{ boot.loader.grub.enable = true; }";
        let modified = "{ boot.loader.grub.enable = false; }";
        let result = ConfigWriter::validate_content_structure(original, modified);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apply_patch_rejects_unbalanced() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let patch = ConfigPatch {
            target: PathBuf::from("/tmp/test.nix"),
            original: "{ foo = 1; }".to_string(),
            modified: "{ foo = 1;".to_string(), // unbalanced
            description: "bad patch".to_string(),
        };
        let result = writer.apply_patch_unchecked(&patch);
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_root_rejects_outside_target() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("configuration.nix"), SAMPLE_CONFIG).unwrap();
        std::fs::write(outside.path().join("other.nix"), SAMPLE_CONFIG).unwrap();

        let writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_dry_run(false)
            .with_validate(false)
            .with_machine_binding_override("test-machine".into());
        let patch = ConfigPatch {
            target: outside.path().join("other.nix"),
            original: SAMPLE_CONFIG.to_string(),
            modified: SAMPLE_CONFIG.replace("firefox", "htop"),
            description: "outside root".into(),
        };
        let machine = MachineBinding::new("test-machine").unwrap();
        let plan = ChangePlan::config_only(machine, &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner", [3; 32]).unwrap();

        assert!(writer
            .apply_patch_authorized(&patch, &plan, &auth)
            .is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path().join("other.nix")).unwrap(),
            SAMPLE_CONFIG
        );
    }

    #[test]
    fn test_source_rollback_is_phase_bound() {
        let (_dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let machine = MachineBinding::new("test-machine").unwrap();
        let writer = writer.with_machine_binding(machine.clone());
        let patch = writer.add_system_package("htop").unwrap();
        let plan = ChangePlan::config_only(machine, &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner", [3; 32]).unwrap();

        assert!(writer
            .restore_patch_original_pre_activation_authorized(
                &patch,
                &plan,
                &auth,
                ConfigTransactionPhase::SourceCommitted,
            )
            .is_ok());
        assert!(writer
            .restore_patch_original_pre_activation_authorized(
                &patch,
                &plan,
                &auth,
                ConfigTransactionPhase::ActivationStarted,
            )
            .is_err());
    }

    #[test]
    fn test_authorized_patch_rejects_plan_or_machine_drift() {
        let (dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let machine = MachineBinding::new("test-machine").unwrap();
        let writer = writer.with_machine_binding(machine.clone());
        let patch = writer.add_system_package("htop").unwrap();
        let plan = ChangePlan::config_only(machine.clone(), &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner", [3; 32]).unwrap();

        assert!(writer.apply_patch_authorized(&patch, &plan, &auth).is_ok());

        let other_machine = MachineBinding::new("other-machine").unwrap();
        let wrong_writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_git_backup(false)
            .with_dry_run(true)
            .with_machine_binding(other_machine);
        assert!(
            wrong_writer
                .apply_patch_authorized(&patch, &plan, &auth)
                .is_err()
        );

        let different_patch = writer.set_option("services.nginx.enable", "true").unwrap();
        assert!(
            writer
                .apply_patch_authorized(&different_patch, &plan, &auth)
                .is_err()
        );
    }

    #[test]
    fn test_authorized_patch_rejects_stale_prestate() {
        let (dir, writer) = setup_temp_config(SAMPLE_CONFIG);
        let machine = MachineBinding::new("test-machine").unwrap();
        let writer = writer.with_machine_binding(machine.clone());
        let patch = writer.add_system_package("htop").unwrap();
        let plan = ChangePlan::config_only(machine, &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner", [4; 32]).unwrap();

        fs::write(
            dir.path().join("configuration.nix"),
            SAMPLE_CONFIG.replace("firefox", "chromium"),
        )
        .unwrap();
        let error = writer
            .apply_patch_authorized(&patch, &plan, &auth)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_covenant_apply_and_restore_exact_prestate_without_nix_tooling() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("configuration.nix"), SAMPLE_CONFIG).unwrap();
        let machine = MachineBinding::new("transaction-test-machine").unwrap();
        let mut writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_git_backup(false)
            .with_dry_run(false)
            .with_machine_binding(machine.clone());
        // This test targets covenant/atomic-write semantics, not nix-instantiate.
        writer.validate = false;

        let patch = writer.set_option("services.nginx.enable", "true").unwrap();
        let plan = ChangePlan::config_only(machine, &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "transaction-test-owner", [8; 32])
                .unwrap();

        writer.apply_patch_authorized(&patch, &plan, &auth).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("configuration.nix")).unwrap(),
            patch.modified
        );

        writer
            .restore_patch_original_pre_activation_authorized(&patch, &plan, &auth, ConfigTransactionPhase::SourceCommitted)
            .unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("configuration.nix")).unwrap(),
            patch.original
        );
    }

    #[test]
    fn test_covenant_rollback_refuses_to_clobber_concurrent_change() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("configuration.nix"), SAMPLE_CONFIG).unwrap();
        let machine = MachineBinding::new("transaction-test-machine").unwrap();
        let mut writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_git_backup(false)
            .with_dry_run(false)
            .with_machine_binding(machine.clone());
        writer.validate = false;

        let patch = writer.set_option("services.nginx.enable", "true").unwrap();
        let plan = ChangePlan::config_only(machine, &patch, 60_000).unwrap();
        let auth =
            ChangeAuthorization::from_verified_approval(&plan, "transaction-test-owner", [6; 32])
                .unwrap();
        writer.apply_patch_authorized(&patch, &plan, &auth).unwrap();

        fs::write(
            dir.path().join("configuration.nix"),
            format!("{}\n# concurrent operator edit\n", patch.modified),
        )
        .unwrap();
        let error = writer
            .restore_patch_original_pre_activation_authorized(&patch, &plan, &auth, ConfigTransactionPhase::SourceCommitted)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    // ---- Real (non-dry-run) write-path integration tests ----
    //
    // Every test above uses `.with_dry_run(true)`, so `apply_patch`'s real
    // branch — nix-instantiate syntax validation, git backup, atomic
    // temp+rename write — had zero test coverage before this module. All
    // tests here run against a `tempfile::tempdir()`, never real
    // `/etc/nixos`. See SYMTHAEA_NIXOS_MANAGEMENT_IMPROVEMENT_PLAN_2026-07-26.md
    // Phase 2.

    // These tests exercise the real nix-instantiate --parse validation path
    // (and, when git_backup=true, real git commands), not a mock. That's
    // the point -- see the module comment above. But nix-instantiate isn't
    // installed in every CI environment that runs `cargo test` (e.g. the
    // plain "Test Feature Combinations" matrix legs, as opposed to the
    // Nix-equipped "Hardened Nix Regressions" job) -- and since nixward is
    // a default workspace member, that made every one of those legs fail
    // regardless of which symthaea feature was actually under test (found
    // 2026-07-27 verifying export-to-standalone.sh against real CI). Skip
    // gracefully rather than fail when the tool genuinely isn't there,
    // rather than fail the whole matrix on an environment gap unrelated to
    // the code under test.
    fn nix_instantiate_available() -> bool {
        Command::new("nix-instantiate")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn setup_temp_config_live(
        content: &str,
        _git_backup: bool,
    ) -> Option<(tempfile::TempDir, ConfigWriter)> {
        if !nix_instantiate_available() {
            eprintln!(
                "SKIPPED: nix-instantiate not found on PATH -- this test exercises the real \
                 nix-instantiate --parse validation path and cannot run without it. \
                 Run under `nix develop` or in a Nix-equipped CI job to exercise this test."
            );
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("configuration.nix"), content).unwrap();
        let writer = ConfigWriter::new()
            .with_config_root(dir.path())
            .with_git_backup(git_backup)
            .with_dry_run(false);
        Some((dir, writer))
    }

    #[test]
    fn test_apply_patch_writes_atomically_for_real() {
        let Some((dir, writer)) = setup_temp_config_live(SAMPLE_CONFIG, false) else {
            return;
        };
        let patch = writer.add_system_package("htop").unwrap();
        let result = writer.apply_patch_unchecked(&patch).unwrap();
        assert!(result.changed);
        assert_eq!(result.commit_state, WriteCommitState::Committed);

        let on_disk = fs::read_to_string(dir.path().join("configuration.nix")).unwrap();
        assert!(
            on_disk.contains("pkgs.htop"),
            "real (non-dry-run) apply_patch must actually write the new content"
        );
        // The atomic-write temp file must not be left behind.
        assert!(!dir.path().join("configuration.nix.tmp").exists());
    }

    #[test]
    fn test_apply_patch_rejects_invalid_nix_syntax_via_nix_instantiate() {
        // Brace/bracket-balanced but syntactically invalid — the crude
        // structural check in validate_content_structure() cannot catch
        // this; only the real `nix-instantiate --parse` layer can.
        let Some((dir, writer)) = setup_temp_config_live(SAMPLE_CONFIG, false) else {
            return;
        };
        let patch = ConfigPatch {
            target: dir.path().join("configuration.nix"),
            original: SAMPLE_CONFIG.to_string(),
            modified: "{ foo = ; }".to_string(),
            description: "deliberately invalid nix syntax".to_string(),
        };
        let result = writer.apply_patch_unchecked(&patch);
        assert!(
            result.is_err(),
            "nix-instantiate --parse should reject this even though braces balance"
        );
        assert!(
            result.unwrap_err().to_string().contains("syntax"),
            "error should come from the real Nix syntax validator"
        );

        // And the on-disk file must be untouched — validation runs before
        // the write.
        let on_disk = fs::read_to_string(dir.path().join("configuration.nix")).unwrap();
        assert_eq!(on_disk, SAMPLE_CONFIG);
    }

    #[test]
    fn test_patch_diff() {
        let patch = ConfigPatch {
            target: PathBuf::from("/etc/nixos/configuration.nix"),
            original: "line1\nline2\n".to_string(),
            modified: "line1\nline2_changed\n".to_string(),
            description: "test".to_string(),
        };
        let diff = patch.diff();
        assert!(diff.contains("-line2"));
        assert!(diff.contains("+line2_changed"));
    }
}
