// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Durable, output-free process observations for journal-owned activation workers.
//!
//! A process observation is not evidence of the resulting NixOS state. It only
//! records that the exact journal-bound worker identity was observed to exit
//! (or terminate by signal) and that this observer published a receipt.

use super::config_transaction::{ActivationWorkerIdentity, ActivationWorkerPurpose};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OBSERVATION_SCHEMA: &str = "luminous-nixward-worker-observation";
const OBSERVATION_VERSION: u16 = 1;
const OBSERVATION_DOMAIN: &[u8] = b"nixward-worker-observation-identity-v1\0";
const MAX_OBSERVATION_BYTES: u64 = 16 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerObservationReceipt {
    schema: String,
    version: u16,
    transaction_id: String,
    purpose: ActivationWorkerPurpose,
    pid: u32,
    boot_id: String,
    start_time_ticks: u64,
    worker_identity_digest: String,
    observed_at_unix_ms: Option<u64>,
    elapsed_ms: u64,
    disposition: WorkerProcessDisposition,
}

/// Process disposition only; this does not assert activation or recovery success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub(super) enum WorkerProcessDisposition {
    Exited { code: i32 },
    Signaled { signal: i32 },
}

impl WorkerObservationReceipt {
    pub(super) fn path_for(
        journal_path: &Path,
        worker: &ActivationWorkerIdentity,
    ) -> Result<PathBuf, String> {
        worker.validate_identity()?;
        let parent = journal_path
            .parent()
            .ok_or_else(|| "transaction journal path has no parent for worker observation".to_string())?;
        let journal_name = journal_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "transaction journal filename is not canonical UTF-8".to_string())?;
        let purpose = match worker.purpose {
            ActivationWorkerPurpose::ProfileTransition => "profile_transition",
            ActivationWorkerPurpose::Activation => "activation",
            ActivationWorkerPurpose::RecoveryProfileTransition => "recovery_profile_transition",
            ActivationWorkerPurpose::RecoveryActivation => "recovery_activation",
        };
        let boot_id = worker.boot_id.replace('-', "");
        Ok(parent.join(format!(
            "{journal_name}.worker-{purpose}-{}-{}-{boot_id}.json",
            worker.pid, worker.start_time_ticks
        )))
    }

    pub(super) fn from_status(
        worker: &ActivationWorkerIdentity,
        status: &std::process::ExitStatus,
        elapsed_ms: u64,
    ) -> Result<Self, String> {
        worker.validate_identity()?;
        let disposition = match status.code() {
            Some(code) => WorkerProcessDisposition::Exited { code },
            None => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    let signal = status
                        .signal()
                        .ok_or_else(|| "worker exit status has neither an exit code nor a signal".to_string())?;
                    WorkerProcessDisposition::Signaled { signal }
                }
                #[cfg(not(unix))]
                {
                    return Err("platform does not expose a worker termination signal".into());
                }
            }
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .filter(|value| *value <= MAX_SAFE_INTEGER);
        let receipt = Self {
            schema: OBSERVATION_SCHEMA.to_string(),
            version: OBSERVATION_VERSION,
            transaction_id: worker.transaction_id.clone(),
            purpose: worker.purpose,
            pid: worker.pid,
            boot_id: worker.boot_id.clone(),
            start_time_ticks: worker.start_time_ticks,
            worker_identity_digest: Self::worker_identity_digest(worker)?,
            observed_at_unix_ms: now_ms,
            elapsed_ms,
            disposition,
        };
        receipt.validate_against(worker)?;
        Ok(receipt)
    }

    pub(super) fn validate_against(
        &self,
        expected_worker: &ActivationWorkerIdentity,
    ) -> Result<(), String> {
        self.validate_shape()?;
        expected_worker.validate_identity()?;
        if self.schema != OBSERVATION_SCHEMA || self.version != OBSERVATION_VERSION {
            return Err("unsupported worker observation schema/version".into());
        }
        if self.transaction_id != expected_worker.transaction_id
            || self.purpose != expected_worker.purpose
            || self.pid != expected_worker.pid
            || self.boot_id != expected_worker.boot_id
            || self.start_time_ticks != expected_worker.start_time_ticks
        {
            return Err("worker observation does not bind the expected transaction/process identity".into());
        }
        if self.worker_identity_digest != Self::worker_identity_digest(expected_worker)? {
            return Err("worker observation digest does not bind the exact persisted worker identity".into());
        }
        if self.elapsed_ms > MAX_SAFE_INTEGER
            || self.observed_at_unix_ms.is_some_and(|value| value > MAX_SAFE_INTEGER)
        {
            return Err("worker observation time exceeds the interoperable safe-integer range".into());
        }
        match &self.disposition {
            WorkerProcessDisposition::Exited { .. } => {}
            WorkerProcessDisposition::Signaled { signal } if *signal > 0 => {}
            WorkerProcessDisposition::Signaled { .. } => {
                return Err("worker observation signal must be positive".into());
            }
        }
        Ok(())
    }

    pub(super) fn persist_atomic(&self, path: &Path) -> Result<(), String> {
        self.validate_shape()?;
        let parent = path
            .parent()
            .ok_or_else(|| "worker observation path has no parent".to_string())?;
        if !parent.is_dir() {
            return Err("worker observation parent is not an existing directory".into());
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "worker observation filename is not canonical UTF-8".to_string())?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let temporary_path = parent.join(format!(
            ".{filename}.{}.{}.tmp",
            std::process::id(),
            nonce
        ));
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("failed to serialize worker observation: {error}"))?;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut temporary = options
            .open(&temporary_path)
            .map_err(|error| format!("failed to create worker observation candidate: {error}"))?;

        if let Err(error) = temporary.write_all(&encoded).and_then(|_| temporary.sync_all()) {
            drop(temporary);
            let _ = fs::remove_file(&temporary_path);
            return Err(format!("failed to sync worker observation before publication: {error}"));
        }
        drop(temporary);

        // hard_link is an atomic no-clobber publication: an existing receipt is
        // never silently replaced by a later process with a reused filename.
        if let Err(error) = fs::hard_link(&temporary_path, path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(format!("worker observation publication failed without replacing an existing receipt: {error}"));
        }
        if let Err(error) = fs::remove_file(&temporary_path) {
            return Err(format!("worker observation is visible but temporary-link cleanup failed; durability is indeterminate: {error}"));
        }
        let parent_file = File::open(parent)
            .map_err(|error| format!("worker observation is visible but parent-directory sync could not start: {error}"))?;
        parent_file
            .sync_all()
            .map_err(|error| format!("worker observation is visible but parent-directory durability is indeterminate: {error}"))?;
        Ok(())
    }

    pub(super) fn load_for_worker(
        path: &Path,
        expected_worker: &ActivationWorkerIdentity,
    ) -> Result<Self, String> {
        let metadata = fs::metadata(path)
            .map_err(|error| format!("failed to inspect worker observation: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_OBSERVATION_BYTES {
            return Err("worker observation is not a regular file or exceeds the wire limit".into());
        }
        let mut file = File::open(path)
            .map_err(|error| format!("failed to open worker observation: {error}"))?;
        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_OBSERVATION_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|error| format!("failed to read worker observation: {error}"))?;
        if encoded.len() as u64 > MAX_OBSERVATION_BYTES {
            return Err("worker observation exceeds the wire limit".into());
        }
        let receipt: Self = serde_json::from_slice(&encoded)
            .map_err(|error| format!("worker observation is not valid JSON: {error}"))?;
        receipt.validate_against(expected_worker)?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.schema != OBSERVATION_SCHEMA || self.version != OBSERVATION_VERSION {
            return Err("unsupported worker observation schema/version".into());
        }
        if self.transaction_id.len() != 64
            || !self.transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("worker observation transaction id is not canonical lowercase hexadecimal".into());
        }
        if self.pid <= 1 || self.start_time_ticks == 0 {
            return Err("worker observation PID or start-time identity is invalid".into());
        }
        if self.boot_id.len() != 36
            || !self.boot_id.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                    || (!matches!(index, 8 | 13 | 18 | 23)
                        && byte.is_ascii_hexdigit()
                        && !byte.is_ascii_uppercase())
            })
        {
            return Err("worker observation boot id is not canonical lowercase UUID text".into());
        }
        if self.worker_identity_digest.len() != 64
            || !self.worker_identity_digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("worker observation identity digest is not canonical lowercase hexadecimal".into());
        }
        if self.elapsed_ms > MAX_SAFE_INTEGER
            || self.observed_at_unix_ms.is_some_and(|value| value > MAX_SAFE_INTEGER)
        {
            return Err("worker observation time exceeds the interoperable safe-integer range".into());
        }
        if let WorkerProcessDisposition::Signaled { signal } = &self.disposition {
            if *signal <= 0 {
                return Err("worker observation signal must be positive".into());
            }
        }
        Ok(())
    }

    fn worker_identity_digest(worker: &ActivationWorkerIdentity) -> Result<String, String> {
        let encoded = serde_json::to_vec(worker)
            .map_err(|error| format!("failed to serialize worker identity: {error}"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(OBSERVATION_DOMAIN);
        hasher.update(&encoded);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::action::config_transaction::activation_argv_digest;

    fn worker() -> ActivationWorkerIdentity {
        let executable = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixward-worker-gate/bin/nixward-worker-gate";
        let payload_executable = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-rebuild/bin/nixos-rebuild";
        let payload_args = vec!["switch".to_string()];
        let release_challenge_digest = "e".repeat(64);
        let mut gate_args = vec![
            "--nixward-worker-gate-v1".to_string(),
            payload_executable.to_string(),
            release_challenge_digest.clone(),
        ];
        gate_args.extend(payload_args.iter().cloned());
        ActivationWorkerIdentity {
            transaction_id: "d".repeat(64),
            purpose: ActivationWorkerPurpose::Activation,
            pid: 4242,
            boot_id: "00000000-0000-0000-0000-000000000000".into(),
            start_time_ticks: 13,
            executable: executable.into(),
            process_image: executable.into(),
            argv_digest: activation_argv_digest(executable, &gate_args),
            payload_executable: payload_executable.into(),
            payload_args: payload_args.clone(),
            release_challenge_digest,
            payload_argv_digest: activation_argv_digest(payload_executable, &payload_args),
            environment_digest: "f".repeat(64),
        }
    }

    #[test]
    fn worker_observation_round_trips_and_does_not_export_process_output() {
        let worker = worker();
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .status()
            .unwrap();
        let receipt = WorkerObservationReceipt::from_status(&worker, &status, 17).unwrap();
        let encoded = serde_json::to_string(&receipt).unwrap();
        assert!(!encoded.contains("stdout"));
        assert!(!encoded.contains("stderr"));
        assert!(!encoded.contains("secret-output"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transaction.json.worker-4242-13.json");
        receipt.persist_atomic(&path).unwrap();
        let loaded = WorkerObservationReceipt::load_for_worker(&path, &worker).unwrap();
        assert_eq!(loaded, receipt);
        assert!(loaded.validate_against(&worker).is_ok());
        assert!(
            receipt.persist_atomic(&path).is_err(),
            "an existing receipt must never be overwritten"
        );
    }

    #[test]
    fn worker_observation_rejects_receipt_rebinding_to_another_worker() {
        let worker = worker();
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .status()
            .unwrap();
        let receipt = WorkerObservationReceipt::from_status(&worker, &status, 1).unwrap();
        let mut changed_worker = worker.clone();
        changed_worker.payload_args.push("--different-target".into());
        assert!(receipt.validate_against(&changed_worker).is_err());
    }
}
