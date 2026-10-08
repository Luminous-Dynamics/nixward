// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only UEFI Secure Boot state evidence.
//!
//! Secure Boot policy state is intentionally separate from UKI identity and
//! signature validity. This module observes firmware state only.

use serde::{Deserialize, Serialize};
use std::path::Path;

const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const EFI_VARS_DIR: &str = "/sys/firmware/efi/efivars";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootState {
    Enabled,
    Disabled,
    SetupMode,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootEvidence {
    pub state: SecureBootState,
    pub secure_boot_variable: Option<bool>,
    pub setup_mode_variable: Option<bool>,
    pub observed_at_ms: Option<u64>,
    pub evidence_digest: Option<[u8; 32]>,
}

impl SecureBootEvidence {
    pub fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let preimage = serde_json::to_vec(&(
            self.state,
            self.secure_boot_variable,
            self.setup_mode_variable,
            observed_at_ms,
        ))
        .map_err(|error| format!("failed to serialize Secure Boot evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

pub fn parse_efi_boolean_payload(bytes: &[u8]) -> Result<bool, String> {
    if bytes.len() != 5 {
        return Err("EFI boolean variable must contain 4 attributes bytes plus one data byte".into());
    }
    match bytes[4] {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(format!("EFI boolean variable contains unsupported value {value}")),
    }
}

pub fn derive_secure_boot_state(
    secure_boot: Option<bool>,
    setup_mode: Option<bool>,
) -> SecureBootState {
    match (secure_boot, setup_mode) {
        (Some(true), Some(false)) => SecureBootState::Enabled,
        (Some(false), Some(true)) | (Some(false), Some(false)) => SecureBootState::Disabled,
        (Some(true), Some(true)) => SecureBootState::SetupMode,
        _ => SecureBootState::Unknown,
    }
}

pub fn build_secure_boot_evidence(
    secure_boot: Option<bool>,
    setup_mode: Option<bool>,
) -> SecureBootEvidence {
    SecureBootEvidence {
        state: derive_secure_boot_state(secure_boot, setup_mode),
        secure_boot_variable: secure_boot,
        setup_mode_variable: setup_mode,
        observed_at_ms: None,
        evidence_digest: None,
    }
}

#[cfg(feature = "native")]
pub fn observe_secure_boot() -> Result<SecureBootEvidence, String> {
    let secure_boot = read_global_efi_bool("SecureBoot")?;
    let setup_mode = read_global_efi_bool("SetupMode")?;
    let evidence = build_secure_boot_evidence(secure_boot, setup_mode);
    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock could not produce observation timestamp: {error}"))?
        .as_millis() as u64;
    evidence
        .with_observation_metadata(observed_at_ms)
        .map_err(|error| format!("failed to digest Secure Boot observation: {error}"))
}

#[cfg(feature = "native")]
fn read_global_efi_bool(name: &str) -> Result<Option<bool>, String> {
    let prefix = format!("{name}-{EFI_GLOBAL_GUID}");
    let mut matches = Vec::new();
    for item in std::fs::read_dir(EFI_VARS_DIR)
        .map_err(|error| format!("failed to read EFI variable directory: {error}"))?
    {
        let item = item.map_err(|error| format!("failed to enumerate EFI variables: {error}"))?;
        let file_name = item.file_name();
        let Some(file_name) = file_name.to_str() else { continue; };
        if file_name == prefix {
            matches.push(item.path());
        }
    }
    match matches.as_slice() {
        [] => Ok(None),
        [path] => {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|error| format!("failed to inspect EFI variable {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(format!("EFI variable {} is not a regular non-symlink file", path.display()));
            }
            let bytes = std::fs::read(path)
                .map_err(|error| format!("failed to read EFI variable {}: {error}", path.display()))?;
            parse_efi_boolean_payload(&bytes).map(Some)
        }
        _ => Err(format!("EFI variable {name} has multiple global-GUID instances")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_efi_boolean_payload_exactly() {
        assert!(parse_efi_boolean_payload(&[0, 0, 0, 7, 1]).unwrap());
        assert!(!parse_efi_boolean_payload(&[0, 0, 0, 7, 0]).unwrap());
    }

    #[test]
    fn rejects_extra_or_invalid_efi_boolean_bytes() {
        assert!(parse_efi_boolean_payload(&[0, 0, 0, 7]).is_err());
        assert!(parse_efi_boolean_payload(&[0, 0, 0, 7, 2]).is_err());
        assert!(parse_efi_boolean_payload(&[0, 0, 0, 7, 1, 0]).is_err());
    }

    #[test]
    fn derives_secure_boot_state_fail_closed() {
        assert_eq!(
            derive_secure_boot_state(Some(true), Some(false)),
            SecureBootState::Enabled
        );
        assert_eq!(
            derive_secure_boot_state(Some(false), Some(true)),
            SecureBootState::Disabled
        );
        assert_eq!(
            derive_secure_boot_state(Some(true), Some(true)),
            SecureBootState::SetupMode
        );
        assert_eq!(
            derive_secure_boot_state(None, Some(false)),
            SecureBootState::Unknown
        );
    }

    #[test]
    fn evidence_digest_binds_secure_boot_state() {
        let first = build_secure_boot_evidence(Some(true), Some(false))
            .with_observation_metadata(100)
            .expect("evidence");
        let second = build_secure_boot_evidence(Some(false), Some(false))
            .with_observation_metadata(100)
            .expect("evidence");
        assert_ne!(first.evidence_digest, second.evidence_digest);
    }
}