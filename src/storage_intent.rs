// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed, evidence-bound storage intent for sovereign NixOS births.
//!
//! V27 deliberately keeps storage authority small.  The browser may suggest a
//! layout, but only the trusted relay may bind that intent to a locally
//! observed stable `/dev/disk/by-id/...` identity.  The resulting plan renders
//! one canonical Disko module and a secret-free JSON receipt.  Disk encryption
//! key *material* is never embedded in Nix; only a short-lived root-owned key
//! file path may appear in the plan.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const STORAGE_PLAN_SCHEMA_VERSION: u32 = 1;
pub const AUTHORITATIVE_STORAGE_STATUS: &str = "authoritative-disko-v1";
pub const LUKS_REALIZATION_KEY_PATH: &str = "/run/symthaea-install/luks.key";
const STORAGE_PLAN_DOMAIN: &[u8] = b"symthaea-storage-plan-v1\0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageIntentError {
    #[error("unsupported authoritative storage layout {0:?}")]
    UnsupportedLayout(String),
    #[error("stable disk identity must use /dev/disk/by-id/: {0:?}")]
    UnstableDiskIdentity(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StorageLayout {
    SingleBtrfs,
    SingleLuksBtrfs,
}

impl StorageLayout {
    pub fn from_install_layout(layout: &str) -> Result<Self, StorageIntentError> {
        match layout {
            "single" => Ok(Self::SingleBtrfs),
            "single-luks" => Ok(Self::SingleLuksBtrfs),
            other => Err(StorageIntentError::UnsupportedLayout(other.to_string())),
        }
    }

    pub fn as_install_layout(self) -> &'static str {
        match self {
            Self::SingleBtrfs => "single",
            Self::SingleLuksBtrfs => "single-luks",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StableDiskIdentity {
    /// Stable Linux device identity. Never `/dev/sda`, `/dev/nvme0n1`, etc.
    pub by_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wwn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub size: String,
}

impl StableDiskIdentity {
    pub fn validate(&self) -> Result<(), StorageIntentError> {
        let path = self.by_id.trim();
        let safe = path.starts_with("/dev/disk/by-id/")
            && !path.contains("-part")
            && !path.contains('\n')
            && !path.contains('\r')
            && !path.contains('\0');
        if !safe {
            return Err(StorageIntentError::UnstableDiskIdentity(self.by_id.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageIntent {
    pub layout: StorageLayout,
    pub primary: StableDiskIdentity,
}

impl StorageIntent {
    pub fn validate(&self) -> Result<(), StorageIntentError> {
        self.primary.validate()?;
        Ok(())
    }

    pub fn into_plan(self) -> Result<StoragePlan, StorageIntentError> {
        self.validate()?;
        let disko_module = render_disko_module(&self);
        let canonical =
            serde_json::to_vec(&self).expect("StorageIntent serialization is infallible");
        let mut hasher = blake3::Hasher::new();
        hasher.update(STORAGE_PLAN_DOMAIN);
        hasher.update(&(canonical.len() as u64).to_le_bytes());
        hasher.update(&canonical);
        hasher.update(&(disko_module.len() as u64).to_le_bytes());
        hasher.update(disko_module.as_bytes());
        let plan_digest_blake3 = hasher.finalize().to_hex().to_string();

        Ok(StoragePlan {
            schema_version: STORAGE_PLAN_SCHEMA_VERSION,
            kind: "symthaea-storage-plan-v1".to_string(),
            realization: AUTHORITATIVE_STORAGE_STATUS.to_string(),
            intent: self,
            disko_module,
            plan_digest_blake3,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoragePlan {
    pub schema_version: u32,
    pub kind: String,
    pub realization: String,
    pub intent: StorageIntent,
    /// Canonical Disko module authorized by this plan.
    #[serde(skip_serializing)]
    pub disko_module: String,
    pub plan_digest_blake3: String,
}

impl StoragePlan {
    pub fn receipt_json(&self) -> String {
        // Deliberately serialize a public projection. The Disko source is
        // already hashed into `plan_digest_blake3` and lives separately as
        // `disko/default.nix`.
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{\"error\":\"storage plan serialization failed\"}".into())
            + "\n"
    }
}

fn nix_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        // Prevent Nix interpolation inside a quoted literal.
        .replace("${", "\\${");
    format!("\"{escaped}\"")
}

fn btrfs_content() -> &'static str {
    r#"{
                type = "btrfs";
                extraArgs = [ "-f" ];
                subvolumes = {
                  "@" = {
                    mountpoint = "/";
                    mountOptions = [ "compress=zstd:3" "noatime" ];
                  };
                  "@home" = {
                    mountpoint = "/home";
                    mountOptions = [ "compress=zstd:3" "noatime" ];
                  };
                  "@nix" = {
                    mountpoint = "/nix";
                    mountOptions = [ "compress=zstd:3" "noatime" ];
                  };
                  "@log" = {
                    mountpoint = "/var/log";
                    mountOptions = [ "compress=zstd:3" "noatime" ];
                  };
                  "@snapshots" = {
                    mountpoint = "/.snapshots";
                    mountOptions = [ "compress=zstd:3" "noatime" ];
                  };
                };
              }"#
}

fn render_disko_module(intent: &StorageIntent) -> String {
    let device = nix_string(&intent.primary.by_id);
    let root_content = match intent.layout {
        StorageLayout::SingleBtrfs => btrfs_content().to_string(),
        StorageLayout::SingleLuksBtrfs => format!(
            r#"{{
              type = "luks";
              name = "cryptroot";
              passwordFile = {key};
              settings = {{
                allowDiscards = false;
              }};
              content = {btrfs};
            }}"#,
            key = nix_string(LUKS_REALIZATION_KEY_PATH),
            btrfs = btrfs_content(),
        ),
    };

    format!(
        r#"# Generated by Nixward from typed StorageIntent.
# DO NOT hand-edit during installation: the content is bound into
# generated/storage-plan.json and the Spore preflight receipt.
{{ ... }}:
{{
  disko.devices.disk.primary = {{
    type = "disk";
    device = {device};
    content = {{
      type = "gpt";
      partitions = {{
        # Keep a tiny BIOS boot partition even on UEFI systems. This makes the
        # physical layout portable across firmware modes without changing the
        # root partition identity.
        BIOS = {{
          type = "EF02";
          size = "1M";
          priority = 1;
        }};
        ESP = {{
          type = "EF00";
          size = "1G";
          priority = 2;
          content = {{
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          }};
        }};
        root = {{
          size = "100%";
          priority = 3;
          content = {root_content};
        }};
      }};
    }};
  }};
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk() -> StableDiskIdentity {
        StableDiskIdentity {
            by_id: "/dev/disk/by-id/nvme-Samsung_SSD_990_PRO_TEST".into(),
            model: "Samsung SSD 990 PRO".into(),
            serial: "TEST".into(),
            wwn: "eui.test".into(),
            size: "2T".into(),
        }
    }

    #[test]
    fn rejects_kernel_enumeration_names() {
        let mut bad = disk();
        bad.by_id = "/dev/nvme0n1".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn plain_plan_never_contains_a_secret_path() {
        let plan = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: disk(),
        }
        .into_plan()
        .unwrap();
        assert!(plan.disko_module.contains("/dev/disk/by-id/"));
        assert!(!plan.disko_module.contains("passwordFile"));
        assert_eq!(plan.realization, AUTHORITATIVE_STORAGE_STATUS);
    }

    #[test]
    fn luks_plan_binds_only_the_ephemeral_key_path() {
        let plan = StorageIntent {
            layout: StorageLayout::SingleLuksBtrfs,
            primary: disk(),
        }
        .into_plan()
        .unwrap();
        assert!(plan.disko_module.contains("passwordFile"));
        assert!(plan.disko_module.contains(LUKS_REALIZATION_KEY_PATH));
        assert!(!plan.receipt_json().contains("disko_module"));
    }

    #[test]
    fn plan_digest_changes_with_disk_identity() {
        let a = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: disk(),
        }
        .into_plan()
        .unwrap();
        let mut second = disk();
        second.by_id.push_str("-other");
        let b = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: second,
        }
        .into_plan()
        .unwrap();
        assert_ne!(a.plan_digest_blake3, b.plan_digest_blake3);
    }
}
