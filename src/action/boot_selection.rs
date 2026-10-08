// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only boot-selection evidence primitives.
//!
//! This module intentionally separates boot selection from runtime activation.
//! It contains deterministic parsers/resolvers only; host observation is a
//! separate boundary that must supply authoritative loader state.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use super::uki_evidence::{inspect_uki_file, resolve_boot_artifact_path};
#[cfg(feature = "native")]
use std::process::Command;

/// Supported bootloader evidence families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootloaderFamily {
    SystemdBoot,
    Grub,
    Unknown,
}

/// Which authoritative selection source determined the effective entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionKind {
    OneShot,
    PersistentDefault,
    GeneratedDefault,
    Unknown,
}

/// Boot-counting state associated with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootCountState {
    Good,
    Indeterminate,
    Bad,
    NotTracked,
    Unknown,
}

/// Exact metadata parsed from a Type #1 BLS entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsEntry {
    pub entry_id: String,
    pub title: Option<String>,
    pub version: Option<String>,
    pub machine_id: Option<String>,
    pub linux: Option<String>,
    pub initrd: Vec<String>,
    pub options: Option<String>,
    pub efi: Option<String>,
    pub uki: Option<String>,
    pub boot_count_state: BootCountState,
    pub tries_left: Option<u32>,
    pub tries_done: Option<u32>,
}

/// A read-only effective-selection observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSelectionEvidence {
    pub bootloader_family: BootloaderFamily,
    pub selection_kind: SelectionKind,
    pub selected_entry_id: Option<String>,
    pub selected_entry_source: String,
    pub candidate_closure: Option<String>,
    pub boot_count_state: BootCountState,
    /// Exact selected EFI image path when the boot subject is a Type #2 UKI.
    pub selected_image_path: Option<String>,
    /// Exact BLAKE3 identity of the selected EFI image when observed.
    pub selected_image_blake3: Option<[u8; 32]>,
    /// Host observation timestamp in Unix milliseconds. Pure resolvers leave this
    /// unset; host observers attach it at the authoritative observation boundary.
    pub observed_at_ms: Option<u64>,
    /// BLAKE3 digest over the complete observation excluding this digest field.
    pub evidence_digest: Option<[u8; 32]>,
}

impl BootSelectionEvidence {
    /// Attach immutable observation metadata and derive its evidence digest.
    pub fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let preimage = serde_json::to_vec(&(
            self.bootloader_family,
            self.selection_kind,
            &self.selected_entry_id,
            &self.selected_entry_source,
            &self.candidate_closure,
            self.boot_count_state,
            &self.selected_image_path,
            &self.selected_image_blake3,
            observed_at_ms,
        ))
        .map_err(|error| format!("failed to serialize boot selection evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

/// Explicitly unqualified evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownBootSelection {
    pub bootloader_family: BootloaderFamily,
    pub reason: String,
}

/// Parse a UAPI.1 Type #1 BLS entry.
///
/// Unknown keys are ignored deliberately: they must not become accidental
/// authorization inputs. Required boot payload fields are preserved exactly.
pub fn parse_bls_entry(entry_id: &str, text: &str) -> Result<BlsEntry, String> {
    if entry_id.is_empty() {
        return Err("BLS entry identifier must not be empty".into());
    }

    let (boot_count_state, tries_left, tries_done) = parse_boot_count(entry_id)?;

    let mut title = None;
    let mut version = None;
    let mut machine_id = None;
    let mut linux = None;
    let mut initrd = Vec::new();
    let mut options = None;
    let mut efi = None;
    let mut uki = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once(|c: char| c.is_ascii_whitespace()) else {
            continue;
        };
        let value = value.trim();
        match key {
            "title" => title = Some(value.to_string()),
            "version" => version = Some(value.to_string()),
            "machine-id" => machine_id = Some(value.to_string()),
            "linux" => linux = Some(value.to_string()),
            "initrd" => initrd.push(value.to_string()),
            "options" => options = Some(value.to_string()),
            "efi" => efi = Some(value.to_string()),
            "uki" => uki = Some(value.to_string()),
            _ => {}
        }
    }

    if linux.is_none() && efi.is_none() && uki.is_none() {
        return Err("BLS entry has no linux, efi, or uki payload".into());
    }

    Ok(BlsEntry {
        entry_id: entry_id.to_string(),
        title,
        version,
        machine_id,
        linux,
        initrd,
        options,
        efi,
        uki,
        boot_count_state,
        tries_left,
        tries_done,
    })
}

/// Resolve systemd-boot effective selection from already-read authoritative
/// loader state and a set of exact BLS entries.
///
/// A one-shot selection takes precedence over the persistent default. Wildcard
/// defaults are intentionally not resolved here because they are a selection
/// rule, not an observed exact entry identity.
pub fn resolve_systemd_boot_selection(
    one_shot_entry: Option<&str>,
    persistent_default: Option<&str>,
    entries: &BTreeMap<String, BlsEntry>,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    resolve_systemd_boot_selection_with_source(
        one_shot_entry,
        persistent_default,
        entries,
        "efi:LoaderEntryDefault/loader.conf",
    )
}

fn resolve_systemd_boot_selection_with_source(
    one_shot_entry: Option<&str>,
    persistent_default: Option<&str>,
    entries: &BTreeMap<String, BlsEntry>,
    persistent_source: &str,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let (selection_kind, selected, source) = match one_shot_entry {
        Some(id) if !id.is_empty() => (SelectionKind::OneShot, id, "efi:LoaderEntryOneShot"),
        _ => match persistent_default {
            Some(id) if !id.is_empty() && !contains_selection_pattern(id) => {
                (SelectionKind::PersistentDefault, id, persistent_source)
            }
            Some(_) => {
                return Err(UnknownBootSelection {
                    bootloader_family: BootloaderFamily::SystemdBoot,
                    reason: "persistent default is a pattern rather than an exact selected entry"
                        .into(),
                })
            }
            None => {
                return Err(UnknownBootSelection {
                    bootloader_family: BootloaderFamily::SystemdBoot,
                    reason: "neither one-shot nor exact persistent default selection is observable"
                        .into(),
                })
            }
        },
    };

    let entry_key = resolve_bls_entry_key(selected, entries).ok_or_else(|| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason: format!("selected entry {selected} is not present as an exact Type #1 BLS entry"),
    })?;
    let entry = entries.get(&entry_key).expect("resolved BLS entry key");

    Ok(BootSelectionEvidence {
        bootloader_family: BootloaderFamily::SystemdBoot,
        selection_kind,
        selected_entry_id: Some(entry.entry_id.clone()),
        selected_entry_source: source.into(),
        candidate_closure: exact_store_path_from_entry(entry),
        boot_count_state: entry.boot_count_state,
        observed_at_ms: None,
        evidence_digest: None,
    })
}

fn resolve_bls_entry_key(selected: &str, entries: &BTreeMap<String, BlsEntry>) -> Option<String> {
    if let Some(entry) = entries.get(selected) {
        return Some(entry.entry_id.clone());
    }
    if selected.ends_with(".conf") || selected.ends_with(".efi") {
        return None;
    }
    let conf = format!("{selected}.conf");
    match entries.get(&conf) {
        Some(entry) => Some(entry.entry_id.clone()),
        None => None,
    }
}

/// Parse the exact `default` selector from systemd-boot's loader.conf.
/// Patterns and magic selectors are preserved and are later rejected by the
/// exact-selection resolver rather than being guessed.
fn parse_systemd_loader_default(text: &str) -> Option<String> {
    text.lines().find_map(|raw_line| {
        let line = raw_line.trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("default") {
            return None;
        }
        let selector = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        Some(selector.to_string())
    })
}

/// Require an observed boot selection to bind to the exact authorized system closure.
///
/// This is deliberately separate from selection resolution: knowing which entry
/// the bootloader selects does not prove that the entry denotes the authorized
/// NixOS closure.
pub fn require_candidate_binding(
    evidence: &BootSelectionEvidence,
    expected_candidate_closure: &str,
) -> Result<(), UnknownBootSelection> {
    if !super::execution_intent::is_valid_nix_store_path(expected_candidate_closure)
        || !expected_candidate_closure.contains("-nixos-system-")
    {
        return Err(UnknownBootSelection {
            bootloader_family: evidence.bootloader_family,
            reason: "authorized candidate is not an exact NixOS system store closure".into(),
        });
    }

    match evidence.candidate_closure.as_deref() {
        Some(observed) if observed == expected_candidate_closure => Ok(()),
        Some(observed) => Err(UnknownBootSelection {
            bootloader_family: evidence.bootloader_family,
            reason: format!(
                "selected boot entry resolves to {}, not the authorized candidate {}",
                observed, expected_candidate_closure
            ),
        }),
        None => Err(UnknownBootSelection {
            bootloader_family: evidence.bootloader_family,
            reason: "selected boot entry does not expose an exact NixOS system closure binding".into(),
        }),
    }
}
/// Read-only systemd-boot observer.
///
/// The observer uses the authoritative current-loader path, UAPI EFI selection
/// variables, and the BLS entry directory discovered by bootctl. It never
/// changes loader state. Unsupported or incomplete observations become
/// explicit Unknown results.
#[cfg(feature = "native")]
pub fn observe_systemd_boot() -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let loader_path = run_read_only(["--print-loader-path"])?;
    observe_systemd_boot_from_loader(loader_path.trim())
}

#[cfg(feature = "native")]
fn observe_systemd_boot_from_loader(loader_path: &str) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let loader_name = Path::new(loader_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !loader_name.to_ascii_lowercase().starts_with("systemd-boot") {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Unknown,
            reason: format!("current EFI loader is not systemd-boot: {loader_path}"),
        });
    }

    let boot_path = PathBuf::from(run_read_only(["-x"])?.trim());
    if !boot_path.is_absolute() {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::SystemdBoot,
            reason: "bootctl -x returned a non-absolute BLS root".into(),
        });
    }
    let entries_path = boot_path.join("loader/entries");
    let entries = read_bls_entries(&entries_path).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;

    let one_shot = read_efi_variable("LoaderEntryOneShot").map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;
    let persistent_default = read_efi_variable("LoaderEntryDefault").map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;
    let (persistent_default, persistent_source) = match persistent_default {
        Some(value) => (Some(value), "efi:LoaderEntryDefault"),
        None => {
            let loader_conf = std::fs::read_to_string(boot_path.join("loader/loader.conf"))
                .map_err(|error| UnknownBootSelection {
                    bootloader_family: BootloaderFamily::SystemdBoot,
                    reason: format!("failed to read systemd-boot loader.conf: {error}"),
                })?;
            (
                parse_systemd_loader_default(&loader_conf),
                "loader.conf:default",
            )
        }
    };

    let (selected, selection_kind, selection_source) = systemd_effective_selector(
        one_shot.as_deref(),
        persistent_default.as_deref(),
        persistent_source,
    )?;

    let evidence = match resolve_systemd_boot_selection_with_source(
        one_shot.as_deref(),
        persistent_default.as_deref(),
        &entries,
        persistent_source,
    ) {
        Ok(evidence) => evidence,
        Err(_selection_error) if is_uki_selector(selected) => {
            observe_systemd_uki_from_selection(
                &boot_path,
                selected,
                selection_kind,
                selection_source,
            )?
        }
        Err(selection_error) => return Err(selection_error),
    };
    if evidence.boot_count_state == BootCountState::Bad {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::SystemdBoot,
            reason: "selected systemd-boot entry is marked bad by boot-counting state".into(),
        });
    }
    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| UnknownBootSelection {
            bootloader_family: BootloaderFamily::SystemdBoot,
            reason: format!("system clock could not produce an observation timestamp: {error}"),
        })?
        .as_millis() as u64;
    evidence
        .with_observation_metadata(observed_at_ms)
        .map_err(|reason| UnknownBootSelection {
            bootloader_family: BootloaderFamily::SystemdBoot,
            reason,
        })
}

/// Observe GRUB selection and keep candidate qualification separate.
#[cfg(feature = "native")]
pub fn observe_grub() -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let loader_path = run_read_only(["--print-loader-path"])?;
    observe_grub_from_loader(loader_path.trim())
}

#[cfg(feature = "native")]
fn observe_grub_from_loader(loader_path: &str) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let loader_name = Path::new(loader_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !loader_name.contains("grub") {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Unknown,
            reason: format!("current EFI loader is not GRUB: {loader_path}"),
        });
    }

    let preferred_root = run_read_only(["-x"])
        .ok()
        .map(|value| PathBuf::from(value.trim()))
        .filter(|path| path.is_absolute());
    let root = discover_grub_root(preferred_root.as_deref()).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason,
    })?;
    let config_path = root.join("grub.cfg");
    let env_path = root.join("grubenv");
    let config = std::fs::read_to_string(&config_path).map_err(|error| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason: format!("failed to read generated GRUB config {}: {error}", config_path.display()),
    })?;
    let environment_text = run_grub_read_only(&env_path).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason,
    })?;
    let environment = parse_grub_environment(&environment_text);
    let generated_default = parse_grub_config_default(&config);
    let entries = parse_grub_config_entries(&config).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason,
    })?;
    let evidence = resolve_grub_selection(&environment, generated_default.as_deref(), &entries)?;
    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: format!("system clock could not produce an observation timestamp: {error}"),
        })?
        .as_millis() as u64;
    evidence.with_observation_metadata(observed_at_ms).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason,
    })
}

#[cfg(feature = "native")]
pub fn observe_grub_for_candidate(
    expected_candidate_closure: &str,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let evidence = observe_grub()?;
    require_candidate_binding(&evidence, expected_candidate_closure)?;
    Ok(evidence)
}

#[cfg(feature = "native")]
pub fn observe_boot_selection() -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let loader_path = run_read_only(["--print-loader-path"])?;
    let loader_path = loader_path.trim();
    let loader_name = Path::new(loader_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if loader_name.starts_with("systemd-boot") {
        observe_systemd_boot_from_loader(loader_path)
    } else if loader_name.contains("grub") {
        observe_grub_from_loader(loader_path)
    } else {
        Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Unknown,
            reason: format!("unsupported current EFI bootloader: {loader_path}"),
        })
    }
}

#[cfg(feature = "native")]
pub fn observe_boot_selection_for_candidate(
    expected_candidate_closure: &str,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let evidence = observe_boot_selection()?;
    require_candidate_binding(&evidence, expected_candidate_closure)?;
    Ok(evidence)
}

#[cfg(feature = "native")]
fn candidate_grub_roots(preferred_root: Option<&Path>) -> Vec<PathBuf> {
    let defaults = [
        PathBuf::from("/boot/grub"),
        PathBuf::from("/boot/efi/grub"),
        PathBuf::from("/efi/grub"),
    ];
    let mut candidates = Vec::new();
    if let Some(preferred) = preferred_root {
        candidates.push(preferred.to_path_buf());
    }
    for candidate in defaults {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

#[cfg(feature = "native")]
fn discover_grub_root(preferred_root: Option<&Path>) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    for root in candidate_grub_roots(preferred_root) {
        match std::fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("refusing symlinked GRUB root {}", root.display()));
            }
            Ok(metadata) if !metadata.file_type().is_dir() => continue,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!("failed to inspect GRUB root {}: {error}", root.display()));
            }
        }
        let cfg = root.join("grub.cfg");
        let env = root.join("grubenv");
        if regular_file(&cfg)? && regular_file(&env)? {
            matches.push(root);
        }
    }
    match matches.as_slice() {
        [root] => Ok(root.clone()),
        [] => Err("no supported NixOS GRUB config/environment pair was found".into()),
        _ => Err("multiple GRUB config/environment pairs were found; refusing ambiguous observation".into()),
    }
}

#[cfg(feature = "native")]
fn regular_file(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!("refusing symlinked bootloader state {}", path.display())),
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect bootloader state {}: {error}", path.display())),
    }
}

#[cfg(feature = "native")]
fn run_grub_read_only(env_path: &Path) -> Result<String, String> {
    let output = Command::new("grub-editenv")
        .args([env_path.as_os_str(), std::ffi::OsStr::new("list")])
        .output()
        .map_err(|error| format!("failed to execute read-only grub-editenv list: {error}"))?;
    if !output.status.success() {
        return Err(format!("grub-editenv list failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("grub-editenv produced invalid UTF-8: {error}"))
}

fn systemd_effective_selector(
    one_shot_entry: Option<&str>,
    persistent_default: Option<&str>,
    persistent_source: &str,
) -> Result<(&str, SelectionKind, &str), UnknownBootSelection> {
    match one_shot_entry {
        Some(id) if !id.is_empty() => Ok((id, SelectionKind::OneShot, "efi:LoaderEntryOneShot")),
        _ => match persistent_default {
            Some(id) if !id.is_empty() && !contains_selection_pattern(id) => {
                Ok((id, SelectionKind::PersistentDefault, persistent_source))
            }
            Some(_) => Err(UnknownBootSelection {
                bootloader_family: BootloaderFamily::SystemdBoot,
                reason: "persistent default is a pattern or otherwise non-exact selector".into(),
            }),
            None => Err(UnknownBootSelection {
                bootloader_family: BootloaderFamily::SystemdBoot,
                reason: "no exact systemd-boot default selector is observable".into(),
            }),
        },
    }
}

fn is_uki_selector(selector: &str) -> bool {
    selector.ends_with(".efi")
        && !selector.contains('/')
        && !selector.contains('\\')
        && !selector.contains("..")
}

#[cfg(feature = "native")]
fn observe_systemd_uki_from_selection(
    boot_path: &Path,
    selected: &str,
    selection_kind: SelectionKind,
    selection_source: &str,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let uki_path = resolve_boot_artifact_path(
        boot_path,
        &format!("/EFI/Linux/{selected}"),
    )
    .map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;
    let uki = inspect_uki_file(&uki_path).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;
    let (boot_count_state, _, _) = parse_boot_count(selected).map_err(|reason| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason,
    })?;
    if boot_count_state == BootCountState::Bad {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::SystemdBoot,
            reason: "selected UKI is marked bad by boot-counting state".into(),
        });
    }
    Ok(BootSelectionEvidence {
        bootloader_family: BootloaderFamily::SystemdBoot,
        selection_kind,
        selected_entry_id: Some(selected.to_string()),
        selected_entry_source: selection_source.to_string(),
        candidate_closure: uki.system_closure,
        boot_count_state,
        selected_image_path: Some(uki_path.display().to_string()),
        selected_image_blake3: Some(uki.image_blake3),
        observed_at_ms: None,
        evidence_digest: None,
    })
}

/// Observe systemd-boot selection and require an exact authorized candidate binding.
#[cfg(feature = "native")]
pub fn observe_systemd_boot_for_candidate(
    expected_candidate_closure: &str,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    let evidence = observe_systemd_boot()?;
    require_candidate_binding(&evidence, expected_candidate_closure)?;
    Ok(evidence)
}

#[cfg(feature = "native")]
fn run_read_only<const N: usize>(args: [&str; N]) -> Result<String, UnknownBootSelection> {
    let output = Command::new("bootctl")
        .args(args)
        .output()
        .map_err(|error| UnknownBootSelection {
            bootloader_family: BootloaderFamily::Unknown,
            reason: format!("failed to execute bootctl read-only query: {error}"),
        })?;
    if !output.status.success() {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Unknown,
            reason: format!(
                "bootctl read-only query failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    String::from_utf8(output.stdout).map_err(|error| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Unknown,
        reason: format!("bootctl produced invalid UTF-8: {error}"),
    })
}

#[cfg(feature = "native")]
fn read_bls_entries(entries_path: &Path) -> Result<BTreeMap<String, BlsEntry>, String> {
    let root_metadata = std::fs::symlink_metadata(entries_path)
        .map_err(|error| format!("failed to inspect BLS entry directory {}: {error}", entries_path.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        return Err(format!(
            "BLS entry directory {} is not a regular non-symlink directory",
            entries_path.display()
        ));
    }
    let mut entries = BTreeMap::new();
    let directory = std::fs::read_dir(entries_path).map_err(|error| {
        format!("failed to read authoritative BLS entry directory {}: {error}", entries_path.display())
    })?;
    for item in directory {
        let item = item.map_err(|error| format!("failed to enumerate BLS entry directory: {error}"))?;
        let path = item.path();
        if path.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect BLS entry {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!(
                "BLS entry {} is not a regular non-symlink file",
                path.display()
            ));
        }
        let id = path
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or_else(|| format!("BLS entry filename is not valid UTF-8: {}", path.display()))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read BLS entry {}: {error}", path.display()))?;
        let entry = parse_bls_entry(id, &text)?;
        entries.insert(id.to_string(), entry);
    }
    if entries.is_empty() {
        return Err(format!("no Type #1 BLS entries found in {}", entries_path.display()));
    }
    Ok(entries)
}

#[cfg(feature = "native")]
fn read_efi_variable(name: &str) -> Result<Option<String>, String> {
    let dir = Path::new("/sys/firmware/efi/efivars");
    let prefix = format!("{}-", name);
    let mut matches = Vec::new();
    for item in std::fs::read_dir(dir)
        .map_err(|error| format!("failed to read EFI variable directory: {error}"))?
    {
        let item = item.map_err(|error| format!("failed to enumerate EFI variables: {error}"))?;
        let file_name = item.file_name();
        let Some(file_name) = file_name.to_str() else { continue; };
        if file_name.starts_with(&prefix) {
            matches.push(item.path());
        }
    }
    if matches.len() > 1 {
        return Err(format!("EFI variable {name} has multiple vendor instances"));
    }
    let Some(path) = matches.into_iter().next() else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("failed to read EFI variable {}: {error}", path.display()))?;
    decode_efivar_string(&bytes).map(Some)
}

#[cfg(feature = "native")]
fn decode_efivar_string(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 4 || (bytes.len() - 4) % 2 != 0 {
        return Err("EFI variable payload is not a valid UTF-16LE string".into());
    }
    let mut units = Vec::new();
    let mut terminated = false;
    for chunk in bytes[4..].chunks_exact(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            terminated = true;
            break;
        }
        units.push(value);
    }
    if !terminated {
        return Err("EFI variable UTF-16 payload is not NUL terminated".into());
    }
    String::from_utf16(&units).map_err(|error| format!("EFI variable UTF-16 decoding failed: {error}"))
}

/// Parse GRUB environment variables used by NixOS-generated configuration.
pub fn parse_grub_environment(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim_matches(|c: char| c == '\'' || c == '"').to_string()))
        })
        .collect()
}

/// Parse NixOS-generated GRUB menu entries from read-only grub.cfg text.
///
/// NixOS emits a menuentry title and a linux command whose init= argument
/// points at the exact system closure. Titles are accepted only as lookup keys
/// within this one observed config and duplicate titles fail closed.
pub fn parse_grub_config_entries(text: &str) -> Result<BTreeMap<String, BlsEntry>, String> {
    let mut entries = BTreeMap::new();
    let mut submenu_stack: Vec<String> = Vec::new();
    let mut current: Option<(String, String, String, Vec<String>, usize)> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if current.is_none() && line.starts_with("submenu ") {
            let title = parse_grub_menuentry_title(line.strip_prefix("submenu ").unwrap_or(line))?;
            submenu_stack.push(title);
            continue;
        }

        if current.is_none() && line.starts_with("menuentry ") {
            let title = parse_grub_menuentry_title(line)?;
            let entry_id = if submenu_stack.is_empty() {
                title.clone()
            } else {
                format!("{} > {}", submenu_stack.join(" > "), title)
            };
            let depth = line.matches('{').count().saturating_sub(line.matches('}').count());
            if depth == 0 {
                return Err("GRUB menuentry has no opening block".into());
            }
            current = Some((entry_id, title, String::new(), Vec::new(), depth));
            continue;
        }

        if let Some((entry_id, title, linux_line, initrds, depth)) = current.as_mut() {
            if line.starts_with("linux ") || line.starts_with("linuxefi ") || line.starts_with("multiboot ") {
                *linux_line = line.to_string();
            } else if line.starts_with("initrd ") || line.starts_with("initrdefi ") {
                initrds.push(line.to_string());
            }

            let opened = line.matches('{').count();
            let closed = line.matches('}').count();
            *depth = depth
                .checked_add(opened)
                .ok_or_else(|| "GRUB menuentry nesting depth overflowed".to_string())?;
            if closed > *depth {
                return Err("GRUB menuentry has unbalanced closing braces".into());
            }
            *depth -= closed;

            if *depth == 0 {
                let (entry_id, title, linux_line, initrds, _) = current.take().expect("entry state");
                let (linux, options) = if linux_line.is_empty() {
                    (None, String::new())
                } else {
                    parse_grub_linux_line(&linux_line)?
                };
                let entry = BlsEntry {
                    entry_id: entry_id.clone(),
                    title: Some(title),
                    version: None,
                    machine_id: None,
                    linux,
                    initrd: initrds,
                    options: Some(options),
                    efi: None,
                    uki: None,
                    boot_count_state: BootCountState::NotTracked,
                    tries_left: None,
                    tries_done: None,
                };
                if entries.insert(entry_id, entry).is_some() {
                    return Err("duplicate exact GRUB menu entry identity".into());
                }
            }
        } else if line == "}" && !submenu_stack.is_empty() {
            submenu_stack.pop();
        }
    }

    if current.is_some() {
        return Err("unterminated GRUB menuentry".into());
    }
    if !submenu_stack.is_empty() {
        return Err("unterminated GRUB submenu".into());
    }
    if entries.is_empty() {
        return Err("no GRUB menuentry blocks found".into());
    }
    Ok(entries)
}
fn parse_grub_menuentry_title(line: &str) -> Result<String, String> {
    let rest = line.strip_prefix("menuentry ").unwrap_or("").trim_start();
    if !rest.starts_with('"') {
        return Err("GRUB menuentry title is not a quoted string".into());
    }
    let bytes = rest.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'"' && bytes[i - 1] != b'\\' {
            return Ok(rest[1..i].to_string());
        }
    }
    Err("unterminated GRUB menuentry title".into())
}

fn parse_grub_linux_line(line: &str) -> Result<(Option<String>, String), String> {
    let rest = line
        .strip_prefix("linux ")
        .or_else(|| line.strip_prefix("linuxefi "))
        .or_else(|| line.strip_prefix("multiboot "))
        .ok_or_else(|| "GRUB menuentry has no Linux boot command".to_string())?
        .trim();
    let mut parts = rest.split_whitespace();
    let kernel = parts
        .next()
        .ok_or_else(|| "GRUB Linux boot command has no kernel path".to_string())?
        .to_string();
    let options = parts.collect::<Vec<_>>().join(" ");
    Ok((Some(kernel), options))
}

/// Parse the generated GRUB default expression without interpreting it as identity.
pub fn parse_grub_config_default(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|raw_line| {
            let line = raw_line.trim();
            let value = line.strip_prefix("set default=")?.trim();
            Some(value.trim_matches(|c: char| c == '\'' || c == '"').to_string())
        })
        .filter(|value| !value.contains("${next_entry}"))
        .last()
}
/// Resolve a conservative GRUB selection from exact environment/config values.
///
/// A numeric generated default is intentionally rejected: menu position is not
/// an identity. Literal entry identifiers are accepted only when the caller's
/// menu parser supplies an exact matching entry.
fn resolve_grub_entry<'a>(
    selector: &str,
    menu_entries: &'a BTreeMap<String, BlsEntry>,
) -> Result<&'a BlsEntry, UnknownBootSelection> {
    if let Some(entry) = menu_entries.get(selector) {
        return Ok(entry);
    }
    let matches: Vec<&BlsEntry> = menu_entries
        .values()
        .filter(|entry| entry.title.as_deref() == Some(selector))
        .collect();
    match matches.as_slice() {
        [entry] => Ok(entry),
        [] => Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: format!("GRUB selector {selector} is not mapped to an exact menu entry"),
        }),
        _ => Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: format!("GRUB selector {selector} matches multiple menu entries; refusing ambiguous selection"),
        }),
    }
}

pub fn resolve_grub_selection(
    environment: &BTreeMap<String, String>,
    generated_default: Option<&str>,
    menu_entries: &BTreeMap<String, BlsEntry>,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    if let Some(next_entry) = environment.get("next_entry").filter(|v| !v.is_empty()) {
        let entry = resolve_grub_entry(next_entry, menu_entries)?;
        return Ok(BootSelectionEvidence {
            bootloader_family: BootloaderFamily::Grub,
            selection_kind: SelectionKind::OneShot,
            selected_entry_id: Some(entry.entry_id.clone()),
            selected_entry_source: "grubenv:next_entry".into(),
            candidate_closure: exact_store_path_from_entry(entry),
            boot_count_state: entry.boot_count_state,
            selected_image_path: None,
            selected_image_blake3: None,
            observed_at_ms: None,
            evidence_digest: None,
        });
    }

    let default = generated_default
        .filter(|v| !v.is_empty())
        .ok_or_else(|| UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: "no GRUB generated default is available".into(),
        })?;

    let (default, default_source) = match default {
        "saved" | "${saved_entry}" => {
            let saved = environment.get("saved_entry").filter(|v| !v.is_empty()).ok_or_else(|| {
                UnknownBootSelection {
                    bootloader_family: BootloaderFamily::Grub,
                    reason: "GRUB default delegates to saved_entry, but no exact saved_entry is observable".into(),
                }
            })?;
            (saved.as_str(), "grubenv:saved_entry+generated-grub-config:default")
        }
        value => (value, "generated-grub-config:default"),
    };

    if default.parse::<u64>().is_ok() {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: "numeric GRUB default is menu position, not exact entry identity".into(),
        });
    }

    let entry = resolve_grub_entry(default, menu_entries)?;

    Ok(BootSelectionEvidence {
        bootloader_family: BootloaderFamily::Grub,
        selection_kind: SelectionKind::GeneratedDefault,
        selected_entry_id: Some(entry.entry_id.clone()),
        selected_entry_source: default_source.into(),
        candidate_closure: exact_store_path_from_entry(entry),
        boot_count_state: entry.boot_count_state,
        observed_at_ms: None,
        evidence_digest: None,
    })
}

fn exact_store_path_from_entry(entry: &BlsEntry) -> Option<String> {
    // Kernel/initrd/EFI artifact paths are not the NixOS system closure. For
    // Type #1 entries, the system closure is bound by the kernel command's
    // init=.../init target, which NixOS emits from the generation's init path.
    entry.options.as_deref().and_then(|options| {
        options.split_whitespace().find_map(|token| {
            let init = token.strip_prefix("init=")?;
            let store_path = init.strip_suffix("/init")?;
            if super::execution_intent::is_valid_nix_store_path(store_path)
                && store_path.contains("-nixos-system-")
            {
                Some(store_path.to_string())
            } else {
                None
            }
        })
    })
}

fn contains_selection_pattern(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

fn parse_boot_count(entry_id: &str) -> Result<(BootCountState, Option<u32>, Option<u32>), String> {
    let stem = entry_id
        .strip_suffix(".conf")
        .or_else(|| entry_id.strip_suffix(".efi"))
        .unwrap_or(entry_id);

    let Some(plus) = stem.rfind('+') else {
        return Ok((BootCountState::NotTracked, None, None));
    };

    let counters = &stem[plus + 1..];
    if counters.is_empty() {
        return Err("malformed boot-count suffix: missing tries-left value".into());
    }

    let (tries_left_text, tries_done_text) = counters.split_once('-').map_or((counters, None), |(l, d)| {
        (l, Some(d))
    });

    if !tries_left_text.chars().all(|c| c.is_ascii_digit()) {
        return Err("malformed boot-count suffix: tries-left is not numeric".into());
    }

    let tries_left = tries_left_text
        .parse::<u32>()
        .map_err(|_| "boot-count tries-left overflows u32".to_string())?;

    let tries_done = match tries_done_text {
        Some(text) if !text.chars().all(|c| c.is_ascii_digit()) => {
            return Err("malformed boot-count suffix: tries-done is not numeric".into())
        }
        Some(text) => Some(
            text.parse::<u32>()
                .map_err(|_| "boot-count tries-done overflows u32".to_string())?,
        ),
        None => None,
    };

    let state = if tries_left == 0 {
        BootCountState::Bad
    } else {
        BootCountState::Indeterminate
    };

    Ok((state, Some(tries_left), tries_done))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, text: &str) -> BlsEntry {
        parse_bls_entry(id, text).expect("valid BLS fixture")
    }

    #[test]
    fn parses_type1_entry_and_boot_count() {
        let parsed = entry(
            "nixos-6.12+03-01.conf",
            r#"title NixOS
version 6.12
machine-id 0123456789abcdef0123456789abcdef
linux /EFI/nixos/abc-linux-6.12.efi
initrd /EFI/nixos/def-initrd.efi
options init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init quiet
"#,
        );

        assert_eq!(parsed.title.as_deref(), Some("NixOS"));
        assert_eq!(parsed.tries_left, Some(3));
        assert_eq!(parsed.tries_done, Some(1));
        assert_eq!(parsed.boot_count_state, BootCountState::Indeterminate);
    }

    #[test]
    fn exact_candidate_binding_comes_from_init_option_not_kernel_artifact() {
        let parsed = entry(
            "candidate.conf",
            "linux /EFI/nixos/kernel.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init quiet\n",
        );
        assert_eq!(
            super::exact_store_path_from_entry(&parsed).as_deref(),
            Some("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate"),
        );
    }
    #[cfg(feature = "native")]
    #[test]
    fn decodes_efi_variable_attributes_and_utf16_payload() {
        let mut bytes = vec![0, 0, 0, 7];
        for unit in "candidate.conf".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_efivar_string(&bytes).unwrap(), "candidate.conf");
    }

    #[cfg(feature = "native")]
    #[test]
    fn malformed_efi_variable_payload_is_unknown() {
        assert!(decode_efivar_string(&[0, 0, 0, 7, 1]).is_err());
    }
    #[test]
    fn uncounted_entry_is_not_treated_as_successfully_assessed() {
        let parsed = entry(
            "nixos.conf",
            "linux /EFI/nixos/kernel.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init quiet\n",
        );
        assert_eq!(parsed.boot_count_state, BootCountState::NotTracked);
    }

    #[test]
    fn evidence_digest_binds_observation_metadata() {
        let evidence = BootSelectionEvidence {
            bootloader_family: BootloaderFamily::SystemdBoot,
            selection_kind: SelectionKind::OneShot,
            selected_entry_id: Some("candidate.conf".into()),
            selected_entry_source: "efi:LoaderEntryOneShot".into(),
            candidate_closure: Some("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate".into()),
            boot_count_state: BootCountState::NotTracked,
            observed_at_ms: None,
            evidence_digest: None,
        };
        let first = evidence.clone().with_observation_metadata(100).expect("metadata");
        let second = evidence.with_observation_metadata(101).expect("metadata");
        assert_ne!(first.evidence_digest, second.evidence_digest);
        assert_eq!(first.observed_at_ms, Some(100));
    }
    #[test]
    fn boot_count_zero_is_bad() {
        let parsed = entry(
            "nixos+00-04.efi",
            "uki /EFI/Linux/nixos.efi\n",
        );
        assert_eq!(parsed.boot_count_state, BootCountState::Bad);
    }

    #[test]
    fn systemd_one_shot_beats_persistent_default() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "candidate.conf".into(),
            entry(
                "candidate.conf",
                "linux /EFI/nixos/abc-linux-6.12.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init quiet\n",
            ),
        );
        entries.insert(
            "old.conf".into(),
            entry(
                "old.conf",
                "linux /EFI/nixos/old-linux-6.11.efi\noptions init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old/init quiet\n",
            ),
        );

        let evidence =
            resolve_systemd_boot_selection(Some("candidate"), Some("old"), &entries)
                .expect("selection");
        assert_eq!(evidence.selection_kind, SelectionKind::OneShot);
        assert_eq!(
            evidence.candidate_closure.as_deref(),
            Some("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate")
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn uki_selector_is_detected_only_for_plain_efi_ids() {
        assert!(is_uki_selector("nixos.efi"));
        assert!(!is_uki_selector("nixos.conf"));
        assert!(!is_uki_selector("../nixos.efi"));
        assert!(!is_uki_selector("EFI/nixos.efi"));
    }
    #[test]
    fn systemd_loader_conf_default_is_parsed_without_inference() {
        let exact = parse_systemd_loader_default("timeout 5\ndefault candidate\n");
        assert_eq!(exact.as_deref(), Some("candidate"));
        let pattern = parse_systemd_loader_default("default nixos-*\n");
        assert_eq!(pattern.as_deref(), Some("nixos-*"));
    }
    #[test]
    fn boot_artifact_path_cannot_qualify_as_system_closure() {
        let parsed = entry(
            "candidate.conf",
            "linux /nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-lookalike-kernel\n",
        );
        assert_eq!(super::exact_store_path_from_entry(&parsed), None);
    }
    #[test]
    fn systemd_default_parser_rejects_extra_selector_tokens() {
        assert_eq!(parse_systemd_loader_default("default candidate extra\n"), None);
        assert_eq!(parse_systemd_loader_default("default candidate\n"), Some("candidate".into()));
    }
    #[test]
    fn systemd_loader_entry_suffix_is_normalized_exactly() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "candidate.conf".into(),
            entry(
                "candidate.conf",
                "linux /EFI/nixos/kernel.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init\n",
            ),
        );
        let evidence = resolve_systemd_boot_selection(Some("candidate"), None, &entries)
            .expect("suffix-less LoaderEntryOneShot should map to candidate.conf");
        assert_eq!(evidence.selected_entry_id.as_deref(), Some("candidate.conf"));
    }

    #[test]
    fn malformed_systemd_default_directive_is_ignored() {
        assert_eq!(parse_systemd_loader_default("defaults candidate\n"), None);
        assert_eq!(parse_systemd_loader_default("default candidate trailing\n").as_deref(), Some("candidate"));
    }
    #[test]
    fn systemd_pattern_default_is_unknown() {
        let entries = BTreeMap::new();
        let error = resolve_systemd_boot_selection(None, Some("nixos-*"), &entries)
            .expect_err("pattern must not become exact identity");
        assert!(error.reason.contains("pattern"));
    }

    #[test]
    fn grub_numeric_default_is_unknown() {
        let environment = BTreeMap::new();
        let entries = BTreeMap::new();
        let error = resolve_grub_selection(&environment, Some("0"), &entries)
            .expect_err("numeric menu position must not qualify");
        assert!(error.reason.contains("menu position"));
    }

    #[test]
    fn parses_nixos_grub_menuentry_and_exact_init_closure() {
        let entries = parse_grub_config_entries(
            r#"menuentry "NixOS - Configuration 42" --class nixos {
 linux /nix/store/0123456789abcdfghijklmnpqrsvwxyz-linux-kernel init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate/init quiet
 initrd /nix/store/0123456789abcdfghijklmnpqrsvwxyz-initrd
}
"#,
        )
        .expect("GRUB fixture parses");

        let entry = entries.get("NixOS - Configuration 42").expect("entry");
        assert_eq!(entry.title.as_deref(), Some("NixOS - Configuration 42"));
        assert_eq!(
            super::exact_store_path_from_entry(entry).as_deref(),
            Some("/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate"),
        );
    }

    #[test]
    fn nested_grub_block_does_not_end_menuentry_early() {
        let entries = parse_grub_config_entries(
            "menuentry \"Nested\" {\n if [ x = y ]; then\n  echo hello\n fi\n linux /boot/kernel init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate/init\n}\n",
        )
        .expect("nested shell block should parse");
        assert!(entries.contains_key("Nested"));
    }
    #[test]
    fn duplicate_grub_titles_in_distinct_submenus_are_not_ambiguous_by_path() {
        let entries = parse_grub_config_entries(
            "submenu \"A\" {\n menuentry \"Same\" {\n  linux /boot/a init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-a/init\n }\n}\nsubmenu \"B\" {\n menuentry \"Same\" {\n  linux /boot/b init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-b/init\n }\n}\n",
        )
        .expect("nested GRUB fixture parses");
        assert!(entries.contains_key("A > Same"));
        assert!(entries.contains_key("B > Same"));
        let env = BTreeMap::new();
        let ambiguous = resolve_grub_selection(&env, Some("Same"), &entries)
            .expect_err("ambiguous title must fail closed");
        assert!(ambiguous.reason.contains("multiple menu entries"));
    }
    #[test]
    fn saved_grub_default_requires_exact_saved_entry() {
        let environment = parse_grub_environment("saved_entry=candidate\n");
        let mut entries = BTreeMap::new();
        entries.insert(
            "candidate".into(),
            entry(
                "candidate",
                "efi /EFI/nixos/candidate.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init\n",
            ),
        );
        let evidence = resolve_grub_selection(&environment, Some("saved"), &entries)
            .expect("saved entry selection");
        assert_eq!(evidence.selection_kind, SelectionKind::GeneratedDefault);
        assert_eq!(evidence.selected_entry_id.as_deref(), Some("candidate"));
        assert!(evidence.selected_entry_source.contains("saved_entry"));
    }

    #[cfg(feature = "native")]
    #[test]
    fn grub_root_preference_stays_first() {
        let preferred = PathBuf::from("/boot-custom");
        let candidates = candidate_grub_roots(Some(&preferred));
        assert_eq!(candidates.first(), Some(&preferred));
        assert_eq!(candidates.iter().filter(|p| *p == &preferred).count(), 1);
    }

    #[cfg(feature = "native")]
    #[test]
    fn malformed_efi_string_without_nul_is_rejected() {
        assert!(decode_efivar_string(&[0, 0, 0, 7, 0x41, 0x00]).is_err());
    }
    #[test]
    fn grub_config_default_is_parsed_read_only() {
        assert_eq!(parse_grub_config_default("set timeout=5\nset default=0\n"), Some("0".into()));
        assert_eq!(
            parse_grub_config_default("if [ \"${next_entry}\" ]; then\\nset default=\"${next_entry}\"\\nelse\\nset default=\"${saved_entry}\"\\nfi\\n"),
            Some("${saved_entry}".into()),
        );
        assert_eq!(parse_grub_config_default("set default=\"${saved_entry}\"\n"), Some("${saved_entry}".into()));
        assert_eq!(parse_grub_config_default("set timeout=5\n"), None);
    }

    #[cfg(feature = "native")]
    #[test]
    fn grub_root_preference_is_first_and_deduplicated() {
        let preferred = PathBuf::from("/boot-custom");
        let candidates = candidate_grub_roots(Some(&preferred));
        assert_eq!(candidates.first(), Some(&preferred));
        assert_eq!(candidates.iter().filter(|p| *p == &preferred).count(), 1);
    }
    #[test]
    fn selected_non_nixos_grub_entry_is_unbound() {
        let entries = parse_grub_config_entries(
            "menuentry \"Windows\" {\n chainloader /EFI/Microsoft/Boot/bootmgfw.efi\n}\nmenuentry \"NixOS\" {\n linux /boot/kernel init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate/init\n}\n",
        )
        .expect("mixed GRUB config parses");
        let environment = BTreeMap::from([(
            "next_entry".to_string(),
            "Windows".to_string(),
        )]);
        let evidence = resolve_grub_selection(&environment, None, &entries)
            .expect("selected non-NixOS entry should still be observable");
        assert_eq!(evidence.selected_entry_id.as_deref(), Some("Windows"));
        assert_eq!(evidence.candidate_closure, None);
        assert!(require_candidate_binding(
            &evidence,
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate",
        ).is_err());
    }
    #[test]
    fn duplicate_grub_titles_fail_closed() {
        let result = parse_grub_config_entries(
            "menuentry \"same\" {\n linux /boot/a init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-a/init\n}\nmenuentry \"same\" {\n linux /boot/b init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-b/init\n}\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn candidate_binding_rejects_mismatch_and_missing_binding() {
        let evidence = BootSelectionEvidence {
            bootloader_family: BootloaderFamily::SystemdBoot,
            selection_kind: SelectionKind::OneShot,
            selected_entry_id: Some("candidate.conf".into()),
            selected_entry_source: "efi:LoaderEntryOneShot".into(),
            candidate_closure: Some(
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-other".into(),
            ),
            boot_count_state: BootCountState::NotTracked,
            observed_at_ms: None,
            evidence_digest: None,
        };
        let expected =
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate";
        let mismatch = require_candidate_binding(&evidence, expected)
            .expect_err("foreign candidate binding must not qualify");
        assert!(mismatch.reason.contains("not the authorized candidate"));

        let unbound = BootSelectionEvidence {
            candidate_closure: None,
            ..evidence
        };
        let missing = require_candidate_binding(&unbound, expected)
            .expect_err("unbound boot entry must not qualify");
        assert!(missing.reason.contains("does not expose an exact"));
    }
    #[test]
    fn grub_next_entry_requires_exact_mapping() {
        let environment =
            parse_grub_environment("next_entry=candidate\nsaved_entry=old\n");
        let entries = BTreeMap::from([(
            "candidate".into(),
            entry(
                "candidate",
                "efi /EFI/nixos/candidate.efi\noptions init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init\n",
            ),
        )]);

        let evidence =
            resolve_grub_selection(&environment, None, &entries).expect("grub selection");
        assert_eq!(evidence.selection_kind, SelectionKind::OneShot);
        assert_eq!(evidence.selected_entry_id.as_deref(), Some("candidate"));
    }
}
