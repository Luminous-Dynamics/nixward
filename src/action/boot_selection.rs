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

        let Some((key, value)) = line.split_once(char::is_whitespace) else {
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
    let (selection_kind, selected, source) = match one_shot_entry {
        Some(id) if !id.is_empty() => (SelectionKind::OneShot, id, "efi:LoaderEntryOneShot"),
        _ => match persistent_default {
            Some(id) if !id.is_empty() && !contains_selection_pattern(id) => {
                (SelectionKind::PersistentDefault, id, "efi:LoaderEntryDefault/loader.conf")
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

    let entry = entries.get(selected).ok_or_else(|| UnknownBootSelection {
        bootloader_family: BootloaderFamily::SystemdBoot,
        reason: format!("selected entry {selected} is not present in the authoritative entry set"),
    })?;

    Ok(BootSelectionEvidence {
        bootloader_family: BootloaderFamily::SystemdBoot,
        selection_kind,
        selected_entry_id: Some(entry.entry_id.clone()),
        selected_entry_source: source.into(),
        candidate_closure: exact_store_path_from_entry(entry),
        boot_count_state: entry.boot_count_state,
    })
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
            Some((key.trim().to_string(), value.trim_matches(['\'', '"']).to_string()))
        })
        .collect()
}

/// Resolve a conservative GRUB selection from exact environment/config values.
///
/// A numeric generated default is intentionally rejected: menu position is not
/// an identity. Literal entry identifiers are accepted only when the caller's
/// menu parser supplies an exact matching entry.
pub fn resolve_grub_selection(
    environment: &BTreeMap<String, String>,
    generated_default: Option<&str>,
    menu_entries: &BTreeMap<String, BlsEntry>,
) -> Result<BootSelectionEvidence, UnknownBootSelection> {
    if let Some(next_entry) = environment.get("next_entry").filter(|v| !v.is_empty()) {
        let entry = menu_entries.get(next_entry).ok_or_else(|| UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: format!("GRUB next_entry {next_entry} is not mapped to an exact menu entry"),
        })?;
        return Ok(BootSelectionEvidence {
            bootloader_family: BootloaderFamily::Grub,
            selection_kind: SelectionKind::OneShot,
            selected_entry_id: Some(entry.entry_id.clone()),
            selected_entry_source: "grubenv:next_entry".into(),
            candidate_closure: exact_store_path_from_entry(entry),
            boot_count_state: entry.boot_count_state,
        });
    }

    let default = generated_default
        .filter(|v| !v.is_empty())
        .ok_or_else(|| UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: "no exact GRUB generated default is available".into(),
        })?;

    if default.parse::<u64>().is_ok() {
        return Err(UnknownBootSelection {
            bootloader_family: BootloaderFamily::Grub,
            reason: "numeric GRUB default is menu position, not exact entry identity".into(),
        });
    }

    let entry = menu_entries.get(default).ok_or_else(|| UnknownBootSelection {
        bootloader_family: BootloaderFamily::Grub,
        reason: format!("GRUB default {default} is not mapped to an exact menu entry"),
    })?;

    Ok(BootSelectionEvidence {
        bootloader_family: BootloaderFamily::Grub,
        selection_kind: SelectionKind::GeneratedDefault,
        selected_entry_id: Some(entry.entry_id.clone()),
        selected_entry_source: "generated-grub-config:default".into(),
        candidate_closure: exact_store_path_from_entry(entry),
        boot_count_state: entry.boot_count_state,
    })
}

fn exact_store_path_from_entry(entry: &BlsEntry) -> Option<String> {
    [
        entry.linux.as_deref(),
        entry.efi.as_deref(),
        entry.uki.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|value| {
        super::execution_intent::is_valid_nix_store_path(value)
            && value.contains("-nixos-system-")
    })
    .map(str::to_string)
    .or_else(|| {
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
    )
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
        return Ok((BootCountState::Good, None, None));
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
            resolve_systemd_boot_selection(Some("candidate.conf"), Some("old.conf"), &entries)
                .expect("selection");
        assert_eq!(evidence.selection_kind, SelectionKind::OneShot);
        assert_eq!(
            evidence.candidate_closure.as_deref(),
            Some("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate")
        );
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
    fn grub_next_entry_requires_exact_mapping() {
        let environment =
            parse_grub_environment("next_entry=candidate\nsaved_entry=old\n");
        let entries = BTreeMap::from([(
            "candidate".into(),
            entry(
                "candidate",
                "efi /nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate\n",
            ),
        )]);

        let evidence =
            resolve_grub_selection(&environment, None, &entries).expect("grub selection");
        assert_eq!(evidence.selection_kind, SelectionKind::OneShot);
        assert_eq!(evidence.selected_entry_id.as_deref(), Some("candidate"));
    }
}
