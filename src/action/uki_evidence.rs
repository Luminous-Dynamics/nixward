// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only UKI identity and NixOS system-closure binding.
//!
//! Type #2 Unified Kernel Images are executable PE images. The image digest
//! and the embedded kernel command line are separate evidence dimensions.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "native")]
use std::fs;

/// Exact read-only identity evidence for one UKI image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UkiSystemClosureEvidence {
    pub image_path: String,
    pub image_blake3: [u8; 32],
    pub cmdline: String,
    pub system_closure: Option<String>,
}

/// Extract the `.cmdline` PE section from a UKI.
///
/// Exactly one `.cmdline` section is required. Multi-profile UKIs with multiple
/// command-line sections are intentionally left Unknown until a profile-selection
/// subject is supplied.
pub fn extract_cmdline_section(image: &[u8]) -> Result<String, String> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err("UKI is not a PE image with an MZ header".into());
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    let pe_end = pe_offset.checked_add(4 + 20).ok_or_else(|| "PE header offset overflows".to_string())?;
    if pe_end > image.len() || &image[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("UKI has no valid PE signature".into());
    }

    let number_of_sections = read_u16(image, pe_offset + 6)? as usize;
    let optional_header_size = read_u16(image, pe_offset + 20)? as usize;
    let section_table = pe_offset
        .checked_add(4 + 20)
        .and_then(|x| x.checked_add(optional_header_size))
        .ok_or_else(|| "PE section table offset overflows".to_string())?;
    let table_size = number_of_sections
        .checked_mul(40)
        .ok_or_else(|| "PE section table size overflows".to_string())?;
    let table_end = section_table
        .checked_add(table_size)
        .ok_or_else(|| "PE section table end overflows".to_string())?;
    if table_end > image.len() {
        return Err("PE section table is truncated".into());
    }

    let mut cmdline: Option<&[u8]> = None;
    for index in 0..number_of_sections {
        let offset = section_table + index * 40;
        let name_bytes = &image[offset..offset + 8];
        let name_end = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = &name_bytes[..name_end];
        if name != b".cmdline" {
            continue;
        }

        let raw_size = read_u32(image, offset + 16)? as usize;
        let raw_pointer = read_u32(image, offset + 20)? as usize;
        let raw_end = raw_pointer
            .checked_add(raw_size)
            .ok_or_else(|| "UKI .cmdline raw section overflows".to_string())?;
        if raw_end > image.len() {
            return Err("UKI .cmdline section lies outside the image".into());
        }
        if cmdline.is_some() {
            return Err("UKI contains multiple .cmdline sections; profile selection is ambiguous".into());
        }
        cmdline = Some(&image[raw_pointer..raw_end]);
    }

    let cmdline = cmdline.ok_or_else(|| "UKI has no .cmdline section".to_string())?;
    let end = cmdline.iter().position(|byte| *byte == 0).unwrap_or(cmdline.len());
    let text = std::str::from_utf8(&cmdline[..end])
        .map_err(|error| format!("UKI .cmdline is not valid UTF-8: {error}"))?
        .trim()
        .to_string();
    if text.is_empty() {
        return Err("UKI .cmdline section is empty".into());
    }
    Ok(text)
}

/// Extract one exact NixOS system closure from a UKI kernel command line.
///
/// The only accepted binding is an `init=/nix/store/...-nixos-system-.../init`
/// token. Missing or conflicting values are errors; identical duplicate tokens
/// are accepted as the same binding.
pub fn extract_nixos_system_closure(cmdline: &str) -> Result<Option<String>, String> {
    let mut closures = BTreeSet::new();
    for token in cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix("init=") else {
            continue;
        };
        let Some(store_path) = value.strip_suffix("/init") else {
            continue;
        };
        if !super::execution_intent::is_valid_nix_store_path(store_path)
            || !store_path.contains("-nixos-system-")
        {
            return Err("UKI init= token is not an exact NixOS system store closure".into());
        }
        closures.insert(store_path.to_string());
    }

    match closures.len() {
        0 => Ok(None),
        1 => Ok(closures.into_iter().next()),
        _ => Err("UKI .cmdline contains conflicting init= system closures".into()),
    }
}

/// Inspect a UKI byte image and derive immutable image + closure evidence.
pub fn inspect_uki_bytes(image_path: &str, image: &[u8]) -> Result<UkiSystemClosureEvidence, String> {
    let cmdline = extract_cmdline_section(image)?;
    let system_closure = extract_nixos_system_closure(&cmdline)?;
    Ok(UkiSystemClosureEvidence {
        image_path: image_path.to_string(),
        image_blake3: *blake3::hash(image).as_bytes(),
        cmdline,
        system_closure,
    })
}

/// Require an exact UKI-to-system-closure binding.
pub fn require_uki_candidate_binding(
    evidence: &UkiSystemClosureEvidence,
    expected_candidate_closure: &str,
) -> Result<(), String> {
    if !super::execution_intent::is_valid_nix_store_path(expected_candidate_closure)
        || !expected_candidate_closure.contains("-nixos-system-")
    {
        return Err("authorized candidate is not an exact NixOS system store closure".into());
    }
    match evidence.system_closure.as_deref() {
        Some(observed) if observed == expected_candidate_closure => Ok(()),
        Some(observed) => Err(format!(
            "UKI embeds system closure {}, not authorized candidate {}",
            observed, expected_candidate_closure
        )),
        None => Err("UKI does not expose an exact NixOS system closure binding".into()),
    }
}

/// Resolve a BLS `efi` path against the authoritative boot partition.
///
/// Parent traversal and redirected final files are rejected. Canonicalization
/// must remain inside the supplied boot root.
pub fn resolve_boot_artifact_path(boot_root: &Path, efi_path: &str) -> Result<PathBuf, String> {
    let root_metadata = fs::symlink_metadata(boot_root).map_err(|error| {
        format!("failed to inspect boot root {}: {error}", boot_root.display())
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        return Err(format!(
            "boot root {} is not a regular non-symlink directory",
            boot_root.display()
        ));
    }
    let relative = efi_path
        .strip_prefix('/')
        .ok_or_else(|| "BLS EFI path must be absolute within the boot partition".to_string())?;
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Err("BLS EFI path remains absolute after prefix normalization".into());
    }
    for component in relative_path.components() {
        if matches!(component, Component::RootDir | Component::Prefix(_) | Component::ParentDir | Component::CurDir) {
            return Err("BLS EFI path contains traversal or root components".into());
        }
    }
    let root = fs::canonicalize(boot_root).map_err(|error| {
        format!("failed to canonicalize boot root {}: {error}", boot_root.display())
    })?;
    let candidate = root.join(relative_path);
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        format!("failed to inspect UKI path {}: {error}", candidate.display())
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("UKI path {} is not a regular non-symlink file", candidate.display()));
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        format!("failed to canonicalize UKI path {}: {error}", candidate.display())
    })?;
    if !canonical.starts_with(&root) {
        return Err("UKI path resolves outside the authoritative boot root".into());
    }
    Ok(canonical)
}

#[cfg(feature = "native")]
pub fn inspect_uki_file(path: &Path) -> Result<UkiSystemClosureEvidence, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!("failed to inspect UKI file {}: {error}", path.display())
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("UKI file {} is not a regular non-symlink file", path.display()));
    }
    let image = fs::read(path).map_err(|error| {
        format!("failed to read UKI image {}: {error}", path.display())
    })?;
    inspect_uki_bytes(&path.display().to_string(), &image)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset.checked_add(2).ok_or_else(|| "u16 read overflows".to_string())?;
    let slice = bytes.get(offset..end).ok_or_else(|| "PE header is truncated".to_string())?;
    Ok(u16::from_le_bytes(slice.try_into().expect("2-byte slice")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or_else(|| "u32 read overflows".to_string())?;
    let slice = bytes.get(offset..end).ok_or_else(|| "PE header is truncated".to_string())?;
    Ok(u32::from_le_bytes(slice.try_into().expect("4-byte slice")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_cmdlines(cmdlines: &[&str]) -> Vec<u8> {
        let pe_offset = 0x40usize;
        let sections = cmdlines.len();
        let table = pe_offset + 4 + 20;
        let raw_start = table + sections * 40;
        let mut image = vec![0u8; raw_start];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        image[pe_offset + 6..pe_offset + 8].copy_from_slice(&(sections as u16).to_le_bytes());
        image[pe_offset + 20..pe_offset + 22].copy_from_slice(&0u16.to_le_bytes());

        let mut raw_offset = raw_start;
        for (index, cmdline) in cmdlines.iter().enumerate() {
            let section = table + index * 40;
            image[section..section + 8].copy_from_slice(b".cmdline");
            let mut bytes = cmdline.as_bytes().to_vec();
            bytes.push(0);
            let raw_size = bytes.len() as u32;
            image[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
            image[section + 20..section + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
            image.extend_from_slice(&bytes);
            raw_offset += bytes.len();
        }
        image
    }

    #[test]
    fn extracts_exact_system_closure_from_uki_cmdline() {
        let path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate";
        let cmdline = format!("quiet init={path}/init");
        assert_eq!(
            extract_nixos_system_closure(&cmdline).unwrap().as_deref(),
            Some(path)
        );
    }

    #[test]
    fn conflicting_uki_init_bindings_fail_closed() {
        let a = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-a";
        let b = "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-b";
        let error = extract_nixos_system_closure(&format!("init={a}/init init={b}/init"))
            .expect_err("conflicting init bindings must fail");
        assert!(error.contains("conflicting"));
    }

    #[test]
    fn kernel_artifact_does_not_bind_uki_to_system_closure() {
        let cmdline = "quiet init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-linux/init";
        assert!(extract_nixos_system_closure(cmdline).is_err());
    }

    #[test]
    fn multiple_cmdline_sections_are_ambiguous() {
        let image = pe_with_cmdlines(&["init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-a/init", "init=/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-b/init"]);
        let error = extract_cmdline_section(&image).expect_err("multi-profile image must be ambiguous");
        assert!(error.contains("multiple .cmdline"));
    }

    #[test]
    fn uki_image_digest_is_exact_and_stable() {
        let image = pe_with_cmdlines(&["quiet init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate/init"]);
        let evidence_a = inspect_uki_bytes("candidate.efi", &image).expect("UKI fixture");
        let evidence_b = inspect_uki_bytes("candidate.efi", &image).expect("UKI fixture");
        assert_eq!(evidence_a.image_blake3, evidence_b.image_blake3);
        assert_eq!(evidence_a.system_closure.as_deref(), Some("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-candidate"));
    }

    #[test]
    fn uki_candidate_binding_rejects_mismatch() {
        let image = pe_with_cmdlines(&["init=/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-other/init"]);
        let evidence = inspect_uki_bytes("candidate.efi", &image).expect("UKI fixture");
        assert!(require_uki_candidate_binding(
            &evidence,
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-candidate",
        ).is_err());
    }

    #[test]
    fn boot_artifact_path_rejects_double_root_escape() {
        let error = resolve_boot_artifact_path(Path::new("/boot"), "//EFI/Linux/candidate.efi")
            .expect_err("double-root path must fail closed");
        assert!(error.contains("absolute") || error.contains("root"));
    }
    #[test]
    fn boot_artifact_path_rejects_traversal() {
        let error = resolve_boot_artifact_path(Path::new("/boot"), "/EFI/Linux/../evil.efi")
            .expect_err("path traversal must fail closed");
        assert!(error.contains("traversal"));
    }
}