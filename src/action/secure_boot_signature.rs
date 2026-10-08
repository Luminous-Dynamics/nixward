// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only PE Authenticode certificate-table evidence.
//!
//! This module does not claim cryptographic signature validity or trust-policy
//! acceptance. It proves only what certificate-table bytes are actually present
//! in the exact observed image.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureTableState {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeCertificateRecord {
    pub revision: u16,
    pub certificate_type: u16,
    pub length: u32,
    pub payload_blake3: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeSignatureTableEvidence {
    pub image_blake3: [u8; 32],
    pub state: SignatureTableState,
    pub table_offset: Option<u32>,
    pub table_size: Option<u32>,
    pub table_blake3: Option<[u8; 32]>,
    pub certificates: Vec<PeCertificateRecord>,
}

/// Compute the SHA-256 Authenticode/PE image hash.
///
/// This is intentionally distinct from a flat file hash: the PE checksum,
/// Certificate Table directory entry, certificate table, and bytes past the
/// section-derived hashed region are excluded according to the Authenticode
/// procedure.
pub fn authenticode_sha256(image: &[u8]) -> Result<[u8; 32], String> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err("image is not a PE file with an MZ header".into());
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    let coff = pe_offset
        .checked_add(4)
        .ok_or_else(|| "PE COFF header offset overflows".to_string())?;
    if coff.checked_add(20).ok_or_else(|| "PE COFF header overflows".to_string())? > image.len() {
        return Err("PE/COFF header is truncated".into());
    }
    if &image[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("image has no PE signature".into());
    }

    let section_count = read_u16(image, coff + 2)? as usize;
    let optional_size = read_u16(image, coff + 16)? as usize;
    let optional = coff + 20;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or_else(|| "PE optional header size overflows".to_string())?;
    if optional_end > image.len() {
        return Err("PE optional header is truncated".into());
    }
    let magic = read_u16(image, optional)?;
    let cert_dir_offset = match magic {
        0x10b => optional + 128,
        0x20b => optional + 144,
        _ => return Err(format!("unsupported PE optional-header magic 0x{magic:04x}")),
    };
    if optional + 68 > optional_end || cert_dir_offset + 8 > optional_end {
        return Err("PE optional header is too short for Authenticode fields".into());
    }

    let checksum_offset = optional + 64;
    let size_of_headers = read_u32(image, optional + 60)? as usize;
    if size_of_headers > image.len() || size_of_headers < cert_dir_offset + 8 {
        return Err("PE SizeOfHeaders is inconsistent with the certificate directory".into());
    }
    let cert_table_offset = read_u32(image, cert_dir_offset)? as usize;
    let cert_table_size = read_u32(image, cert_dir_offset + 4)? as usize;
    let cert_end = cert_table_offset
        .checked_add(cert_table_size)
        .ok_or_else(|| "PE certificate table range overflows".to_string())?;
    if cert_table_size != 0 && (cert_table_offset == 0 || cert_end > image.len()) {
        return Err("PE certificate table lies outside the image".into());
    }

    let section_table = optional_end;
    let section_bytes = section_count
        .checked_mul(40)
        .ok_or_else(|| "PE section table size overflows".to_string())?;
    if section_table.checked_add(section_bytes).ok_or_else(|| "PE section table overflows".to_string())? > image.len() {
        return Err("PE section table is truncated".into());
    }

    let mut hasher = Sha256::new();
    hasher.update(&image[..checksum_offset]);
    hasher.update(&image[checksum_offset + 4..cert_dir_offset]);
    hasher.update(&image[cert_dir_offset + 8..size_of_headers]);

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section = section_table + index * 40;
        let size_of_raw = read_u32(image, section + 16)? as usize;
        let ptr_to_raw = read_u32(image, section + 20)? as usize;
        if size_of_raw == 0 {
            continue;
        }
        let end = ptr_to_raw
            .checked_add(size_of_raw)
            .ok_or_else(|| "PE section range overflows".to_string())?;
        if end > image.len() {
            return Err(format!("PE section [{ptr_to_raw}..{end}] exceeds image size {}", image.len()));
        }
        sections.push((ptr_to_raw, size_of_raw));
    }
    sections.sort_unstable_by_key(|(offset, _)| *offset);

    let mut sum_of_bytes_hashed = size_of_headers;
    for (ptr_to_raw, size_of_raw) in sections {
        let end = ptr_to_raw + size_of_raw;
        hasher.update(&image[ptr_to_raw..end]);
        sum_of_bytes_hashed = sum_of_bytes_hashed
            .checked_add(size_of_raw)
            .ok_or_else(|| "Authenticode hashed-byte counter overflows".to_string())?;
    }

    let tail_end = image.len()
        .checked_sub(cert_table_size)
        .ok_or_else(|| "Authenticode certificate exclusion exceeds image size".to_string())?;
    if tail_end < sum_of_bytes_hashed {
        return Err("Authenticode hashed-byte region overlaps excluded certificate table".into());
    }
    if tail_end > sum_of_bytes_hashed {
        hasher.update(&image[sum_of_bytes_hashed..tail_end]);
    }
    Ok(hasher.finalize().into())
}

/// Extract and hash the PE certificate table from an exact image.
pub fn inspect_pe_signature_table(image: &[u8]) -> Result<PeSignatureTableEvidence, String> {
    let image_blake3 = *blake3::hash(image).as_bytes();
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err("image is not a PE file with an MZ header".into());
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    if pe_offset.checked_add(24).ok_or_else(|| "PE header offset overflows".to_string())? > image.len() {
        return Err("PE/COFF header is truncated".into());
    }
    if &image[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("image has no PE signature".into());
    }

    let optional_size = read_u16(image, pe_offset + 20)? as usize;
    if optional_size < 2 {
        return Err("PE optional header is truncated".into());
    }
    let optional_start = pe_offset + 24;
    let optional_end = optional_start
        .checked_add(optional_size)
        .ok_or_else(|| "PE optional header size overflows".to_string())?;
    if optional_end > image.len() {
        return Err("PE optional header is truncated".into());
    }

    let magic = read_u16(image, optional_start)?;
    let directory_start_rel = match magic {
        0x10b => 96usize,
        0x20b => 112usize,
        _ => return Err(format!("unsupported PE optional-header magic 0x{magic:04x}")),
    };
    let directory_count_offset = directory_start_rel
        .checked_sub(4)
        .ok_or_else(|| "PE data-directory offset underflow".to_string())?;
    if directory_count_offset + 4 > optional_size || directory_start_rel + 5 * 8 > optional_size {
        return Ok(PeSignatureTableEvidence {
            image_blake3,
            state: SignatureTableState::Absent,
            table_offset: None,
            table_size: None,
            table_blake3: None,
            certificates: Vec::new(),
        });
    }

    let directory_count = read_u32(image, optional_start + directory_count_offset)?;
    if directory_count <= 4 {
        return Ok(PeSignatureTableEvidence {
            image_blake3,
            state: SignatureTableState::Absent,
            table_offset: None,
            table_size: None,
            table_blake3: None,
            certificates: Vec::new(),
        });
    }

    let directory = optional_start + directory_start_rel + 4 * 8;
    let table_offset = read_u32(image, directory)?;
    let table_size = read_u32(image, directory + 4)?;
    if table_offset == 0 || table_size == 0 {
        return Ok(PeSignatureTableEvidence {
            image_blake3,
            state: SignatureTableState::Absent,
            table_offset: Some(table_offset),
            table_size: Some(table_size),
            table_blake3: None,
            certificates: Vec::new(),
        });
    }

    let table_end = (table_offset as usize)
        .checked_add(table_size as usize)
        .ok_or_else(|| "PE certificate table end overflows".to_string())?;
    if table_end > image.len() {
        return Err("PE certificate table lies outside the image".into());
    }

    let table = &image[table_offset as usize..table_end];
    let mut certificates = Vec::new();
    let mut cursor = 0usize;
    while cursor < table.len() {
        if table.len() - cursor < 8 {
            return Err("PE certificate table contains a truncated WIN_CERTIFICATE header".into());
        }
        let length = u32::from_le_bytes(table[cursor..cursor + 4].try_into().expect("4-byte length"));
        if length < 8 {
            return Err("PE WIN_CERTIFICATE length is smaller than its header".into());
        }
        let end = cursor
            .checked_add(length as usize)
            .ok_or_else(|| "PE WIN_CERTIFICATE length overflows".to_string())?;
        if end > table.len() {
            return Err("PE WIN_CERTIFICATE extends past certificate table".into());
        }
        let revision = u16::from_le_bytes(table[cursor + 4..cursor + 6].try_into().expect("2-byte revision"));
        let certificate_type = u16::from_le_bytes(table[cursor + 6..cursor + 8].try_into().expect("2-byte certificate type"));
        let payload = &table[cursor + 8..end];
        certificates.push(PeCertificateRecord {
            revision,
            certificate_type,
            length,
            payload_blake3: *blake3::hash(payload).as_bytes(),
        });
        let aligned = (length as usize)
            .checked_add(7)
            .ok_or_else(|| "PE WIN_CERTIFICATE alignment overflows".to_string())?
            & !7usize;
        if aligned > table.len() - cursor {
            return Err("PE WIN_CERTIFICATE alignment exceeds certificate table".into());
        }
        cursor += aligned;
    }

    Ok(PeSignatureTableEvidence {
        image_blake3,
        state: SignatureTableState::Present,
        table_offset: Some(table_offset),
        table_size: Some(table_size),
        table_blake3: Some(*blake3::hash(table).as_bytes()),
        certificates,
    })
}

pub fn require_signature_table_image(
    evidence: &PeSignatureTableEvidence,
    expected_image_blake3: &[u8; 32],
) -> Result<(), String> {
    if &evidence.image_blake3 != expected_image_blake3 {
        return Err("signature-table evidence is bound to a different image digest".into());
    }
    if evidence.state != SignatureTableState::Present || evidence.certificates.is_empty() {
        return Err("exact image does not contain an observed PE certificate table".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureVerificationState {
    Verified,
    Failed,
    ToolUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationEvidence {
    pub image_blake3: [u8; 32],
    pub certificate_blake3: [u8; 32],
    pub verifier: String,
    pub state: SignatureVerificationState,
    pub stdout_blake3: [u8; 32],
    pub stderr_blake3: [u8; 32],
}

#[cfg(feature = "native")]
pub fn verify_pe_signature_with_certificate(
    image_path: &std::path::Path,
    certificate_path: &std::path::Path,
) -> Result<SignatureVerificationEvidence, String> {
    let image_metadata = std::fs::symlink_metadata(image_path)
        .map_err(|error| format!("failed to inspect signature image {}: {error}", image_path.display()))?;
    let certificate_metadata = std::fs::symlink_metadata(certificate_path)
        .map_err(|error| format!("failed to inspect verification certificate {}: {error}", certificate_path.display()))?;
    if image_metadata.file_type().is_symlink() || !image_metadata.file_type().is_file() {
        return Err(format!("signature image {} is not a regular non-symlink file", image_path.display()));
    }
    if certificate_metadata.file_type().is_symlink() || !certificate_metadata.file_type().is_file() {
        return Err(format!("verification certificate {} is not a regular non-symlink file", certificate_path.display()));
    }
    let image = std::fs::read(image_path)
        .map_err(|error| format!("failed to read signature image {}: {error}", image_path.display()))?;
    let certificate = std::fs::read(certificate_path)
        .map_err(|error| format!("failed to read verification certificate {}: {error}", certificate_path.display()))?;
    let image_before = *blake3::hash(&image).as_bytes();
    let certificate_before = *blake3::hash(&certificate).as_bytes();
    let output = std::process::Command::new("sbverify")
        .args(["--cert"])
        .arg(certificate_path)
        .arg(image_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SignatureVerificationEvidence {
                image_blake3: *blake3::hash(&image).as_bytes(),
                certificate_blake3: certificate_before,
                verifier: "sbverify".into(),
                state: SignatureVerificationState::ToolUnavailable,
                stdout_blake3: *blake3::hash(&[]).as_bytes(),
                stderr_blake3: *blake3::hash(error.to_string().as_bytes()).as_bytes(),
            })
        }
        Err(error) => return Err(format!("failed to execute sbverify: {error}")),
    };
    let image_after = std::fs::read(image_path)
        .map_err(|error| format!("failed to re-read signature image {}: {error}", image_path.display()))?;
    let certificate_after = std::fs::read(certificate_path)
        .map_err(|error| format!("failed to re-read verification certificate {}: {error}", certificate_path.display()))?;
    let image_after_hash = *blake3::hash(&image_after).as_bytes();
    let certificate_after_hash = *blake3::hash(&certificate_after).as_bytes();
    let stable = image_after_hash == image_before && certificate_after_hash == certificate_before;

    Ok(SignatureVerificationEvidence {
        image_blake3: image_before,
        certificate_blake3: *blake3::hash(&certificate).as_bytes(),
        verifier: "sbverify".into(),
        state: if output.status.success() && stable {
            SignatureVerificationState::Verified
        } else {
            SignatureVerificationState::Failed
        },
        stdout_blake3: *blake3::hash(&output.stdout).as_bytes(),
        stderr_blake3: *blake3::hash(&output.stderr).as_bytes(),
    })
}

pub fn require_verified_signature_image(
    evidence: &SignatureVerificationEvidence,
    expected_image_blake3: &[u8; 32],
) -> Result<(), String> {
    if &evidence.image_blake3 != expected_image_blake3 {
        return Err("signature verification evidence is bound to a different image digest".into());
    }
    if evidence.state != SignatureVerificationState::Verified {
        return Err(format!("signature verification state is {:?}, not Verified", evidence.state));
    }
    Ok(())
}

#[cfg(feature = "native")]
pub fn inspect_pe_signature_file(path: &std::path::Path) -> Result<PeSignatureTableEvidence, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect signature subject {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("signature subject {} is not a regular non-symlink file", path.display()));
    }
    let image = std::fs::read(path)
        .map_err(|error| format!("failed to read signature subject {}: {error}", path.display()))?;
    inspect_pe_signature_table(&image)
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

    fn pe_with_certificate(certificate_type: u16, payload: &[u8]) -> Vec<u8> {
        let pe_offset = 0x40usize;
        let optional_size = 112usize + 5 * 8;
        let section_table = pe_offset + 24 + optional_size;
        let table_offset = section_table;
        let length = (8 + payload.len()) as u32;
        let aligned = (length as usize + 7) & !7usize;
        let mut image = vec![0u8; table_offset + aligned];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        image[pe_offset + 6..pe_offset + 8].copy_from_slice(&0u16.to_le_bytes());
        image[pe_offset + 20..pe_offset + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
        let optional = pe_offset + 24;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&5u32.to_le_bytes());
        let directory = optional + 112 + 4 * 8;
        image[directory..directory + 4].copy_from_slice(&(table_offset as u32).to_le_bytes());
        image[directory + 4..directory + 8].copy_from_slice(&(aligned as u32).to_le_bytes());
        image[table_offset..table_offset + 4].copy_from_slice(&length.to_le_bytes());
        image[table_offset + 4..table_offset + 6].copy_from_slice(&0x0200u16.to_le_bytes());
        image[table_offset + 6..table_offset + 8].copy_from_slice(&certificate_type.to_le_bytes());
        image[table_offset + 8..table_offset + 8 + payload.len()].copy_from_slice(payload);
        image
    }

    #[test]
    fn authenticode_hash_excludes_checksum_and_certificate_table() {
        let mut image = pe_with_certificate(0x0002, b"signed-payload");
        let before = authenticode_sha256(&image).expect("authenticode hash");
        let checksum_offset = 0x40 + 24 + 64;
        image[checksum_offset..checksum_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let after_checksum = authenticode_sha256(&image).expect("authenticode hash");
        assert_eq!(before, after_checksum);
        let cert_offset = 0x40 + 24 + 112 + 40;
        image[cert_offset + 8] ^= 0xff;
        let after_certificate = authenticode_sha256(&image).expect("authenticode hash");
        assert_eq!(before, after_certificate);
    }

    #[test]
    fn authenticode_hash_changes_when_hashed_section_bytes_change() {
        let mut image = vec![0u8; 0x400];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        image[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        image[0x54..0x56].copy_from_slice(&224u16.to_le_bytes());
        image[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes());
        image[0x94..0x98].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x138..0x13c].copy_from_slice(&0x100u32.to_le_bytes());
        image[0x13c..0x140].copy_from_slice(&0x200u32.to_le_bytes());
        for byte in &mut image[0x200..0x300] { *byte = 0x41; }
        let first = authenticode_sha256(&image).expect("authenticode hash");
        image[0x250] ^= 0x01;
        let second = authenticode_sha256(&image).expect("authenticode hash");
        assert_ne!(first, second);
    }
    #[test]
    fn absent_certificate_table_is_distinct_from_error() {
        let image = vec![0u8; 0x40];
        assert!(inspect_pe_signature_table(&image).is_err());
        let mut minimal = vec![0u8; 0x40 + 24 + 112];
        minimal[0..2].copy_from_slice(b"MZ");
        minimal[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        minimal[0x40..0x44].copy_from_slice(b"PE\0\0");
        minimal[0x54..0x56].copy_from_slice(&112u16.to_le_bytes());
        minimal[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes());
        let evidence = inspect_pe_signature_table(&minimal).expect("well-formed unsigned PE");
        assert_eq!(evidence.state, SignatureTableState::Absent);
    }

    #[test]
    fn certificate_table_identity_is_exact() {
        let image = pe_with_certificate(0x0002, b"signed-payload");
        let evidence = inspect_pe_signature_table(&image).expect("certificate table");
        assert_eq!(evidence.state, SignatureTableState::Present);
        assert_eq!(evidence.certificates.len(), 1);
        assert_eq!(evidence.certificates[0].certificate_type, 0x0002);
        assert_eq!(evidence.certificates[0].revision, 0x0200);
        assert_eq!(evidence.image_blake3, *blake3::hash(&image).as_bytes());
    }

    #[test]
    fn malformed_certificate_length_fails_closed() {
        let mut image = pe_with_certificate(0x0002, b"x");
        let table_offset = image.len() - 16;
        image[table_offset..table_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect_pe_signature_table(&image).is_err());
    }

    #[test]
    fn verification_binding_rejects_other_image() {
        let evidence = SignatureVerificationEvidence {
            image_blake3: [1; 32],
            certificate_blake3: [2; 32],
            verifier: "sbverify".into(),
            state: SignatureVerificationState::Verified,
            stdout_blake3: [3; 32],
            stderr_blake3: [4; 32],
        };
        assert!(require_verified_signature_image(&evidence, &[9; 32]).is_err());
        assert!(require_verified_signature_image(&evidence, &[1; 32]).is_ok());
    }

    #[test]
    fn failed_verification_is_not_a_pass() {
        let evidence = SignatureVerificationEvidence {
            image_blake3: [1; 32],
            certificate_blake3: [2; 32],
            verifier: "sbverify".into(),
            state: SignatureVerificationState::Failed,
            stdout_blake3: [3; 32],
            stderr_blake3: [4; 32],
        };
        assert!(require_verified_signature_image(&evidence, &[1; 32]).is_err());
    }
    #[test]
    fn signature_table_binding_rejects_other_image() {
        let image = pe_with_certificate(0x0002, b"signed-payload");
        let evidence = inspect_pe_signature_table(&image).expect("certificate table");
        let other = [9u8; 32];
        assert!(require_signature_table_image(&evidence, &other).is_err());
        assert!(require_signature_table_image(&evidence, &evidence.image_blake3).is_ok());
    }
}