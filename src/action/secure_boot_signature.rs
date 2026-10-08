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
    /// Exact certificate payload bytes. Omitted from serialized evidence; the
    /// digest above is the wire-level identity.
    #[serde(skip)]
    pub payload: Vec<u8>,
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

    let mut highest_section_end = size_of_headers;
    let mut previous_section_end = size_of_headers;
    for (ptr_to_raw, size_of_raw) in sections {
        if ptr_to_raw < size_of_headers {
            return Err("PE section raw data overlaps PE headers".into());
        }
        if ptr_to_raw < previous_section_end {
            return Err("PE section raw-data ranges overlap or are out of order".into());
        }

        let end = ptr_to_raw
            .checked_add(size_of_raw)
            .ok_or_else(|| "PE section raw-data range overflows".to_string())?;

        if cert_table_size != 0 {
            let cert_start = cert_table_offset;
            let cert_end = cert_start
                .checked_add(cert_table_size)
                .ok_or_else(|| "PE certificate table range overflows".to_string())?;
            if ptr_to_raw < cert_end && end > cert_start {
                return Err("PE section raw data overlaps the certificate table".into());
            }
        }

        hasher.update(&image[ptr_to_raw..end]);
        highest_section_end = highest_section_end.max(end);
        previous_section_end = end;
    }

    // Authenticode hashes the bytes belonging to the PE headers and the
    // declared section ranges. Bytes beyond the highest section raw-data end
    // are not part of the image hash (and therefore do not receive special
    // treatment merely because a certificate table happens to follow them).
    let _ = highest_section_end;
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
            payload: payload.to_vec(),
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


/// X.509 identity evidence extracted from one PKCS#7 signature's certificate
/// set. Chain membership is determined from the signer certificate through
/// issuer/subject relationships with cryptographic child-signature checks.
#[cfg(feature = "native")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509ChainCertificateEvidence {
    pub signature_index: u32,
    pub certificate_index: u32,
    pub certificate_blake3: [u8; 32],
    pub issuer_blake3: [u8; 32],
    pub serial_blake3: [u8; 32],
    pub tbs_sha256: [u8; 32],
    pub tbs_sha384: [u8; 48],
    pub tbs_sha512: [u8; 64],
    pub is_signer: bool,
    pub is_chain_member: bool,
}

/// Extract X.509 certificates from every embedded PKCS#7 PE signature and
/// identify the signer chain candidates. This is read-only and bounded by the
/// already-parsed PE certificate table.
#[cfg(feature = "native")]
pub fn inspect_x509_signature_chains(
    image: &[u8],
) -> Result<Vec<X509ChainCertificateEvidence>, String> {
    use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
    use openssl::stack::Stack;
    use openssl::x509::X509;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    let table = inspect_pe_signature_table(image)?;
    let mut output = Vec::new();

    for (signature_index, record) in table
        .certificates
        .iter()
        .filter(|record| record.certificate_type == 0x0002)
        .enumerate()
    {
        let pkcs7 = Pkcs7::from_der(&record.payload)
            .map_err(|error| format!("failed to parse embedded PKCS#7 signature {signature_index}: {error}"))?;
        let signed = pkcs7
            .signed()
            .ok_or_else(|| format!("embedded PKCS#7 signature {signature_index} is not SignedData"))?;
        let certificates = signed
            .certificates()
            .ok_or_else(|| format!("embedded PKCS#7 signature {signature_index} contains no certificates"))?;

        let empty_store = Stack::<X509>::new()
            .map_err(|error| format!("failed to create PKCS#7 signer certificate store: {error}"))?;
        let signers = pkcs7
            .signers(&empty_store, Pkcs7Flags::empty())
            .map_err(|error| format!("failed to identify PKCS#7 signers for signature {signature_index}: {error}"))?;
        let signer_digests: Vec<[u8; 32]> = signers
            .iter()
            .map(|cert| {
                let der = cert
                    .to_der()
                    .map_err(|error| format!("failed to serialize signer certificate: {error}"))?;
                Ok(*blake3::hash(&der).as_bytes())
            })
            .collect::<Result<_, String>>()?;

        let mut certs = Vec::with_capacity(certificates.len());
        for cert in certificates.iter() {
            let der = cert
                .to_der()
                .map_err(|error| format!("failed to serialize embedded X.509 certificate: {error}"))?;
            let (_, parsed) = x509_parser::parse_x509_certificate(&der)
                .map_err(|error| format!("failed to parse embedded X.509 certificate: {error}"))?;
            let issuer = parsed.tbs_certificate.issuer.as_ref();
            let serial = cert
                .serial_number()
                .to_bn()
                .map_err(|error| format!("failed to normalize X.509 serial number: {error}"))?
                .to_vec();
            let tbs = parsed.tbs_certificate.as_ref();

            let mut sha256 = Sha256::new();
            sha256.update(tbs);
            let mut sha384 = Sha384::new();
            sha384.update(tbs);
            let mut sha512 = Sha512::new();
            sha512.update(tbs);

            certs.push((
                cert,
                *blake3::hash(&der).as_bytes(),
                *blake3::hash(issuer).as_bytes(),
                *blake3::hash(&serial).as_bytes(),
                sha256.finalize().into(),
                sha384.finalize().into(),
                sha512.finalize().into(),
            ));
        }

        let mut chain_indices = std::collections::BTreeSet::new();
        for signer in signers.iter() {
            let signer_der = signer
                .to_der()
                .map_err(|error| format!("failed to serialize signer certificate: {error}"))?;
            let signer_digest = *blake3::hash(&signer_der).as_bytes();
            let Some(mut current_index) = certs
                .iter()
                .position(|(_, digest, ..)| *digest == signer_digest)
            else {
                return Err(format!(
                    "PKCS#7 signer certificate for signature {signature_index} is absent from the embedded certificate set"
                ));
            };

            loop {
                if !chain_indices.insert(current_index) {
                    break;
                }

                let current = certs[current_index].0;
                let mut parent_candidates = Vec::new();
                for (candidate_index, candidate) in certs.iter().enumerate() {
                    if candidate_index == current_index {
                        continue;
                    }
                    if candidate
                        .0
                        .subject_name()
                        .try_cmp(current.issuer_name())
                        .map_err(|error| format!("failed to compare X.509 issuer/subject names: {error}"))?
                        != std::cmp::Ordering::Equal
                    {
                        continue;
                    }
                    let public_key = candidate
                        .0
                        .public_key()
                        .map_err(|error| format!("failed to extract parent certificate public key: {error}"))?;
                    let signed_by_parent = current
                        .verify(&public_key)
                        .map_err(|error| format!("failed to verify X.509 chain link: {error}"))?;
                    if signed_by_parent {
                        parent_candidates.push(candidate_index);
                    }
                }

                match parent_candidates.as_slice() {
                    [] => break,
                    [only] => current_index = *only,
                    _ => {
                        return Err(format!(
                            "PKCS#7 signature {signature_index} has ambiguous certificate-chain parentage"
                        ))
                    }
                }
            }
        }

        for (certificate_index, (_, certificate_blake3, issuer_blake3, serial_blake3, tbs_sha256, tbs_sha384, tbs_sha512)) in
            certs.iter().enumerate()
        {
            output.push(X509ChainCertificateEvidence {
                signature_index: signature_index as u32,
                certificate_index: certificate_index as u32,
                certificate_blake3: *certificate_blake3,
                issuer_blake3: *issuer_blake3,
                serial_blake3: *serial_blake3,
                tbs_sha256: *tbs_sha256,
                tbs_sha384: *tbs_sha384,
                tbs_sha512: *tbs_sha512,
                is_signer: signer_digests.contains(certificate_blake3),
                is_chain_member: chain_indices.contains(&certificate_index),
            });
        }
    }

    Ok(output)
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
        let optional_size = 240usize;
        let optional = pe_offset + 24;
        let section_table = optional + optional_size;
        let size_of_headers = 0x200usize;
        let raw_offset = size_of_headers;
        let raw_size = 0x100usize;
        let cert_offset = raw_offset + raw_size;
        let cert_length = 8usize + payload.len();
        let cert_padded = (cert_length + 7) & !7usize;
        let mut image = vec![0u8; cert_offset + cert_padded];

        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&(size_of_headers as u32).to_le_bytes());
        image[optional + 64..optional + 68].copy_from_slice(&0x12345678u32.to_le_bytes());
        let cert_dir = optional + 144;
        image[cert_dir..cert_dir + 4].copy_from_slice(&(cert_offset as u32).to_le_bytes());
        image[cert_dir + 4..cert_dir + 8].copy_from_slice(&(cert_padded as u32).to_le_bytes());

        image[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
        image[section_table + 8..section_table + 12].copy_from_slice(&(raw_size as u32).to_le_bytes());
        image[section_table + 12..section_table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section_table + 16..section_table + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        image[section_table + 20..section_table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
        image[raw_offset..raw_offset + raw_size].fill(0x41);

        image[cert_offset..cert_offset + 4].copy_from_slice(&(cert_length as u32).to_le_bytes());
        image[cert_offset + 4..cert_offset + 6].copy_from_slice(&0x0200u16.to_le_bytes());
        image[cert_offset + 6..cert_offset + 8].copy_from_slice(&certificate_type.to_le_bytes());
        image[cert_offset + 8..cert_offset + 8 + payload.len()].copy_from_slice(payload);
        image
    }

    fn pe_with_two_sections_and_overlay() -> Vec<u8> {
        let pe_offset = 0x40usize;
        let optional_size = 240usize;
        let optional = pe_offset + 24;
        let section_table = optional + optional_size;
        let size_of_headers = 0x200usize;
        let first_offset = 0x200usize;
        let first_size = 0x100usize;
        let second_offset = 0x400usize;
        let second_size = 0x100usize;
        let cert_offset = 0x500usize;
        let cert_payload = b"timestamped-signature";
        let cert_length = 8usize + cert_payload.len();
        let cert_padded = (cert_length + 7) & !7usize;
        let overlay_end = cert_offset + cert_padded + 0x40;
        let mut image = vec![0u8; overlay_end];

        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\\0\\0");
        let coff = pe_offset + 4;
        image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&(size_of_headers as u32).to_le_bytes());
        let cert_dir = optional + 144;
        image[cert_dir..cert_dir + 4].copy_from_slice(&(cert_offset as u32).to_le_bytes());
        image[cert_dir + 4..cert_dir + 8].copy_from_slice(&(cert_padded as u32).to_le_bytes());

        let first_header = section_table;
        image[first_header..first_header + 8].copy_from_slice(b".text\\0\\0\\0");
        image[first_header + 16..first_header + 20].copy_from_slice(&(first_size as u32).to_le_bytes());
        image[first_header + 20..first_header + 24].copy_from_slice(&(first_offset as u32).to_le_bytes());
        let second_header = section_table + 40;
        image[second_header..second_header + 8].copy_from_slice(b".data\\0\\0\\0");
        image[second_header + 16..second_header + 20].copy_from_slice(&(second_size as u32).to_le_bytes());
        image[second_header + 20..second_header + 24].copy_from_slice(&(second_offset as u32).to_le_bytes());

        image[first_offset..first_offset + first_size].fill(0x41);
        image[first_offset + first_size..second_offset].fill(0x47);
        image[second_offset..second_offset + second_size].fill(0x42);
        image[cert_offset..cert_offset + 4].copy_from_slice(&(cert_length as u32).to_le_bytes());
        image[cert_offset + 4..cert_offset + 6].copy_from_slice(&0x0200u16.to_le_bytes());
        image[cert_offset + 6..cert_offset + 8].copy_from_slice(&0x0002u16.to_le_bytes());
        image[cert_offset + 8..cert_offset + 8 + cert_payload.len()].copy_from_slice(cert_payload);
        image[cert_offset + cert_padded..].fill(0x4f);
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
        let cert_offset = 0x300;
        image[cert_offset + 8] ^= 0xff;
        let after_certificate = authenticode_sha256(&image).expect("authenticode hash");
        assert_eq!(before, after_certificate);
    }

    #[test]
    fn authenticode_hash_excludes_section_gaps_and_post_section_overlay() {
        let image = pe_with_two_sections_and_overlay();
        let first = authenticode_sha256(&image).expect("authenticode hash");

        let mut gap_changed = image.clone();
        gap_changed[0x300] ^= 0x01;
        assert_eq!(
            authenticode_sha256(&gap_changed).expect("gap-mutated authenticode hash"),
            first
        );

        let mut overlay_changed = image.clone();
        overlay_changed[0x520] ^= 0x01;
        assert_eq!(
            authenticode_sha256(&overlay_changed).expect("overlay-mutated authenticode hash"),
            first
        );

        let mut first_section_changed = image.clone();
        first_section_changed[0x250] ^= 0x01;
        assert_ne!(
            authenticode_sha256(&first_section_changed).expect("first-section authenticode hash"),
            first
        );

        let mut second_section_changed = image.clone();
        second_section_changed[0x450] ^= 0x01;
        assert_ne!(
            authenticode_sha256(&second_section_changed).expect("second-section authenticode hash"),
            first
        );
    }

    #[test]
    fn authenticode_hash_changes_when_hashed_section_bytes_change() {
        let mut image = pe_with_certificate(0x0002, b"signed-payload");
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

    #[cfg(feature = "native")]
    #[test]
    fn pkcs7_fixture_extracts_signer_chain_identity() {
        use openssl::hash::MessageDigest;
        use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::stack::Stack;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).expect("test RSA key");
        let key = PKey::from_rsa(rsa).expect("test private key");

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", "Nixward PKCS7 Fixture")
            .expect("CN");
        let name = name.build();

        let mut builder = X509Builder::new().expect("certificate builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("public key");

        let serial = openssl::asn1::Asn1Integer::from_bn(
            &openssl::bn::BigNum::from_u32(7).expect("serial"),
        )
        .expect("serial number");
        builder.set_serial_number(&serial).expect("serial number");
        builder
            .sign(&key, MessageDigest::sha256())
            .expect("certificate signature");
        let certificate = builder.build();

        let certificates = Stack::new().expect("certificate stack");
        let pkcs7 = Pkcs7::sign(
            &certificate,
            &key,
            &certificates,
            b"nixward-chain-fixture",
            Pkcs7Flags::BINARY,
        )
        .expect("PKCS7 signing");
        let payload = pkcs7.to_der().expect("PKCS7 DER");
        let image = pe_with_certificate(0x0002, &payload);

        let evidence = inspect_x509_signature_chains(&image).expect("chain evidence");
        assert!(!evidence.is_empty());
        assert_eq!(
            evidence.iter().filter(|certificate| certificate.is_signer).count(),
            1
        );
        assert_eq!(
            evidence
                .iter()
                .filter(|certificate| certificate.is_chain_member)
                .count(),
            1
        );
        assert_eq!(
            evidence
                .iter()
                .find(|certificate| certificate.is_signer)
                .map(|certificate| certificate.certificate_blake3),
            Some(*blake3::hash(&certificate.to_der().expect("certificate DER")).as_bytes())
        );
    }

}