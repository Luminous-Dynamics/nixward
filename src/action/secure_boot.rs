// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Read-only UEFI Secure Boot state evidence.
//!
//! Secure Boot policy state is intentionally separate from UKI identity and
//! signature validity. This module observes firmware state only.

use serde::{Deserialize, Serialize};
use super::secure_boot_signature::authenticode_sha256;

const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const EFI_IMAGE_SECURITY_DATABASE_GUID: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";
const EFI_VARS_DIR: &str = "/sys/firmware/efi/efivars";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureListKind {
    Sha256ImageHash,
    X509Certificate,
    X509TbsSha256,
    X509TbsSha384,
    X509TbsSha512,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDatabaseRecord {
    pub kind: SignatureListKind,
    pub signature_size: u32,
    pub signature_data_blake3: [u8; 32],
    pub owner: [u8; 16],
    pub image_authenticode_sha256: Option<[u8; 32]>,
    pub certificate_der_blake3: Option<[u8; 32]>,
    #[serde(skip)]
    pub certificate_der: Option<Vec<u8>>,
    pub certificate_tbs_hash: Option<Vec<u8>>,
    pub revocation_time: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDatabaseMatchEvidence {
    pub db_records: Vec<SignatureDatabaseRecord>,
    pub dbx_records: Vec<SignatureDatabaseRecord>,
    pub image_authenticode_sha256: [u8; 32],
    pub direct_db_authenticode_hash_match: bool,
    pub direct_dbx_authenticode_hash_match: bool,
    pub exact_certificate_in_db: bool,
    pub exact_certificate_in_dbx: bool,
    pub exact_certificate_tbs_hash_in_db: bool,
    pub exact_certificate_tbs_hash_in_dbx: bool,
    pub matched_dbx_tbs_revocation_time: Option<[u8; 16]>,
    pub certificate_chain_authorization: Option<bool>,
    pub observed_at_ms: Option<u64>,
    pub evidence_digest: Option<[u8; 32]>,
}

impl SignatureDatabaseMatchEvidence {
    pub fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let preimage = serde_json::to_vec(&(
            &self.db_records,
            &self.dbx_records,
            self.image_authenticode_sha256,
            self.direct_db_authenticode_hash_match,
            self.direct_dbx_authenticode_hash_match,
            self.exact_certificate_in_db,
            self.exact_certificate_in_dbx,
            self.exact_certificate_tbs_hash_in_db,
            self.exact_certificate_tbs_hash_in_dbx,
            self.matched_dbx_tbs_revocation_time,
            self.certificate_chain_authorization,
            observed_at_ms,
        ))
        .map_err(|error| format!("failed to serialize signature-database evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootDatabaseState {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootDatabaseEvidence {
    pub db_state: SecureBootDatabaseState,
    pub db_payload_blake3: Option<[u8; 32]>,
    pub dbx_state: SecureBootDatabaseState,
    pub dbx_payload_blake3: Option<[u8; 32]>,
    pub observed_at_ms: Option<u64>,
    pub evidence_digest: Option<[u8; 32]>,
}

impl SecureBootDatabaseEvidence {
    pub fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let preimage = serde_json::to_vec(&(
            self.db_state,
            self.db_payload_blake3,
            self.dbx_state,
            self.dbx_payload_blake3,
            observed_at_ms,
        ))
        .map_err(|error| format!("failed to serialize Secure Boot database evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectTrustDisposition {
    ForbiddenByAuthenticodeHash,
    ForbiddenByExactCertificate,
    PotentialX509TbsRevocation,
    ForbiddenByDbxTbsRevocation,
    AuthenticodeHashInDb,
    ExactCertificateInDbx,
    ExactCertificateInDb,
    NoDirectMatch,
    UnknownUnsupportedRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootState {
    Enabled,
    Disabled,
    SetupMode,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootSnapshotEvidence {
    pub state: SecureBootState,
    pub secure_boot_variable: Option<bool>,
    pub setup_mode_variable: Option<bool>,
    pub db_state: SecureBootDatabaseState,
    pub db_payload_blake3: Option<[u8; 32]>,
    pub dbx_state: SecureBootDatabaseState,
    pub dbx_payload_blake3: Option<[u8; 32]>,
    pub observed_at_ms: Option<u64>,
    pub evidence_digest: Option<[u8; 32]>,
}

impl SecureBootSnapshotEvidence {
    fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let preimage = serde_json::to_vec(&(
            self.state,
            self.secure_boot_variable,
            self.setup_mode_variable,
            self.db_state,
            self.db_payload_blake3,
            self.dbx_state,
            self.dbx_payload_blake3,
            observed_at_ms,
        ))
        .map_err(|error| format!("failed to serialize Secure Boot snapshot: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
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
        (Some(false), Some(true)) => SecureBootState::SetupMode,
        (Some(false), Some(false)) => SecureBootState::Disabled,
        (Some(true), Some(true)) => SecureBootState::Unknown,
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

const EFI_CERT_SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
const EFI_CERT_X509_SHA256_GUID: [u8; 16] = [
    0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96, 0x79, 0x40, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed,
];
const EFI_CERT_X509_SHA384_GUID: [u8; 16] = [
    0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80, 0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b,
];
const EFI_CERT_X509_SHA512_GUID: [u8; 16] = [
    0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25, 0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d,
];

pub fn parse_signature_database(payload: &[u8]) -> Result<Vec<SignatureDatabaseRecord>, String> {
    let mut records = Vec::new();
    let mut cursor = 0usize;
    while cursor < payload.len() {
        if payload.len() - cursor < 28 {
            return Err("EFI signature database contains a truncated SignatureList header".into());
        }
        let list_size = read_u32_le(payload, cursor + 16)? as usize;
        let header_size = read_u32_le(payload, cursor + 20)? as usize;
        let signature_size = read_u32_le(payload, cursor + 24)? as usize;
        if list_size < 28 || header_size > list_size - 28 || signature_size == 0 {
            return Err("EFI signature database contains invalid SignatureList dimensions".into());
        }
        let list_end = cursor.checked_add(list_size).ok_or_else(|| "SignatureList size overflows".to_string())?;
        if list_end > payload.len() {
            return Err("EFI SignatureList extends past database payload".into());
        }
        let records_bytes = list_size - 28 - header_size;
        if records_bytes == 0 || records_bytes % signature_size != 0 {
            return Err("EFI SignatureList records do not divide evenly by SignatureSize".into());
        }
        let sig_start = cursor + 28 + header_size;
        let kind = if payload[cursor..cursor + 16] == EFI_CERT_SHA256_GUID {
            SignatureListKind::Sha256ImageHash
        } else if payload[cursor..cursor + 16] == EFI_CERT_X509_GUID {
            SignatureListKind::X509Certificate
        } else if payload[cursor..cursor + 16] == EFI_CERT_X509_SHA256_GUID {
            SignatureListKind::X509TbsSha256
        } else if payload[cursor..cursor + 16] == EFI_CERT_X509_SHA384_GUID {
            SignatureListKind::X509TbsSha384
        } else if payload[cursor..cursor + 16] == EFI_CERT_X509_SHA512_GUID {
            SignatureListKind::X509TbsSha512
        } else {
            SignatureListKind::Unsupported
        };
        let count = records_bytes / signature_size;
        for index in 0..count {
            let start = sig_start + index * signature_size;
            let end = start + signature_size;
            let data = &payload[start..end];
            if data.len() < 16 {
                return Err("EFI signature record is missing SignatureOwner".into());
            }
            let mut owner = [0u8; 16];
            owner.copy_from_slice(&data[..16]);
            let (image_authenticode_sha256, certificate_der_blake3, certificate_der, certificate_tbs_hash, revocation_time) = match kind {
                SignatureListKind::Sha256ImageHash if data.len() == 48 => {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&data[16..48]);
                    (Some(hash), None, None, None, None)
                }
                SignatureListKind::X509Certificate if data.len() >= 17 => {
                    (None, Some(*blake3::hash(&data[16..]).as_bytes()), Some(data[16..].to_vec()), None, None)
                }
                SignatureListKind::X509TbsSha256 if data.len() == 64 => {
                    let mut hash = Vec::from(&data[16..48]);
                    let mut time = [0u8; 16];
                    time.copy_from_slice(&data[48..64]);
                    (None, None, None, Some(std::mem::take(&mut hash)), Some(time))
                }
                SignatureListKind::X509TbsSha384 if data.len() == 80 => {
                    let hash = data[16..64].to_vec();
                    let mut time = [0u8; 16];
                    time.copy_from_slice(&data[64..80]);
                    (None, None, None, Some(hash), Some(time))
                }
                SignatureListKind::X509TbsSha512 if data.len() == 96 => {
                    let hash = data[16..80].to_vec();
                    let mut time = [0u8; 16];
                    time.copy_from_slice(&data[80..96]);
                    (None, None, None, Some(hash), Some(time))
                }
                SignatureListKind::Unsupported => (None, None, None, None, None),
                SignatureListKind::Sha256ImageHash
                | SignatureListKind::X509Certificate
                | SignatureListKind::X509TbsSha256
                | SignatureListKind::X509TbsSha384
                | SignatureListKind::X509TbsSha512 => {
                    return Err("EFI signature record has an invalid SignatureSize".into())
                }
            };
            records.push(SignatureDatabaseRecord {
                kind,
                signature_size: signature_size as u32,
                signature_data_blake3: *blake3::hash(data).as_bytes(),
                owner,
                image_authenticode_sha256,
                certificate_der_blake3,
                certificate_der,
                certificate_tbs_hash,
                revocation_time,
            });
        }
        cursor = list_end;
    }
    Ok(records)
}

pub fn image_authenticode_sha256(image: &[u8]) -> Result<[u8; 32], String> {
    authenticode_sha256(image)
}

pub fn match_secure_boot_databases(
    db_payload: &[u8],
    dbx_payload: &[u8],
    image_authenticode_sha256: [u8; 32],
    signer_certificate_der: Option<&[u8]>,
    signer_certificate_tbs_hashes: &[Vec<u8>],
) -> Result<SignatureDatabaseMatchEvidence, String> {
    let db_records = parse_signature_database(db_payload)?;
    let dbx_records = parse_signature_database(dbx_payload)?;
    let signer_digest = signer_certificate_der.map(|bytes| *blake3::hash(bytes).as_bytes());
    let mut matched_dbx_tbs_revocation_time = None;
    for record in &dbx_records {
        let Some(hash) = record.certificate_tbs_hash.as_ref() else {
            continue;
        };
        if !signer_certificate_tbs_hashes
            .iter()
            .any(|candidate| candidate == hash)
        {
            continue;
        }
        if record.revocation_time == Some([0; 16]) {
            matched_dbx_tbs_revocation_time = record.revocation_time;
            break;
        }
        if matched_dbx_tbs_revocation_time.is_none() {
            matched_dbx_tbs_revocation_time = record.revocation_time;
        }
    }
    Ok(SignatureDatabaseMatchEvidence {
        direct_db_authenticode_hash_match: db_records.iter().any(|record| record.image_authenticode_sha256 == Some(image_authenticode_sha256)),
        direct_dbx_authenticode_hash_match: dbx_records.iter().any(|record| record.image_authenticode_sha256 == Some(image_authenticode_sha256)),
        exact_certificate_in_db: signer_digest.is_some_and(|digest| db_records.iter().any(|record| record.certificate_der_blake3 == Some(digest))),
        exact_certificate_in_dbx: signer_digest.is_some_and(|digest| dbx_records.iter().any(|record| record.certificate_der_blake3 == Some(digest))),
        exact_certificate_tbs_hash_in_db: db_records.iter().any(|record| {
            record.certificate_tbs_hash.as_ref().is_some_and(|hash| signer_certificate_tbs_hashes.iter().any(|candidate| candidate == hash))
        }),
        exact_certificate_tbs_hash_in_dbx: matched_dbx_tbs_revocation_time.is_some()
            || dbx_records.iter().any(|record| {
                record.certificate_tbs_hash.as_ref().is_some_and(|hash| signer_certificate_tbs_hashes.iter().any(|candidate| candidate == hash))
            }),
        matched_dbx_tbs_revocation_time,
        db_records,
        dbx_records,
        image_authenticode_sha256,
        certificate_chain_authorization: None,
        observed_at_ms: None,
        evidence_digest: None,
    })
}

#[cfg(feature = "native")]
pub fn match_secure_boot_databases_for_image(
    db_payload: &[u8],
    dbx_payload: &[u8],
    image: &[u8],
    signer_certificate_der: Option<&[u8]>,
    signer_certificate_tbs_hashes: &[Vec<u8>],
) -> Result<SignatureDatabaseMatchEvidence, String> {
    let image_authenticode_sha256 = image_authenticode_sha256(image)?;
    match_secure_boot_databases(
        db_payload,
        dbx_payload,
        image_authenticode_sha256,
        signer_certificate_der,
        signer_certificate_tbs_hashes,
    )
}

pub fn derive_direct_trust_disposition(
    evidence: &SignatureDatabaseMatchEvidence,
) -> DirectTrustDisposition {
    // Definite image-hash and exact X.509 certificate matches in dbx are
    // immediate veto evidence. Unsupported rules dominate uncertain outcomes.
    // X.509 TBS-hash records can carry a revocation time, so an exact match
    // requires signature-timestamp evaluation before it can be classified as
    // allowed or forbidden.
    if evidence.direct_dbx_authenticode_hash_match {
        return DirectTrustDisposition::ForbiddenByAuthenticodeHash;
    }
    if evidence.exact_certificate_in_dbx {
        return DirectTrustDisposition::ForbiddenByExactCertificate;
    }
    if evidence.dbx_records.iter().any(|record| record.kind == SignatureListKind::Unsupported) {
        return DirectTrustDisposition::UnknownUnsupportedRecord;
    }
    if evidence.exact_certificate_tbs_hash_in_dbx {
        if evidence.matched_dbx_tbs_revocation_time == Some([0; 16]) {
            return DirectTrustDisposition::ForbiddenByDbxTbsRevocation;
        }
        return DirectTrustDisposition::PotentialX509TbsRevocation;
    }
    if evidence.direct_db_authenticode_hash_match {
        return DirectTrustDisposition::AuthenticodeHashInDb;
    }
    if evidence.exact_certificate_in_db || evidence.exact_certificate_tbs_hash_in_db {
        return DirectTrustDisposition::ExactCertificateInDb;
    }
    if evidence.db_records.iter().any(|record| record.kind == SignatureListKind::Unsupported) {
        return DirectTrustDisposition::UnknownUnsupportedRecord;
    }
    DirectTrustDisposition::NoDirectMatch
}
fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset.checked_add(4).ok_or_else(|| "u32 read overflows".to_string())?;
    let slice = bytes.get(offset..end).ok_or_else(|| "EFI signature database is truncated".to_string())?;
    Ok(u32::from_le_bytes(slice.try_into().expect("4-byte slice")))
}

pub fn build_secure_boot_database_evidence(
    db_payload: Option<&[u8]>,
    dbx_payload: Option<&[u8]>,
) -> SecureBootDatabaseEvidence {
    SecureBootDatabaseEvidence {
        db_state: if db_payload.is_some() {
            SecureBootDatabaseState::Present
        } else {
            SecureBootDatabaseState::Absent
        },
        db_payload_blake3: db_payload.map(|bytes| *blake3::hash(bytes).as_bytes()),
        dbx_state: if dbx_payload.is_some() {
            SecureBootDatabaseState::Present
        } else {
            SecureBootDatabaseState::Absent
        },
        dbx_payload_blake3: dbx_payload.map(|bytes| *blake3::hash(bytes).as_bytes()),
        observed_at_ms: None,
        evidence_digest: None,
    }
}

#[cfg(feature = "native")]
pub fn observe_secure_boot_databases() -> Result<SecureBootDatabaseEvidence, String> {
    let db = read_efi_database("db")?;
    let dbx = read_efi_database("dbx")?;
    let evidence = build_secure_boot_database_evidence(db.as_deref(), dbx.as_deref());
    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock could not produce observation timestamp: {error}"))?
        .as_millis() as u64;
    evidence
        .with_observation_metadata(observed_at_ms)
        .map_err(|error| format!("failed to digest Secure Boot database observation: {error}"))
}

#[cfg(feature = "native")]
pub fn observe_secure_boot_snapshot() -> Result<SecureBootSnapshotEvidence, String> {
    let secure_boot = read_global_efi_bool("SecureBoot")?;
    let setup_mode = read_global_efi_bool("SetupMode")?;
    let db = read_efi_database("db")?;
    let dbx = read_efi_database("dbx")?;
    let evidence = SecureBootSnapshotEvidence {
        state: derive_secure_boot_state(secure_boot, setup_mode),
        secure_boot_variable: secure_boot,
        setup_mode_variable: setup_mode,
        db_state: if db.is_some() {
            SecureBootDatabaseState::Present
        } else {
            SecureBootDatabaseState::Absent
        },
        db_payload_blake3: db.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes()),
        dbx_state: if dbx.is_some() {
            SecureBootDatabaseState::Present
        } else {
            SecureBootDatabaseState::Absent
        },
        dbx_payload_blake3: dbx.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes()),
        observed_at_ms: None,
        evidence_digest: None,
    };
    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock could not produce observation timestamp: {error}"))?
        .as_millis() as u64;
    evidence.with_observation_metadata(observed_at_ms)
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
fn read_efi_regular_file_no_follow(
    path: &std::path::Path,
) -> Result<Option<Vec<u8>>, String> {
    use nix::errno::Errno;
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::{fstat, Mode, SFlag};
    use nix::unistd::{close, read};

    let fd = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to securely open EFI variable {} without symlink following: {error}",
                path.display()
            ))
        }
    };

    let read_result: Result<Vec<u8>, String> = (|| {
        let metadata = fstat(fd)
            .map_err(|error| format!("failed to inspect EFI variable {}: {error}", path.display()))?;
        if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
            return Err(format!(
                "EFI variable {} is not a regular file",
                path.display()
            ));
        }

        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match read(fd, &mut buffer) {
                Ok(0) => break,
                Ok(read_len) => bytes.extend_from_slice(&buffer[..read_len]),
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(format!(
                        "failed to read EFI variable {}: {error}",
                        path.display()
                    ))
                }
            }
        }
        Ok(bytes)
    })();

    let close_result = close(fd);
    match (read_result, close_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "failed to close EFI variable {} after read: {error}",
            path.display()
        )),
        (Ok(bytes), Ok(())) => Ok(Some(bytes)),
    }
}

#[cfg(feature = "native")]
fn read_efi_database(name: &str) -> Result<Option<Vec<u8>>, String> {
    let path = std::path::PathBuf::from(format!(
        "{}/{}-{}",
        EFI_VARS_DIR, name, EFI_IMAGE_SECURITY_DATABASE_GUID
    ));
    let Some(bytes) = read_efi_regular_file_no_follow(&path)? else {
        return Ok(None);
    };
    if bytes.len() < 4 {
        return Err(format!(
            "EFI database {} is missing its attribute header",
            path.display()
        ));
    }
    Ok(Some(bytes[4..].to_vec()))
}

#[cfg(feature = "native")]
fn read_efi_timestamp_database() -> Result<Option<Vec<u8>>, String> {
    let path = std::path::PathBuf::from(format!(
        "{}/dbt-{}",
        EFI_VARS_DIR, EFI_IMAGE_SECURITY_DATABASE_GUID
    ));
    let Some(bytes) = read_efi_regular_file_no_follow(&path)? else {
        return Ok(None);
    };
    if bytes.len() < 4 {
        return Err(format!(
            "EFI timestamp database {} is missing its attribute header",
            path.display()
        ));
    }
    Ok(Some(bytes[4..].to_vec()))
}

#[cfg(feature = "native")]
fn timestamp_database_certificate_digests(
    dbt_payload: Option<&[u8]>,
) -> Result<Vec<[u8; 32]>, String> {
    let Some(payload) = dbt_payload else {
        return Ok(Vec::new());
    };
    Ok(parse_signature_database(payload)?
        .into_iter()
        .filter(|record| record.kind == SignatureListKind::X509Certificate)
        .filter_map(|record| record.certificate_der_blake3)
        .collect())
}

#[cfg(feature = "native")]
fn read_global_efi_bool(name: &str) -> Result<Option<bool>, String> {
    let path = std::path::PathBuf::from(format!("{}/{}-{}", EFI_VARS_DIR, name, EFI_GLOBAL_GUID));
    let Some(bytes) = read_efi_regular_file_no_follow(&path)? else {
        return Ok(None);
    };
    parse_efi_boolean_payload(&bytes).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbCertificateVerificationState {
    VerifiedAgainstDbCertificate,
    NoMatchingDbCertificate,
    ForbiddenByDbxImageHash,
    ForbiddenByDbxCertificateChain,
    ForbiddenByDbxTbsRevocation,
    PotentialDbxTbsRevocation,
    UnknownDbxCertificateRules,
    MissingSecureBootDatabase,
    DatabaseChangedDuringVerification,
    ToolUnavailable,
    ImageChangedDuringVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbCertificateVerificationEvidence {
    pub image_blake3: [u8; 32],
    pub image_authenticode_sha256: [u8; 32],
    pub image_chain_certificate_digests: Vec<[u8; 32]>,
    pub image_signer_certificate_digests: Vec<[u8; 32]>,
    pub verified_db_anchor_certificate_digests: Vec<[u8; 32]>,
    pub db_certificate_digests: Vec<[u8; 32]>,
    pub dbx_certificate_digests: Vec<[u8; 32]>,
    pub verifying_db_certificate: Option<[u8; 32]>,
    pub verifying_dbx_certificate: Option<[u8; 32]>,
    pub dbx_chain_identity_match: Option<[u8; 32]>,
    pub dbx_chain_tbs_hash_match: Option<[u8; 32]>,
    pub dbx_chain_tbs_revocation_times: Vec<[u8; 16]>,
    pub db_payload_blake3: Option<[u8; 32]>,
    pub dbx_payload_blake3: Option<[u8; 32]>,
    pub dbt_certificate_digests: Vec<[u8; 32]>,
    pub dbt_payload_blake3: Option<[u8; 32]>,
    pub timestamp_database_stability: Option<bool>,
    pub database_stability: Option<bool>,
    pub state: DbCertificateVerificationState,
    pub verifier: String,
    pub stdout_blake3: [u8; 32],
    pub stderr_blake3: [u8; 32],
    pub observed_at_ms: Option<u64>,
    pub evidence_digest: Option<[u8; 32]>,
}

impl DbCertificateVerificationEvidence {
    pub fn with_observation_metadata(mut self, observed_at_ms: u64) -> Result<Self, String> {
        let mut preimage = Vec::new();
        preimage.push(b'[');
        macro_rules! append_json {
            ($value:expr) => {{
                if preimage.len() > 1 {
                    preimage.push(b',');
                }
                serde_json::to_writer(&mut preimage, &$value).map_err(|error| {
                    format!("failed to serialize DB certificate verification evidence: {error}")
                })?;
            }};
        }
        append_json!(self.image_blake3);
        append_json!(self.image_authenticode_sha256);
        append_json!(&self.image_chain_certificate_digests);
        append_json!(&self.image_signer_certificate_digests);
        append_json!(&self.verified_db_anchor_certificate_digests);
        append_json!(&self.db_certificate_digests);
        append_json!(&self.dbx_certificate_digests);
        append_json!(self.verifying_db_certificate);
        append_json!(self.verifying_dbx_certificate);
        append_json!(self.dbx_chain_identity_match);
        append_json!(self.dbx_chain_tbs_hash_match);
        append_json!(&self.dbx_chain_tbs_revocation_times);
        append_json!(self.db_payload_blake3);
        append_json!(self.dbx_payload_blake3);
        append_json!(&self.dbt_certificate_digests);
        append_json!(self.dbt_payload_blake3);
        append_json!(self.timestamp_database_stability);
        append_json!(self.database_stability);
        append_json!(self.state);
        append_json!(&self.verifier);
        append_json!(self.stdout_blake3);
        append_json!(self.stderr_blake3);
        append_json!(observed_at_ms);
        preimage.push(b']');
        .map_err(|error| format!("failed to serialize DB certificate verification evidence: {error}"))?;
        self.observed_at_ms = Some(observed_at_ms);
        self.evidence_digest = Some(*blake3::hash(&preimage).as_bytes());
        Ok(self)
    }
}

#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateVerifierRunState {
    Verified,
    Failed,
    ToolUnavailable,
    ImageChanged,
}

#[cfg(feature = "native")]
struct CertificateVerifierRun {
    state: CertificateVerifierRunState,
    stdout_blake3: [u8; 32],
    stderr_blake3: [u8; 32],
}

#[cfg(feature = "native")]
fn run_sbverify_against_certificate(
    image_path: &std::path::Path,
    certificate_der: &[u8],
) -> Result<CertificateVerifierRun, String> {
    let image_before = std::fs::read(image_path)
        .map_err(|error| format!("failed to read UKI {}: {error}", image_path.display()))?;
    let image_before_hash = *blake3::hash(&image_before).as_bytes();

    let mut image_snapshot = tempfile::NamedTempFile::new()
        .map_err(|error| format!("failed to create temporary image snapshot: {error}"))?;
    use std::io::Write;
    image_snapshot
        .write_all(&image_before)
        .map_err(|error| format!("failed to write temporary image snapshot: {error}"))?;
    image_snapshot
        .flush()
        .map_err(|error| format!("failed to flush temporary image snapshot: {error}"))?;

    let mut certificate_snapshot = tempfile::NamedTempFile::new()
        .map_err(|error| format!("failed to create temporary certificate file: {error}"))?;
    certificate_snapshot
        .write_all(pem_encode_certificate(certificate_der).as_bytes())
        .map_err(|error| format!("failed to write temporary certificate file: {error}"))?;
    certificate_snapshot
        .flush()
        .map_err(|error| format!("failed to flush temporary certificate file: {error}"))?;

    let output = match std::process::Command::new("sbverify")
        .args(["--cert"])
        .arg(certificate_snapshot.path())
        .arg(image_snapshot.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CertificateVerifierRun {
                state: CertificateVerifierRunState::ToolUnavailable,
                stdout_blake3: *blake3::hash(&[]).as_bytes(),
                stderr_blake3: *blake3::hash(error.to_string().as_bytes()).as_bytes(),
            });
        }
        Err(error) => return Err(format!("failed to execute sbverify: {error}")),
    };

    let image_after = std::fs::read(image_path)
        .map_err(|error| format!("failed to re-read UKI {}: {error}", image_path.display()))?;
    let image_after_hash = *blake3::hash(&image_after).as_bytes();

    Ok(CertificateVerifierRun {
        state: if image_after_hash != image_before_hash {
            CertificateVerifierRunState::ImageChanged
        } else if output.status.success() {
            CertificateVerifierRunState::Verified
        } else {
            CertificateVerifierRunState::Failed
        },
        stdout_blake3: *blake3::hash(&output.stdout).as_bytes(),
        stderr_blake3: *blake3::hash(&output.stderr).as_bytes(),
    })
}

#[cfg(feature = "native")]
fn db_certificate_verification_base_evidence(
    image_blake3: [u8; 32],
    image_authenticode_sha256: [u8; 32],
    db_payload: &[u8],
    dbx_payload: &[u8],
    db_records: &[SignatureDatabaseRecord],
    dbx_records: &[SignatureDatabaseRecord],
) -> DbCertificateVerificationEvidence {
    DbCertificateVerificationEvidence {
        image_blake3,
        image_authenticode_sha256,
        image_chain_certificate_digests: Vec::new(),
        image_signer_certificate_digests: Vec::new(),
        verified_db_anchor_certificate_digests: Vec::new(),
        db_certificate_digests: db_records
            .iter()
            .filter_map(|record| record.certificate_der_blake3)
            .collect(),
        dbx_certificate_digests: dbx_records
            .iter()
            .filter_map(|record| record.certificate_der_blake3)
            .collect(),
        verifying_db_certificate: None,
        verifying_dbx_certificate: None,
        dbx_chain_identity_match: None,
        dbx_chain_tbs_hash_match: None,
        dbx_chain_tbs_revocation_times: Vec::new(),
        db_payload_blake3: Some(*blake3::hash(db_payload).as_bytes()),
        dbx_payload_blake3: Some(*blake3::hash(dbx_payload).as_bytes()),
        dbt_certificate_digests: Vec::new(),
        dbt_payload_blake3: None,
        timestamp_database_stability: None,
        database_stability: None,
        state: DbCertificateVerificationState::NoMatchingDbCertificate,
        verifier: "sbverify".into(),
        stdout_blake3: *blake3::hash(&[]).as_bytes(),
        stderr_blake3: *blake3::hash(&[]).as_bytes(),
        observed_at_ms: None,
        evidence_digest: None,
    }
}

#[cfg(feature = "native")]
fn finalize_image_bound_verification(
    image_path: &std::path::Path,
    mut evidence: DbCertificateVerificationEvidence,
) -> Result<DbCertificateVerificationEvidence, String> {
    let image = std::fs::read(image_path)
        .map_err(|error| format!("failed to re-read UKI {} after verification: {error}", image_path.display()))?;
    let observed_hash = *blake3::hash(&image).as_bytes();
    if observed_hash != evidence.image_blake3 {
        evidence.image_chain_certificate_digests.clear();
        evidence.image_signer_certificate_digests.clear();
        evidence.verifying_db_certificate = None;
        evidence.verifying_dbx_certificate = None;
        evidence.dbx_chain_identity_match = None;
        evidence.dbx_chain_tbs_hash_match = None;
        evidence.database_stability = Some(false);
        evidence.state = DbCertificateVerificationState::ImageChangedDuringVerification;
        evidence.stderr_blake3 =
            *blake3::hash(b"exact UKI bytes changed across verification boundary").as_bytes();
    }
    Ok(evidence)
}

#[cfg(feature = "native")]
fn dbx_x509_record_matches_certificate(
    record: &SignatureDatabaseRecord,
    certificate_der: &[u8],
) -> Result<bool, String> {
    use sha2::Digest;
    let Some(record_der) = record.certificate_der.as_deref() else {
        return Ok(false);
    };

    let (_, record_certificate) = x509_parser::parse_x509_certificate(record_der)
        .map_err(|error| format!("failed to parse dbx X.509 certificate: {error}"))?;
    let (_, candidate_certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|error| format!("failed to parse signing X.509 certificate: {error}"))?;

    let record_issuer = *blake3::hash(
        &openssl::x509::X509::from_der(record_der)
            .map_err(|error| format!("failed to parse record X.509 certificate with OpenSSL: {error}"))?
            .issuer_name()
            .to_der()
            .map_err(|error| format!("failed to serialize record X.509 issuer name: {error}"))?,
    )
    .as_bytes();
    let record_serial =
        *blake3::hash(record_certificate.tbs_certificate.raw_serial()).as_bytes();
    let mut record_tbs_hasher = sha2::Sha256::new();
    record_tbs_hasher.update(record_certificate.tbs_certificate.as_ref());
    let record_tbs_sha256: [u8; 32] = record_tbs_hasher.finalize().into();

    let candidate_issuer = *blake3::hash(
        &openssl::x509::X509::from_der(certificate_der)
            .map_err(|error| format!("failed to parse candidate X.509 certificate with OpenSSL: {error}"))?
            .issuer_name()
            .to_der()
            .map_err(|error| format!("failed to serialize candidate X.509 issuer name: {error}"))?,
    )
    .as_bytes();
    let candidate_serial =
        *blake3::hash(candidate_certificate.tbs_certificate.raw_serial()).as_bytes();
    let mut candidate_tbs_hasher = sha2::Sha256::new();
    candidate_tbs_hasher.update(candidate_certificate.tbs_certificate.as_ref());
    let candidate_tbs_sha256: [u8; 32] = candidate_tbs_hasher.finalize().into();

    Ok(record_issuer == candidate_issuer
        && record_serial == candidate_serial
        && record_tbs_sha256 == candidate_tbs_sha256)
}

#[cfg(feature = "native")]
fn dbx_tbs_record_matches_certificate(
    record: &SignatureDatabaseRecord,
    certificate_der: &[u8],
) -> Result<bool, String> {
    let Some(expected) = record.certificate_tbs_hash.as_deref() else {
        return Ok(false);
    };

    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|error| format!("failed to parse signing X.509 certificate: {error}"))?;

    use sha2::Digest;
    let matches = match expected.len() {
        32 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(certificate.tbs_certificate.as_ref());
            hasher.finalize().as_slice() == expected
        }
        48 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(certificate.tbs_certificate.as_ref());
            hasher.finalize().as_slice() == expected
        }
        64 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(certificate.tbs_certificate.as_ref());
            hasher.finalize().as_slice() == expected
        }
        _ => false,
    };

    Ok(matches)
}

#[cfg(feature = "native")]
fn dbx_x509_record_matches_chain(
    record: &SignatureDatabaseRecord,
    chain: &[super::secure_boot_signature::X509ChainCertificateEvidence],
) -> Result<Option<[u8; 32]>, String> {
    let Some(certificate_der) = record.certificate_der.as_deref() else {
        return Ok(None);
    };

    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|error| format!("failed to parse dbx X.509 certificate: {error}"))?;

    let issuer_der = openssl::x509::X509::from_der(certificate_der)
        .map_err(|error| format!("failed to parse dbx X.509 certificate with OpenSSL: {error}"))?
        .issuer_name()
        .to_der()
        .map_err(|error| format!("failed to serialize dbx X.509 issuer name: {error}"))?;
    let issuer_blake3 = *blake3::hash(&issuer_der).as_bytes();
    let serial_blake3 =
        *blake3::hash(certificate.tbs_certificate.raw_serial()).as_bytes();

    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(certificate.tbs_certificate.as_ref());
    let tbs_sha256: [u8; 32] = sha256.finalize().into();

    for candidate in chain.iter().filter(|candidate| candidate.is_chain_member) {
        if candidate.issuer_blake3 == issuer_blake3
            && candidate.serial_blake3 == serial_blake3
            && candidate.tbs_sha256 == tbs_sha256
        {
            return Ok(Some(candidate.certificate_blake3));
        }
    }

    Ok(None)
}

#[cfg(feature = "native")]
fn dbx_tbs_record_is_always_revoked(record: &SignatureDatabaseRecord) -> bool {
    record.revocation_time == Some([0; 16])
}

#[cfg(feature = "native")]
fn classify_dbx_tbs_revocation_records<'a, I>(
    records: I,
) -> (bool, bool)
where
    I: IntoIterator<Item = &'a SignatureDatabaseRecord>,
{
    let mut always_revoked = false;
    let mut potential_revocation = false;
    for record in records {
        if dbx_tbs_record_is_always_revoked(record) {
            always_revoked = true;
        } else {
            potential_revocation = true;
        }
    }
    (always_revoked, potential_revocation)
}

#[cfg(feature = "native")]
fn dbx_tbs_record_matches_chain(
    record: &SignatureDatabaseRecord,
    chain: &[super::secure_boot_signature::X509ChainCertificateEvidence],
) -> Option<[u8; 32]> {
    let Some(expected) = record.certificate_tbs_hash.as_deref() else {
        return None;
    };

    chain
        .iter()
        .filter(|candidate| candidate.is_chain_member)
        .find(|candidate| match expected.len() {
            32 => candidate.tbs_sha256.as_slice() == expected,
            48 => candidate.tbs_sha384.as_slice() == expected,
            64 => candidate.tbs_sha512.as_slice() == expected,
            _ => false,
        })
        .map(|candidate| candidate.certificate_blake3)
}

#[cfg(feature = "native")]
pub fn verify_image_against_db_certificates(
    image_path: &std::path::Path,
    db_payload: &[u8],
    dbx_payload: &[u8],
) -> Result<DbCertificateVerificationEvidence, String> {
    let metadata = std::fs::symlink_metadata(image_path)
        .map_err(|error| format!("failed to inspect UKI {}: {error}", image_path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("UKI {} is not a regular non-symlink file", image_path.display()));
    }

    let image = std::fs::read(image_path)
        .map_err(|error| format!("failed to read UKI {}: {error}", image_path.display()))?;
    let image_blake3 = *blake3::hash(&image).as_bytes();
    let image_authenticode_sha256 = super::secure_boot_signature::authenticode_sha256(&image)?;
    let db = parse_signature_database(db_payload)?;
    let dbx = parse_signature_database(dbx_payload)?;
    let mut evidence = db_certificate_verification_base_evidence(
        image_blake3,
        image_authenticode_sha256,
        db_payload,
        dbx_payload,
        &db,
        &dbx,
    );

    let chain = super::secure_boot_signature::inspect_x509_signature_chains(&image)?;
    evidence.image_chain_certificate_digests = chain
        .iter()
        .filter(|certificate| certificate.is_chain_member)
        .map(|certificate| certificate.certificate_blake3)
        .collect();
    evidence.image_signer_certificate_digests = chain
        .iter()
        .filter(|certificate| certificate.is_signer)
        .map(|certificate| certificate.certificate_blake3)
        .collect();

    if dbx.iter().any(|record| {
        record.image_authenticode_sha256 == Some(image_authenticode_sha256)
    }) {
        evidence.state = DbCertificateVerificationState::ForbiddenByDbxImageHash;
        evidence.stderr_blake3 = *blake3::hash(b"dbx image hash veto").as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    for record in dbx.iter().filter(|record| {
        record.kind == SignatureListKind::X509Certificate
    }) {
        if let Some(matched_certificate) = dbx_x509_record_matches_chain(record, &chain)? {
            evidence.verifying_dbx_certificate = record.certificate_der_blake3;
            evidence.dbx_chain_identity_match = Some(matched_certificate);
            evidence.state = DbCertificateVerificationState::ForbiddenByDbxCertificateChain;
            evidence.stderr_blake3 =
                *blake3::hash(b"dbx X509 Issuer+Serial+TBS chain match").as_bytes();
            return finalize_image_bound_verification(image_path, evidence);
        }
    }

    if dbx.iter().any(|record| record.kind == SignatureListKind::Unsupported) {
        evidence.state = DbCertificateVerificationState::UnknownDbxCertificateRules;
        evidence.stderr_blake3 =
            *blake3::hash(b"unsupported dbx signature rule").as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    let mut matched_tbs_records = Vec::new();
    let mut first_chain_tbs_match = None;
    for record in dbx.iter().filter(|record| {
        matches!(
            record.kind,
            SignatureListKind::X509TbsSha256
                | SignatureListKind::X509TbsSha384
                | SignatureListKind::X509TbsSha512
        )
    }) {
        if let Some(matched_certificate) = dbx_tbs_record_matches_chain(record, &chain) {
            if first_chain_tbs_match.is_none() {
                first_chain_tbs_match = Some(matched_certificate);
            }
            matched_tbs_records.push(record);
        }
    }
    if let Some(matched_certificate) = first_chain_tbs_match {
        let (always_revoked, potential_revocation) =
            classify_dbx_tbs_revocation_records(matched_tbs_records.iter().copied());
        debug_assert!(always_revoked || potential_revocation);
        evidence.dbx_chain_tbs_hash_match = Some(matched_certificate);
        evidence.dbx_chain_tbs_revocation_times = matched_tbs_records
            .iter()
            .filter_map(|record| record.revocation_time)
            .collect();
        evidence.state = if always_revoked {
            DbCertificateVerificationState::ForbiddenByDbxTbsRevocation
        } else {
            DbCertificateVerificationState::PotentialDbxTbsRevocation
        };
        evidence.stderr_blake3 = *blake3::hash(
            if always_revoked {
                b"dbx X509 TBS chain match with zero EFI_TIME: always revoked" as &[u8]
            } else {
                b"dbx X509 TBS chain match requires timestamp evaluation"
            },
        )
        .as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    if dbx.iter().any(|record| {
        matches!(
            record.kind,
            SignatureListKind::X509Certificate
                | SignatureListKind::X509TbsSha256
                | SignatureListKind::X509TbsSha384
                | SignatureListKind::X509TbsSha512
        )
    }) && evidence.image_chain_certificate_digests.is_empty()
    {
        evidence.state = DbCertificateVerificationState::UnknownDbxCertificateRules;
        evidence.stderr_blake3 = *blake3::hash(
            b"dbx certificate rule cannot be correlated to an image signing chain",
        )
        .as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    let db_certificates: Vec<(&[u8], [u8; 32])> = db
        .iter()
        .filter_map(|record| {
            Some((record.certificate_der.as_deref()?, record.certificate_der_blake3?))
        })
        .collect();

    let mut last_stdout = Vec::new();
    let mut last_stderr = Vec::new();
    let mut revoked_db_anchor: Option<([u8; 32], [u8; 32])> = None;
    let mut potential_db_anchor: Option<[u8; 32]> = None;

    for (certificate, certificate_digest) in db_certificates.iter().copied() {
        let run = run_sbverify_against_certificate(image_path, certificate)?;
        evidence.stdout_blake3 = run.stdout_blake3;
        evidence.stderr_blake3 = run.stderr_blake3;

        match run.state {
            CertificateVerifierRunState::Verified => {
                evidence.verified_db_anchor_certificate_digests.push(certificate_digest);

                let mut dbx_identity_veto = None;
                for record in dbx.iter().filter(|record| {
                    record.kind == SignatureListKind::X509Certificate
                }) {
                    if dbx_x509_record_matches_certificate(record, certificate)? {
                        dbx_identity_veto = Some(
                            record
                                .certificate_der_blake3
                                .unwrap_or(certificate_digest),
                        );
                        break;
                    }
                }

                if let Some(dbx_digest) = dbx_identity_veto {
                    revoked_db_anchor = Some((certificate_digest, dbx_digest));
                    last_stdout = run.stdout_blake3.to_vec();
                    last_stderr = run.stderr_blake3.to_vec();
                    continue;
                }

                let mut matched_anchor_tbs_records = Vec::new();
                for record in dbx.iter().filter(|record| {
                    matches!(
                        record.kind,
                        SignatureListKind::X509TbsSha256
                            | SignatureListKind::X509TbsSha384
                            | SignatureListKind::X509TbsSha512
                    )
                }) {
                    if dbx_tbs_record_matches_certificate(record, certificate)? {
                        matched_anchor_tbs_records.push(record);
                    }
                }

                if !matched_anchor_tbs_records.is_empty() {
                    let (always_revoked, potential_revocation) =
                        classify_dbx_tbs_revocation_records(
                            matched_anchor_tbs_records.iter().copied(),
                        );
                    debug_assert!(always_revoked || potential_revocation);
                    if always_revoked {
                        evidence.verifying_dbx_certificate = None;
                        evidence.dbx_chain_tbs_hash_match = Some(certificate_digest);
                        evidence.dbx_chain_tbs_revocation_times = matched_anchor_tbs_records
                            .iter()
                            .filter_map(|record| record.revocation_time)
                            .collect();
                        evidence.state =
                            DbCertificateVerificationState::ForbiddenByDbxTbsRevocation;
                        evidence.stderr_blake3 = *blake3::hash(
                            b"verified db trust anchor has zero-time dbx TBS revocation",
                        )
                        .as_bytes();
                        return finalize_image_bound_verification(image_path, evidence);
                    }

                    // A timestamped revocation match is unresolved without
                    // signature-time evidence. Preserve it, but do not let
                    // one potentially revoked db anchor suppress a different
                    // later anchor that verifies cleanly.
                    if potential_revocation {
                        potential_db_anchor.get_or_insert(certificate_digest);
                        last_stdout = run.stdout_blake3.to_vec();
                        last_stderr = run.stderr_blake3.to_vec();
                        continue;
                    }
                }

                evidence.verifying_db_certificate = Some(certificate_digest);
                evidence.state = DbCertificateVerificationState::VerifiedAgainstDbCertificate;
                return finalize_image_bound_verification(image_path, evidence);
            }

            CertificateVerifierRunState::ToolUnavailable => {
                evidence.state = DbCertificateVerificationState::ToolUnavailable;
                return finalize_image_bound_verification(image_path, evidence);
            }

            CertificateVerifierRunState::ImageChanged => {
                evidence.state = DbCertificateVerificationState::ImageChangedDuringVerification;
                return finalize_image_bound_verification(image_path, evidence);
            }

            CertificateVerifierRunState::Failed => {
                last_stdout = run.stdout_blake3.to_vec();
                last_stderr = run.stderr_blake3.to_vec();
            }
        }
    }

    if let Some((db_anchor, dbx_digest)) = revoked_db_anchor {
        evidence.verifying_db_certificate = None;
        evidence.verifying_dbx_certificate = Some(dbx_digest);
        evidence.dbx_chain_identity_match = Some(db_anchor);
        evidence.state = DbCertificateVerificationState::ForbiddenByDbxCertificateChain;
        evidence.stdout_blake3 = *blake3::hash(&last_stdout).as_bytes();
        evidence.stderr_blake3 =
            *blake3::hash(b"verified db trust anchor is directly reflected in dbx").as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    if let Some(db_anchor) = potential_db_anchor {
        evidence.verifying_db_certificate = Some(db_anchor);
        evidence.dbx_chain_tbs_hash_match = Some(db_anchor);
        evidence.state = DbCertificateVerificationState::PotentialDbxTbsRevocation;
        evidence.stdout_blake3 = *blake3::hash(&last_stdout).as_bytes();
        evidence.stderr_blake3 =
            *blake3::hash(b"verified db trust anchor has potential dbx TBS revocation").as_bytes();
        return finalize_image_bound_verification(image_path, evidence);
    }

    evidence.stdout_blake3 = *blake3::hash(&last_stdout).as_bytes();
    evidence.stderr_blake3 = *blake3::hash(&last_stderr).as_bytes();
    evidence.state = DbCertificateVerificationState::NoMatchingDbCertificate;
    finalize_image_bound_verification(image_path, evidence)
}

#[cfg(feature = "native")]
pub fn verify_image_against_live_secure_boot_databases(
    image_path: &std::path::Path,
) -> Result<DbCertificateVerificationEvidence, String> {
    let db_before = read_efi_database("db")?;
    let dbx_before = read_efi_database("dbx")?;
    let dbt_before = read_efi_timestamp_database()?;

    if db_before.is_none() || dbx_before.is_none() {
        let image = std::fs::read(image_path)
            .map_err(|error| format!("failed to read UKI {}: {error}", image_path.display()))?;
        let image_blake3 = *blake3::hash(&image).as_bytes();
        let image_authenticode_sha256 = super::secure_boot_signature::authenticode_sha256(&image)?;
        return Ok(DbCertificateVerificationEvidence {
            image_blake3,
            image_authenticode_sha256,
            image_chain_certificate_digests: Vec::new(),
            image_signer_certificate_digests: Vec::new(),
            verified_db_anchor_certificate_digests: Vec::new(),
            db_certificate_digests: db_before
                .as_deref()
                .map(parse_signature_database)
                .transpose()?
                .unwrap_or_default()
                .iter()
                .filter_map(|record| record.certificate_der_blake3)
                .collect(),
            dbx_certificate_digests: dbx_before
                .as_deref()
                .map(parse_signature_database)
                .transpose()?
                .unwrap_or_default()
                .iter()
                .filter_map(|record| record.certificate_der_blake3)
                .collect(),
            verifying_db_certificate: None,
            verifying_dbx_certificate: None,
            dbx_chain_identity_match: None,
            dbx_chain_tbs_hash_match: None,
        dbx_chain_tbs_revocation_times: Vec::new(),
            db_payload_blake3: db_before.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes()),
            dbx_payload_blake3: dbx_before.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes()),
            dbt_certificate_digests: timestamp_database_certificate_digests(dbt_before.as_deref())?,
            dbt_payload_blake3: dbt_before.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes()),
            timestamp_database_stability: None,
            database_stability: None,
            state: DbCertificateVerificationState::MissingSecureBootDatabase,
            verifier: "sbverify".into(),
            stdout_blake3: *blake3::hash(&[]).as_bytes(),
            stderr_blake3: *blake3::hash(b"secure boot db/dbx missing").as_bytes(),
            observed_at_ms: None,
            evidence_digest: None,
        });
    }

    let mut evidence = verify_image_against_db_certificates(
        image_path,
        db_before.as_deref().expect("db presence checked"),
        dbx_before.as_deref().expect("dbx presence checked"),
    )?;
    evidence.dbt_certificate_digests = timestamp_database_certificate_digests(dbt_before.as_deref())?;
    evidence.dbt_payload_blake3 =
        dbt_before.as_deref().map(|bytes| *blake3::hash(bytes).as_bytes());

    let db_after = read_efi_database("db")?;
    let dbx_after = read_efi_database("dbx")?;
    let dbt_after = read_efi_timestamp_database()?;
    let stable = db_after
        .as_deref()
        .map(|bytes| *blake3::hash(bytes).as_bytes())
        == db_before
            .as_deref()
            .map(|bytes| *blake3::hash(bytes).as_bytes())
        && dbx_after
            .as_deref()
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            == dbx_before
                .as_deref()
                .map(|bytes| *blake3::hash(bytes).as_bytes());

    let timestamp_stable = dbt_after
        .as_deref()
        .map(|bytes| *blake3::hash(bytes).as_bytes())
        == dbt_before
            .as_deref()
            .map(|bytes| *blake3::hash(bytes).as_bytes());
    evidence.database_stability = Some(stable);
    evidence.timestamp_database_stability = Some(timestamp_stable);
    if !stable {
        evidence.verifying_db_certificate = None;
        evidence.verifying_dbx_certificate = None;
        evidence.state = DbCertificateVerificationState::DatabaseChangedDuringVerification;
        evidence.stderr_blake3 = *blake3::hash(b"db/dbx changed during verification").as_bytes();
    }

    let observed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock could not produce observation timestamp: {error}"))?
        .as_millis() as u64;
    evidence.with_observation_metadata(observed_at_ms)
}

pub fn require_db_certificate_verification(
    evidence: &DbCertificateVerificationEvidence,
    expected_image_blake3: &[u8; 32],
) -> Result<(), String> {
    if &evidence.image_blake3 != expected_image_blake3 {
        return Err("db certificate verification is bound to a different UKI image".into());
    }
    if evidence.state != DbCertificateVerificationState::VerifiedAgainstDbCertificate {
        return Err(format!("db certificate verification state is {:?}", evidence.state));
    }
    Ok(())
}

pub fn require_live_db_certificate_verification(
    evidence: &DbCertificateVerificationEvidence,
    expected_image_blake3: &[u8; 32],
) -> Result<(), String> {
    require_db_certificate_verification(evidence, expected_image_blake3)?;
    if evidence.database_stability != Some(true) {
        return Err("live Secure Boot database evidence was not stable across verification".into());
    }
    Ok(())
}

fn pem_encode_certificate(der: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    let mut index = 0usize;
    while index < der.len() {
        let a = der[index];
        let b = if index + 1 < der.len() { der[index + 1] } else { 0 };
        let d = if index + 2 < der.len() { der[index + 2] } else { 0 };
        encoded.push(TABLE[(a >> 2) as usize] as char);
        encoded.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        encoded.push(if index + 1 < der.len() { TABLE[(((b & 0x0f) << 2) | (d >> 6)) as usize] as char } else { '=' });
        encoded.push(if index + 2 < der.len() { TABLE[(d & 0x3f) as usize] as char } else { '=' });
        if encoded.len() % 64 == 0 { encoded.push('\n'); }
        index += 3;
    }
    format!("-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n", encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_image_hash_signature_list(hash: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![0u8; 28 + 48];
        payload[..16].copy_from_slice(&EFI_CERT_SHA256_GUID);
        payload[16..20].copy_from_slice(&(76u32).to_le_bytes());
        payload[24..28].copy_from_slice(&48u32.to_le_bytes());
        payload[44..76].copy_from_slice(&hash);
        payload
    }
    #[test]
    fn image_hash_subject_is_named_authenticode() {
        let records = SignatureDatabaseRecord {
            kind: SignatureListKind::Sha256ImageHash,
            signature_size: 48,
            signature_data_blake3: [0; 32],
            owner: [0; 16],
            image_authenticode_sha256: Some([7; 32]),
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: None,
            revocation_time: None,
        };
        assert_eq!(records.image_authenticode_sha256, Some([7; 32]));
    }
    #[test]
    fn trust_matcher_subject_is_explicitly_authenticode_hash() {
        let expected = [0xabu8; 32];
        let db = make_image_hash_signature_list(expected);
        let evidence = match_secure_boot_databases(&db, &[], expected, None, &[])
            .expect("db matcher");
        assert!(evidence.direct_db_authenticode_hash_match);
        assert_eq!(evidence.image_authenticode_sha256, expected);
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::AuthenticodeHashInDb
        );
    }
    #[test]
    fn exact_dbx_tbs_match_is_potential_revocation_not_immediate_veto() {
        let evidence = SignatureDatabaseMatchEvidence {
            db_records: Vec::new(),
            dbx_records: Vec::new(),
            image_authenticode_sha256: [1; 32],
            direct_db_authenticode_hash_match: false,
            direct_dbx_authenticode_hash_match: false,
            exact_certificate_in_db: false,
            exact_certificate_in_dbx: false,
            exact_certificate_tbs_hash_in_db: false,
            exact_certificate_tbs_hash_in_dbx: true,
            matched_dbx_tbs_revocation_time: None,
            certificate_chain_authorization: None,
            observed_at_ms: None,
            evidence_digest: None,
        };
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::PotentialX509TbsRevocation
        );
    }
    #[test]
    fn direct_trust_summary_distinguishes_zero_time_dbx_tbs_revocation() {
        let evidence = SignatureDatabaseMatchEvidence {
            db_records: Vec::new(),
            dbx_records: Vec::new(),
            image_authenticode_sha256: [0; 32],
            direct_db_authenticode_hash_match: false,
            direct_dbx_authenticode_hash_match: false,
            exact_certificate_in_db: false,
            exact_certificate_in_dbx: false,
            exact_certificate_tbs_hash_in_db: false,
            exact_certificate_tbs_hash_in_dbx: true,
            matched_dbx_tbs_revocation_time: Some([0; 16]),
            certificate_chain_authorization: None,
            observed_at_ms: None,
            evidence_digest: None,
        };
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::ForbiddenByDbxTbsRevocation
        );
    }

    #[test]
    fn zero_time_dbx_tbs_match_dominates_timestamped_match_ordering() {
        let evidence = SignatureDatabaseMatchEvidence {
            db_records: Vec::new(),
            dbx_records: vec![
                SignatureDatabaseRecord {
                    kind: SignatureListKind::X509TbsSha256,
                    signature_size: 64,
                    signature_data_blake3: [1; 32],
                    owner: [1; 16],
                    image_authenticode_sha256: None,
                    certificate_der_blake3: None,
                    certificate_der: None,
                    certificate_tbs_hash: Some(vec![3; 32]),
                    revocation_time: Some([7; 16]),
                },
                SignatureDatabaseRecord {
                    kind: SignatureListKind::X509TbsSha256,
                    signature_size: 64,
                    signature_data_blake3: [2; 32],
                    owner: [2; 16],
                    image_authenticode_sha256: None,
                    certificate_der_blake3: None,
                    certificate_der: None,
                    certificate_tbs_hash: Some(vec![3; 32]),
                    revocation_time: Some([0; 16]),
                },
            ],
            image_authenticode_sha256: [0; 32],
            direct_db_authenticode_hash_match: false,
            direct_dbx_authenticode_hash_match: false,
            exact_certificate_in_db: false,
            exact_certificate_in_dbx: false,
            exact_certificate_tbs_hash_in_db: false,
            exact_certificate_tbs_hash_in_dbx: true,
            matched_dbx_tbs_revocation_time: Some([0; 16]),
            certificate_chain_authorization: None,
            observed_at_ms: None,
            evidence_digest: None,
        };

        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::ForbiddenByDbxTbsRevocation
        );
    }

    #[test]
    fn exact_dbx_certificate_match_beats_unevaluated_rules() {
        let evidence = SignatureDatabaseMatchEvidence {
            db_records: Vec::new(),
            dbx_records: vec![SignatureDatabaseRecord {
                kind: SignatureListKind::X509Certificate,
                signature_size: 48,
                signature_data_blake3: [1; 32],
                owner: [2; 16],
                image_authenticode_sha256: None,
                certificate_der_blake3: Some([3; 32]),
                certificate_der: Some(vec![0x30, 0x01]),
                certificate_tbs_hash: None,
                revocation_time: None,
            }],
            image_authenticode_sha256: [4; 32],
            direct_db_authenticode_hash_match: false,
            direct_dbx_authenticode_hash_match: false,
            exact_certificate_in_db: false,
            exact_certificate_in_dbx: true,
            exact_certificate_tbs_hash_in_db: false,
            exact_certificate_tbs_hash_in_dbx: false,
            matched_dbx_tbs_revocation_time: None,
            certificate_chain_authorization: None,
            observed_at_ms: None,
            evidence_digest: None,
        };
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::ExactCertificateInDbx
        );
    }
    #[test]
    fn parses_sha256_signature_database_records() {
        let mut payload = vec![0u8; 28 + 48];
        payload[..16].copy_from_slice(&EFI_CERT_SHA256_GUID);
        payload[16..20].copy_from_slice(&(76u32).to_le_bytes());
        payload[20..24].copy_from_slice(&0u32.to_le_bytes());
        payload[24..28].copy_from_slice(&48u32.to_le_bytes());
        for (index, byte) in payload[28..44].iter_mut().enumerate() { *byte = index as u8; }
        for (index, byte) in payload[44..76].iter_mut().enumerate() { *byte = (index + 1) as u8; }
        let records = parse_signature_database(&payload).expect("SHA256 signature list");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, SignatureListKind::Sha256ImageHash);
        assert_eq!(records[0].image_authenticode_sha256, Some([1u8; 32]));
    }

    #[test]
    fn direct_dbx_authenticode_hash_match_is_observed_separately() {
        let image_hash = [7u8; 32];
        let mut payload = vec![0u8; 28 + 48];
        payload[..16].copy_from_slice(&EFI_CERT_SHA256_GUID);
        payload[16..20].copy_from_slice(&(76u32).to_le_bytes());
        payload[24..28].copy_from_slice(&48u32.to_le_bytes());
        payload[44..76].copy_from_slice(&image_hash);
        let evidence = match_secure_boot_databases(&payload, &payload, image_hash, None, &[]).expect("database matcher");
        assert!(evidence.direct_db_authenticode_hash_match);
        assert!(evidence.direct_dbx_authenticode_hash_match);
        assert_eq!(evidence.certificate_chain_authorization, None);
    }

    #[test]
    fn parses_x509_tbs_sha256_revocation_record() {
        let mut payload = vec![0u8; 28 + 64];
        payload[..16].copy_from_slice(&EFI_CERT_X509_SHA256_GUID);
        payload[16..20].copy_from_slice(&(92u32).to_le_bytes());
        payload[24..28].copy_from_slice(&64u32.to_le_bytes());
        payload[28..44].fill(0x11);
        payload[44..76].fill(0x22);
        payload[76..92].fill(0x33);
        let records = parse_signature_database(&payload).expect("x509 sha256 revocation record");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, SignatureListKind::X509TbsSha256);
        assert_eq!(records[0].certificate_tbs_hash, Some(vec![0x22; 32]));
        assert_eq!(records[0].revocation_time, Some([0x33; 16]));
    }
    #[test]
    fn unsupported_signature_list_type_is_retained_not_authorized() {
        let mut payload = vec![0u8; 28 + 16];
        payload[16..20].copy_from_slice(&(44u32).to_le_bytes());
        payload[24..28].copy_from_slice(&16u32.to_le_bytes());
        let records = parse_signature_database(&payload).expect("unsupported signature list");
        assert_eq!(records[0].kind, SignatureListKind::Unsupported);
        assert_eq!(records[0].image_authenticode_sha256, None);
    }
    #[test]
    fn dbx_image_hash_veto_has_precedence_over_db_authorization() {
        let image_hash = [7u8; 32];
        let db = make_image_hash_signature_list(image_hash);
        let dbx = make_image_hash_signature_list(image_hash);
        let evidence = match_secure_boot_databases(&db, &dbx, image_hash, None, &[])
            .expect("database matcher");
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::ForbiddenByAuthenticodeHash
        );
    }

    #[test]
    fn unsupported_dbx_record_prevents_authorization_conclusion() {
        let image_hash = [8u8; 32];
        let db = make_image_hash_signature_list(image_hash);
        let mut dbx = vec![0u8; 28 + 16];
        dbx[16..20].copy_from_slice(&(44u32).to_le_bytes());
        dbx[24..28].copy_from_slice(&16u32.to_le_bytes());
        let evidence = match_secure_boot_databases(&db, &dbx, image_hash, None, &[])
            .expect("database matcher");
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::UnknownUnsupportedRecord
        );
    }
    #[test]
    fn certificate_based_dbx_rules_block_hash_only_authorization() {
        let image_hash = [8u8; 32];
        let db = make_image_hash_signature_list(image_hash);
        let mut dbx = vec![0u8; 28 + 17];
        dbx[16..20].copy_from_slice(&(45u32).to_le_bytes());
        dbx[24..28].copy_from_slice(&17u32.to_le_bytes());
        dbx[28..44].fill(0);
        dbx[44] = 0x30;
        let evidence = match_secure_boot_databases(&db, &dbx, image_hash, None, &[])
            .expect("database matcher");
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::UnknownUnsupportedRecord
        );
    }
    #[test]
    fn db_image_hash_is_authorizing_only_without_dbx_veto() {
        let image_hash = [8u8; 32];
        let db = make_image_hash_signature_list(image_hash);
        let evidence = match_secure_boot_databases(&db, &[], image_hash, None, &[])
            .expect("database matcher");
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::AuthenticodeHashInDb
        );
    }
    #[test]
    fn database_evidence_hashes_exact_payloads() {
        let db = b"authorized";
        let dbx = b"forbidden";
        let evidence = build_secure_boot_database_evidence(Some(db), Some(dbx));
        assert_eq!(evidence.db_state, SecureBootDatabaseState::Present);
        assert_eq!(evidence.dbx_state, SecureBootDatabaseState::Present);
        assert_eq!(evidence.db_payload_blake3, Some(*blake3::hash(db).as_bytes()));
        assert_eq!(evidence.dbx_payload_blake3, Some(*blake3::hash(dbx).as_bytes()));
    }

    #[test]
    fn database_observation_digest_binds_payload_identities() {
        let evidence = build_secure_boot_database_evidence(Some(b"db"), Some(b"dbx"))
            .with_observation_metadata(100)
            .expect("database evidence");
        assert_eq!(evidence.observed_at_ms, Some(100));
        assert!(evidence.evidence_digest.is_some());
    }
    #[test]
    fn missing_databases_are_not_treated_as_empty_trust() {
        let evidence = build_secure_boot_database_evidence(None, None);
        assert_eq!(evidence.db_state, SecureBootDatabaseState::Absent);
        assert_eq!(evidence.dbx_state, SecureBootDatabaseState::Absent);
        assert_eq!(evidence.db_payload_blake3, None);
        assert_eq!(evidence.dbx_payload_blake3, None);
    }
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
            SecureBootState::SetupMode
        );
        assert_eq!(
            derive_secure_boot_state(Some(true), Some(true)),
            SecureBootState::Unknown
        );
        assert_eq!(
            derive_secure_boot_state(None, Some(false)),
            SecureBootState::Unknown
        );
    }

    #[test]
    fn secure_boot_snapshot_digest_binds_policy_and_databases() {
        let first = SecureBootSnapshotEvidence {
            state: SecureBootState::Enabled,
            secure_boot_variable: Some(true),
            setup_mode_variable: Some(false),
            db_state: SecureBootDatabaseState::Present,
            db_payload_blake3: Some([1; 32]),
            dbx_state: SecureBootDatabaseState::Present,
            dbx_payload_blake3: Some([2; 32]),
            observed_at_ms: None,
            evidence_digest: None,
        }
        .with_observation_metadata(100)
        .expect("snapshot evidence");
        let second = SecureBootSnapshotEvidence {
            dbx_payload_blake3: Some([3; 32]),
            ..first.clone()
        }
        .with_observation_metadata(100)
        .expect("snapshot evidence");
        assert_ne!(first.evidence_digest, second.evidence_digest);
    }
    #[test]
    fn unsupported_dbx_rule_dominates_potential_tbs_revocation() {
        let evidence = SignatureDatabaseMatchEvidence {
            db_records: Vec::new(),
            dbx_records: vec![
                SignatureDatabaseRecord {
                    kind: SignatureListKind::X509TbsSha256,
                    signature_size: 64,
                    signature_data_blake3: [0; 32],
                    owner: [0; 16],
                    image_authenticode_sha256: None,
                    certificate_der_blake3: None,
                    certificate_der: None,
                    certificate_tbs_hash: Some(vec![1; 32]),
                    revocation_time: Some([2; 16]),
                },
                SignatureDatabaseRecord {
                    kind: SignatureListKind::Unsupported,
                    signature_size: 16,
                    signature_data_blake3: [0; 32],
                    owner: [0; 16],
                    image_authenticode_sha256: None,
                    certificate_der_blake3: None,
                    certificate_der: None,
                    certificate_tbs_hash: None,
                    revocation_time: None,
                },
            ],
            image_authenticode_sha256: [3; 32],
            direct_db_authenticode_hash_match: false,
            direct_dbx_authenticode_hash_match: false,
            exact_certificate_in_db: false,
            exact_certificate_in_dbx: false,
            exact_certificate_tbs_hash_in_db: false,
            exact_certificate_tbs_hash_in_dbx: true,
            matched_dbx_tbs_revocation_time: None,
            certificate_chain_authorization: None,
            observed_at_ms: None,
            evidence_digest: None,
        };

        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::UnknownUnsupportedRecord
        );
    }

    #[test]
    fn dbx_tbs_zero_time_match_dominates_timestamped_match_ordering() {
        let timestamped = SignatureDatabaseRecord {
            kind: SignatureListKind::X509TbsSha256,
            signature_size: 64,
            signature_data_blake3: [0; 32],
            owner: [0; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: Some(vec![3; 32]),
            revocation_time: Some([1; 16]),
        };
        let always_revoked = SignatureDatabaseRecord {
            revocation_time: Some([0; 16]),
            ..timestamped.clone()
        };

        assert_eq!(
            classify_dbx_tbs_revocation_records([&timestamped, &always_revoked]),
            (true, true)
        );
        assert_eq!(
            classify_dbx_tbs_revocation_records([&always_revoked, &timestamped]),
            (true, true)
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn dbt_certificate_digest_observation_is_separate_from_trust() {
        let cert = vec![0x30, 0x01, 0x00];
        let mut payload = vec![0u8; 28 + 16 + cert.len()];
        payload[..16].copy_from_slice(&EFI_CERT_X509_GUID);
        let signature_size = (16 + cert.len()) as u32;
        let list_size = (28 + signature_size) as u32;
        payload[16..20].copy_from_slice(&list_size.to_le_bytes());
        payload[24..28].copy_from_slice(&signature_size.to_le_bytes());
        payload[28..44].fill(0x11);
        payload[44..].copy_from_slice(&cert);

        let digests = timestamp_database_certificate_digests(Some(&payload))
            .expect("dbt database parse");
        assert_eq!(digests, vec![*blake3::hash(&cert).as_bytes()]);
    }

    #[test]
    fn zero_time_dbx_tbs_record_is_always_revoked() {
        let record = SignatureDatabaseRecord {
            kind: SignatureListKind::X509TbsSha256,
            signature_size: 64,
            signature_data_blake3: [0; 32],
            owner: [0; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: Some(vec![3; 32]),
            revocation_time: Some([0; 16]),
        };
        assert!(dbx_tbs_record_is_always_revoked(&record));
    }

    #[test]
    fn nonzero_time_dbx_tbs_record_remains_time_dependent() {
        let record = SignatureDatabaseRecord {
            kind: SignatureListKind::X509TbsSha256,
            signature_size: 64,
            signature_data_blake3: [0; 32],
            owner: [0; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: Some(vec![3; 32]),
            revocation_time: Some([1; 16]),
        };
        assert!(!dbx_tbs_record_is_always_revoked(&record));
    }

    #[cfg(feature = "native")]
    #[test]
    fn evidence_digest_binds_all_dbx_tbs_revocation_times() {
        let mut first = db_certificate_verification_base_evidence(
            [1; 32],
            [2; 32],
            b"db",
            b"dbx",
            &[],
            &[],
        );
        first.dbx_chain_tbs_revocation_times = vec![[1; 16], [2; 16]];
        let first = first
            .with_observation_metadata(100)
            .expect("first evidence");

        let mut second = db_certificate_verification_base_evidence(
            [1; 32],
            [2; 32],
            b"db",
            b"dbx",
            &[],
            &[],
        );
        second.dbx_chain_tbs_revocation_times = vec![[1; 16], [3; 16]];
        let second = second
            .with_observation_metadata(100)
            .expect("second evidence");

        assert_ne!(first.evidence_digest, second.evidence_digest);
    }

    #[cfg(all(feature = "native", unix))]
    #[test]
    fn efivar_reader_rejects_symlinks_and_non_regular_files() {
        let temp = tempfile::tempdir().expect("temporary EFI variable directory");
        let regular = temp.path().join("regular");
        let directory = temp.path().join("directory");
        let symlink = temp.path().join("symlink");

        std::fs::write(&regular, [0, 0, 0, 7, 1]).expect("regular EFI variable fixture");
        std::fs::create_dir(&directory).expect("directory fixture");
        std::os::unix::fs::symlink(&regular, &symlink).expect("symlink fixture");

        assert_eq!(
            read_efi_regular_file_no_follow(&regular).expect("regular file read"),
            Some(vec![0, 0, 0, 7, 1])
        );
        assert!(
            read_efi_regular_file_no_follow(&directory)
                .expect_err("directory must be rejected")
                .contains("not a regular file")
        );
        assert!(
            read_efi_regular_file_no_follow(&symlink)
                .expect_err("symlink must be rejected")
                .contains("without symlink following")
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

    #[cfg(feature = "native")]
    #[test]
    fn final_image_recheck_invalidates_stale_chain_evidence() {
        let temp = tempfile::NamedTempFile::new().expect("temporary UKI path");
        std::fs::write(temp.path(), b"initial-image").expect("initial image");

        let initial_hash = *blake3::hash(b"initial-image").as_bytes();
        let mut evidence = DbCertificateVerificationEvidence {
            image_blake3: initial_hash,
            image_authenticode_sha256: [7; 32],
            image_chain_certificate_digests: vec![[1; 32]],
            image_signer_certificate_digests: vec![[2; 32]],
            verified_db_anchor_certificate_digests: vec![[3; 32]],
            db_certificate_digests: vec![[4; 32]],
            dbx_certificate_digests: vec![[5; 32]],
            verifying_db_certificate: Some([6; 32]),
            verifying_dbx_certificate: None,
            dbx_chain_identity_match: Some([7; 32]),
            dbx_chain_tbs_hash_match: None,
        dbx_chain_tbs_revocation_times: Vec::new(),
            db_payload_blake3: Some([8; 32]),
            dbx_payload_blake3: Some([9; 32]),
            dbt_certificate_digests: Vec::new(),
            dbt_payload_blake3: None,
            timestamp_database_stability: None,
            database_stability: Some(true),
            state: DbCertificateVerificationState::VerifiedAgainstDbCertificate,
            verifier: "fixture".into(),
            stdout_blake3: [10; 32],
            stderr_blake3: [11; 32],
            observed_at_ms: None,
            evidence_digest: None,
        };

        std::fs::write(temp.path(), b"replacement-image").expect("replacement image");

        evidence = finalize_image_bound_verification(temp.path(), evidence)
            .expect("final image recheck");

        assert_eq!(
            evidence.state,
            DbCertificateVerificationState::ImageChangedDuringVerification
        );
        assert_eq!(evidence.database_stability, Some(false));
        assert!(evidence.image_chain_certificate_digests.is_empty());
        assert!(evidence.image_signer_certificate_digests.is_empty());
        assert_eq!(evidence.verifying_db_certificate, None);
        assert_eq!(evidence.dbx_chain_identity_match, None);
    }

    #[cfg(feature = "native")]
    #[test]
    fn dbx_tbs_revocation_only_matches_exact_chain_member() {
        let evidence = super::secure_boot_signature::X509ChainCertificateEvidence {
            signature_index: 0,
            certificate_index: 0,
            certificate_blake3: [9; 32],
            issuer_blake3: [1; 32],
            serial_blake3: [2; 32],
            tbs_sha256: [3; 32],
            tbs_sha384: [4; 48],
            tbs_sha512: [5; 64],
            is_signer: true,
            is_chain_member: true,
        };

        let mut record = SignatureDatabaseRecord {
            kind: SignatureListKind::X509TbsSha256,
            signature_size: 64,
            signature_data_blake3: [0; 32],
            owner: [0; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: Some(vec![3; 32]),
            revocation_time: Some([0x11; 16]),
        };

        assert_eq!(
            dbx_tbs_record_matches_chain(&record, &[evidence.clone()]),
            Some([9; 32])
        );

        record.certificate_tbs_hash = Some(vec![7; 32]);
        assert_eq!(
            dbx_tbs_record_matches_chain(&record, &[evidence]),
            None
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn dbx_x509_rule_requires_exact_issuer_serial_and_tbs_identity() {
        use openssl::asn1::Asn1Integer;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::X509NameBuilder;
        use openssl::x509::X509Builder;
        use sha2::Digest;

        let rsa = Rsa::generate(2048).expect("test RSA key");
        let key = PKey::from_rsa(rsa).expect("test private key");
        let mut name_builder = X509NameBuilder::new().expect("name builder");
        name_builder
            .append_entry_by_text("CN", "Nixward Test")
            .expect("CN");
        let name = name_builder.build();

        let serial_bn = BigNum::from_u32(128).expect("serial");
        let serial = Asn1Integer::from_bn(&serial_bn).expect("ASN.1 serial");
        let mut builder = X509Builder::new().expect("certificate builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_serial_number(&serial).expect("serial number");
        builder.set_pubkey(&key).expect("public key");
        builder
            .sign(&key, MessageDigest::sha256())
            .expect("certificate signature");
        let certificate = builder.build();
        let der = certificate.to_der().expect("certificate DER");

        let (_, parsed) =
            x509_parser::parse_x509_certificate(&der).expect("parse generated certificate");

        let issuer_der = X509::from_der(&der)
            .expect("parse generated issuer certificate")
            .issuer_name()
            .to_der()
            .expect("serialize generated issuer name");
        let issuer_blake3 = *blake3::hash(&issuer_der).as_bytes();
        let serial_blake3 =
            *blake3::hash(parsed.tbs_certificate.raw_serial()).as_bytes();
        let mut tbs_hasher = sha2::Sha256::new();
        tbs_hasher.update(parsed.tbs_certificate.as_ref());
        let tbs_sha256: [u8; 32] = tbs_hasher.finalize().into();

        let certificate_digest = *blake3::hash(&der).as_bytes();
        let (_, parsed_for_serial_test) =
            x509_parser::parse_x509_certificate(&der).expect("parse serial test certificate");
        let expected_serial_digest =
            *blake3::hash(parsed_for_serial_test.tbs_certificate.raw_serial()).as_bytes();

        let chain = [super::secure_boot_signature::X509ChainCertificateEvidence {
            signature_index: 0,
            certificate_index: 0,
            certificate_blake3: certificate_digest,
            issuer_blake3,
            serial_blake3: expected_serial_digest,
            tbs_sha256,
            tbs_sha384: [0; 48],
            tbs_sha512: [0; 64],
            is_signer: true,
            is_chain_member: true,
        }];

        let record = SignatureDatabaseRecord {
            kind: SignatureListKind::X509Certificate,
            signature_size: (16 + der.len()) as u32,
            signature_data_blake3: *blake3::hash(&der).as_bytes(),
            owner: [7; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: Some(certificate_digest),
            certificate_der: Some(der),
            certificate_tbs_hash: None,
            revocation_time: None,
        };

        assert_eq!(
            dbx_x509_record_matches_chain(&record, &chain).expect("X509 match"),
            Some(certificate_digest)
        );

        assert!(
            dbx_x509_record_matches_certificate(
                &record,
                record.certificate_der.as_deref().expect("record certificate"),
            )
            .expect("exact anchor identity match")
        );
        assert_eq!(
            chain[0].serial_blake3,
            expected_serial_digest,
            "chain serial identity must preserve raw X.509 serial bytes"
        );

        let tbs_record = SignatureDatabaseRecord {
            kind: SignatureListKind::X509TbsSha256,
            signature_size: 64,
            signature_data_blake3: [0; 32],
            owner: [7; 16],
            image_authenticode_sha256: None,
            certificate_der_blake3: None,
            certificate_der: None,
            certificate_tbs_hash: Some(tbs_sha256.to_vec()),
            revocation_time: Some([1; 16]),
        };
        assert!(
            dbx_tbs_record_matches_certificate(&tbs_record, &der)
                .expect("exact anchor TBS match")
        );
    }


}