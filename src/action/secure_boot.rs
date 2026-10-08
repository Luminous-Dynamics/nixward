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
    AuthorizedByAuthenticodeHash,
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
    Ok(SignatureDatabaseMatchEvidence {
        direct_db_authenticode_hash_match: db_records.iter().any(|record| record.image_authenticode_sha256 == Some(image_authenticode_sha256)),
        direct_dbx_authenticode_hash_match: dbx_records.iter().any(|record| record.image_authenticode_sha256 == Some(image_authenticode_sha256)),
        exact_certificate_in_db: signer_digest.is_some_and(|digest| db_records.iter().any(|record| record.certificate_der_blake3 == Some(digest))),
        exact_certificate_in_dbx: signer_digest.is_some_and(|digest| dbx_records.iter().any(|record| record.certificate_der_blake3 == Some(digest))),
        exact_certificate_tbs_hash_in_db: db_records.iter().any(|record| {
            record.certificate_tbs_hash.as_ref().is_some_and(|hash| signer_certificate_tbs_hashes.iter().any(|candidate| candidate == hash))
        }),
        exact_certificate_tbs_hash_in_dbx: dbx_records.iter().any(|record| {
            record.certificate_tbs_hash.as_ref().is_some_and(|hash| signer_certificate_tbs_hashes.iter().any(|candidate| candidate == hash))
        }),
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
    // UEFI validation gives dbx veto semantics precedence over db authorization.
    // Any unsupported dbx list type prevents an "authorized" conclusion because
    // the unsupported record may encode a revocation rule we do not evaluate.
    if evidence.direct_dbx_authenticode_hash_match {
        return DirectTrustDisposition::ForbiddenByImageHash;
    }
    if evidence.dbx_records.iter().any(|record| record.kind != SignatureListKind::Sha256ImageHash) {
        // Certificate and certificate-chain revocation rules can veto an image
        // independently of its direct SHA-256 hash match. Without chain-aware
        // evaluation, an authorization conclusion would be unsound.
        return DirectTrustDisposition::UnknownUnsupportedRecord;
    }
    if evidence.direct_db_authenticode_hash_match {
        return DirectTrustDisposition::AuthorizedByImageHash;
    }
    if evidence.exact_certificate_in_dbx || evidence.exact_certificate_tbs_hash_in_dbx {
        return DirectTrustDisposition::ExactCertificateInDbx;
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
fn read_efi_database(name: &str) -> Result<Option<Vec<u8>>, String> {
    let path = std::path::PathBuf::from(format!("{}/{}-{}", EFI_VARS_DIR, name, EFI_IMAGE_SECURITY_DATABASE_GUID));
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("EFI database {} is a symlink", path.display()));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(format!("EFI database {} is not a regular file", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to inspect EFI database {}: {error}", path.display())),
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("failed to read EFI database {}: {error}", path.display()))?;
    if bytes.len() < 4 {
        return Err(format!("EFI database {} is missing its attribute header", path.display()));
    }
    Ok(Some(bytes[4..].to_vec()))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbCertificateVerificationState {
    VerifiedAgainstDbCertificate,
    NoMatchingDbCertificate,
    ForbiddenByDbxImageHash,
    UnknownDbxCertificateRules,
    ToolUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbCertificateVerificationEvidence {
    pub image_blake3: [u8; 32],
    pub image_authenticode_sha256: [u8; 32],
    pub db_certificate_digests: Vec<[u8; 32]>,
    pub verifying_db_certificate: Option<[u8; 32]>,
    pub state: DbCertificateVerificationState,
    pub verifier: String,
    pub stdout_blake3: [u8; 32],
    pub stderr_blake3: [u8; 32],
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
    if dbx.iter().any(|record| record.image_authenticode_sha256 == Some(image_authenticode_sha256)) {
        return Ok(DbCertificateVerificationEvidence {
            image_blake3,
            image_authenticode_sha256,
            db_certificate_digests: db.iter().filter_map(|r| r.certificate_der_blake3).collect(),
            verifying_db_certificate: None,
            state: DbCertificateVerificationState::ForbiddenByDbxImageHash,
            verifier: "sbverify".into(),
            stdout_blake3: *blake3::hash(&[]).as_bytes(),
            stderr_blake3: *blake3::hash(b"dbx image hash veto").as_bytes(),
        });
    }
    if dbx.iter().any(|record| record.kind != SignatureListKind::Sha256ImageHash) {
        return Ok(DbCertificateVerificationEvidence {
            image_blake3,
            image_authenticode_sha256,
            db_certificate_digests: db.iter().filter_map(|r| r.certificate_der_blake3).collect(),
            verifying_db_certificate: None,
            state: DbCertificateVerificationState::UnknownDbxCertificateRules,
            verifier: "sbverify".into(),
            stdout_blake3: *blake3::hash(&[]).as_bytes(),
            stderr_blake3: *blake3::hash(b"unevaluated dbx certificate rule").as_bytes(),
        });
    }

    let db_certificates: Vec<(&[u8], [u8; 32])> = db.iter().filter_map(|record| {
        Some((record.certificate_der.as_deref()?, record.certificate_der_blake3?))
    }).collect();
    let db_certificate_digests = db_certificates.iter().map(|(_, digest)| *digest).collect::<Vec<_>>();
    let mut last_stdout = Vec::new();
    let mut last_stderr = Vec::new();
    for (certificate, certificate_digest) in db_certificates {
        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|error| format!("failed to create temporary certificate file: {error}"))?;
        let pem = pem_encode_certificate(certificate);
        use std::io::Write;
        temp.write_all(pem.as_bytes())
            .map_err(|error| format!("failed to write temporary certificate file: {error}"))?;
        temp.flush()
            .map_err(|error| format!("failed to flush temporary certificate file: {error}"))?;
        let output = match std::process::Command::new("sbverify")
            .args(["--cert"])
            .arg(temp.path())
            .arg(image_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DbCertificateVerificationEvidence {
                    image_blake3,
                    image_authenticode_sha256,
                    db_certificate_digests,
                    verifying_db_certificate: None,
                    state: DbCertificateVerificationState::ToolUnavailable,
                    verifier: "sbverify".into(),
                    stdout_blake3: *blake3::hash(&last_stdout).as_bytes(),
                    stderr_blake3: *blake3::hash(error.to_string().as_bytes()).as_bytes(),
                });
            }
            Err(error) => return Err(format!("failed to execute sbverify: {error}")),
        };
        last_stdout = output.stdout.clone();
        last_stderr = output.stderr.clone();
        if output.status.success() {
            let image_after = std::fs::read(image_path)
                .map_err(|error| format!("failed to re-read UKI {}: {error}", image_path.display()))?;
            let stable = *blake3::hash(&image_after).as_bytes() == image_blake3;
            if stable {
                return Ok(DbCertificateVerificationEvidence {
                    image_blake3,
                    image_authenticode_sha256,
                    db_certificate_digests,
                    verifying_db_certificate: Some(certificate_digest),
                    state: DbCertificateVerificationState::VerifiedAgainstDbCertificate,
                    verifier: "sbverify".into(),
                    stdout_blake3: *blake3::hash(&output.stdout).as_bytes(),
                    stderr_blake3: *blake3::hash(&output.stderr).as_bytes(),
                });
            }
        }
    }
    Ok(DbCertificateVerificationEvidence {
        image_blake3,
        image_authenticode_sha256,
        db_certificate_digests,
        verifying_db_certificate: None,
        state: DbCertificateVerificationState::NoMatchingDbCertificate,
        verifier: "sbverify".into(),
        stdout_blake3: *blake3::hash(&last_stdout).as_bytes(),
        stderr_blake3: *blake3::hash(&last_stderr).as_bytes(),
    })
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
            DirectTrustDisposition::AuthorizedByAuthenticodeHash
        );
    }
    #[test]
    fn parses_sha256_signature_database_records() {
        let mut payload = vec![0u8; 28 + 48];
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
            DirectTrustDisposition::ForbiddenByImageHash
        );
    }

    #[test]
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
    fn db_image_hash_is_authorizing_only_without_dbx_veto() {
        let image_hash = [8u8; 32];
        let db = make_image_hash_signature_list(image_hash);
        let evidence = match_secure_boot_databases(&db, &[], image_hash, None, &[])
            .expect("database matcher");
        assert_eq!(
            derive_direct_trust_disposition(&evidence),
            DirectTrustDisposition::AuthorizedByImageHash
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