// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Independent verification of observer-witness receipts and CT-style Merkle proofs.
//!
//! The tree construction and proof-verification algorithms follow RFC 9162,
//! Sections 2.1.1, 2.1.3 and 2.1.4. This module verifies receipts; it does not
//! operate a transparency log, establish administrative independence between
//! witnesses, or turn a Merkle proof into consensus.

use super::signed_checkpoint::VerifiedOciObserverCheckpoint;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const OCI_WITNESS_RECEIPT_SCHEMA_VERSION: u32 = 2;
pub const OCI_WITNESS_RECEIPT_KIND: &str = "nixward-oci-observer-witness-receipt-v2";
pub const OCI_WITNESS_TREE_HEAD_KIND: &str = "nixward-oci-observer-witness-tree-head-v2";
pub const OCI_WITNESS_TREE_HASH_ALGORITHM: &str = "sha256-rfc9162";

const TREE_HEAD_DOMAIN: &[u8] = b"nixward:oci-observer-witness-tree-head:v2\0";
const LEAF_DOMAIN: &[u8] = b"nixward:oci-observer-witness-leaf:v2\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"nixward:oci-observer-witness-receipt-digest:v2\0";
const QUORUM_DIGEST_DOMAIN: &[u8] = b"nixward:oci-observer-witness-quorum:v2\0";
const WITNESS_REQUEST_DOMAIN: &[u8] = b"nixward:oci-observer-witness-request:v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"nixward:oci-observer-witness-request-digest:v1\0";
const IDEMPOTENCY_DOMAIN: &[u8] = b"nixward:oci-observer-witness-idempotency:v1\0";
const MAX_MERKLE_PROOF_NODES: usize = 65;
const MAX_WITNESSES: usize = 4;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OciWitnessProofError {
    #[error("witness receipt has an invalid shape")]
    InvalidShape,
    #[error("witness receipt has invalid lowercase-hex encoding")]
    InvalidEncoding,
    #[error("witness identity does not match the provisioned key")]
    WitnessIdentityMismatch,
    #[error("witness trust domain is invalid")]
    InvalidTrustDomain,
    #[error("witness key is not currently valid")]
    KeyNotCurrentlyValid,
    #[error("witness key is revoked for new admission")]
    KeyRevoked,
    #[error("witness tree-head signature is invalid")]
    InvalidTreeHeadSignature,
    #[error("witness tree-head timestamp is in the future")]
    TreeHeadFromFuture,
    #[error("witness tree head is too old for admission")]
    TreeHeadStale,
    #[error("witness receipt does not match the expected checkpoint request")]
    SubjectMismatch,
    #[error("witness receipt does not extend the retained prior tree head")]
    PriorTreeHeadMismatch,
    #[error("Merkle inclusion proof is invalid")]
    InvalidInclusionProof,
    #[error("Merkle consistency proof is invalid")]
    InvalidConsistencyProof,
    #[error("witness quorum threshold is invalid")]
    InvalidQuorumThreshold,
    #[error("not enough distinct witnesses for the required quorum")]
    QuorumNotMet,
    #[error("witness identity is counted more than once")]
    DuplicateWitness,
    #[error("witness trust domain is counted more than once")]
    DuplicateTrustDomain,
    #[error("witnesses disagree on the checkpoint or request commitment")]
    WitnessSubjectDisagreement,
    #[error("signed tree heads do not establish equivocation")]
    NotEquivocation,
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], OciWitnessProofError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OciWitnessProofError::InvalidEncoding);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = (value.as_bytes()[index * 2] as char)
            .to_digit(16)
            .ok_or(OciWitnessProofError::InvalidEncoding)?;
        let low = (value.as_bytes()[index * 2 + 1] as char)
            .to_digit(16)
            .ok_or(OciWitnessProofError::InvalidEncoding)?;
        *slot = ((high << 4) | low) as u8;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_digest(value: &str) -> Result<(), OciWitnessProofError> {
    decode_hex::<32>(value).map(|_| ())
}

fn validate_identifier(value: &str) -> Result<(), OciWitnessProofError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(OciWitnessProofError::InvalidShape);
    }
    Ok(())
}

fn validate_trust_domain(value: &str) -> Result<(), OciWitnessProofError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(OciWitnessProofError::InvalidTrustDomain);
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&sha256(bytes))
}

fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = 0x01;
    input[1..33].copy_from_slice(left);
    input[33..65].copy_from_slice(right);
    sha256(&input)
}

/// RFC 9162 MTH for an empty tree: SHA-256 of the empty byte string.
pub fn empty_merkle_root_sha256() -> String {
    sha256_hex(&[])
}

/// Hash one raw transparency-log entry using RFC 9162's leaf prefix.
pub fn merkle_leaf_hash_sha256(entry: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(entry.len() + 1);
    input.push(0x00);
    input.extend_from_slice(entry);
    sha256(&input)
}

fn largest_power_of_two_less_than(value: u64) -> u64 {
    debug_assert!(value > 1);
    let mut power = 1u64;
    while power <= (value - 1) / 2 {
        power *= 2;
    }
    power
}

/// Verify one RFC 9162 Merkle inclusion proof. Proof nodes are lowercase
/// 32-byte SHA-256 hashes, in RFC order.
pub fn verify_merkle_inclusion_sha256(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    inclusion_path: &[String],
    expected_root_sha256: &str,
) -> Result<(), OciWitnessProofError> {
    if tree_size == 0
        || leaf_index >= tree_size
        || inclusion_path.len() > MAX_MERKLE_PROOF_NODES
    {
        return Err(OciWitnessProofError::InvalidInclusionProof);
    }
    let expected_root = decode_hex::<32>(expected_root_sha256)
        .map_err(|_| OciWitnessProofError::InvalidInclusionProof)?;

    let mut fn_index = leaf_index;
    let mut sn_index = tree_size - 1;
    let mut calculated = *leaf_hash;

    for sibling_hex in inclusion_path {
        if sn_index == 0 {
            return Err(OciWitnessProofError::InvalidInclusionProof);
        }
        let sibling = decode_hex::<32>(sibling_hex)
            .map_err(|_| OciWitnessProofError::InvalidInclusionProof)?;

        if (fn_index & 1) == 1 || fn_index == sn_index {
            calculated = merkle_node_hash(&sibling, &calculated);
            if (fn_index & 1) == 0 {
                while fn_index != 0 && (fn_index & 1) == 0 {
                    fn_index >>= 1;
                    sn_index >>= 1;
                }
            }
        } else {
            calculated = merkle_node_hash(&calculated, &sibling);
        }

        fn_index >>= 1;
        sn_index >>= 1;
    }

    if sn_index == 0 && calculated == expected_root {
        Ok(())
    } else {
        Err(OciWitnessProofError::InvalidInclusionProof)
    }
}

/// Verify that a new RFC 9162 tree head is an append-only extension of a
/// previously retained tree head. The caller must persist the accepted new
/// size/root outside the witness and candidate trust domains.
pub fn verify_merkle_consistency_sha256(
    old_size: u64,
    old_root_sha256: &str,
    new_size: u64,
    new_root_sha256: &str,
    consistency_path: &[String],
) -> Result<(), OciWitnessProofError> {
    let old_root = decode_hex::<32>(old_root_sha256)
        .map_err(|_| OciWitnessProofError::InvalidConsistencyProof)?;
    let new_root = decode_hex::<32>(new_root_sha256)
        .map_err(|_| OciWitnessProofError::InvalidConsistencyProof)?;

    if old_size > new_size || consistency_path.len() > MAX_MERKLE_PROOF_NODES {
        return Err(OciWitnessProofError::InvalidConsistencyProof);
    }
    if old_size == new_size {
        if old_root == new_root && consistency_path.is_empty() {
            return Ok(());
        }
        return Err(OciWitnessProofError::InvalidConsistencyProof);
    }
    if old_size == 0 {
        if new_size > 0 && old_root == sha256(&[]) && consistency_path.is_empty() {
            return Ok(());
        }
        return Err(OciWitnessProofError::InvalidConsistencyProof);
    }
    if consistency_path.is_empty() {
        return Err(OciWitnessProofError::InvalidConsistencyProof);
    }

    let mut fn_index = old_size - 1;
    let mut sn_index = new_size - 1;
    while (fn_index & 1) == 1 {
        fn_index >>= 1;
        sn_index >>= 1;
    }

    let mut proof_iter = consistency_path.iter();
    let first = if old_size.is_power_of_two() {
        old_root
    } else {
        decode_hex::<32>(
            proof_iter
                .next()
                .ok_or(OciWitnessProofError::InvalidConsistencyProof)?,
        )
        .map_err(|_| OciWitnessProofError::InvalidConsistencyProof)?
    };
    let mut first_root = first;
    let mut second_root = first;

    for sibling_hex in proof_iter {
        if sn_index == 0 {
            return Err(OciWitnessProofError::InvalidConsistencyProof);
        }
        let sibling = decode_hex::<32>(sibling_hex)
            .map_err(|_| OciWitnessProofError::InvalidConsistencyProof)?;

        if (fn_index & 1) == 1 || fn_index == sn_index {
            first_root = merkle_node_hash(&sibling, &first_root);
            second_root = merkle_node_hash(&sibling, &second_root);
            if (fn_index & 1) == 0 {
                while fn_index != 0 && (fn_index & 1) == 0 {
                    fn_index >>= 1;
                    sn_index >>= 1;
                }
            }
        } else {
            second_root = merkle_node_hash(&second_root, &sibling);
        }

        fn_index >>= 1;
        sn_index >>= 1;
    }

    if sn_index == 0 && first_root == old_root && second_root == new_root {
        Ok(())
    } else {
        Err(OciWitnessProofError::InvalidConsistencyProof)
    }
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

/// The exact entry committed into a witness's transparency log. It binds the
/// task-relevant checkpoint, exact witness request, idempotency key, and the
/// witness/key generation that accepted the append.
pub fn witness_leaf_input(
    witness_id: &str,
    key_id: &str,
    key_generation: u64,
    checkpoint_digest_blake3: &str,
    request_digest_blake3: &str,
    idempotency_key_blake3: &str,
    branch_endorsement_digest_blake3: &str,
) -> Result<Vec<u8>, OciWitnessProofError> {
    validate_identifier(witness_id)?;
    validate_identifier(key_id)?;
    if key_generation == 0 {
        return Err(OciWitnessProofError::InvalidShape);
    }
    validate_digest(checkpoint_digest_blake3)?;
    validate_digest(request_digest_blake3)?;
    validate_digest(idempotency_key_blake3)?;
    validate_digest(branch_endorsement_digest_blake3)?;

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(LEAF_DOMAIN);
    push_string(&mut out, witness_id);
    push_string(&mut out, key_id);
    out.extend_from_slice(&key_generation.to_le_bytes());
    push_string(&mut out, checkpoint_digest_blake3);
    push_string(&mut out, request_digest_blake3);
    push_string(&mut out, idempotency_key_blake3);
    push_string(&mut out, branch_endorsement_digest_blake3);
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOciWitnessTreeHead {
    pub schema_version: u32,
    pub kind: String,
    pub witness_id: String,
    pub key_id: String,
    pub key_generation: u64,
    pub tree_size: u64,
    pub root_hash_sha256: String,
    pub timestamp_ms: u64,
    pub signature_hex: String,
}

impl SignedOciWitnessTreeHead {
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, OciWitnessProofError> {
        if self.schema_version != OCI_WITNESS_RECEIPT_SCHEMA_VERSION
            || self.kind != OCI_WITNESS_TREE_HEAD_KIND
            || self.key_generation == 0
            || self.tree_size == 0
            || self.timestamp_ms == 0
        {
            return Err(OciWitnessProofError::InvalidShape);
        }
        validate_identifier(&self.witness_id)?;
        validate_identifier(&self.key_id)?;
        let root = decode_hex::<32>(&self.root_hash_sha256)?;

        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(TREE_HEAD_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        push_string(&mut out, &self.kind);
        push_string(&mut out, OCI_WITNESS_TREE_HASH_ALGORITHM);
        push_string(&mut out, &self.witness_id);
        push_string(&mut out, &self.key_id);
        out.extend_from_slice(&self.key_generation.to_le_bytes());
        out.extend_from_slice(&self.tree_size.to_le_bytes());
        out.extend_from_slice(&root);
        out.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OciObserverWitnessReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub checkpoint_digest_blake3: String,
    pub request_digest_blake3: String,
    pub idempotency_key_blake3: String,
    pub branch_endorsement_digest_blake3: String,
    pub leaf_index: u64,
    pub inclusion_path_sha256: Vec<String>,
    pub previous_tree_size: u64,
    pub previous_root_sha256: String,
    pub consistency_path_sha256: Vec<String>,
    pub tree_head: SignedOciWitnessTreeHead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedOciWitnessKey {
    /// Operator-assigned administrative trust domain. This is a configuration
    /// assertion, not a cryptographic proof that operators are independent.
    pub trust_domain_id: String,
    pub witness_id: String,
    pub key_id: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciWitnessReceiptExpectation {
    pub previous_tree_size: u64,
    pub previous_root_sha256: String,
    pub now_ms: u64,
    pub max_tree_head_age_ms: u64,
    pub max_future_skew_ms: u64,
}

/// Opaque, canonical witness request derived only from a verified observer
/// checkpoint. Callers cannot independently edit the request fields or
/// substitute arbitrary bytes while claiming they correspond to this token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciObserverWitnessRequest {
    observer_id_blake3: String,
    machine_id_blake3: String,
    boot_id: String,
    sequence: u64,
    checkpoint_digest_blake3: String,
    key_id: String,
    key_generation: u64,
    snapshot_digest_blake3: String,
    chain_head_blake3: String,
    previous_checkpoint_blake3: Option<String>,
    challenge_blake3: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl OciObserverWitnessRequest {
    pub fn from_verified_checkpoint(
        checkpoint: &VerifiedOciObserverCheckpoint,
    ) -> Result<Self, OciWitnessProofError> {
        let request = Self {
            observer_id_blake3: checkpoint.observer_id_blake3().to_owned(),
            machine_id_blake3: checkpoint.machine_id_blake3().to_owned(),
            boot_id: checkpoint.boot_id().to_owned(),
            sequence: checkpoint.sequence(),
            checkpoint_digest_blake3: checkpoint.checkpoint_digest_blake3().to_owned(),
            key_id: checkpoint.key_id().to_owned(),
            key_generation: checkpoint.key_generation(),
            snapshot_digest_blake3: checkpoint.snapshot_digest_blake3().to_owned(),
            chain_head_blake3: checkpoint.chain_head_blake3().to_owned(),
            previous_checkpoint_blake3: checkpoint.previous_checkpoint_blake3().map(str::to_owned),
            challenge_blake3: checkpoint.challenge_blake3().to_owned(),
            issued_at_ms: checkpoint.issued_at_ms(),
            expires_at_ms: checkpoint.expires_at_ms(),
        };
        request.canonical_bytes()?;
        Ok(request)
    }

    pub fn checkpoint_digest_blake3(&self) -> &str {
        &self.checkpoint_digest_blake3
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OciWitnessProofError> {
        if self.sequence == 0
            || self.key_generation == 0
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(OciWitnessProofError::InvalidShape);
        }
        validate_digest(&self.observer_id_blake3)?;
        validate_digest(&self.machine_id_blake3)?;
        validate_digest(&self.checkpoint_digest_blake3)?;
        validate_digest(&self.snapshot_digest_blake3)?;
        validate_digest(&self.chain_head_blake3)?;
        validate_digest(&self.challenge_blake3)?;
        validate_identifier(&self.boot_id)?;
        validate_identifier(&self.key_id)?;
        if let Some(previous) = &self.previous_checkpoint_blake3 {
            validate_digest(previous)?;
        }

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(WITNESS_REQUEST_DOMAIN);
        out.extend_from_slice(&OCI_WITNESS_RECEIPT_SCHEMA_VERSION.to_le_bytes());
        push_string(&mut out, OCI_WITNESS_RECEIPT_KIND);
        push_string(&mut out, &self.observer_id_blake3);
        push_string(&mut out, &self.machine_id_blake3);
        push_string(&mut out, &self.boot_id);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        push_string(&mut out, &self.checkpoint_digest_blake3);
        push_string(&mut out, &self.key_id);
        out.extend_from_slice(&self.key_generation.to_le_bytes());
        push_string(&mut out, &self.snapshot_digest_blake3);
        push_string(&mut out, &self.chain_head_blake3);
        match &self.previous_checkpoint_blake3 {
            Some(previous) => {
                out.push(1);
                push_string(&mut out, previous);
            }
            None => out.push(0),
        }
        push_string(&mut out, &self.challenge_blake3);
        out.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        Ok(out)
    }

    pub fn request_digest_blake3(&self) -> Result<String, OciWitnessProofError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn idempotency_key_blake3(&self) -> Result<String, OciWitnessProofError> {
        let request_digest = self.request_digest_blake3()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(IDEMPOTENCY_DOMAIN);
        hasher.update(&(self.checkpoint_digest_blake3.len() as u64).to_le_bytes());
        hasher.update(self.checkpoint_digest_blake3.as_bytes());
        hasher.update(&(request_digest.len() as u64).to_le_bytes());
        hasher.update(request_digest.as_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn matches_checkpoint(&self, checkpoint: &VerifiedOciObserverCheckpoint) -> bool {
        self.observer_id_blake3 == checkpoint.observer_id_blake3()
            && self.machine_id_blake3 == checkpoint.machine_id_blake3()
            && self.boot_id == checkpoint.boot_id()
            && self.sequence == checkpoint.sequence()
            && self.checkpoint_digest_blake3 == checkpoint.checkpoint_digest_blake3()
            && self.key_id == checkpoint.key_id()
            && self.key_generation == checkpoint.key_generation()
            && self.snapshot_digest_blake3 == checkpoint.snapshot_digest_blake3()
            && self.chain_head_blake3 == checkpoint.chain_head_blake3()
            && self.previous_checkpoint_blake3.as_deref()
                == checkpoint.previous_checkpoint_blake3()
            && self.challenge_blake3 == checkpoint.challenge_blake3()
            && self.issued_at_ms == checkpoint.issued_at_ms()
            && self.expires_at_ms == checkpoint.expires_at_ms()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciWitnessQuorumSubject {
    pub checkpoint_digest_blake3: String,
    pub request_digest_blake3: String,
    pub idempotency_key_blake3: String,
}

/// Opaque cryptographic evidence that one provisioned witness key signed
/// two different roots for the same tree size. This is a historical proof;
/// it remains meaningful even after the witness key is revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciWitnessEquivocation {
    witness_id: String,
    key_id: String,
    key_generation: u64,
    tree_size: u64,
    first_root_sha256: String,
    second_root_sha256: String,
    first_tree_head_digest_blake3: String,
    second_tree_head_digest_blake3: String,
}

impl VerifiedOciWitnessEquivocation {
    pub fn witness_id(&self) -> &str { &self.witness_id }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub fn key_generation(&self) -> u64 { self.key_generation }
    pub fn tree_size(&self) -> u64 { self.tree_size }
    pub fn first_root_sha256(&self) -> &str { &self.first_root_sha256 }
    pub fn second_root_sha256(&self) -> &str { &self.second_root_sha256 }
    pub fn first_tree_head_digest_blake3(&self) -> &str { &self.first_tree_head_digest_blake3 }
    pub fn second_tree_head_digest_blake3(&self) -> &str { &self.second_tree_head_digest_blake3 }
}

/// Verify two signed tree heads from the same provisioned witness key. A
/// different root at the same tree size is cryptographic evidence of
/// equivocation. This detects a split view only after both statements are
/// brought together by gossip or an independent monitor.
pub fn verify_witness_tree_head_equivocation(
    first: &SignedOciWitnessTreeHead,
    second: &SignedOciWitnessTreeHead,
    trusted_key: &TrustedOciWitnessKey,
) -> Result<VerifiedOciWitnessEquivocation, OciWitnessProofError> {
    validate_identifier(&trusted_key.witness_id)?;
    validate_identifier(&trusted_key.key_id)?;
    validate_trust_domain(&trusted_key.trust_domain_id)?;
    if trusted_key.key_generation == 0
        || trusted_key.valid_until_ms <= trusted_key.valid_from_ms
    {
        return Err(OciWitnessProofError::InvalidShape);
    }
    if first.witness_id != trusted_key.witness_id
        || second.witness_id != trusted_key.witness_id
        || first.key_id != trusted_key.key_id
        || second.key_id != trusted_key.key_id
        || first.key_generation != trusted_key.key_generation
        || second.key_generation != trusted_key.key_generation
        || first.tree_size != second.tree_size
    {
        return Err(OciWitnessProofError::WitnessIdentityMismatch);
    }
    if first.timestamp_ms < trusted_key.valid_from_ms
        || first.timestamp_ms >= trusted_key.valid_until_ms
        || second.timestamp_ms < trusted_key.valid_from_ms
        || second.timestamp_ms >= trusted_key.valid_until_ms
    {
        return Err(OciWitnessProofError::KeyNotCurrentlyValid);
    }
    let first_bytes = first.signing_bytes()?;
    let second_bytes = second.signing_bytes()?;
    let public_key = decode_hex::<32>(&trusted_key.public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| OciWitnessProofError::InvalidEncoding)?;
    let first_signature = Signature::from_bytes(&decode_hex::<64>(&first.signature_hex)?);
    let second_signature = Signature::from_bytes(&decode_hex::<64>(&second.signature_hex)?);
    verifying_key
        .verify_strict(&first_bytes, &first_signature)
        .map_err(|_| OciWitnessProofError::InvalidTreeHeadSignature)?;
    verifying_key
        .verify_strict(&second_bytes, &second_signature)
        .map_err(|_| OciWitnessProofError::InvalidTreeHeadSignature)?;
    if first.root_hash_sha256 == second.root_hash_sha256 {
        return Err(OciWitnessProofError::NotEquivocation);
    }

    let first_bytes = serde_json::to_vec(first).map_err(|_| OciWitnessProofError::InvalidShape)?;
    let second_bytes = serde_json::to_vec(second).map_err(|_| OciWitnessProofError::InvalidShape)?;
    let mut first_digest = blake3::Hasher::new();
    first_digest.update(RECEIPT_DIGEST_DOMAIN);
    first_digest.update(&(first_bytes.len() as u64).to_le_bytes());
    first_digest.update(&first_bytes);
    let mut second_digest = blake3::Hasher::new();
    second_digest.update(RECEIPT_DIGEST_DOMAIN);
    second_digest.update(&(second_bytes.len() as u64).to_le_bytes());
    second_digest.update(&second_bytes);

    Ok(VerifiedOciWitnessEquivocation {
        witness_id: first.witness_id.clone(),
        key_id: first.key_id.clone(),
        key_generation: first.key_generation,
        tree_size: first.tree_size,
        first_root_sha256: first.root_hash_sha256.clone(),
        second_root_sha256: second.root_hash_sha256.clone(),
        first_tree_head_digest_blake3: first_digest.finalize().to_hex().to_string(),
        second_tree_head_digest_blake3: second_digest.finalize().to_hex().to_string(),
    })
}

pub struct OciWitnessEvidence<'a> {
    pub receipt: &'a OciObserverWitnessReceipt,
    pub trusted_key: &'a TrustedOciWitnessKey,
    pub expectation: &'a OciWitnessReceiptExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciWitnessReceipt {
    witness_id: String,
    trust_domain_id: String,
    checkpoint_digest_blake3: String,
    request_digest_blake3: String,
    idempotency_key_blake3: String,
    branch_endorsement_digest_blake3: String,
    key_id: String,
    key_generation: u64,
    signer_public_key_hex: String,
    tree_head_timestamp_ms: u64,
    previous_tree_size: u64,
    previous_root_sha256: String,
    tree_size: u64,
    root_hash_sha256: String,
    receipt_digest_blake3: String,
    receipt_bytes: Vec<u8>,
}

impl VerifiedOciWitnessReceipt {
    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }
    pub fn trust_domain_id(&self) -> &str {
        &self.trust_domain_id
    }
    pub fn checkpoint_digest_blake3(&self) -> &str {
        &self.checkpoint_digest_blake3
    }
    pub fn request_digest_blake3(&self) -> &str {
        &self.request_digest_blake3
    }
    pub fn idempotency_key_blake3(&self) -> &str {
        &self.idempotency_key_blake3
    }
    pub fn branch_endorsement_digest_blake3(&self) -> &str {
        &self.branch_endorsement_digest_blake3
    }
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    pub(crate) fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub(crate) fn signer_public_key_hex(&self) -> &str {
        &self.signer_public_key_hex
    }
    pub(crate) fn tree_head_timestamp_ms(&self) -> u64 {
        self.tree_head_timestamp_ms
    }
    pub(crate) fn previous_tree_size(&self) -> u64 {
        self.previous_tree_size
    }
    pub(crate) fn previous_root_sha256(&self) -> &str {
        &self.previous_root_sha256
    }
    pub(crate) fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }
    pub fn root_hash_sha256(&self) -> &str {
        &self.root_hash_sha256
    }
    pub fn receipt_digest_blake3(&self) -> &str {
        &self.receipt_digest_blake3
    }
}

/// Opaque result of verifying all supplied witness receipts. This proves only
/// that the configured quorum policy was satisfied by these trust records and
/// cryptographic proofs; operator-assigned trust domains still need review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOciWitnessQuorum {
    checkpoint_digest_blake3: String,
    request_digest_blake3: String,
    idempotency_key_blake3: String,
    required_trust_domains: usize,
    receipts: Vec<VerifiedOciWitnessReceipt>,
    evidence_digest_blake3: String,
}

impl VerifiedOciWitnessQuorum {
    pub fn checkpoint_digest_blake3(&self) -> &str {
        &self.checkpoint_digest_blake3
    }
    pub fn request_digest_blake3(&self) -> &str {
        &self.request_digest_blake3
    }
    pub fn idempotency_key_blake3(&self) -> &str {
        &self.idempotency_key_blake3
    }
    pub fn required_trust_domains(&self) -> usize {
        self.required_trust_domains
    }
    pub fn receipts(&self) -> &[VerifiedOciWitnessReceipt] {
        &self.receipts
    }
    pub fn evidence_digest_blake3(&self) -> &str {
        &self.evidence_digest_blake3
    }
}

pub fn verify_witness_receipt(
    receipt: &OciObserverWitnessReceipt,
    trusted_key: &TrustedOciWitnessKey,
    subject: &OciWitnessQuorumSubject,
    expectation: &OciWitnessReceiptExpectation,
) -> Result<VerifiedOciWitnessReceipt, OciWitnessProofError> {
    if receipt.schema_version != OCI_WITNESS_RECEIPT_SCHEMA_VERSION
        || receipt.kind != OCI_WITNESS_RECEIPT_KIND
        || receipt.inclusion_path_sha256.len() > MAX_MERKLE_PROOF_NODES
        || receipt.consistency_path_sha256.len() > MAX_MERKLE_PROOF_NODES
        || receipt.tree_head.tree_size <= receipt.previous_tree_size
        || receipt.leaf_index >= receipt.tree_head.tree_size
    {
        return Err(OciWitnessProofError::InvalidShape);
    }

    validate_trust_domain(&trusted_key.trust_domain_id)?;
    validate_identifier(&trusted_key.witness_id)?;
    validate_identifier(&trusted_key.key_id)?;
    if trusted_key.key_generation == 0
        || trusted_key.valid_until_ms <= trusted_key.valid_from_ms
    {
        return Err(OciWitnessProofError::InvalidShape);
    }

    if receipt.checkpoint_digest_blake3 != subject.checkpoint_digest_blake3
        || receipt.request_digest_blake3 != subject.request_digest_blake3
        || receipt.idempotency_key_blake3 != subject.idempotency_key_blake3
    {
        return Err(OciWitnessProofError::SubjectMismatch);
    }

    let head = &receipt.tree_head;
    if head.witness_id != trusted_key.witness_id
        || head.key_id != trusted_key.key_id
        || head.key_generation != trusted_key.key_generation
    {
        return Err(OciWitnessProofError::WitnessIdentityMismatch);
    }

    if expectation.now_ms < trusted_key.valid_from_ms
        || expectation.now_ms >= trusted_key.valid_until_ms
        || head.timestamp_ms < trusted_key.valid_from_ms
        || head.timestamp_ms >= trusted_key.valid_until_ms
    {
        return Err(OciWitnessProofError::KeyNotCurrentlyValid);
    }
    if trusted_key
        .revoked_at_ms
        .is_some_and(|revoked_at| expectation.now_ms >= revoked_at)
    {
        return Err(OciWitnessProofError::KeyRevoked);
    }
    if head.timestamp_ms > expectation.now_ms
        && head.timestamp_ms - expectation.now_ms > expectation.max_future_skew_ms
    {
        return Err(OciWitnessProofError::TreeHeadFromFuture);
    }
    if expectation.now_ms.saturating_sub(head.timestamp_ms)
        > expectation.max_tree_head_age_ms
    {
        return Err(OciWitnessProofError::TreeHeadStale);
    }

    let signing_bytes = head.signing_bytes()?;
    let public_key = decode_hex::<32>(&trusted_key.public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| OciWitnessProofError::InvalidEncoding)?;
    let signature_bytes = decode_hex::<64>(&head.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| OciWitnessProofError::InvalidTreeHeadSignature)?;

    if receipt.previous_tree_size != expectation.previous_tree_size
        || receipt.previous_root_sha256 != expectation.previous_root_sha256
    {
        return Err(OciWitnessProofError::PriorTreeHeadMismatch);
    }

    verify_merkle_consistency_sha256(
        receipt.previous_tree_size,
        &receipt.previous_root_sha256,
        head.tree_size,
        &head.root_hash_sha256,
        &receipt.consistency_path_sha256,
    )?;

    let leaf_input = witness_leaf_input(
        &head.witness_id,
        &head.key_id,
        head.key_generation,
        &receipt.checkpoint_digest_blake3,
        &receipt.request_digest_blake3,
        &receipt.idempotency_key_blake3,
        &receipt.branch_endorsement_digest_blake3,
    )?;
    let leaf_hash = merkle_leaf_hash_sha256(&leaf_input);
    verify_merkle_inclusion_sha256(
        &leaf_hash,
        receipt.leaf_index,
        head.tree_size,
        &receipt.inclusion_path_sha256,
        &head.root_hash_sha256,
    )?;

    let receipt_bytes = serde_json::to_vec(receipt).map_err(|_| OciWitnessProofError::InvalidShape)?;
    let mut digest = blake3::Hasher::new();
    digest.update(RECEIPT_DIGEST_DOMAIN);
    digest.update(&(receipt_bytes.len() as u64).to_le_bytes());
    digest.update(&receipt_bytes);

    Ok(VerifiedOciWitnessReceipt {
        witness_id: head.witness_id.clone(),
        trust_domain_id: trusted_key.trust_domain_id.clone(),
        checkpoint_digest_blake3: receipt.checkpoint_digest_blake3.clone(),
        request_digest_blake3: receipt.request_digest_blake3.clone(),
        idempotency_key_blake3: receipt.idempotency_key_blake3.clone(),
        branch_endorsement_digest_blake3: receipt.branch_endorsement_digest_blake3.clone(),
        key_id: head.key_id.clone(),
        key_generation: head.key_generation,
        signer_public_key_hex: encode_hex(&public_key),
        tree_head_timestamp_ms: head.timestamp_ms,
        previous_tree_size: receipt.previous_tree_size,
        previous_root_sha256: receipt.previous_root_sha256.clone(),
        tree_size: head.tree_size,
        root_hash_sha256: head.root_hash_sha256.clone(),
        receipt_digest_blake3: digest.finalize().to_hex().to_string(),
        receipt_bytes,
    })
}

/// Verify a quorum of distinct witness identities in distinct operator-assigned
/// trust domains (up to four). The durable high-assurance store separately
/// enforces a 3-of-4 profile. All receipts must commit to exactly the same checkpoint,
/// request and idempotency key. A 2-of-3 threshold is a policy assumption, not
/// a proof that the trust domains are operationally independent.
pub fn verify_witness_quorum(
    subject: &OciWitnessQuorumSubject,
    evidence: &[OciWitnessEvidence<'_>],
    required_trust_domains: usize,
) -> Result<VerifiedOciWitnessQuorum, OciWitnessProofError> {
    validate_digest(&subject.checkpoint_digest_blake3)?;
    validate_digest(&subject.request_digest_blake3)?;
    validate_digest(&subject.idempotency_key_blake3)?;

    if !(1..=MAX_WITNESSES).contains(&required_trust_domains) {
        return Err(OciWitnessProofError::InvalidQuorumThreshold);
    }
    if evidence.len() < required_trust_domains || evidence.len() > MAX_WITNESSES {
        return Err(OciWitnessProofError::QuorumNotMet);
    }

    let mut witness_ids = BTreeSet::new();
    let mut trust_domains = BTreeSet::new();
    let mut verified = Vec::with_capacity(evidence.len());

    for item in evidence {
        if !witness_ids.insert(item.trusted_key.witness_id.clone()) {
            return Err(OciWitnessProofError::DuplicateWitness);
        }
        if !trust_domains.insert(item.trusted_key.trust_domain_id.clone()) {
            return Err(OciWitnessProofError::DuplicateTrustDomain);
        }

        let receipt = verify_witness_receipt(
            item.receipt,
            item.trusted_key,
            subject,
            item.expectation,
        )?;
        verified.push(receipt);
    }

    if trust_domains.len() < required_trust_domains {
        return Err(OciWitnessProofError::QuorumNotMet);
    }

    verified.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    let mut digest = blake3::Hasher::new();
    digest.update(QUORUM_DIGEST_DOMAIN);
    digest.update(&(required_trust_domains as u64).to_le_bytes());
    digest.update(&(verified.len() as u64).to_le_bytes());
    for receipt in &verified {
        digest.update(&(receipt.receipt_digest_blake3.len() as u64).to_le_bytes());
        digest.update(receipt.receipt_digest_blake3.as_bytes());
        digest.update(&(receipt.trust_domain_id.len() as u64).to_le_bytes());
        digest.update(receipt.trust_domain_id.as_bytes());
    }

    Ok(VerifiedOciWitnessQuorum {
        checkpoint_digest_blake3: subject.checkpoint_digest_blake3.clone(),
        request_digest_blake3: subject.request_digest_blake3.clone(),
        idempotency_key_blake3: subject.idempotency_key_blake3.clone(),
        required_trust_domains,
        receipts: verified,
        evidence_digest_blake3: digest.finalize().to_hex().to_string(),
    })
}

#[cfg(test)]
pub(crate) fn make_test_witness_quorum_for_request_with_branch_endorsement_digests(
    request: &OciObserverWitnessRequest,
    branch_endorsement_digests: &[String],
) -> Result<(Vec<TrustedOciWitnessKey>, VerifiedOciWitnessQuorum), OciWitnessProofError> {
    use ed25519_dalek::{Signer, SigningKey};

    let witness_count = branch_endorsement_digests.len();
    if !(1..=MAX_WITNESSES).contains(&witness_count) {
        return Err(OciWitnessProofError::InvalidQuorumThreshold);
    }

    let subject = OciWitnessQuorumSubject {
        checkpoint_digest_blake3: request.checkpoint_digest_blake3().to_owned(),
        request_digest_blake3: request.request_digest_blake3()?,
        idempotency_key_blake3: request.idempotency_key_blake3()?,
    };

    let mut signing_keys = Vec::with_capacity(witness_count);
    let mut trusted_keys = Vec::with_capacity(witness_count);
    let mut receipts = Vec::with_capacity(witness_count);
    let mut expectations = Vec::with_capacity(witness_count);

    for index in 0..witness_count {
        let seed = 41u8 + index as u8;
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let suffix = (b'a' + index as u8) as char;
        let witness_id = format!("witness-{suffix}");
        let trusted_key = TrustedOciWitnessKey {
            trust_domain_id: format!("operator-{suffix}"),
            witness_id: witness_id.clone(),
            key_id: format!("key-{suffix}"),
            key_generation: 1,
            public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        };
        let leaf_input = witness_leaf_input(
            &trusted_key.witness_id,
            &trusted_key.key_id,
            trusted_key.key_generation,
            &subject.checkpoint_digest_blake3,
            &subject.request_digest_blake3,
            &subject.idempotency_key_blake3,
            &branch_endorsement_digests[index],
        )?;
        let root = merkle_leaf_hash_sha256(&leaf_input);
        let mut tree_head = SignedOciWitnessTreeHead {
            schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
            kind: OCI_WITNESS_TREE_HEAD_KIND.to_owned(),
            witness_id: trusted_key.witness_id.clone(),
            key_id: trusted_key.key_id.clone(),
            key_generation: trusted_key.key_generation,
            tree_size: 1,
            root_hash_sha256: encode_hex(&root),
            timestamp_ms: 1_100,
            signature_hex: String::new(),
        };
        tree_head.signature_hex =
            encode_hex(&signing_key.sign(&tree_head.signing_bytes()?).to_bytes());

        receipts.push(OciObserverWitnessReceipt {
            schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
            kind: OCI_WITNESS_RECEIPT_KIND.to_owned(),
            checkpoint_digest_blake3: subject.checkpoint_digest_blake3.clone(),
            request_digest_blake3: subject.request_digest_blake3.clone(),
            idempotency_key_blake3: subject.idempotency_key_blake3.clone(),
            branch_endorsement_digest_blake3: branch_endorsement_digests[index].clone(),
            leaf_index: 0,
            inclusion_path_sha256: Vec::new(),
            previous_tree_size: 0,
            previous_root_sha256: empty_merkle_root_sha256(),
            consistency_path_sha256: Vec::new(),
            tree_head,
        });
        expectations.push(OciWitnessReceiptExpectation {
            previous_tree_size: 0,
            previous_root_sha256: empty_merkle_root_sha256(),
            now_ms: 1_200,
            max_tree_head_age_ms: 500,
            max_future_skew_ms: 0,
        });
        signing_keys.push(signing_key);
        trusted_keys.push(trusted_key);
    }

    let evidence: Vec<OciWitnessEvidence<'_>> = receipts
        .iter()
        .zip(trusted_keys.iter())
        .zip(expectations.iter())
        .map(|((receipt, trusted_key), expectation)| OciWitnessEvidence {
            receipt,
            trusted_key,
            expectation,
        })
        .collect();
    let quorum = verify_witness_quorum(&subject, &evidence, witness_count)?;
    drop(signing_keys);
    Ok((trusted_keys, quorum))
}

#[cfg(test)]
pub(crate) fn make_test_witness_quorum_for_request(
    request: &OciObserverWitnessRequest,
    witness_count: usize,
) -> Result<(Vec<TrustedOciWitnessKey>, VerifiedOciWitnessQuorum), OciWitnessProofError> {
    let branch_endorsement_digests = vec!["00".repeat(32); witness_count];
    make_test_witness_quorum_for_request_with_branch_endorsement_digests(
        request,
        &branch_endorsement_digests,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn mth(entries: &[Vec<u8>]) -> [u8; 32] {
        match entries.len() {
            0 => sha256(&[]),
            1 => merkle_leaf_hash_sha256(&entries[0]),
            n => {
                let split = largest_power_of_two_less_than(n as u64) as usize;
                merkle_node_hash(&mth(&entries[..split]), &mth(&entries[split..]))
            }
        }
    }

    fn inclusion_path(entries: &[Vec<u8>], index: usize) -> Vec<String> {
        assert!(index < entries.len());
        if entries.len() == 1 {
            return Vec::new();
        }
        let split = largest_power_of_two_less_than(entries.len() as u64) as usize;
        let mut proof = if index < split {
            inclusion_path(&entries[..split], index)
        } else {
            inclusion_path(&entries[split..], index - split)
        };
        let sibling = if index < split {
            mth(&entries[split..])
        } else {
            mth(&entries[..split])
        };
        proof.push(encode_hex(&sibling));
        proof
    }

    fn consistency_subproof(
        old_size: usize,
        entries: &[Vec<u8>],
        complete_subtree: bool,
    ) -> Vec<String> {
        if old_size == entries.len() {
            return if complete_subtree {
                Vec::new()
            } else {
                vec![encode_hex(&mth(entries))]
            };
        }
        let split = largest_power_of_two_less_than(entries.len() as u64) as usize;
        if old_size <= split {
            let mut proof =
                consistency_subproof(old_size, &entries[..split], complete_subtree);
            proof.push(encode_hex(&mth(&entries[split..])));
            proof
        } else {
            let mut proof =
                consistency_subproof(old_size - split, &entries[split..], false);
            proof.push(encode_hex(&mth(&entries[..split])));
            proof
        }
    }

    fn consistency_path(old_size: usize, entries: &[Vec<u8>]) -> Vec<String> {
        if old_size == 0 || old_size == entries.len() {
            Vec::new()
        } else {
            consistency_subproof(old_size, entries, true)
        }
    }

    fn subject() -> OciWitnessQuorumSubject {
        OciWitnessQuorumSubject {
            checkpoint_digest_blake3: "11".repeat(32),
            request_digest_blake3: "22".repeat(32),
            idempotency_key_blake3: "33".repeat(32),
        }
    }

    fn trusted(signing: &SigningKey, witness_id: &str) -> TrustedOciWitnessKey {
        TrustedOciWitnessKey {
            trust_domain_id: format!("operator-{witness_id}"),
            witness_id: witness_id.to_owned(),
            key_id: format!("key-{witness_id}"),
            key_generation: 1,
            public_key_hex: encode_hex(signing.verifying_key().as_bytes()),
            valid_from_ms: 100,
            valid_until_ms: 10_000,
            revoked_at_ms: None,
        }
    }

    fn receipt_fixture(
        signing: &SigningKey,
        trusted: &TrustedOciWitnessKey,
        prior_entries: &[Vec<u8>],
    ) -> (OciObserverWitnessReceipt, OciWitnessReceiptExpectation) {
        let sub = subject();
        let branch_endorsement_digest_blake3 = "11".repeat(32);
        let leaf_input = witness_leaf_input(
            &trusted.witness_id,
            &trusted.key_id,
            trusted.key_generation,
            &sub.checkpoint_digest_blake3,
            &sub.request_digest_blake3,
            &sub.idempotency_key_blake3,
            &branch_endorsement_digest_blake3,
        )
        .unwrap();

        let mut entries = prior_entries.to_vec();
        let leaf_index = entries.len();
        entries.push(leaf_input);

        let previous_tree_size = prior_entries.len() as u64;
        let previous_root_sha256 = encode_hex(&mth(prior_entries));
        let tree_size = entries.len() as u64;
        let root_hash_sha256 = encode_hex(&mth(&entries));

        let mut head = SignedOciWitnessTreeHead {
            schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
            kind: OCI_WITNESS_TREE_HEAD_KIND.to_owned(),
            witness_id: trusted.witness_id.clone(),
            key_id: trusted.key_id.clone(),
            key_generation: trusted.key_generation,
            tree_size,
            root_hash_sha256: root_hash_sha256.clone(),
            timestamp_ms: 1_100,
            signature_hex: String::new(),
        };
        head.signature_hex = encode_hex(&signing.sign(&head.signing_bytes().unwrap()).to_bytes());

        let receipt = OciObserverWitnessReceipt {
            schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
            kind: OCI_WITNESS_RECEIPT_KIND.to_owned(),
            checkpoint_digest_blake3: sub.checkpoint_digest_blake3,
            request_digest_blake3: sub.request_digest_blake3,
            idempotency_key_blake3: sub.idempotency_key_blake3,
            branch_endorsement_digest_blake3,
            leaf_index: leaf_index as u64,
            inclusion_path_sha256: inclusion_path(&entries, leaf_index),
            previous_tree_size,
            previous_root_sha256: previous_root_sha256.clone(),
            consistency_path_sha256: consistency_path(prior_entries.len(), &entries),
            tree_head: head,
        };
        let expectation = OciWitnessReceiptExpectation {
            previous_tree_size,
            previous_root_sha256,
            now_ms: 1_200,
            max_tree_head_age_ms: 500,
            max_future_skew_ms: 10,
        };
        (receipt, expectation)
    }

    fn single_receipt_evidence(
        witness_id: &str,
    ) -> (
        SigningKey,
        TrustedOciWitnessKey,
        OciObserverWitnessReceipt,
        OciWitnessReceiptExpectation,
    ) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trust = trusted(&signing, witness_id);
        let (receipt, expectation) = receipt_fixture(&signing, &trust, &[]);
        (signing, trust, receipt, expectation)
    }

    #[test]
    fn verifies_single_witness_receipt_with_inclusion_and_genesis_consistency() {
        let (_signing, trust, receipt, expectation) = single_receipt_evidence("witness-a");
        let verified = verify_witness_receipt(&receipt, &trust, &subject(), &expectation).unwrap();
        assert_eq!(verified.witness_id(), "witness-a");
        assert_eq!(verified.tree_size(), 1);
        assert_eq!(verified.checkpoint_digest_blake3(), "11".repeat(32));
    }

    #[test]
    fn detects_two_valid_signed_roots_at_the_same_tree_size() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trust = trusted(&signing, "witness-a");
        let make_head = |root: &str| {
            let mut head = SignedOciWitnessTreeHead {
                schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
                kind: OCI_WITNESS_TREE_HEAD_KIND.to_owned(),
                witness_id: trust.witness_id.clone(),
                key_id: trust.key_id.clone(),
                key_generation: trust.key_generation,
                tree_size: 7,
                root_hash_sha256: root.to_owned(),
                timestamp_ms: 1_100,
                signature_hex: String::new(),
            };
            head.signature_hex = encode_hex(&signing.sign(&head.signing_bytes().unwrap()).to_bytes());
            head
        };
        let first = make_head(&"aa".repeat(32));
        let second = make_head(&"bb".repeat(32));
        let evidence = verify_witness_tree_head_equivocation(&first, &second, &trust).unwrap();
        assert_eq!(evidence.witness_id(), "witness-a");
        assert_eq!(evidence.tree_size(), 7);
        assert_ne!(evidence.first_root_sha256(), evidence.second_root_sha256());
        assert_ne!(
            evidence.first_tree_head_digest_blake3(),
            evidence.second_tree_head_digest_blake3()
        );
    }

    #[test]
    fn rejects_same_root_as_non_equivocation() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trust = trusted(&signing, "witness-a");
        let make_head = || {
            let mut head = SignedOciWitnessTreeHead {
                schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
                kind: OCI_WITNESS_TREE_HEAD_KIND.to_owned(),
                witness_id: trust.witness_id.clone(),
                key_id: trust.key_id.clone(),
                key_generation: trust.key_generation,
                tree_size: 7,
                root_hash_sha256: "aa".repeat(32),
                timestamp_ms: 1_100,
                signature_hex: String::new(),
            };
            head.signature_hex = encode_hex(&signing.sign(&head.signing_bytes().unwrap()).to_bytes());
            head
        };
        let first = make_head();
        let second = make_head();
        assert_eq!(
            verify_witness_tree_head_equivocation(&first, &second, &trust),
            Err(OciWitnessProofError::NotEquivocation)
        );
    }

    #[test]
    fn rejects_equivocation_pair_signed_by_untrusted_key() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_signing = SigningKey::from_bytes(&[43u8; 32]);
        let trust = trusted(&signing, "witness-a");
        let make_head = |key: &SigningKey, root: &str| {
            let mut head = SignedOciWitnessTreeHead {
                schema_version: OCI_WITNESS_RECEIPT_SCHEMA_VERSION,
                kind: OCI_WITNESS_TREE_HEAD_KIND.to_owned(),
                witness_id: trust.witness_id.clone(),
                key_id: trust.key_id.clone(),
                key_generation: trust.key_generation,
                tree_size: 7,
                root_hash_sha256: root.to_owned(),
                timestamp_ms: 1_100,
                signature_hex: String::new(),
            };
            head.signature_hex = encode_hex(&key.sign(&head.signing_bytes().unwrap()).to_bytes());
            head
        };
        let first = make_head(&signing, &"aa".repeat(32));
        let second = make_head(&wrong_signing, &"bb".repeat(32));
        assert_eq!(
            verify_witness_tree_head_equivocation(&first, &second, &trust),
            Err(OciWitnessProofError::InvalidTreeHeadSignature)
        );
    }

    #[test]
    fn verifies_published_rfc9162_seven_leaf_proof_shapes() {
        let entries: Vec<Vec<u8>> = (0..7)
            .map(|index| format!("rfc9162-leaf-{index}").into_bytes())
            .collect();
        let root = encode_hex(&mth(&entries));

        for index in [0usize, 3, 4] {
            let proof = inclusion_path(&entries, index);
            assert_eq!(proof.len(), 3);
            let leaf = merkle_leaf_hash_sha256(&entries[index]);
            verify_merkle_inclusion_sha256(
                &leaf,
                index as u64,
                7,
                &proof,
                &root,
            )
            .unwrap();
        }
        let last_proof = inclusion_path(&entries, 6);
        assert_eq!(last_proof.len(), 2);
        verify_merkle_inclusion_sha256(
            &merkle_leaf_hash_sha256(&entries[6]),
            6,
            7,
            &last_proof,
            &root,
        )
        .unwrap();

        for (old_size, expected_path_len) in [(3usize, 4usize), (4, 1), (6, 3)] {
            let old_root = encode_hex(&mth(&entries[..old_size]));
            let proof = consistency_path(old_size, &entries);
            assert_eq!(proof.len(), expected_path_len);
            verify_merkle_consistency_sha256(
                old_size as u64,
                &old_root,
                7,
                &root,
                &proof,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_tree_head_signature_mutation() {
        let (_signing, trust, mut receipt, expectation) =
            single_receipt_evidence("witness-a");
        receipt.tree_head.root_hash_sha256 = "ff".repeat(32);
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::InvalidTreeHeadSignature)
        );
    }

    #[test]
    fn rejects_inclusion_path_mutation() {
        let (_signing, trust, mut receipt, expectation) =
            single_receipt_evidence("witness-a");
        receipt.inclusion_path_sha256.push("aa".repeat(32));
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::InvalidInclusionProof)
        );
    }

    #[test]
    fn rejects_branch_endorsement_digest_substitution() {
        let (_signing, trust, mut receipt, expectation) = single_receipt_evidence("witness-a");
        receipt.branch_endorsement_digest_blake3 = "ff".repeat(32);
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::InvalidInclusionProof)
        );
    }

    #[test]
    fn rejects_checkpoint_or_request_substitution() {
        let (_signing, trust, receipt, expectation) = single_receipt_evidence("witness-a");
        let mut altered = subject();
        altered.checkpoint_digest_blake3 = "44".repeat(32);
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &altered, &expectation),
            Err(OciWitnessProofError::SubjectMismatch)
        );
    }

    #[test]
    fn rejects_stale_signed_tree_head() {
        let (_signing, trust, receipt, mut expectation) =
            single_receipt_evidence("witness-a");
        expectation.now_ms = 2_000;
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::TreeHeadStale)
        );
    }

    #[test]
    fn rejects_revoked_witness_key_for_new_admission() {
        let (_signing, mut trust, receipt, expectation) =
            single_receipt_evidence("witness-a");
        trust.revoked_at_ms = Some(1_150);
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::KeyRevoked)
        );
    }

    #[test]
    fn verifies_witness_receipt_extending_nonempty_prior_history() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trust = trusted(&signing, "witness-a");
        let prior = vec![b"older-0".to_vec(), b"older-1".to_vec()];
        let (receipt, expectation) = receipt_fixture(&signing, &trust, &prior);
        let verified =
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation).unwrap();
        assert_eq!(verified.tree_size(), 3);
        assert_eq!(verified.root_hash_sha256(), receipt.tree_head.root_hash_sha256);
        assert_eq!(verified.checkpoint_digest_blake3(), "11".repeat(32));
    }

    #[test]
    fn rejects_prior_tree_head_substitution() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let trust = trusted(&signing, "witness-a");
        let prior = vec![b"older-0".to_vec(), b"older-1".to_vec()];
        let (receipt, mut expectation) = receipt_fixture(&signing, &trust, &prior);
        expectation.previous_root_sha256 = "ff".repeat(32);
        assert_eq!(
            verify_witness_receipt(&receipt, &trust, &subject(), &expectation),
            Err(OciWitnessProofError::PriorTreeHeadMismatch)
        );
    }

    #[test]
    fn verifies_rfc9162_consistency_proofs_for_many_tree_sizes() {
        let entries: Vec<Vec<u8>> = (0..40)
            .map(|index| format!("entry-{index}").into_bytes())
            .collect();
        for new_size in 1..=entries.len() {
            for old_size in 0..new_size {
                let old_root = encode_hex(&mth(&entries[..old_size]));
                let new_root = encode_hex(&mth(&entries[..new_size]));
                let proof = consistency_path(old_size, &entries[..new_size]);
                verify_merkle_consistency_sha256(
                    old_size as u64,
                    &old_root,
                    new_size as u64,
                    &new_root,
                    &proof,
                )
                .unwrap_or_else(|error| {
                    panic!("consistency failed for old={old_size}, new={new_size}: {error}")
                });
            }
        }
    }

    #[test]
    fn verifies_rfc9162_inclusion_for_every_leaf_in_many_tree_sizes() {
        let entries: Vec<Vec<u8>> = (0..40)
            .map(|index| format!("leaf-{index}").into_bytes())
            .collect();
        for tree_size in 1..=entries.len() {
            let root = encode_hex(&mth(&entries[..tree_size]));
            for leaf_index in 0..tree_size {
                let proof = inclusion_path(&entries[..tree_size], leaf_index);
                let leaf = merkle_leaf_hash_sha256(&entries[leaf_index]);
                verify_merkle_inclusion_sha256(
                    &leaf,
                    leaf_index as u64,
                    tree_size as u64,
                    &proof,
                    &root,
                )
                .unwrap_or_else(|error| {
                    panic!("inclusion failed for leaf={leaf_index}, size={tree_size}: {error}")
                });
            }
        }
    }

    #[test]
    fn rejects_mismatched_zero_size_tree_heads() {
        assert_eq!(
            verify_merkle_consistency_sha256(0, &empty_merkle_root_sha256(), 0, &"ff".repeat(32), &[]),
            Err(OciWitnessProofError::InvalidConsistencyProof)
        );
    }

    #[test]
    fn rejects_consistency_proof_mutation() {
        let entries: Vec<Vec<u8>> = (0..7)
            .map(|index| format!("entry-{index}").into_bytes())
            .collect();
        let old_root = encode_hex(&mth(&entries[..3]));
        let new_root = encode_hex(&mth(&entries));
        let mut proof = consistency_path(3, &entries);
        proof[0] = "ff".repeat(32);
        assert_eq!(
            verify_merkle_consistency_sha256(3, &old_root, 7, &new_root, &proof),
            Err(OciWitnessProofError::InvalidConsistencyProof)
        );
    }

    #[test]
    fn accepts_two_distinct_witness_trust_domains() {
        let signing_a = SigningKey::from_bytes(&[41u8; 32]);
        let signing_b = SigningKey::from_bytes(&[42u8; 32]);
        let trust_a = trusted(&signing_a, "witness-a");
        let trust_b = trusted(&signing_b, "witness-b");
        let (receipt_a, expectation_a) = receipt_fixture(&signing_a, &trust_a, &[]);
        let (receipt_b, expectation_b) = receipt_fixture(&signing_b, &trust_b, &[]);
        let evidence = [
            OciWitnessEvidence {
                receipt: &receipt_a,
                trusted_key: &trust_a,
                expectation: &expectation_a,
            },
            OciWitnessEvidence {
                receipt: &receipt_b,
                trusted_key: &trust_b,
                expectation: &expectation_b,
            },
        ];
        let quorum = verify_witness_quorum(&subject(), &evidence, 2).unwrap();
        assert_eq!(quorum.required_trust_domains(), 2);
        assert_eq!(quorum.receipts().len(), 2);
        assert_eq!(quorum.checkpoint_digest_blake3(), "11".repeat(32));
        assert_eq!(quorum.request_digest_blake3(), "22".repeat(32));
    }

    #[test]
    fn rejects_duplicate_witness_identity_in_quorum() {
        let signing_a = SigningKey::from_bytes(&[41u8; 32]);
        let signing_b = SigningKey::from_bytes(&[42u8; 32]);
        let trust_a = trusted(&signing_a, "witness-a");
        let mut trust_b = trusted(&signing_b, "witness-a");
        trust_b.trust_domain_id = "operator-b".to_owned();
        let (receipt_a, expectation_a) = receipt_fixture(&signing_a, &trust_a, &[]);
        let (receipt_b, expectation_b) = receipt_fixture(&signing_b, &trust_b, &[]);
        let evidence = [
            OciWitnessEvidence {
                receipt: &receipt_a,
                trusted_key: &trust_a,
                expectation: &expectation_a,
            },
            OciWitnessEvidence {
                receipt: &receipt_b,
                trusted_key: &trust_b,
                expectation: &expectation_b,
            },
        ];
        assert_eq!(
            verify_witness_quorum(&subject(), &evidence, 2),
            Err(OciWitnessProofError::DuplicateWitness)
        );
    }

    #[test]
    fn rejects_duplicate_administrative_trust_domain_in_quorum() {
        let signing_a = SigningKey::from_bytes(&[41u8; 32]);
        let signing_b = SigningKey::from_bytes(&[42u8; 32]);
        let trust_a = trusted(&signing_a, "witness-a");
        let mut trust_b = trusted(&signing_b, "witness-b");
        trust_b.trust_domain_id = trust_a.trust_domain_id.clone();
        let (receipt_a, expectation_a) = receipt_fixture(&signing_a, &trust_a, &[]);
        let (receipt_b, expectation_b) = receipt_fixture(&signing_b, &trust_b, &[]);
        let evidence = [
            OciWitnessEvidence {
                receipt: &receipt_a,
                trusted_key: &trust_a,
                expectation: &expectation_a,
            },
            OciWitnessEvidence {
                receipt: &receipt_b,
                trusted_key: &trust_b,
                expectation: &expectation_b,
            },
        ];
        assert_eq!(
            verify_witness_quorum(&subject(), &evidence, 2),
            Err(OciWitnessProofError::DuplicateTrustDomain)
        );
    }

    #[test]
    fn rejects_missing_witnesses_for_quorum() {
        let (_signing, trust, receipt, expectation) = single_receipt_evidence("witness-a");
        let evidence = [OciWitnessEvidence {
            receipt: &receipt,
            trusted_key: &trust,
            expectation: &expectation,
        }];
        assert_eq!(
            verify_witness_quorum(&subject(), &evidence, 2),
            Err(OciWitnessProofError::QuorumNotMet)
        );
    }

    #[test]
    fn rejects_unknown_tree_head_fields() {
        let (_signing, _trust, receipt, _expectation) =
            single_receipt_evidence("witness-a");
        let mut value = serde_json::to_value(&receipt).unwrap();
        value
            .get_mut("tree_head")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert("uncommitted".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<OciObserverWitnessReceipt>(value).is_err());
    }
}
