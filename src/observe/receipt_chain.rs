// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Domain-separated append-only links for OCI observer receipts.
//!
//! This is an in-memory integrity-chain prototype. It detects mutation,
//! reordering, duplicate sequence numbers and unannounced boot-epoch changes
//! relative to a trusted prior head. It is not durable storage, a signature,
//! an external anchor, or proof that the observer/kernel is trustworthy.

use crate::observe::oci_runtime::OciRuntimeConsistencySnapshot;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RECEIPT_LINK_DOMAIN: &[u8] = b"nixward:oci-observer-receipt-link:v1\0";
const RECEIPT_CHAIN_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciReceiptLinkKind {
    Snapshot,
    BootEpochTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OciReceiptLinkPayload {
    schema_version: u32,
    kind: OciReceiptLinkKind,
    observer_id_blake3: String,
    boot_id: String,
    sequence_start: u64,
    sequence_end: u64,
    snapshot_digest_blake3: Option<String>,
    previous_link_blake3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciObserverReceiptLink {
    payload: OciReceiptLinkPayload,
    link_blake3: String,
}

impl OciObserverReceiptLink {
    pub fn kind(&self) -> OciReceiptLinkKind { self.payload.kind }
    pub fn observer_id_blake3(&self) -> &str { &self.payload.observer_id_blake3 }
    pub fn boot_id(&self) -> &str { &self.payload.boot_id }
    pub fn sequence_start(&self) -> u64 { self.payload.sequence_start }
    pub fn sequence_end(&self) -> u64 { self.payload.sequence_end }
    pub fn snapshot_digest_blake3(&self) -> Option<&str> {
        self.payload.snapshot_digest_blake3.as_deref()
    }
    pub fn previous_link_blake3(&self) -> Option<&str> {
        self.payload.previous_link_blake3.as_deref()
    }
    pub fn link_blake3(&self) -> &str { &self.link_blake3 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciObserverReceiptChain {
    observer_id_blake3: String,
    current_boot_id: Option<String>,
    last_sequence: Option<u64>,
    links: Vec<OciObserverReceiptLink>,
}

impl OciObserverReceiptChain {
    pub fn new(observer_id_blake3: impl Into<String>) -> Result<Self, OciReceiptChainError> {
        let observer_id_blake3 = observer_id_blake3.into();
        validate_digest(&observer_id_blake3)?;
        Ok(Self {
            observer_id_blake3,
            current_boot_id: None,
            last_sequence: None,
            links: Vec::new(),
        })
    }

    pub fn links(&self) -> &[OciObserverReceiptLink] { &self.links }
    pub fn head_blake3(&self) -> Option<&str> {
        self.links.last().map(OciObserverReceiptLink::link_blake3)
    }
    pub fn last_sequence(&self) -> Option<u64> { self.last_sequence }
    pub fn current_boot_id(&self) -> Option<&str> { self.current_boot_id.as_deref() }

    /// Append a source-consistent observation. The collector snapshot is
    /// checked again at the chain boundary; caller-supplied claims are not.
    pub fn append_snapshot(
        &mut self,
        snapshot: &OciRuntimeConsistencySnapshot,
    ) -> Result<&OciObserverReceiptLink, OciReceiptChainError> {
        if !snapshot.source_agreement()
            || !snapshot.stable_across_observation_window()
            || snapshot.runtime_enforcement_proven()
        {
            return Err(OciReceiptChainError::SnapshotNotQualified);
        }
        let boot_id = snapshot.boot_id().to_owned();
        if let Some(current) = &self.current_boot_id {
            if current != &boot_id {
                return Err(OciReceiptChainError::BootTransitionRequired);
            }
        }
        if snapshot.observer_sequence_end() < snapshot.observer_sequence_start() {
            return Err(OciReceiptChainError::SequenceRollback);
        }
        if let Some(last) = self.last_sequence {
            if snapshot.observer_sequence_start() <= last
                || snapshot.observer_sequence_end() <= last
            {
                return Err(OciReceiptChainError::SequenceRollback);
            }
        }
        let digest = snapshot
            .digest_blake3()
            .map_err(|_| OciReceiptChainError::SnapshotDigest)?;
        let payload = OciReceiptLinkPayload {
            schema_version: RECEIPT_CHAIN_VERSION,
            kind: OciReceiptLinkKind::Snapshot,
            observer_id_blake3: self.observer_id_blake3.clone(),
            boot_id: boot_id.clone(),
            sequence_start: snapshot.observer_sequence_start(),
            sequence_end: snapshot.observer_sequence_end(),
            snapshot_digest_blake3: Some(digest),
            previous_link_blake3: self.head_blake3().map(str::to_owned),
        };
        let link = build_link(payload)?;
        self.current_boot_id = Some(boot_id);
        self.last_sequence = Some(link.sequence_end());
        self.links.push(link);
        Ok(self.links.last().expect("link inserted"))
    }

    /// Record an explicit boot transition before appending any snapshot from
    /// the new boot epoch. transition_sequence must be allocated by the
    /// persistent observer service and remain globally monotonic.
    pub fn begin_boot_epoch(
        &mut self,
        new_boot_id: impl Into<String>,
        transition_sequence: u64,
    ) -> Result<&OciObserverReceiptLink, OciReceiptChainError> {
        let new_boot_id = new_boot_id.into();
        validate_boot_id(&new_boot_id)?;
        if self.current_boot_id.is_none() {
            return Err(OciReceiptChainError::InvalidBootTransition);
        }
        if self.current_boot_id.as_deref() == Some(new_boot_id.as_str()) {
            return Err(OciReceiptChainError::BootEpochUnchanged);
        }
        if let Some(last) = self.last_sequence {
            if transition_sequence <= last {
                return Err(OciReceiptChainError::SequenceRollback);
            }
        }
        let payload = OciReceiptLinkPayload {
            schema_version: RECEIPT_CHAIN_VERSION,
            kind: OciReceiptLinkKind::BootEpochTransition,
            observer_id_blake3: self.observer_id_blake3.clone(),
            boot_id: new_boot_id.clone(),
            sequence_start: transition_sequence,
            sequence_end: transition_sequence,
            snapshot_digest_blake3: None,
            previous_link_blake3: self.head_blake3().map(str::to_owned),
        };
        let link = build_link(payload)?;
        self.current_boot_id = Some(new_boot_id);
        self.last_sequence = Some(transition_sequence);
        self.links.push(link);
        Ok(self.links.last().expect("link inserted"))
    }

    /// Verify a serialized chain against the expected observer identity.
    /// The caller must compare its final head with a separately trusted anchor
    /// to detect replacement/truncation of the entire chain.
    pub fn verify_chain(
        observer_id_blake3: &str,
        links: &[OciObserverReceiptLink],
    ) -> Result<(), OciReceiptChainError> {
        validate_digest(observer_id_blake3)?;
        let mut expected_previous: Option<&str> = None;
        let mut current_boot: Option<&str> = None;
        let mut last_sequence: Option<u64> = None;

        for link in links {
            if link.payload.schema_version != RECEIPT_CHAIN_VERSION
                || link.payload.observer_id_blake3 != observer_id_blake3
            {
                return Err(OciReceiptChainError::IdentityMismatch);
            }
            validate_boot_id(&link.payload.boot_id)?;
            validate_digest(&link.link_blake3)?;
            if link.payload.previous_link_blake3.as_deref() != expected_previous {
                return Err(OciReceiptChainError::ChainLinkMismatch);
            }
            if let Some(last) = last_sequence {
                if link.payload.sequence_start <= last || link.payload.sequence_end < link.payload.sequence_start {
                    return Err(OciReceiptChainError::SequenceRollback);
                }
            } else if link.payload.sequence_end < link.payload.sequence_start {
                return Err(OciReceiptChainError::SequenceRollback);
            }

            match link.payload.kind {
                OciReceiptLinkKind::Snapshot => {
                    if current_boot.is_some_and(|boot| boot != link.payload.boot_id) {
                        return Err(OciReceiptChainError::BootTransitionRequired);
                    }
                    let snapshot_digest = link.payload.snapshot_digest_blake3.as_deref()
                        .ok_or(OciReceiptChainError::SnapshotDigest)?;
                    validate_digest(snapshot_digest)?;
                }
                OciReceiptLinkKind::BootEpochTransition => {
                    if current_boot.is_none()
                        || current_boot == Some(link.payload.boot_id.as_str())
                        || link.payload.snapshot_digest_blake3.is_some()
                    {
                        return Err(OciReceiptChainError::InvalidBootTransition);
                    }
                }
            }

            let expected_link = calculate_link_digest(&link.payload)?;
            if expected_link != link.link_blake3 {
                return Err(OciReceiptChainError::ChainLinkMismatch);
            }
            current_boot = Some(&link.payload.boot_id);
            last_sequence = Some(link.payload.sequence_end);
            expected_previous = Some(&link.link_blake3);
        }
        Ok(())
    }
}

fn build_link(payload: OciReceiptLinkPayload) -> Result<OciObserverReceiptLink, OciReceiptChainError> {
    let link_blake3 = calculate_link_digest(&payload)?;
    Ok(OciObserverReceiptLink { payload, link_blake3 })
}

fn calculate_link_digest(payload: &OciReceiptLinkPayload) -> Result<String, OciReceiptChainError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| OciReceiptChainError::Serialization)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_LINK_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_digest(value: &str) -> Result<(), OciReceiptChainError> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(OciReceiptChainError::InvalidDigest)
    }
}

fn validate_boot_id(value: &str) -> Result<(), OciReceiptChainError> {
    let value = value.to_ascii_lowercase();
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() == 5
        && parts.iter().map(|part| part.len()).sum::<usize>() == 32
        && parts.concat().bytes().all(|b| b.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(OciReceiptChainError::InvalidBootId)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OciReceiptChainError {
    #[error("observer identity must be a lowercase 32-byte hexadecimal digest")]
    InvalidDigest,
    #[error("boot ID must be a canonical UUID")]
    InvalidBootId,
    #[error("snapshot is not a source-consistent stable observation")]
    SnapshotNotQualified,
    #[error("boot epoch changed without an explicit transition link")]
    BootTransitionRequired,
    #[error("boot transition must change the current boot epoch")]
    BootEpochUnchanged,
    #[error("boot transition link is invalid")]
    InvalidBootTransition,
    #[error("observer sequence is duplicated, non-monotonic or rolled back")]
    SequenceRollback,
    #[error("observer identity or chain state does not match")]
    IdentityMismatch,
    #[error("previous-link or current-link digest mismatch")]
    ChainLinkMismatch,
    #[error("snapshot digest could not be calculated or is missing")]
    SnapshotDigest,
    #[error("receipt link serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observer() -> String { "a5".repeat(32) }
    const BOOT_ONE: &str = "11111111-2222-3333-4444-555555555555";
    const BOOT_TWO: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn snapshot(sequence: u64) -> OciRuntimeConsistencySnapshot {
        crate::observe::oci_runtime::test_fixture_for_contract_at(
            &format!("sha256:{}", "d".repeat(64)),
            sequence,
            BOOT_ONE,
        )
    }

    fn snapshot_on_boot(sequence: u64, boot_id: &str) -> OciRuntimeConsistencySnapshot {
        crate::observe::oci_runtime::test_fixture_for_contract_at(
            &format!("sha256:{}", "d".repeat(64)), sequence, boot_id,
        )
    }

    #[test]
    fn appends_and_verifies_two_monotonic_snapshot_links() {
        let mut chain = OciObserverReceiptChain::new(observer()).unwrap();
        chain.append_snapshot(&snapshot(10)).unwrap();
        chain.append_snapshot(&snapshot(12)).unwrap();
        assert_eq!(chain.links().len(), 2);
        OciObserverReceiptChain::verify_chain(&observer(), chain.links()).unwrap();
    }

    #[test]
    fn rejects_duplicate_or_rolled_back_snapshot_sequence() {
        let mut chain = OciObserverReceiptChain::new(observer()).unwrap();
        chain.append_snapshot(&snapshot(10)).unwrap();
        assert!(matches!(
            chain.append_snapshot(&snapshot(10)),
            Err(OciReceiptChainError::SequenceRollback)
        ));
    }

    #[test]
    fn requires_explicit_boot_epoch_transition() {
        let mut chain = OciObserverReceiptChain::new(observer()).unwrap();
        chain.append_snapshot(&snapshot(10)).unwrap();
        let other = snapshot_on_boot(13, BOOT_TWO);
        assert!(matches!(
            chain.append_snapshot(&other),
            Err(OciReceiptChainError::BootTransitionRequired)
        ));
        chain.begin_boot_epoch(BOOT_TWO, 12).unwrap();
        chain.append_snapshot(&other).unwrap();
        OciObserverReceiptChain::verify_chain(&observer(), chain.links()).unwrap();
    }

    #[test]
    fn detects_link_reordering_and_payload_mutation() {
        let mut chain = OciObserverReceiptChain::new(observer()).unwrap();
        chain.append_snapshot(&snapshot(10)).unwrap();
        chain.append_snapshot(&snapshot(12)).unwrap();
        let mut reversed = chain.links().to_vec();
        reversed.reverse();
        assert!(matches!(
            OciObserverReceiptChain::verify_chain(OBSERVER, &reversed),
            Err(OciReceiptChainError::ChainLinkMismatch) | Err(OciReceiptChainError::SequenceRollback)
        ));
        let mut tampered = chain.links().to_vec();
        tampered[0].payload.snapshot_digest_blake3 = Some("ff".repeat(32));
        assert!(matches!(
            OciObserverReceiptChain::verify_chain(OBSERVER, &tampered),
            Err(OciReceiptChainError::ChainLinkMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_observer_identity() {
        let mut chain = OciObserverReceiptChain::new(observer()).unwrap();
        chain.append_snapshot(&snapshot(10)).unwrap();
        assert!(matches!(
            OciObserverReceiptChain::verify_chain(&"bb".repeat(32), chain.links()),
            Err(OciReceiptChainError::IdentityMismatch)
        ));
    }

    #[test]
    fn empty_chain_is_valid_but_needs_external_anchor() {
        OciObserverReceiptChain::verify_chain(&observer(), &[]).unwrap();
        let chain = OciObserverReceiptChain::new(observer()).unwrap();
        assert!(chain.head_blake3().is_none());
    }
}
