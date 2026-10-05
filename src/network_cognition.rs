// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Observe-only network cognition.
//!
//! V41 encodes privacy-preserving flow metadata into Symthaea's 16,384-bit HDC
//! space and emits calibrated *evidence*. It cannot authorize, deny, quarantine,
//! load kernel policy, or mint capability leases. Hard policy contradictions are
//! enforced by the Network Covenant/kernel plane; statistical novelty remains an
//! operator/Symthaea reasoning signal until separately validated and authorized.

use crate::network_covenant::{NetworkDirection, NetworkProtocol, NetworkZone};
use serde::{Deserialize, Serialize};
use symthaea_core::hdc::binary_hv::BinaryHV;
use thiserror::Error;

const OBSERVATION_DOMAIN: &[u8] = b"symthaea:nixward:network-observation:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"symthaea:nixward:network-anomaly-evidence:v1\0";
const HDC_FINGERPRINT_DOMAIN: &[u8] = b"symthaea:nixward:network-hdc-fingerprint:v1\0";

pub const NETWORK_COGNITION_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_HDC_DIMENSION: usize = BinaryHV::DIM;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityDecision {
    Allowed,
    Denied,
    NoMatchingCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFlowObservation {
    pub schema_version: u32,
    pub holon_id: String,
    pub network_policy_blake3: String,
    pub workload_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_blake3: Option<String>,
    pub decision: CapabilityDecision,
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
    pub destination_zone: NetworkZone,
    /// Privacy-preserving stable label/destination identity digest. Raw payload
    /// and raw destination need not be stored for the reasoning plane.
    pub destination_identity_blake3: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
    /// Coarse local-time bucket 0..23; exact timestamps live in a separate
    /// forensic ledger if owner policy enables them.
    pub hour_bucket: u8,
    /// Must remain zero in V41 baseline evidence.
    pub payload_bytes_captured: u64,
}

impl NetworkFlowObservation {
    pub fn validate(&self) -> Result<(), NetworkCognitionError> {
        if self.schema_version != NETWORK_COGNITION_SCHEMA_VERSION {
            return Err(NetworkCognitionError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_token("holon id", &self.holon_id, 256)?;
        for digest in [
            &self.network_policy_blake3,
            &self.workload_blake3,
            &self.destination_identity_blake3,
        ] {
            validate_digest(digest)?;
        }
        if let Some(digest) = &self.capability_blake3 {
            validate_digest(digest)?;
        }
        if matches!(self.decision, CapabilityDecision::Allowed) && self.capability_blake3.is_none()
        {
            return Err(NetworkCognitionError::InvalidObservation(
                "allowed flow is missing the capability that authorized it".into(),
            ));
        }
        if self.hour_bucket > 23 {
            return Err(NetworkCognitionError::InvalidObservation(
                "hour bucket".into(),
            ));
        }
        if self.payload_bytes_captured != 0 {
            return Err(NetworkCognitionError::PayloadCaptureForbidden);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCognitionError> {
        self.validate()?;
        hash_json(OBSERVATION_DOMAIN, self)
    }

    pub fn hdc_fingerprint_hex(&self) -> Result<String, NetworkCognitionError> {
        let hv = encode_observation_hv(self)?;
        let mut h = blake3::Hasher::new();
        h.update(HDC_FINGERPRINT_DOMAIN);
        h.update(&hv.0);
        Ok(h.finalize().to_hex().to_string())
    }
}

/// Runtime-only behavior prototype. It is intentionally not network authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBehaviorPrototype {
    pub schema_version: u32,
    pub workload_blake3: String,
    pub sample_count: u64,
    pub prototype_hv: BinaryHV,
    pub provenance_blake3: String,
}

impl NetworkBehaviorPrototype {
    pub fn from_observations(
        observations: &[NetworkFlowObservation],
    ) -> Result<Self, NetworkCognitionError> {
        if observations.is_empty() {
            return Err(NetworkCognitionError::EmptyBaseline);
        }
        let workload = observations[0].workload_blake3.clone();
        let mut vectors = Vec::with_capacity(observations.len());
        let mut provenance = blake3::Hasher::new();
        provenance.update(b"symthaea:nixward:network-behavior-prototype:v1\0");
        for observation in observations {
            observation.validate()?;
            if observation.workload_blake3 != workload {
                return Err(NetworkCognitionError::MixedWorkloads);
            }
            let digest = observation.digest_hex()?;
            provenance.update(digest.as_bytes());
            vectors.push(encode_observation_hv(observation)?);
        }
        Ok(Self {
            schema_version: NETWORK_COGNITION_SCHEMA_VERSION,
            workload_blake3: workload,
            sample_count: observations.len() as u64,
            prototype_hv: BinaryHV::bundle_safe(&vectors),
            provenance_blake3: provenance.finalize().to_hex().to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), NetworkCognitionError> {
        if self.schema_version != NETWORK_COGNITION_SCHEMA_VERSION {
            return Err(NetworkCognitionError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.workload_blake3)?;
        validate_digest(&self.provenance_blake3)?;
        if self.sample_count == 0 {
            return Err(NetworkCognitionError::EmptyBaseline);
        }
        Ok(())
    }

    pub fn fingerprint_hex(&self) -> Result<String, NetworkCognitionError> {
        self.validate()?;
        let mut h = blake3::Hasher::new();
        h.update(b"symthaea:nixward:network-behavior-prototype-fingerprint:v1\0");
        h.update(&self.prototype_hv.0);
        h.update(self.provenance_blake3.as_bytes());
        Ok(h.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAnomalyEvidence {
    pub schema_version: u32,
    pub observation_blake3: String,
    pub workload_blake3: String,
    pub baseline_blake3: String,
    /// 0 = very similar to learned baseline, 1000 = maximally different.
    pub novelty_milli: u16,
    pub policy_contradiction: bool,
    pub model_family: String,
    pub response: String,
    pub quarantine_authority: bool,
    pub network_enforcement_authority: bool,
}

impl NetworkAnomalyEvidence {
    pub fn assess(
        observation: &NetworkFlowObservation,
        baseline: &NetworkBehaviorPrototype,
    ) -> Result<Self, NetworkCognitionError> {
        observation.validate()?;
        baseline.validate()?;
        if observation.workload_blake3 != baseline.workload_blake3 {
            return Err(NetworkCognitionError::MixedWorkloads);
        }
        let hv = encode_observation_hv(observation)?;
        let similarity = hv.similarity(&baseline.prototype_hv).clamp(0.0, 1.0);
        let novelty_milli = ((1.0 - similarity) * 1000.0).round() as u16;
        let policy_contradiction = matches!(
            observation.decision,
            CapabilityDecision::Denied | CapabilityDecision::NoMatchingCapability
        );
        let evidence = Self {
            schema_version: NETWORK_COGNITION_SCHEMA_VERSION,
            observation_blake3: observation.digest_hex()?,
            workload_blake3: observation.workload_blake3.clone(),
            baseline_blake3: baseline.fingerprint_hex()?,
            novelty_milli,
            policy_contradiction,
            model_family: "hdc-behavior-distance-v1".into(),
            response: "observe-only-v41".into(),
            quarantine_authority: false,
            network_enforcement_authority: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), NetworkCognitionError> {
        if self.schema_version != NETWORK_COGNITION_SCHEMA_VERSION {
            return Err(NetworkCognitionError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        for digest in [
            &self.observation_blake3,
            &self.workload_blake3,
            &self.baseline_blake3,
        ] {
            validate_digest(digest)?;
        }
        if self.novelty_milli > 1000 {
            return Err(NetworkCognitionError::InvalidObservation(
                "novelty range".into(),
            ));
        }
        if self.model_family != "hdc-behavior-distance-v1" {
            return Err(NetworkCognitionError::InvalidObservation(
                "network anomaly model-family identity drifted from V41 evidence".into(),
            ));
        }
        if self.response != "observe-only-v41"
            || self.quarantine_authority
            || self.network_enforcement_authority
        {
            return Err(NetworkCognitionError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCognitionError> {
        self.validate()?;
        hash_json(EVIDENCE_DOMAIN, self)
    }
}

pub fn network_cognition_policy_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_COGNITION_SCHEMA_VERSION,
        "kind": "symthaea-network-cognition-policy-v1",
        "status": "observe-only-v41",
        "hdc": {
            "dimension": NETWORK_HDC_DIMENSION,
            "model_family": "hdc-behavior-distance-v1",
            "baseline": "explicit-evidence-prototype"
        },
        "telemetry": {
            "payload_capture_default": false,
            "flow_metadata": [
                "workload-identity",
                "capability-decision",
                "destination-class",
                "protocol",
                "byte-counts",
                "duration",
                "coarse-time-context"
            ]
        },
        "authority": {
            "network_enforcement": false,
            "quarantine": false,
            "capability_lease_minting": false,
            "automatic_response": "none"
        },
        "active_inference": {
            "status": "future-calibrated-evidence-input",
            "expected_free_energy_is_not_authority": true
        }
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"status\":\"serialization-failed\"}}\n",
            NETWORK_COGNITION_SCHEMA_VERSION
        )
    })
}

fn encode_observation_hv(
    observation: &NetworkFlowObservation,
) -> Result<BinaryHV, NetworkCognitionError> {
    observation.validate()?;
    let tokens = [
        format!("workload:{}", observation.workload_blake3),
        format!("decision:{:?}", observation.decision),
        format!("direction:{:?}", observation.direction),
        format!("protocol:{:?}", observation.protocol),
        format!("zone:{:?}", observation.destination_zone),
        format!("destination:{}", observation.destination_identity_blake3),
        format!("sent:{}", bucket_bytes(observation.bytes_sent)),
        format!("recv:{}", bucket_bytes(observation.bytes_received)),
        format!("duration:{}", bucket_duration(observation.duration_ms)),
        format!("hour:{}", observation.hour_bucket),
    ];
    let mut vectors = Vec::with_capacity(tokens.len());
    for (index, token) in tokens.iter().enumerate() {
        let digest = blake3::hash(token.as_bytes());
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&digest.as_bytes()[..8]);
        let filler = BinaryHV::random(u64::from_le_bytes(seed_bytes));
        let role = BinaryHV::random(0x4E45_5400_0000_0000u64 + index as u64);
        vectors.push(role.bind(&filler));
    }
    Ok(BinaryHV::bundle_safe(&vectors))
}

fn bucket_bytes(value: u64) -> u8 {
    if value == 0 {
        0
    } else {
        (64 - value.leading_zeros()).min(63) as u8
    }
}

fn bucket_duration(value: u64) -> u8 {
    if value == 0 {
        0
    } else {
        (64 - value.leading_zeros()).min(63) as u8
    }
}

fn validate_digest(value: &str) -> Result<(), NetworkCognitionError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NetworkCognitionError::InvalidDigest)
    }
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), NetworkCognitionError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(NetworkCognitionError::InvalidObservation(field.into()))
    } else {
        Ok(())
    }
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkCognitionError> {
    let encoded = serde_json::to_vec(value).map_err(|_| NetworkCognitionError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkCognitionError {
    #[error("unsupported network-cognition schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid network cognition digest")]
    InvalidDigest,
    #[error("invalid network observation: {0}")]
    InvalidObservation(String),
    #[error("payload capture is forbidden in the V41 baseline")]
    PayloadCaptureForbidden,
    #[error("network behavior baseline is empty")]
    EmptyBaseline,
    #[error("network behavior evidence mixed multiple workloads")]
    MixedWorkloads,
    #[error("network cognition attempted to escalate into enforcement/quarantine authority")]
    AuthorityEscalation,
    #[error("network cognition evidence serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(destination: &str, decision: CapabilityDecision) -> NetworkFlowObservation {
        NetworkFlowObservation {
            schema_version: NETWORK_COGNITION_SCHEMA_VERSION,
            holon_id: "holon-a".into(),
            network_policy_blake3: "11".repeat(32),
            workload_blake3: "22".repeat(32),
            capability_blake3: Some("33".repeat(32)),
            decision,
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destination_zone: NetworkZone::Internet,
            destination_identity_blake3: destination.into(),
            bytes_sent: 8192,
            bytes_received: 4096,
            duration_ms: 1200,
            hour_bucket: 12,
            payload_bytes_captured: 0,
        }
    }

    #[test]
    fn hdc_encoding_is_deterministic_and_payload_free() {
        let a = obs(&"44".repeat(32), CapabilityDecision::Allowed);
        let b = a.clone();
        assert_eq!(
            a.hdc_fingerprint_hex().unwrap(),
            b.hdc_fingerprint_hex().unwrap()
        );
        assert_eq!(a.payload_bytes_captured, 0);
    }

    #[test]
    fn anomaly_evidence_cannot_quarantine_even_for_policy_contradiction() {
        let baseline_obs = obs(&"44".repeat(32), CapabilityDecision::Allowed);
        let baseline = NetworkBehaviorPrototype::from_observations(&[baseline_obs]).unwrap();
        let suspicious = obs(&"55".repeat(32), CapabilityDecision::Denied);
        let evidence = NetworkAnomalyEvidence::assess(&suspicious, &baseline).unwrap();
        assert!(evidence.policy_contradiction);
        assert_eq!(evidence.response, "observe-only-v41");
        assert!(!evidence.quarantine_authority);
        assert!(!evidence.network_enforcement_authority);
    }

    #[test]
    fn payload_capture_is_rejected_by_baseline_contract() {
        let mut observation = obs(&"44".repeat(32), CapabilityDecision::Allowed);
        observation.payload_bytes_captured = 1;
        assert!(matches!(
            observation.validate(),
            Err(NetworkCognitionError::PayloadCaptureForbidden)
        ));
    }
}
