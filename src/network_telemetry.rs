// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Privacy-preserving trusted network telemetry ledger.
//!
//! V47 records metadata-only observations as an append-only, hash-chained
//! evidence stream.  It deliberately stores no payload bytes and, by default,
//! stores only a digest for destination identity.  Telemetry may feed V41/V45
//! cognition/calibration but has no authority to mutate network policy.

use crate::network_cognition::{NetworkCognitionError, NetworkFlowObservation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RECORD_DOMAIN: &[u8] = b"symthaea:nixward:network-telemetry-record:v1\0";
const LEDGER_DOMAIN: &[u8] = b"symthaea:nixward:network-telemetry-ledger:v1\0";
const EXPORT_DOMAIN: &[u8] = b"symthaea:nixward:network-telemetry-calibration-export:v1\0";

pub const NETWORK_TELEMETRY_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_TELEMETRY_MAX_EVENTS_DEFAULT: usize = 10_000;
pub const NETWORK_TELEMETRY_GENESIS_LINK: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTelemetryPolicy {
    pub schema_version: u32,
    pub payload_capture: bool,
    pub raw_destination_storage: bool,
    pub exact_timestamp_storage: bool,
    pub time_bucket_ms: u64,
    pub max_events: usize,
    pub reasoning_authority: String,
    pub network_enforcement_authority: bool,
}

impl Default for NetworkTelemetryPolicy {
    fn default() -> Self {
        Self {
            schema_version: NETWORK_TELEMETRY_SCHEMA_VERSION,
            payload_capture: false,
            raw_destination_storage: false,
            exact_timestamp_storage: false,
            time_bucket_ms: 5 * 60 * 1000,
            max_events: NETWORK_TELEMETRY_MAX_EVENTS_DEFAULT,
            reasoning_authority: "evidence-only".into(),
            network_enforcement_authority: false,
        }
    }
}

impl NetworkTelemetryPolicy {
    pub fn validate(&self) -> Result<(), NetworkTelemetryError> {
        if self.schema_version != NETWORK_TELEMETRY_SCHEMA_VERSION {
            return Err(NetworkTelemetryError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.payload_capture || self.raw_destination_storage || self.exact_timestamp_storage {
            return Err(NetworkTelemetryError::PrivacyEscalation);
        }
        if self.time_bucket_ms < 60_000 || self.max_events == 0 || self.max_events > 1_000_000 {
            return Err(NetworkTelemetryError::InvalidPolicy);
        }
        if self.reasoning_authority != "evidence-only" || self.network_enforcement_authority {
            return Err(NetworkTelemetryError::AuthorityEscalation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTelemetryRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_record_blake3: String,
    pub observation: NetworkFlowObservation,
    pub collector_id: String,
    pub collector_build_blake3: String,
    /// Wall-clock observation time rounded down to the configured privacy bucket.
    pub observed_time_bucket_ms: u64,
    pub source: String,
    pub payload_bytes_captured: u64,
}

impl NetworkTelemetryRecord {
    pub fn validate(&self, policy: &NetworkTelemetryPolicy) -> Result<(), NetworkTelemetryError> {
        policy.validate()?;
        if self.schema_version != NETWORK_TELEMETRY_SCHEMA_VERSION {
            return Err(NetworkTelemetryError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.previous_record_blake3)?;
        validate_digest(&self.collector_build_blake3)?;
        if self.collector_id.trim().is_empty()
            || self.collector_id.len() > 256
            || self.collector_id.contains('\0')
        {
            return Err(NetworkTelemetryError::InvalidRecord(
                "collector identity".into(),
            ));
        }
        if self.source != "kernel-metadata-only-v47" || self.payload_bytes_captured != 0 {
            return Err(NetworkTelemetryError::PrivacyEscalation);
        }
        if self.observed_time_bucket_ms % policy.time_bucket_ms != 0 {
            return Err(NetworkTelemetryError::InvalidRecord(
                "time bucket is not policy aligned".into(),
            ));
        }
        self.observation.validate()?;
        if self.observation.payload_bytes_captured != 0 {
            return Err(NetworkTelemetryError::PrivacyEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(
        &self,
        policy: &NetworkTelemetryPolicy,
    ) -> Result<String, NetworkTelemetryError> {
        self.validate(policy)?;
        hash_json(RECORD_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTelemetryLedger {
    pub schema_version: u32,
    pub holon_id: String,
    pub network_policy_blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_receipt_blake3: Option<String>,
    pub policy: NetworkTelemetryPolicy,
    pub records: Vec<NetworkTelemetryRecord>,
    pub status: String,
    pub network_enforcement_authority: bool,
}

impl NetworkTelemetryLedger {
    pub fn empty(
        holon_id: impl Into<String>,
        network_policy_blake3: impl Into<String>,
        activation_receipt_blake3: Option<String>,
        policy: NetworkTelemetryPolicy,
    ) -> Result<Self, NetworkTelemetryError> {
        let ledger = Self {
            schema_version: NETWORK_TELEMETRY_SCHEMA_VERSION,
            holon_id: holon_id.into(),
            network_policy_blake3: network_policy_blake3.into(),
            activation_receipt_blake3,
            policy,
            records: Vec::new(),
            status: "metadata-only-hash-chain-v47".into(),
            network_enforcement_authority: false,
        };
        ledger.validate()?;
        Ok(ledger)
    }

    pub fn append(
        &mut self,
        observation: NetworkFlowObservation,
        collector_id: impl Into<String>,
        collector_build_blake3: impl Into<String>,
        observed_at_ms: u64,
    ) -> Result<String, NetworkTelemetryError> {
        self.validate()?;
        if observation.holon_id != self.holon_id
            || observation.network_policy_blake3 != self.network_policy_blake3
        {
            return Err(NetworkTelemetryError::ContextMismatch);
        }
        if self.records.len() >= self.policy.max_events {
            return Err(NetworkTelemetryError::RetentionLimitReached);
        }
        let previous_record_blake3 = match self.records.last() {
            Some(previous) => previous.digest_hex(&self.policy)?,
            None => NETWORK_TELEMETRY_GENESIS_LINK.into(),
        };
        let record = NetworkTelemetryRecord {
            schema_version: NETWORK_TELEMETRY_SCHEMA_VERSION,
            sequence: self.records.len() as u64,
            previous_record_blake3,
            observation,
            collector_id: collector_id.into(),
            collector_build_blake3: collector_build_blake3.into(),
            observed_time_bucket_ms: observed_at_ms - (observed_at_ms % self.policy.time_bucket_ms),
            source: "kernel-metadata-only-v47".into(),
            payload_bytes_captured: 0,
        };
        let digest = record.digest_hex(&self.policy)?;
        self.records.push(record);
        self.validate()?;
        Ok(digest)
    }

    pub fn validate(&self) -> Result<(), NetworkTelemetryError> {
        if self.schema_version != NETWORK_TELEMETRY_SCHEMA_VERSION {
            return Err(NetworkTelemetryError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        self.policy.validate()?;
        if self.holon_id.trim().is_empty() || self.holon_id.contains('\0') {
            return Err(NetworkTelemetryError::InvalidLedger(
                "Holon identity".into(),
            ));
        }
        validate_digest(&self.network_policy_blake3)?;
        if let Some(receipt) = &self.activation_receipt_blake3 {
            validate_digest(receipt)?;
        }
        if self.status != "metadata-only-hash-chain-v47" || self.network_enforcement_authority {
            return Err(NetworkTelemetryError::AuthorityEscalation);
        }
        if self.records.len() > self.policy.max_events {
            return Err(NetworkTelemetryError::RetentionLimitReached);
        }
        let mut expected_previous = NETWORK_TELEMETRY_GENESIS_LINK.to_string();
        for (index, record) in self.records.iter().enumerate() {
            record.validate(&self.policy)?;
            if record.sequence != index as u64 || record.previous_record_blake3 != expected_previous
            {
                return Err(NetworkTelemetryError::BrokenHashChain);
            }
            if record.observation.holon_id != self.holon_id
                || record.observation.network_policy_blake3 != self.network_policy_blake3
            {
                return Err(NetworkTelemetryError::ContextMismatch);
            }
            expected_previous = record.digest_hex(&self.policy)?;
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkTelemetryError> {
        self.validate()?;
        hash_json(LEDGER_DOMAIN, self)
    }

    pub fn calibration_export(
        &self,
    ) -> Result<NetworkTelemetryCalibrationExport, NetworkTelemetryError> {
        self.validate()?;
        if self.records.is_empty() {
            return Err(NetworkTelemetryError::EmptyLedger);
        }
        let export = NetworkTelemetryCalibrationExport {
            schema_version: NETWORK_TELEMETRY_SCHEMA_VERSION,
            telemetry_ledger_blake3: self.digest_hex()?,
            holon_id: self.holon_id.clone(),
            network_policy_blake3: self.network_policy_blake3.clone(),
            observation_blake3: self
                .records
                .iter()
                .map(|record| record.observation.digest_hex())
                .collect::<Result<Vec<_>, _>>()?,
            status: "measurement-input-only-v47".into(),
            payload_capture: false,
            network_enforcement_authority: false,
        };
        export.validate()?;
        Ok(export)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTelemetryCalibrationExport {
    pub schema_version: u32,
    pub telemetry_ledger_blake3: String,
    pub holon_id: String,
    pub network_policy_blake3: String,
    pub observation_blake3: Vec<String>,
    pub status: String,
    pub payload_capture: bool,
    pub network_enforcement_authority: bool,
}

impl NetworkTelemetryCalibrationExport {
    pub fn validate(&self) -> Result<(), NetworkTelemetryError> {
        if self.schema_version != NETWORK_TELEMETRY_SCHEMA_VERSION {
            return Err(NetworkTelemetryError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.telemetry_ledger_blake3)?;
        validate_digest(&self.network_policy_blake3)?;
        if self.observation_blake3.is_empty() {
            return Err(NetworkTelemetryError::EmptyLedger);
        }
        for digest in &self.observation_blake3 {
            validate_digest(digest)?;
        }
        if self.status != "measurement-input-only-v47"
            || self.payload_capture
            || self.network_enforcement_authority
        {
            return Err(NetworkTelemetryError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkTelemetryError> {
        self.validate()?;
        hash_json(EXPORT_DOMAIN, self)
    }
}

pub fn network_telemetry_policy_json() -> String {
    let policy = NetworkTelemetryPolicy::default();
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_TELEMETRY_SCHEMA_VERSION,
        "kind": "symthaea-network-telemetry-policy-v1",
        "status": "metadata-only-hash-chain-v47",
        "collector": "trusted-kernel-metadata-adapter-required",
        "payload_capture": policy.payload_capture,
        "raw_destination_storage": policy.raw_destination_storage,
        "exact_timestamp_storage": policy.exact_timestamp_storage,
        "time_bucket_ms": policy.time_bucket_ms,
        "max_events": policy.max_events,
        "destination_identity": "blake3-only-by-default",
        "calibration_export": "measurement-input-only-v47",
        "reasoning_authority": policy.reasoning_authority,
        "network_enforcement_authority": policy.network_enforcement_authority
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| "{\"schema_version\":1,\"status\":\"serialization-failed\"}\n".into())
}

fn validate_digest(value: &str) -> Result<(), NetworkTelemetryError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetworkTelemetryError::InvalidDigest);
    }
    Ok(())
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkTelemetryError> {
    let bytes = serde_json::to_vec(value).map_err(|_| NetworkTelemetryError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error)]
pub enum NetworkTelemetryError {
    #[error("unsupported network telemetry schema {0}")]
    UnsupportedSchema(u32),
    #[error("invalid telemetry BLAKE3 digest")]
    InvalidDigest,
    #[error("network telemetry privacy policy was weakened")]
    PrivacyEscalation,
    #[error("network telemetry may not gain enforcement authority")]
    AuthorityEscalation,
    #[error("invalid network telemetry policy")]
    InvalidPolicy,
    #[error("invalid network telemetry record: {0}")]
    InvalidRecord(String),
    #[error("invalid network telemetry ledger: {0}")]
    InvalidLedger(String),
    #[error("network telemetry hash chain is broken")]
    BrokenHashChain,
    #[error("network telemetry context does not match the ledger Holon/policy")]
    ContextMismatch,
    #[error("network telemetry retention limit reached")]
    RetentionLimitReached,
    #[error("network telemetry ledger is empty")]
    EmptyLedger,
    #[error("network telemetry serialization failed")]
    Serialization,
    #[error("network cognition observation rejected: {0}")]
    Cognition(#[from] NetworkCognitionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_cognition::CapabilityDecision;
    use crate::network_covenant::{NetworkDirection, NetworkProtocol, NetworkZone};

    fn observation() -> NetworkFlowObservation {
        NetworkFlowObservation {
            schema_version: 1,
            holon_id: "holon-a".into(),
            network_policy_blake3: "11".repeat(32),
            workload_blake3: "22".repeat(32),
            capability_blake3: Some("33".repeat(32)),
            decision: CapabilityDecision::Allowed,
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destination_zone: NetworkZone::Internet,
            destination_identity_blake3: "44".repeat(32),
            bytes_sent: 100,
            bytes_received: 200,
            duration_ms: 25,
            hour_bucket: 12,
            payload_bytes_captured: 0,
        }
    }

    #[test]
    fn ledger_is_hash_chained_and_exports_measurement_only_evidence() {
        let mut ledger = NetworkTelemetryLedger::empty(
            "holon-a",
            "11".repeat(32),
            Some("55".repeat(32)),
            NetworkTelemetryPolicy::default(),
        )
        .unwrap();
        ledger
            .append(observation(), "collector-a", "66".repeat(32), 600_123)
            .unwrap();
        ledger
            .append(observation(), "collector-a", "66".repeat(32), 900_999)
            .unwrap();
        ledger.validate().unwrap();
        let export = ledger.calibration_export().unwrap();
        assert_eq!(export.status, "measurement-input-only-v47");
        assert!(!export.payload_capture);
        assert!(!export.network_enforcement_authority);
    }

    #[test]
    fn broken_previous_link_is_rejected() {
        let mut ledger = NetworkTelemetryLedger::empty(
            "holon-a",
            "11".repeat(32),
            None,
            NetworkTelemetryPolicy::default(),
        )
        .unwrap();
        ledger
            .append(observation(), "collector-a", "66".repeat(32), 600_123)
            .unwrap();
        ledger.records[0].previous_record_blake3 = "ff".repeat(32);
        assert!(matches!(
            ledger.validate(),
            Err(NetworkTelemetryError::BrokenHashChain)
        ));
    }
}
