// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! V43 calibration and drift evidence for observe-only network cognition.
//!
//! Statistical novelty is measured against explicit labeled evidence. Hard
//! Network Covenant contradictions are reported separately and are never used
//! as "AI ground truth" because the deterministic policy plane already knows
//! whether those events violated authority.

use crate::network_cognition::{
    NETWORK_COGNITION_SCHEMA_VERSION, NetworkAnomalyEvidence, NetworkBehaviorPrototype,
    NetworkCognitionError, NetworkFlowObservation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const CORPUS_DOMAIN: &[u8] = b"symthaea:nixward:network-calibration-corpus:v1\0";
const REPORT_DOMAIN: &[u8] = b"symthaea:nixward:network-calibration-report:v1\0";
const DRIFT_DOMAIN: &[u8] = b"symthaea:nixward:network-drift-evidence:v1\0";

pub const NETWORK_CALIBRATION_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_CALIBRATION_MODEL_FAMILY: &str = "hdc-behavior-distance-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CalibrationSampleRole {
    Baseline,
    Evaluation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CalibrationLabel {
    InDistribution,
    BenignNovel,
    SyntheticAnomaly,
    PolicyContradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledNetworkObservation {
    pub case_id: String,
    pub role: CalibrationSampleRole,
    pub label: CalibrationLabel,
    pub observation: NetworkFlowObservation,
}

impl LabeledNetworkObservation {
    fn validate(&self) -> Result<(), NetworkCalibrationError> {
        validate_token("case id", &self.case_id, 128)?;
        self.observation.validate()?;
        if matches!(self.role, CalibrationSampleRole::Baseline)
            && self.label != CalibrationLabel::InDistribution
        {
            return Err(NetworkCalibrationError::InvalidBaselineLabel);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCalibrationCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub model_family: String,
    pub source_kind: String,
    pub payload_capture: bool,
    pub samples: Vec<LabeledNetworkObservation>,
}

impl NetworkCalibrationCorpus {
    pub fn validate(&self) -> Result<(), NetworkCalibrationError> {
        if self.schema_version != NETWORK_CALIBRATION_SCHEMA_VERSION {
            return Err(NetworkCalibrationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_token("corpus id", &self.corpus_id, 256)?;
        if self.model_family != NETWORK_CALIBRATION_MODEL_FAMILY {
            return Err(NetworkCalibrationError::ModelFamilyDrift);
        }
        if self.source_kind != "synthetic-or-owner-reviewed-v43" {
            return Err(NetworkCalibrationError::InvalidSourceKind);
        }
        if self.payload_capture {
            return Err(NetworkCalibrationError::PayloadCaptureForbidden);
        }
        if self.samples.is_empty() {
            return Err(NetworkCalibrationError::EmptyCorpus);
        }

        let mut ids = BTreeSet::new();
        let mut baseline = 0usize;
        let mut evaluation = 0usize;
        let mut has_in_distribution_eval = false;
        let mut has_benign_novel = false;
        let mut has_synthetic_anomaly = false;
        for sample in &self.samples {
            sample.validate()?;
            if !ids.insert(sample.case_id.as_str()) {
                return Err(NetworkCalibrationError::DuplicateCase(
                    sample.case_id.clone(),
                ));
            }
            match sample.role {
                CalibrationSampleRole::Baseline => baseline += 1,
                CalibrationSampleRole::Evaluation => {
                    evaluation += 1;
                    match sample.label {
                        CalibrationLabel::InDistribution => has_in_distribution_eval = true,
                        CalibrationLabel::BenignNovel => has_benign_novel = true,
                        CalibrationLabel::SyntheticAnomaly => has_synthetic_anomaly = true,
                        CalibrationLabel::PolicyContradiction => {}
                    }
                }
            }
        }
        if baseline == 0 || evaluation == 0 {
            return Err(NetworkCalibrationError::MissingSplit);
        }
        if !has_in_distribution_eval || !has_benign_novel || !has_synthetic_anomaly {
            return Err(NetworkCalibrationError::IncompleteEvaluationClasses);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCalibrationError> {
        self.validate()?;
        hash_json(CORPUS_DOMAIN, self)
    }

    pub fn calibrate(
        &self,
        novelty_threshold_milli: u16,
    ) -> Result<NetworkCalibrationReport, NetworkCalibrationError> {
        self.validate()?;
        if novelty_threshold_milli > 1000 {
            return Err(NetworkCalibrationError::InvalidThreshold);
        }
        let baseline_observations = self
            .samples
            .iter()
            .filter(|sample| sample.role == CalibrationSampleRole::Baseline)
            .map(|sample| sample.observation.clone())
            .collect::<Vec<_>>();
        let prototype = NetworkBehaviorPrototype::from_observations(&baseline_observations)?;

        let mut tp = 0u64;
        let mut fp = 0u64;
        let mut tn = 0u64;
        let mut fn_ = 0u64;
        let mut policy_contradictions = 0u64;
        let mut evaluated = 0u64;
        let mut novelty_values = Vec::new();

        for sample in self
            .samples
            .iter()
            .filter(|s| s.role == CalibrationSampleRole::Evaluation)
        {
            let evidence = NetworkAnomalyEvidence::assess(&sample.observation, &prototype)?;
            novelty_values.push(evidence.novelty_milli);
            if sample.label == CalibrationLabel::PolicyContradiction {
                policy_contradictions += 1;
                continue;
            }
            evaluated += 1;
            let predicted = evidence.novelty_milli >= novelty_threshold_milli;
            let positive = sample.label == CalibrationLabel::SyntheticAnomaly;
            match (predicted, positive) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, false) => tn += 1,
                (false, true) => fn_ += 1,
            }
        }
        novelty_values.sort_unstable();

        let report = NetworkCalibrationReport {
            schema_version: NETWORK_CALIBRATION_SCHEMA_VERSION,
            corpus_blake3: self.digest_hex()?,
            model_family: NETWORK_CALIBRATION_MODEL_FAMILY.into(),
            novelty_threshold_milli,
            evaluated_model_samples: evaluated,
            policy_contradiction_samples: policy_contradictions,
            true_positive: tp,
            false_positive: fp,
            true_negative: tn,
            false_negative: fn_,
            precision_milli: ratio_milli(tp, tp + fp),
            recall_milli: ratio_milli(tp, tp + fn_),
            false_positive_rate_milli: ratio_milli(fp, fp + tn),
            false_negative_rate_milli: ratio_milli(fn_, tp + fn_),
            median_novelty_milli: percentile(&novelty_values, 50),
            p95_novelty_milli: percentile(&novelty_values, 95),
            threshold_selection: "explicit-candidate-not-auto-optimized-v43".into(),
            status: "measurement-only-v43".into(),
            autonomous_response_eligible: false,
            quarantine_authority: false,
            network_enforcement_authority: false,
        };
        report.validate()?;
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCalibrationReport {
    pub schema_version: u32,
    pub corpus_blake3: String,
    pub model_family: String,
    pub novelty_threshold_milli: u16,
    pub evaluated_model_samples: u64,
    pub policy_contradiction_samples: u64,
    pub true_positive: u64,
    pub false_positive: u64,
    pub true_negative: u64,
    pub false_negative: u64,
    pub precision_milli: u16,
    pub recall_milli: u16,
    pub false_positive_rate_milli: u16,
    pub false_negative_rate_milli: u16,
    pub median_novelty_milli: u16,
    pub p95_novelty_milli: u16,
    pub threshold_selection: String,
    pub status: String,
    pub autonomous_response_eligible: bool,
    pub quarantine_authority: bool,
    pub network_enforcement_authority: bool,
}

impl NetworkCalibrationReport {
    pub fn validate(&self) -> Result<(), NetworkCalibrationError> {
        if self.schema_version != NETWORK_CALIBRATION_SCHEMA_VERSION {
            return Err(NetworkCalibrationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.corpus_blake3)?;
        if self.model_family != NETWORK_CALIBRATION_MODEL_FAMILY {
            return Err(NetworkCalibrationError::ModelFamilyDrift);
        }
        if self.novelty_threshold_milli > 1000
            || self.precision_milli > 1000
            || self.recall_milli > 1000
            || self.false_positive_rate_milli > 1000
            || self.false_negative_rate_milli > 1000
            || self.median_novelty_milli > 1000
            || self.p95_novelty_milli > 1000
        {
            return Err(NetworkCalibrationError::InvalidMetric);
        }
        if self.evaluated_model_samples
            != self.true_positive + self.false_positive + self.true_negative + self.false_negative
        {
            return Err(NetworkCalibrationError::ConfusionMatrixMismatch);
        }
        if self.threshold_selection != "explicit-candidate-not-auto-optimized-v43"
            || self.status != "measurement-only-v43"
            || self.autonomous_response_eligible
            || self.quarantine_authority
            || self.network_enforcement_authority
        {
            return Err(NetworkCalibrationError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCalibrationError> {
        self.validate()?;
        hash_json(REPORT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDriftEvidence {
    pub schema_version: u32,
    pub workload_blake3: String,
    pub baseline_blake3: String,
    pub window_id: String,
    pub sample_count: u64,
    pub mean_novelty_milli: u16,
    pub p95_novelty_milli: u16,
    pub policy_contradictions: u64,
    pub model_family: String,
    pub response: String,
    pub network_enforcement_authority: bool,
    pub quarantine_authority: bool,
}

impl NetworkDriftEvidence {
    pub fn assess(
        baseline: &NetworkBehaviorPrototype,
        window_id: impl Into<String>,
        observations: &[NetworkFlowObservation],
    ) -> Result<Self, NetworkCalibrationError> {
        baseline.validate()?;
        if observations.is_empty() {
            return Err(NetworkCalibrationError::EmptyDriftWindow);
        }
        let mut values = Vec::with_capacity(observations.len());
        let mut contradictions = 0u64;
        for observation in observations {
            if observation.workload_blake3 != baseline.workload_blake3 {
                return Err(NetworkCalibrationError::MixedWorkloads);
            }
            let evidence = NetworkAnomalyEvidence::assess(observation, baseline)?;
            values.push(evidence.novelty_milli);
            if evidence.policy_contradiction {
                contradictions += 1;
            }
        }
        values.sort_unstable();
        let sum: u64 = values.iter().map(|v| *v as u64).sum();
        let evidence = Self {
            schema_version: NETWORK_CALIBRATION_SCHEMA_VERSION,
            workload_blake3: baseline.workload_blake3.clone(),
            baseline_blake3: baseline.fingerprint_hex()?,
            window_id: window_id.into(),
            sample_count: values.len() as u64,
            mean_novelty_milli: (sum / values.len() as u64) as u16,
            p95_novelty_milli: percentile(&values, 95),
            policy_contradictions: contradictions,
            model_family: NETWORK_CALIBRATION_MODEL_FAMILY.into(),
            response: "observe-only-drift-v43".into(),
            network_enforcement_authority: false,
            quarantine_authority: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), NetworkCalibrationError> {
        if self.schema_version != NETWORK_CALIBRATION_SCHEMA_VERSION {
            return Err(NetworkCalibrationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        validate_digest(&self.workload_blake3)?;
        validate_digest(&self.baseline_blake3)?;
        validate_token("window id", &self.window_id, 256)?;
        if self.sample_count == 0 || self.mean_novelty_milli > 1000 || self.p95_novelty_milli > 1000
        {
            return Err(NetworkCalibrationError::InvalidMetric);
        }
        if self.model_family != NETWORK_CALIBRATION_MODEL_FAMILY
            || self.response != "observe-only-drift-v43"
            || self.network_enforcement_authority
            || self.quarantine_authority
        {
            return Err(NetworkCalibrationError::AuthorityEscalation);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, NetworkCalibrationError> {
        self.validate()?;
        hash_json(DRIFT_DOMAIN, self)
    }
}

pub fn network_calibration_policy_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": NETWORK_CALIBRATION_SCHEMA_VERSION,
        "kind": "symthaea-network-calibration-policy-v1",
        "status": "measurement-only-v43",
        "model_family": NETWORK_CALIBRATION_MODEL_FAMILY,
        "corpus": {
            "source": "synthetic-or-owner-reviewed-v43",
            "split": "explicit-baseline-calibration-and-held-out-v45",
            "held_out_required": true,
            "held_out_case_ids_disjoint": true,
            "required_evaluation_classes": [
                "in-distribution",
                "benign-novel",
                "synthetic-anomaly"
            ],
            "policy_contradictions": "reported-separately-not-ai-ground-truth"
        },
        "threshold": {
            "selection": "externally-selected-before-held-out-v45",
            "held_out_may_not_select_threshold": true,
            "automatic_tuning": false
        },
        "telemetry": {
            "payload_capture": false
        },
        "authority": {
            "network_enforcement": false,
            "quarantine": false,
            "capability_lease_minting": false,
            "autonomous_response_eligible": false
        },
        "drift": {
            "status": "observe-only-drift-v43",
            "automatic_response": false
        }
    }))
    .map(|s| s + "\n")
    .unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"status\":\"serialization-failed\"}}\n",
            NETWORK_CALIBRATION_SCHEMA_VERSION
        )
    })
}

fn ratio_milli(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        0
    } else {
        ((numerator.saturating_mul(1000) / denominator).min(1000)) as u16
    }
}

fn percentile(values: &[u16], percentile: usize) -> u16 {
    if values.is_empty() {
        return 0;
    }
    let index = ((values.len() - 1) * percentile + 50) / 100;
    values[index.min(values.len() - 1)]
}

fn validate_digest(value: &str) -> Result<(), NetworkCalibrationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(NetworkCalibrationError::InvalidDigest)
    }
}

fn validate_token(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), NetworkCalibrationError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        Err(NetworkCalibrationError::InvalidToken(field))
    } else {
        Ok(())
    }
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, NetworkCalibrationError> {
    let encoded = serde_json::to_vec(value).map_err(|_| NetworkCalibrationError::Serialization)?;
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    Ok(h.finalize().to_hex().to_string())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkCalibrationError {
    #[error("unsupported network calibration schema version {0}")]
    UnsupportedSchema(u32),
    #[error("network cognition error: {0}")]
    Cognition(#[from] NetworkCognitionError),
    #[error("network calibration model family drifted from V41/V43 contract")]
    ModelFamilyDrift,
    #[error("invalid calibration corpus source kind")]
    InvalidSourceKind,
    #[error("payload capture is forbidden in the V43 calibration baseline")]
    PayloadCaptureForbidden,
    #[error("network calibration corpus is empty")]
    EmptyCorpus,
    #[error("calibration case id is duplicated: {0}")]
    DuplicateCase(String),
    #[error("baseline samples must be labeled in-distribution")]
    InvalidBaselineLabel,
    #[error("calibration corpus requires non-empty baseline and evaluation splits")]
    MissingSplit,
    #[error(
        "evaluation split must contain in-distribution, benign-novel and synthetic-anomaly samples"
    )]
    IncompleteEvaluationClasses,
    #[error("invalid novelty threshold")]
    InvalidThreshold,
    #[error("invalid calibration/drift metric")]
    InvalidMetric,
    #[error("calibration confusion matrix disagrees with evaluated sample count")]
    ConfusionMatrixMismatch,
    #[error("network calibration attempted to gain autonomous enforcement/quarantine authority")]
    AuthorityEscalation,
    #[error("network drift window is empty")]
    EmptyDriftWindow,
    #[error("network drift evidence mixed multiple workloads")]
    MixedWorkloads,
    #[error("invalid network calibration digest")]
    InvalidDigest,
    #[error("invalid network calibration token {0}")]
    InvalidToken(&'static str),
    #[error("network calibration evidence serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_cognition::CapabilityDecision;
    use crate::network_covenant::{NetworkDirection, NetworkProtocol, NetworkZone};

    fn obs(destination: u8, sent: u64) -> NetworkFlowObservation {
        NetworkFlowObservation {
            schema_version: NETWORK_COGNITION_SCHEMA_VERSION,
            holon_id: "holon-a".into(),
            network_policy_blake3: "11".repeat(32),
            workload_blake3: "22".repeat(32),
            capability_blake3: Some("33".repeat(32)),
            decision: CapabilityDecision::Allowed,
            direction: NetworkDirection::Egress,
            protocol: NetworkProtocol::Tcp,
            destination_zone: NetworkZone::Internet,
            destination_identity_blake3: format!("{:02x}", destination).repeat(32),
            bytes_sent: sent,
            bytes_received: 1024,
            duration_ms: 500,
            hour_bucket: 12,
            payload_bytes_captured: 0,
        }
    }

    fn corpus() -> NetworkCalibrationCorpus {
        NetworkCalibrationCorpus {
            schema_version: 1,
            corpus_id: "deterministic-fixture-v43".into(),
            model_family: NETWORK_CALIBRATION_MODEL_FAMILY.into(),
            source_kind: "synthetic-or-owner-reviewed-v43".into(),
            payload_capture: false,
            samples: vec![
                LabeledNetworkObservation {
                    case_id: "base-a".into(),
                    role: CalibrationSampleRole::Baseline,
                    label: CalibrationLabel::InDistribution,
                    observation: obs(0x44, 1024),
                },
                LabeledNetworkObservation {
                    case_id: "base-b".into(),
                    role: CalibrationSampleRole::Baseline,
                    label: CalibrationLabel::InDistribution,
                    observation: obs(0x44, 2048),
                },
                LabeledNetworkObservation {
                    case_id: "eval-normal".into(),
                    role: CalibrationSampleRole::Evaluation,
                    label: CalibrationLabel::InDistribution,
                    observation: obs(0x44, 1536),
                },
                LabeledNetworkObservation {
                    case_id: "eval-benign".into(),
                    role: CalibrationSampleRole::Evaluation,
                    label: CalibrationLabel::BenignNovel,
                    observation: obs(0x45, 1 << 20),
                },
                LabeledNetworkObservation {
                    case_id: "eval-synthetic".into(),
                    role: CalibrationSampleRole::Evaluation,
                    label: CalibrationLabel::SyntheticAnomaly,
                    observation: obs(0x99, 1 << 28),
                },
            ],
        }
    }

    #[test]
    fn calibration_is_measurement_only_even_when_metrics_are_good() {
        let report = corpus().calibrate(500).unwrap();
        assert_eq!(report.status, "measurement-only-v43");
        assert!(!report.autonomous_response_eligible);
        assert!(!report.network_enforcement_authority);
        assert!(!report.quarantine_authority);
    }

    #[test]
    fn benign_novel_is_a_false_positive_if_threshold_flags_it() {
        let report = corpus().calibrate(0).unwrap();
        assert!(report.false_positive >= 1);
    }

    #[test]
    fn baseline_cannot_be_seeded_with_anomalies() {
        let mut corpus = corpus();
        corpus.samples[0].label = CalibrationLabel::SyntheticAnomaly;
        assert_eq!(
            corpus.validate(),
            Err(NetworkCalibrationError::InvalidBaselineLabel)
        );
    }
}
