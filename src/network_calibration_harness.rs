// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! V45 held-out calibration experiment for observe-only network cognition.
//! The candidate novelty threshold is supplied externally. Calibration and
//! held-out samples are disjoint by case id and policy contradictions never
//! count toward model performance.

use crate::network_calibration::CalibrationLabel;
use crate::network_cognition::{
    NetworkAnomalyEvidence, NetworkBehaviorPrototype, NetworkFlowObservation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const NETWORK_CALIBRATION_EXPERIMENT_SCHEMA_VERSION: u32 = 1;
pub const NETWORK_CALIBRATION_EXPERIMENT_STATUS: &str = "held-out-measurement-only-v45";
const DOMAIN: &[u8] = b"symthaea:nixward:network-calibration-experiment:v45\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationCaseV45 {
    pub case_id: String,
    pub label: CalibrationLabel,
    pub observation: NetworkFlowObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCalibrationExperimentV45 {
    pub schema_version: u32,
    pub experiment_id: String,
    pub source_kind: String,
    pub payload_capture: bool,
    pub baseline: Vec<NetworkFlowObservation>,
    pub calibration: Vec<CalibrationCaseV45>,
    pub held_out: Vec<CalibrationCaseV45>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionMetricsV45 {
    pub evaluated: u64,
    pub policy_contradictions: u64,
    pub benign_novel: u64,
    pub true_positive: u64,
    pub false_positive: u64,
    pub true_negative: u64,
    pub false_negative: u64,
    pub precision_milli: u16,
    pub recall_milli: u16,
    pub false_positive_rate_milli: u16,
    pub false_negative_rate_milli: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCalibrationExperimentReportV45 {
    pub schema_version: u32,
    pub experiment_blake3: String,
    pub threshold_milli: u16,
    pub threshold_selection: String,
    pub calibration: PartitionMetricsV45,
    pub held_out: PartitionMetricsV45,
    pub status: String,
    pub held_out_required: bool,
    pub autonomous_response_eligible: bool,
    pub quarantine_authority: bool,
    pub network_enforcement_authority: bool,
}

impl NetworkCalibrationExperimentV45 {
    pub fn validate(&self) -> Result<(), CalibrationHarnessError> {
        if self.schema_version != NETWORK_CALIBRATION_EXPERIMENT_SCHEMA_VERSION {
            return Err(CalibrationHarnessError::Schema);
        }
        if self.experiment_id.trim().is_empty() || self.experiment_id.contains('\n') {
            return Err(CalibrationHarnessError::InvalidId);
        }
        if self.source_kind != "deterministic-synthetic-or-owner-reviewed-v45"
            || self.payload_capture
        {
            return Err(CalibrationHarnessError::InvalidSource);
        }
        if self.baseline.is_empty() || self.calibration.is_empty() || self.held_out.is_empty() {
            return Err(CalibrationHarnessError::MissingPartition);
        }
        let workload = self.baseline[0].workload_blake3.clone();
        let mut ids = BTreeSet::new();
        for observation in &self.baseline {
            observation
                .validate()
                .map_err(|_| CalibrationHarnessError::Observation)?;
            if observation.workload_blake3 != workload {
                return Err(CalibrationHarnessError::MixedWorkload);
            }
        }
        for cases in [&self.calibration, &self.held_out] {
            let mut has_normal = false;
            let mut has_benign = false;
            let mut has_anomaly = false;
            for case in cases {
                if !ids.insert(case.case_id.as_str()) {
                    return Err(CalibrationHarnessError::DuplicateCase);
                }
                case.observation
                    .validate()
                    .map_err(|_| CalibrationHarnessError::Observation)?;
                if case.observation.workload_blake3 != workload {
                    return Err(CalibrationHarnessError::MixedWorkload);
                }
                match case.label {
                    CalibrationLabel::InDistribution => has_normal = true,
                    CalibrationLabel::BenignNovel => has_benign = true,
                    CalibrationLabel::SyntheticAnomaly => has_anomaly = true,
                    CalibrationLabel::PolicyContradiction => {}
                }
            }
            if !has_normal || !has_benign || !has_anomaly {
                return Err(CalibrationHarnessError::IncompleteClasses);
            }
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, CalibrationHarnessError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| CalibrationHarnessError::Serialization)?;
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        Ok(h.finalize().to_hex().to_string())
    }

    pub fn evaluate(
        &self,
        threshold_milli: u16,
    ) -> Result<NetworkCalibrationExperimentReportV45, CalibrationHarnessError> {
        self.validate()?;
        if threshold_milli > 1000 {
            return Err(CalibrationHarnessError::Threshold);
        }
        let prototype = NetworkBehaviorPrototype::from_observations(&self.baseline)
            .map_err(|_| CalibrationHarnessError::Observation)?;
        let report = NetworkCalibrationExperimentReportV45 {
            schema_version: 1,
            experiment_blake3: self.digest_hex()?,
            threshold_milli,
            threshold_selection: "externally-selected-before-held-out-v45".into(),
            calibration: score(&prototype, &self.calibration, threshold_milli)?,
            held_out: score(&prototype, &self.held_out, threshold_milli)?,
            status: NETWORK_CALIBRATION_EXPERIMENT_STATUS.into(),
            held_out_required: true,
            autonomous_response_eligible: false,
            quarantine_authority: false,
            network_enforcement_authority: false,
        };
        report.validate()?;
        Ok(report)
    }
}

impl NetworkCalibrationExperimentReportV45 {
    pub fn validate(&self) -> Result<(), CalibrationHarnessError> {
        if self.schema_version != 1
            || self.experiment_blake3.len() != 64
            || !self
                .experiment_blake3
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CalibrationHarnessError::Schema);
        }
        if self.threshold_milli > 1000
            || self.threshold_selection != "externally-selected-before-held-out-v45"
            || self.status != NETWORK_CALIBRATION_EXPERIMENT_STATUS
            || !self.held_out_required
            || self.autonomous_response_eligible
            || self.quarantine_authority
            || self.network_enforcement_authority
        {
            return Err(CalibrationHarnessError::Authority);
        }
        Ok(())
    }
}

fn score(
    prototype: &NetworkBehaviorPrototype,
    cases: &[CalibrationCaseV45],
    threshold: u16,
) -> Result<PartitionMetricsV45, CalibrationHarnessError> {
    let (mut tp, mut fp, mut tn, mut fn_, mut pc, mut benign) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for case in cases {
        let ev = NetworkAnomalyEvidence::assess(&case.observation, prototype)
            .map_err(|_| CalibrationHarnessError::Observation)?;
        if case.label == CalibrationLabel::PolicyContradiction {
            pc += 1;
            continue;
        }
        if case.label == CalibrationLabel::BenignNovel {
            benign += 1;
        }
        let predicted = ev.novelty_milli >= threshold;
        let positive = case.label == CalibrationLabel::SyntheticAnomaly;
        match (predicted, positive) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, false) => tn += 1,
            (false, true) => fn_ += 1,
        }
    }
    Ok(PartitionMetricsV45 {
        evaluated: tp + fp + tn + fn_,
        policy_contradictions: pc,
        benign_novel: benign,
        true_positive: tp,
        false_positive: fp,
        true_negative: tn,
        false_negative: fn_,
        precision_milli: ratio(tp, tp + fp),
        recall_milli: ratio(tp, tp + fn_),
        false_positive_rate_milli: ratio(fp, fp + tn),
        false_negative_rate_milli: ratio(fn_, tp + fn_),
    })
}
fn ratio(n: u64, d: u64) -> u16 {
    if d == 0 {
        0
    } else {
        ((n * 1000 + d / 2) / d).min(1000) as u16
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CalibrationHarnessError {
    #[error("invalid schema/digest")]
    Schema,
    #[error("invalid experiment id")]
    InvalidId,
    #[error("invalid source/privacy claim")]
    InvalidSource,
    #[error("missing experiment partition")]
    MissingPartition,
    #[error("duplicate case across calibration/held-out")]
    DuplicateCase,
    #[error("mixed workload identities")]
    MixedWorkload,
    #[error("partition is missing required semantic classes")]
    IncompleteClasses,
    #[error("invalid flow observation")]
    Observation,
    #[error("invalid threshold")]
    Threshold,
    #[error("authority/status escalation")]
    Authority,
    #[error("serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_cannot_gain_authority() {
        let mut r = NetworkCalibrationExperimentReportV45 {
            schema_version: 1,
            experiment_blake3: "aa".repeat(32),
            threshold_milli: 500,
            threshold_selection: "externally-selected-before-held-out-v45".into(),
            calibration: PartitionMetricsV45 {
                evaluated: 1,
                policy_contradictions: 0,
                benign_novel: 0,
                true_positive: 0,
                false_positive: 0,
                true_negative: 1,
                false_negative: 0,
                precision_milli: 0,
                recall_milli: 0,
                false_positive_rate_milli: 0,
                false_negative_rate_milli: 0,
            },
            held_out: PartitionMetricsV45 {
                evaluated: 1,
                policy_contradictions: 0,
                benign_novel: 0,
                true_positive: 0,
                false_positive: 0,
                true_negative: 1,
                false_negative: 0,
                precision_milli: 0,
                recall_milli: 0,
                false_positive_rate_milli: 0,
                false_negative_rate_milli: 0,
            },
            status: NETWORK_CALIBRATION_EXPERIMENT_STATUS.into(),
            held_out_required: true,
            autonomous_response_eligible: false,
            quarantine_authority: false,
            network_enforcement_authority: false,
        };
        assert!(r.validate().is_ok());
        r.quarantine_authority = true;
        assert!(r.validate().is_err());
    }
}
