// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

//! Provenance binding between an AI proposal and one exact Nixward ChangePlan.
//!
//! This module binds content digests; it does not verify an AI proof, assert that
//! inputs are true, decide whether a policy is appropriate, or grant execution
//! authority. Callers must independently verify referenced artifacts/evidence
//! and use the existing ChangeAuthorization and enforcement path for privileged
//! actions. A binding from another plan must never be reused for this plan.

use super::change_covenant::{ChangePlan, MachineBinding};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const AI_PROPOSAL_BINDING_SCHEMA_VERSION: u16 = 1;
const AI_PROPOSAL_BINDING_DOMAIN: &[u8] = b"nixward-ai-proposal-binding-v1\0";

/// Content-addressed provenance for one AI-generated proposal.
///
/// Digest fields are fixed-width 32-byte values supplied by the caller. The
/// caller is responsible for computing each digest over the intended artifact
/// or canonical input bytes; this type cannot verify bytes it does not receive.
/// The constructor rejects all-zero placeholders, and validation must be
/// repeated after deserializing untrusted data. This type intentionally has no
/// method that authorizes or executes a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiProposalBinding {
    schema_version: u16,
    plan_digest: [u8; 32],
    model_artifact_digest: [u8; 32],
    input_digest: [u8; 32],
    policy_digest: [u8; 32],
    proposal_output_digest: [u8; 32],
    verifier_artifact_digest: [u8; 32],
    evaluation_evidence_digest: [u8; 32],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AiProposalBindingError {
    #[error("unsupported AI proposal binding schema version: {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("missing or zero {0} digest")]
    MissingDigest(&'static str),
    #[error("AI proposal binding refers to a different change plan")]
    PlanBindingMismatch,
}

impl AiProposalBinding {
    /// Bind AI provenance to the exact, already-constructed ChangePlan.
    ///
    /// This is a provenance constructor, not a proof verifier. The meaning and
    /// origin of each supplied digest must be documented by the caller.
    /// evaluation_evidence_digest does not imply that evidence has been checked.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan: &ChangePlan,
        model_artifact_digest: [u8; 32],
        input_digest: [u8; 32],
        policy_digest: [u8; 32],
        proposal_output_digest: [u8; 32],
        verifier_artifact_digest: [u8; 32],
        evaluation_evidence_digest: [u8; 32],
    ) -> Result<Self, AiProposalBindingError> {
        let binding = Self {
            schema_version: AI_PROPOSAL_BINDING_SCHEMA_VERSION,
            plan_digest: plan.digest(),
            model_artifact_digest,
            input_digest,
            policy_digest,
            proposal_output_digest,
            verifier_artifact_digest,
            evaluation_evidence_digest,
        };
        binding.validate_shape()?;
        Ok(binding)
    }

    /// Validate schema and bind this evidence to the exact supplied plan.
    ///
    /// Freshness and single-use replay consumption remain responsibilities of
    /// the existing authorization/execution flow.
    pub fn validate_for_plan(&self, plan: &ChangePlan) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        if self.plan_digest != plan.digest() {
            return Err(AiProposalBindingError::PlanBindingMismatch);
        }
        Ok(())
    }

    /// Stable domain-separated digest for use as provenance/evidence digest.
    ///
    /// This digest does not itself mean the proposal is safe or authorized.
    pub fn digest(&self) -> Result<[u8; 32], AiProposalBindingError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_PROPOSAL_BINDING_DOMAIN);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.plan_digest);
        hasher.update(&self.model_artifact_digest);
        hasher.update(&self.input_digest);
        hasher.update(&self.policy_digest);
        hasher.update(&self.proposal_output_digest);
        hasher.update(&self.verifier_artifact_digest);
        hasher.update(&self.evaluation_evidence_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn model_artifact_digest(&self) -> [u8; 32] {
        self.model_artifact_digest
    }

    pub fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn proposal_output_digest(&self) -> [u8; 32] {
        self.proposal_output_digest
    }

    pub fn verifier_artifact_digest(&self) -> [u8; 32] {
        self.verifier_artifact_digest
    }

    pub fn evaluation_evidence_digest(&self) -> [u8; 32] {
        self.evaluation_evidence_digest
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_BINDING_SCHEMA_VERSION {
            return Err(AiProposalBindingError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        for (name, digest) in [
            ("plan", &self.plan_digest),
            ("model artifact", &self.model_artifact_digest),
            ("input", &self.input_digest),
            ("policy", &self.policy_digest),
            ("proposal output", &self.proposal_output_digest),
            ("verifier artifact", &self.verifier_artifact_digest),
            ("evaluation evidence", &self.evaluation_evidence_digest),
        ] {
            if *digest == [0; 32] {
                return Err(AiProposalBindingError::MissingDigest(name));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::executor::NixOSCommand;

    fn plan(machine_id: &str) -> ChangePlan {
        ChangePlan::command_only(
            MachineBinding::new(machine_id).unwrap(),
            NixOSCommand::Search {
                query: "nixpkgs#hello".into(),
                json: true,
            },
            60_000,
        )
        .unwrap()
    }

    fn binding(plan: &ChangePlan) -> AiProposalBinding {
        AiProposalBinding::new(
            plan,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
        )
        .unwrap()
    }

    #[test]
    fn binding_round_trips_and_remains_plan_bound() {
        let plan = plan("machine-a");
        let original = binding(&plan);
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: AiProposalBinding = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, original);
        assert!(decoded.validate_for_plan(&plan).is_ok());
        assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());
    }

    #[test]
    fn binding_cannot_be_reused_for_another_plan() {
        let first_plan = plan("machine-a");
        let second_plan = plan("machine-b");
        let evidence = binding(&first_plan);

        assert!(evidence.validate_for_plan(&first_plan).is_ok());
        assert_eq!(
            evidence.validate_for_plan(&second_plan),
            Err(AiProposalBindingError::PlanBindingMismatch)
        );
    }

    #[test]
    fn digest_binds_each_evidence_dimension() {
        let plan = plan("machine-a");
        let original = binding(&plan);

        let mut changed_model = original.clone();
        changed_model.model_artifact_digest = [11; 32];
        assert_ne!(original.digest().unwrap(), changed_model.digest().unwrap());

        let mut changed_policy = original.clone();
        changed_policy.policy_digest = [12; 32];
        assert_ne!(original.digest().unwrap(), changed_policy.digest().unwrap());

        let mut changed_input = original.clone();
        changed_input.input_digest = [13; 32];
        assert_ne!(original.digest().unwrap(), changed_input.digest().unwrap());
    }

    #[test]
    fn zero_digest_is_rejected_even_after_deserialization() {
        let plan = plan("machine-a");
        let mut evidence = binding(&plan);
        evidence.evaluation_evidence_digest = [0; 32];

        assert_eq!(
            evidence.validate_for_plan(&plan),
            Err(AiProposalBindingError::MissingDigest("evaluation evidence"))
        );
        assert_eq!(
            evidence.digest(),
            Err(AiProposalBindingError::MissingDigest("evaluation evidence"))
        );
    }

    #[test]
    fn unsupported_schema_version_is_rejected_even_after_deserialization() {
        let plan = plan("machine-a");
        let mut evidence = binding(&plan);
        evidence.schema_version = AI_PROPOSAL_BINDING_SCHEMA_VERSION + 1;

        assert_eq!(
            evidence.validate_for_plan(&plan),
            Err(AiProposalBindingError::UnsupportedSchemaVersion(2))
        );
    }
}
