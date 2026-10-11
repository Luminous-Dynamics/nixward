// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

//! Provenance binding between an AI proposal and one exact Nixward ChangePlan.
//!
//! This module binds content digests; it does not verify an AI proof, assert that
//! inputs are true, decide whether a policy is appropriate, prove that a proposal
//! semantically entails the resulting ChangePlan, or grant execution authority.
//! Callers must independently verify referenced artifacts/evidence and the
//! proposal-to-plan derivation, then use the existing ChangeAuthorization and
//! enforcement path for privileged actions. A binding from another plan must
//! never be reused for this plan.

use super::change_covenant::{ChangePlan, MachineBinding};
use super::config_writer::ConfigPatch;
use super::executor::NixOSCommand;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

pub const AI_PROPOSAL_BINDING_SCHEMA_VERSION: u16 = 1;
pub const AI_PROPOSAL_OUTPUT_SCHEMA_VERSION: u16 = 1;
const AI_PROPOSAL_BINDING_DOMAIN: &[u8] = b"nixward-ai-proposal-binding-v1\0";
const AI_PROPOSAL_ARTIFACT_DOMAIN: &[u8] = b"nixward-ai-proposal-artifact-v1\0";


/// Structured, versioned proposal output used for exact plan resolution.
///
/// This is deliberately not a free-form natural-language semantic verifier.
/// It verifies that the structured machine/configuration/command intent in the
/// proposal is exactly the intent in a ChangePlan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalOutputIntent {
    schema_version: u16,
    machine_id: String,
    config_patch: Option<AiProposalOutputConfigPatch>,
    command: Option<NixOSCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiProposalOutputConfigPatch {
    target: String,
    original: String,
    modified: String,
    description: String,
}

/// Artifact classes used to domain-separate proposal provenance digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalArtifactKind {
    ModelArtifact,
    Input,
    Policy,
    ProposalOutput,
    VerifierArtifact,
    EvaluationEvidence,
}

impl ProposalArtifactKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::ModelArtifact => b"model-artifact",
            Self::Input => b"input",
            Self::Policy => b"policy",
            Self::ProposalOutput => b"proposal-output",
            Self::VerifierArtifact => b"verifier-artifact",
            Self::EvaluationEvidence => b"evaluation-evidence",
        }
    }
}

/// Hash exact artifact bytes with a stable domain and role tag.
///
/// For structured inputs, callers must first encode the value canonically. This
/// helper does not validate what the artifact means or whether it is trustworthy.
pub fn digest_artifact(kind: ProposalArtifactKind, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AI_PROPOSAL_ARTIFACT_DOMAIN);
    let tag = kind.tag();
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Content-addressed provenance for one AI-generated proposal.

/// Digest fields are fixed-width 32-byte values supplied by the caller. The
/// caller is responsible for computing each digest over the intended artifact
/// or canonical input bytes; this type cannot verify bytes it does not receive.
/// The constructor rejects all-zero placeholders, and validation must be
/// repeated after deserializing untrusted data. This type intentionally has no
/// method that authorizes or executes a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalBinding {
    schema_version: u16,
    #[serde(with = "serde_hex_32")]
    plan_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    model_artifact_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    input_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    policy_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    proposal_output_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    verifier_artifact_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    evaluation_evidence_digest: [u8; 32],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AiProposalBindingError {
    #[error("unsupported AI proposal binding schema version: {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("missing or zero {0} digest")]
    MissingDigest(&'static str),
    #[error("required {0} artifact bytes must not be empty")]
    EmptyArtifactBytes(&'static str),
    #[error("{0} artifact digest does not match the supplied bytes")]
    ArtifactDigestMismatch(&'static str),
    #[error("AI proposal binding refers to a different change plan")]
    PlanBindingMismatch,
    #[error("AI proposal validation evidence refers to a different proposal binding")]
    ProposalBindingMismatch,
    #[error("unsupported AI proposal validation evidence schema version: {0}")]
    UnsupportedValidationEvidenceSchemaVersion(u16),
    #[error("unsupported AI proposal output schema version: {0}")]
    UnsupportedProposalOutputSchemaVersion(u16),
    #[error("invalid AI proposal output intent: {0}")]
    InvalidProposalOutput(String),
    #[error("AI proposal output intent does not exactly match the ChangePlan")]
    ProposalOutputPlanMismatch,
}


impl AiProposalOutputIntent {
    /// Build a structured proposal output from typed intent components.
    pub fn new(
        machine: &MachineBinding,
        config_patch: Option<&ConfigPatch>,
        command: Option<&NixOSCommand>,
    ) -> Result<Self, AiProposalBindingError> {
        let config_patch = config_patch
            .map(|patch| {
                let target = patch.target.to_str().ok_or_else(|| {
                    AiProposalBindingError::InvalidProposalOutput(
                        "configuration target path is not valid UTF-8".into(),
                    )
                })?;
                Ok(AiProposalOutputConfigPatch {
                    target: target.to_string(),
                    original: patch.original.clone(),
                    modified: patch.modified.clone(),
                    description: patch.description.clone(),
                })
            })
            .transpose()?;

        let intent = Self {
            schema_version: AI_PROPOSAL_OUTPUT_SCHEMA_VERSION,
            machine_id: machine.machine_id().to_string(),
            config_patch,
            command: command.cloned(),
        };
        intent.validate_shape()?;
        Ok(intent)
    }

    /// Decode only the canonical JSON byte representation for schema v1.
    ///
    /// Re-encoding must reproduce the exact input bytes. This rejects whitespace,
    /// reordered fields, omitted null fields, unknown fields, and non-canonical
    /// nested command encodings before their digest is accepted as proposal output.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AiProposalBindingError> {
        if bytes.is_empty() {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "canonical output bytes must not be empty".into(),
            ));
        }
        let intent: Self = serde_json::from_slice(bytes).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!("invalid JSON: {error}"))
        })?;
        intent.validate_shape()?;
        let canonical = serde_json::to_vec(&intent).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!(
                "canonical JSON encoding failed: {error}"
            ))
        })?;
        if canonical.as_slice() != bytes {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "output must use the canonical schema-v1 JSON encoding".into(),
            ));
        }
        Ok(intent)
    }

    /// Serialize the canonical schema-v1 output bytes that are digest-bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AiProposalBindingError> {
        self.validate_shape()?;
        serde_json::to_vec(self).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!(
                "canonical JSON encoding failed: {error}"
            ))
        })
    }

    /// Require the proposal's structured intent to match this exact plan.
    pub fn validate_for_plan(
        &self,
        plan: &ChangePlan,
    ) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        let machine = MachineBinding::new(self.machine_id.clone())
            .map_err(AiProposalBindingError::InvalidProposalOutput)?;
        let patch = self.config_patch.as_ref().map(|patch| ConfigPatch {
            target: PathBuf::from(&patch.target),
            original: patch.original.clone(),
            modified: patch.modified.clone(),
            description: patch.description.clone(),
        });
        if plan.matches_intent(&machine, patch.as_ref(), self.command.as_ref()) {
            Ok(())
        } else {
            Err(AiProposalBindingError::ProposalOutputPlanMismatch)
        }
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_OUTPUT_SCHEMA_VERSION {
            return Err(AiProposalBindingError::UnsupportedProposalOutputSchemaVersion(
                self.schema_version,
            ));
        }
        let machine = MachineBinding::new(self.machine_id.clone())
            .map_err(AiProposalBindingError::InvalidProposalOutput)?;
        if machine.machine_id() != self.machine_id {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "machine_id must use its normalized representation".into(),
            ));
        }
        if self.config_patch.is_none() && self.command.is_none() {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "output must include a configuration patch or command".into(),
            ));
        }
        if self
            .config_patch
            .as_ref()
            .is_some_and(|patch| patch.target.trim().is_empty())
        {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "configuration target path must not be empty".into(),
            ));
        }
        Ok(())
    }
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
        model_artifact_bytes: &[u8],
        input_canonical_bytes: &[u8],
        policy_canonical_bytes: &[u8],
        proposal_output_canonical_bytes: &[u8],
        verifier_artifact_bytes: &[u8],
        evaluation_evidence_canonical_bytes: &[u8],
    ) -> Result<Self, AiProposalBindingError> {
        for (label, bytes) in [
            ("model artifact", model_artifact_bytes),
            ("input", input_canonical_bytes),
            ("policy", policy_canonical_bytes),
            ("proposal output", proposal_output_canonical_bytes),
            ("verifier artifact", verifier_artifact_bytes),
            ("evaluation evidence", evaluation_evidence_canonical_bytes),
        ] {
            if bytes.is_empty() {
                return Err(AiProposalBindingError::EmptyArtifactBytes(label));
            }
        }

        AiProposalOutputIntent::from_canonical_bytes(proposal_output_canonical_bytes)?
            .validate_for_plan(plan)?;

        let binding = Self {
            schema_version: AI_PROPOSAL_BINDING_SCHEMA_VERSION,
            plan_digest: plan.digest(),
            model_artifact_digest: digest_artifact(
                ProposalArtifactKind::ModelArtifact,
                model_artifact_bytes,
            ),
            input_digest: digest_artifact(ProposalArtifactKind::Input, input_canonical_bytes),
            policy_digest: digest_artifact(ProposalArtifactKind::Policy, policy_canonical_bytes),
            proposal_output_digest: digest_artifact(
                ProposalArtifactKind::ProposalOutput,
                proposal_output_canonical_bytes,
            ),
            verifier_artifact_digest: digest_artifact(
                ProposalArtifactKind::VerifierArtifact,
                verifier_artifact_bytes,
            ),
            evaluation_evidence_digest: digest_artifact(
                ProposalArtifactKind::EvaluationEvidence,
                evaluation_evidence_canonical_bytes,
            ),
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

    /// Verify this decoded envelope against the exact plan and referenced bytes.
    ///
    /// Structured inputs must be supplied in the same canonical encoding used
    /// when the binding was created. This checks byte-to-digest correspondence;
    /// it does not verify the truth, safety, or cryptographic validity of content.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_against_artifacts(
        &self,
        plan: &ChangePlan,
        model_artifact_bytes: &[u8],
        input_canonical_bytes: &[u8],
        policy_canonical_bytes: &[u8],
        proposal_output_canonical_bytes: &[u8],
        verifier_artifact_bytes: &[u8],
        evaluation_evidence_canonical_bytes: &[u8],
    ) -> Result<(), AiProposalBindingError> {
        self.validate_for_plan(plan)?;

        for (label, kind, bytes, expected_digest) in [
            (
                "model artifact",
                ProposalArtifactKind::ModelArtifact,
                model_artifact_bytes,
                &self.model_artifact_digest,
            ),
            (
                "input",
                ProposalArtifactKind::Input,
                input_canonical_bytes,
                &self.input_digest,
            ),
            (
                "policy",
                ProposalArtifactKind::Policy,
                policy_canonical_bytes,
                &self.policy_digest,
            ),
            (
                "proposal output",
                ProposalArtifactKind::ProposalOutput,
                proposal_output_canonical_bytes,
                &self.proposal_output_digest,
            ),
            (
                "verifier artifact",
                ProposalArtifactKind::VerifierArtifact,
                verifier_artifact_bytes,
                &self.verifier_artifact_digest,
            ),
            (
                "evaluation evidence",
                ProposalArtifactKind::EvaluationEvidence,
                evaluation_evidence_canonical_bytes,
                &self.evaluation_evidence_digest,
            ),
        ] {
            if bytes.is_empty() {
                return Err(AiProposalBindingError::EmptyArtifactBytes(label));
            }
            if *expected_digest != digest_artifact(kind, bytes) {
                return Err(AiProposalBindingError::ArtifactDigestMismatch(label));
            }
        }
        AiProposalOutputIntent::from_canonical_bytes(proposal_output_canonical_bytes)?
            .validate_for_plan(plan)?;
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

/// Versioned join between ordinary validation evidence and one AI proposal.
///
/// The digest of this envelope is stored in Nixward's existing
/// SystemTransaction validation receipt. This keeps the wire transaction shape
/// unchanged while making its validation-evidence digest commit to both the
/// ordinary validation evidence and the exact AI proposal provenance.
///
/// The envelope is correlation/evidence metadata only. It is not an approval,
/// signature, proof verification result, or execution capability.
pub const AI_PROPOSAL_VALIDATION_EVIDENCE_SCHEMA_VERSION: u16 = 1;
const AI_PROPOSAL_VALIDATION_EVIDENCE_DOMAIN: &[u8] =
    b"nixward-ai-proposal-validation-evidence-v1\0";

/// Stable lowercase-hex JSON encoding for fixed-width content digests.
mod serde_hex_32 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(64);
        for byte in value {
            encoded.push_str(&format!("{byte:02x}"));
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "digest must be 64 lowercase hexadecimal characters",
            ));
        }

        let mut digest = [0u8; 32];
        for (index, slot) in digest.iter_mut().enumerate() {
            let high = (encoded.as_bytes()[index * 2] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("invalid digest encoding"))?;
            let low = (encoded.as_bytes()[index * 2 + 1] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("invalid digest encoding"))?;
            *slot = ((high << 4) | low) as u8;
        }
        Ok(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalValidationEvidence {
    schema_version: u16,
    #[serde(with = "serde_hex_32")]
    plan_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    validation_evidence_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    proposal_binding_digest: [u8; 32],
}

impl AiProposalValidationEvidence {
    pub fn new(
        plan: &ChangePlan,
        validation_evidence_digest: [u8; 32],
        proposal: &AiProposalBinding,
    ) -> Result<Self, AiProposalBindingError> {
        proposal.validate_for_plan(plan)?;
        if validation_evidence_digest == [0; 32] {
            return Err(AiProposalBindingError::MissingDigest("validation evidence"));
        }
        let evidence = Self {
            schema_version: AI_PROPOSAL_VALIDATION_EVIDENCE_SCHEMA_VERSION,
            plan_digest: plan.digest(),
            validation_evidence_digest,
            proposal_binding_digest: proposal.digest()?,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    pub fn validate_for(
        &self,
        plan: &ChangePlan,
        proposal: &AiProposalBinding,
    ) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        if self.plan_digest != plan.digest() {
            return Err(AiProposalBindingError::PlanBindingMismatch);
        }
        proposal.validate_for_plan(plan)?;
        if self.proposal_binding_digest != proposal.digest()? {
            return Err(AiProposalBindingError::ProposalBindingMismatch);
        }
        Ok(())
    }

    /// Content digest to place in SystemTransaction::ValidationReceipt.
    pub fn digest(&self) -> Result<[u8; 32], AiProposalBindingError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_PROPOSAL_VALIDATION_EVIDENCE_DOMAIN);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.plan_digest);
        hasher.update(&self.validation_evidence_digest);
        hasher.update(&self.proposal_binding_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn validation_evidence_digest(&self) -> [u8; 32] {
        self.validation_evidence_digest
    }

    pub fn proposal_binding_digest(&self) -> [u8; 32] {
        self.proposal_binding_digest
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_VALIDATION_EVIDENCE_SCHEMA_VERSION {
            return Err(
                AiProposalBindingError::UnsupportedValidationEvidenceSchemaVersion(
                    self.schema_version,
                ),
            );
        }
        for (name, digest) in [
            ("plan", &self.plan_digest),
            ("validation evidence", &self.validation_evidence_digest),
            ("proposal binding", &self.proposal_binding_digest),
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

    fn proposal_output(plan: &ChangePlan) -> Vec<u8> {
        AiProposalOutputIntent::new(plan.machine(), None, plan.command())
            .unwrap()
            .canonical_bytes()
            .unwrap()
    }

    fn binding(plan: &ChangePlan) -> AiProposalBinding {
        let output = proposal_output(plan);
        AiProposalBinding::new(
            plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &output,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap()
    }

    #[test]
    fn structured_proposal_output_is_canonical_and_matches_exact_plan_intent() {
        let plan = plan("machine-a");
        let output = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let encoded = output.canonical_bytes().unwrap();
        let decoded = AiProposalOutputIntent::from_canonical_bytes(&encoded).unwrap();
        assert!(decoded.validate_for_plan(&plan).is_ok());

        let wrong_command = NixOSCommand::Search {
            query: "nixpkgs#different".into(),
            json: true,
        };
        let mismatched =
            AiProposalOutputIntent::new(plan.machine(), None, Some(&wrong_command)).unwrap();
        assert_eq!(
            mismatched.validate_for_plan(&plan),
            Err(AiProposalBindingError::ProposalOutputPlanMismatch)
        );

        let pretty = serde_json::to_vec_pretty(&output).unwrap();
        assert!(matches!(
            AiProposalOutputIntent::from_canonical_bytes(&pretty),
            Err(AiProposalBindingError::InvalidProposalOutput(_))
        ));
    }

    #[test]
    fn proposal_output_fixture_is_canonical_and_resolves_exact_plan() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/ai-proposal-output-intent-v1.json"
        ));
        let output = AiProposalOutputIntent::from_canonical_bytes(raw.as_bytes()).unwrap();
        let plan = plan("machine-a");
        assert_eq!(output.schema_version, AI_PROPOSAL_OUTPUT_SCHEMA_VERSION);
        assert!(output.validate_for_plan(&plan).is_ok());
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

        let mut changed_output = original.clone();
        changed_output.proposal_output_digest = [14; 32];
        assert_ne!(original.digest().unwrap(), changed_output.digest().unwrap());

        let mut changed_verifier = original.clone();
        changed_verifier.verifier_artifact_digest = [15; 32];
        assert_ne!(original.digest().unwrap(), changed_verifier.digest().unwrap());

        let mut changed_evaluation = original.clone();
        changed_evaluation.evaluation_evidence_digest = [16; 32];
        assert_ne!(original.digest().unwrap(), changed_evaluation.digest().unwrap());
    }

    #[test]
    fn zero_digest_is_rejected_during_validation() {
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
    fn decoded_binding_checks_every_artifact_against_supplied_bytes() {
        let plan = plan("machine-a");
        let encoded = serde_json::to_vec(&binding(&plan)).unwrap();
        let evidence: AiProposalBinding = serde_json::from_slice(&encoded).unwrap();
        assert!(evidence
            .validate_against_artifacts(
                &plan,
                b"model-artifact-v1",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                &proposal_output(&plan),
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
            )
            .is_ok());

        assert_eq!(
            evidence.validate_against_artifacts(
                &plan,
                b"model-artifact-substituted",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                &proposal_output(&plan),
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
            ),
            Err(AiProposalBindingError::ArtifactDigestMismatch("model artifact"))
        );

        let mut tampered = evidence.clone();
        tampered.input_digest = [99; 32];
        assert_eq!(
            tampered.validate_against_artifacts(
                &plan,
                b"model-artifact-v1",
                b"canonical-input-v1",
                b"canonical-policy-v1",
                &proposal_output(&plan),
                b"verifier-artifact-v1",
                b"canonical-evaluation-evidence-v1",
            ),
            Err(AiProposalBindingError::ArtifactDigestMismatch("input"))
        );
    }

    #[test]
    fn required_artifact_bytes_cannot_be_omitted() {
        let plan = plan("machine-a");
        let result = AiProposalBinding::new(
            &plan,
            b"",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &proposal_output(&plan),
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        );

        assert_eq!(
            result,
            Err(AiProposalBindingError::EmptyArtifactBytes("model artifact"))
        );
    }

    #[test]
    fn artifact_digest_is_bound_to_role_and_exact_bytes() {
        let model = digest_artifact(ProposalArtifactKind::ModelArtifact, b"model-v1");
        assert_eq!(
            model,
            digest_artifact(ProposalArtifactKind::ModelArtifact, b"model-v1")
        );
        assert_ne!(
            model,
            digest_artifact(ProposalArtifactKind::ModelArtifact, b"model-v2")
        );
        assert_ne!(
            model,
            digest_artifact(ProposalArtifactKind::Input, b"model-v1")
        );
    }

    #[test]
    fn unknown_fields_are_rejected_on_deserialization() {
        let plan = plan("machine-a");
        let encoded = serde_json::to_string(&binding(&plan)).unwrap();
        let with_unknown = encoded.trim_end_matches('}').to_owned() + ",\"unexpected\":true}";
        assert!(serde_json::from_str::<AiProposalBinding>(&with_unknown).is_err());
    }

    #[test]
    fn validation_evidence_envelope_round_trips_and_binds_components() {
        let plan = plan("machine-a");
        let proposal = binding(&plan);
        let original =
            AiProposalValidationEvidence::new(&plan, [21; 32], &proposal).unwrap();
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: AiProposalValidationEvidence = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, original);
        assert!(decoded.validate_for(&plan, &proposal).is_ok());
        assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());

        let mut changed_validation = decoded.clone();
        changed_validation.validation_evidence_digest = [99; 32];
        assert_ne!(
            decoded.digest().unwrap(),
            changed_validation.digest().unwrap()
        );
    }

    #[test]
    fn validation_evidence_envelope_rejects_mismatched_proposal_at_construction() {
        let plan = plan("machine-a");
        let other_plan = plan("machine-b");
        let other_proposal = binding(&other_plan);
        assert_eq!(
            AiProposalValidationEvidence::new(&plan, [21; 32], &other_proposal),
            Err(AiProposalBindingError::PlanBindingMismatch)
        );
    }

    #[test]
    fn validation_evidence_envelope_rejects_plan_and_proposal_substitution() {
        let plan = plan("machine-a");
        let other_plan = plan("machine-b");
        let proposal = binding(&plan);
        let evidence =
            AiProposalValidationEvidence::new(&plan, [21; 32], &proposal).unwrap();

        assert_eq!(
            evidence.validate_for(&other_plan, &proposal),
            Err(AiProposalBindingError::PlanBindingMismatch)
        );

        let mut different_proposal = proposal.clone();
        different_proposal.policy_digest = [77; 32];
        assert_eq!(
            evidence.validate_for(&plan, &different_proposal),
            Err(AiProposalBindingError::ProposalBindingMismatch)
        );
    }

    #[test]
    fn digest_fields_reject_uppercase_and_wrong_length_hex() {
        let plan = plan("machine-a");
        let mut uppercase = serde_json::to_value(binding(&plan)).unwrap();
        uppercase["plan_digest"] = serde_json::json!("AA".repeat(32));
        assert!(serde_json::from_value::<AiProposalBinding>(uppercase).is_err());

        let mut short = serde_json::to_value(binding(&plan)).unwrap();
        short["plan_digest"] = serde_json::json!("abcd");
        assert!(serde_json::from_value::<AiProposalBinding>(short).is_err());
    }

    #[test]
    fn validation_evidence_fixture_uses_lowercase_hex_digests() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/ai-proposal-validation-evidence-v1.json"
        ));
        let parsed: AiProposalValidationEvidence = serde_json::from_str(raw).unwrap();
        let encoded = serde_json::to_value(&parsed).unwrap();

        assert_eq!(
            parsed.schema_version(),
            AI_PROPOSAL_VALIDATION_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(encoded["plan_digest"].as_str().unwrap().len(), 64);
        assert_eq!(
            encoded["validation_evidence_digest"].as_str().unwrap().len(),
            64
        );
        assert_eq!(encoded["proposal_binding_digest"].as_str().unwrap().len(), 64);
        assert!(parsed.digest().is_ok());
    }

    #[test]
    fn unsupported_schema_version_is_rejected_after_deserialization() {
        let plan = plan("machine-a");
        let evidence = binding(&plan);
        let unsupported_version = AI_PROPOSAL_BINDING_SCHEMA_VERSION + 1;
        let mut value = serde_json::to_value(evidence).unwrap();
        value["schema_version"] = serde_json::json!(unsupported_version);
        let decoded: AiProposalBinding = serde_json::from_value(value).unwrap();

        assert_eq!(
            decoded.validate_for_plan(&plan),
            Err(AiProposalBindingError::UnsupportedSchemaVersion(
                unsupported_version
            ))
        );
    }
}
