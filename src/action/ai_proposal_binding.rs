// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

//! Provenance binding between an AI proposal and one exact Nixward ChangePlan.
//!
//! This module binds content digests and validates the structured, canonical
//! proposal intent against one exact ChangePlan. It does not verify an AI proof,
//! assert that inputs are true, decide whether a policy is appropriate, or prove
//! that free-form model text was faithfully converted to that intent. Callers
//! must independently validate that conversion and referenced artifacts/evidence,
//! then use the existing ChangeAuthorization and enforcement path for privileged
//! actions. A binding from another plan must never be reused for this plan.

use super::change_covenant::{ChangePlan, MachineBinding};
use super::config_writer::ConfigPatch;
use super::executor::NixOSCommand;
use crate::release_integrity::{verify_release_tree, SignedReleaseManifest};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const AI_PROPOSAL_BINDING_SCHEMA_VERSION: u16 = 1;
pub const AI_PROPOSAL_OUTPUT_SCHEMA_VERSION: u16 = 1;
const MAX_AI_PROPOSAL_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const AI_PROPOSAL_RESOLUTION_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const AI_PROPOSAL_JSON_RESOLVER_ID: &str = "nixward.ai-proposal-json-resolver";
pub const AI_PROPOSAL_JSON_RESOLVER_VERSION: u16 = 1;
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
    RawModelOutput,
    ResolverSource,
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
            Self::RawModelOutput => b"raw-model-output",
            Self::ResolverSource => b"resolver-source",
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
    #[error("AI proposal output exceeds size limit ({actual} bytes, max {max} bytes)")]
    ProposalOutputTooLarge { actual: usize, max: usize },
    #[error("AI proposal output intent does not exactly match the ChangePlan")]
    ProposalOutputPlanMismatch,
    #[error("unsupported AI proposal resolution receipt schema version: {0}")]
    UnsupportedResolutionReceiptSchemaVersion(u16),
    #[error("AI proposal resolution receipt does not match the supplied raw response, resolver source, output, or plan")]
    ResolutionReceiptMismatch,
    #[error("unsupported AI proposal resolved validation evidence schema version: {0}")]
    UnsupportedResolvedValidationEvidenceSchemaVersion(u16),
    #[error("resolver runtime verification failed: {0}")]
    ResolverRuntimeVerification(String),
    #[error("resolver runtime verification requires Linux /proc/self/exe")]
    ResolverRuntimeUnsupportedPlatform,
    #[error("resolved validation evidence does not match the verified runtime binding")]
    ResolverRuntimeBindingMismatch,
    #[error("unsupported runtime-verified validation evidence schema version: {0}")]
    UnsupportedRuntimeValidationEvidenceSchemaVersion(u16),
}


impl AiProposalOutputIntent {
    /// Build a structured proposal output from typed intent components.
    pub fn new(
        machine: &MachineBinding,
        config_patch: Option<&ConfigPatch>,
        command: Option<&NixOSCommand>,
    ) -> Result<Self, AiProposalBindingError> {
        let config_patch = config_patch
            .map(|patch| -> Result<AiProposalOutputConfigPatch, AiProposalBindingError> {
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
        if bytes.len() > MAX_AI_PROPOSAL_OUTPUT_BYTES {
            return Err(AiProposalBindingError::ProposalOutputTooLarge {
                actual: bytes.len(),
                max: MAX_AI_PROPOSAL_OUTPUT_BYTES,
            });
        }
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

    /// Parse a model/provider JSON response while rejecting data the schema
    /// would otherwise silently discard. Formatting and key order may vary here;
    /// the returned value must be serialized with canonical_bytes before hashing.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, AiProposalBindingError> {
        if bytes.len() > MAX_AI_PROPOSAL_OUTPUT_BYTES {
            return Err(AiProposalBindingError::ProposalOutputTooLarge {
                actual: bytes.len(),
                max: MAX_AI_PROPOSAL_OUTPUT_BYTES,
            });
        }
        if bytes.is_empty() {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "JSON output bytes must not be empty".into(),
            ));
        }
        let intent: Self = serde_json::from_slice(bytes).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!("invalid JSON: {error}"))
        })?;
        intent.validate_shape()?;
        let supplied_value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!("invalid JSON: {error}"))
        })?;
        let represented_value = serde_json::to_value(&intent).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!(
                "schema-v1 JSON encoding failed: {error}"
            ))
        })?;
        if supplied_value != represented_value {
            return Err(AiProposalBindingError::InvalidProposalOutput(
                "JSON contains fields or data not represented by schema v1".into(),
            ));
        }
        Ok(intent)
    }

    /// Serialize the canonical schema-v1 output bytes that are digest-bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AiProposalBindingError> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|error| {
            AiProposalBindingError::InvalidProposalOutput(format!(
                "canonical JSON encoding failed: {error}"
            ))
        })?;
        if bytes.len() > MAX_AI_PROPOSAL_OUTPUT_BYTES {
            return Err(AiProposalBindingError::ProposalOutputTooLarge {
                actual: bytes.len(),
                max: MAX_AI_PROPOSAL_OUTPUT_BYTES,
            });
        }
        Ok(bytes)
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
            target: PathBuf::from(patch.target.as_str()),
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

/// Content-addressed receipt linking raw provider JSON to the canonical intent
/// and exact plan produced by this resolver implementation.
///
/// The resolver source digest is computed from the source file embedded into
/// this build. This is a source identity, not an attestation that the executing
/// binary is untampered or that a deployment actually ran this resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalResolutionReceipt {
    schema_version: u16,
    resolver_id: String,
    resolver_version: u16,
    #[serde(with = "serde_hex_32")]
    plan_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    raw_model_output_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    resolver_source_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    canonical_intent_digest: [u8; 32],
}

const AI_PROPOSAL_RESOLUTION_DOMAIN: &[u8] =
    b"nixward-ai-proposal-resolution-receipt-v1\0";

fn embedded_resolver_source_digest() -> [u8; 32] {
    digest_artifact(
        ProposalArtifactKind::ResolverSource,
        include_bytes!("ai_proposal_binding.rs"),
    )
}

impl AiProposalResolutionReceipt {
    /// Run the built-in strict JSON resolver over the raw provider response.
    ///
    /// The raw model-output JSON payload is hashed before parsing; this is the
    /// model-produced content, not its surrounding provider HTTP/API envelope.
    /// Successful parsing is normalized to the exact canonical schema-v1 intent
    /// and checked against the provided ChangePlan. Free-form natural-language
    /// responses are intentionally not interpreted by this resolver.
    pub fn resolve_provider_json(
        plan: &ChangePlan,
        raw_model_output_bytes: &[u8],
    ) -> Result<(Self, Vec<u8>), AiProposalBindingError> {
        if raw_model_output_bytes.is_empty() {
            return Err(AiProposalBindingError::EmptyArtifactBytes(
                "raw model output",
            ));
        }

        let intent = AiProposalOutputIntent::from_json_bytes(raw_model_output_bytes)?;
        intent.validate_for_plan(plan)?;
        let canonical_intent_bytes = intent.canonical_bytes()?;
        let receipt = Self {
            schema_version: AI_PROPOSAL_RESOLUTION_RECEIPT_SCHEMA_VERSION,
            resolver_id: AI_PROPOSAL_JSON_RESOLVER_ID.to_string(),
            resolver_version: AI_PROPOSAL_JSON_RESOLVER_VERSION,
            plan_digest: plan.digest(),
            raw_model_output_digest: digest_artifact(
                ProposalArtifactKind::RawModelOutput,
                raw_model_output_bytes,
            ),
            resolver_source_digest: embedded_resolver_source_digest(),
            canonical_intent_digest: digest_artifact(
                ProposalArtifactKind::ProposalOutput,
                &canonical_intent_bytes,
            ),
        };
        receipt.validate_for_plan(plan)?;
        Ok((receipt, canonical_intent_bytes))
    }

    /// Re-run resolution and reject substitutions in any linked byte sequence.
    pub fn validate_against_artifacts(
        &self,
        plan: &ChangePlan,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
    ) -> Result<(), AiProposalBindingError> {
        self.validate_for_plan(plan)?;
        let (recomputed, recomputed_intent) =
            Self::resolve_provider_json(plan, raw_model_output_bytes)?;
        if &recomputed != self || recomputed_intent.as_slice() != canonical_intent_bytes {
            return Err(AiProposalBindingError::ResolutionReceiptMismatch);
        }
        Ok(())
    }

    pub fn validate_for_plan(&self, plan: &ChangePlan) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        if self.plan_digest != plan.digest()
            || self.resolver_source_digest != embedded_resolver_source_digest()
        {
            return Err(AiProposalBindingError::ResolutionReceiptMismatch);
        }
        Ok(())
    }

    /// Verify this receipt against a signed release tree and the current process.
    ///
    /// The trusted key must come from an independently provisioned release-root
    /// policy; the key embedded in the manifest is never accepted as its own root.
    /// Linux /proc/self/exe is hashed to bind the check to the executable file
    /// backing this process, subject to the integrity of the running OS/kernel.
    pub fn verify_current_runtime(
        &self,
        root: &Path,
        signed_release: &SignedReleaseManifest,
        trusted_release_public_key_hex: &str,
        plan: &ChangePlan,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
        resolver_source_relative_path: &str,
    ) -> Result<VerifiedResolverRuntimeBinding, AiProposalBindingError> {
        self.validate_against_artifacts(plan, raw_model_output_bytes, canonical_intent_bytes)
            .map_err(|error| AiProposalBindingError::ResolverRuntimeVerification(error.to_string()))?;

        #[cfg(target_os = "linux")]
        {
            let exe_link = Path::new("/proc/self/exe");
            let runtime_path = std::fs::read_link(exe_link).map_err(|error| {
                AiProposalBindingError::ResolverRuntimeVerification(format!(
                    "cannot resolve /proc/self/exe: {error}"
                ))
            })?;
            if runtime_path.to_string_lossy().ends_with(" (deleted)") {
                return Err(AiProposalBindingError::ResolverRuntimeVerification(
                    "current executable has been unlinked or replaced".into(),
                ));
            }
            let runtime_path = runtime_path.canonicalize().map_err(|error| {
                AiProposalBindingError::ResolverRuntimeVerification(format!(
                    "cannot canonicalize current executable: {error}"
                ))
            })?;
            let runtime_bytes = std::fs::read(exe_link).map_err(|error| {
                AiProposalBindingError::ResolverRuntimeVerification(format!(
                    "cannot read current executable bytes: {error}"
                ))
            })?;
            verify_runtime_binding_from_bundle(
                root,
                signed_release,
                trusted_release_public_key_hex,
                &runtime_path,
                &runtime_bytes,
                resolver_source_relative_path,
                plan,
                self,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                root,
                signed_release,
                trusted_release_public_key_hex,
                plan,
                raw_model_output_bytes,
                canonical_intent_bytes,
                resolver_source_relative_path,
            );
            Err(AiProposalBindingError::ResolverRuntimeUnsupportedPlatform)
        }
    }

    /// Stable digest to join this receipt into a resolved validation envelope.
    pub fn digest(&self) -> Result<[u8; 32], AiProposalBindingError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_PROPOSAL_RESOLUTION_DOMAIN);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&(self.resolver_id.len() as u64).to_le_bytes());
        hasher.update(self.resolver_id.as_bytes());
        hasher.update(&self.resolver_version.to_le_bytes());
        hasher.update(&self.plan_digest);
        hasher.update(&self.raw_model_output_digest);
        hasher.update(&self.resolver_source_digest);
        hasher.update(&self.canonical_intent_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn resolver_id(&self) -> &str {
        &self.resolver_id
    }

    pub fn resolver_version(&self) -> u16 {
        self.resolver_version
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn raw_model_output_digest(&self) -> [u8; 32] {
        self.raw_model_output_digest
    }

    pub fn resolver_source_digest(&self) -> [u8; 32] {
        self.resolver_source_digest
    }

    pub fn canonical_intent_digest(&self) -> [u8; 32] {
        self.canonical_intent_digest
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_RESOLUTION_RECEIPT_SCHEMA_VERSION {
            return Err(
                AiProposalBindingError::UnsupportedResolutionReceiptSchemaVersion(
                    self.schema_version,
                ),
            );
        }
        if self.resolver_id != AI_PROPOSAL_JSON_RESOLVER_ID
            || self.resolver_version != AI_PROPOSAL_JSON_RESOLVER_VERSION
        {
            return Err(AiProposalBindingError::ResolutionReceiptMismatch);
        }
        for (name, digest) in [
            ("resolution plan", &self.plan_digest),
            ("raw model output", &self.raw_model_output_digest),
            ("resolver source", &self.resolver_source_digest),
            ("canonical intent", &self.canonical_intent_digest),
        ] {
            if *digest == [0; 32] {
                return Err(AiProposalBindingError::MissingDigest(name));
            }
        }
        Ok(())
    }
}

impl AiProposalBinding {
    /// Bind AI provenance to the exact, already-constructed ChangePlan.
    ///
    /// Proposal-output bytes must be a canonical AiProposalOutputIntent v1 and
    /// the embedded machine/config/command intent must match this plan. This is
    /// not a proof verifier: other artifact meaning, input truth, policy quality,
    /// evaluation validity, and upstream parsing fidelity remain separate checks.
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
    /// when the binding was created. Besides checking byte-to-digest correspondence,
    /// this checks the structured proposal intent against the exact plan. It does
    /// not verify truth, safety, cryptographic validity, or upstream parsing fidelity.
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


const AI_RESOLVER_RUNTIME_BINDING_DOMAIN: &[u8] =
    b"nixward-ai-resolver-runtime-binding-v1\0";

fn require_safe_release_relative_path(path: &str) -> Result<(), AiProposalBindingError> {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AiProposalBindingError::ResolverRuntimeVerification(
            format!("unsafe release-relative artifact path: {path}"),
        ));
    }
    Ok(())
}

fn verify_runtime_binding_from_bundle(
    root: &Path,
    signed_release: &SignedReleaseManifest,
    trusted_release_public_key_hex: &str,
    runtime_executable_path: &Path,
    runtime_executable_bytes: &[u8],
    resolver_source_relative_path: &str,
    plan: &ChangePlan,
    resolution: &AiProposalResolutionReceipt,
) -> Result<VerifiedResolverRuntimeBinding, AiProposalBindingError> {
    require_safe_release_relative_path(resolver_source_relative_path)?;

    let canonical_root = root.canonicalize().map_err(|error| {
        AiProposalBindingError::ResolverRuntimeVerification(format!(
            "cannot canonicalize signed release root: {error}"
        ))
    })?;
    let canonical_executable = runtime_executable_path.canonicalize().map_err(|error| {
        AiProposalBindingError::ResolverRuntimeVerification(format!(
            "cannot canonicalize running executable: {error}"
        ))
    })?;
    let runtime_relative = canonical_executable
        .strip_prefix(&canonical_root)
        .map_err(|_| {
            AiProposalBindingError::ResolverRuntimeVerification(
                "running executable is outside the signed release root".into(),
            )
        })?
        .to_str()
        .ok_or_else(|| {
            AiProposalBindingError::ResolverRuntimeVerification(
                "running executable path is not UTF-8".into(),
            )
        })?
        .replace('\\', "/");
    require_safe_release_relative_path(&runtime_relative)?;
    if runtime_relative == resolver_source_relative_path {
        return Err(AiProposalBindingError::ResolverRuntimeVerification(
            "runtime executable and resolver source paths must be distinct".into(),
        ));
    }

    let verified = verify_release_tree(root, signed_release, trusted_release_public_key_hex)
        .map_err(|error| {
            AiProposalBindingError::ResolverRuntimeVerification(format!(
                "signed release verification failed: {error}"
            ))
        })?;
    let source_artifact = signed_release
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == resolver_source_relative_path)
        .ok_or_else(|| {
            AiProposalBindingError::ResolverRuntimeVerification(
                "signed release manifest omits the resolver source artifact".into(),
            )
        })?;
    let executable_artifact = signed_release
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == runtime_relative)
        .ok_or_else(|| {
            AiProposalBindingError::ResolverRuntimeVerification(
                "signed release manifest omits the current executable".into(),
            )
        })?;

    let actual_executable_digest = blake3::hash(runtime_executable_bytes).to_hex().to_string();
    if runtime_executable_bytes.len() as u64 != executable_artifact.size_bytes
        || actual_executable_digest != executable_artifact.blake3.to_ascii_lowercase()
    {
        return Err(AiProposalBindingError::ResolverRuntimeVerification(
            "running executable bytes differ from the signed release manifest".into(),
        ));
    }

    let resolver_source_bytes = std::fs::read(canonical_root.join(resolver_source_relative_path))
        .map_err(|error| {
            AiProposalBindingError::ResolverRuntimeVerification(format!(
                "cannot read signed resolver source artifact: {error}"
            ))
        })?;
    let source_digest = digest_artifact(ProposalArtifactKind::ResolverSource, &resolver_source_bytes);
    if source_digest != resolution.resolver_source_digest() {
        return Err(AiProposalBindingError::ResolverRuntimeVerification(
            "signed resolver source differs from the source embedded in the resolver receipt"
                .into(),
        ));
    }

    Ok(VerifiedResolverRuntimeBinding {
        release_id: verified.release_id,
        release_manifest_digest: verified.manifest_blake3,
        release_source_revision: signed_release.manifest.source_revision.clone(),
        release_signer_public_key_hex: verified.signer_public_key_hex,
        runtime_binary_relative_path: runtime_relative,
        runtime_binary_digest: *blake3::hash(runtime_executable_bytes).as_bytes(),
        resolver_source_relative_path: source_artifact.path.clone(),
        resolver_source_digest: source_digest,
        plan_digest: plan.digest(),
        resolution_receipt_digest: resolution.digest()?,
    })
}

/// An opaque, in-memory result of checking the current executable against a
/// release manifest signed by a separately trusted release root.
///
/// This type deliberately does not implement Deserialize: a JSON claim cannot
/// manufacture verified runtime evidence. It is software-level evidence under
/// the running OS/kernel trust assumption, not TPM/measured-boot attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedResolverRuntimeBinding {
    release_id: String,
    release_manifest_digest: String,
    release_source_revision: String,
    release_signer_public_key_hex: String,
    runtime_binary_relative_path: String,
    runtime_binary_digest: [u8; 32],
    resolver_source_relative_path: String,
    resolver_source_digest: [u8; 32],
    plan_digest: [u8; 32],
    resolution_receipt_digest: [u8; 32],
}

impl VerifiedResolverRuntimeBinding {
    pub fn digest(&self) -> [u8; 32] {
        fn push(hasher: &mut blake3::Hasher, value: &str) {
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_RESOLVER_RUNTIME_BINDING_DOMAIN);
        push(&mut hasher, &self.release_id);
        push(&mut hasher, &self.release_manifest_digest);
        push(&mut hasher, &self.release_source_revision);
        push(&mut hasher, &self.release_signer_public_key_hex);
        push(&mut hasher, &self.runtime_binary_relative_path);
        hasher.update(&self.runtime_binary_digest);
        push(&mut hasher, &self.resolver_source_relative_path);
        hasher.update(&self.resolver_source_digest);
        hasher.update(&self.plan_digest);
        hasher.update(&self.resolution_receipt_digest);
        *hasher.finalize().as_bytes()
    }

    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    pub fn release_manifest_digest(&self) -> &str {
        &self.release_manifest_digest
    }

    pub fn release_source_revision(&self) -> &str {
        &self.release_source_revision
    }

    pub fn release_signer_public_key_hex(&self) -> &str {
        &self.release_signer_public_key_hex
    }

    pub fn runtime_binary_relative_path(&self) -> &str {
        &self.runtime_binary_relative_path
    }

    pub fn runtime_binary_digest(&self) -> [u8; 32] {
        self.runtime_binary_digest
    }

    pub fn resolver_source_relative_path(&self) -> &str {
        &self.resolver_source_relative_path
    }

    pub fn resolver_source_digest(&self) -> [u8; 32] {
        self.resolver_source_digest
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn resolution_receipt_digest(&self) -> [u8; 32] {
        self.resolution_receipt_digest
    }
}

/// Validation envelope for a proposal whose raw provider response was resolved
/// by the built-in JSON resolver and linked to a plan.
///
/// Persist this envelope with the referenced AiProposalResolutionReceipt,
/// AiProposalBinding, raw response, canonical intent, and ordinary validation
/// evidence. Its digest can occupy the existing ValidationReceipt digest slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalResolvedValidationEvidence {
    schema_version: u16,
    #[serde(with = "serde_hex_32")]
    plan_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    validation_evidence_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    proposal_binding_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    resolution_receipt_digest: [u8; 32],
}

const AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_DOMAIN: &[u8] =
    b"nixward-ai-proposal-resolved-validation-evidence-v1\0";

impl AiProposalResolvedValidationEvidence {
    pub fn new(
        plan: &ChangePlan,
        validation_evidence_digest: [u8; 32],
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
    ) -> Result<Self, AiProposalBindingError> {
        proposal.validate_for_plan(plan)?;
        resolution.validate_against_artifacts(
            plan,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )?;
        if proposal.proposal_output_digest()
            != digest_artifact(ProposalArtifactKind::ProposalOutput, canonical_intent_bytes)
        {
            return Err(AiProposalBindingError::ArtifactDigestMismatch("proposal output"));
        }
        if validation_evidence_digest == [0; 32] {
            return Err(AiProposalBindingError::MissingDigest("validation evidence"));
        }
        let evidence = Self {
            schema_version: AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_SCHEMA_VERSION,
            plan_digest: plan.digest(),
            validation_evidence_digest,
            proposal_binding_digest: proposal.digest()?,
            resolution_receipt_digest: resolution.digest()?,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    /// Check that the persisted evidence envelope joins these exact components.
    ///
    /// The resolution receipt must separately be checked against raw response and
    /// canonical intent bytes using AiProposalResolutionReceipt::validate_against_artifacts.
    pub fn validate_for(
        &self,
        plan: &ChangePlan,
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
    ) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        if self.plan_digest != plan.digest() {
            return Err(AiProposalBindingError::PlanBindingMismatch);
        }
        proposal.validate_for_plan(plan)?;
        resolution.validate_against_artifacts(
            plan,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )?;
        if proposal.proposal_output_digest()
            != digest_artifact(ProposalArtifactKind::ProposalOutput, canonical_intent_bytes)
        {
            return Err(AiProposalBindingError::ArtifactDigestMismatch("proposal output"));
        }
        if self.proposal_binding_digest != proposal.digest()? {
            return Err(AiProposalBindingError::ProposalBindingMismatch);
        }
        if self.resolution_receipt_digest != resolution.digest()? {
            return Err(AiProposalBindingError::ResolutionReceiptMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], AiProposalBindingError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_DOMAIN);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.plan_digest);
        hasher.update(&self.validation_evidence_digest);
        hasher.update(&self.proposal_binding_digest);
        hasher.update(&self.resolution_receipt_digest);
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

    pub fn resolution_receipt_digest(&self) -> [u8; 32] {
        self.resolution_receipt_digest
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_SCHEMA_VERSION {
            return Err(
                AiProposalBindingError::UnsupportedResolvedValidationEvidenceSchemaVersion(
                    self.schema_version,
                ),
            );
        }
        for (name, digest) in [
            ("resolved plan", &self.plan_digest),
            ("resolved validation evidence", &self.validation_evidence_digest),
            ("resolved proposal binding", &self.proposal_binding_digest),
            ("resolution receipt", &self.resolution_receipt_digest),
        ] {
            if *digest == [0; 32] {
                return Err(AiProposalBindingError::MissingDigest(name));
            }
        }
        Ok(())
    }
}

/// Validation evidence that joins resolved model output to the signed release
/// and the executable bytes backing the current process.
///
/// Unlike the resolution receipt, this envelope requires an opaque
/// VerifiedResolverRuntimeBinding produced by live release-tree verification.
/// It is not deserializable into a trusted runtime token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiProposalRuntimeVerifiedValidationEvidence {
    schema_version: u16,
    #[serde(with = "serde_hex_32")]
    plan_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    resolved_validation_evidence_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    runtime_binding_digest: [u8; 32],
    #[serde(with = "serde_hex_32")]
    resolution_receipt_digest: [u8; 32],
}

const AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_DOMAIN: &[u8] =
    b"nixward-ai-proposal-runtime-verified-validation-evidence-v1\0";

impl AiProposalRuntimeVerifiedValidationEvidence {
    pub fn new(
        plan: &ChangePlan,
        resolved: &AiProposalResolvedValidationEvidence,
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        runtime: &VerifiedResolverRuntimeBinding,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
    ) -> Result<Self, AiProposalBindingError> {
        resolved.validate_for(
            plan,
            proposal,
            resolution,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )?;
        if runtime.plan_digest() != plan.digest()
            || runtime.resolution_receipt_digest() != resolution.digest()?
            || runtime.resolver_source_digest() != resolution.resolver_source_digest()
            || resolved.resolution_receipt_digest() != resolution.digest()?
        {
            return Err(AiProposalBindingError::ResolverRuntimeBindingMismatch);
        }
        let evidence = Self {
            schema_version: AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_SCHEMA_VERSION,
            plan_digest: plan.digest(),
            resolved_validation_evidence_digest: resolved.digest()?,
            runtime_binding_digest: runtime.digest(),
            resolution_receipt_digest: resolution.digest()?,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    pub fn validate_for(
        &self,
        plan: &ChangePlan,
        resolved: &AiProposalResolvedValidationEvidence,
        proposal: &AiProposalBinding,
        resolution: &AiProposalResolutionReceipt,
        runtime: &VerifiedResolverRuntimeBinding,
        raw_model_output_bytes: &[u8],
        canonical_intent_bytes: &[u8],
    ) -> Result<(), AiProposalBindingError> {
        self.validate_shape()?;
        resolved.validate_for(
            plan,
            proposal,
            resolution,
            raw_model_output_bytes,
            canonical_intent_bytes,
        )?;
        if self.plan_digest != plan.digest() {
            return Err(AiProposalBindingError::PlanBindingMismatch);
        }
        if runtime.plan_digest() != plan.digest()
            || runtime.resolution_receipt_digest() != resolution.digest()?
            || runtime.resolver_source_digest() != resolution.resolver_source_digest()
            || resolved.resolution_receipt_digest() != resolution.digest()?
        {
            return Err(AiProposalBindingError::ResolverRuntimeBindingMismatch);
        }
        if self.resolved_validation_evidence_digest != resolved.digest()?
            || self.runtime_binding_digest != runtime.digest()
            || self.resolution_receipt_digest != resolution.digest()?
        {
            return Err(AiProposalBindingError::ResolverRuntimeBindingMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], AiProposalBindingError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_DOMAIN);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.plan_digest);
        hasher.update(&self.resolved_validation_evidence_digest);
        hasher.update(&self.runtime_binding_digest);
        hasher.update(&self.resolution_receipt_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn resolved_validation_evidence_digest(&self) -> [u8; 32] {
        self.resolved_validation_evidence_digest
    }

    pub fn runtime_binding_digest(&self) -> [u8; 32] {
        self.runtime_binding_digest
    }

    pub fn resolution_receipt_digest(&self) -> [u8; 32] {
        self.resolution_receipt_digest
    }

    fn validate_shape(&self) -> Result<(), AiProposalBindingError> {
        if self.schema_version != AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_SCHEMA_VERSION {
            return Err(
                AiProposalBindingError::UnsupportedRuntimeValidationEvidenceSchemaVersion(
                    self.schema_version,
                ),
            );
        }
        for (name, digest) in [
            ("runtime-verified plan", &self.plan_digest),
            (
                "resolved validation evidence",
                &self.resolved_validation_evidence_digest,
            ),
            ("runtime binding", &self.runtime_binding_digest),
            ("runtime resolution receipt", &self.resolution_receipt_digest),
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
    use crate::release_integrity::{
        RELEASE_MANIFEST_KIND, RELEASE_SCHEMA_VERSION, RELEASE_SIGNATURE_KIND, ReleaseArtifact,
        ReleaseManifest,
    };
    use ed25519_dalek::{Signer, SigningKey};

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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn signed_runtime_bundle(
        root: &Path,
        resolver_source_relative_path: &str,
        runtime_binary_relative_path: &str,
        source_bytes: &[u8],
        runtime_binary_bytes: &[u8],
        signing: &SigningKey,
    ) -> SignedReleaseManifest {
        let source_path = root.join(resolver_source_relative_path);
        let binary_path = root.join(runtime_binary_relative_path);
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(binary_path.parent().unwrap()).unwrap();
        std::fs::write(&source_path, source_bytes).unwrap();
        std::fs::write(&binary_path, runtime_binary_bytes).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&binary_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&binary_path, permissions).unwrap();
        }

        let artifacts = vec![
            ReleaseArtifact {
                path: resolver_source_relative_path.into(),
                blake3: blake3::hash(source_bytes).to_hex().to_string(),
                size_bytes: source_bytes.len() as u64,
                executable: false,
            },
            ReleaseArtifact {
                path: runtime_binary_relative_path.into(),
                blake3: blake3::hash(runtime_binary_bytes).to_hex().to_string(),
                size_bytes: runtime_binary_bytes.len() as u64,
                executable: true,
            },
        ];
        let manifest = ReleaseManifest {
            schema_version: RELEASE_SCHEMA_VERSION,
            kind: RELEASE_MANIFEST_KIND.into(),
            release_id: "nixward-runtime-binding-test".into(),
            created_at_ms: 1_800_000_000_000,
            source_revision: "test-commit-revision".into(),
            artifacts,
        };
        let signature = signing.sign(&manifest.signing_bytes().unwrap());
        SignedReleaseManifest {
            kind: RELEASE_SIGNATURE_KIND.into(),
            algorithm: "ed25519".into(),
            signer_public_key_hex: hex(signing.verifying_key().as_bytes()),
            signature_hex: hex(&signature.to_bytes()),
            manifest,
        }
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
    fn oversized_provider_json_is_rejected_before_parsing() {
        let oversized = vec![b' '; MAX_AI_PROPOSAL_OUTPUT_BYTES + 1];
        assert!(matches!(
            AiProposalOutputIntent::from_json_bytes(&oversized),
            Err(AiProposalBindingError::ProposalOutputTooLarge {
                actual,
                max,
            }) if actual == MAX_AI_PROPOSAL_OUTPUT_BYTES + 1
                && max == MAX_AI_PROPOSAL_OUTPUT_BYTES
        ));
        assert!(matches!(
            AiProposalOutputIntent::from_canonical_bytes(&oversized),
            Err(AiProposalBindingError::ProposalOutputTooLarge {
                actual,
                max,
            }) if actual == MAX_AI_PROPOSAL_OUTPUT_BYTES + 1
                && max == MAX_AI_PROPOSAL_OUTPUT_BYTES
        ));
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
        let parsed_pretty = AiProposalOutputIntent::from_json_bytes(&pretty).unwrap();
        assert_eq!(parsed_pretty.canonical_bytes().unwrap(), encoded);

        let non_schema_field =
            String::from_utf8(encoded.clone()).unwrap().replace(
                "\"json\":true",
                "\"json\":true,\"untrusted_extra\":1",
            );
        assert!(AiProposalOutputIntent::from_json_bytes(non_schema_field.as_bytes()).is_err());
    }

    #[test]
    fn binding_constructor_rejects_structured_output_for_another_command() {
        let plan = plan("machine-a");
        let wrong_command = NixOSCommand::Search {
            query: "nixpkgs#different".into(),
            json: true,
        };
        let output = AiProposalOutputIntent::new(
            plan.machine(),
            None,
            Some(&wrong_command),
        )
        .unwrap()
        .canonical_bytes()
        .unwrap();

        let result = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &output,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        );
        assert_eq!(
            result,
            Err(AiProposalBindingError::ProposalOutputPlanMismatch)
        );
    }

    #[test]
    fn structured_proposal_output_binds_exact_config_patch() {
        let machine = MachineBinding::new("machine-a").unwrap();
        let patch = crate::action::config_writer::ConfigPatch {
            target: PathBuf::from("/etc/nixos/configuration.nix"),
            original: "{ }".into(),
            modified: "{ services.openssh.enable = true; }".into(),
            description: "enable OpenSSH".into(),
        };
        let plan = ChangePlan::config_only(machine.clone(), &patch, 60_000).unwrap();
        let output = AiProposalOutputIntent::new(&machine, Some(&patch), None).unwrap();
        assert!(output.validate_for_plan(&plan).is_ok());

        let changed_patch = crate::action::config_writer::ConfigPatch {
            modified: "{ services.openssh.enable = false; }".into(),
            ..patch.clone()
        };
        let mismatched =
            AiProposalOutputIntent::new(&machine, Some(&changed_patch), None).unwrap();
        assert_eq!(
            mismatched.validate_for_plan(&plan),
            Err(AiProposalBindingError::ProposalOutputPlanMismatch)
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn signed_release_binding_checks_manifest_root_source_and_executable_bytes() {
        let plan = plan("machine-a");
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let raw = serde_json::to_vec_pretty(&intent).unwrap();
        let (receipt, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let source_path = "share/nixward/src/action/ai_proposal_binding.rs";
        let binary_path = "bin/nixward-daemon";
        let source_bytes = include_bytes!("ai_proposal_binding.rs");
        let binary_bytes = b"test-runtime-executable";
        let signing = SigningKey::from_bytes(&[71u8; 32]);
        let signed = signed_runtime_bundle(
            temp.path(),
            source_path,
            binary_path,
            source_bytes,
            binary_bytes,
            &signing,
        );

        let binding = verify_runtime_binding_from_bundle(
            temp.path(),
            &signed,
            &hex(signing.verifying_key().as_bytes()),
            &temp.path().join(binary_path),
            binary_bytes,
            source_path,
            &plan,
            &receipt,
        )
        .unwrap();

        assert_eq!(binding.release_id(), "nixward-runtime-binding-test");
        assert_eq!(binding.release_source_revision(), "test-commit-revision");
        assert_eq!(binding.runtime_binary_relative_path(), binary_path);
        assert_eq!(binding.resolver_source_relative_path(), source_path);
        assert_eq!(binding.plan_digest(), plan.digest());
        assert_eq!(binding.resolution_receipt_digest(), receipt.digest().unwrap());
        assert_eq!(binding.resolver_source_digest(), receipt.resolver_source_digest());
        assert_ne!(binding.digest(), [0; 32]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_binding_rejects_untrusted_root_and_changed_executable_bytes() {
        let plan = plan("machine-a");
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let raw = serde_json::to_vec_pretty(&intent).unwrap();
        let (receipt, _) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let source_path = "share/nixward/src/action/ai_proposal_binding.rs";
        let binary_path = "bin/nixward-daemon";
        let source_bytes = include_bytes!("ai_proposal_binding.rs");
        let binary_bytes = b"test-runtime-executable";
        let signing = SigningKey::from_bytes(&[72u8; 32]);
        let signed = signed_runtime_bundle(
            temp.path(),
            source_path,
            binary_path,
            source_bytes,
            binary_bytes,
            &signing,
        );

        let untrusted = SigningKey::from_bytes(&[73u8; 32]);
        assert!(matches!(
            verify_runtime_binding_from_bundle(
                temp.path(),
                &signed,
                &hex(untrusted.verifying_key().as_bytes()),
                &temp.path().join(binary_path),
                binary_bytes,
                source_path,
                &plan,
                &receipt,
            ),
            Err(AiProposalBindingError::ResolverRuntimeVerification(_))
        ));

        assert!(matches!(
            verify_runtime_binding_from_bundle(
                temp.path(),
                &signed,
                &hex(signing.verifying_key().as_bytes()),
                &temp.path().join(binary_path),
                b"tampered-runtime-executable",
                source_path,
                &plan,
                &receipt,
            ),
            Err(AiProposalBindingError::ResolverRuntimeVerification(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_binding_rejects_source_not_matching_embedded_resolver_digest() {
        let plan = plan("machine-a");
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let raw = serde_json::to_vec_pretty(&intent).unwrap();
        let (receipt, _) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let source_path = "share/nixward/src/action/ai_proposal_binding.rs";
        let binary_path = "bin/nixward-daemon";
        let mut source_bytes = include_bytes!("ai_proposal_binding.rs").to_vec();
        source_bytes.push(b'\n');
        let binary_bytes = b"test-runtime-executable";
        let signing = SigningKey::from_bytes(&[74u8; 32]);
        let signed = signed_runtime_bundle(
            temp.path(),
            source_path,
            binary_path,
            &source_bytes,
            binary_bytes,
            &signing,
        );

        assert!(matches!(
            verify_runtime_binding_from_bundle(
                temp.path(),
                &signed,
                &hex(signing.verifying_key().as_bytes()),
                &temp.path().join(binary_path),
                binary_bytes,
                source_path,
                &plan,
                &receipt,
            ),
            Err(AiProposalBindingError::ResolverRuntimeVerification(_))
        ));
    }

    #[test]
    fn resolution_receipt_links_raw_provider_json_to_canonical_intent_and_plan() {
        let plan = plan("machine-a");
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let raw = serde_json::to_vec_pretty(&intent).unwrap();
        let (receipt, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();

        assert_ne!(raw, canonical);
        assert_eq!(
            receipt.raw_model_output_digest(),
            digest_artifact(ProposalArtifactKind::RawModelOutput, &raw)
        );
        assert_eq!(
            receipt.canonical_intent_digest(),
            digest_artifact(ProposalArtifactKind::ProposalOutput, &canonical)
        );
        assert_eq!(receipt.plan_digest(), plan.digest());
        assert_eq!(receipt.resolver_id(), AI_PROPOSAL_JSON_RESOLVER_ID);
        assert_eq!(receipt.resolver_version(), AI_PROPOSAL_JSON_RESOLVER_VERSION);
        assert!(receipt.resolver_source_digest() != [0; 32]);
        assert!(receipt
            .validate_against_artifacts(&plan, &raw, &canonical)
            .is_ok());

        // Different raw bytes with identical meaning must not reuse the receipt.
        let mut altered_raw = raw.clone();
        altered_raw.push(b' ');
        assert_eq!(
            receipt.validate_against_artifacts(&plan, &altered_raw, &canonical),
            Err(AiProposalBindingError::ResolutionReceiptMismatch)
        );

        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: AiProposalResolutionReceipt = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.digest().unwrap(), receipt.digest().unwrap());
    }

    #[test]
    fn resolved_validation_evidence_joins_resolution_and_proposal_binding() {
        let plan = plan("machine-a");
        let intent = AiProposalOutputIntent::new(plan.machine(), None, plan.command()).unwrap();
        let raw = serde_json::to_vec_pretty(&intent).unwrap();
        let (resolution, canonical) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &raw).unwrap();
        let proposal = AiProposalBinding::new(
            &plan,
            b"model-artifact-v1",
            b"canonical-input-v1",
            b"canonical-policy-v1",
            &canonical,
            b"verifier-artifact-v1",
            b"canonical-evaluation-evidence-v1",
        )
        .unwrap();
        let evidence =
            AiProposalResolvedValidationEvidence::new(
                &plan,
                [21; 32],
                &proposal,
                &resolution,
                &raw,
                &canonical,
            )
            .unwrap();
        assert!(evidence.validate_for(&plan, &proposal, &resolution, &raw, &canonical).is_ok());

        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: AiProposalResolvedValidationEvidence =
            serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, evidence);
        assert_eq!(decoded.digest().unwrap(), evidence.digest().unwrap());

        let other_raw = serde_json::to_vec(&intent).unwrap();
        let (other_resolution, _) =
            AiProposalResolutionReceipt::resolve_provider_json(&plan, &other_raw).unwrap();
        assert_eq!(
            evidence.validate_for(&plan, &proposal, &other_resolution, &other_raw, &canonical),
            Err(AiProposalBindingError::ResolutionReceiptMismatch)
        );

        let mut mismatched_output_binding = proposal.clone();
        mismatched_output_binding.proposal_output_digest = [77; 32];
        assert_eq!(
            AiProposalResolvedValidationEvidence::new(
                &plan,
                [21; 32],
                &mismatched_output_binding,
                &resolution,
                &raw,
                &canonical,
            ),
            Err(AiProposalBindingError::ArtifactDigestMismatch("proposal output"))
        );
    }

    #[test]
    fn resolution_receipt_fixture_has_strict_hex_and_versioned_identity() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/ai-proposal-resolution-receipt-v1.json"
        ));
        let parsed: AiProposalResolutionReceipt = serde_json::from_str(raw).unwrap();
        assert_eq!(
            parsed.schema_version(),
            AI_PROPOSAL_RESOLUTION_RECEIPT_SCHEMA_VERSION
        );
        assert_eq!(parsed.resolver_id(), AI_PROPOSAL_JSON_RESOLVER_ID);
        assert_eq!(parsed.resolver_version(), AI_PROPOSAL_JSON_RESOLVER_VERSION);
        let encoded = serde_json::to_value(&parsed).unwrap();
        for field in [
            "plan_digest",
            "raw_model_output_digest",
            "resolver_source_digest",
            "canonical_intent_digest",
        ] {
            assert_eq!(encoded[field].as_str().unwrap().len(), 64);
        }
        assert!(parsed.digest().is_ok());
    }

    #[test]
    fn runtime_verified_validation_evidence_fixture_has_strict_hex_and_version() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/ai-proposal-runtime-verified-validation-evidence-v1.json"
        ));
        let parsed: AiProposalRuntimeVerifiedValidationEvidence =
            serde_json::from_str(raw).unwrap();
        assert_eq!(
            parsed.schema_version(),
            AI_PROPOSAL_RUNTIME_VALIDATION_EVIDENCE_SCHEMA_VERSION
        );
        let encoded = serde_json::to_value(&parsed).unwrap();
        for field in [
            "plan_digest",
            "resolved_validation_evidence_digest",
            "runtime_binding_digest",
            "resolution_receipt_digest",
        ] {
            assert_eq!(encoded[field].as_str().unwrap().len(), 64);
        }
        assert!(parsed.digest().is_ok());
    }

    #[test]
    fn resolved_validation_evidence_fixture_has_strict_hex_and_versioned_identity() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/fixtures/ai-proposal-resolved-validation-evidence-v1.json"
        ));
        let parsed: AiProposalResolvedValidationEvidence =
            serde_json::from_str(raw).unwrap();
        assert_eq!(
            parsed.schema_version(),
            AI_PROPOSAL_RESOLVED_VALIDATION_EVIDENCE_SCHEMA_VERSION
        );
        let encoded = serde_json::to_value(&parsed).unwrap();
        for field in [
            "plan_digest",
            "validation_evidence_digest",
            "proposal_binding_digest",
            "resolution_receipt_digest",
        ] {
            assert_eq!(encoded[field].as_str().unwrap().len(), 64);
        }
        assert!(parsed.digest().is_ok());
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
