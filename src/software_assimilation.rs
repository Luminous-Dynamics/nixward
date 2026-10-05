// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Proposal-only assimilation of ephemeral software into reproducible forms.
//!
//! V38 deliberately does **not** infer that an S3 experiment is reproducible
//! merely because it ran successfully. An ephemeral receipt is limited
//! execution evidence. It may inform a proposal for an S1 Nix enclosure or an
//! exact S2 guest, but promotion remains a separate declarative Change/Update
//! Covenant after the target earns the required reproducibility/equivalence
//! evidence.

use crate::guest_realization::{GuestAssurance, GuestObservation, GuestRealizationReceipt};
use crate::software_ingress::{
    ContentDigest, SoftwareIngressError, SoftwareIngressPlan, SoftwareIngressSpec,
    SoftwareTrustClass,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const OBSERVATION_DOMAIN: &[u8] = b"symthaea:nixward:assimilation-observation:v1\0";
const PROPOSAL_DOMAIN: &[u8] = b"symthaea:nixward:assimilation-proposal:v1\0";

pub const SOFTWARE_ASSIMILATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationCompleteness {
    /// We know the exact S3 source digest, launch contract and exit status that
    /// the V37 capsule receipt observed. We do not claim syscall/dependency or
    /// behavioral-equivalence completeness.
    LimitedExecutionReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssimilationObservation {
    pub schema_version: u32,
    pub kind: String,
    pub holon_id: String,
    pub source_plan: SoftwareIngressPlan,
    pub source_plan_blake3: String,
    pub source_content_digest: ContentDigest,
    pub guest_realization_receipt_blake3: String,
    pub launch_contract_blake3: String,
    pub exit_code: i32,
    pub completeness: ObservationCompleteness,
}

impl AssimilationObservation {
    pub fn from_ephemeral_receipt(
        holon_id: impl Into<String>,
        source_plan: &SoftwareIngressPlan,
        receipt: &GuestRealizationReceipt,
    ) -> Result<Self, AssimilationError> {
        source_plan.validate()?;
        let holon_id = holon_id.into();
        validate_blake3("Holon identity", &holon_id)?;
        if source_plan.trust_class() != SoftwareTrustClass::EphemeralGuest {
            return Err(AssimilationError::SourceMustBeEphemeral);
        }
        if receipt.trust_class != SoftwareTrustClass::EphemeralGuest
            || receipt.assurance != GuestAssurance::EphemeralObserved
            || receipt.guest_name != source_plan.name
            || receipt.plan_blake3 != source_plan.digest_hex()?
        {
            return Err(AssimilationError::ReceiptDoesNotMatchSource);
        }
        let capsule = match (&source_plan.spec, &receipt.observation) {
            (
                SoftwareIngressSpec::EphemeralCapsule(spec),
                GuestObservation::Capsule(observation),
            ) => {
                if observation.source_digest != spec.source_digest
                    || receipt.launch_contract_blake3 != spec.permissions.digest_hex()?
                    || observation.launch_contract_blake3 != receipt.launch_contract_blake3
                {
                    return Err(AssimilationError::ReceiptDoesNotMatchSource);
                }
                (spec, observation)
            }
            _ => return Err(AssimilationError::ReceiptDoesNotMatchSource),
        };
        let source_plan_blake3 = source_plan.digest_hex()?;
        let guest_realization_receipt_blake3 = receipt
            .digest_hex()
            .map_err(|e| AssimilationError::GuestEvidence(e.to_string()))?;
        Ok(Self {
            schema_version: SOFTWARE_ASSIMILATION_SCHEMA_VERSION,
            kind: "symthaea-assimilation-observation-v1".into(),
            holon_id,
            source_plan: source_plan.clone(),
            source_plan_blake3,
            source_content_digest: capsule.0.source_digest.clone(),
            guest_realization_receipt_blake3,
            launch_contract_blake3: receipt.launch_contract_blake3.clone(),
            exit_code: capsule.1.exit_code,
            completeness: ObservationCompleteness::LimitedExecutionReceipt,
        })
    }

    pub fn validate(&self) -> Result<(), AssimilationError> {
        if self.schema_version != SOFTWARE_ASSIMILATION_SCHEMA_VERSION
            || self.kind != "symthaea-assimilation-observation-v1"
        {
            return Err(AssimilationError::UnsupportedSchema(self.schema_version));
        }
        validate_blake3("Holon identity", &self.holon_id)?;
        self.source_plan.validate()?;
        if self.source_plan.trust_class() != SoftwareTrustClass::EphemeralGuest {
            return Err(AssimilationError::SourceMustBeEphemeral);
        }
        if self.source_plan.digest_hex()? != self.source_plan_blake3 {
            return Err(AssimilationError::ObservationDrift("source plan"));
        }
        self.source_content_digest.validate()?;
        let source_digest = match &self.source_plan.spec {
            SoftwareIngressSpec::EphemeralCapsule(spec) => &spec.source_digest,
            _ => return Err(AssimilationError::SourceMustBeEphemeral),
        };
        if source_digest != &self.source_content_digest {
            return Err(AssimilationError::ObservationDrift("source content"));
        }
        validate_blake3(
            "guest realization receipt",
            &self.guest_realization_receipt_blake3,
        )?;
        validate_blake3("launch contract", &self.launch_contract_blake3)?;
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, AssimilationError> {
        self.validate()?;
        hash_json(OBSERVATION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionGate {
    OwnerReview,
    BehavioralEquivalenceReview,
    FixedSourceDigest,
    NixDerivationBuild,
    NixEvaluation,
    GuestArtifactPin,
    GuestRealizationReceipt,
    PermissionEnvelopeReview,
    DeclarativeChangeCovenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionDisposition {
    /// Exact S1 source/derivation metadata exists, but no build/evaluation proof
    /// has been attached to this proposal yet.
    NeedsNixProof,
    /// Exact S2 artifact/permission intent exists, but equivalence to the S3
    /// experiment and a fresh S2 realization receipt remain outstanding.
    NeedsGuestProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssimilationProposal {
    pub schema_version: u32,
    pub kind: String,
    pub holon_id: String,
    pub observation_blake3: String,
    pub source_plan_blake3: String,
    pub target_plan: SoftwareIngressPlan,
    pub target_plan_blake3: String,
    pub disposition: PromotionDisposition,
    pub required_gates: Vec<PromotionGate>,
    /// Always false in V38. A successful S3 execution is not authorization to
    /// rewrite `/etc/nixos` or guest state.
    pub automatic_promotion: bool,
    pub evidence_completeness: ObservationCompleteness,
}

impl AssimilationProposal {
    pub fn new(
        observation: &AssimilationObservation,
        target_plan: SoftwareIngressPlan,
    ) -> Result<Self, AssimilationError> {
        observation.validate()?;
        target_plan.validate()?;
        if target_plan.name != observation.source_plan.name {
            return Err(AssimilationError::TargetNameChanged);
        }

        let (disposition, mut gates) = match &target_plan.spec {
            SoftwareIngressSpec::NixEnclosedForeign(spec) => {
                // For direct S3 -> S1 promotion the content that was executed
                // must be the content the fixed-output derivation claims to
                // enclose. A different source is a new software proposal, not
                // promotion evidence for this observation.
                if spec.source_digest != observation.source_content_digest {
                    return Err(AssimilationError::SourceDigestChanged);
                }
                (
                    PromotionDisposition::NeedsNixProof,
                    vec![
                        PromotionGate::OwnerReview,
                        PromotionGate::FixedSourceDigest,
                        PromotionGate::NixDerivationBuild,
                        PromotionGate::NixEvaluation,
                        PromotionGate::DeclarativeChangeCovenant,
                    ],
                )
            }
            SoftwareIngressSpec::FlatpakGuest(_) | SoftwareIngressSpec::OciGuest(_) => (
                PromotionDisposition::NeedsGuestProof,
                vec![
                    PromotionGate::OwnerReview,
                    PromotionGate::BehavioralEquivalenceReview,
                    PromotionGate::GuestArtifactPin,
                    PromotionGate::PermissionEnvelopeReview,
                    PromotionGate::GuestRealizationReceipt,
                    PromotionGate::DeclarativeChangeCovenant,
                ],
            ),
            SoftwareIngressSpec::SovereignNix(_) => {
                return Err(AssimilationError::UnsupportedTarget(
                    "S0 promotion is a separate trusted package-resolution path; V38 only promotes S3 into S1 or S2",
                ));
            }
            SoftwareIngressSpec::EphemeralCapsule(_) => {
                return Err(AssimilationError::UnsupportedTarget(
                    "S3 -> S3 does not improve reproducibility",
                ));
            }
        };
        gates.sort();
        gates.dedup();

        Ok(Self {
            schema_version: SOFTWARE_ASSIMILATION_SCHEMA_VERSION,
            kind: "symthaea-assimilation-proposal-v1".into(),
            holon_id: observation.holon_id.clone(),
            observation_blake3: observation.digest_hex()?,
            source_plan_blake3: observation.source_plan_blake3.clone(),
            target_plan_blake3: target_plan.digest_hex()?,
            target_plan,
            disposition,
            required_gates: gates,
            automatic_promotion: false,
            evidence_completeness: observation.completeness,
        })
    }

    pub fn validate(&self) -> Result<(), AssimilationError> {
        if self.schema_version != SOFTWARE_ASSIMILATION_SCHEMA_VERSION
            || self.kind != "symthaea-assimilation-proposal-v1"
        {
            return Err(AssimilationError::UnsupportedSchema(self.schema_version));
        }
        validate_blake3("Holon identity", &self.holon_id)?;
        validate_blake3("observation", &self.observation_blake3)?;
        validate_blake3("source plan", &self.source_plan_blake3)?;
        self.target_plan.validate()?;
        if self.target_plan.digest_hex()? != self.target_plan_blake3 {
            return Err(AssimilationError::ObservationDrift("target plan"));
        }
        if self.automatic_promotion {
            return Err(AssimilationError::AutomaticPromotionForbidden);
        }
        match (self.disposition, self.target_plan.trust_class()) {
            (PromotionDisposition::NeedsNixProof, SoftwareTrustClass::NixEnclosedForeign)
            | (PromotionDisposition::NeedsGuestProof, SoftwareTrustClass::SovereignGuest) => {}
            _ => return Err(AssimilationError::ProposalClassMismatch),
        }
        if !self
            .required_gates
            .contains(&PromotionGate::DeclarativeChangeCovenant)
            || !self.required_gates.contains(&PromotionGate::OwnerReview)
        {
            return Err(AssimilationError::MissingRequiredGate);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, AssimilationError> {
        self.validate()?;
        hash_json(PROPOSAL_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AssimilationPolicyDocument {
    schema_version: u32,
    kind: &'static str,
    status: &'static str,
    automatic_promotion: bool,
    source_evidence_claim: &'static str,
    s1_required_gates: Vec<&'static str>,
    s2_required_gates: Vec<&'static str>,
    host_source_mutation: &'static str,
    prohibited_inference: Vec<&'static str>,
}

pub fn assimilation_policy_json() -> String {
    let policy = AssimilationPolicyDocument {
        schema_version: SOFTWARE_ASSIMILATION_SCHEMA_VERSION,
        kind: "symthaea-software-assimilation-policy-v1",
        status: "proposal-only-v38",
        automatic_promotion: false,
        source_evidence_claim: "limited-execution-receipt-not-dependency-or-equivalence-proof",
        s1_required_gates: vec![
            "owner-review",
            "fixed-source-digest",
            "nix-derivation-build",
            "nix-evaluation",
            "declarative-change-covenant",
        ],
        s2_required_gates: vec![
            "owner-review",
            "behavioral-equivalence-review",
            "guest-artifact-pin",
            "permission-envelope-review",
            "guest-realization-receipt",
            "declarative-change-covenant",
        ],
        host_source_mutation: "change-or-update-covenant-only",
        prohibited_inference: vec![
            "successful-s3-execution-implies-reproducibility",
            "successful-s3-execution-implies-complete-dependency-discovery",
            "matching-name-implies-behavioral-equivalence",
            "proposal-implies-authorization",
        ],
    };
    serde_json::to_string_pretty(&policy)
        .unwrap_or_else(|_| {
            "{\"schema_version\":1,\"kind\":\"symthaea-software-assimilation-policy-v1\",\"status\":\"serialization-failed\",\"automatic_promotion\":false}".into()
        })
        + "\n"
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AssimilationError {
    #[error("unsupported software-assimilation schema version {0}")]
    UnsupportedSchema(u32),
    #[error("assimilation source must be an S3 ephemeral guest")]
    SourceMustBeEphemeral,
    #[error("guest realization receipt does not match the exact S3 source plan")]
    ReceiptDoesNotMatchSource,
    #[error("assimilation observation drifted at {0}")]
    ObservationDrift(&'static str),
    #[error("promotion target must retain the software name; rename is a separate migration")]
    TargetNameChanged,
    #[error("S1 target source digest differs from the S3 content that was observed")]
    SourceDigestChanged,
    #[error("unsupported promotion target: {0}")]
    UnsupportedTarget(&'static str),
    #[error("automatic promotion is forbidden in V38")]
    AutomaticPromotionForbidden,
    #[error("proposal disposition does not match target trust class")]
    ProposalClassMismatch,
    #[error("proposal is missing the owner/declarative-change gate")]
    MissingRequiredGate,
    #[error("invalid {0} digest")]
    InvalidDigest(&'static str),
    #[error(transparent)]
    Software(#[from] SoftwareIngressError),
    #[error("guest realization evidence error: {0}")]
    GuestEvidence(String),
}

fn validate_blake3(field: &'static str, value: &str) -> Result<(), AssimilationError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AssimilationError::InvalidDigest(field));
    }
    Ok(())
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, AssimilationError> {
    let encoded =
        serde_json::to_vec(value).map_err(|e| AssimilationError::GuestEvidence(e.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_realization::{CapsuleObservation, GuestObservation};
    use crate::software_ingress::{
        CapsuleNetworkPolicy, CapsulePersistence, DigestAlgorithm, EphemeralCapsulePlan,
        FlatpakGuestPlan, FlatpakRuntimePin, GuestPermissionEnvelope, NixEnclosedForeignPackage,
    };

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn source_plan() -> SoftwareIngressPlan {
        SoftwareIngressPlan::new(
            "weird-tool",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest {
                    algorithm: DigestAlgorithm::Blake3,
                    hex: digest('a'),
                },
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap()
    }

    fn observation() -> AssimilationObservation {
        let plan = source_plan();
        let contract = plan.spec.authority_digest_hex().unwrap();
        let receipt = GuestRealizationReceipt::verify(
            &plan,
            GuestObservation::Capsule(CapsuleObservation {
                source_digest: match &plan.spec {
                    SoftwareIngressSpec::EphemeralCapsule(v) => v.source_digest.clone(),
                    _ => unreachable!(),
                },
                sandbox_backend: "bubblewrap".into(),
                launch_contract_blake3: contract,
                network_isolated: true,
                host_root_read_only: true,
                nix_daemon_absent: true,
                exit_code: 0,
                workspace_preserved: false,
            }),
        )
        .unwrap();
        AssimilationObservation::from_ephemeral_receipt(digest('b'), &plan, &receipt).unwrap()
    }

    #[test]
    fn s1_requires_same_observed_source_digest_and_nix_gates() {
        let obs = observation();
        let target = SoftwareIngressPlan::new(
            "weird-tool",
            SoftwareIngressSpec::NixEnclosedForeign(NixEnclosedForeignPackage {
                pname: "weird-tool".into(),
                version: "1.0".into(),
                source: "https://example.invalid/weird-tool".into(),
                source_digest: obs.source_content_digest.clone(),
                derivation_blake3: digest('c'),
            }),
        )
        .unwrap();
        let proposal = AssimilationProposal::new(&obs, target).unwrap();
        assert_eq!(proposal.disposition, PromotionDisposition::NeedsNixProof);
        assert!(
            proposal
                .required_gates
                .contains(&PromotionGate::NixDerivationBuild)
        );
        assert!(!proposal.automatic_promotion);
    }

    #[test]
    fn s1_rejects_source_substitution() {
        let obs = observation();
        let mut different = obs.source_content_digest.clone();
        different.hex = digest('d');
        let target = SoftwareIngressPlan::new(
            "weird-tool",
            SoftwareIngressSpec::NixEnclosedForeign(NixEnclosedForeignPackage {
                pname: "weird-tool".into(),
                version: "1.0".into(),
                source: "https://example.invalid/other".into(),
                source_digest: different,
                derivation_blake3: digest('c'),
            }),
        )
        .unwrap();
        assert_eq!(
            AssimilationProposal::new(&obs, target).unwrap_err(),
            AssimilationError::SourceDigestChanged
        );
    }

    #[test]
    fn s2_is_proposal_only_and_requires_equivalence_plus_realization() {
        let obs = observation();
        let target = SoftwareIngressPlan::new(
            "weird-tool",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.example.Tool".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: digest('e'),
                runtime_pins: vec![FlatpakRuntimePin {
                    reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                    commit: digest('f'),
                }],
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let proposal = AssimilationProposal::new(&obs, target).unwrap();
        assert_eq!(proposal.disposition, PromotionDisposition::NeedsGuestProof);
        assert!(
            proposal
                .required_gates
                .contains(&PromotionGate::BehavioralEquivalenceReview)
        );
        assert!(
            proposal
                .required_gates
                .contains(&PromotionGate::GuestRealizationReceipt)
        );
        assert!(!proposal.automatic_promotion);
    }

    #[test]
    fn s0_and_s3_targets_are_rejected() {
        let obs = observation();
        let s0 = SoftwareIngressPlan::new(
            "weird-tool",
            SoftwareIngressSpec::SovereignNix(crate::software_ingress::SovereignNixPackage {
                attribute: "hello".into(),
            }),
        )
        .unwrap();
        assert!(AssimilationProposal::new(&obs, s0).is_err());
        assert!(AssimilationProposal::new(&obs, source_plan()).is_err());
    }
}
