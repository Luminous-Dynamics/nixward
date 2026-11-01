// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verifier-owned NixOS activation compatibility profiles.
//!
//! This module resolves an exact, pre-qualified release/binary/semantics tuple.
//! It is deliberately pure: it does not inspect the host, execute activation,
//! call systemd, or authorize dispatch. An empty registry denies every request.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const ACTIVATION_PROFILE_REGISTRY_SCHEMA: &str =
    "org.luminousdynamics.nixward.activation-profile-registry";
pub const ACTIVATION_PROFILE_SCHEMA: &str =
    "org.luminousdynamics.nixward.activation-profile";
pub const ACTIVATION_PROFILE_VERSION: u16 = 1;
const PROFILE_DOMAIN: &[u8] = b"nixward-activation-profile-v1\0";
const PLAN_DOMAIN: &[u8] = b"nixward-activation-plan-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"nixward-activation-compatibility-receipt-v1\0";
const MAX_PROFILES: usize = 256;
const MAX_MODE_CONTRACTS: usize = 4;
const MAX_STEPS_PER_MODE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Switch,
    Test,
    Boot,
    DryActivate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationExpectation {
    TargetGeneration,
    PreservePreState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPostconditions {
    pub running_generation: GenerationExpectation,
    pub boot_default_generation: GenerationExpectation,
    pub runtime_mutation_expected: bool,
    pub boot_default_mutation_expected: bool,
    pub running_target_requires_reboot_observation: bool,
}

impl ActivationPostconditions {
    /// Verifier-owned postconditions for the native NixOS mode contract.
    ///
    /// A profile may support a mode, but it may not redefine what success for
    /// that mode means.
    pub const fn for_mode(mode: ActivationMode) -> Self {
        match mode {
            ActivationMode::Switch => Self {
                running_generation: GenerationExpectation::TargetGeneration,
                boot_default_generation: GenerationExpectation::TargetGeneration,
                runtime_mutation_expected: true,
                boot_default_mutation_expected: true,
                running_target_requires_reboot_observation: false,
            },
            ActivationMode::Test => Self {
                running_generation: GenerationExpectation::TargetGeneration,
                boot_default_generation: GenerationExpectation::PreservePreState,
                runtime_mutation_expected: true,
                boot_default_mutation_expected: false,
                running_target_requires_reboot_observation: false,
            },
            ActivationMode::Boot => Self {
                running_generation: GenerationExpectation::PreservePreState,
                boot_default_generation: GenerationExpectation::TargetGeneration,
                runtime_mutation_expected: false,
                boot_default_mutation_expected: true,
                running_target_requires_reboot_observation: true,
            },
            ActivationMode::DryActivate => Self {
                running_generation: GenerationExpectation::PreservePreState,
                boot_default_generation: GenerationExpectation::PreservePreState,
                runtime_mutation_expected: false,
                boot_default_mutation_expected: false,
                running_target_requires_reboot_observation: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStepKind {
    CheckSwitchInhibitors,
    ValidateTargetClosure,
    DryActivationPreview,
    UpdateBootDefault,
    RunActivationScript,
    StopUnit,
    DaemonReexec,
    DaemonReload,
    ReloadUnit,
    RestartUnit,
    StartUnit,
    CaptureHostPostState,
    /// Historical/forbidden adapter capability. New profiles must not depend
    /// on activation-script callbacks to reload or restart systemd units.
    DeprecatedActivationScriptServiceCallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationStepSpec {
    pub step_id: String,
    pub kind: ActivationStepKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InhibitorPolicy {
    Required,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationModeContract {
    pub mode: ActivationMode,
    pub postconditions: ActivationPostconditions,
    /// Exact ordered step contract qualified for this release and binary.
    pub steps: Vec<ActivationStepSpec>,
    pub inhibitor_policy: InhibitorPolicy,
    pub authorized_inhibitor_bypass_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdCapabilityProfile {
    /// Exact systemd version string captured during release qualification.
    pub version: String,
    pub job_removed_evidence: bool,
    pub unit_invocation_id: bool,
    pub get_unit_by_pidfd: bool,
    /// Required fallback when the exact systemd build lacks PIDFD attribution.
    pub process_start_tuple_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProfile {
    pub schema: String,
    pub version: u16,
    pub profile_id: String,
    /// Exact nixos-version release value; no fuzzy major/minor matching.
    pub nixos_release: String,
    /// Exact Nixpkgs source revision used to build the qualified system.
    pub nixpkgs_revision: String,
    /// SHA-256 of the exact switch-to-configuration executable.
    pub switch_to_configuration_sha256: String,
    pub activation_semantics_revision: String,
    pub activation_semantics_digest: String,
    pub systemd: SystemdCapabilityProfile,
    pub observer_adapter_revision: String,
    pub mode_contracts: Vec<ActivationModeContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActivationProfileKey {
    nixos_release: String,
    nixpkgs_revision: String,
    switch_to_configuration_sha256: String,
    activation_semantics_revision: String,
    activation_semantics_digest: String,
    systemd_version: String,
    observer_adapter_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProfileQuery {
    pub nixos_release: String,
    pub nixpkgs_revision: String,
    pub switch_to_configuration_sha256: String,
    pub activation_semantics_revision: String,
    pub activation_semantics_digest: String,
    pub systemd_version: String,
    pub observer_adapter_revision: String,
    pub expected_profile_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InhibitorDisposition {
    Passed,
    Blocked,
    Bypassed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchInhibitorEvidence {
    pub disposition: InhibitorDisposition,
    pub old_values_digest: String,
    pub new_values_digest: String,
    pub changed_names_digest: String,
    /// Reference to a separately verified, action-scoped bypass authorization.
    /// This module checks presence and binding, not the cryptographic signature.
    pub bypass_authorization_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPlanRequest {
    pub transaction_id: String,
    pub mode: ActivationMode,
    pub target_generation_digest: String,
    pub pre_state_running_generation_digest: String,
    pub pre_state_boot_default_generation_digest: String,
    pub steps: Vec<ActivationStepSpec>,
    pub inhibitor_evidence: Option<SwitchInhibitorEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPlan {
    pub schema: String,
    pub version: u16,
    pub transaction_id: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub mode: ActivationMode,
    pub target_generation_digest: String,
    pub pre_state_running_generation_digest: String,
    pub pre_state_boot_default_generation_digest: String,
    pub expected_postconditions: ActivationPostconditions,
    pub steps: Vec<ActivationStepSpec>,
    pub inhibitor_evidence: Option<SwitchInhibitorEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCompatibilityReceipt {
    pub schema: String,
    pub version: u16,
    pub profile_id: String,
    pub profile_digest: String,
    pub nixos_release: String,
    pub nixpkgs_revision: String,
    pub switch_to_configuration_sha256: String,
    pub activation_semantics_revision: String,
    pub activation_semantics_digest: String,
    pub systemd_version: String,
    pub systemd_job_removed_evidence: bool,
    pub systemd_unit_invocation_id: bool,
    pub systemd_get_unit_by_pidfd: bool,
    pub process_start_tuple_fallback: bool,
    pub observer_adapter_revision: String,
    pub mode: ActivationMode,
    pub expected_postconditions: ActivationPostconditions,
    pub plan_digest: String,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActivationPlan {
    pub plan: ActivationPlan,
    pub compatibility: ActivationCompatibilityReceipt,
}

#[derive(Debug, Default)]
pub struct ActivationProfileRegistry {
    profiles: BTreeMap<ActivationProfileKey, ActivationProfile>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ActivationProfileError {
    #[error("unsupported activation profile schema or version")]
    UnsupportedSchema,
    #[error("invalid activation profile field: {0}")]
    InvalidProfile(&'static str),
    #[error("invalid activation plan: {0}")]
    InvalidPlan(&'static str),
    #[error("duplicate activation profile key")]
    DuplicateProfile,
    #[error("activation profile registry is full")]
    RegistryFull,
    #[error("no exact activation profile matches the requested release/binary/semantics tuple")]
    UnknownProfile,
    #[error("activation profile digest does not match the qualified registry entry")]
    ProfileDigestMismatch,
    #[error("activation mode is not supported by the exact activation profile")]
    UnsupportedMode,
    #[error("switch inhibitors blocked this activation")]
    InhibitorBlocked,
    #[error("this profile does not permit an authorized switch-inhibitor bypass")]
    InhibitorBypassForbidden,
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
        })
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn update_hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

impl ActivationProfile {
    pub fn validate(&self) -> Result<(), ActivationProfileError> {
        if self.schema != ACTIVATION_PROFILE_SCHEMA || self.version != ACTIVATION_PROFILE_VERSION {
            return Err(ActivationProfileError::UnsupportedSchema);
        }
        if !valid_token(&self.profile_id)
            || !valid_token(&self.nixos_release)
            || !valid_hex(&self.nixpkgs_revision, 40)
            || !valid_hex(&self.switch_to_configuration_sha256, 64)
            || !valid_token(&self.activation_semantics_revision)
            || !valid_hex(&self.activation_semantics_digest, 64)
            || !valid_token(&self.systemd.version)
            || !valid_token(&self.observer_adapter_revision)
        {
            return Err(ActivationProfileError::InvalidProfile("identity or exact binary/revision pin"));
        }
        if !self.systemd.job_removed_evidence || !self.systemd.unit_invocation_id {
            return Err(ActivationProfileError::InvalidProfile(
                "systemd JobRemoved and InvocationID evidence are mandatory",
            ));
        }
        if !self.systemd.get_unit_by_pidfd && !self.systemd.process_start_tuple_fallback {
            return Err(ActivationProfileError::InvalidProfile(
                "PIDFD attribution is absent and no process-start-tuple fallback is qualified",
            ));
        }
        if self.mode_contracts.is_empty() || self.mode_contracts.len() > MAX_MODE_CONTRACTS {
            return Err(ActivationProfileError::InvalidProfile("mode contract count"));
        }

        let mut seen_modes = std::collections::BTreeSet::new();
        for contract in &self.mode_contracts {
            if !seen_modes.insert(contract.mode) {
                return Err(ActivationProfileError::InvalidProfile("duplicate mode contract"));
            }
            if contract.postconditions != ActivationPostconditions::for_mode(contract.mode) {
                return Err(ActivationProfileError::InvalidProfile(
                    "mode postconditions differ from verifier-owned NixOS semantics",
                ));
            }
            if contract.steps.is_empty() || contract.steps.len() > MAX_STEPS_PER_MODE {
                return Err(ActivationProfileError::InvalidProfile("mode step count"));
            }
            let mut step_ids = std::collections::BTreeSet::new();
            for step in &contract.steps {
                if !valid_token(&step.step_id) || !step_ids.insert(step.step_id.as_str()) {
                    return Err(ActivationProfileError::InvalidProfile(
                        "step IDs must be non-empty, bounded and unique within a mode",
                    ));
                }
                if step.kind == ActivationStepKind::DeprecatedActivationScriptServiceCallback {
                    return Err(ActivationProfileError::InvalidProfile(
                        "deprecated activation-script service callback is forbidden",
                    ));
                }
            }

            let kinds = contract.steps.iter().map(|step| step.kind).collect::<Vec<_>>();
            let has = |kind| kinds.contains(&kind);
            if !has(ActivationStepKind::ValidateTargetClosure)
                || !has(ActivationStepKind::CaptureHostPostState)
            {
                return Err(ActivationProfileError::InvalidProfile(
                    "every mode must validate the exact closure and capture post-state",
                ));
            }
            if contract.inhibitor_policy == InhibitorPolicy::Required
                && kinds.first() != Some(&ActivationStepKind::CheckSwitchInhibitors)
            {
                return Err(ActivationProfileError::InvalidProfile(
                    "required switch inhibitors must be the first activation step",
                ));
            }
            if contract.inhibitor_policy == InhibitorPolicy::NotApplicable
                && has(ActivationStepKind::CheckSwitchInhibitors)
            {
                return Err(ActivationProfileError::InvalidProfile(
                    "non-applicable inhibitor mode cannot claim an inhibitor check step",
                ));
            }
            if contract.inhibitor_policy == InhibitorPolicy::NotApplicable
                && contract.authorized_inhibitor_bypass_allowed
            {
                return Err(ActivationProfileError::InvalidProfile(
                    "inhibitor bypass cannot be enabled when the inhibitor is not applicable",
                ));
            }

            match contract.mode {
                ActivationMode::Switch => {
                    if !has(ActivationStepKind::UpdateBootDefault)
                        || !has(ActivationStepKind::RunActivationScript)
                    {
                        return Err(ActivationProfileError::InvalidProfile(
                            "switch requires boot-default update and running activation steps",
                        ));
                    }
                }
                ActivationMode::Test => {
                    if has(ActivationStepKind::UpdateBootDefault)
                        || !has(ActivationStepKind::RunActivationScript)
                    {
                        return Err(ActivationProfileError::InvalidProfile(
                            "test mutates the running system but must preserve boot default",
                        ));
                    }
                }
                ActivationMode::Boot => {
                    if !has(ActivationStepKind::UpdateBootDefault)
                        || has(ActivationStepKind::RunActivationScript)
                        || has(ActivationStepKind::StopUnit)
                        || has(ActivationStepKind::RestartUnit)
                        || has(ActivationStepKind::ReloadUnit)
                        || has(ActivationStepKind::StartUnit)
                    {
                        return Err(ActivationProfileError::InvalidProfile(
                            "boot changes the next boot target without claiming current runtime activation",
                        ));
                    }
                }
                ActivationMode::DryActivate => {
                    if !has(ActivationStepKind::DryActivationPreview)
                        || kinds.iter().any(|kind| {
                            matches!(
                                kind,
                                ActivationStepKind::UpdateBootDefault
                                    | ActivationStepKind::RunActivationScript
                                    | ActivationStepKind::StopUnit
                                    | ActivationStepKind::DaemonReexec
                                    | ActivationStepKind::DaemonReload
                                    | ActivationStepKind::ReloadUnit
                                    | ActivationStepKind::RestartUnit
                                    | ActivationStepKind::StartUnit
                            )
                        })
                    {
                        return Err(ActivationProfileError::InvalidProfile(
                            "dry-activate must be a read-only preview without activation mutations",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ActivationProfileError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ActivationProfileError::InvalidProfile("profile serialization"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROFILE_DOMAIN);
        update_hash_field(&mut hasher, &bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub fn expected_postconditions(
        &self,
        mode: ActivationMode,
    ) -> Result<ActivationPostconditions, ActivationProfileError> {
        self.validate()?;
        self.mode_contract(mode)?;
        Ok(ActivationPostconditions::for_mode(mode))
    }

    fn mode_contract(
        &self,
        mode: ActivationMode,
    ) -> Result<&ActivationModeContract, ActivationProfileError> {
        self.mode_contracts
            .iter()
            .find(|contract| contract.mode == mode)
            .ok_or(ActivationProfileError::UnsupportedMode)
    }

    pub fn validate_plan(
        &self,
        request: &ActivationPlanRequest,
        profile_digest: &str,
    ) -> Result<ActivationPlan, ActivationProfileError> {
        self.validate()?;
        if !valid_token(&request.transaction_id)
            || !valid_hex(&request.target_generation_digest, 64)
            || !valid_hex(&request.pre_state_running_generation_digest, 64)
            || !valid_hex(&request.pre_state_boot_default_generation_digest, 64)
        {
            return Err(ActivationProfileError::InvalidPlan("transaction or generation digest"));
        }
        let contract = self.mode_contract(request.mode)?;
        if request.steps != contract.steps {
            return Err(ActivationProfileError::InvalidPlan(
                "steps differ from the exact ordered steps qualified by the profile",
            ));
        }
        match (contract.inhibitor_policy, request.inhibitor_evidence.as_ref()) {
            (InhibitorPolicy::Required, None) => {
                return Err(ActivationProfileError::InvalidPlan("required switch-inhibitor evidence is missing"));
            }
            (InhibitorPolicy::NotApplicable, Some(_)) => {
                return Err(ActivationProfileError::InvalidPlan("unexpected inhibitor evidence for this mode"));
            }
            (InhibitorPolicy::Required, Some(evidence)) => {
                if !valid_hex(&evidence.old_values_digest, 64)
                    || !valid_hex(&evidence.new_values_digest, 64)
                    || !valid_hex(&evidence.changed_names_digest, 64)
                {
                    return Err(ActivationProfileError::InvalidPlan("malformed switch-inhibitor evidence"));
                }
                match evidence.disposition {
                    InhibitorDisposition::Passed => {
                        if evidence.bypass_authorization_digest.is_some() {
                            return Err(ActivationProfileError::InvalidPlan(
                                "passed inhibitor evidence cannot carry a bypass authorization",
                            ));
                        }
                    }
                    InhibitorDisposition::Blocked => {
                        return Err(ActivationProfileError::InhibitorBlocked);
                    }
                    InhibitorDisposition::Bypassed => {
                        if !contract.authorized_inhibitor_bypass_allowed {
                            return Err(ActivationProfileError::InhibitorBypassForbidden);
                        }
                        if !evidence
                            .bypass_authorization_digest
                            .as_deref()
                            .is_some_and(|digest| valid_hex(digest, 64))
                        {
                            return Err(ActivationProfileError::InvalidPlan(
                                "bypass requires a separately verified authorization receipt digest",
                            ));
                        }
                    }
                }
            }
            (InhibitorPolicy::NotApplicable, None) => {}
        }

        let digest = self.digest()?;
        if profile_digest != digest {
            return Err(ActivationProfileError::ProfileDigestMismatch);
        }
        Ok(ActivationPlan {
            schema: ACTIVATION_PROFILE_SCHEMA.into(),
            version: ACTIVATION_PROFILE_VERSION,
            transaction_id: request.transaction_id.clone(),
            profile_id: self.profile_id.clone(),
            profile_digest: digest,
            mode: request.mode,
            target_generation_digest: request.target_generation_digest.clone(),
            pre_state_running_generation_digest: request.pre_state_running_generation_digest.clone(),
            pre_state_boot_default_generation_digest: request.pre_state_boot_default_generation_digest.clone(),
            expected_postconditions: contract.postconditions,
            steps: request.steps.clone(),
            inhibitor_evidence: request.inhibitor_evidence.clone(),
        })
    }

    fn key(&self) -> ActivationProfileKey {
        ActivationProfileKey {
            nixos_release: self.nixos_release.clone(),
            nixpkgs_revision: self.nixpkgs_revision.clone(),
            switch_to_configuration_sha256: self.switch_to_configuration_sha256.clone(),
            activation_semantics_revision: self.activation_semantics_revision.clone(),
            activation_semantics_digest: self.activation_semantics_digest.clone(),
            systemd_version: self.systemd.version.clone(),
            observer_adapter_revision: self.observer_adapter_revision.clone(),
        }
    }
}

impl ActivationPlan {
    pub fn digest(&self) -> Result<String, ActivationProfileError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ActivationProfileError::InvalidPlan("plan serialization"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(PLAN_DOMAIN);
        update_hash_field(&mut hasher, &bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

impl ActivationProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a release-qualified profile from trusted, verifier-owned
    /// configuration. This is not an agent-facing runtime API.
    pub fn register_qualified_profile(
        &mut self,
        profile: ActivationProfile,
    ) -> Result<String, ActivationProfileError> {
        profile.validate()?;
        if self.profiles.len() >= MAX_PROFILES {
            return Err(ActivationProfileError::RegistryFull);
        }
        let key = profile.key();
        if self.profiles.contains_key(&key) {
            return Err(ActivationProfileError::DuplicateProfile);
        }
        let digest = profile.digest()?;
        self.profiles.insert(key, profile);
        Ok(digest)
    }

    pub fn resolve(
        &self,
        query: &ActivationProfileQuery,
    ) -> Result<&ActivationProfile, ActivationProfileError> {
        if !valid_token(&query.nixos_release)
            || !valid_hex(&query.nixpkgs_revision, 40)
            || !valid_hex(&query.switch_to_configuration_sha256, 64)
            || !valid_token(&query.activation_semantics_revision)
            || !valid_hex(&query.activation_semantics_digest, 64)
            || !valid_token(&query.systemd_version)
            || !valid_token(&query.observer_adapter_revision)
            || !valid_hex(&query.expected_profile_digest, 64)
        {
            return Err(ActivationProfileError::InvalidPlan("malformed exact activation profile query"));
        }
        let key = ActivationProfileKey {
            nixos_release: query.nixos_release.clone(),
            nixpkgs_revision: query.nixpkgs_revision.clone(),
            switch_to_configuration_sha256: query.switch_to_configuration_sha256.clone(),
            activation_semantics_revision: query.activation_semantics_revision.clone(),
            activation_semantics_digest: query.activation_semantics_digest.clone(),
            systemd_version: query.systemd_version.clone(),
            observer_adapter_revision: query.observer_adapter_revision.clone(),
        };
        let profile = self.profiles.get(&key).ok_or(ActivationProfileError::UnknownProfile)?;
        if profile.digest()? != query.expected_profile_digest {
            return Err(ActivationProfileError::ProfileDigestMismatch);
        }
        Ok(profile)
    }

    pub fn resolve_and_validate_plan(
        &self,
        query: &ActivationProfileQuery,
        request: &ActivationPlanRequest,
    ) -> Result<ResolvedActivationPlan, ActivationProfileError> {
        let profile = self.resolve(query)?;
        let profile_digest = profile.digest()?;
        let plan = profile.validate_plan(request, &profile_digest)?;
        let compatibility = compatibility_receipt(profile, request.mode, &plan)?;
        Ok(ResolvedActivationPlan { plan, compatibility })
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

fn compatibility_receipt(
    profile: &ActivationProfile,
    mode: ActivationMode,
    plan: &ActivationPlan,
) -> Result<ActivationCompatibilityReceipt, ActivationProfileError> {
    let profile_digest = profile.digest()?;
    let plan_digest = plan.digest()?;
    let mut receipt = ActivationCompatibilityReceipt {
        schema: ACTIVATION_PROFILE_SCHEMA.into(),
        version: ACTIVATION_PROFILE_VERSION,
        profile_id: profile.profile_id.clone(),
        profile_digest: profile_digest.clone(),
        nixos_release: profile.nixos_release.clone(),
        nixpkgs_revision: profile.nixpkgs_revision.clone(),
        switch_to_configuration_sha256: profile.switch_to_configuration_sha256.clone(),
        activation_semantics_revision: profile.activation_semantics_revision.clone(),
        activation_semantics_digest: profile.activation_semantics_digest.clone(),
        systemd_version: profile.systemd.version.clone(),
        systemd_job_removed_evidence: profile.systemd.job_removed_evidence,
        systemd_unit_invocation_id: profile.systemd.unit_invocation_id,
        systemd_get_unit_by_pidfd: profile.systemd.get_unit_by_pidfd,
        process_start_tuple_fallback: profile.systemd.process_start_tuple_fallback,
        observer_adapter_revision: profile.observer_adapter_revision.clone(),
        mode,
        expected_postconditions: plan.expected_postconditions,
        plan_digest,
        receipt_digest: String::new(),
    };
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|_| ActivationProfileError::InvalidProfile("compatibility receipt serialization"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_DOMAIN);
    update_hash_field(&mut hasher, &bytes);
    receipt.receipt_digest = hasher.finalize().to_hex().to_string();
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn revision(byte: char) -> String {
        std::iter::repeat(byte).take(40).collect()
    }

    fn step(step_id: &str, kind: ActivationStepKind) -> ActivationStepSpec {
        ActivationStepSpec { step_id: step_id.into(), kind }
    }

    fn contract(
        mode: ActivationMode,
        steps: Vec<ActivationStepSpec>,
        inhibitor_policy: InhibitorPolicy,
        bypass: bool,
    ) -> ActivationModeContract {
        ActivationModeContract {
            mode,
            postconditions: ActivationPostconditions::for_mode(mode),
            steps,
            inhibitor_policy,
            authorized_inhibitor_bypass_allowed: bypass,
        }
    }

    fn profile() -> ActivationProfile {
        ActivationProfile {
            schema: ACTIVATION_PROFILE_SCHEMA.into(),
            version: ACTIVATION_PROFILE_VERSION,
            profile_id: "nixos-26.05-qualified-build-001".into(),
            nixos_release: "26.05".into(),
            nixpkgs_revision: revision('a'),
            switch_to_configuration_sha256: digest('b'),
            activation_semantics_revision: "nixos-switch-semantics-v1".into(),
            activation_semantics_digest: digest('c'),
            systemd: SystemdCapabilityProfile {
                version: "systemd-257".into(),
                job_removed_evidence: true,
                unit_invocation_id: true,
                get_unit_by_pidfd: true,
                process_start_tuple_fallback: false,
            },
            observer_adapter_revision: "nixward-observer-v1".into(),
            mode_contracts: vec![
                contract(
                    ActivationMode::Switch,
                    vec![
                        step("inhibitors", ActivationStepKind::CheckSwitchInhibitors),
                        step("closure", ActivationStepKind::ValidateTargetClosure),
                        step("boot-default", ActivationStepKind::UpdateBootDefault),
                        step("activation", ActivationStepKind::RunActivationScript),
                        step("post-state", ActivationStepKind::CaptureHostPostState),
                    ],
                    InhibitorPolicy::Required,
                    false,
                ),
                contract(
                    ActivationMode::Test,
                    vec![
                        step("closure", ActivationStepKind::ValidateTargetClosure),
                        step("activation", ActivationStepKind::RunActivationScript),
                        step("post-state", ActivationStepKind::CaptureHostPostState),
                    ],
                    InhibitorPolicy::NotApplicable,
                    false,
                ),
                contract(
                    ActivationMode::Boot,
                    vec![
                        step("closure", ActivationStepKind::ValidateTargetClosure),
                        step("boot-default", ActivationStepKind::UpdateBootDefault),
                        step("post-state", ActivationStepKind::CaptureHostPostState),
                    ],
                    InhibitorPolicy::NotApplicable,
                    false,
                ),
                contract(
                    ActivationMode::DryActivate,
                    vec![
                        step("closure", ActivationStepKind::ValidateTargetClosure),
                        step("preview", ActivationStepKind::DryActivationPreview),
                        step("post-state", ActivationStepKind::CaptureHostPostState),
                    ],
                    InhibitorPolicy::NotApplicable,
                    false,
                ),
            ],
        }
    }

    fn inhibitor(disposition: InhibitorDisposition, bypass: Option<String>) -> SwitchInhibitorEvidence {
        SwitchInhibitorEvidence {
            disposition,
            old_values_digest: digest('d'),
            new_values_digest: digest('e'),
            changed_names_digest: digest('f'),
            bypass_authorization_digest: bypass,
        }
    }

    fn request(mode: ActivationMode) -> ActivationPlanRequest {
        let p = profile();
        ActivationPlanRequest {
            transaction_id: "tx-001".into(),
            mode,
            target_generation_digest: digest('1'),
            pre_state_running_generation_digest: digest('2'),
            pre_state_boot_default_generation_digest: digest('3'),
            steps: p.mode_contract(mode).unwrap().steps.clone(),
            inhibitor_evidence: if mode == ActivationMode::Switch {
                Some(inhibitor(InhibitorDisposition::Passed, None))
            } else {
                None
            },
        }
    }

    fn query(p: &ActivationProfile) -> ActivationProfileQuery {
        ActivationProfileQuery {
            nixos_release: p.nixos_release.clone(),
            nixpkgs_revision: p.nixpkgs_revision.clone(),
            switch_to_configuration_sha256: p.switch_to_configuration_sha256.clone(),
            activation_semantics_revision: p.activation_semantics_revision.clone(),
            activation_semantics_digest: p.activation_semantics_digest.clone(),
            systemd_version: p.systemd.version.clone(),
            observer_adapter_revision: p.observer_adapter_revision.clone(),
            expected_profile_digest: p.digest().unwrap(),
        }
    }

    #[test]
    fn empty_registry_denies_every_profile() {
        let registry = ActivationProfileRegistry::new();
        assert!(registry.is_empty());
        assert!(matches!(registry.resolve(&query(&profile())), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn exact_release_binary_systemd_and_semantics_tuple_resolves() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        let digest = registry.register_qualified_profile(p.clone()).unwrap();
        assert_eq!(digest, p.digest().unwrap());
        assert_eq!(registry.resolve(&query(&p)).unwrap(), &p);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn unknown_release_is_denied_without_minor_or_latest_fallback() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.nixos_release = "26.11".into();
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn wrong_switch_binary_digest_is_denied() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.switch_to_configuration_sha256 = digest('9');
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn wrong_nixpkgs_revision_is_denied() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.nixpkgs_revision = revision('9');
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn wrong_semantics_digest_or_revision_is_denied() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.activation_semantics_digest = digest('9');
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
        let mut q = query(&p);
        q.activation_semantics_revision = "nixos-switch-semantics-v2".into();
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn wrong_systemd_version_or_observer_adapter_is_denied() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.systemd_version = "systemd-258".into();
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
        let mut q = query(&p);
        q.observer_adapter_revision = "observer-v2".into();
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn caller_cannot_substitute_profile_digest() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.expected_profile_digest = digest('9');
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::ProfileDigestMismatch)));
    }

    #[test]
    fn duplicate_profile_key_is_rejected_even_with_changed_profile_id() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register_qualified_profile(p.clone()).unwrap();
        let mut duplicate = p;
        duplicate.profile_id = "another-profile-id".into();
        assert!(matches!(registry.register_qualified_profile(duplicate), Err(ActivationProfileError::DuplicateProfile)));
    }

    #[test]
    fn corrupted_profile_digest_changes_exact_resolution() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        let digest = registry.register_qualified_profile(p.clone()).unwrap();
        let mut q = query(&p);
        q.expected_profile_digest = digest;
        q.switch_to_configuration_sha256 = digest::<'x'>(); // invalid compile marker removed below
        assert!(matches!(registry.resolve(&q), Err(ActivationProfileError::UnknownProfile)));
    }

    #[test]
    fn systemd_requires_job_removed_and_invocation_id_evidence() {
        let mut p = profile();
        p.systemd.job_removed_evidence = false;
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
        let mut p = profile();
        p.systemd.unit_invocation_id = false;
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn missing_pidfd_requires_process_start_tuple_fallback() {
        let mut p = profile();
        p.systemd.get_unit_by_pidfd = false;
        p.systemd.process_start_tuple_fallback = false;
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
        p.systemd.process_start_tuple_fallback = true;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn empty_or_duplicate_mode_contracts_are_rejected() {
        let mut p = profile();
        p.mode_contracts.clear();
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
        let mut p = profile();
        p.mode_contracts.push(p.mode_contracts[0].clone());
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn mode_postconditions_are_not_caller_defined() {
        let mut p = profile();
        p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Test).unwrap()
            .postconditions.boot_default_generation = GenerationExpectation::TargetGeneration;
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn switch_requires_boot_default_and_running_activation_steps() {
        let mut p = profile();
        let switch = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap();
        switch.steps.retain(|s| s.kind != ActivationStepKind::RunActivationScript);
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn test_mode_cannot_update_boot_default() {
        let mut p = profile();
        let test = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Test).unwrap();
        test.steps.insert(1, step("boot-default", ActivationStepKind::UpdateBootDefault));
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn boot_mode_cannot_claim_current_runtime_activation() {
        let mut p = profile();
        let boot = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Boot).unwrap();
        boot.steps.push(step("start-service", ActivationStepKind::StartUnit));
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn dry_activate_cannot_contain_mutation_steps() {
        let mut p = profile();
        let dry = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::DryActivate).unwrap();
        dry.steps.push(step("runtime", ActivationStepKind::RestartUnit));
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn deprecated_activation_script_service_callback_is_forbidden() {
        let mut p = profile();
        let switch = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap();
        switch.steps.push(step("deprecated", ActivationStepKind::DeprecatedActivationScriptServiceCallback));
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }

    #[test]
    fn required_inhibitors_must_be_first_and_not_silently_bypassed() {
        let mut p = profile();
        let switch = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap();
        switch.steps.swap(0, 1);
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
        let switch = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap();
        switch.steps.swap(0, 1);
        switch.authorized_inhibitor_bypass_allowed = true;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn missing_required_inhibitor_evidence_is_denied() {
        let p = profile();
        assert!(matches!(
            p.validate_plan(&request(ActivationMode::Switch), &p.digest().unwrap()),
            Ok(_)
        ));
        let mut req = request(ActivationMode::Switch);
        req.inhibitor_evidence = None;
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InvalidPlan(_))
        ));
    }

    #[test]
    fn blocked_inhibitor_preflight_denies_activation() {
        let p = profile();
        let mut req = request(ActivationMode::Switch);
        req.inhibitor_evidence = Some(inhibitor(InhibitorDisposition::Blocked, None));
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InhibitorBlocked)
        ));
    }

    #[test]
    fn unauthorized_inhibitor_bypass_is_denied() {
        let p = profile();
        let mut req = request(ActivationMode::Switch);
        req.inhibitor_evidence = Some(inhibitor(InhibitorDisposition::Bypassed, Some(digest('8'))));
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InhibitorBypassForbidden)
        ));
    }

    #[test]
    fn authorized_bypass_requires_separate_receipt_digest() {
        let mut p = profile();
        p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap()
            .authorized_inhibitor_bypass_allowed = true;
        let mut req = request(ActivationMode::Switch);
        req.inhibitor_evidence = Some(inhibitor(InhibitorDisposition::Bypassed, None));
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InvalidPlan(_))
        ));
        req.inhibitor_evidence = Some(inhibitor(InhibitorDisposition::Bypassed, Some(digest('8'))));
        assert!(p.validate_plan(&req, &p.digest().unwrap()).is_ok());
    }

    #[test]
    fn not_applicable_inhibitors_reject_a_fabricated_inhibitor_result() {
        let p = profile();
        let mut req = request(ActivationMode::Test);
        req.inhibitor_evidence = Some(inhibitor(InhibitorDisposition::Passed, None));
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InvalidPlan(_))
        ));
    }

    #[test]
    fn plan_steps_must_equal_exact_ordered_profile_steps() {
        let p = profile();
        let mut req = request(ActivationMode::Switch);
        req.steps.swap(0, 1);
        assert!(matches!(
            p.validate_plan(&req, &p.digest().unwrap()),
            Err(ActivationProfileError::InvalidPlan(_))
        ));
    }

    #[test]
    fn plan_profile_digest_is_exact_and_profile_bound() {
        let p = profile();
        assert!(matches!(
            p.validate_plan(&request(ActivationMode::Switch), &digest('0')),
            Err(ActivationProfileError::ProfileDigestMismatch)
        ));
    }

    #[test]
    fn mode_specific_postconditions_match_native_nixos_contract() {
        let p = profile();
        assert_eq!(p.expected_postconditions(ActivationMode::Switch).unwrap(),
                   ActivationPostconditions::for_mode(ActivationMode::Switch));
        assert_eq!(p.expected_postconditions(ActivationMode::Test).unwrap().boot_default_generation,
                   GenerationExpectation::PreservePreState);
        assert_eq!(p.expected_postconditions(ActivationMode::Boot).unwrap().running_generation,
                   GenerationExpectation::PreservePreState);
        assert_eq!(p.expected_postconditions(ActivationMode::DryActivate).unwrap().runtime_mutation_expected,
                   false);
    }

    #[test]
    fn plan_and_compatibility_receipt_are_domain_separated() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        let profile_digest = registry.register_qualified_profile(p.clone()).unwrap();
        let resolved = registry.resolve_and_validate_plan(
            &query(&p),
            &request(ActivationMode::Switch),
        ).unwrap();
        assert_eq!(resolved.plan.profile_digest, profile_digest);
        assert_eq!(resolved.compatibility.profile_digest, profile_digest);
        assert_eq!(resolved.compatibility.mode, ActivationMode::Switch);
        assert_eq!(resolved.compatibility.expected_postconditions,
                   ActivationPostconditions::for_mode(ActivationMode::Switch));
        assert!(valid_hex(&resolved.compatibility.plan_digest, 64));
        assert!(valid_hex(&resolved.compatibility.receipt_digest, 64));
    }

    #[test]
    fn corrupted_pre_state_or_target_digest_is_denied() {
        let p = profile();
        let mut req = request(ActivationMode::Switch);
        req.target_generation_digest = "bad".into();
        assert!(matches!(p.validate_plan(&req, &p.digest().unwrap()), Err(ActivationProfileError::InvalidPlan(_))));
        let mut req = request(ActivationMode::Switch);
        req.pre_state_running_generation_digest = "bad".into();
        assert!(matches!(p.validate_plan(&req, &p.digest().unwrap()), Err(ActivationProfileError::InvalidPlan(_))));
    }

    #[test]
    fn duplicate_and_malformed_step_ids_are_denied() {
        let mut p = profile();
        let switch = p.mode_contracts.iter_mut().find(|c| c.mode == ActivationMode::Switch).unwrap();
        switch.steps[1].step_id = switch.steps[0].step_id.clone();
        assert!(matches!(p.validate(), Err(ActivationProfileError::InvalidProfile(_))));
    }
}
