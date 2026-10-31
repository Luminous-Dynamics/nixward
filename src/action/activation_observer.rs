// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Evidence model for NixOS activation as a multi-step, partially observable
//! host transition. This module observes and validates receipts; it does not
//! execute activation, issue D-Bus calls, or claim an atomic rollback.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ACTIVATION_TRACE_SCHEMA: &str = "luminous-nixward-activation-trace-v1";
pub const ACTIVATION_TRACE_VERSION: u16 = 1;
const PLAN_DOMAIN: &[u8] = b"nixward-activation-plan-v1\0";
const TRACE_DOMAIN: &[u8] = b"nixward-activation-trace-v1\0";
const MAX_ACTIVATION_STEPS: usize = 256;
const MAX_ACTIVATION_EVENTS: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Switch,
    Test,
    Boot,
    DryActivate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InhibitorDisposition {
    Passed,
    Blocked,
    Bypassed,
}

/// Evidence about the pre-switch inhibitor comparison.
///
/// The digest fields identify the exact old/new inhibitor values and the
/// changed inhibitor names. They do not authenticate the evidence producer;
/// the ingress layer must bind this receipt to a verified local observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchInhibitorReceipt {
    pub disposition: InhibitorDisposition,
    pub checked_inhibitor_count: u32,
    pub old_values_digest: String,
    pub new_values_digest: String,
    pub changed_names_digest: String,
    pub bypass_authorization_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStateSnapshot {
    pub running_generation_digest: String,
    pub boot_default_generation_digest: String,
    pub boot_id: String,
    pub state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationTarget {
    /// Exact immutable Nix store path, not a mutable channel or profile name.
    pub system_closure_path: String,
    pub system_closure_digest: String,
    /// Digest that identifies the intended NixOS generation/profile state.
    pub generation_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStepKind {
    CheckInhibitors,
    ValidateClosure,
    SwitchToConfiguration,
    DryActivationPreview,
    StopUnit,
    RunActivationScript,
    DaemonReexec,
    DaemonReload,
    ReloadUnit,
    RestartUnit,
    StartUnit,
    BootloaderUpdate,
    ProbePostState,
    Compensation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedActivationStep {
    pub step_id: String,
    pub kind: ActivationStepKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPlan {
    pub schema: String,
    pub version: u16,
    pub transaction_id: String,
    pub target_machine_digest: String,
    pub mode: ActivationMode,
    pub target: ActivationTarget,
    pub pre_state: HostStateSnapshot,
    /// NixOS release and exact switch-to-configuration program provenance.
    pub nixos_release: String,
    pub activation_semantics_revision: String,
    pub switch_to_configuration_digest: String,
    pub inhibitor_receipt: SwitchInhibitorReceipt,
    /// Bypass is denied unless policy explicitly allows it and the request
    /// carries a separate authorization digest.
    pub allow_inhibitor_bypass: bool,
    pub steps: Vec<PlannedActivationStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationEffect {
    ReadOnly,
    RuntimeMutation,
    BootDefaultMutation,
    CompositeMutation,
    Compensation,
}

impl ActivationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != ACTIVATION_TRACE_SCHEMA || self.version != ACTIVATION_TRACE_VERSION {
            return Err("unsupported activation trace schema or version".into());
        }
        if !valid_token(&self.transaction_id)
            || !valid_digest(&self.target_machine_digest)
            || !valid_digest(&self.target.system_closure_digest)
            || !valid_digest(&self.target.generation_digest)
            || !valid_digest(&self.pre_state.running_generation_digest)
            || !valid_digest(&self.pre_state.boot_default_generation_digest)
            || !valid_digest(&self.pre_state.state_digest)
            || !valid_token(&self.pre_state.boot_id)
            || !valid_token(&self.target.system_closure_path)
            || !self.target.system_closure_path.starts_with("/nix/store/")
            || self.target.system_closure_path.contains("/../")
            || self.target.system_closure_path.contains('\0')
            || !valid_token(&self.nixos_release)
            || !valid_token(&self.activation_semantics_revision)
            || !valid_digest(&self.switch_to_configuration_digest)
            || self.steps.len() < 3
            || self.steps.len() > MAX_ACTIVATION_STEPS
        {
            return Err("activation plan contains malformed or unbound identity fields".into());
        }

        let inhibitor = &self.inhibitor_receipt;
        if !valid_digest(&inhibitor.old_values_digest)
            || !valid_digest(&inhibitor.new_values_digest)
            || !valid_digest(&inhibitor.changed_names_digest)
        {
            return Err("switch inhibitor receipt contains an invalid digest".into());
        }
        match inhibitor.disposition {
            InhibitorDisposition::Passed => {
                if inhibitor.bypass_authorization_digest.is_some() {
                    return Err("passed inhibitor receipt cannot carry bypass authorization".into());
                }
            }
            InhibitorDisposition::Blocked => {
                return Err("switch inhibitor preflight blocked activation".into());
            }
            InhibitorDisposition::Bypassed => {
                if !self.allow_inhibitor_bypass
                    || !inhibitor.bypass_authorization_digest.as_deref()
                        .is_some_and(valid_digest)
                {
                    return Err("switch inhibitor bypass lacks explicit policy and authorization".into());
                }
            }
        }

        let mut ids = BTreeSet::new();
        for step in &self.steps {
            if !valid_token(&step.step_id) || !ids.insert(step.step_id.as_str()) {
                return Err("activation plan has an empty or duplicate step ID".into());
            }
        }
        if self.steps.first().map(|step| step.kind) != Some(ActivationStepKind::CheckInhibitors)
            || self.steps.get(1).map(|step| step.kind) != Some(ActivationStepKind::ValidateClosure)
            || self.steps.last().map(|step| step.kind) != Some(ActivationStepKind::ProbePostState)
        {
            return Err("activation plan must start with inhibitor/closure preflight and end with a post-state probe".into());
        }

        let switch_count = self.steps.iter()
            .filter(|step| step.kind == ActivationStepKind::SwitchToConfiguration).count();
        let dry_preview_count = self.steps.iter()
            .filter(|step| step.kind == ActivationStepKind::DryActivationPreview).count();
        let inhibitor_count = self.steps.iter()
            .filter(|step| step.kind == ActivationStepKind::CheckInhibitors).count();
        let closure_check_count = self.steps.iter()
            .filter(|step| step.kind == ActivationStepKind::ValidateClosure).count();
        let post_probe_count = self.steps.iter()
            .filter(|step| step.kind == ActivationStepKind::ProbePostState).count();
        if inhibitor_count != 1 || closure_check_count != 1 || post_probe_count != 1 {
            return Err("activation plan must contain exactly one inhibitor check, closure validation and post-state probe".into());
        }
        match self.mode {
            ActivationMode::DryActivate if dry_preview_count != 1 || switch_count != 0 => {
                return Err("dry-activate plans require a preview step and cannot dispatch activation".into());
            }
            ActivationMode::Switch | ActivationMode::Test | ActivationMode::Boot
                if switch_count != 1 || dry_preview_count != 0 =>
            {
                return Err("switch/test/boot plans require exactly the activation dispatch step".into());
            }
            _ => {}
        }

        for step in &self.steps {
            match (self.mode, step.kind) {
                (ActivationMode::DryActivate, ActivationStepKind::StopUnit
                    | ActivationStepKind::RunActivationScript
                    | ActivationStepKind::DaemonReexec
                    | ActivationStepKind::DaemonReload
                    | ActivationStepKind::ReloadUnit
                    | ActivationStepKind::RestartUnit
                    | ActivationStepKind::StartUnit
                    | ActivationStepKind::BootloaderUpdate
                    | ActivationStepKind::Compensation) => {
                    return Err("dry-activate plan contains a mutating step".into());
                }
                (ActivationMode::Test, ActivationStepKind::BootloaderUpdate) => {
                    return Err("test activation cannot mutate the boot default".into());
                }
                (ActivationMode::Boot, ActivationStepKind::StopUnit
                    | ActivationStepKind::RunActivationScript
                    | ActivationStepKind::DaemonReexec
                    | ActivationStepKind::DaemonReload
                    | ActivationStepKind::ReloadUnit
                    | ActivationStepKind::RestartUnit
                    | ActivationStepKind::StartUnit
                    | ActivationStepKind::Compensation) => {
                    return Err("boot activation plan contains a running-system mutation".into());
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("cannot serialize activation plan: {error}"))?;
        Ok(digest_domain(PLAN_DOMAIN, &bytes))
    }

    fn effect_for(&self, kind: ActivationStepKind) -> ActivationEffect {
        match kind {
            ActivationStepKind::CheckInhibitors
            | ActivationStepKind::ValidateClosure
            | ActivationStepKind::DryActivationPreview
            | ActivationStepKind::ProbePostState => ActivationEffect::ReadOnly,
            ActivationStepKind::SwitchToConfiguration => match self.mode {
                ActivationMode::Switch => ActivationEffect::CompositeMutation,
                ActivationMode::Test => ActivationEffect::RuntimeMutation,
                ActivationMode::Boot => ActivationEffect::BootDefaultMutation,
                ActivationMode::DryActivate => ActivationEffect::ReadOnly,
            },
            ActivationStepKind::StopUnit
            | ActivationStepKind::RunActivationScript
            | ActivationStepKind::DaemonReexec
            | ActivationStepKind::DaemonReload
            | ActivationStepKind::ReloadUnit
            | ActivationStepKind::RestartUnit
            | ActivationStepKind::StartUnit => ActivationEffect::RuntimeMutation,
            ActivationStepKind::BootloaderUpdate => ActivationEffect::BootDefaultMutation,
            ActivationStepKind::Compensation => ActivationEffect::Compensation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationTransition {
    Started,
    Completed,
    Failed,
    Unknown,
    ReconciledCompleted,
    ReconciledFailed,
    Compensated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvent {
    pub sequence: u64,
    pub at_monotonic_ns: u64,
    pub boot_id: String,
    pub step_id: String,
    pub kind: ActivationStepKind,
    pub effect: ActivationEffect,
    pub transition: ActivationTransition,
    pub receipt_digest: Option<String>,
    pub reason_digest: Option<String>,
    pub observed_state_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationTrace {
    pub schema: String,
    pub version: u16,
    pub plan: ActivationPlan,
    pub events: Vec<ActivationEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPostState {
    pub running_generation_digest: String,
    pub boot_default_generation_digest: String,
    pub boot_id: String,
    pub state_digest: String,
    /// Health of the current running OS; this does not assert that a future
    /// boot into the selected default generation has succeeded.
    pub running_system_healthy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationOutcome {
    Verified,
    VerifiedWithInhibitorBypass,
    SafeHold,
    ReconciliationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvaluation {
    pub outcome: ActivationOutcome,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub running_generation_matches_target: bool,
    pub boot_default_matches_target: bool,
    pub running_system_healthy: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayedStepState {
    Started,
    Completed,
    Failed,
    Unknown,
    ReconciledCompleted,
    ReconciledFailed,
    Compensated,
}

#[derive(Debug, Clone)]
struct ReplayedStep {
    kind: ActivationStepKind,
    effect: ActivationEffect,
    state: ReplayedStepState,
}

impl ActivationTrace {
    pub fn new(plan: ActivationPlan) -> Result<Self, String> {
        plan.validate()?;
        Ok(Self {
            schema: ACTIVATION_TRACE_SCHEMA.to_string(),
            version: ACTIVATION_TRACE_VERSION,
            plan,
            events: Vec::new(),
        })
    }

    /// Append one event only when it is a valid next transition. The previous
    /// event history is immutable and remains available for independent replay.
    pub fn append(&mut self, event: ActivationEvent) -> Result<(), String> {
        if self.events.len() >= MAX_ACTIVATION_EVENTS {
            return Err("activation trace event limit exceeded".into());
        }
        let mut candidate = self.events.clone();
        candidate.push(event);
        replay_events(&self.plan, &candidate)?;
        self.events = candidate;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != ACTIVATION_TRACE_SCHEMA || self.version != ACTIVATION_TRACE_VERSION {
            return Err("unsupported activation trace envelope".into());
        }
        replay_events(&self.plan, &self.events).map(|_| ())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("cannot serialize activation trace: {error}"))?;
        Ok(digest_domain(TRACE_DOMAIN, &bytes))
    }

    pub fn evaluate(&self, post_state: &ActivationPostState) -> Result<ActivationEvaluation, String> {
        self.validate()?;
        if !valid_digest(&post_state.running_generation_digest)
            || !valid_digest(&post_state.boot_default_generation_digest)
            || !valid_digest(&post_state.state_digest)
            || !valid_token(&post_state.boot_id)
        {
            return Err("post-state observation is malformed".into());
        }
        let replayed = replay_events(&self.plan, &self.events)?;
        let mut blockers = Vec::new();

        let completed_steps = replayed.values().filter(|step| {
            matches!(
                step.state,
                ReplayedStepState::Completed | ReplayedStepState::ReconciledCompleted
            )
        }).count();
        let unresolved = replayed.values().any(|step| {
            matches!(step.state, ReplayedStepState::Started | ReplayedStepState::Unknown)
        });
        let failed = replayed.values().any(|step| {
            matches!(step.state, ReplayedStepState::Failed | ReplayedStepState::ReconciledFailed)
        });
        let compensated = replayed.values().any(|step| step.state == ReplayedStepState::Compensated);

        if unresolved {
            blockers.push("one or more activation steps have an unknown or in-flight outcome".into());
        }
        if failed {
            blockers.push("one or more activation steps failed and were not successfully reconciled".into());
        }
        if compensated {
            blockers.push("one or more activation steps required compensation; verify convergence independently".into());
        }

        let last_boot_id = self.events.last().map(|event| event.boot_id.as_str())
            .unwrap_or(self.plan.pre_state.boot_id.as_str());
        if post_state.boot_id != last_boot_id {
            blockers.push("post-state observation belongs to a different boot than the last activation receipt".into());
        }

        let post_probe = self.events.iter().rev().find(|event| {
            event.kind == ActivationStepKind::ProbePostState
                && matches!(
                    event.transition,
                    ActivationTransition::Completed | ActivationTransition::ReconciledCompleted
                )
        });
        if !post_probe.is_some_and(|event| {
            event.observed_state_digest.as_deref() == Some(post_state.state_digest.as_str())
        }) {
            blockers.push("no completed post-state probe matches the supplied host snapshot".into());
        }

        let running_matches = match self.plan.mode {
            ActivationMode::Switch | ActivationMode::Test =>
                post_state.running_generation_digest == self.plan.target.generation_digest,
            ActivationMode::Boot | ActivationMode::DryActivate =>
                post_state.running_generation_digest == self.plan.pre_state.running_generation_digest,
        };
        let boot_default_matches = match self.plan.mode {
            ActivationMode::Switch | ActivationMode::Boot =>
                post_state.boot_default_generation_digest == self.plan.target.generation_digest,
            ActivationMode::Test | ActivationMode::DryActivate =>
                post_state.boot_default_generation_digest == self.plan.pre_state.boot_default_generation_digest,
        };
        if !running_matches {
            blockers.push("running generation does not match the activation-mode postcondition".into());
        }
        if !boot_default_matches {
            blockers.push("boot default does not match the activation-mode postcondition".into());
        }
        if !post_state.running_system_healthy {
            blockers.push("post-state health probe did not establish a healthy running system".into());
        }

        let outcome = if unresolved || failed || compensated
            || !running_matches || !boot_default_matches || !post_state.running_system_healthy
            || post_probe.is_none()
            || !blockers.is_empty()
        {
            if failed || compensated {
                ActivationOutcome::SafeHold
            } else {
                ActivationOutcome::ReconciliationRequired
            }
        } else if self.plan.inhibitor_receipt.disposition == InhibitorDisposition::Bypassed {
            ActivationOutcome::VerifiedWithInhibitorBypass
        } else {
            ActivationOutcome::Verified
        };

        Ok(ActivationEvaluation {
            outcome,
            completed_steps,
            total_steps: self.plan.steps.len(),
            running_generation_matches_target: running_matches,
            boot_default_matches_target: boot_default_matches,
            running_system_healthy: post_state.running_system_healthy,
            blockers,
        })
    }
}

fn replay_events(
    plan: &ActivationPlan,
    events: &[ActivationEvent],
) -> Result<BTreeMap<String, ReplayedStep>, String> {
    plan.validate()?;
    if events.len() > MAX_ACTIVATION_EVENTS {
        return Err("activation trace event limit exceeded".into());
    }
    let plan_steps = plan.steps.iter()
        .enumerate()
        .map(|(index, step)| (step.step_id.as_str(), (index, step)))
        .collect::<BTreeMap<_, _>>();
    let mut states = BTreeMap::<String, ReplayedStep>::new();
    let mut active_boot_id = plan.pre_state.boot_id.clone();
    let mut last_monotonic_ns = 0_u64;

    for (index, event) in events.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if event.sequence != expected_sequence || !valid_token(&event.boot_id) {
            return Err("activation event sequence or boot identity is invalid".into());
        }
        let Some((plan_index, planned)) = plan_steps.get(event.step_id.as_str()) else {
            return Err("activation event references an unplanned step".into());
        };
        if event.kind != planned.kind || event.effect != plan.effect_for(planned.kind) {
            return Err("activation event kind/effect differs from the immutable plan".into());
        }

        if event.boot_id != active_boot_id {
            if !matches!(
                event.transition,
                ActivationTransition::ReconciledCompleted
                    | ActivationTransition::ReconciledFailed
                    | ActivationTransition::Compensated
            ) {
                return Err("boot ID changed without an explicit reconciliation receipt".into());
            }
            active_boot_id = event.boot_id.clone();
            last_monotonic_ns = 0;
        }
        if event.at_monotonic_ns < last_monotonic_ns {
            return Err("monotonic activation timestamps moved backwards within one boot".into());
        }
        last_monotonic_ns = event.at_monotonic_ns;

        match event.transition {
            ActivationTransition::Started => {
                if states.contains_key(&event.step_id) {
                    return Err("activation step was started more than once".into());
                }
                for prior in plan.steps.iter().take(*plan_index) {
                    let Some(state) = states.get(&prior.step_id) else {
                        return Err("activation step started before a prior planned step".into());
                    };
                    if !matches!(
                        state.state,
                        ReplayedStepState::Completed | ReplayedStepState::ReconciledCompleted
                    ) {
                        return Err("activation step started while a prior step is unresolved or failed".into());
                    }
                }
                if event.receipt_digest.is_some()
                    || event.reason_digest.is_some()
                    || event.observed_state_digest.is_some()
                {
                    return Err("step-start event cannot carry terminal evidence".into());
                }
                states.insert(event.step_id.clone(), ReplayedStep {
                    kind: event.kind,
                    effect: event.effect,
                    state: ReplayedStepState::Started,
                });
            }
            ActivationTransition::Completed => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("step completed without a start receipt")?;
                if state.state != ReplayedStepState::Started
                    || !event.receipt_digest.as_deref().is_some_and(valid_digest)
                    || event.reason_digest.is_some()
                {
                    return Err("step completion lacks a valid receipt or has an invalid transition".into());
                }
                if event.kind == ActivationStepKind::ProbePostState
                    && !event.observed_state_digest.as_deref().is_some_and(valid_digest)
                {
                    return Err("post-state probe completion lacks an observed state digest".into());
                }
                state.state = ReplayedStepState::Completed;
            }
            ActivationTransition::Failed => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("step failed without a start receipt")?;
                if state.state != ReplayedStepState::Started
                    || !event.reason_digest.as_deref().is_some_and(valid_digest)
                    || event.receipt_digest.is_some()
                {
                    return Err("step failure lacks a reason digest or has an invalid transition".into());
                }
                state.state = ReplayedStepState::Failed;
            }
            ActivationTransition::Unknown => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("unknown outcome recorded without a start receipt")?;
                if state.state != ReplayedStepState::Started
                    || !event.reason_digest.as_deref().is_some_and(valid_digest)
                    || event.receipt_digest.is_some()
                {
                    return Err("unknown outcome lacks a reason digest or has an invalid transition".into());
                }
                state.state = ReplayedStepState::Unknown;
            }
            ActivationTransition::ReconciledCompleted => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("reconciliation has no earlier unknown step")?;
                if state.state != ReplayedStepState::Unknown
                    || !event.receipt_digest.as_deref().is_some_and(valid_digest)
                    || !event.observed_state_digest.as_deref().is_some_and(valid_digest)
                {
                    return Err("reconciled completion lacks receipt/state evidence".into());
                }
                state.state = ReplayedStepState::ReconciledCompleted;
            }
            ActivationTransition::ReconciledFailed => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("reconciliation has no earlier unknown step")?;
                if state.state != ReplayedStepState::Unknown
                    || !event.reason_digest.as_deref().is_some_and(valid_digest)
                    || !event.observed_state_digest.as_deref().is_some_and(valid_digest)
                {
                    return Err("reconciled failure lacks reason/state evidence".into());
                }
                state.state = ReplayedStepState::ReconciledFailed;
            }
            ActivationTransition::Compensated => {
                let state = states.get_mut(&event.step_id)
                    .ok_or("compensation has no earlier failed/unknown step")?;
                if !matches!(state.state, ReplayedStepState::Failed | ReplayedStepState::Unknown)
                    || !event.receipt_digest.as_deref().is_some_and(valid_digest)
                    || !event.observed_state_digest.as_deref().is_some_and(valid_digest)
                {
                    return Err("compensation lacks receipt/state evidence or has an invalid transition".into());
                }
                state.state = ReplayedStepState::Compensated;
            }
        }
    }
    Ok(states)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && !value.contains("..")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn plan(mode: ActivationMode) -> ActivationPlan {
        let dispatch = match mode {
            ActivationMode::DryActivate => PlannedActivationStep {
                step_id: "dry-preview".into(),
                kind: ActivationStepKind::DryActivationPreview,
            },
            _ => PlannedActivationStep {
                step_id: "activation-dispatch".into(),
                kind: ActivationStepKind::SwitchToConfiguration,
            },
        };
        ActivationPlan {
            schema: ACTIVATION_TRACE_SCHEMA.into(),
            version: ACTIVATION_TRACE_VERSION,
            transaction_id: "tx-activation-1".into(),
            target_machine_digest: digest('1'),
            mode,
            target: ActivationTarget {
                system_closure_path: "/nix/store/00000000000000000000000000000000-nixos-system-test".into(),
                system_closure_digest: digest('2'),
                generation_digest: digest('3'),
            },
            pre_state: HostStateSnapshot {
                running_generation_digest: digest('4'),
                boot_default_generation_digest: digest('5'),
                boot_id: "boot-before".into(),
                state_digest: digest('6'),
            },
            nixos_release: "26.05".into(),
            activation_semantics_revision: "switch-to-configuration-ng-v1".into(),
            switch_to_configuration_digest: digest('7'),
            inhibitor_receipt: SwitchInhibitorReceipt {
                disposition: InhibitorDisposition::Passed,
                checked_inhibitor_count: 2,
                old_values_digest: digest('8'),
                new_values_digest: digest('9'),
                changed_names_digest: digest('a'),
                bypass_authorization_digest: None,
            },
            allow_inhibitor_bypass: false,
            steps: vec![
                PlannedActivationStep { step_id: "inhibitors".into(), kind: ActivationStepKind::CheckInhibitors },
                PlannedActivationStep { step_id: "closure".into(), kind: ActivationStepKind::ValidateClosure },
                dispatch,
                PlannedActivationStep { step_id: "post-state".into(), kind: ActivationStepKind::ProbePostState },
            ],
        }
    }

    fn post_state(plan: &ActivationPlan) -> ActivationPostState {
        let (running, boot_default) = match plan.mode {
            ActivationMode::Switch => (plan.target.generation_digest.clone(), plan.target.generation_digest.clone()),
            ActivationMode::Test => (plan.target.generation_digest.clone(), plan.pre_state.boot_default_generation_digest.clone()),
            ActivationMode::Boot => (plan.pre_state.running_generation_digest.clone(), plan.target.generation_digest.clone()),
            ActivationMode::DryActivate => (plan.pre_state.running_generation_digest.clone(), plan.pre_state.boot_default_generation_digest.clone()),
        };
        ActivationPostState {
            running_generation_digest: running,
            boot_default_generation_digest: boot_default,
            boot_id: plan.pre_state.boot_id.clone(),
            state_digest: digest('b'),
            running_system_healthy: true,
        }
    }

    fn completed_event(plan: &ActivationPlan, seq: u64, step: &PlannedActivationStep, at: u64, transition: ActivationTransition, receipt: Option<String>, observed: Option<String>) -> ActivationEvent {
        ActivationEvent {
            sequence: seq,
            at_monotonic_ns: at,
            boot_id: plan.pre_state.boot_id.clone(),
            step_id: step.step_id.clone(),
            kind: step.kind,
            effect: plan.effect_for(step.kind),
            transition,
            receipt_digest: receipt,
            reason_digest: None,
            observed_state_digest: observed,
        }
    }

    fn complete_trace(mode: ActivationMode) -> (ActivationTrace, ActivationPostState) {
        let p = plan(mode);
        let post = post_state(&p);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let mut seq = 1;
        let mut at = 10;
        for step in &p.steps {
            trace.append(completed_event(&p, seq, step, at, ActivationTransition::Started, None, None)).unwrap();
            seq += 1;
            at += 10;
            let observed = (step.kind == ActivationStepKind::ProbePostState).then(|| post.state_digest.clone());
            trace.append(completed_event(&p, seq, step, at, ActivationTransition::Completed, Some(digest('c')), observed)).unwrap();
            seq += 1;
            at += 10;
        }
        (trace, post)
    }


    #[test]
    fn duplicate_dispatch_step_is_rejected() {
        let mut p = plan(ActivationMode::Switch);
        p.steps.insert(3, PlannedActivationStep {
            step_id: "activation-dispatch-duplicate".into(),
            kind: ActivationStepKind::SwitchToConfiguration,
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn boot_mode_reports_boot_default_write_without_claiming_future_boot_health() {
        let (trace, post) = complete_trace(ActivationMode::Boot);
        let result = trace.evaluate(&post).unwrap();
        assert_eq!(result.outcome, ActivationOutcome::Verified);
        assert!(result.boot_default_matches_target);
        assert!(!result.running_generation_matches_target);
        assert!(result.running_system_healthy);
    }

    #[test]
    fn mode_specific_switch_postcondition_requires_running_and_boot_default() {
        let (trace, post) = complete_trace(ActivationMode::Switch);
        assert_eq!(trace.evaluate(&post).unwrap().outcome, ActivationOutcome::Verified);
    }

    #[test]
    fn test_activation_preserves_boot_default() {
        let (trace, post) = complete_trace(ActivationMode::Test);
        assert_eq!(trace.evaluate(&post).unwrap().outcome, ActivationOutcome::Verified);
        let mut wrong = post;
        wrong.boot_default_generation_digest = digest('d');
        assert_eq!(trace.evaluate(&wrong).unwrap().outcome, ActivationOutcome::ReconciliationRequired);
    }

    #[test]
    fn boot_activation_changes_only_boot_default() {
        let (trace, post) = complete_trace(ActivationMode::Boot);
        assert_eq!(trace.evaluate(&post).unwrap().outcome, ActivationOutcome::Verified);
        let mut wrong = post;
        wrong.running_generation_digest = digest('3');
        assert_eq!(trace.evaluate(&wrong).unwrap().outcome, ActivationOutcome::ReconciliationRequired);
    }

    #[test]
    fn dry_activate_is_read_only_and_preserves_both_generation_pointers() {
        let (trace, post) = complete_trace(ActivationMode::DryActivate);
        assert_eq!(trace.evaluate(&post).unwrap().outcome, ActivationOutcome::Verified);
        let mut invalid = plan(ActivationMode::DryActivate);
        invalid.steps.insert(2, PlannedActivationStep {
            step_id: "restart".into(), kind: ActivationStepKind::RestartUnit,
        });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn inhibitor_block_is_a_hard_plan_rejection() {
        let mut p = plan(ActivationMode::Switch);
        p.inhibitor_receipt.disposition = InhibitorDisposition::Blocked;
        assert!(p.validate().is_err());
    }

    #[test]
    fn inhibitor_bypass_requires_explicit_policy_and_authorization_receipt() {
        let mut p = plan(ActivationMode::Switch);
        p.inhibitor_receipt.disposition = InhibitorDisposition::Bypassed;
        assert!(p.validate().is_err());
        p.allow_inhibitor_bypass = true;
        p.inhibitor_receipt.bypass_authorization_digest = Some(digest('f'));
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let post = post_state(&p);
        let mut seq = 1;
        for step in &p.steps {
            trace.append(completed_event(&p, seq, step, seq * 10, ActivationTransition::Started, None, None)).unwrap();
            seq += 1;
            let observed = (step.kind == ActivationStepKind::ProbePostState).then(|| post.state_digest.clone());
            trace.append(completed_event(&p, seq, step, seq * 10, ActivationTransition::Completed, Some(digest('c')), observed)).unwrap();
            seq += 1;
        }
        assert_eq!(trace.evaluate(&post).unwrap().outcome, ActivationOutcome::VerifiedWithInhibitorBypass);
    }

    #[test]
    fn unknown_step_outcome_requires_reconciliation() {
        let mut p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let first = &p.steps[0];
        trace.append(completed_event(&p, 1, first, 10, ActivationTransition::Started, None, None)).unwrap();
        trace.append(ActivationEvent {
            sequence: 2, at_monotonic_ns: 20, boot_id: p.pre_state.boot_id.clone(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::Unknown, receipt_digest: None,
            reason_digest: Some(digest('d')), observed_state_digest: None,
        }).unwrap();
        assert_eq!(trace.evaluate(&post_state(&p)).unwrap().outcome, ActivationOutcome::ReconciliationRequired);
    }

    #[test]
    fn boot_id_change_requires_explicit_reconciliation_event() {
        let mut p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let first = &p.steps[0];
        trace.append(completed_event(&p, 1, first, 10, ActivationTransition::Started, None, None)).unwrap();
        let invalid = ActivationEvent {
            sequence: 2, at_monotonic_ns: 1, boot_id: "boot-after".into(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::Completed, receipt_digest: Some(digest('c')),
            reason_digest: None, observed_state_digest: None,
        };
        assert!(trace.append(invalid).is_err());
    }

    #[test]
    fn reconciliation_may_reset_monotonic_clock_only_with_new_boot_id() {
        let mut p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let first = &p.steps[0];
        trace.append(completed_event(&p, 1, first, 100, ActivationTransition::Started, None, None)).unwrap();
        trace.append(ActivationEvent {
            sequence: 2, at_monotonic_ns: 110, boot_id: p.pre_state.boot_id.clone(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::Unknown, receipt_digest: None,
            reason_digest: Some(digest('d')), observed_state_digest: None,
        }).unwrap();
        let rec = ActivationEvent {
            sequence: 3, at_monotonic_ns: 2, boot_id: "boot-after".into(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::ReconciledCompleted,
            receipt_digest: Some(digest('c')), reason_digest: None,
            observed_state_digest: Some(digest('e')),
        };
        trace.append(rec).unwrap();
    }

    #[test]
    fn completion_requires_a_prior_start_and_exact_step_kind() {
        let mut p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let first = &p.steps[0];
        assert!(trace.append(completed_event(&p, 1, first, 10, ActivationTransition::Completed, Some(digest('c')), None)).is_err());
    }

    #[test]
    fn out_of_order_step_start_is_rejected() {
        let p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let second = &p.steps[1];
        assert!(trace.append(completed_event(&p, 1, second, 10, ActivationTransition::Started, None, None)).is_err());
    }

    #[test]
    fn trace_digest_is_deterministic_and_changes_when_receipt_changes() {
        let (trace, _) = complete_trace(ActivationMode::Switch);
        let first = trace.digest().unwrap();
        assert_eq!(first, trace.digest().unwrap());
        let mut changed = trace.clone();
        changed.events[1].receipt_digest = Some(digest('d'));
        assert_ne!(first, digest_domain(TRACE_DOMAIN, &serde_json::to_vec(&changed).unwrap()));
    }

    #[test]
    fn malformed_generation_digest_is_rejected() {
        let mut p = plan(ActivationMode::Switch);
        p.target.system_closure_digest = digest('f');
        assert!(p.validate().is_ok());
        p.target.generation_digest = "not-a-digest".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn compensation_is_not_silently_reported_as_success() {
        let mut p = plan(ActivationMode::Switch);
        let mut trace = ActivationTrace::new(p.clone()).unwrap();
        let first = &p.steps[0];
        trace.append(completed_event(&p, 1, first, 10, ActivationTransition::Started, None, None)).unwrap();
        trace.append(ActivationEvent {
            sequence: 2, at_monotonic_ns: 20, boot_id: p.pre_state.boot_id.clone(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::Failed, receipt_digest: None,
            reason_digest: Some(digest('d')), observed_state_digest: None,
        }).unwrap();
        trace.append(ActivationEvent {
            sequence: 3, at_monotonic_ns: 30, boot_id: p.pre_state.boot_id.clone(),
            step_id: first.step_id.clone(), kind: first.kind, effect: p.effect_for(first.kind),
            transition: ActivationTransition::Compensated, receipt_digest: Some(digest('e')),
            reason_digest: None, observed_state_digest: Some(digest('f')),
        }).unwrap();
        assert_eq!(trace.evaluate(&post_state(&p)).unwrap().outcome, ActivationOutcome::SafeHold);
    }
}
