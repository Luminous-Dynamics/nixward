// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! NixOS-Specific Action Patterns
//!
//! Provides NixOS-aware action execution with:
//! - Generation-based rollback support
//! - Evidence-bound authorization for modifying operations
//! - Command classification and safety scoring
//! - JSON output mode for structured results

use super::authority_replay::AuthorityReplayLedger;
use super::change_covenant::{ApprovalEvidenceKind, ChangeAuthorization, ChangePlan};
use super::generation_manager::GenerationManager;
use crate::traits::{ActionType, ConsciousnessThresholds, PhiAwareScoring};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{info, warn};

/// NixOS-specific commands with structured parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NixOSCommand {
    /// nixos-rebuild switch (system-wide change)
    RebuildSwitch {
        flake: Option<String>,
        extra_args: Vec<String>,
    },
    /// nixos-rebuild test (temporary, no boot entry)
    RebuildTest {
        flake: Option<String>,
        extra_args: Vec<String>,
    },
    /// nixos-rebuild boot (next reboot only)
    RebuildBoot {
        flake: Option<String>,
        extra_args: Vec<String>,
    },
    /// Activate one already-realized immutable NixOS system closure.
    ActivateSystemClosure {
        store_path: String,
        action: SystemActivation,
    },
    /// nix-env -i (user package install)
    EnvInstall { packages: Vec<String> },
    /// nix-env -e (user package remove)
    EnvRemove { packages: Vec<String> },
    /// nix-env --rollback (user profile rollback)
    EnvRollback,
    /// nix search (package search)
    Search { query: String, json: bool },
    /// nix-channel operations
    Channel { operation: ChannelOperation },
    /// nix flake operations
    Flake { operation: FlakeOperation },
    /// home-manager switch
    HomeManagerSwitch { flake: Option<String> },
    /// nix-collect-garbage
    CollectGarbage {
        older_than_days: Option<u32>,
        delete_all: bool,
    },
    /// Custom command with safety classification
    Custom {
        command: String,
        args: Vec<String>,
        safety_level: SafetyLevel,
    },
}

/// Channel operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelOperation {
    Update { channel: Option<String> },
    Add { url: String, name: String },
    Remove { name: String },
    List,
}

/// Flake operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlakeOperation {
    Update { inputs: Vec<String> },
    Lock { inputs: Vec<String> },
    Show,
    Check,
}

/// switch-to-configuration action for an immutable system closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemActivation {
    Switch,
    Test,
    Boot,
}

impl SystemActivation {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Switch => "switch",
            Self::Test => "test",
            Self::Boot => "boot",
        }
    }
}

/// Safety levels for commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyLevel {
    ReadOnly,
    UserModify,
    SystemModify,
    SystemCritical,
    Destructive,
}

impl SafetyLevel {
    /// Convert to the cognitive action class used for advisory decision-quality thresholds.
    pub fn to_action_type(&self) -> ActionType {
        match self {
            Self::ReadOnly => ActionType::BasicQuery,
            Self::UserModify => ActionType::StateModifying,
            Self::SystemModify => ActionType::SystemCritical,
            Self::SystemCritical => ActionType::SystemCritical,
            Self::Destructive => ActionType::Irreversible,
        }
    }

    /// Advisory decision-quality threshold for this safety class.
    ///
    /// This value never grants execution authority. Modifying commands still
    /// require an [`ExecutionAuthorization`] bound to the exact command.
    pub fn recommended_decision_quality(&self) -> f32 {
        ConsciousnessThresholds::default().threshold_for(self.to_action_type())
    }
}

/// Hard architectural execution policy for the sovereign host.
///
/// A ChangePlan can authorize a permitted mutation, but it cannot legalize an
/// operation that violates the Software Ingress Covenant. In particular,
/// imperative package/profile installation, mutable channels, arbitrary shell
/// execution, and persistent `systemctl enable/disable` are forbidden even
/// under an otherwise valid execution capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostExecutionPolicy {
    Allowed,
    Forbidden { reason: String },
}

impl HostExecutionPolicy {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::Forbidden { reason } => Some(reason),
        }
    }
}

impl NixOSCommand {
    /// Create a Custom command with auto-classified safety level.
    ///
    /// Uses `classify_command_destructiveness` from `phi_gate` to infer
    /// the safety level from the command string, rather than requiring
    /// the caller to specify it manually.
    pub fn custom_auto(command: &str, args: Vec<String>) -> Self {
        let full_cmd = if args.is_empty() {
            command.to_string()
        } else {
            format!("{} {}", command, args.join(" "))
        };
        let safety_level = super::phi_gate::classify_command_destructiveness(&full_cmd);
        Self::Custom {
            command: command.to_string(),
            args,
            safety_level,
        }
    }

    /// Enforce the sovereign host mutation boundary before authorization.
    ///
    /// This policy is intentionally stricter than `SafetyLevel`: a forbidden
    /// operation remains forbidden even if a user cryptographically signs it.
    pub fn host_execution_policy(&self) -> HostExecutionPolicy {
        use HostExecutionPolicy::{Allowed, Forbidden};

        match self {
            // `nix-env` user profiles are generational but are still ambient,
            // out-of-band state relative to the Holon's flake/Home Manager
            // lineage. Software changes must be expressed declaratively.
            Self::EnvInstall { .. } | Self::EnvRemove { .. } | Self::EnvRollback => Forbidden {
                reason: "imperative nix-env profile mutation is outside the sovereign declarative state; express software through the Software Ingress Covenant".into(),
            },

            // Mutable channels are a second dependency graph outside flake.lock.
            Self::Channel {
                operation: ChannelOperation::Update { .. }
                    | ChannelOperation::Add { .. }
                    | ChannelOperation::Remove { .. },
            } => Forbidden {
                reason: "mutable nix-channel state is forbidden; sovereign systems use source-policy-bound flake inputs and candidate-built lock updates".into(),
            },
            Self::Channel {
                operation: ChannelOperation::List,
            } => Allowed,

            // Direct lock mutation bypasses the Update Steward's isolated
            // candidate, source-drift check, future-Nix probe and evidence chain.
            Self::Flake {
                operation: FlakeOperation::Update { .. } | FlakeOperation::Lock { .. },
            } => Forbidden {
                reason: "direct flake lock mutation is forbidden; use the Symthaea Update Steward candidate path".into(),
            },
            Self::Flake {
                operation: FlakeOperation::Show | FlakeOperation::Check,
            } => Allowed,

            // A Home Manager switch is declarative only when the exact flake
            // source is explicit. Ambient discovery would create an unbound
            // user-state mutation.
            Self::HomeManagerSwitch { flake: None } => Forbidden {
                reason: "home-manager switch requires an explicit flake reference so user state is provenance-bound".into(),
            },
            Self::HomeManagerSwitch { flake: Some(_) } => Allowed,

            // `Custom` exists for legacy internal call sites only. It is not an
            // arbitrary command escape hatch. Admit a tiny typed-by-shape
            // compatibility set while those callers migrate to dedicated enum
            // variants; everything else fails closed.
            Self::Custom { command, args, .. } => {
                match command.as_str() {
                    "systemctl" => {
                        let action = args.first().map(String::as_str).unwrap_or("");
                        if matches!(action, "start" | "stop" | "restart" | "reload")
                            && args.len() == 2
                        {
                            Allowed
                        } else {
                            Forbidden {
                                reason: "legacy systemctl compatibility permits only transient start/stop/restart/reload; enable/disable and arbitrary systemctl mutation must be declarative".into(),
                            }
                        }
                    }
                    "nixos-rebuild" if args.len() == 2 && args[0] == "switch" && args[1] == "--rollback" => Forbidden {
                        reason: "ambient nixos-rebuild rollback is forbidden; recovery must target an exact immutable system closure".into(),
                    },
                    "nix-env" if is_system_generation_maintenance(args) => Forbidden {
                        reason: "ambient system-generation profile mutation is forbidden; resolve the exact generation closure and activate it immutably".into(),
                    },
                    "nix" if is_flake_init(args) => Allowed,
                    _ => Forbidden {
                        reason: format!(
                            "arbitrary host command `{command}` is forbidden by the Software Ingress Covenant"
                        ),
                    },
                }
            }

            // A privileged system mutation must operate on one exact realized
            // closure. Direct nixos-rebuild commands resolve ambient source/configuration
            // at execution time, so their command digest alone is not a sufficient
            // mutation subject. They remain available as candidate/preview vocabulary,
            // but are not executable through the host mutation boundary.
            Self::RebuildSwitch { .. }
            | Self::RebuildTest { .. }
            | Self::RebuildBoot { .. } => Forbidden {
                reason: "direct nixos-rebuild mutation is not authorized by the sovereign host boundary; realize the exact system closure first and activate it through ActivateSystemClosure".into(),
            },

            // This is the canonical privileged system mutation primitive: the
            // store path is immutable and the execution-intent authority path binds
            // source/configuration/lock identities to that exact realization.
            Self::ActivateSystemClosure { store_path, .. } => {
                if super::execution_intent::is_valid_nix_store_path(store_path) {
                    Allowed
                } else {
                    Forbidden {
                        reason: "system closure activation requires one canonical immutable /nix/store path".into(),
                    }
                }
            }

            Self::Search { .. } | Self::CollectGarbage { .. } => Allowed,
        }
    }

    /// Get the safety level of this command
    pub fn safety_level(&self) -> SafetyLevel {
        match self {
            Self::Search { .. } => SafetyLevel::ReadOnly,
            Self::Channel {
                operation: ChannelOperation::List,
            } => SafetyLevel::ReadOnly,
            Self::Flake {
                operation: FlakeOperation::Show,
            } => SafetyLevel::ReadOnly,
            Self::Flake {
                operation: FlakeOperation::Check,
            } => SafetyLevel::ReadOnly,

            Self::EnvInstall { .. } => SafetyLevel::UserModify,
            Self::EnvRemove { .. } => SafetyLevel::UserModify,
            Self::EnvRollback => SafetyLevel::UserModify,
            Self::Channel {
                operation: ChannelOperation::Update { .. },
            } => SafetyLevel::UserModify,
            Self::Channel {
                operation: ChannelOperation::Add { .. },
            } => SafetyLevel::UserModify,
            Self::Channel {
                operation: ChannelOperation::Remove { .. },
            } => SafetyLevel::UserModify,
            Self::Flake {
                operation: FlakeOperation::Update { .. },
            } => SafetyLevel::UserModify,
            Self::Flake {
                operation: FlakeOperation::Lock { .. },
            } => SafetyLevel::UserModify,
            Self::HomeManagerSwitch { .. } => SafetyLevel::UserModify,

            Self::RebuildTest { .. } => SafetyLevel::SystemModify,
            Self::RebuildBoot { .. } => SafetyLevel::SystemModify,
            Self::ActivateSystemClosure { action, .. } => match action {
                SystemActivation::Switch => SafetyLevel::SystemCritical,
                SystemActivation::Test | SystemActivation::Boot => SafetyLevel::SystemModify,
            },

            Self::RebuildSwitch { .. } => SafetyLevel::SystemCritical,

            Self::CollectGarbage { .. } => SafetyLevel::Destructive,

            Self::Custom { safety_level, .. } => *safety_level,
        }
    }

    /// Stable digest of the exact structured command.
    ///
    /// This is used to bind execution approval to the command that was actually
    /// reviewed, preventing a later plan change from reusing stale approval.
    pub fn command_digest(&self) -> [u8; 32] {
        let encoded = serde_json::to_vec(self)
            .expect("NixOSCommand serialization is infallible for in-memory variants");
        *blake3::hash(&encoded).as_bytes()
    }

    /// Get the rollback command if available
    pub fn rollback_command(&self) -> Option<NixOSCommand> {
        match self {
            Self::RebuildSwitch { .. } | Self::RebuildTest { .. } | Self::RebuildBoot { .. } => {
                Some(NixOSCommand::Custom {
                    command: "nixos-rebuild".to_string(),
                    args: vec!["switch".to_string(), "--rollback".to_string()],
                    safety_level: SafetyLevel::SystemCritical,
                })
            }
            // Exact closure activation has a transaction-bound recovery command
            // in ChangePlan::RollbackBinding. There is deliberately no generic
            // rollback fallback for this mutation class.
            Self::ActivateSystemClosure { .. } => None,
            Self::EnvInstall { .. } | Self::EnvRemove { .. } => {
                Some(NixOSCommand::EnvRollback)
            }
            Self::HomeManagerSwitch { .. } => {
                Some(NixOSCommand::Custom {
                    command: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "home-manager generations | head -2 | tail -1 | awk '{print $NF}' | xargs -I {} {}/activate".to_string(),
                    ],
                    safety_level: SafetyLevel::UserModify,
                })
            }
            _ => None,
        }
    }

    /// Convert to shell command and arguments
    pub fn to_command(&self) -> (String, Vec<String>) {
        match self {
            Self::RebuildSwitch { flake, extra_args } => {
                let flake_extra = if flake.is_some() { 2 } else { 0 };
                let mut args = Vec::with_capacity(1 + flake_extra + extra_args.len());
                args.push("switch".to_string());
                if let Some(f) = flake {
                    args.push("--flake".to_string());
                    args.push(f.clone());
                }
                args.extend(extra_args.iter().cloned());
                ("nixos-rebuild".to_string(), args)
            }
            Self::RebuildTest { flake, extra_args } => {
                let flake_extra = if flake.is_some() { 2 } else { 0 };
                let mut args = Vec::with_capacity(1 + flake_extra + extra_args.len());
                args.push("test".to_string());
                if let Some(f) = flake {
                    args.push("--flake".to_string());
                    args.push(f.clone());
                }
                args.extend(extra_args.iter().cloned());
                ("nixos-rebuild".to_string(), args)
            }
            Self::RebuildBoot { flake, extra_args } => {
                let flake_extra = if flake.is_some() { 2 } else { 0 };
                let mut args = Vec::with_capacity(1 + flake_extra + extra_args.len());
                args.push("boot".to_string());
                if let Some(f) = flake {
                    args.push("--flake".to_string());
                    args.push(f.clone());
                }
                args.extend(extra_args.iter().cloned());
                ("nixos-rebuild".to_string(), args)
            }
            Self::ActivateSystemClosure { store_path, action } => (
                format!("{store_path}/bin/switch-to-configuration"),
                vec![action.as_arg().to_string()],
            ),
            Self::EnvInstall { packages } => {
                let mut args = Vec::with_capacity(1 + packages.len());
                args.push("-iA".to_string());
                for pkg in packages {
                    args.push(format!("nixpkgs.{pkg}"));
                }
                ("nix-env".to_string(), args)
            }
            Self::EnvRemove { packages } => {
                let mut args = Vec::with_capacity(1 + packages.len());
                args.push("-e".to_string());
                args.extend(packages.iter().cloned());
                ("nix-env".to_string(), args)
            }
            Self::EnvRollback => ("nix-env".to_string(), vec!["--rollback".to_string()]),
            Self::Search { query, json } => {
                let cap = if *json { 4 } else { 3 };
                let mut args = Vec::with_capacity(cap);
                args.push("search".to_string());
                args.push("nixpkgs".to_string());
                args.push(query.clone());
                if *json {
                    args.push("--json".to_string());
                }
                ("nix".to_string(), args)
            }
            Self::Channel { operation } => match operation {
                ChannelOperation::Update { channel } => {
                    let cap = if channel.is_some() { 2 } else { 1 };
                    let mut args = Vec::with_capacity(cap);
                    args.push("--update".to_string());
                    if let Some(ch) = channel {
                        args.push(ch.clone());
                    }
                    ("nix-channel".to_string(), args)
                }
                ChannelOperation::Add { url, name } => (
                    "nix-channel".to_string(),
                    vec!["--add".to_string(), url.clone(), name.clone()],
                ),
                ChannelOperation::Remove { name } => (
                    "nix-channel".to_string(),
                    vec!["--remove".to_string(), name.clone()],
                ),
                ChannelOperation::List => ("nix-channel".to_string(), vec!["--list".to_string()]),
            },
            Self::Flake { operation } => match operation {
                FlakeOperation::Update { inputs } => {
                    let mut args = Vec::with_capacity(2 + inputs.len());
                    args.push("flake".to_string());
                    args.push("update".to_string());
                    args.extend(inputs.iter().cloned());
                    ("nix".to_string(), args)
                }
                FlakeOperation::Lock { inputs } => {
                    let mut args = Vec::with_capacity(2 + 2 * inputs.len());
                    args.push("flake".to_string());
                    args.push("lock".to_string());
                    for input in inputs {
                        args.push("--update-input".to_string());
                        args.push(input.clone());
                    }
                    ("nix".to_string(), args)
                }
                FlakeOperation::Show => (
                    "nix".to_string(),
                    vec!["flake".to_string(), "show".to_string()],
                ),
                FlakeOperation::Check => (
                    "nix".to_string(),
                    vec!["flake".to_string(), "check".to_string()],
                ),
            },
            Self::HomeManagerSwitch { flake } => {
                let cap = if flake.is_some() { 3 } else { 1 };
                let mut args = Vec::with_capacity(cap);
                args.push("switch".to_string());
                if let Some(f) = flake {
                    args.push("--flake".to_string());
                    args.push(f.clone());
                }
                ("home-manager".to_string(), args)
            }
            Self::CollectGarbage {
                older_than_days,
                delete_all,
            } => {
                let cap = 1
                    + if older_than_days.is_some() { 2 } else { 0 }
                    + if *delete_all { 1 } else { 0 };
                let mut args = Vec::with_capacity(cap);
                args.push("-d".to_string());
                if let Some(days) = older_than_days {
                    args.push("--delete-older-than".to_string());
                    args.push(format!("{days}d"));
                }
                if *delete_all {
                    args.push("--delete-old".to_string());
                }
                ("nix-collect-garbage".to_string(), args)
            }
            Self::Custom { command, args, .. } => (command.clone(), args.clone()),
        }
    }
}

fn is_system_generation_maintenance(args: &[String]) -> bool {
    // Compatibility for GenerationManager only. This allows switching/deleting
    // *system* generations, never installing packages into user profiles.
    let has_system_profile = args
        .windows(2)
        .any(|pair| pair[0] == "-p" && pair[1] == "/nix/var/nix/profiles/system");
    if !has_system_profile {
        return false;
    }
    matches!(
        args.first().map(String::as_str),
        Some("--switch-generation" | "--delete-generations")
    )
}

fn is_flake_init(args: &[String]) -> bool {
    matches!(args, [a, b, ..] if a == "flake" && b == "init")
        && !args.iter().any(|arg| arg == "--impure")
}

/// Evidence-bound authorization for one exact command.
///
/// This object is deliberately separate from Φ / confidence. Cognitive scores
/// may influence whether Symthaea *recommends* an action, but they do not grant
/// authority to mutate the host.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionAuthorization {
    command_digest: [u8; 32],
    rollback_digest: Option<[u8; 32]>,
    authorized_safety: SafetyLevel,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer: String,
    evidence_digest: [u8; 32],
    change_plan_digest: Option<[u8; 32]>,
    approval_evidence_kind: Option<ApprovalEvidenceKind>,
    execution_intent_digest: Option<[u8; 32]>,
    realization_plan_digest: Option<[u8; 32]>,
    authority_signer_key_id: Option<String>,
    authority_challenge_blake3: Option<String>,
    authority_replay_key: Option<String>,
    authority_subject_blake3: Option<String>,
    /// Exact recovery command bound into the original ChangePlan.
    #[serde(default)]
    recovery_command: Option<NixOSCommand>,
    automatic_read_only: bool,
    rollback_only: bool,
}

impl ExecutionAuthorization {
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Create the built-in capability for an exact read-only command.
    pub fn automatic_read_only(command: &NixOSCommand) -> Result<Self, String> {
        if command.safety_level() != SafetyLevel::ReadOnly {
            return Err("automatic authorization is restricted to ReadOnly commands".into());
        }
        Ok(Self {
            command_digest: command.command_digest(),
            rollback_digest: None,
            authorized_safety: SafetyLevel::ReadOnly,
            issued_at_ms: Self::now_ms(),
            expires_at_ms: u64::MAX,
            issuer: "nixward:automatic-read-only".into(),
            evidence_digest: [0; 32],
            change_plan_digest: None,
            approval_evidence_kind: None,
            execution_intent_digest: None,
            realization_plan_digest: None,
            authority_signer_key_id: None,
            authority_challenge_blake3: None,
            authority_replay_key: None,
            authority_subject_blake3: None,
            recovery_command: None,
            automatic_read_only: true,
            rollback_only: false,
        })
    }

    /// Derive a command capability from an approval bound to a full ChangePlan.
    ///
    /// The command, rollback command, target machine, optional config mutation,
    /// nonce, and freshness window are all covered by the plan digest before an
    /// execution capability can be created.
    pub fn from_change_authorization(
        plan: &ChangePlan,
        authorization: &ChangeAuthorization,
    ) -> Result<Self, String> {
        authorization.validate_plan(plan)?;
        let command = plan
            .command()
            .ok_or_else(|| "change plan does not contain an executable command".to_string())?;
        let recovery_command = match (
            plan.rollback().prior_system_closure(),
            plan.rollback().recovery_action(),
        ) {
            (Some(store_path), Some(action)) => Some(NixOSCommand::ActivateSystemClosure {
                store_path: store_path.to_string(),
                action,
            }),
            (None, None) => None,
            _ => return Err("change plan recovery binding is incomplete".into()),
        };

        let rollback_digest = recovery_command
            .as_ref()
            .map(NixOSCommand::command_digest)
            .or_else(|| plan.rollback().command_digest());

        if matches!(command, NixOSCommand::ActivateSystemClosure { .. })
            && recovery_command.is_none()
        {
            return Err(
                "ActivateSystemClosure authorization requires exact prior-closure recovery".into(),
            );
        }

        Ok(Self {
            command_digest: command.command_digest(),
            rollback_digest,
            authorized_safety: command.safety_level(),
            issued_at_ms: authorization.issued_at_ms(),
            expires_at_ms: authorization.expires_at_ms(),
            issuer: authorization.issuer().to_string(),
            evidence_digest: authorization.evidence_digest(),
            change_plan_digest: Some(plan.digest()),
            approval_evidence_kind: Some(authorization.approval_evidence_kind()),
            execution_intent_digest: authorization.execution_intent_digest(),
            realization_plan_digest: authorization.realization_plan_digest(),
            authority_signer_key_id: authorization
                .authority_signer_key_id()
                .map(|value| value.to_string()),
            authority_challenge_blake3: authorization
                .authority_challenge_blake3()
                .map(|value| value.to_string()),
            authority_replay_key: authorization
                .authority_replay_key()
                .map(|value| value.to_string()),
            authority_subject_blake3: authorization
                .authority_subject_blake3()
                .map(|value| value.to_string()),
            recovery_command,
            automatic_read_only: false,
            rollback_only: false,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    pub fn change_plan_digest(&self) -> Option<[u8; 32]> {
        self.change_plan_digest
    }

    pub fn execution_intent_digest(&self) -> Option<[u8; 32]> {
        self.execution_intent_digest
    }

    pub fn realization_plan_digest(&self) -> Option<[u8; 32]> {
        self.realization_plan_digest
    }

    pub fn authority_signer_key_id(&self) -> Option<&str> {
        self.authority_signer_key_id.as_deref()
    }

    pub fn authority_challenge_blake3(&self) -> Option<&str> {
        self.authority_challenge_blake3.as_deref()
    }

    pub fn authority_replay_key(&self) -> Option<&str> {
        self.authority_replay_key.as_deref()
    }

    pub fn authority_subject_blake3(&self) -> Option<&str> {
        self.authority_subject_blake3.as_deref()
    }

    fn validate_for(&self, command: &NixOSCommand) -> Result<(), String> {
        if self.command_digest != command.command_digest() {
            return Err("authorization is bound to a different command".into());
        }
        if self.authorized_safety != command.safety_level() {
            return Err("authorization safety classification does not match command".into());
        }
        if self.automatic_read_only && command.safety_level() != SafetyLevel::ReadOnly {
            return Err("automatic read-only authorization cannot mutate the system".into());
        }
        if !self.automatic_read_only && !self.rollback_only && Self::now_ms() > self.expires_at_ms {
            return Err("authorization expired".into());
        }
        if !self.automatic_read_only && self.evidence_digest == [0; 32] {
            return Err("authorization has no approval evidence".into());
        }
        let authority_backed = matches!(
            self.approval_evidence_kind,
            Some(
                ApprovalEvidenceKind::AuthoritySignature
                    | ApprovalEvidenceKind::ExecutionIntentAuthority
            )
        );
        if authority_backed
            && !self.rollback_only
            && (self.authority_signer_key_id.is_none()
                || self.authority_challenge_blake3.is_none()
                || self.authority_replay_key.is_none()
                || self.authority_subject_blake3.is_none())
        {
            return Err("authority-backed execution is missing signer, challenge, subject or replay binding".into());
        }
        if matches!(command, NixOSCommand::ActivateSystemClosure { .. })
            && !self.rollback_only
            && (self.approval_evidence_kind != Some(ApprovalEvidenceKind::ExecutionIntentAuthority)
                || self.execution_intent_digest.is_none()
                || self.realization_plan_digest.is_none()
                || self.authority_replay_key.is_none())
        {
            return Err("system closure activation requires cryptographically verified execution-intent authority".into());
        }
        Ok(())
    }

    /// Derive the exact rollback capability that was pre-bound when the
    /// original approval was created. No arbitrary rollback command can be
    /// substituted after the fact.
    pub(crate) fn for_rollback(&self, rollback: &NixOSCommand) -> Result<Self, String> {
        let Some(expected) = self.rollback_digest else {
            return Err("authorization did not include a rollback command".into());
        };
        if expected != rollback.command_digest() {
            return Err("rollback command does not match authorized rollback".into());
        }
        if let Some(exact) = &self.recovery_command {
            if exact.command_digest() != expected {
                return Err("stored exact recovery command does not match rollback binding".into());
            }
        }
        let mut derived = self.clone();
        derived.command_digest = expected;
        derived.rollback_digest = None;
        derived.recovery_command = None;
        // Rollback authority was pre-bound by the original ChangePlan. Reusing
        // the original replay key would incorrectly attempt a second consumption.
        derived.authority_replay_key = None;
        derived.authorized_safety = rollback.safety_level();
        derived.rollback_only = true;
        Ok(derived)
    }
}

/// Result of NixOS command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionResult {
    Success {
        stdout: String,
        stderr: String,
        execution_time_ms: u64,
    },
    /// A cognitive recommendation was produced, but no execution authority was
    /// supplied. `decision_quality` / `recommended_quality` are advisory only.
    PendingConfirmation {
        command: NixOSCommand,
        decision_quality: f32,
        recommended_quality: f32,
        confidence: String,
    },
    RolledBack {
        error: String,
        rollback_output: String,
        /// Exact immutable closure targeted by the recovery operation.
        #[serde(default)]
        recovery_closure: Option<String>,
        /// Observed exact system closure after recovery.
        #[serde(default)]
        post_recovery_closure: Option<String>,
    },
    FailedNoRollback {
        error: String,
        rollback_error: Option<String>,
    },
    Blocked {
        reason: String,
        safety_level: SafetyLevel,
    },
}

/// NixOS-aware command executor.
///
/// Φ/confidence remains available as decision telemetry, but privileged
/// execution requires an `ExecutionAuthorization` bound to the exact command.
pub struct NixOSExecutor {
    current_generation: Option<u32>,
    thresholds: ConsciousnessThresholds,
    history: VecDeque<ExecutionRecord>,
    dry_run: bool,
    authority_replay_ledger: AuthorityReplayLedger,
}

/// Record of an execution for learning and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub command: NixOSCommand,
    pub decision_quality_at_execution: Option<f32>,
    pub authorization_issuer: String,
    pub authorization_evidence_digest: [u8; 32],
    pub authorization_change_plan_digest: Option<[u8; 32]>,
    #[serde(default)]
    pub authorization_execution_intent_digest: Option<[u8; 32]>,
    #[serde(default)]
    pub authorization_realization_plan_digest: Option<[u8; 32]>,
    #[serde(default)]
    pub authorization_signer_key_id: Option<String>,
    #[serde(default)]
    pub authorization_challenge_blake3: Option<String>,
    #[serde(default)]
    pub authorization_subject_blake3: Option<String>,
    #[serde(default)]
    pub authorization_replay_key: Option<String>,
    pub result: ExecutionResult,
    pub timestamp_ms: u64,
}

impl Default for NixOSExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl NixOSExecutor {
    pub fn new() -> Self {
        Self {
            current_generation: None,
            thresholds: ConsciousnessThresholds::default(),
            history: VecDeque::with_capacity(1000),
            dry_run: false,
            authority_replay_ledger: AuthorityReplayLedger::system_default(),
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Override persistent replay storage (primarily for tests or a deliberately
    /// relocated state directory). Signed authority is never accepted without
    /// one-shot replay consumption on a real execution path.
    pub fn with_authority_replay_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.authority_replay_ledger = AuthorityReplayLedger::new(path);
        self
    }

    /// Configure the *advisory* Φ thresholds used for PendingConfirmation
    /// recommendations. These thresholds never authorize mutation.
    pub fn with_thresholds(mut self, thresholds: ConsciousnessThresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Capture the current NixOS generation for rollback
    pub async fn capture_generation(&mut self) -> anyhow::Result<u32> {
        let output = Command::new("nixos-rebuild")
            .args(["list-generations"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if line.contains("(current)")
                && let Some(gen_str) = line.split_whitespace().next()
                && let Ok(r#gen) = gen_str.trim().parse::<u32>()
            {
                self.current_generation = Some(r#gen);
                info!(generation = r#gen, "Captured current NixOS generation");
                return Ok(r#gen);
            }
        }

        Err(anyhow::anyhow!("Could not determine current generation"))
    }

    /// Recommendation-only entry point.
    ///
    /// Read-only commands receive an automatic exact-command capability.
    /// Modifying commands NEVER execute from `decision_quality`, regardless of
    /// how high it is; they return `PendingConfirmation` until a separate
    /// approval path supplies `ExecutionAuthorization`.
    pub async fn execute(
        &mut self,
        command: NixOSCommand,
        decision_quality: f32,
    ) -> ExecutionResult {
        let safety = command.safety_level();
        if let HostExecutionPolicy::Forbidden { reason } = command.host_execution_policy() {
            return ExecutionResult::Blocked {
                reason,
                safety_level: safety,
            };
        }
        if safety != SafetyLevel::ReadOnly {
            let recommended_quality = self.thresholds.threshold_for(safety.to_action_type());
            let confidence = PhiAwareScoring::confidence_level(decision_quality);
            return ExecutionResult::PendingConfirmation {
                command,
                decision_quality,
                recommended_quality,
                confidence: confidence.recommendation().to_string(),
            };
        }

        let authorization = ExecutionAuthorization::automatic_read_only(&command)
            .expect("ReadOnly safety classification must admit automatic authorization");
        self.execute_authorized(command, authorization, Some(decision_quality))
            .await
    }

    fn validate_exact_activation_observation(
        observed: &str,
        candidate: &str,
        prior: &str,
    ) -> Result<(), String> {
        if observed != prior {
            return Err(format!(
                "pre-state drift detected: expected exact prior system closure {}, observed {}",
                prior, observed
            ));
        }
        if candidate == prior {
            return Err("activation target is identical to the bound prior system closure".into());
        }
        Ok(())
    }

    fn validate_exact_activation_pre_state(
        command: &NixOSCommand,
        authorization: &ExecutionAuthorization,
    ) -> Result<(), String> {
        let NixOSCommand::ActivateSystemClosure { store_path, .. } = command else {
            return Ok(());
        };
        let Some(NixOSCommand::ActivateSystemClosure {
            store_path: prior_closure,
            ..
        }) = authorization.recovery_command.as_ref()
        else {
            return Err(
                "exact system closure activation has no exact prior-closure recovery binding"
                    .into(),
            );
        };

        let observed = GenerationManager::current_system_closure().map_err(|error| {
            format!("failed to observe current system closure before activation: {error}")
        })?;
        Self::validate_exact_activation_observation(&observed, store_path, prior_closure)
    }

    fn validate_exact_recovery_observation(
        observed: &str,
        candidate: &str,
        prior: &str,
    ) -> Result<(), String> {
        if observed != candidate && observed != prior {
            return Err(format!(
                "recovery refused because system state changed outside the transaction: expected {} or {}, observed {}",
                prior, candidate, observed
            ));
        }
        Ok(())
    }

    fn validate_exact_recovery_state(
        original_command: &NixOSCommand,
        recovery_command: &NixOSCommand,
    ) -> Result<String, String> {
        let (
            NixOSCommand::ActivateSystemClosure {
                store_path: candidate,
                ..
            },
            NixOSCommand::ActivateSystemClosure {
                store_path: prior,
                ..
            },
        ) = (original_command, recovery_command)
        else {
            return Err(
                "exact system recovery requires ActivateSystemClosure for both primary and recovery commands"
                    .into(),
            );
        };

        let observed = GenerationManager::current_system_closure().map_err(|error| {
            format!("failed to observe current system closure before recovery: {error}")
        })?;
        Self::validate_exact_recovery_observation(&observed, candidate, prior)?;
        Ok(observed)
    }

    /// Execute an exact command under an evidence-bound capability.
    pub async fn execute_authorized(
        &mut self,
        command: NixOSCommand,
        authorization: ExecutionAuthorization,
        decision_quality: Option<f32>,
    ) -> ExecutionResult {
        let safety = command.safety_level();
        if let HostExecutionPolicy::Forbidden { reason } = command.host_execution_policy() {
            return ExecutionResult::Blocked {
                reason,
                safety_level: safety,
            };
        }
        if let Err(reason) = authorization.validate_for(&command) {
            return ExecutionResult::Blocked {
                reason,
                safety_level: safety,
            };
        }

        if !self.dry_run {
            if let Err(reason) =
                Self::validate_exact_activation_pre_state(&command, &authorization)
            {
                let blocked = ExecutionResult::Blocked {
                    reason,
                    safety_level: safety,
                };
                self.record_execution(&command, decision_quality, &authorization, &blocked);
                return blocked;
            }
        }

        let (cmd, args) = command.to_command();
        info!(
            command = %cmd,
            args = ?args,
            safety = ?safety,
            authorization_issuer = %authorization.issuer(),
            decision_quality = ?decision_quality,
            "Executing authorized NixOS command"
        );

        if self.dry_run {
            return ExecutionResult::Success {
                stdout: format!("[DRY-RUN] Would execute: {} {}", cmd, args.join(" ")),
                stderr: String::new(),
                execution_time_ms: 0,
            };
        }

        // Verification is deliberately read-only. Burn the replay key only on
        // the real mutation path, after all authorization/command checks and
        // immediately before spawning the privileged command.
        if let Some(replay_key) = authorization.authority_replay_key() {
            let Some(challenge_blake3) = authorization.authority_challenge_blake3() else {
                let blocked = ExecutionResult::Blocked {
                    reason: "authority-backed execution omitted challenge digest".into(),
                    safety_level: safety,
                };
                self.record_execution(&command, decision_quality, &authorization, &blocked);
                return blocked;
            };
            let Some(subject_blake3) = authorization.authority_subject_blake3() else {
                let blocked = ExecutionResult::Blocked {
                    reason: "authority-backed execution omitted subject digest".into(),
                    safety_level: safety,
                };
                self.record_execution(&command, decision_quality, &authorization, &blocked);
                return blocked;
            };
            if let Err(error) = self.authority_replay_ledger.consume(
                replay_key,
                challenge_blake3,
                authorization.evidence_digest(),
                subject_blake3,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as u64)
                    .unwrap_or(0),
            ) {
                let blocked = ExecutionResult::Blocked {
                    reason: format!("authority replay consumption failed: {error}"),
                    safety_level: safety,
                };
                self.record_execution(&command, decision_quality, &authorization, &blocked);
                return blocked;
            }
        }

        let start = std::time::Instant::now();
        let result = Command::new(&cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(output) if output.status.success() => {
                let exec_result = ExecutionResult::Success {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    execution_time_ms: elapsed,
                };
                self.record_execution(&command, decision_quality, &authorization, &exec_result);
                exec_result
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr).to_string();
                warn!(error = %error, "Command failed, attempting authorized rollback");

                let rollback_cmd = authorization
                    .recovery_command
                    .clone()
                    .or_else(|| command.rollback_command());

                if let Some(rollback_cmd) = rollback_cmd {
                    if matches!(command, NixOSCommand::ActivateSystemClosure { .. }) {
                        if let Err(reason) =
                            Self::validate_exact_recovery_state(&command, &rollback_cmd)
                        {
                            let exec_result = ExecutionResult::FailedNoRollback {
                                error,
                                rollback_error: Some(reason),
                            };
                            self.record_execution(
                                &command,
                                decision_quality,
                                &authorization,
                                &exec_result,
                            );
                            return exec_result;
                        }
                    }

                    match authorization.for_rollback(&rollback_cmd) {
                        Ok(rollback_authorization) => {
                            if let Err(reason) = rollback_authorization.validate_for(&rollback_cmd)
                            {
                                let exec_result = ExecutionResult::FailedNoRollback {
                                    error,
                                    rollback_error: Some(format!(
                                        "rollback authorization invalid: {reason}"
                                    )),
                                };
                                self.record_execution(
                                    &command,
                                    decision_quality,
                                    &authorization,
                                    &exec_result,
                                );
                                return exec_result;
                            }

                            if let HostExecutionPolicy::Forbidden { reason } =
                                rollback_cmd.host_execution_policy()
                            {
                                let exec_result = ExecutionResult::FailedNoRollback {
                                    error,
                                    rollback_error: Some(format!(
                                        "rollback violates sovereign host execution policy: {reason}"
                                    )),
                                };
                                self.record_execution(
                                    &command,
                                    decision_quality,
                                    &authorization,
                                    &exec_result,
                                );
                                return exec_result;
                            }

                            let (rb_cmd, rb_args) = rollback_cmd.to_command();
                            let rb_result = Command::new(&rb_cmd)
                                .args(&rb_args)
                                .stdout(Stdio::piped())
                                .stderr(Stdio::piped())
                                .output()
                                .await;

                            let exec_result = match rb_result {
                                Ok(rb_output) if rb_output.status.success() => {
                                    if matches!(command, NixOSCommand::ActivateSystemClosure { .. }) {
                                        match GenerationManager::current_system_closure() {
                                            Ok(post_recovery_closure) => {
                                                let expected_post = match &rollback_cmd {
                                                    NixOSCommand::ActivateSystemClosure {
                                                        store_path, ..
                                                    } => store_path,
                                                    _ => unreachable!(),
                                                };
                                                if post_recovery_closure != *expected_post {
                                                    ExecutionResult::FailedNoRollback {
                                                        error,
                                                        rollback_error: Some(format!(
                                                            "exact recovery command succeeded but post-recovery closure is {} rather than {}",
                                                            post_recovery_closure, expected_post
                                                        )),
                                                    }
                                                } else {
                                                    ExecutionResult::RolledBack {
                                                        error,
                                                        rollback_output: String::from_utf8_lossy(
                                                            &rb_output.stdout,
                                                        )
                                                        .to_string(),
                                                        recovery_closure: Some(
                                                            expected_post.clone(),
                                                        ),
                                                        post_recovery_closure: Some(
                                                            post_recovery_closure,
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(recovery_error) => {
                                                ExecutionResult::FailedNoRollback {
                                                    error,
                                                    rollback_error: Some(format!(
                                                        "exact recovery executed but post-recovery closure could not be verified: {recovery_error}"
                                                    )),
                                                }
                                            }
                                        }
                                    } else {
                                        ExecutionResult::RolledBack {
                                            error,
                                            rollback_output: String::from_utf8_lossy(
                                                &rb_output.stdout,
                                            )
                                            .to_string(),
                                            recovery_closure: None,
                                            post_recovery_closure: None,
                                        }
                                    }
                                }
                                Ok(rb_output) => ExecutionResult::FailedNoRollback {
                                    error,
                                    rollback_error: Some(
                                        String::from_utf8_lossy(&rb_output.stderr).to_string(),
                                    ),
                                },
                                Err(e) => ExecutionResult::FailedNoRollback {
                                    error,
                                    rollback_error: Some(e.to_string()),
                                },
                            };
                            self.record_execution(
                                &command,
                                decision_quality,
                                &authorization,
                                &exec_result,
                            );
                            exec_result
                        }
                        Err(reason) => {
                            let exec_result = ExecutionResult::FailedNoRollback {
                                error,
                                rollback_error: Some(format!(
                                    "rollback was not included in the execution capability: {reason}"
                                )),
                            };
                            self.record_execution(
                                &command,
                                decision_quality,
                                &authorization,
                                &exec_result,
                            );
                            exec_result
                        }
                    }
                } else {
                    let exec_result = ExecutionResult::FailedNoRollback {
                        error,
                        rollback_error: None,
                    };
                    self.record_execution(&command, decision_quality, &authorization, &exec_result);
                    exec_result
                }
            }
            Err(e) => {
                let exec_result = ExecutionResult::FailedNoRollback {
                    error: e.to_string(),
                    rollback_error: None,
                };
                self.record_execution(&command, decision_quality, &authorization, &exec_result);
                exec_result
            }
        }
    }

    fn record_execution(
        &mut self,
        command: &NixOSCommand,
        decision_quality: Option<f32>,
        authorization: &ExecutionAuthorization,
        result: &ExecutionResult,
    ) {
        let record = ExecutionRecord {
            command: command.clone(),
            decision_quality_at_execution: decision_quality,
            authorization_issuer: authorization.issuer().to_string(),
            authorization_evidence_digest: authorization.evidence_digest(),
            authorization_change_plan_digest: authorization.change_plan_digest(),
            authorization_execution_intent_digest: authorization.execution_intent_digest(),
            authorization_realization_plan_digest: authorization.realization_plan_digest(),
            authorization_signer_key_id: authorization
                .authority_signer_key_id()
                .map(|value| value.to_string()),
            authorization_challenge_blake3: authorization
                .authority_challenge_blake3()
                .map(|value| value.to_string()),
            authorization_subject_blake3: authorization
                .authority_subject_blake3()
                .map(|value| value.to_string()),
            authorization_replay_key: authorization
                .authority_replay_key()
                .map(|value| value.to_string()),
            result: result.clone(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        self.history.push_back(record);

        if self.history.len() > 1000 {
            self.history.pop_front();
        }
    }

    pub fn history(&self) -> &VecDeque<ExecutionRecord> {
        &self.history
    }

    pub fn success_rate(&self, safety_level: SafetyLevel) -> Option<f32> {
        let matching: Vec<_> = self
            .history
            .iter()
            .filter(|r| r.command.safety_level() == safety_level)
            .collect();

        if matching.is_empty() {
            return None;
        }

        let successes = matching
            .iter()
            .filter(|r| matches!(r.result, ExecutionResult::Success { .. }))
            .count();

        Some(successes as f32 / matching.len() as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_safety_levels() {
        let search = NixOSCommand::Search {
            query: "vim".to_string(),
            json: false,
        };
        assert_eq!(search.safety_level(), SafetyLevel::ReadOnly);

        let install = NixOSCommand::EnvInstall {
            packages: vec!["vim".to_string()],
        };
        assert_eq!(install.safety_level(), SafetyLevel::UserModify);

        let rebuild = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        assert_eq!(rebuild.safety_level(), SafetyLevel::SystemCritical);

        let gc = NixOSCommand::CollectGarbage {
            older_than_days: Some(7),
            delete_all: false,
        };
        assert_eq!(gc.safety_level(), SafetyLevel::Destructive);
    }

    #[test]
    fn test_command_to_shell() {
        let install = NixOSCommand::EnvInstall {
            packages: vec!["vim".to_string(), "git".to_string()],
        };
        let (cmd, args) = install.to_command();
        assert_eq!(cmd, "nix-env");
        assert_eq!(args, vec!["-iA", "nixpkgs.vim", "nixpkgs.git"]);

        let search = NixOSCommand::Search {
            query: "editor".to_string(),
            json: true,
        };
        let (cmd, args) = search.to_command();
        assert_eq!(cmd, "nix");
        assert_eq!(args, vec!["search", "nixpkgs", "editor", "--json"]);
    }

    #[test]
    fn exact_activation_observation_accepts_bound_prior_and_rejects_drift() {
        assert!(NixOSExecutor::validate_exact_activation_observation(
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
        )
        .is_ok());

        assert!(
            NixOSExecutor::validate_exact_activation_observation(
                "/nix/store/11111111111111111111111111111111-nixos-system-other",
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
                "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            )
            .is_err()
        );
    }

    #[test]
    fn exact_activation_observation_rejects_candidate_equal_to_prior() {
        assert!(
            NixOSExecutor::validate_exact_activation_observation(
                "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
                "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
                "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            )
            .is_err()
        );
    }

    #[test]
    fn exact_recovery_observation_accepts_only_transaction_states() {
        assert!(NixOSExecutor::validate_exact_recovery_observation(
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
        )
        .is_ok());

        assert!(NixOSExecutor::validate_exact_recovery_observation(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
        )
        .is_ok());

        assert!(
            NixOSExecutor::validate_exact_recovery_observation(
                "/nix/store/11111111111111111111111111111111-nixos-system-other",
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-new",
                "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            )
            .is_err()
        );
    }

    #[test]
    fn exact_activation_authorization_requires_exact_recovery_binding() {
        let command = NixOSCommand::ActivateSystemClosure {
            store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-test".into(),
            action: SystemActivation::Switch,
        };
        let plan = ChangePlan::command_only_with_system_recovery(
            super::super::change_covenant::MachineBinding::new("machine-a").unwrap(),
            command,
            "/nix/store/abcdefabcdefabcdefabcdefabcdefab-nixos-system-old",
            SystemActivation::Switch,
            60_000,
        )
        .unwrap();
        let approval =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner", [7; 32]).unwrap();
        let auth = ExecutionAuthorization::from_change_authorization(&plan, &approval).unwrap();
        assert!(auth.recovery_command.is_some());
    }

    #[test]
    fn test_rollback_commands() {
        let rebuild = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        assert!(rebuild.rollback_command().is_some());

        let install = NixOSCommand::EnvInstall {
            packages: vec!["vim".to_string()],
        };
        assert!(install.rollback_command().is_some());

        let exact = NixOSCommand::ActivateSystemClosure {
            store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-test".into(),
            action: SystemActivation::Switch,
        };
        assert!(
            exact.rollback_command().is_none(),
            "exact closure activation must never fall back to ambient rollback"
        );

        let search = NixOSCommand::Search {
            query: "vim".to_string(),
            json: false,
        };
        assert!(search.rollback_command().is_none());
    }

    #[test]
    fn test_safety_to_phi() {
        assert_eq!(SafetyLevel::ReadOnly.recommended_decision_quality(), 0.2);
        assert_eq!(SafetyLevel::UserModify.recommended_decision_quality(), 0.3);
        assert_eq!(
            SafetyLevel::SystemCritical.recommended_decision_quality(),
            0.4
        );
        assert_eq!(SafetyLevel::Destructive.recommended_decision_quality(), 0.6);
    }

    #[tokio::test]
    async fn test_dry_run_execution() {
        let mut executor = NixOSExecutor::new().with_dry_run(true);

        let search = NixOSCommand::Search {
            query: "vim".to_string(),
            json: false,
        };
        let result = executor.execute(search, 0.5).await;

        match result {
            ExecutionResult::Success { stdout, .. } => {
                assert!(stdout.contains("[DRY-RUN]"));
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_ambient_rebuild_is_blocked_even_with_high_decision_quality() {
        let mut executor = NixOSExecutor::new().with_dry_run(true);

        let rebuild = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        // The candidate vocabulary remains representable, but direct mutation
        // is now outside the privileged host boundary regardless of Phi/approval.
        let result = executor.execute(rebuild, 1.0).await;

        match result {
            ExecutionResult::Blocked { reason, .. } => {
                assert!(reason.contains("direct nixos-rebuild mutation"));
                assert!(reason.contains("ActivateSystemClosure"));
            }
            _ => panic!("Expected ambient rebuild to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_general_change_approval_cannot_activate_ambient_rebuild() {
        use super::super::change_covenant::{ChangeAuthorization, ChangePlan, MachineBinding};

        let mut executor = NixOSExecutor::new().with_dry_run(true);
        let rebuild = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        let plan = ChangePlan::command_only(
            MachineBinding::new("machine-a").unwrap(),
            rebuild.clone(),
            60_000,
        )
        .unwrap();
        let change_auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-human-approval", [7; 32])
                .unwrap();
        let auth =
            ExecutionAuthorization::from_change_authorization(&plan, &change_auth).unwrap();

        let result = executor
            .execute_authorized(rebuild, auth, Some(1.0))
            .await;
        match result {
            ExecutionResult::Blocked { reason, .. } => {
                assert!(reason.contains("direct nixos-rebuild mutation"));
            }
            _ => panic!("Expected ambient rebuild mutation to be blocked"),
        }
    }

    #[tokio::test]
    async fn test_change_authorization_remains_exact_plan_bound_for_ambient_rebuilds() {
        use super::super::change_covenant::{ChangeAuthorization, ChangePlan, MachineBinding};

        let mut executor = NixOSExecutor::new().with_dry_run(true);
        let rebuild = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        let plan = ChangePlan::command_only(
            MachineBinding::new("machine-a").unwrap(),
            rebuild.clone(),
            60_000,
        )
        .unwrap();
        let change_auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-change-approval", [9; 32])
                .unwrap();
        let exec_auth =
            ExecutionAuthorization::from_change_authorization(&plan, &change_auth).unwrap();
        assert_eq!(exec_auth.change_plan_digest(), Some(plan.digest()));

        let result = executor
            .execute_authorized(rebuild, exec_auth, Some(1.0))
            .await;
        assert!(matches!(result, ExecutionResult::Blocked { .. }));
    }

    #[test]
    fn test_rebuild_with_flake_to_command() {
        let cmd = NixOSCommand::RebuildSwitch {
            flake: Some(".#myhost".to_string()),
            extra_args: vec!["--show-trace".to_string()],
        };
        let (bin, args) = cmd.to_command();
        assert_eq!(bin, "nixos-rebuild");
        assert!(args.contains(&"switch".to_string()));
        assert!(args.contains(&"--flake".to_string()));
        assert!(args.contains(&".#myhost".to_string()));
        assert!(args.contains(&"--show-trace".to_string()));
    }

    #[test]
    fn test_rebuild_test_and_boot_to_command() {
        let test_cmd = NixOSCommand::RebuildTest {
            flake: None,
            extra_args: vec![],
        };
        let (bin, args) = test_cmd.to_command();
        assert_eq!(bin, "nixos-rebuild");
        assert_eq!(args[0], "test");

        let boot_cmd = NixOSCommand::RebuildBoot {
            flake: None,
            extra_args: vec![],
        };
        let (bin, args) = boot_cmd.to_command();
        assert_eq!(bin, "nixos-rebuild");
        assert_eq!(args[0], "boot");
    }

    #[test]
    fn test_channel_operations_to_command() {
        let list = NixOSCommand::Channel {
            operation: ChannelOperation::List,
        };
        let (bin, args) = list.to_command();
        assert_eq!(bin, "nix-channel");
        assert!(args.contains(&"--list".to_string()));

        let update = NixOSCommand::Channel {
            operation: ChannelOperation::Update {
                channel: Some("nixos".into()),
            },
        };
        let (bin, args) = update.to_command();
        assert_eq!(bin, "nix-channel");
        assert!(args.contains(&"--update".to_string()));
        assert!(args.contains(&"nixos".to_string()));

        let add = NixOSCommand::Channel {
            operation: ChannelOperation::Add {
                url: "https://nixos.org/channels/nixpkgs-unstable".into(),
                name: "nixpkgs".into(),
            },
        };
        let (bin, args) = add.to_command();
        assert_eq!(bin, "nix-channel");
        assert!(args.contains(&"--add".to_string()));

        let remove = NixOSCommand::Channel {
            operation: ChannelOperation::Remove {
                name: "nixpkgs".into(),
            },
        };
        let (bin, args) = remove.to_command();
        assert_eq!(bin, "nix-channel");
        assert!(args.contains(&"--remove".to_string()));
    }

    #[test]
    fn test_flake_operations_to_command() {
        let update = NixOSCommand::Flake {
            operation: FlakeOperation::Update {
                inputs: vec!["nixpkgs".into()],
            },
        };
        let (bin, args) = update.to_command();
        assert_eq!(bin, "nix");
        assert!(args.contains(&"flake".to_string()));
        assert!(args.contains(&"update".to_string()));
        assert!(args.contains(&"nixpkgs".to_string()));

        let lock = NixOSCommand::Flake {
            operation: FlakeOperation::Lock {
                inputs: vec!["nixpkgs".into()],
            },
        };
        let (bin, args) = lock.to_command();
        assert_eq!(bin, "nix");
        assert!(args.contains(&"lock".to_string()));
        assert!(args.contains(&"--update-input".to_string()));
    }

    #[test]
    fn test_home_manager_to_command() {
        let hm = NixOSCommand::HomeManagerSwitch {
            flake: Some(".".into()),
        };
        let (bin, args) = hm.to_command();
        assert_eq!(bin, "home-manager");
        assert!(args.contains(&"switch".to_string()));
        assert!(args.contains(&"--flake".to_string()));
    }

    #[test]
    fn test_gc_to_command() {
        let gc = NixOSCommand::CollectGarbage {
            older_than_days: Some(30),
            delete_all: false,
        };
        let (bin, args) = gc.to_command();
        assert_eq!(bin, "nix-collect-garbage");
        assert!(args.contains(&"--delete-older-than".to_string()));
        assert!(args.contains(&"30d".to_string()));

        let gc_all = NixOSCommand::CollectGarbage {
            older_than_days: None,
            delete_all: true,
        };
        let (_, args) = gc_all.to_command();
        assert!(args.contains(&"--delete-old".to_string()));
    }

    #[test]
    fn test_custom_auto_classify_search() {
        let cmd =
            NixOSCommand::custom_auto("nix", vec!["search".into(), "nixpkgs".into(), "vim".into()]);
        assert_eq!(cmd.safety_level(), SafetyLevel::ReadOnly);
    }

    #[test]
    fn test_custom_auto_classify_rebuild() {
        let cmd = NixOSCommand::custom_auto("nixos-rebuild", vec!["switch".into()]);
        assert_eq!(cmd.safety_level(), SafetyLevel::SystemCritical);
    }

    #[test]
    fn test_custom_auto_classify_gc() {
        let cmd = NixOSCommand::custom_auto("nix-collect-garbage", vec!["-d".into()]);
        assert_eq!(cmd.safety_level(), SafetyLevel::Destructive);
    }

    #[test]
    fn test_custom_auto_classify_unknown() {
        // Unknown commands default to SystemCritical (conservative)
        let cmd = NixOSCommand::custom_auto("some-unknown-tool", vec![]);
        assert_eq!(cmd.safety_level(), SafetyLevel::SystemCritical);
    }

    #[test]
    fn test_custom_command_safety() {
        let custom = NixOSCommand::Custom {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            safety_level: SafetyLevel::ReadOnly,
        };
        assert_eq!(custom.safety_level(), SafetyLevel::ReadOnly);
        let (bin, args) = custom.to_command();
        assert_eq!(bin, "echo");
        assert_eq!(args, vec!["hello"]);
    }

    #[test]
    fn test_all_safety_levels_complete() {
        // Verify every safety level maps to a valid action type
        for level in [
            SafetyLevel::ReadOnly,
            SafetyLevel::UserModify,
            SafetyLevel::SystemModify,
            SafetyLevel::SystemCritical,
            SafetyLevel::Destructive,
        ] {
            let quality = level.recommended_decision_quality();
            assert!(
                (0.0..=1.0).contains(&quality),
                "Decision quality for {:?} out of range: {}",
                level,
                quality
            );
        }
    }

    #[test]
    fn test_rollback_all_rebuild_variants() {
        let switch = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        let test = NixOSCommand::RebuildTest {
            flake: None,
            extra_args: vec![],
        };
        let boot = NixOSCommand::RebuildBoot {
            flake: None,
            extra_args: vec![],
        };
        let hm = NixOSCommand::HomeManagerSwitch { flake: None };
        let gc = NixOSCommand::CollectGarbage {
            older_than_days: None,
            delete_all: false,
        };

        assert!(switch.rollback_command().is_some());
        assert!(test.rollback_command().is_some());
        assert!(boot.rollback_command().is_some());
        assert!(hm.rollback_command().is_some());
        assert!(
            gc.rollback_command().is_none(),
            "GC should not have rollback"
        );
    }

    #[tokio::test]
    async fn test_dry_run_skips_history() {
        // Dry-run returns before recording to history (by design)
        let mut executor = NixOSExecutor::new().with_dry_run(true);
        assert!(executor.history().is_empty());

        let cmd = NixOSCommand::Search {
            query: "test".into(),
            json: false,
        };
        executor.execute(cmd, 0.5).await;
        assert!(
            executor.history().is_empty(),
            "Dry-run should not record to history"
        );
    }

    #[tokio::test]
    async fn test_unapproved_modification_skips_history() {
        // Unapproved modifying commands never reach execution history
        let mut executor = NixOSExecutor::new().with_dry_run(true);
        let cmd = NixOSCommand::RebuildSwitch {
            flake: None,
            extra_args: vec![],
        };
        executor.execute(cmd, 1.0).await; // decision quality never grants authority
        assert!(
            executor.history().is_empty(),
            "Unapproved modifying command should not record to history"
        );
    }

    #[test]
    fn test_success_rate_no_history() {
        let executor = NixOSExecutor::new();
        assert!(executor.success_rate(SafetyLevel::ReadOnly).is_none());
        assert!(executor.success_rate(SafetyLevel::UserModify).is_none());
    }

    #[test]
    fn test_history_ring_buffer_eviction() {
        let mut executor = NixOSExecutor::new();
        // Fill beyond 1000 entries
        for i in 0..1005 {
            let record = ExecutionRecord {
                command: NixOSCommand::Search {
                    query: format!("pkg{i}"),
                    json: false,
                },
                decision_quality_at_execution: Some(0.5),
                authorization_issuer: "test".into(),
                authorization_evidence_digest: [1; 32],
                authorization_change_plan_digest: None,
                authorization_execution_intent_digest: None,
                authorization_realization_plan_digest: None,
                authorization_signer_key_id: None,
                authorization_challenge_blake3: None,
                authorization_subject_blake3: None,
                authorization_replay_key: None,
                result: ExecutionResult::Success {
                    stdout: String::new(),
                    stderr: String::new(),
                    execution_time_ms: 0,
                },
                timestamp_ms: i as u64,
            };
            executor.history.push_back(record);
            if executor.history.len() > 1000 {
                executor.history.pop_front();
            }
        }
        assert_eq!(executor.history.len(), 1000);
        // Oldest entry should be pkg5 (0..4 evicted)
        if let NixOSCommand::Search { query, .. } = &executor.history[0].command {
            assert_eq!(query, "pkg5");
        } else {
            panic!("Expected Search command");
        }
    }

    #[test]
    fn test_to_command_capacity_hints() {
        // Ensure pre-allocated capacity is sufficient (no reallocation panics)
        let cmd = NixOSCommand::RebuildSwitch {
            flake: Some(".#host".into()),
            extra_args: vec!["--show-trace".into(), "--verbose".into()],
        };
        let (_, args) = cmd.to_command();
        assert_eq!(args.len(), 5); // switch, --flake, .#host, --show-trace, --verbose

        let cmd = NixOSCommand::CollectGarbage {
            older_than_days: Some(30),
            delete_all: true,
        };
        let (_, args) = cmd.to_command();
        assert_eq!(args.len(), 4); // -d, --delete-older-than, 30d, --delete-old
    }

    #[test]
    fn test_command_serde_roundtrip() {
        let cmd = NixOSCommand::RebuildSwitch {
            flake: Some(".#host".into()),
            extra_args: vec!["--show-trace".into()],
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let restored: NixOSCommand = serde_json::from_str(&json).unwrap();
        let (bin, args) = restored.to_command();
        assert_eq!(bin, "nixos-rebuild");
        assert!(args.contains(&".#host".to_string()));
    }

    #[test]
    fn software_ingress_covenant_blocks_ambient_generation_mutation() {
        let rollback = NixOSCommand::Custom {
            command: "nixos-rebuild".into(),
            args: vec!["switch".into(), "--rollback".into()],
            safety_level: SafetyLevel::SystemCritical,
        };
        let policy = rollback.host_execution_policy();
        assert!(!policy.is_allowed());
        assert!(policy.reason().unwrap().contains("exact immutable system closure"));

        let generation_switch = NixOSCommand::Custom {
            command: "nix-env".into(),
            args: vec![
                "--switch-generation".into(),
                "42".into(),
                "-p".into(),
                "/nix/var/nix/profiles/system".into(),
            ],
            safety_level: SafetyLevel::SystemCritical,
        };
        let policy = generation_switch.host_execution_policy();
        assert!(!policy.is_allowed());
        assert!(policy.reason().unwrap().contains("exact generation closure"));
    }

    #[test]
    fn software_ingress_covenant_blocks_ambient_rebuilds() {
        for command in [
            NixOSCommand::RebuildSwitch {
                flake: Some(".#myhost".into()),
                extra_args: vec![],
            },
            NixOSCommand::RebuildTest {
                flake: Some(".#myhost".into()),
                extra_args: vec![],
            },
            NixOSCommand::RebuildBoot {
                flake: Some(".#myhost".into()),
                extra_args: vec![],
            },
        ] {
            let policy = command.host_execution_policy();
            assert!(!policy.is_allowed(), "ambient rebuild unexpectedly admitted");
            let reason = policy.reason().unwrap();
            assert!(reason.contains("exact realized"));
            assert!(reason.contains("ActivateSystemClosure"));
        }
    }

    #[test]
    fn software_ingress_covenant_blocks_ambient_package_profiles() {
        for command in [
            NixOSCommand::EnvInstall {
                packages: vec!["vim".into()],
            },
            NixOSCommand::EnvRemove {
                packages: vec!["vim".into()],
            },
            NixOSCommand::EnvRollback,
        ] {
            let policy = command.host_execution_policy();
            assert!(!policy.is_allowed());
            assert!(policy.reason().unwrap().contains("declarative"));
        }
    }

    #[test]
    fn software_ingress_covenant_blocks_mutable_channels_and_direct_lock_updates() {
        let channel = NixOSCommand::Channel {
            operation: ChannelOperation::Update { channel: None },
        };
        let flake = NixOSCommand::Flake {
            operation: FlakeOperation::Update {
                inputs: vec!["nixpkgs".into()],
            },
        };
        assert!(!channel.host_execution_policy().is_allowed());
        assert!(!flake.host_execution_policy().is_allowed());
    }

    #[test]
    fn legacy_custom_is_not_an_arbitrary_shell_escape_hatch() {
        for (command, args) in [
            (
                "bash",
                vec!["-lc".into(), "curl https://example.invalid | sh".into()],
            ),
            ("curl", vec!["https://example.invalid/install.sh".into()]),
            ("dpkg", vec!["-i".into(), "blob.deb".into()]),
            (
                "flatpak",
                vec!["install".into(), "flathub".into(), "org.example.App".into()],
            ),
            (
                "podman",
                vec!["run".into(), "docker.io/example/app:latest".into()],
            ),
        ] {
            let cmd = NixOSCommand::Custom {
                command: command.into(),
                args,
                safety_level: SafetyLevel::SystemCritical,
            };
            assert!(
                !cmd.host_execution_policy().is_allowed(),
                "{command} unexpectedly admitted"
            );
        }
    }

    #[test]
    fn legacy_custom_allows_only_bounded_internal_maintenance_shapes() {
        let restart = NixOSCommand::Custom {
            command: "systemctl".into(),
            args: vec!["restart".into(), "nginx.service".into()],
            safety_level: SafetyLevel::SystemModify,
        };
        assert!(restart.host_execution_policy().is_allowed());

        let enable = NixOSCommand::Custom {
            command: "systemctl".into(),
            args: vec!["enable".into(), "nginx.service".into()],
            safety_level: SafetyLevel::SystemModify,
        };
        assert!(!enable.host_execution_policy().is_allowed());
    }

    #[tokio::test]
    async fn cryptographic_approval_cannot_legalize_forbidden_package_install() {
        use super::super::change_covenant::{ChangeAuthorization, ChangePlan, MachineBinding};

        let mut executor = NixOSExecutor::new().with_dry_run(true);
        let install = NixOSCommand::EnvInstall {
            packages: vec!["vim".into()],
        };
        let plan = ChangePlan::command_only(
            MachineBinding::new("machine-a").unwrap(),
            install.clone(),
            60_000,
        )
        .unwrap();
        let change_auth =
            ChangeAuthorization::from_verified_approval(&plan, "test-owner-signature", [0x42; 32])
                .unwrap();
        let auth = ExecutionAuthorization::from_change_authorization(&plan, &change_auth).unwrap();
        let result = executor.execute_authorized(install, auth, Some(1.0)).await;
        assert!(matches!(result, ExecutionResult::Blocked { .. }));
    }

    #[test]
    fn home_manager_requires_explicit_flake_provenance() {
        assert!(
            !NixOSCommand::HomeManagerSwitch { flake: None }
                .host_execution_policy()
                .is_allowed()
        );
        assert!(
            NixOSCommand::HomeManagerSwitch {
                flake: Some("/etc/nixos#owner".into())
            }
            .host_execution_policy()
            .is_allowed()
        );
    }
}
