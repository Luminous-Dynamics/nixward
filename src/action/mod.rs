pub mod uki_evidence;
pub mod boot_selection;
// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Covenant-Bound Action Execution
//!
//! Cognitive Φ/decision-quality values inform recommendations only. Host
//! mutations require an explicit ChangePlan plus approval evidence bound to
//! the exact machine/config/command intent; execution capabilities remain
//! exact-command scoped and rollback-bound.

pub mod authority_approval;
pub mod authority_replay;
pub mod change_covenant;
pub mod config_writer;
pub mod execution_intent;
pub mod executor;
pub mod flake_ops;
pub mod gc_manager;
pub mod generation_manager;
pub mod phi_gate;
pub mod plan_executor;
pub mod service_manager;
pub mod system_transaction;

pub use authority_approval::{
    NIXWARD_CHANGE_AUDIENCE, NIXWARD_EXECUTION_INTENT_AUDIENCE,
    build_execution_intent_change_challenge, build_general_change_challenge,
    execution_intent_authority_subject, general_change_authority_subject,
    verify_execution_intent_change_authority, verify_general_change_authority,
};
pub use authority_replay::{
    AuthorityReplayError, AuthorityReplayLedger, DEFAULT_AUTHORITY_REPLAY_DB,
};
pub use change_covenant::{
    ApprovalEvidenceKind, ChangeAuthorization, ChangePlan, ConfigMutationBinding, MachineBinding,
    RollbackBinding,
};
pub use config_writer::{ConfigPatch, ConfigWriter, WriteResult};
pub use execution_intent::{VerifiedExecutionBundle, verify_nixward_execution_bundle};
pub use executor::{
    ChannelOperation, ExecutionRecord, ExecutionResult, FlakeOperation, HostExecutionPolicy,
    NixOSCommand, NixOSExecutor, SafetyLevel, SystemActivation,
};
pub use flake_ops::{FlakeCheckResult, FlakeMetadata, FlakeOps};
pub use gc_manager::{GcAnalysis, GcManager, GcRecommendation};
pub use generation_manager::{Generation, GenerationDiff, GenerationManager};
pub use phi_gate::{classify_command_destructiveness, get_nixos_rollback};
pub use plan_executor::{PlanExecutionResult, PlanExecutor, PlanStep, StepStatus};
pub use service_manager::{ServiceManager, ServiceStatus};
pub use system_transaction::{
    ApplicationReceipt, AuthorizationReceipt, OutcomeReceipt, SnapshotReceipt,
    SystemTransaction, TransactionPhase, ValidationReceipt, VerificationReceipt,
    SYSTEM_TRANSACTION_SCHEMA, SYSTEM_TRANSACTION_VERSION,
};
