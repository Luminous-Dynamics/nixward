// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Versioned system-transaction envelope.
//!
//! This module does not introduce another authorization mechanism. It wraps
//! the existing ChangePlan and ChangeAuthorization identities with lifecycle
//! receipts so the installer, management UI, and remote transports can
//! exchange one stable, digest-addressed transaction vocabulary.

use super::change_covenant::{ApprovalEvidenceKind, ChangeAuthorization, ChangePlan};
use serde::{Deserialize, Serialize};

const TRANSACTION_DOMAIN: &[u8] = b"nixward-system-transaction-v1\0";
pub const SYSTEM_TRANSACTION_SCHEMA: &str = "luminous-nixward-system-transaction-v1";
pub const SYSTEM_TRANSACTION_VERSION: u16 = 1;

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn transaction_id(plan: &ChangePlan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(&plan.digest());
    hasher.update(&plan.nonce());
    digest_hex(hasher.finalize().as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPhase {
    Planned,
    Authorized,
    Validated,
    Snapshotted,
    Applied,
    Verified,
    Promoted,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    pub issuer: String,
    pub evidence_digest: String,
    pub evidence_kind: ApprovalEvidenceKind,
    pub expires_at_ms: u64,
    pub signer_key_id: Option<String>,
    pub challenge_blake3: Option<String>,
    pub replay_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReceipt {
    pub evidence_digest: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReceipt {
    pub pre_state_digest: String,
    pub recovery_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationReceipt {
    pub command_digest: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub exit_status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub post_state_digest: String,
    pub evidence_digest: String,
    pub boot_healthy: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeReceipt {
    pub phase: TransactionPhase,
    pub reason: Option<String>,
}

/// Serialized transaction vocabulary shared across Nixward consumers.
///
/// Digest-bearing fields intentionally contain no secret material. A caller
/// can exchange this envelope through browser/relay/IPC boundaries without
/// exposing passwords, private keys, or raw filesystem state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTransaction {
    pub schema: String,
    pub version: u16,
    pub transaction_id: String,
    pub target_machine_digest: String,
    pub plan_digest: String,
    pub phase: TransactionPhase,
    pub authorization: Option<AuthorizationReceipt>,
    pub validation: Option<ValidationReceipt>,
    pub snapshot: Option<SnapshotReceipt>,
    pub application: Option<ApplicationReceipt>,
    pub verification: Option<VerificationReceipt>,
    pub outcome: Option<OutcomeReceipt>,
}

impl SystemTransaction {
    pub fn planned(plan: &ChangePlan) -> Self {
        Self {
            schema: SYSTEM_TRANSACTION_SCHEMA.to_string(),
            version: SYSTEM_TRANSACTION_VERSION,
            transaction_id: transaction_id(plan),
            target_machine_digest: digest_hex(&plan.machine().digest()),
            plan_digest: digest_hex(&plan.digest()),
            phase: TransactionPhase::Planned,
            authorization: None,
            validation: None,
            snapshot: None,
            application: None,
            verification: None,
            outcome: None,
        }
    }

    fn ensure_identity(&self, plan: &ChangePlan) -> Result<(), String> {
        if self.schema != SYSTEM_TRANSACTION_SCHEMA || self.version != SYSTEM_TRANSACTION_VERSION {
            return Err("unsupported system transaction schema".into());
        }
        if self.plan_digest != digest_hex(&plan.digest()) {
            return Err("transaction references a different change plan".into());
        }
        if self.target_machine_digest != digest_hex(&plan.machine().digest()) {
            return Err("transaction references a different target machine".into());
        }
        if self.transaction_id != transaction_id(plan) {
            return Err("transaction identity does not match the change plan".into());
        }
        Ok(())
    }

    pub fn authorize(
        &mut self,
        plan: &ChangePlan,
        authorization: &ChangeAuthorization,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        authorization.validate_plan(plan)?;
        self.authorization = Some(AuthorizationReceipt {
            issuer: authorization.issuer().to_string(),
            evidence_digest: digest_hex(&authorization.evidence_digest()),
            evidence_kind: authorization.approval_evidence_kind(),
            expires_at_ms: authorization.expires_at_ms(),
            signer_key_id: authorization.authority_signer_key_id().map(ToOwned::to_owned),
            challenge_blake3: authorization
                .authority_challenge_blake3()
                .map(ToOwned::to_owned),
            replay_key: authorization.authority_replay_key().map(ToOwned::to_owned),
        });
        self.phase = TransactionPhase::Authorized;
        Ok(())
    }

    pub fn record_validation(
        &mut self,
        plan: &ChangePlan,
        evidence_digest: [u8; 32],
        summary: impl Into<String>,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if self.authorization.is_none() {
            return Err("validation cannot be recorded before authorization in this envelope".into());
        }
        if evidence_digest == [0; 32] {
            return Err("validation evidence digest must be non-zero".into());
        }
        self.validation = Some(ValidationReceipt {
            evidence_digest: digest_hex(&evidence_digest),
            summary: summary.into(),
        });
        self.phase = TransactionPhase::Validated;
        Ok(())
    }

    pub fn record_snapshot(
        &mut self,
        plan: &ChangePlan,
        pre_state_digest: [u8; 32],
        recovery_binding_digest: [u8; 32],
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if self.validation.is_none() {
            return Err("snapshot cannot be recorded before validation".into());
        }
        if pre_state_digest == [0; 32] || recovery_binding_digest == [0; 32] {
            return Err("snapshot digests must be non-zero".into());
        }
        self.snapshot = Some(SnapshotReceipt {
            pre_state_digest: digest_hex(&pre_state_digest),
            recovery_binding_digest: digest_hex(&recovery_binding_digest),
        });
        self.phase = TransactionPhase::Snapshotted;
        Ok(())
    }

    pub fn record_application(
        &mut self,
        plan: &ChangePlan,
        command_digest: [u8; 32],
        started_at_ms: u64,
        finished_at_ms: u64,
        exit_status: i32,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if self.authorization.is_none()
            || self.validation.is_none()
            || self.snapshot.is_none()
        {
            return Err("application requires authorization, validation, and snapshot evidence".into());
        }
        if command_digest == [0; 32] {
            return Err("application command digest must be non-zero".into());
        }
        if finished_at_ms < started_at_ms {
            return Err("application receipt has an invalid time range".into());
        }
        let Some(command) = plan.command() else {
            return Err("application receipt requires a command-backed change plan".into());
        };
        if command.command_digest() != command_digest {
            return Err("application command digest differs from the approved plan".into());
        }
        self.application = Some(ApplicationReceipt {
            command_digest: digest_hex(&command_digest),
            started_at_ms,
            finished_at_ms,
            exit_status,
        });
        if exit_status == 0 {
            self.phase = TransactionPhase::Applied;
        } else {
            self.phase = TransactionPhase::Failed;
            self.outcome = Some(OutcomeReceipt {
                phase: TransactionPhase::Failed,
                reason: Some(format!("command exited with status {exit_status}")),
            });
        }
        Ok(())
    }

    pub fn record_verification(
        &mut self,
        plan: &ChangePlan,
        post_state_digest: [u8; 32],
        evidence_digest: [u8; 32],
        boot_healthy: Option<bool>,
    ) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Applied) {
            return Err("verification requires a successfully applied transaction".into());
        }
        if post_state_digest == [0; 32] || evidence_digest == [0; 32] {
            return Err("verification digests must be non-zero".into());
        }
        self.verification = Some(VerificationReceipt {
            post_state_digest: digest_hex(&post_state_digest),
            evidence_digest: digest_hex(&evidence_digest),
            boot_healthy,
        });
        self.phase = TransactionPhase::Verified;
        Ok(())
    }

    pub fn promote(&mut self, plan: &ChangePlan) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if !matches!(self.phase, TransactionPhase::Verified) {
            return Err("promotion requires verified post-state evidence".into());
        }
        if self
            .verification
            .as_ref()
            .and_then(|receipt| receipt.boot_healthy)
            .is_some_and(|healthy| !healthy)
        {
            return Err("unhealthy boot cannot be promoted".into());
        }
        self.phase = TransactionPhase::Promoted;
        self.outcome = Some(OutcomeReceipt {
            phase: TransactionPhase::Promoted,
            reason: None,
        });
        Ok(())
    }

    pub fn recover(&mut self, plan: &ChangePlan, reason: impl Into<String>) -> Result<(), String> {
        self.ensure_identity(plan)?;
        if self.snapshot.is_none() {
            return Err("recovery requires snapshot/recovery evidence".into());
        }
        self.phase = TransactionPhase::Recovered;
        self.outcome = Some(OutcomeReceipt {
            phase: TransactionPhase::Recovered,
            reason: Some(reason.into()),
        });
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(*blake3::hash(bytes.as_slice()).as_bytes())
    }

    pub fn digest_hex(&self) -> Result<String, String> {
        self.digest().map(|digest| digest_hex(&digest))
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            TransactionPhase::Promoted | TransactionPhase::Recovered | TransactionPhase::Failed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::executor::NixOSCommand;

    fn plan() -> ChangePlan {
        ChangePlan::command_only(
            crate::action::change_covenant::MachineBinding::new("machine-a").unwrap(),
            NixOSCommand::RebuildSwitch {
                flake: None,
                extra_args: Vec::new(),
            },
            60_000,
        )
        .unwrap()
    }

    fn authorization(plan: &ChangePlan) -> ChangeAuthorization {
        ChangeAuthorization::from_verified_approval(plan, "test-owner", [7; 32]).unwrap()
    }

    #[test]
    fn transaction_id_is_bound_to_plan_and_nonce() {
        let plan = plan();
        let tx = SystemTransaction::planned(&plan);
        assert_eq!(tx.plan_digest, digest_hex(&plan.digest()));
        assert_eq!(tx.target_machine_digest, digest_hex(&plan.machine().digest()));
        assert_eq!(tx.transaction_id, transaction_id(&plan));
    }

    #[test]
    fn lifecycle_is_fail_closed_and_terminal() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);

        assert!(tx.record_snapshot(&plan, [1; 32], [2; 32]).is_err());
        tx.authorize(&plan, &auth).unwrap();
        tx.record_validation(&plan, [3; 32], "syntax + policy validation")
            .unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();

        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 0).unwrap();
        tx.record_verification(&plan, [6; 32], [8; 32], Some(true))
            .unwrap();
        tx.promote(&plan).unwrap();

        assert_eq!(tx.phase, TransactionPhase::Promoted);
        assert!(tx.is_terminal());
        assert_eq!(tx.digest_hex().unwrap().len(), 64);
    }

    #[test]
    fn failed_apply_can_only_finish_as_recovery_or_failure() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);
        tx.authorize(&plan, &auth).unwrap();
        tx.record_validation(&plan, [3; 32], "validation").unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();

        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 1).unwrap();
        assert_eq!(tx.phase, TransactionPhase::Failed);
        assert!(tx.promote(&plan).is_err());

        tx.recover(&plan, "restored previous generation").unwrap();
        assert_eq!(tx.phase, TransactionPhase::Recovered);
        assert!(tx.is_terminal());
    }

    #[test]
    fn unhealthy_boot_cannot_be_promoted() {
        let plan = plan();
        let auth = authorization(&plan);
        let mut tx = SystemTransaction::planned(&plan);
        tx.authorize(&plan, &auth).unwrap();
        tx.record_validation(&plan, [3; 32], "validation").unwrap();
        tx.record_snapshot(&plan, [4; 32], [5; 32]).unwrap();
        let command = plan.command().unwrap().command_digest();
        tx.record_application(&plan, command, 10, 20, 0).unwrap();
        tx.record_verification(&plan, [6; 32], [8; 32], Some(false))
            .unwrap();
        assert!(tx.promote(&plan).is_err());
    }
}
