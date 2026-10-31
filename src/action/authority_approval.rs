// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native Nixward authority approval binding.
//!
//! This module deliberately reuses Nixward's existing detached Ed25519
//! authority protocol. It adds no new signing scheme. The security job here is
//! narrower: define an exact Nixward audience and subject for a ChangePlan,
//! cryptographically verify the detached authority artifact, then convert the
//! opaque verification result into a ChangeAuthorization.

use super::change_covenant::{ChangeAuthorization, ChangePlan};
use super::execution_intent::VerifiedExecutionBundle;
use crate::authority_signature::{
    AuthorityAction, AuthorityChallenge, AuthorityTrustPolicy, AuthorityVerifier,
    DetachedAuthoritySignature,
};

pub const NIXWARD_CHANGE_AUDIENCE: &str = "nixward-change-v1";
pub const NIXWARD_EXECUTION_INTENT_AUDIENCE: &str = "nixward-execution-intent-v1";
const EXECUTION_INTENT_AUTHORITY_SUBJECT_DOMAIN: &[u8] =
    b"nixward-execution-intent-authority-subject-v1\0";

fn hex_32(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The ordinary ChangePlan digest is already a domain-separated BLAKE3 digest
/// over the target machine, exact command/config mutation, rollback binding,
/// nonce, and freshness window.
pub fn general_change_authority_subject(plan: &ChangePlan) -> String {
    hex_32(&plan.digest())
}

/// Bind an authority signature to both the exact ChangePlan and the exact v34
/// framework realization semantics that permitted immutable closure activation.
pub fn execution_intent_authority_subject(
    plan: &ChangePlan,
    bundle: &VerifiedExecutionBundle,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXECUTION_INTENT_AUTHORITY_SUBJECT_DOMAIN);
    hasher.update(&plan.digest());
    hasher.update(&bundle.intent_digest());
    hasher.update(&bundle.realization_plan_digest());
    hasher.finalize().to_hex().to_string()
}

pub fn build_general_change_challenge(
    plan: &ChangePlan,
    holon_id: impl Into<String>,
    nonce_entropy: [u8; 32],
    issued_at_ms: u64,
    ttl_ms: u64,
) -> Result<AuthorityChallenge, String> {
    AuthorityChallenge::new(
        AuthorityAction::Change,
        general_change_authority_subject(plan),
        holon_id,
        NIXWARD_CHANGE_AUDIENCE,
        nonce_entropy,
        issued_at_ms,
        ttl_ms,
    )
    .map_err(|error| error.to_string())
}

pub fn build_execution_intent_change_challenge(
    plan: &ChangePlan,
    bundle: &VerifiedExecutionBundle,
    holon_id: impl Into<String>,
    nonce_entropy: [u8; 32],
    issued_at_ms: u64,
    ttl_ms: u64,
) -> Result<AuthorityChallenge, String> {
    AuthorityChallenge::new(
        AuthorityAction::Change,
        execution_intent_authority_subject(plan, bundle),
        holon_id,
        NIXWARD_EXECUTION_INTENT_AUDIENCE,
        nonce_entropy,
        issued_at_ms,
        ttl_ms,
    )
    .map_err(|error| error.to_string())
}

fn require_exact_audience(
    signed: &DetachedAuthoritySignature,
    expected: &'static str,
) -> Result<(), String> {
    if signed.challenge.audience.as_str() != expected {
        return Err(format!(
            "authority signature audience mismatch: expected {expected}, got {}",
            signed.challenge.audience
        ));
    }
    Ok(())
}

/// Verify exact detached proof bytes for a normal ChangePlan.
pub fn verify_general_change_authority_json(
    plan: &ChangePlan,
    policy: &AuthorityTrustPolicy,
    signed_proof_json: &[u8],
    expected_holon_id: &str,
    now_ms: u64,
) -> Result<ChangeAuthorization, String> {
    let subject = general_change_authority_subject(plan);
    let receipt = AuthorityVerifier::new(policy)
        .map_err(|error| error.to_string())?
        .verify_json(signed_proof_json, AuthorityAction::Change, &subject, expected_holon_id, now_ms)
        .map_err(|error| error.to_string())?;
    if receipt.audience() != NIXWARD_CHANGE_AUDIENCE {
        return Err(format!(
            "authority signature audience mismatch: expected {}, got {}",
            NIXWARD_CHANGE_AUDIENCE,
            receipt.audience()
        ));
    }
    ChangeAuthorization::from_verified_authority_receipt(plan, &receipt, &subject)
}

/// Typed compatibility wrapper. Use the JSON variant at ingress to preserve original proof bytes.
pub fn verify_general_change_authority(
    plan: &ChangePlan,
    policy: &AuthorityTrustPolicy,
    signed: &DetachedAuthoritySignature,
    expected_holon_id: &str,
    now_ms: u64,
) -> Result<ChangeAuthorization, String> {
    let bytes = serde_json::to_vec(signed).map_err(|error| error.to_string())?;
    verify_general_change_authority_json(plan, policy, &bytes, expected_holon_id, now_ms)
}

/// Verify exact detached proof bytes for one v34 execution-intent and realization-plan pair.
pub fn verify_execution_intent_change_authority_json(
    plan: &ChangePlan,
    bundle: &VerifiedExecutionBundle,
    policy: &AuthorityTrustPolicy,
    signed_proof_json: &[u8],
    expected_holon_id: &str,
    now_ms: u64,
) -> Result<ChangeAuthorization, String> {
    let subject = execution_intent_authority_subject(plan, bundle);
    let receipt = AuthorityVerifier::new(policy)
        .map_err(|error| error.to_string())?
        .verify_json(signed_proof_json, AuthorityAction::Change, &subject, expected_holon_id, now_ms)
        .map_err(|error| error.to_string())?;
    if receipt.audience() != NIXWARD_EXECUTION_INTENT_AUDIENCE {
        return Err(format!(
            "authority signature audience mismatch: expected {}, got {}",
            NIXWARD_EXECUTION_INTENT_AUDIENCE,
            receipt.audience()
        ));
    }
    ChangeAuthorization::from_verified_execution_intent_authority_receipt(
        plan, bundle, &receipt, &subject,
    )
}

/// Typed compatibility wrapper for callers that already decoded the proof.
pub fn verify_execution_intent_change_authority(
    plan: &ChangePlan,
    bundle: &VerifiedExecutionBundle,
    policy: &AuthorityTrustPolicy,
    signed: &DetachedAuthoritySignature,
    expected_holon_id: &str,
    now_ms: u64,
) -> Result<ChangeAuthorization, String> {
    let bytes = serde_json::to_vec(signed).map_err(|error| error.to_string())?;
    verify_execution_intent_change_authority_json(
        plan, bundle, policy, &bytes, expected_holon_id, now_ms,
    )
}
