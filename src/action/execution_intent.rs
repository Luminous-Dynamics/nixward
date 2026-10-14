// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native verifier for the v34 framework execution-intent + realization-plan pair.
//!
//! The Python contract layer remains authoritative for constructing the objects.
//! Nixward re-verifies their canonical SHA-256 identities before deriving a host
//! mutation capability.  The verified bundle is intentionally opaque outside
//! this module so callers cannot manufacture a `VerifiedExecutionBundle` from a
//! cached `verified=true` flag or an arbitrary digest.

use serde_json::Value;
use sha2::{Digest, Sha256};

const NIXWARD_INTENT_SCHEMA: &str = "luminous-nixward-framework-execution-intent-v1";
const REALIZATION_PLAN_SCHEMA: &str = "luminous-nix-realization-plan-v1";

#[derive(Debug, Clone)]
pub struct VerifiedExecutionBundle {
    intent_digest: [u8; 32],
    realization_plan_digest: [u8; 32],
    execution_target_identity: String,
    execution_nonce: [u8; 32],
    expected_out_path: String,
    installable: String,
}

impl VerifiedExecutionBundle {
    pub fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    pub fn realization_plan_digest(&self) -> [u8; 32] {
        self.realization_plan_digest
    }

    pub fn execution_target_identity(&self) -> &str {
        &self.execution_target_identity
    }

    pub fn execution_nonce(&self) -> [u8; 32] {
        self.execution_nonce
    }

    pub fn expected_out_path(&self) -> &str {
        &self.expected_out_path
    }

    pub fn installable(&self) -> &str {
        &self.installable
    }
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| format!("{label} is not UTF-8"))?;
        out[index] = u8::from_str_radix(text, 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal"))?;
    }
    Ok(out)
}

fn self_digest(value: &Value, field: &str, schema: &str) -> Result<[u8; 32], String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{schema} must be a JSON object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(format!("wrong object schema; expected {schema}"));
    }
    let claimed = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is missing"))?;
    let claimed = decode_hex_32(claimed, field)?;

    let mut body = object.clone();
    body.remove(field);
    // serde_json::Map is key ordered unless preserve_order is enabled.  The
    // workspace does not enable preserve_order, matching Python v34's
    // json.dumps(sort_keys=True,separators=(",",":"),ensure_ascii=False).
    let encoded = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
    let computed: [u8; 32] = Sha256::digest(encoded).into();
    if computed != claimed {
        return Err(format!("{field} does not match canonical object bytes"));
    }
    Ok(claimed)
}

fn target_compute(value: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    value
        .get("targetCompute")
        .and_then(Value::as_object)
        .ok_or_else(|| "targetCompute is missing or not an object".into())
}

fn validate_target_compute(value: &serde_json::Map<String, Value>) -> Result<(), String> {
    for key in ["semanticSha256", "contractSha256", "catalogSha256"] {
        let digest = value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("targetCompute.{key} is missing"))?;
        decode_hex_32(digest, &format!("targetCompute.{key}"))?;
    }
    Ok(())
}

pub fn is_valid_nix_store_path(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    if rest.is_empty() || rest.len() > 255 || rest.contains('/') || rest.contains("..") {
        return false;
    }
    let Some((hash, name)) = rest.split_once('-') else {
        return false;
    };
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    hash.len() == 32
        && hash.bytes().all(|byte| NIX_BASE32.contains(&byte))
        && !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
}

pub fn verify_nixward_execution_bundle(
    intent_json: &[u8],
    realization_plan_json: &[u8],
) -> Result<VerifiedExecutionBundle, String> {
    let intent: Value = serde_json::from_slice(intent_json)
        .map_err(|error| format!("invalid execution intent JSON: {error}"))?;
    let plan: Value = serde_json::from_slice(realization_plan_json)
        .map_err(|error| format!("invalid realization plan JSON: {error}"))?;

    let intent_digest = self_digest(&intent, "intentSha256", NIXWARD_INTENT_SCHEMA)?;
    if intent.get("consumer").and_then(Value::as_str) != Some("nixward") {
        return Err("execution intent consumer must be nixward".into());
    }
    if intent.get("authorizationState").and_then(Value::as_str) != Some("unsigned-execution-intent")
    {
        return Err("execution intent must retain unsigned-execution-intent state".into());
    }

    let target_identity = intent
        .get("executionTargetIdentity")
        .and_then(Value::as_str)
        .ok_or_else(|| "executionTargetIdentity is missing".to_string())?;
    if target_identity.is_empty()
        || target_identity.len() > 256
        || target_identity.chars().any(char::is_control)
    {
        return Err("executionTargetIdentity is invalid".into());
    }
    let execution_nonce = decode_hex_32(
        intent
            .get("executionNonce")
            .and_then(Value::as_str)
            .ok_or_else(|| "executionNonce is missing".to_string())?,
        "executionNonce",
    )?;
    let referenced_plan_digest = decode_hex_32(
        intent
            .get("realizationPlanSha256")
            .and_then(Value::as_str)
            .ok_or_else(|| "realizationPlanSha256 is missing".to_string())?,
        "realizationPlanSha256",
    )?;

    let realization_plan_digest = self_digest(&plan, "planSha256", REALIZATION_PLAN_SCHEMA)?;
    if plan.get("consumer").and_then(Value::as_str) != Some("nixward") {
        return Err("realization plan consumer must be nixward".into());
    }
    if realization_plan_digest != referenced_plan_digest {
        return Err("execution intent references a different realization plan".into());
    }

    let intent_target_compute = target_compute(&intent)?;
    let plan_target_compute = target_compute(&plan)?;
    validate_target_compute(intent_target_compute)?;
    validate_target_compute(plan_target_compute)?;
    if intent_target_compute != plan_target_compute {
        return Err(
            "execution intent and realization plan target different compute contracts".into(),
        );
    }

    let nix = plan
        .get("nix")
        .and_then(Value::as_object)
        .ok_or_else(|| "realization plan nix object is missing".to_string())?;
    for key in ["sourceTreeSha256", "flakeLockSha256", "configurationSha256"] {
        let digest = nix
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("nix.{key} is missing"))?;
        decode_hex_32(digest, &format!("nix.{key}"))?;
    }
    let expected_out_path = nix
        .get("expectedOutPath")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "Nixward execution requires realization-plan nix.expectedOutPath so activation is immutable"
                .to_string()
        })?;
    if !is_valid_nix_store_path(expected_out_path) {
        return Err("nix.expectedOutPath is not a canonical Nix store path".into());
    }
    let installable = nix
        .get("installable")
        .and_then(Value::as_str)
        .ok_or_else(|| "nix.installable is missing".to_string())?;
    if !installable.starts_with(".#")
        || installable.len() <= 2
        || installable
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("nix.installable is not an exact .# selector".into());
    }

    Ok(VerifiedExecutionBundle {
        intent_digest,
        realization_plan_digest,
        execution_target_identity: target_identity.to_string(),
        execution_nonce,
        expected_out_path: expected_out_path.to_string(),
        installable: installable.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_digest(mut value: Value, field: &str) -> Value {
        let encoded = serde_json::to_vec(value.as_object().unwrap()).unwrap();
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        value[field] = Value::String(digest.iter().map(|b| format!("{b:02x}")).collect());
        value
    }

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let target = serde_json::json!({
            "catalogSha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "contractSha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "semanticSha256":"3333333333333333333333333333333333333333333333333333333333333333"
        });
        let plan = canonical_digest(
            serde_json::json!({
                "consumer":"nixward",
                "nix":{
                    "configurationSha256":"4444444444444444444444444444444444444444444444444444444444444444",
                    "expectedOutPath":"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-test",
                    "flakeLockSha256":"5555555555555555555555555555555555555555555555555555555555555555",
                    "installable":".#nixosConfigurations.test.config.system.build.toplevel",
                    "sourceTreeSha256":"6666666666666666666666666666666666666666666666666666666666666666",
                    "system":"x86_64-linux"
                },
                "schema":REALIZATION_PLAN_SCHEMA,
                "targetCompute":target
            }),
            "planSha256",
        );
        let plan_digest = plan["planSha256"].as_str().unwrap().to_string();
        let intent = canonical_digest(
            serde_json::json!({
                "authenticatedFrameworkBindingSha256":"7777777777777777777777777777777777777777777777777777777777777777",
                "authorizationState":"unsigned-execution-intent",
                "consumer":"nixward",
                "executionNonce":"8888888888888888888888888888888888888888888888888888888888888888",
                "executionTargetIdentity":"machine-a",
                "migrationPlanSha256":"9999999999999999999999999999999999999999999999999999999999999999",
                "realizationPlanSha256":plan_digest,
                "schema":NIXWARD_INTENT_SCHEMA,
                "targetCompute":plan["targetCompute"].clone(),
                "targetOverlaySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            "intentSha256",
        );
        (
            serde_json::to_vec(&intent).unwrap(),
            serde_json::to_vec(&plan).unwrap(),
        )
    }

    #[test]
    fn accepts_exact_v34_bundle() {
        let (intent, plan) = fixture();
        let verified = verify_nixward_execution_bundle(&intent, &plan).unwrap();
        assert_eq!(verified.execution_target_identity(), "machine-a");
        assert!(verified.expected_out_path().starts_with("/nix/store/"));
        assert_eq!(
            verified.installable(),
            ".#nixosConfigurations.test.config.system.build.toplevel"
        );
    }

    #[test]
    fn rejects_tampered_intent_or_plan() {
        let (intent, mut plan) = fixture();
        let pos = plan.iter().position(|byte| *byte == b'x').unwrap_or(0);
        plan[pos] ^= 1;
        assert!(verify_nixward_execution_bundle(&intent, &plan).is_err());
    }

    #[test]
    fn rejects_mutable_or_malformed_out_path() {
        assert!(!is_valid_nix_store_path("/etc/nixos"));
        assert!(!is_valid_nix_store_path("/nix/store/../etc"));
        assert!(is_valid_nix_store_path(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-test"
        ));
    }
}
