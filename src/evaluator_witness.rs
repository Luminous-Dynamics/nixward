// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Evaluator-diversity evidence for sovereign Nix.
//!
//! This module deliberately does **not** authorize system mutation.  It turns
//! independent parser/evaluator observations into typed evidence so Nixward can
//! distinguish "the authoritative Nix realization succeeded" from "an
//! independent implementation interpreted the same intent the same way".
//! Tvix is expected to enter through this observer boundary rather than being
//! linked into the privileged mutation path.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SNS_SCHEMA_VERSION: u32 = 1;
pub const EVALUATOR_WITNESS_SCHEMA_VERSION: u32 = 1;
pub const DIFFERENTIAL_EVALUATION_SCHEMA_VERSION: u32 = 1;
const SNS_DOMAIN: &[u8] = b"symthaea-nix-subset-v1\0";
const CANONICAL_JSON_DOMAIN: &[u8] = b"symthaea-canonical-json-v1\0";

/// The initial generated-Nix contract.  SNS-1 is intentionally conservative:
/// ordinary NixOS/nixpkgs may use the full language, while source emitted by
/// Symthaea avoids ambient/environment-dependent and evaluator-specific escape
/// hatches that make differential reasoning unnecessarily fragile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnsValidation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub subset: &'static str,
    pub source_blake3: String,
    pub accepted: bool,
    pub parser_errors: Vec<String>,
    pub violations: Vec<SnsViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnsViolation {
    pub rule: &'static str,
    pub reason: &'static str,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluatorKind {
    CppNix,
    Rnix,
    Tvix,
    Other(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessScope {
    /// Source generated and controlled by Symthaea. Divergence is our bug and
    /// blocks promotion because SNS-1 promises evaluator-portable structure.
    SymthaeaGenerated,
    /// Arbitrary upstream source such as nixpkgs. A non-authoritative witness
    /// may disagree without gaining veto power over production NixOS.
    Upstream,
    /// A whole-system observation. Initially evidence-only for Tvix.
    FullSystem,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessLevel {
    Syntax,
    PureValue,
    ModuleProjection,
    Derivation,
    Realization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessStatus {
    Passed,
    Rejected,
    Unavailable,
    TimedOut,
    InternalError,
}

/// One evaluator observation.  This object is evidence only: there is no
/// capability, signature, or mutation authority embedded in it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvaluatorWitness {
    pub schema_version: u32,
    pub kind: &'static str,
    pub evaluator: EvaluatorKind,
    pub evaluator_version: Option<String>,
    pub evaluator_source_revision: Option<String>,
    pub scope: WitnessScope,
    pub level: WitnessLevel,
    pub source_blake3: String,
    pub result_blake3: Option<String>,
    pub status: WitnessStatus,
    pub duration_micros: Option<u64>,
    pub diagnostics: Vec<String>,
    /// Must remain false for observer implementations such as rnix/Tvix.
    pub authoritative: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DivergenceClass {
    None,
    L0Syntax,
    L1PureValue,
    L2ModuleProjection,
    L3Derivation,
    L4Realization,
    WitnessUnavailable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionDisposition {
    Allow,
    EvidenceOnly,
    RequireReview,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferentialEvaluation {
    pub schema_version: u32,
    pub kind: &'static str,
    pub scope: WitnessScope,
    pub authoritative_evaluator: EvaluatorKind,
    pub witness_evaluator: EvaluatorKind,
    pub level: WitnessLevel,
    pub divergence: DivergenceClass,
    pub disposition: PromotionDisposition,
    pub source_blake3: String,
    pub authoritative_result_blake3: Option<String>,
    pub witness_result_blake3: Option<String>,
    pub explanation: String,
}

/// Validate source emitted by Symthaea against SNS-1.
///
/// This intentionally operates on **generated source only**.  It is not an
/// attempt to ban normal nixpkgs language features.  The first phase uses rnix
/// for actual syntax parsing; the second phase rejects a small set of ambient
/// or evaluator-sensitive constructs that Symthaea never needs to emit.
pub fn validate_sns1(source: &str) -> SnsValidation {
    let parse = rnix::Root::parse(source);
    let parser_errors = parse
        .errors()
        .iter()
        .take(16)
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    const FORBIDDEN: &[(&str, &str, &str)] = &[
        (
            "sns1-no-angle-paths",
            "<nixpkgs>",
            "generated source must use declared/locked inputs instead of ambient NIX_PATH",
        ),
        (
            "sns1-no-getenv",
            "builtins.getEnv",
            "generated source must not derive system intent from ambient process environment",
        ),
        (
            "sns1-no-current-time",
            "builtins.currentTime",
            "generated source must be deterministic rather than wall-clock dependent",
        ),
        (
            "sns1-no-current-system",
            "builtins.currentSystem",
            "generated source receives the target system explicitly",
        ),
        (
            "sns1-no-impure-fetchgit",
            "builtins.fetchGit",
            "generated source must consume inputs from the locked dependency graph",
        ),
        (
            "sns1-no-impure-fetchtarball",
            "builtins.fetchTarball",
            "generated source must consume inputs from the locked dependency graph",
        ),
        (
            "sns1-no-getflake",
            "builtins.getFlake",
            "generated modules must not open a second undeclared flake graph",
        ),
    ];

    let violations = FORBIDDEN
        .iter()
        .filter_map(|(rule, needle, reason)| {
            source.find(needle).map(|offset| SnsViolation {
                rule,
                reason,
                evidence: format!("{needle} at byte {offset}"),
            })
        })
        .collect::<Vec<_>>();

    SnsValidation {
        schema_version: SNS_SCHEMA_VERSION,
        kind: "symthaea-nix-subset-validation-v1",
        subset: "SNS-1",
        source_blake3: sns_source_digest(source),
        accepted: parser_errors.is_empty() && violations.is_empty(),
        parser_errors,
        violations,
    }
}

/// Domain-separated digest for generated source under the SNS contract.
pub fn sns_source_digest(source: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNS_DOMAIN);
    hasher.update(&(source.len() as u64).to_le_bytes());
    hasher.update(source.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Deterministic digest for JSON semantic projections. Object keys are sorted
/// recursively and insignificant whitespace is discarded before hashing.
pub fn canonical_json_digest(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(v) => out.push_str(&v.to_string()),
            Value::String(v) => {
                // serde_json string escaping is canonical enough for our wire
                // representation because the exact bytes are domain-separated.
                out.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into()));
            }
            Value::Array(values) => {
                out.push('[');
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()));
                    out.push(':');
                    write(
                        map.get(key)
                            .expect("canonical JSON key came from the same map"),
                        out,
                    );
                }
                out.push('}');
            }
        }
    }

    let mut canonical = String::new();
    write(value, &mut canonical);
    let mut hasher = blake3::Hasher::new();
    hasher.update(CANONICAL_JSON_DOMAIN);
    hasher.update(&(canonical.len() as u64).to_le_bytes());
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Compare an authoritative observation with an independent witness.
///
/// A disagreement over **Symthaea-generated SNS-1 source** blocks promotion:
/// evaluator portability is our own contract.  A disagreement over arbitrary
/// upstream/full-system behavior is evidence/review material only; an
/// experimental witness never gains authority over production C++ Nix.
pub fn compare_witnesses(
    authoritative: &EvaluatorWitness,
    witness: &EvaluatorWitness,
) -> DifferentialEvaluation {
    let same_source = authoritative.source_blake3 == witness.source_blake3;
    let both_passed =
        authoritative.status == WitnessStatus::Passed && witness.status == WitnessStatus::Passed;
    let results_equal = both_passed
        && authoritative.result_blake3.is_some()
        && authoritative.result_blake3 == witness.result_blake3;

    let divergence = if witness.status == WitnessStatus::Unavailable
        || witness.status == WitnessStatus::TimedOut
        || witness.status == WitnessStatus::InternalError
    {
        DivergenceClass::WitnessUnavailable
    } else if !same_source || authoritative.status != witness.status {
        DivergenceClass::L0Syntax
    } else if results_equal {
        DivergenceClass::None
    } else {
        match authoritative.level.max(witness.level) {
            WitnessLevel::Syntax => DivergenceClass::L0Syntax,
            WitnessLevel::PureValue => DivergenceClass::L1PureValue,
            WitnessLevel::ModuleProjection => DivergenceClass::L2ModuleProjection,
            WitnessLevel::Derivation => DivergenceClass::L3Derivation,
            WitnessLevel::Realization => DivergenceClass::L4Realization,
        }
    };

    let scope = authoritative.scope;
    let disposition = match (scope, divergence) {
        (_, DivergenceClass::None) => PromotionDisposition::Allow,
        (WitnessScope::SymthaeaGenerated, DivergenceClass::WitnessUnavailable) => {
            PromotionDisposition::RequireReview
        }
        (WitnessScope::SymthaeaGenerated, _) => PromotionDisposition::Block,
        (
            WitnessScope::Upstream | WitnessScope::FullSystem,
            DivergenceClass::WitnessUnavailable,
        ) => PromotionDisposition::EvidenceOnly,
        (WitnessScope::Upstream | WitnessScope::FullSystem, _) => {
            PromotionDisposition::RequireReview
        }
    };

    DifferentialEvaluation {
        schema_version: DIFFERENTIAL_EVALUATION_SCHEMA_VERSION,
        kind: "symthaea-differential-evaluation-v1",
        scope,
        authoritative_evaluator: authoritative.evaluator.clone(),
        witness_evaluator: witness.evaluator.clone(),
        level: authoritative.level.max(witness.level),
        divergence,
        disposition,
        source_blake3: authoritative.source_blake3.clone(),
        authoritative_result_blake3: authoritative.result_blake3.clone(),
        witness_result_blake3: witness.result_blake3.clone(),
        explanation: match disposition {
            PromotionDisposition::Allow => "independent evaluator evidence agrees".into(),
            PromotionDisposition::EvidenceOnly => {
                "independent witness is unavailable; production Nix authority is unchanged".into()
            }
            PromotionDisposition::RequireReview => {
                "independent evaluator evidence diverges outside the generated SNS-1 contract"
                    .into()
            }
            PromotionDisposition::Block => {
                "Symthaea-generated SNS-1 source diverges across evaluators; refuse promotion"
                    .into()
            }
        },
    }
}

/// Policy serialized into every generated sovereign bundle.  Tvix is named as
/// the first optional external witness, but remains disabled until a pinned
/// source revision, compatibility corpus and sandbox/resource contract exist.
pub fn evaluator_policy_json() -> String {
    let policy = serde_json::json!({
        "schema_version": EVALUATOR_WITNESS_SCHEMA_VERSION,
        "kind": "symthaea-evaluator-policy-v1",
        "generated_subset": {
            "name": "SNS-1",
            "validator": "rnix-in-process",
            "divergence": "block"
        },
        "authoritative_realizer": "cpp-nix",
        "witnesses": [
            {
                "name": "tvix",
                "mode": "external-unprivileged-process",
                "enabled": false,
                "authority": "none",
                "upstream_divergence": "review-evidence",
                "activation_requirements": [
                    "pinned-source-revision",
                    "pinned-cargo-graph",
                    "sns1-conformance-corpus",
                    "resource-limits",
                    "no-root",
                    "no-network",
                    "no-store-write"
                ]
            }
        ]
    });
    serde_json::to_string_pretty(&policy).unwrap_or_else(|_| {
        "{\"schema_version\":1,\"error\":\"evaluator policy serialization failed\"}".into()
    }) + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sns1_accepts_boring_generated_nixos_module() {
        let result = validate_sns1(
            r#"{ pkgs, ... }: {
  networking.hostName = "guardian";
  environment.systemPackages = with pkgs; [ git ripgrep ];
}
"#,
        );
        assert!(result.accepted, "{result:?}");
    }

    #[test]
    fn sns1_rejects_ambient_and_impure_generated_inputs() {
        let result = validate_sns1(
            r#"{ ... }: {
  environment.etc."x".text = builtins.getEnv "HOME";
  imports = [ <nixpkgs/nixos/modules/profiles/minimal.nix> ];
}
"#,
        );
        assert!(!result.accepted);
        assert!(result.violations.iter().any(|v| v.rule == "sns1-no-getenv"));
        assert!(
            result
                .violations
                .iter()
                .any(|v| v.rule == "sns1-no-angle-paths")
        );
    }

    #[test]
    fn canonical_json_digest_ignores_object_key_order() {
        let a: Value = serde_json::from_str(r#"{"b":2,"a":{"y":1,"x":0}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":0,"y":1},"b":2}"#).unwrap();
        assert_eq!(canonical_json_digest(&a), canonical_json_digest(&b));
    }

    #[test]
    fn generated_subset_divergence_blocks_but_upstream_only_reviews() {
        let make = |scope: WitnessScope, evaluator: EvaluatorKind, result: &str| EvaluatorWitness {
            schema_version: EVALUATOR_WITNESS_SCHEMA_VERSION,
            kind: "symthaea-evaluator-witness-v1",
            evaluator,
            evaluator_version: None,
            evaluator_source_revision: None,
            scope,
            level: WitnessLevel::PureValue,
            source_blake3: "source".into(),
            result_blake3: Some(result.into()),
            status: WitnessStatus::Passed,
            duration_micros: None,
            diagnostics: vec![],
            authoritative: false,
        };
        let authoritative = make(WitnessScope::SymthaeaGenerated, EvaluatorKind::CppNix, "a");
        let witness = make(WitnessScope::SymthaeaGenerated, EvaluatorKind::Tvix, "b");
        assert_eq!(
            compare_witnesses(&authoritative, &witness).disposition,
            PromotionDisposition::Block
        );

        let authoritative = make(WitnessScope::Upstream, EvaluatorKind::CppNix, "a");
        let witness = make(WitnessScope::Upstream, EvaluatorKind::Tvix, "b");
        assert_eq!(
            compare_witnesses(&authoritative, &witness).disposition,
            PromotionDisposition::RequireReview
        );
    }
}
