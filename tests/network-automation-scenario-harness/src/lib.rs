//! Deterministic fault-fixture evaluator for network administration automation.
//!
//! This crate is a pure decision/receipt model. It opens only checked-in fixture
//! files, uses no networking API, launches no runtime subprocess, and has no
//! mutation capability. It is not a live observer, network adapter, simulator,
//! or proof of production safety.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const TASK_SCHEMA_ID: &str = "urn:luminous-dynamics:nixward:network-automation-task-corpus:v1";
const FAULT_SCHEMA_ID: &str = "urn:luminous-dynamics:nixward:network-automation-fault-fixtures:v1";
const TASK_ARTIFACT_ID: &str = "nixward.network-automation-task-corpus.v1";
const FAULT_ARTIFACT_ID: &str = "nixward.network-automation-fault-fixtures.v1";
const ARTIFACT_DOMAIN: &[u8] = b"nixward:network-automation-scenario-harness:artifact:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"nixward:network-automation-scenario-harness:receipt:v1\0";

#[derive(Debug, Clone)]
pub struct InputArtifacts {
    pub task_corpus_bytes: Vec<u8>,
    pub task_schema_bytes: Vec<u8>,
    pub fault_fixture_bytes: Vec<u8>,
    pub fault_schema_bytes: Vec<u8>,
    pub cargo_manifest_bytes: Vec<u8>,
    pub cargo_lock_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct TaskCorpus {
    schema_version: u32,
    artifact_id: String,
    status: String,
    tasks: Vec<TaskReference>,
}

#[derive(Debug, Clone, Deserialize)]
struct TaskReference {
    task_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FaultCorpus {
    schema_version: u32,
    artifact_id: String,
    status: String,
    task_corpus_artifact_id: String,
    common_invariants: Vec<String>,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Scenario {
    scenario_id: String,
    task_id: String,
    layer: String,
    fault_class: String,
    setup: String,
    expected_decision: String,
    expected_receipt_state: String,
    assertions: Vec<String>,
    production_mutation: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SchemaIdentity {
    #[serde(rename = "$schema")]
    schema_draft: String,
    #[serde(rename = "$id")]
    schema_id: String,
    properties: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDigests {
    pub task_corpus_blake3: String,
    pub task_schema_blake3: String,
    pub fault_fixtures_blake3: String,
    pub fault_schema_blake3: String,
    pub cargo_manifest_blake3: String,
    pub cargo_lock_blake3: String,
    pub evaluator_source_blake3: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check_id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub task_id: String,
    pub layer: String,
    pub fault_class: String,
    pub expected_decision: String,
    pub actual_decision: String,
    pub expected_receipt_state: String,
    pub actual_receipt_state: String,
    pub resource_fenced: bool,
    pub simulated_mutation_applied: bool,
    pub postconditions_modelled_verified: bool,
    pub production_mutation_applied: bool,
    pub declared_assertions: Vec<String>,
    pub checks: Vec<CheckResult>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReceipt {
    pub receipt_schema_version: u32,
    pub status: String,
    pub evaluator_id: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub input_digests: ArtifactDigests,
    pub task_corpus_schema_version: u32,
    pub fault_fixture_schema_version: u32,
    pub task_count: usize,
    pub scenario_count: usize,
    pub unique_task_ids: usize,
    pub unique_scenario_ids: usize,
    pub decision_counts: BTreeMap<String, usize>,
    pub receipt_state_counts: BTreeMap<String, usize>,
    pub production_mutation_enabled: bool,
    pub results: Vec<ScenarioResult>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptEnvelope {
    pub receipt_blake3: String,
    pub receipt: RunReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    decision: &'static str,
    receipt_state: &'static str,
    resource_fenced: bool,
    simulated_mutation_applied: bool,
    postconditions_modelled_verified: bool,
}

impl Outcome {
    fn blocked() -> Self {
        Self {
            decision: "BlockMutation",
            receipt_state: "Blocked",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        }
    }
}

fn artifact_digest(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARTIFACT_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn evaluator_source_digest() -> String {
    // Bind the execution evaluator, its entrypoint, and build-identity script.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nixward:network-automation-scenario-harness:source:v1\0");
    for source in [
        include_bytes!("lib.rs").as_slice(),
        include_bytes!("main.rs").as_slice(),
        include_bytes!("../build.rs").as_slice(),
    ] {
        hasher.update(&(source.len() as u64).to_be_bytes());
        hasher.update(source);
    }
    hasher.finalize().to_hex().to_string()
}

pub fn repository_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))
}

pub fn load_input_artifacts(root: &Path) -> Result<InputArtifacts, String> {
    let read = |relative: &str| {
        fs::read(root.join(relative))
            .map_err(|error| format!("cannot read {relative}: {error}"))
    };
    Ok(InputArtifacts {
        task_corpus_bytes: read("docs/NETWORK_AUTOMATION_TASK_CORPUS_V1.json")?,
        task_schema_bytes: read("docs/NETWORK_AUTOMATION_TASK_CORPUS_V1.schema.json")?,
        fault_fixture_bytes: read("docs/NETWORK_AUTOMATION_FAULT_FIXTURES_V1.json")?,
        fault_schema_bytes: read("docs/NETWORK_AUTOMATION_FAULT_FIXTURES_V1.schema.json")?,
        cargo_manifest_bytes: read("tests/network-automation-scenario-harness/Cargo.toml")?,
        cargo_lock_bytes: read("tests/network-automation-scenario-harness/Cargo.lock")?,
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn check_schema_identity(
    bytes: &[u8],
    expected_id: &str,
    label: &str,
) -> Result<SchemaIdentity, String> {
    let schema: SchemaIdentity = parse_json(bytes, label)?;
    if schema.schema_draft != "https://json-schema.org/draft/2020-12/schema" {
        return Err(format!("{label} uses an unsupported schema draft"));
    }
    if schema.schema_id != expected_id {
        return Err(format!("{label} identity mismatch"));
    }
    let version_const = schema
        .properties
        .get("schema_version")
        .and_then(|value| value.get("const"))
        .and_then(Value::as_u64);
    if version_const != Some(1) {
        return Err(format!("{label} must require schema_version const 1"));
    }
    Ok(schema)
}

fn valid_task_id(value: &str) -> bool {
    let Some((prefix, suffix)) = value.rsplit_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && suffix.len() == 3
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_scenario_id(value: &str) -> bool {
    value.strip_prefix("FX-").is_some_and(|suffix| {
        suffix.len() == 3 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn expected_pair_is_supported(decision: &str, state: &str) -> bool {
    match decision {
        "AcceptReadOnly" => state == "CompleteForDeclaredScope",
        "Incomplete" => state == "Incomplete",
        "Reject" => matches!(state, "Invalid" | "Expired" | "Unsupported"),
        "BlockMutation" => matches!(state, "Blocked" | "Incomplete" | "Conflict" | "Unsupported"),
        "RequireApproval" => matches!(state, "Blocked" | "Expired"),
        "MarkIndeterminate" => state == "Indeterminate",
        "EscalateHuman" => matches!(state, "Conflict" | "Unsupported" | "Incomplete"),
        "AbortRollout" => matches!(state, "Blocked" | "Indeterminate" | "Recovered"),
        "RecoverAndVerify" => matches!(state, "Recovered" | "Indeterminate"),
        "ApplyAndVerify" => state == "AppliedAndVerified",
        _ => false,
    }
}

fn evaluate_fault(fault_class: &str, layer: &str) -> Result<Outcome, String> {
    let outcome = match fault_class {
        "missing-terminal" | "interrupted-dump" | "receive-loss" => Outcome {
            decision: "Incomplete",
            receipt_state: "Incomplete",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "event-gap" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Incomplete",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "target-substitution" | "plan-tampering" | "approval-replay" | "secret-leak" => Outcome {
            decision: "Reject",
            receipt_state: "Invalid",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "ownership-conflict" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Blocked",
            resource_fenced: true,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "unknown-field" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Unsupported",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "out-of-domain-model" | "physical-state-ambiguous" => Outcome {
            decision: "EscalateHuman",
            receipt_state: "Unsupported",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "management-path-loss" | "route-leak" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Blocked",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "canary-health-regression" => Outcome {
            decision: "AbortRollout",
            receipt_state: "Blocked",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "external-writer-race" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Conflict",
            resource_fenced: true,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "management-disconnect" => Outcome {
            decision: "RecoverAndVerify",
            receipt_state: "Recovered",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: true,
        },
        "broker-crash-after-apply" | "rollback-failure" => Outcome {
            decision: "MarkIndeterminate",
            receipt_state: "Indeterminate",
            resource_fenced: true,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "critical-asset-misclassification" | "contradictory-timeline" => Outcome {
            decision: "EscalateHuman",
            receipt_state: "Conflict",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        "complete-empty-family" => Outcome {
            decision: "AcceptReadOnly",
            receipt_state: "CompleteForDeclaredScope",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: true,
        },
        "bounded-create-success" if layer == "virtual-lab" => Outcome {
            decision: "ApplyAndVerify",
            receipt_state: "AppliedAndVerified",
            resource_fenced: false,
            simulated_mutation_applied: true,
            postconditions_modelled_verified: true,
        },
        "bounded-create-success" => Outcome::blocked(),
        "false-positive-signature" => Outcome {
            decision: "BlockMutation",
            receipt_state: "Blocked",
            resource_fenced: false,
            simulated_mutation_applied: false,
            postconditions_modelled_verified: false,
        },
        unknown => return Err(format!("unsupported fault_class: {unknown}")),
    };

    if outcome.simulated_mutation_applied && layer != "virtual-lab" {
        return Ok(Outcome::blocked());
    }
    Ok(outcome)
}

fn execute_scenario(
    scenario: &Scenario,
    task_ids: &BTreeSet<String>,
) -> Result<ScenarioResult, String> {
    if !valid_scenario_id(&scenario.scenario_id) {
        return Err(format!("invalid scenario ID: {}", scenario.scenario_id));
    }
    if !valid_task_id(&scenario.task_id) || !task_ids.contains(&scenario.task_id) {
        return Err(format!(
            "{} references unknown or invalid task ID {}",
            scenario.scenario_id, scenario.task_id
        ));
    }
    if scenario.production_mutation {
        return Err(format!(
            "{} violates the no-production-mutation invariant",
            scenario.scenario_id
        ));
    }
    if scenario.setup.trim().is_empty() || scenario.assertions.is_empty() {
        return Err(format!(
            "{} has no setup description or assertions",
            scenario.scenario_id
        ));
    }
    if !expected_pair_is_supported(
        &scenario.expected_decision,
        &scenario.expected_receipt_state,
    ) {
        return Err(format!(
            "{} has an unsupported expected decision/receipt-state pair",
            scenario.scenario_id
        ));
    }

    let outcome = evaluate_fault(&scenario.fault_class, &scenario.layer)?;
    let fence_required = matches!(
        scenario.fault_class.as_str(),
        "ownership-conflict"
            | "external-writer-race"
            | "broker-crash-after-apply"
            | "rollback-failure"
    ) || outcome.receipt_state == "Indeterminate";
    let mutation_layer_safe =
        !outcome.simulated_mutation_applied || scenario.layer == "virtual-lab";
    let fence_satisfied = !fence_required || outcome.resource_fenced;

    let checks = vec![
        CheckResult {
            check_id: "expected_decision_matches".into(),
            passed: outcome.decision == scenario.expected_decision,
        },
        CheckResult {
            check_id: "expected_receipt_state_matches".into(),
            passed: outcome.receipt_state == scenario.expected_receipt_state,
        },
        CheckResult {
            check_id: "production_mutation_forbidden".into(),
            passed: !scenario.production_mutation,
        },
        CheckResult {
            check_id: "positive_mutation_is_virtual_lab_only".into(),
            passed: mutation_layer_safe,
        },
        CheckResult {
            check_id: "required_resource_fence_is_active".into(),
            passed: fence_satisfied,
        },
        CheckResult {
            check_id: "recovered_or_applied_state_has_modelled_postconditions".into(),
            passed: !matches!(outcome.receipt_state, "Recovered" | "AppliedAndVerified")
                || outcome.postconditions_modelled_verified,
        },
        CheckResult {
            check_id: "expected_pair_is_supported".into(),
            passed: expected_pair_is_supported(
                &scenario.expected_decision,
                &scenario.expected_receipt_state,
            ),
        },
        CheckResult {
            check_id: "declared_assertions_non_empty".into(),
            passed: !scenario.assertions.is_empty(),
        },
    ];
    let passed = checks.iter().all(|check| check.passed);

    Ok(ScenarioResult {
        scenario_id: scenario.scenario_id.clone(),
        task_id: scenario.task_id.clone(),
        layer: scenario.layer.clone(),
        fault_class: scenario.fault_class.clone(),
        expected_decision: scenario.expected_decision.clone(),
        actual_decision: outcome.decision.into(),
        expected_receipt_state: scenario.expected_receipt_state.clone(),
        actual_receipt_state: outcome.receipt_state.into(),
        resource_fenced: outcome.resource_fenced,
        simulated_mutation_applied: outcome.simulated_mutation_applied,
        postconditions_modelled_verified: outcome.postconditions_modelled_verified,
        production_mutation_applied: false,
        declared_assertions: scenario.assertions.clone(),
        checks,
        passed,
    })
}

#[cfg(test)]
#[derive(Debug, Default)]
struct SimulatedResourceFence {
    fenced_resources: BTreeSet<String>,
    write_counts: BTreeMap<String, u64>,
}

#[cfg(test)]
impl SimulatedResourceFence {
    fn record_write(&mut self, resource: &str) -> Result<u64, String> {
        if self.fenced_resources.contains(resource) {
            return Err(format!("resource {resource} is fenced pending terminal evidence"));
        }
        let count = self.write_counts.entry(resource.to_owned()).or_insert(0);
        *count += 1;
        Ok(*count)
    }

    fn mark_indeterminate(&mut self, resource: &str) {
        self.fenced_resources.insert(resource.to_owned());
    }

    fn is_fenced(&self, resource: &str) -> bool {
        self.fenced_resources.contains(resource)
    }

    fn write_count(&self, resource: &str) -> u64 {
        self.write_counts.get(resource).copied().unwrap_or(0)
    }

    fn clear_after_verified_recovery(
        &mut self,
        resource: &str,
        recovery_receipt_blake3: Option<&str>,
    ) -> Result<(), String> {
        let digest = recovery_receipt_blake3.unwrap_or_default();
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("fence removal requires a verified 32-byte receipt digest".into());
        }
        self.fenced_resources.remove(resource);
        Ok(())
    }
}

pub fn build_receipt(input: &InputArtifacts) -> Result<ReceiptEnvelope, String> {
    let task_schema = check_schema_identity(
        &input.task_schema_bytes,
        TASK_SCHEMA_ID,
        "task corpus schema",
    )?;
    let fault_schema = check_schema_identity(
        &input.fault_schema_bytes,
        FAULT_SCHEMA_ID,
        "fault fixture schema",
    )?;
    let task_corpus: TaskCorpus = parse_json(&input.task_corpus_bytes, "task corpus")?;
    let fault_corpus: FaultCorpus = parse_json(&input.fault_fixture_bytes, "fault fixture corpus")?;

    if task_corpus.schema_version != 1
        || task_corpus.status != "qualification-design-only"
        || task_corpus.artifact_id != TASK_ARTIFACT_ID
    {
        return Err("task corpus identity/version/status is unsupported".into());
    }
    if fault_corpus.schema_version != 1
        || fault_corpus.status != "qualification-design-only"
        || fault_corpus.artifact_id != FAULT_ARTIFACT_ID
    {
        return Err("fault fixture identity/version/status is unsupported".into());
    }
    if fault_corpus.task_corpus_artifact_id != task_corpus.artifact_id {
        return Err("fault fixtures reference a different task corpus identity".into());
    }
    if fault_corpus.common_invariants.is_empty() {
        return Err("fault fixture common_invariants must not be empty".into());
    }
    if task_schema.properties.get("tasks").is_none()
        || fault_schema.properties.get("scenarios").is_none()
    {
        return Err("schema is missing its required top-level collection property".into());
    }

    let mut task_ids = BTreeSet::new();
    for task in &task_corpus.tasks {
        if !valid_task_id(&task.task_id) {
            return Err(format!("invalid task ID: {}", task.task_id));
        }
        if !task_ids.insert(task.task_id.clone()) {
            return Err(format!("duplicate task ID: {}", task.task_id));
        }
    }

    let mut scenario_ids = BTreeSet::new();
    let mut covered_tasks = BTreeSet::new();
    for scenario in &fault_corpus.scenarios {
        if !scenario_ids.insert(scenario.scenario_id.clone()) {
            return Err(format!("duplicate scenario ID: {}", scenario.scenario_id));
        }
        if !task_ids.contains(&scenario.task_id) {
            return Err(format!("fixture references unknown task ID: {}", scenario.task_id));
        }
        if scenario.production_mutation {
            return Err(format!("fixture {} permits production mutation", scenario.scenario_id));
        }
        if scenario.assertions.is_empty() {
            return Err(format!("fixture {} has no assertions", scenario.scenario_id));
        }
        covered_tasks.insert(scenario.task_id.clone());
    }
    let uncovered = task_ids.difference(&covered_tasks).cloned().collect::<Vec<_>>();
    if !uncovered.is_empty() {
        return Err(format!("tasks without fixtures: {}", uncovered.join(", ")));
    }
    if fault_corpus.scenarios.is_empty() {
        return Err("fault fixture corpus must not be empty".into());
    }

    let mut scenarios = fault_corpus.scenarios.clone();
    scenarios.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    let mut results = Vec::with_capacity(scenarios.len());
    for scenario in &scenarios {
        results.push(execute_scenario(scenario, &task_ids)?);
    }

    let mut decision_counts = BTreeMap::new();
    let mut receipt_state_counts = BTreeMap::new();
    for result in &results {
        *decision_counts.entry(result.actual_decision.clone()).or_insert(0usize) += 1;
        *receipt_state_counts.entry(result.actual_receipt_state.clone()).or_insert(0usize) += 1;
    }
    let all_passed = results.iter().all(|result| result.passed);
    let receipt = RunReceipt {
        receipt_schema_version: 1,
        status: if all_passed { "pass" } else { "fail" }.into(),
        evaluator_id: format!(
            "nixward-network-automation-scenario-harness/{}",
            env!("CARGO_PKG_VERSION")
        ),
        rustc_version: option_env!("NIXWARD_SCENARIO_RUSTC_VERSION")
            .unwrap_or("rustc-version-not-injected")
            .into(),
        cargo_version: option_env!("NIXWARD_SCENARIO_CARGO_VERSION")
            .unwrap_or("cargo-version-not-injected")
            .into(),
        input_digests: ArtifactDigests {
            task_corpus_blake3: artifact_digest(&input.task_corpus_bytes),
            task_schema_blake3: artifact_digest(&input.task_schema_bytes),
            fault_fixtures_blake3: artifact_digest(&input.fault_fixture_bytes),
            fault_schema_blake3: artifact_digest(&input.fault_schema_bytes),
            cargo_manifest_blake3: artifact_digest(&input.cargo_manifest_bytes),
            cargo_lock_blake3: artifact_digest(&input.cargo_lock_bytes),
            evaluator_source_blake3: evaluator_source_digest(),
        },
        task_corpus_schema_version: task_corpus.schema_version,
        fault_fixture_schema_version: fault_corpus.schema_version,
        task_count: task_corpus.tasks.len(),
        scenario_count: results.len(),
        unique_task_ids: task_ids.len(),
        unique_scenario_ids: scenario_ids.len(),
        decision_counts,
        receipt_state_counts,
        production_mutation_enabled: false,
        results,
        limitations: vec![
            "This is a deterministic decision-model evaluation over declared fixture labels, not execution of real kernel, routing, or firewall operations.".into(),
            "The declared natural-language assertions are included for traceability; only the named machine checks are evaluated by this harness.".into(),
            "A pass does not qualify a live observer, Netlink completeness, Batfish model, containerlab topology, network mutation broker, hardware, or production deployment.".into(),
            "The positive create case mutates only a modeled virtual state; it does not touch a host or network.".into(),
            "The checked-in Python validator is required for the supported JSON Schema keyword subset; this Rust crate is not a general JSON Schema implementation.".into(),
        ],
    };
    let receipt_bytes =
        serde_json::to_vec(&receipt).map_err(|error| format!("cannot serialize receipt: {error}"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_DOMAIN);
    hasher.update(&(receipt_bytes.len() as u64).to_be_bytes());
    hasher.update(&receipt_bytes);
    let receipt_blake3 = hasher.finalize().to_hex().to_string();
    Ok(ReceiptEnvelope { receipt_blake3, receipt })
}

pub fn serialize_envelope(envelope: &ReceiptEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(envelope)
        .map_err(|error| format!("cannot serialize receipt envelope: {error}"))
}

pub fn evaluate_repository(root: &Path) -> Result<(ReceiptEnvelope, Vec<u8>), String> {
    let input = load_input_artifacts(root)?;
    let envelope = build_receipt(&input)?;
    let bytes = serialize_envelope(&envelope)?;
    Ok((envelope, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn inputs() -> InputArtifacts {
        load_input_artifacts(&repository_root().expect("repository root"))
            .expect("input artifacts")
    }

    fn parse_fixture_value(input: &InputArtifacts) -> Value {
        serde_json::from_slice(&input.fault_fixture_bytes).expect("valid fixture JSON")
    }

    fn replace_fixture_value(input: &mut InputArtifacts, value: &Value) {
        input.fault_fixture_bytes = serde_json::to_vec(value).expect("serialize mutation");
    }

    #[test]
    fn all_checked_in_scenarios_match_the_evaluator() {
        let (receipt, _) =
            evaluate_repository(&repository_root().expect("root")).expect("receipt");

        assert_eq!(receipt.receipt.status, "pass");
        assert_eq!(receipt.receipt.task_count, 16);
        assert_eq!(receipt.receipt.scenario_count, 25);
        assert_eq!(receipt.receipt.unique_task_ids, 16);
        assert_eq!(receipt.receipt.unique_scenario_ids, 25);
        assert!(!receipt.receipt.production_mutation_enabled);
        assert!(receipt.receipt.results.iter().all(|result| result.passed));
    }

    #[test]
    fn a_changed_expected_decision_is_detected_by_the_oracle() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        let scenarios = value["scenarios"].as_array_mut().expect("scenario array");
        let case = scenarios
            .iter_mut()
            .find(|case| case["scenario_id"] == "FX-001")
            .expect("FX-001");
        case["expected_decision"] = Value::String("Reject".into());
        case["expected_receipt_state"] = Value::String("Invalid".into());
        replace_fixture_value(&mut input, &value);

        let receipt =
            build_receipt(&input).expect("mismatched oracle should produce a failing receipt");
        assert_eq!(receipt.receipt.status, "fail");
        let row = receipt
            .receipt
            .results
            .iter()
            .find(|result| result.scenario_id == "FX-001")
            .expect("result");
        assert!(!row.passed);
        assert!(row.checks.iter().any(|check| {
            check.check_id == "expected_decision_matches" && !check.passed
        }));
    }

    #[test]
    fn an_unknown_fault_kind_fails_closed() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        value["scenarios"][0]["fault_class"] = Value::String("unmodelled-fault".into());
        replace_fixture_value(&mut input, &value);

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("unsupported fault_class"));
    }

    #[test]
    fn production_mutation_fixture_is_rejected() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        value["scenarios"][0]["production_mutation"] = Value::Bool(true);
        replace_fixture_value(&mut input, &value);

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("permits production mutation"));
    }

    #[test]
    fn a_positive_create_oracle_cannot_leave_the_virtual_lab() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        let scenarios = value["scenarios"].as_array_mut().expect("array");
        let case = scenarios
            .iter_mut()
            .find(|case| case["scenario_id"] == "FX-024")
            .expect("FX-024");
        case["layer"] = Value::String("offline-model".into());
        replace_fixture_value(&mut input, &value);

        let receipt = build_receipt(&input)
            .expect("changed layer should be recorded as an oracle mismatch");
        assert_eq!(receipt.receipt.status, "fail");
        let row = receipt
            .receipt
            .results
            .iter()
            .find(|result| result.scenario_id == "FX-024")
            .expect("result");
        assert!(!row.passed);
        assert!(!row.simulated_mutation_applied);
    }

    #[test]
    fn indeterminate_crash_and_rollback_are_fenced() {
        let (receipt, _) =
            evaluate_repository(&repository_root().expect("root")).expect("receipt");
        for scenario_id in ["FX-011", "FX-012"] {
            let row = receipt
                .receipt
                .results
                .iter()
                .find(|result| result.scenario_id == scenario_id)
                .expect("row");
            assert_eq!(row.actual_receipt_state, "Indeterminate");
            assert!(row.resource_fenced);
            assert!(!row.simulated_mutation_applied);
            assert!(!row.production_mutation_applied);
        }
    }

    #[test]
    fn external_writer_conflict_is_fenced() {
        let (receipt, _) =
            evaluate_repository(&repository_root().expect("root")).expect("receipt");
        let row = receipt
            .receipt
            .results
            .iter()
            .find(|result| result.scenario_id == "FX-009")
            .expect("row");
        assert_eq!(row.actual_receipt_state, "Conflict");
        assert!(row.resource_fenced);
    }

    #[test]
    fn indeterminate_transaction_fences_follow_up_writes() {
        let mut ledger = SimulatedResourceFence::default();
        let resource = "lab:firewall-management";

        assert_eq!(ledger.record_write(resource).expect("first simulated write"), 1);
        ledger.mark_indeterminate(resource);

        assert!(ledger.is_fenced(resource));
        assert!(ledger.record_write(resource).is_err());
        assert_eq!(ledger.write_count(resource), 1);
        assert_eq!(
            ledger.record_write("lab:unrelated-interface").expect("unrelated scope"),
            1
        );
    }

    #[test]
    fn only_verified_recovery_receipt_can_clear_resource_fence() {
        let mut ledger = SimulatedResourceFence::default();
        let resource = "lab:default-route";
        ledger.mark_indeterminate(resource);

        assert!(ledger.clear_after_verified_recovery(resource, None).is_err());
        assert!(ledger.is_fenced(resource));
        assert!(ledger
            .clear_after_verified_recovery(resource, Some(&"a".repeat(64)))
            .is_ok());
        assert!(!ledger.is_fenced(resource));
        assert_eq!(
            ledger.record_write(resource).expect("write after verified recovery"),
            1
        );
    }

    #[test]
    fn receipt_is_byte_deterministic_for_identical_inputs() {
        let input = inputs();
        let first = serialize_envelope(&build_receipt(&input).expect("first receipt"))
            .expect("first bytes");
        let second = serialize_envelope(&build_receipt(&input).expect("second receipt"))
            .expect("second bytes");

        assert_eq!(first, second);
    }

    #[test]
    fn receipt_binds_exact_raw_artifact_bytes() {
        let original = inputs();
        let base = build_receipt(&original).expect("original receipt");
        let mut changed = original.clone();
        changed.fault_fixture_bytes.push(b'\n');
        let changed_receipt = build_receipt(&changed)
            .expect("receipt for semantically identical but byte-different fixture");

        assert_ne!(
            base.receipt.input_digests.fault_fixtures_blake3,
            changed_receipt.receipt.input_digests.fault_fixtures_blake3
        );
        assert_ne!(base.receipt_blake3, changed_receipt.receipt_blake3);
    }

    #[test]
    fn task_corpus_identity_substitution_is_rejected() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        value["task_corpus_artifact_id"] = Value::String("another-corpus".into());
        replace_fixture_value(&mut input, &value);

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("different task corpus identity"));
    }

    #[test]
    fn task_corpus_artifact_id_substitution_is_rejected() {
        let mut input = inputs();
        let mut value: Value =
            serde_json::from_slice(&input.task_corpus_bytes).expect("task corpus JSON");
        value["artifact_id"] = Value::String("nixward.other-corpus.v1".into());
        input.task_corpus_bytes = serde_json::to_vec(&value).expect("serialize mutation");

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("task corpus identity/version/status"));
    }

    #[test]
    fn schema_identity_substitution_is_rejected() {
        let mut input = inputs();
        let mut value: Value =
            serde_json::from_slice(&input.task_schema_bytes).expect("task schema JSON");
        value["$id"] = Value::String("urn:wrong-schema".into());
        input.task_schema_bytes = serde_json::to_vec(&value).expect("serialize mutation");

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("task corpus schema identity mismatch"));
    }

    #[test]
    fn duplicate_scenario_id_is_rejected() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        let scenarios = value["scenarios"].as_array_mut().expect("array");
        scenarios[1]["scenario_id"] = scenarios[0]["scenario_id"].clone();
        replace_fixture_value(&mut input, &value);

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("duplicate scenario ID"));
    }

    #[test]
    fn missing_task_coverage_is_rejected() {
        let mut input = inputs();
        let mut value = parse_fixture_value(&input);
        let scenarios = value["scenarios"].as_array_mut().expect("array");
        scenarios.retain(|case| case["task_id"].as_str() != Some("FIX-001"));
        replace_fixture_value(&mut input, &value);

        assert!(build_receipt(&input)
            .unwrap_err()
            .contains("tasks without fixtures: FIX-001"));
    }

    #[test]
    fn receipt_cannot_claim_live_or_production_qualification() {
        let (receipt, _) =
            evaluate_repository(&repository_root().expect("root")).expect("receipt");

        assert!(receipt.receipt.limitations.iter().any(|text| {
            text.contains("not execution of real kernel")
        }));
        assert!(receipt.receipt.limitations.iter().any(|text| {
            text.contains("does not qualify a live observer")
        }));
        assert!(!receipt.receipt.production_mutation_enabled);
        assert!(receipt
            .receipt
            .results
            .iter()
            .all(|result| !result.production_mutation_applied));
    }
}
