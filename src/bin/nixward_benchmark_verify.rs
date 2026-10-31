// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only integrity verifier for deployment benchmark trial evidence.
//! It verifies hashes, evidence completeness, corpus pinning, matched trial
//! identity and trial floors. It does not run deployments or prove semantics.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process;

const RECORD_SCHEMA: &str = "org.luminousdynamics.nixward.deployment-transaction-trial";
const RECORD_VERSION: u64 = 1;
const MATCH_KEYS: &[&str] = &[
    "nixpkgs_revision", "flake_lock_sha256", "candidate_closure_digest",
    "vm_image_digest", "kernel_version", "systemd_version",
    "filesystem_mount_options", "storage_cache_policy", "network_profile",
    "operation_mode", "concurrency", "cache_state",
];
const SAFETY_COUNTERS: &[&str] = &[
    "false_terminal_success_count",
    "duplicate_mutation_for_unresolved_attempt_count",
    "unauthorized_or_replayed_admission_count",
    "foreign_transaction_attempt_worker_or_invocation_acceptance_count",
    "payload_release_before_durable_admission_and_worker_identity_count",
];
const RECORD_KEYS: &[&str] = &[
    "schema", "version", "trial_id", "scenario_id", "baseline_id",
    "comparison_group", "operation_mode", "trial_index", "trial_seed",
    "corpus_sha256", "evidence", "match_fingerprint", "observation_labels",
    "phase_timestamps_ns", "safety_counters", "safe_hold", "scored_as_success",
    "terminal_evidence_complete", "terminal_disposition", "artifacts",
    "record_sha256",
];

#[derive(Debug)]
struct Options {
    corpus: PathBuf,
    records: PathBuf,
    artifact_root: PathBuf,
    require_complete: bool,
    allow_gated: bool,
}

#[derive(Debug)]
struct TrialMeta {
    trial_id: String,
    record_sha256: String,
    scenario: String,
    baseline: String,
    index: u64,
    seed: String,
    fingerprint: String,
    baseline_status: String,
}

fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("{key} must be a non-empty string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn record_digest(value: &Value) -> Result<String, String> {
    let mut copy = value.clone();
    copy.as_object_mut().ok_or("trial record must be an object")?.remove("record_sha256");
    let bytes = serde_json::to_vec(&copy).map_err(|e| e.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn canonical_artifact_root(path: &Path) -> Result<PathBuf, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat artifact root {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("artifact root must be a real directory, not a symlink".into());
    }
    fs::canonicalize(path).map_err(|e| format!("cannot canonicalize artifact root: {e}"))
}

fn verify_artifact(root: &Path, artifact: &Value) -> Result<(), String> {
    let relative = str_field(artifact, "path")?;
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(format!("artifact path must be relative: {relative}"));
    }
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err("artifact path is empty".into());
    }
    let mut current = root.to_path_buf();
    for (i, component) in components.iter().enumerate() {
        match component {
            Component::Normal(part) => current.push(part),
            _ => return Err(format!("artifact path contains traversal: {relative}")),
        }
        let meta = fs::symlink_metadata(&current)
            .map_err(|e| format!("cannot stat artifact {relative}: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("artifact path traverses a symlink: {relative}"));
        }
        if i + 1 < components.len() && !meta.is_dir() {
            return Err(format!("artifact parent is not a directory: {relative}"));
        }
        if i + 1 == components.len() && !meta.is_file() {
            return Err(format!("artifact is not a regular file: {relative}"));
        }
    }
    let bytes = fs::read(&current).map_err(|e| format!("cannot read artifact {relative}: {e}"))?;
    let length = artifact.get("byte_length").and_then(Value::as_u64)
        .ok_or_else(|| format!("artifact {relative} byte_length must be an unsigned integer"))?;
    let expected_sha = str_field(artifact, "sha256")?;
    if !is_sha256(expected_sha) {
        return Err(format!("artifact {relative} has malformed SHA-256"));
    }
    if bytes.is_empty() || bytes.len() as u64 != length {
        return Err(format!("artifact {relative} byte length mismatch"));
    }
    if sha256_hex(&bytes) != expected_sha {
        return Err(format!("artifact {relative} SHA-256 mismatch"));
    }
    Ok(())
}

fn validate_record(
    record: &Value,
    corpus_sha: &str,
    required_evidence: &[String],
    scenarios: &BTreeMap<String, Value>,
    baselines: &BTreeMap<String, String>,
    root: &Path,
    allow_gated: bool,
) -> Result<TrialMeta, String> {
    let object = record.as_object().ok_or("trial record must be an object")?;
    for key in object.keys() {
        if !RECORD_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown trial-record field: {key}"));
        }
    }
    if str_field(record, "schema")? != RECORD_SCHEMA
        || record.get("version").and_then(Value::as_u64) != Some(RECORD_VERSION)
    {
        return Err("unsupported trial-record schema/version".into());
    }
    str_field(record, "trial_id")?;
    let scenario_id = str_field(record, "scenario_id")?.to_string();
    let baseline_id = str_field(record, "baseline_id")?.to_string();
    let scenario = scenarios.get(&scenario_id)
        .ok_or_else(|| format!("unknown scenario {scenario_id}"))?;
    let supported = scenario.get("supported_baselines").and_then(Value::as_array)
        .ok_or("corpus scenario supported_baselines missing")?;
    if !supported.iter().any(|v| v.as_str() == Some(&baseline_id)) {
        return Err(format!("baseline {baseline_id} is not allowed for {scenario_id}"));
    }
    let expected_group = str_field(scenario, "comparison_group")?;
    let expected_mode = str_field(scenario, "operation_mode")?;
    if str_field(record, "comparison_group")? != expected_group {
        return Err("comparison_group differs from corpus".into());
    }
    if str_field(record, "operation_mode")? != expected_mode {
        return Err("operation_mode differs from corpus".into());
    }
    if str_field(record, "corpus_sha256")? != corpus_sha {
        return Err("corpus_sha256 does not match exact corpus bytes".into());
    }
    let baseline_status = baselines.get(&baseline_id)
        .ok_or_else(|| format!("unknown baseline {baseline_id}"))?.clone();
    if baseline_status == "gated-not-yet-qualified" && !allow_gated {
        return Err(format!("baseline {baseline_id} is gated; use --allow-gated only for exploratory records"));
    }

    let evidence = record.get("evidence").and_then(Value::as_object)
        .ok_or("evidence must be an object")?;
    for field in required_evidence {
        let value = evidence.get(field).and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("missing or empty evidence field {field}"))?;
        if value == "n/a" || value == "not-applicable" {
            return Err(format!("evidence.{field} needs an explicit not-applicable reason"));
        }
        if field == "scenario_corpus_sha256" && value != corpus_sha {
            return Err("evidence.scenario_corpus_sha256 does not match exact corpus bytes".into());
        }
        if value.starts_with("not-applicable:") && value["not-applicable:".len()..].trim().is_empty() {
            return Err(format!("evidence.{field} has an empty not-applicable reason"));
        }
        if field == "raw_trial_record_digest_and_terminal_classification"
            && value != "verifier-derived"
        {
            return Err("raw_trial_record_digest_and_terminal_classification must be verifier-derived".into());
        }
    }

    let fingerprint = record.get("match_fingerprint").and_then(Value::as_object)
        .ok_or("match_fingerprint must be an object")?;
    if fingerprint.len() != MATCH_KEYS.len() {
        return Err("match_fingerprint must contain exactly the normative fields".into());
    }
    for key in MATCH_KEYS {
        let value = fingerprint.get(*key).and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| format!("match_fingerprint.{key} must be a non-empty string"))?;
        if value.starts_with("not-applicable") {
            return Err(format!("match_fingerprint.{key} cannot be not-applicable"));
        }
    }
    if fingerprint.get("operation_mode").and_then(Value::as_str) != Some(expected_mode) {
        return Err("match_fingerprint.operation_mode differs from corpus".into());
    }
    let fingerprint_sha = sha256_hex(&serde_json::to_vec(&Value::Object(fingerprint.clone()))
        .map_err(|e| e.to_string())?);

    let labels = record.get("observation_labels").and_then(Value::as_array)
        .ok_or("observation_labels must be an array")?;
    let required_labels = scenario.get("required_observations").and_then(Value::as_array)
        .ok_or("corpus required_observations missing")?;
    for required in required_labels {
        let label = required.as_str().ok_or("corpus observation label must be a string")?;
        if !labels.iter().any(|v| v.as_str() == Some(label)) {
            return Err(format!("required observation label missing: {label}"));
        }
    }

    let phases = record.get("phase_timestamps_ns").and_then(Value::as_array)
        .filter(|v| v.len() >= 2).ok_or("phase_timestamps_ns must contain at least two phases")?;
    let mut previous = None;
    let mut phase_names = BTreeSet::new();
    for phase in phases {
        let name = str_field(phase, "phase")?;
        let timestamp = phase.get("monotonic_ns").and_then(Value::as_u64)
            .ok_or_else(|| format!("phase {name} monotonic_ns must be unsigned"))?;
        if !phase_names.insert(name.to_string()) {
            return Err(format!("duplicate phase name: {name}"));
        }
        if previous.is_some_and(|prev| timestamp <= prev) {
            return Err("phase timestamps are not strictly increasing".into());
        }
        previous = Some(timestamp);
    }

    let counters = record.get("safety_counters").and_then(Value::as_object)
        .ok_or("safety_counters must be an object")?;
    if counters.len() != SAFETY_COUNTERS.len() {
        return Err("safety_counters must contain exactly the normative counters".into());
    }
    for counter in SAFETY_COUNTERS {
        let value = counters.get(*counter).and_then(Value::as_u64)
            .ok_or_else(|| format!("missing/invalid safety counter {counter}"))?;
        if value != 0 {
            return Err(format!("safety counter {counter} is non-zero: {value}"));
        }
    }
    let safe_hold = record.get("safe_hold").and_then(Value::as_bool)
        .ok_or("safe_hold must be boolean")?;
    let scored_as_success = record.get("scored_as_success").and_then(Value::as_bool)
        .ok_or("scored_as_success must be boolean")?;
    if safe_hold && scored_as_success {
        return Err("safe hold cannot be scored as successful recovery".into());
    }
    if scored_as_success && record.get("terminal_evidence_complete").and_then(Value::as_bool) != Some(true) {
        return Err("successful disposition must declare complete terminal evidence".into());
    }
    str_field(record, "terminal_disposition")?;

    let artifacts = record.get("artifacts").and_then(Value::as_array)
        .filter(|v| !v.is_empty()).ok_or("artifacts must contain at least one entry")?;
    let mut artifact_paths = BTreeSet::new();
    for artifact in artifacts {
        let path = str_field(artifact, "path")?.to_string();
        if !artifact_paths.insert(path.clone()) {
            return Err(format!("duplicate artifact path {path}"));
        }
        verify_artifact(root, artifact)?;
    }

    let expected_record_sha = str_field(record, "record_sha256")?;
    let computed_record_sha = record_digest(record)?;
    if !is_sha256(expected_record_sha) || computed_record_sha != expected_record_sha {
        return Err("record_sha256 does not match canonical record digest".into());
    }
    let trial_index = record.get("trial_index").and_then(Value::as_u64)
        .ok_or("trial_index must be an unsigned integer")?;
    Ok(TrialMeta {
        trial_id: str_field(record, "trial_id")?.to_string(),
        record_sha256: computed_record_sha,
        scenario: scenario_id,
        baseline: baseline_id,
        index: trial_index,
        seed: str_field(record, "trial_seed")?.to_string(),
        fingerprint: fingerprint_sha,
        baseline_status,
    })
}

fn audit(corpus_bytes: &[u8], records_bytes: &[u8], artifact_root_path: &Path, allow_gated: bool) -> Result<Value, String> {
    let corpus_sha = sha256_hex(corpus_bytes);
    let corpus: Value = serde_json::from_slice(corpus_bytes).map_err(|e| format!("invalid corpus JSON: {e}"))?;
    if str_field(&corpus, "schema")? != "org.luminousdynamics.nixward.deployment-transaction-benchmark-corpus"
        || corpus.get("version").and_then(Value::as_u64) != Some(1)
        || str_field(&corpus, "status")? != "proposed-not-executed"
    {
        return Err("unsupported or already-executed benchmark corpus schema/version/status".into());
    }
    let required_evidence = corpus.get("trial_evidence_fields").and_then(Value::as_array)
        .ok_or("corpus trial_evidence_fields missing")?
        .iter().map(|item| item.as_str().map(str::to_string).ok_or("trial evidence field must be string"))
        .collect::<Result<Vec<_>, _>>()?;
    if required_evidence.is_empty() || required_evidence.iter().collect::<BTreeSet<_>>().len() != required_evidence.len() {
        return Err("corpus trial evidence fields must be non-empty and unique".into());
    }

    let mut scenarios = BTreeMap::new();
    for scenario in corpus.get("scenarios").and_then(Value::as_array).ok_or("corpus scenarios missing")? {
        let id = str_field(scenario, "id")?.to_string();
        if scenarios.insert(id.clone(), scenario.clone()).is_some() {
            return Err(format!("duplicate scenario ID {id}"));
        }
        let class = str_field(scenario, "trial_class")?;
        if !["clean-baseline", "fault-correctness", "concurrency-correctness", "storage-correctness", "performance"].contains(&class) {
            return Err(format!("scenario {id} has unknown trial_class {class}"));
        }
        let minimum = scenario.get("min_trials").and_then(Value::as_u64).ok_or("scenario min_trials invalid")?;
        let floor = if class == "clean-baseline" || class == "performance" { 30 } else { 100 };
        if minimum < floor {
            return Err(format!("scenario {id} weakens normative floor below {floor}"));
        }
    }

    let mut baselines = BTreeMap::new();
    for baseline in corpus.get("baseline_registry").and_then(Value::as_array).ok_or("corpus baseline_registry missing")? {
        let id = str_field(baseline, "id")?.to_string();
        let status = str_field(baseline, "status")?.to_string();
        if !["available-baseline", "gated-not-yet-qualified", "prototype-only"].contains(&status.as_str()) {
            return Err(format!("baseline {id} has unknown status {status}"));
        }
        if baselines.insert(id.clone(), status).is_some() {
            return Err(format!("duplicate baseline ID {id}"));
        }
    }
    let records: Value = serde_json::from_slice(records_bytes).map_err(|e| format!("invalid records JSON: {e}"))?;
    let records = records.as_array().ok_or("records document must be a JSON array")?;
    let root = canonical_artifact_root(artifact_root_path)?;

    let mut errors = Vec::new();
    let mut records_verified = 0u64;
    let mut trial_ids = BTreeSet::new();
    let mut trial_keys = BTreeSet::new();
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut matched: BTreeMap<(String, u64), Vec<(String, String, String)>> = BTreeMap::new();
    let mut verified_manifest = Vec::new();
    for record in records {
        let id = record.get("trial_id").and_then(Value::as_str).unwrap_or("<missing>");
        let result = validate_record(record, &corpus_sha, &required_evidence, &scenarios, &baselines, &root, allow_gated);
        match result {
            Ok(meta) => {
                if !trial_ids.insert(id.to_string()) {
                    errors.push(format!("trial {id}: duplicate trial_id"));
                    continue;
                }
                if !trial_keys.insert((meta.scenario.clone(), meta.baseline.clone(), meta.index)) {
                    errors.push(format!("trial {id}: duplicate scenario/baseline/index"));
                    continue;
                }
                records_verified += 1;
                verified_manifest.push(json!({
                    "trial_id": meta.trial_id.clone(),
                    "record_sha256": meta.record_sha256.clone(),
                    "scenario_id": meta.scenario.clone(),
                    "baseline_id": meta.baseline.clone(),
                    "trial_index": meta.index,
                    "baseline_status": meta.baseline_status.clone()
                }));
                *counts.entry((meta.scenario.clone(), meta.baseline.clone())).or_default() += 1;
                if meta.baseline_status == "available-baseline" {
                    matched.entry((meta.scenario.clone(), meta.index)).or_default()
                        .push((meta.baseline, meta.seed, meta.fingerprint));
                }
            }
            Err(error) => errors.push(format!("trial {id}: {error}")),
        }
    }

    let mut floors = Vec::new();
    for (scenario_id, scenario) in &scenarios {
        let minimum = scenario.get("min_trials").and_then(Value::as_u64).unwrap();
        let supported = scenario.get("supported_baselines").and_then(Value::as_array).ok_or("scenario baselines missing")?;
        for baseline in supported {
            let baseline_id = baseline.as_str().ok_or("scenario baseline must be string")?;
            let status = baselines.get(baseline_id).ok_or("unknown scenario baseline")?;
            let observed = counts.get(&(scenario_id.clone(), baseline_id.to_string())).copied().unwrap_or(0);
            floors.push(json!({
                "scenario_id": scenario_id, "baseline_id": baseline_id, "baseline_status": status,
                "verified_trials": observed, "minimum_trials": minimum,
                "floor_met": observed >= minimum,
                "qualification_scope": status
            }));
        }
    }
    let mut comparisons = Vec::new();
    for ((scenario, index), rows) in matched {
        if rows.len() < 2 { continue; }
        let seeds = rows.iter().map(|row| row.1.clone()).collect::<BTreeSet<_>>();
        let fingerprints = rows.iter().map(|row| row.2.clone()).collect::<BTreeSet<_>>();
        let valid = seeds.len() == 1 && fingerprints.len() == 1;
        comparisons.push(json!({
            "scenario_id": scenario, "trial_index": index,
            "baselines": rows.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
            "trial_seed_equal": seeds.len() == 1,
            "environment_fingerprint_equal": fingerprints.len() == 1,
            "matched": valid
        }));
        if !valid {
            errors.push(format!("matched trial {scenario}/{index} differs in seed or environment fingerprint"));
        }
    }

    let incomplete = floors.iter().any(|floor| {
        floor["baseline_status"] == "available-baseline" && floor["floor_met"] == false
    });
    let status = if !errors.is_empty() { "invalid" }
        else if incomplete { "integrity-valid-incomplete" }
        else { "integrity-valid-available-baseline-floors-met" };
    Ok(json!({
        "schema": "org.luminousdynamics.nixward.deployment-transaction-evidence-audit",
        "version": 1,
        "status": status,
        "corpus_sha256": corpus_sha,
        "records_seen": records.len(),
        "records_verified": records_verified,
        "verified_record_manifest": verified_manifest,
        "available_baseline_floors_met": !incomplete,
        "errors": errors,
        "trial_floors": floors,
        "matched_trials": comparisons,
        "qualification": "artifact-integrity-only-not-operational-or-semantic-qualification",
        "limitations": [
            "A record digest is not a digital signature or proof of who produced the record.",
            "Artifact hashes prove byte identity, not that observations truthfully describe the host.",
            "Observation labels and safety counters remain runner declarations requiring independent semantic verification.",
            "This tool does not execute commands, mutate hosts, verify cryptographic authority, or establish SOTA performance."
        ]
    }))
}

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let (mut corpus, mut records, mut artifact_root) = (None, None, None);
    let (mut require_complete, mut allow_gated) = (false, false);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => corpus = args.next().map(PathBuf::from),
            "--records" => records = args.next().map(PathBuf::from),
            "--artifact-root" => artifact_root = args.next().map(PathBuf::from),
            "--require-complete" => require_complete = true,
            "--allow-gated" => allow_gated = true,
            "--help" | "-h" => {
                println!("nixward-benchmark-verify --corpus PATH --records PATH --artifact-root DIR [--require-complete] [--allow-gated]");
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Options {
        corpus: corpus.ok_or("--corpus is required")?,
        records: records.ok_or("--records is required")?,
        artifact_root: artifact_root.ok_or("--artifact-root is required")?,
        require_complete,
        allow_gated,
    })
}

fn run() -> Result<i32, String> {
    let options = parse_args()?;
    let corpus = fs::read(&options.corpus).map_err(|e| format!("cannot read corpus: {e}"))?;
    let records = fs::read(&options.records).map_err(|e| format!("cannot read records: {e}"))?;
    let report = audit(&corpus, &records, &options.artifact_root, options.allow_gated)?;
    let status = report["status"].as_str().unwrap_or("invalid");
    let has_errors = report["errors"].as_array().is_some_and(|items| !items.is_empty());
    println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    if has_errors { return Ok(2); }
    if options.require_complete && status == "integrity-valid-incomplete" { return Ok(3); }
    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("nixward-benchmark-verify: {error}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_corpus() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema":"org.luminousdynamics.nixward.deployment-transaction-benchmark-corpus",
            "version":1,"status":"proposed-not-executed",
            "baseline_registry":[
                {"id":"baseline-a","status":"available-baseline"},
                {"id":"baseline-b","status":"available-baseline"},
                {"id":"gated","status":"gated-not-yet-qualified"},
                {"id":"prototype","status":"prototype-only"}
            ],
            "trial_evidence_fields":["source_sha","scenario_corpus_sha256","raw_trial_record_digest_and_terminal_classification"],
            "scenarios":[{
                "id":"scenario-a","comparison_group":"test-group","operation_mode":"nixos-switch",
                "supported_baselines":["baseline-a","baseline-b","gated","prototype"],
                "required_observations":["profile","runtime"],"min_trials":30,"trial_class":"clean-baseline"
            }]
        })).unwrap()
    }

    fn make_record(corpus: &[u8], root: &Path, baseline: &str, index: u64, fingerprint: &str) -> Value {
        let path = format!("{baseline}-{index}.log");
        let bytes = b"raw independent evidence";
        let mut file = fs::File::create(root.join(&path)).unwrap();
        file.write_all(bytes).unwrap();
        let mut record = json!({
            "schema":RECORD_SCHEMA,"version":1,"trial_id":format!("{baseline}-{index}"),
            "scenario_id":"scenario-a","baseline_id":baseline,"comparison_group":"test-group",
            "operation_mode":"nixos-switch","trial_index":index,"trial_seed":"seed-1",
            "corpus_sha256":sha256_hex(corpus),
            "evidence":{
                "source_sha":"abcdef0123456789abcdef0123456789abcdef01",
                "scenario_corpus_sha256":sha256_hex(corpus),
                "raw_trial_record_digest_and_terminal_classification":"verifier-derived"
            },
            "match_fingerprint":{
                "nixpkgs_revision":"rev-1","flake_lock_sha256":"lock-1",
                "candidate_closure_digest":"closure-1","vm_image_digest":"vm-1",
                "kernel_version":"kernel-1","systemd_version":"systemd-1",
                "filesystem_mount_options":"ext4","storage_cache_policy":"default",
                "network_profile":"isolated","operation_mode":"nixos-switch",
                "concurrency":"1","cache_state":fingerprint
            },
            "observation_labels":["profile","runtime"],
            "phase_timestamps_ns":[{"phase":"admission","monotonic_ns":10},{"phase":"observation","monotonic_ns":20}],
            "safety_counters":{
                "false_terminal_success_count":0,
                "duplicate_mutation_for_unresolved_attempt_count":0,
                "unauthorized_or_replayed_admission_count":0,
                "foreign_transaction_attempt_worker_or_invocation_acceptance_count":0,
                "payload_release_before_durable_admission_and_worker_identity_count":0
            },
            "safe_hold":false,"scored_as_success":true,"terminal_evidence_complete":true,
            "terminal_disposition":"validated_terminal_success",
            "artifacts":[{"path":path,"sha256":sha256_hex(bytes),"byte_length":bytes.len()}]
        });
        record["record_sha256"] = Value::String(record_digest(&record).unwrap());
        record
    }

    #[test]
    fn verifies_integrity_without_claiming_operational_qualification() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let record = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        let report = audit(&corpus, &bytes, temp.path(), false).unwrap();
        assert_eq!(report["status"], "integrity-valid-incomplete");
        assert_eq!(report["qualification"], "artifact-integrity-only-not-operational-or-semantic-qualification");
    }

    #[test]
    fn detects_artifact_tampering_and_bad_record_digest() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let mut record = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        fs::write(temp.path().join("baseline-a-0.log"), b"tampered").unwrap();
        record["record_sha256"] = Value::String("0".repeat(64));
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");
    }

    #[test]
    fn refuses_gated_baseline_without_exploratory_opt_in() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let record = make_record(&corpus, temp.path(), "gated", 0, "warm");
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");
    }

    #[test]
    fn rejects_safe_hold_scored_as_success() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let mut record = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        record["safe_hold"] = Value::Bool(true);
        record["record_sha256"] = Value::String(record_digest(&record).unwrap());
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");
    }

    #[test]
    fn rejects_matched_trials_with_environment_drift() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let a = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        let b = make_record(&corpus, temp.path(), "baseline-b", 0, "cold");
        let bytes = serde_json::to_vec(&json!([a,b])).unwrap();
        let report = audit(&corpus, &bytes, temp.path(), false).unwrap();
        assert_eq!(report["status"], "invalid");
    }

    #[test]
    fn rejects_path_traversal_and_non_monotonic_phases() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let mut record = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        record["artifacts"][0]["path"] = Value::String("../outside.log".into());
        record["record_sha256"] = Value::String(record_digest(&record).unwrap());
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");

        let mut record = make_record(&corpus, temp.path(), "baseline-a", 1, "warm");
        record["phase_timestamps_ns"][1]["monotonic_ns"] = Value::from(9);
        record["record_sha256"] = Value::String(record_digest(&record).unwrap());
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");
    }

    #[test]
    fn rejects_missing_required_evidence_even_with_recomputed_record_digest() {
        let temp = tempfile::tempdir().unwrap();
        let corpus = test_corpus();
        let mut record = make_record(&corpus, temp.path(), "baseline-a", 0, "warm");
        record["evidence"].as_object_mut().unwrap().remove("source_sha");
        record["record_sha256"] = Value::String(record_digest(&record).unwrap());
        let bytes = serde_json::to_vec(&json!([record])).unwrap();
        assert_eq!(audit(&corpus, &bytes, temp.path(), false).unwrap()["status"], "invalid");
    }

    #[test]
    fn rejects_symlink_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside.log");
        fs::write(&outside, b"outside").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("escape.log")).unwrap();
        #[cfg(unix)]
        {
            let corpus = test_corpus();
            let mut record = make_record(&corpus, &root, "baseline-a", 0, "warm");
            record["artifacts"][0]["path"] = Value::String("escape.log".into());
            record["artifacts"][0]["sha256"] = Value::String(sha256_hex(b"outside"));
            record["artifacts"][0]["byte_length"] = Value::from(7);
            record["record_sha256"] = Value::String(record_digest(&record).unwrap());
            let records = serde_json::to_vec(&json!([record])).unwrap();
            assert_eq!(audit(&corpus, &records, &root, false).unwrap()["status"], "invalid");
        }
    }
}
