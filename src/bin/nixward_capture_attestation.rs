// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! CLI for verifier-issued capture challenges and DSSE/in-toto evidence checks.
//!
//! This CLI does not perform deployment. It requires the upstream raw-trial
//! verifier's report and hashes the actual evidence files before a challenge
//! can be issued or a signature can be accepted.

use nixward::capture_attestation::{
    new_capture_challenge, sha256_hex, verify_capture_attestation,
    verify_capture_subject_files, CaptureChallenge, CaptureChallengeLedger,
    CapturePredicate, CaptureSubject, CaptureSubjectFile, CaptureTrustPolicy,
    CaptureVerificationReport, StrictDigestMap, validate_capture_trust_policy,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidence {
    schema: String,
    version: u32,
    source_commit_sha: String,
    flake_lock_sha256: String,
    corpus_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationReport {
    schema: String,
    version: u32,
    corpus_sha256: String,
    manifest_sha256: String,
    source_commit_sha: String,
    flake_lock_sha256: String,
    unsafe_trial_count: usize,
    outcome: String,
    trials: Vec<VerifiedTrial>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedTrial {
    trial_id: String,
    scenario_id: String,
    events_sha256: String,
    valid: bool,
    sqlite_snapshot_audit: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReceipt {
    relative_path: String,
    sha256: String,
    artifact_kind: String,
}

#[derive(Debug)]
struct TrialContext {
    trial_id: String,
    scenario_id: String,
    started_monotonic_ns: u64,
    finished_monotonic_ns: u64,
    events_sha256: String,
    source_commit_sha: String,
    flake_lock_sha256: String,
    corpus_sha256: String,
    boot_id: String,
    manifest_sha256: String,
    capture_tool_sha256: String,
    files: Vec<CaptureSubjectFile>,
    extra_subjects: Vec<CaptureSubject>,
}

fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock: {error}"))?;
    u64::try_from(duration.as_millis()).map_err(|_| "system clock overflow".into())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| format!("stat {}: {error}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max_bytes {
        return Err(format!("{} is not a bounded regular non-symlink file", path.display()));
    }
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    let mut limited = file.by_ref().take(max_bytes + 1);
    limited.read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{} grew beyond its size limit", path.display()));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let meta = fs::symlink_metadata(parent)
            .map_err(|error| format!("output directory {}: {error}", parent.display()))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("output parent must be a real directory".into());
        }
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|error| format!("create output {} without overwrite: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| format!("write output: {error}"))?;
    file.sync_all().map_err(|error| format!("sync output: {error}"))?;
    Ok(())
}

fn parse_options() -> Result<(String, BTreeMap<String, String>), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("expected issue-challenge or verify")?;
    if command != "issue-challenge" && command != "verify" {
        return Err("expected issue-challenge or verify".into());
    }
    let mut options = BTreeMap::new();
    while let Some(name) = args.next() {
        if !name.starts_with("--") {
            return Err(format!("unexpected argument {name}"));
        }
        let value = args.next().ok_or_else(|| format!("missing value for {name}"))?;
        let key = name.trim_start_matches("--").to_string();
        if options.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate option --{key}"));
        }
    }
    Ok((command, options))
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    options.get(name).map(String::as_str).ok_or_else(|| format!("--{name} is required"))
}

fn relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if value.trim().is_empty() || path.is_absolute()
        || path.components().any(|part| matches!(
            part, Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ))
    {
        return Err(format!("path must be relative and confined: {value}"));
    }
    Ok(path.to_path_buf())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let rel = relative_path(relative)?;
    let root_meta = fs::symlink_metadata(root)
        .map_err(|error| format!("evidence root: {error}"))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err("evidence root must be a real directory".into());
    }
    let canonical_root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut candidate = canonical_root.clone();
    for component in rel.components() {
        if let Component::Normal(part) = component {
            candidate.push(part);
            let meta = fs::symlink_metadata(&candidate)
                .map_err(|error| format!("evidence path {}: {error}", candidate.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!("symlink is forbidden in evidence path {}", candidate.display()));
            }
        }
    }
    let canonical = fs::canonicalize(&candidate).map_err(|e| e.to_string())?;
    if !canonical.starts_with(&canonical_root) {
        return Err("evidence path escaped root".into());
    }
    Ok(canonical)
}

fn json_string(value: &Value, key: &str) -> Result<String, String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
        .ok_or_else(|| format!("JSON field {key} is missing/not a string"))
}

fn json_u64(value: &Value, key: &str) -> Result<u64, String> {
    value.get(key).and_then(Value::as_u64)
        .ok_or_else(|| format!("JSON field {key} is missing/not a u64"))
}

fn load_trial_context(
    evidence_root: &Path,
    options: &BTreeMap<String, String>,
) -> Result<TrialContext, String> {
    let corpus_rel = required(options, "corpus")?;
    let manifest_rel = required(options, "manifest")?;
    let flake_lock_rel = required(options, "flake-lock")?;
    let verifier_report_rel = required(options, "verification-report")?;
    let artifact_prefix = options.get("artifact-prefix").map(String::as_str).unwrap_or("artifacts");
    relative_path(artifact_prefix)?;

    let corpus_path = safe_join(evidence_root, corpus_rel)?;
    let manifest_path = safe_join(evidence_root, manifest_rel)?;
    let lock_path = safe_join(evidence_root, flake_lock_rel)?;
    let verifier_report_path = safe_join(evidence_root, verifier_report_rel)?;
    let corpus_bytes = read_bounded(&corpus_path, MAX_JSON_BYTES)?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_JSON_BYTES)?;
    let lock_bytes = read_bounded(&lock_path, 256 * 1024 * 1024)?;
    let verifier_bytes = read_bounded(&verifier_report_path, MAX_JSON_BYTES)?;

    let corpus: Value = serde_json::from_slice(&corpus_bytes).map_err(|e| format!("corpus JSON: {e}"))?;
    if json_string(&corpus, "schema")? != "org.luminousdynamics.nixward.payload-release-assurance-benchmark"
        || json_u64(&corpus, "version")? != 1
    {
        return Err("unsupported payload-release corpus".into());
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest JSON: {e}"))?;
    if json_string(&manifest, "schema")? != "org.luminousdynamics.nixward.payload-release-trial-manifest"
        || json_u64(&manifest, "version")? != 1
    {
        return Err("unsupported payload-release trial manifest".into());
    }
    let corpus_sha = sha256_hex(&corpus_bytes);
    let manifest_sha = sha256_hex(&manifest_bytes);
    let lock_sha = sha256_hex(&lock_bytes);
    let source_sha = json_string(&manifest, "source_commit_sha")?;
    let manifest_corpus_sha = json_string(&manifest, "corpus_sha256")?;
    let manifest_lock_sha = json_string(&manifest, "flake_lock_sha256")?;
    if !valid_hex(&source_sha, 40) || manifest_corpus_sha != corpus_sha || manifest_lock_sha != lock_sha {
        return Err("manifest does not bind exact corpus/source/flake.lock bytes".into());
    }

    let trial_id = required(options, "trial-id")?;
    let trials = manifest.get("trials").and_then(Value::as_array)
        .ok_or("manifest trials array is missing")?;
    let matching = trials.iter().filter(|trial| {
        trial.get("trial_id").and_then(Value::as_str) == Some(trial_id)
    }).collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!("expected exactly one manifest trial {trial_id}, found {}", matching.len()));
    }
    let trial = matching[0];
    let scenario_id = json_string(trial, "scenario_id")?;
    let scenario_ids = corpus.get("scenarios").and_then(Value::as_array)
        .ok_or("corpus scenarios array missing")?.iter()
        .filter_map(|scenario| scenario.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if !scenario_ids.contains(scenario_id.as_str()) {
        return Err("trial scenario is not in the exact corpus".into());
    }
    let started = json_u64(trial, "started_monotonic_ns")?;
    let finished = json_u64(trial, "finished_monotonic_ns")?;
    if started >= finished {
        return Err("trial monotonic interval is invalid".into());
    }
    let events_sha = json_string(trial, "events_sha256")?;
    if !valid_hex(&events_sha, 64) {
        return Err("trial event digest is invalid".into());
    }
    let environment = manifest.get("environment").ok_or("manifest environment missing")?;
    let boot_id = json_string(environment, "boot_id")?;
    let artifacts = trial.get("artifacts").and_then(Value::as_array)
        .ok_or("trial artifacts array missing")?;
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err("trial artifact count is invalid".into());
    }

    let mut kind_counts = BTreeMap::<String, usize>::new();
    let mut files = Vec::new();
    for artifact in artifacts {
        let receipt: ArtifactReceipt = serde_json::from_value(artifact.clone())
            .map_err(|e| format!("artifact receipt: {e}"))?;
        *kind_counts.entry(receipt.artifact_kind.clone()).or_default() += 1;
        let prefixed = PathBuf::from(artifact_prefix).join(&receipt.relative_path);
        let relative = prefixed.to_str().ok_or("artifact path is not UTF-8")?;
        files.push(CaptureSubjectFile {
            name: format!("artifact:{}:{}", receipt.artifact_kind, receipt.relative_path),
            relative_path: relative.to_string(),
            expected_sha256: receipt.sha256,
        });
    }
    for mandatory in ["source_manifest", "raw_sqlite", "supervisor_log", "capture_tool"] {
        if kind_counts.get(mandatory).copied() != Some(1) {
            return Err(format!("trial must contain exactly one {mandatory} artifact"));
        }
    }
    let source_manifest_receipt = artifacts.iter().find(|item| {
        item.get("artifact_kind").and_then(Value::as_str) == Some("source_manifest")
    }).ok_or("source_manifest receipt missing")?;
    let source_manifest_rel = PathBuf::from(artifact_prefix)
        .join(json_string(source_manifest_receipt, "relative_path")?);
    let source_manifest_path = safe_join(evidence_root, source_manifest_rel.to_str().ok_or("source manifest path is not UTF-8")?)?;
    let source_manifest_bytes = read_bounded(&source_manifest_path, MAX_JSON_BYTES)?;
    let source_manifest: SourceEvidence = serde_json::from_slice(&source_manifest_bytes)
        .map_err(|e| format!("source manifest: {e}"))?;
    if source_manifest.schema != "org.luminousdynamics.nixward.source-evidence"
        || source_manifest.version != 1
        || source_manifest.source_commit_sha != source_sha
        || source_manifest.flake_lock_sha256 != lock_sha
        || source_manifest.corpus_sha256 != corpus_sha
    {
        return Err("source_manifest does not bind exact corpus, source commit and flake.lock".into());
    }
    let capture_tool_receipt = artifacts.iter().find(|item| {
        item.get("artifact_kind").and_then(Value::as_str) == Some("capture_tool")
    }).ok_or("capture_tool receipt missing")?;
    let capture_tool_sha = json_string(capture_tool_receipt, "sha256")?;

    let verification: VerificationReport = serde_json::from_slice(&verifier_bytes)
        .map_err(|e| format!("raw-trial verification report: {e}"))?;
    if verification.schema != "org.luminousdynamics.nixward.payload-release-trial-verification"
        || verification.version != 1
        || verification.manifest_sha256 != manifest_sha
        || verification.corpus_sha256 != corpus_sha
        || verification.source_commit_sha != source_sha
        || verification.flake_lock_sha256 != lock_sha
        || verification.unsafe_trial_count != 0
        || !["valid", "incomplete"].contains(&verification.outcome.as_str())
    {
        return Err("raw-trial verification report does not bind exact inputs or contains unsafe trials".into());
    }
    let verified_trials = verification.trials.iter().filter(|item| item.trial_id == trial_id).collect::<Vec<_>>();
    if verified_trials.len() != 1
        || !verified_trials[0].valid
        || verified_trials[0].scenario_id != scenario_id
        || verified_trials[0].events_sha256 != events_sha
        || verified_trials[0].sqlite_snapshot_audit == "not_checked"
    {
        return Err("raw-trial verifier did not validate this exact trial".into());
    }

    files.push(CaptureSubjectFile {
        name: "benchmark-corpus".into(),
        relative_path: corpus_rel.into(),
        expected_sha256: corpus_sha.clone(),
    });
    files.push(CaptureSubjectFile {
        name: "trial-manifest".into(),
        relative_path: manifest_rel.into(),
        expected_sha256: manifest_sha.clone(),
    });
    files.push(CaptureSubjectFile {
        name: "flake-lock".into(),
        relative_path: flake_lock_rel.into(),
        expected_sha256: lock_sha.clone(),
    });
    files.push(CaptureSubjectFile {
        name: "raw-trial-verification-report".into(),
        relative_path: verifier_report_rel.into(),
        expected_sha256: sha256_hex(&verifier_bytes),
    });

    let extra_subjects = vec![CaptureSubject {
        name: "verified-trial-event-stream".into(),
        digest: StrictDigestMap(BTreeMap::from([("sha256".into(), events_sha.clone())])),
    }];
    let expected_artifacts = files.iter().map(|file| file.name.clone()).collect::<BTreeSet<_>>();
    if expected_artifacts.len() != files.len() {
        return Err("duplicate capture subject names".into());
    }

    Ok(TrialContext {
        trial_id: trial_id.into(),
        scenario_id,
        started_monotonic_ns: started,
        finished_monotonic_ns: finished,
        events_sha256: events_sha,
        source_commit_sha: source_sha,
        flake_lock_sha256: lock_sha,
        corpus_sha256: corpus_sha,
        boot_id,
        manifest_sha256: manifest_sha,
        capture_tool_sha256: capture_tool_sha,
        files,
        extra_subjects,
    })
}

fn load_trust_policy(path: &Path) -> Result<(Vec<u8>, CaptureTrustPolicy), String> {
    let bytes = read_bounded(path, MAX_POLICY_BYTES)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| e.to_string())?;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err("capture trust policy must not be group/other writable".into());
        }
    }
    let policy: CaptureTrustPolicy = serde_json::from_slice(&bytes)
        .map_err(|e| format!("capture trust policy JSON: {e}"))?;
    validate_capture_trust_policy(&policy).map_err(|e| e.to_string())?;
    Ok((bytes, policy))
}

fn ensure_policy_can_sign(
    policy: &CaptureTrustPolicy,
    machine_binding_digest: &str,
    scenario_id: &str,
    at_ms: u64,
) -> Result<(), String> {
    let eligible = policy.signers.iter().filter(|signer| {
        !signer.revoked
            && at_ms >= signer.not_before_ms
            && at_ms <= signer.not_after_ms
            && signer.allowed_machine_bindings.iter().any(|value| value == machine_binding_digest)
            && signer.allowed_scenarios.iter().any(|value| value == scenario_id)
    }).count();
    if eligible < policy.threshold {
        return Err("capture trust policy has insufficient active signers for this machine/scenario".into());
    }
    Ok(())
}

fn build_context(options: &BTreeMap<String, String>) -> Result<(TrialContext, CaptureChallengeLedger, PathBuf, String, Vec<u8>, CaptureTrustPolicy), String> {
    let root = PathBuf::from(required(options, "evidence-root")?);
    if !root.is_absolute() {
        return Err("--evidence-root must be absolute".into());
    }
    let context = load_trial_context(&root, options)?;
    let machine = required(options, "machine-binding-digest")?;
    if !valid_hex(machine, 64) {
        return Err("--machine-binding-digest must be a 64-character lowercase digest".into());
    }
    let policy_path = PathBuf::from(required(options, "capture-policy")?);
    if !policy_path.is_absolute() {
        return Err("--capture-policy must be an absolute verifier-controlled path".into());
    }
    let (policy_bytes, policy) = load_trust_policy(&policy_path)?;
    let now = now_ms()?;
    ensure_policy_can_sign(&policy, machine, &context.scenario_id, now)?;
    let ledger_path = PathBuf::from(required(options, "ledger")?);
    if !ledger_path.is_absolute() {
        return Err("--ledger must be absolute".into());
    }
    let ledger = CaptureChallengeLedger::new(ledger_path).map_err(|e| e.to_string())?;
    Ok((context, ledger, root, machine.to_string(), policy_bytes, policy))
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("expected issue-challenge or verify")?;
    if command != "issue-challenge" && command != "verify" {
        return Err("expected issue-challenge or verify".into());
    }
    let mut options = BTreeMap::new();
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") { return Err(format!("unexpected argument {arg}")); }
        let value = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
        let name = arg.trim_start_matches("--").to_string();
        if options.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate option --{name}"));
        }
    }
    let (context, ledger, root, machine, policy_bytes, policy) = build_context(&options)?;
    let verified_evidence = verify_capture_subject_files(
        &root, &context.files, &context.extra_subjects
    ).map_err(|e| e.to_string())?;
    let policy_sha = sha256_hex(&policy_bytes);
    match command.as_str() {
        "issue-challenge" => {
            let now = now_ms()?;
            let ttl_ms = options.get("ttl-ms").map(|v| v.parse::<u64>())
                .transpose().map_err(|e| format!("invalid --ttl-ms: {e}"))?
                .unwrap_or(300_000);
            ensure_policy_can_sign(&policy, &machine, &context.scenario_id, now)?;
            let challenge = new_capture_challenge(
                context.corpus_sha256.clone(),
                context.source_commit_sha.clone(),
                context.flake_lock_sha256.clone(),
                policy_sha,
                context.trial_id.clone(),
                context.scenario_id.clone(),
                machine,
                context.capture_tool_sha256.clone(),
                verified_evidence.evidence_set_sha256().to_string(),
                now,
                ttl_ms,
            ).map_err(|e| e.to_string())?;
            ledger.issue(&challenge).map_err(|e| e.to_string())?;
            let output = serde_json::to_vec_pretty(&challenge).map_err(|e| e.to_string())?;
            write_new(Path::new(required(&options, "output")?), &output)?;
            Ok(())
        }
        "verify" => {
            let challenge_path = PathBuf::from(required(&options, "challenge")?);
            let envelope_path = PathBuf::from(required(&options, "envelope")?);
            let challenge_bytes = read_bounded(&challenge_path, 64 * 1024)?;
            let envelope_bytes = read_bounded(&envelope_path, MAX_ENVELOPE_BYTES)?;
            let challenge: CaptureChallenge = serde_json::from_slice(&challenge_bytes)
                .map_err(|e| format!("capture challenge: {e}"))?;
            let expected = CapturePredicate {
                schema_version: 1,
                kind: "nixward-payload-release-capture-v1".into(),
                trial_id: context.trial_id.clone(),
                scenario_id: context.scenario_id.clone(),
                source_commit_sha: context.source_commit_sha.clone(),
                flake_lock_sha256: context.flake_lock_sha256.clone(),
                corpus_sha256: context.corpus_sha256.clone(),
                boot_id: context.boot_id.clone(),
                machine_binding_digest: machine,
                capture_tool_sha256: context.capture_tool_sha256.clone(),
                started_monotonic_ns: context.started_monotonic_ns,
                finished_monotonic_ns: context.finished_monotonic_ns,
                captured_at_ms: 0,
                challenge_id: challenge.challenge_id.clone(),
                challenge_nonce: challenge.nonce.clone(),
                evidence_set_sha256: verified_evidence.evidence_set_sha256().to_string(),
                assurance_mode: "software_only".into(),
            };
            let report = verify_capture_attestation(
                &envelope_bytes,
                &policy_bytes,
                &challenge,
                &verified_evidence,
                &expected,
                &ledger,
                now_ms()?,
            ).map_err(|e| e.to_string())?;
            let output = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
            write_new(Path::new(required(&options, "output")?), &output)?;
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nixward-capture-attestation: {error}");
        std::process::exit(2);
    }
}
