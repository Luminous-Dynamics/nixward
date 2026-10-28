use serde::Deserialize;
use std::collections::HashSet;

const CORPUS: &str =
    include_str!("../docs/fixtures/transaction-qualification-v0.1.json");

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: String,
    version: u32,
    status: String,
    required_run_binding: Vec<String>,
    hard_gates: HardGates,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct HardGates {
    unauthorized_mutations: u64,
    false_successes: u64,
    canonical_negative_controls_rejected: String,
    canonical_case_evidence_completeness: String,
    missing_or_unexecuted_essential_checks_are_passes: bool,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    gate: String,
    category: String,
    scenario: String,
    expected_disposition: String,
    assertions: Vec<String>,
}

fn parse_corpus() -> Manifest {
    serde_json::from_str(CORPUS)
        .expect("transaction qualification corpus must remain valid JSON matching its v0.1 fields")
}

#[test]
fn transaction_qualification_corpus_is_explicitly_a_specification() {
    let manifest = parse_corpus();

    assert_eq!(
        manifest.schema,
        "luminous-nixward-transaction-qualification-v0.1"
    );
    assert_eq!(manifest.version, 1);
    assert_eq!(
        manifest.status, "specification_only",
        "a case manifest must not be mistaken for test execution evidence"
    );
}

#[test]
fn transaction_qualification_cases_are_unique_and_actionable() {
    let manifest = parse_corpus();
    assert!(
        manifest.cases.len() >= 15,
        "v0.1 must preserve the canonical multi-boundary corpus"
    );

    let mut ids = HashSet::new();
    for case in &manifest.cases {
        assert!(!case.id.trim().is_empty(), "case id must not be empty");
        assert!(ids.insert(case.id.as_str()), "duplicate case id: {}", case.id);
        assert!(
            ["A", "B", "C", "D", "E"].contains(&case.gate.as_str()),
            "{} has an unknown qualification gate",
            case.id
        );
        assert!(!case.category.trim().is_empty(), "{} lacks category", case.id);
        assert!(!case.scenario.trim().is_empty(), "{} lacks scenario", case.id);
        assert!(
            !case.expected_disposition.trim().is_empty(),
            "{} lacks expected disposition",
            case.id
        );
        assert!(
            !case.assertions.is_empty(),
            "{} needs observable assertions",
            case.id
        );

        let mut assertion_ids = HashSet::new();
        for assertion in &case.assertions {
            assert!(
                !assertion.trim().is_empty(),
                "{} contains an empty assertion",
                case.id
            );
            assert!(
                assertion_ids.insert(assertion.as_str()),
                "{} repeats assertion {assertion}",
                case.id
            );
        }
    }
}

#[test]
fn transaction_qualification_corpus_keeps_noncompensatory_safety_gates() {
    let manifest = parse_corpus();
    let gates = manifest.hard_gates;

    assert_eq!(gates.unauthorized_mutations, 0);
    assert_eq!(gates.false_successes, 0);
    assert_eq!(gates.canonical_negative_controls_rejected, "100%");
    assert_eq!(gates.canonical_case_evidence_completeness, "100%");
    assert!(
        !gates.missing_or_unexecuted_essential_checks_are_passes,
        "queued, skipped, and unexecuted checks must not count as passes"
    );
}

#[test]
fn transaction_qualification_run_requires_reproducible_identity() {
    let manifest = parse_corpus();
    let required: HashSet<&str> = manifest
        .required_run_binding
        .iter()
        .map(String::as_str)
        .collect();

    for field in [
        "source_commit_sha",
        "toolchain_digest",
        "flake_lock_digest",
        "vm_image_digest",
        "policy_version",
        "corpus_digest",
        "run_id",
    ] {
        assert!(
            required.contains(field),
            "qualification reports must bind {field}"
        );
    }
}

#[test]
fn transaction_qualification_corpus_covers_the_core_fault_boundaries() {
    let manifest = parse_corpus();
    let categories: HashSet<&str> = manifest
        .cases
        .iter()
        .map(|case| case.category.as_str())
        .collect();

    for category in [
        "authorization",
        "untrusted_input",
        "concurrency",
        "realization",
        "journal_prepublication",
        "journal_postpublication",
        "process_lifecycle",
        "execution",
        "postcondition",
        "boot_health",
        "recovery",
        "confidentiality",
        "fleet",
    ] {
        assert!(
            categories.contains(category),
            "canonical qualification corpus is missing {category}"
        );
    }
}
