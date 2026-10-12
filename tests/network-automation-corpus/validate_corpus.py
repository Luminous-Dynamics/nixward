#!/usr/bin/env python3
"""Dependency-free, fail-closed validator for the network automation task corpus.

Checks the subset of JSON Schema 2020-12 keywords used by the checked-in
schema and additional corpus invariants. Unknown schema keywords are errors.
This validates shape/internal consistency only, not operational safety,
authorization, evidence truth, or corpus representativeness.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

SUPPORTED_KEYWORDS = {
    "$schema", "$id", "title", "description", "type", "additionalProperties",
    "required", "properties", "const", "enum", "format", "minLength",
    "pattern", "minItems", "uniqueItems", "items",
}
SUPPORTED_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
MODE_TIERS = {
    "read-only": {"A1", "A2"},
    "plan-only": {"A2"},
    "bounded-change": {"A3"},
    "approval-gated-change": {"A4"},
    "bounded-or-approval-gated-change": {"A3", "A4"},
    "approval-gated-progression": {"A4"},
    "recommendation": {"A2"},
    "human-led-exception": {"A5"},
    "human-led-physical-work": {"A5"},
}


class SchemaDefinitionError(ValueError):
    """The schema uses unsupported or malformed validation semantics."""


def json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int equality ambiguity."""
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == json.dumps(
            right, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError):
        return False


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaDefinitionError(f"unsupported schema type: {expected!r}")


def check_schema_supported(schema: Any, path: str = "$schema") -> None:
    """Fail closed if the schema contains a keyword this validator ignores."""
    if not isinstance(schema, dict):
        raise SchemaDefinitionError(f"{path}: schema must be an object")
    unknown = sorted(set(schema) - SUPPORTED_KEYWORDS)
    if unknown:
        raise SchemaDefinitionError(f"{path}: unsupported schema keyword(s): {', '.join(unknown)}")
    schema_type = schema.get("type")
    if schema_type is not None and (
        not isinstance(schema_type, str) or schema_type not in SUPPORTED_TYPES
    ):
        raise SchemaDefinitionError(f"{path}: unsupported type {schema_type!r}")
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise SchemaDefinitionError(f"{path}: required must be an array of strings")
    if len(required) != len(set(required)):
        raise SchemaDefinitionError(f"{path}: required entries must be unique")
    for keyword in ("minLength", "minItems"):
        if keyword in schema and (
            not isinstance(schema[keyword], int)
            or isinstance(schema[keyword], bool)
            or schema[keyword] < 0
        ):
            raise SchemaDefinitionError(f"{path}: {keyword} must be a non-negative integer")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise SchemaDefinitionError(f"{path}: uniqueItems must be boolean")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise SchemaDefinitionError(f"{path}: pattern must be a string")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise SchemaDefinitionError(f"{path}: invalid pattern: {exc}") from exc
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaDefinitionError(f"{path}: properties must be an object")
    for name, child in properties.items():
        check_schema_supported(child, f"{path}.properties[{name!r}]")
    if "items" in schema:
        check_schema_supported(schema["items"], f"{path}.items")
    additional = schema.get("additionalProperties", True)
    if isinstance(additional, dict):
        check_schema_supported(additional, f"{path}.additionalProperties")
    elif not isinstance(additional, bool):
        raise SchemaDefinitionError(f"{path}: additionalProperties must be boolean or schema")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise SchemaDefinitionError(f"{path}: enum must be a non-empty array")
    if "format" in schema:
        if not isinstance(schema["format"], str) or schema["format"] != "date":
            raise SchemaDefinitionError(f"{path}: unsupported format {schema['format']!r}")


def validate_instance(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Validate one instance and return deterministic path-labelled errors."""
    errors: list[str] = []
    if "type" in schema and not type_matches(value, schema["type"]):
        return [f"{path}: expected {schema['type']}, got {type(value).__name__}"]
    if "const" in schema and not json_equal(value, schema["const"]):
        errors.append(f"{path}: value does not match const")
    if "enum" in schema and not any(json_equal(value, allowed) for allowed in schema["enum"]):
        errors.append(f"{path}: value is not in enum")

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, child_value in value.items():
            child_path = f"{path}.{name}"
            if name in properties:
                errors.extend(validate_instance(child_value, properties[name], child_path))
            elif additional is False:
                errors.append(f"{child_path}: additional property is not allowed")
            elif isinstance(additional, dict):
                errors.extend(validate_instance(child_value, additional, child_path))

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        if schema.get("uniqueItems", False):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: items must be unique")
        if "items" in schema:
            for index, child_value in enumerate(value):
                errors.extend(validate_instance(child_value, schema["items"], f"{path}[{index}]"))

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: expected at least {schema['minLength']} characters")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: value does not match required pattern")
        if schema.get("format") == "date":
            try:
                parsed = dt.date.fromisoformat(value)
                if parsed.isoformat() != value:
                    raise ValueError("non-canonical date")
            except ValueError:
                errors.append(f"{path}: expected canonical ISO date YYYY-MM-DD")
    return errors


def validate_corpus(corpus: Any, schema: Any) -> list[str]:
    check_schema_supported(schema)
    errors = validate_instance(corpus, schema)
    if not isinstance(corpus, dict):
        return errors

    tasks = corpus.get("tasks")
    if isinstance(tasks, list):
        ids: list[str] = []
        for index, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            task_id = task.get("task_id")
            if isinstance(task_id, str):
                ids.append(task_id)
            mode, tier = task.get("mode"), task.get("max_tier_after_qualification")
            if isinstance(mode, str) and mode in MODE_TIERS:
                allowed_tiers = MODE_TIERS[mode]
                if not isinstance(tier, str) or tier not in allowed_tiers:
                    errors.append(
                        f"$.tasks[{index}]: tier {tier!r} incompatible with mode {mode!r}; "
                        f"expected one of {sorted(allowed_tiers)}"
                    )
        if len(ids) != len(set(ids)):
            errors.append("$.tasks: task_id values must be unique")

    shared = corpus.get("common_hard_stops")
    if isinstance(shared, list) and all(isinstance(item, str) for item in shared):
        if len(shared) != len(set(shared)):
            errors.append("$.common_hard_stops: entries must be unique")
    if isinstance(tasks, list) and isinstance(shared, list):
        uses_shared = any(
            isinstance(task, dict)
            and isinstance(task.get("stop_conditions"), list)
            and "common_hard_stops" in task["stop_conditions"]
            for task in tasks
        )
        semantics = corpus.get("evaluation_semantics")
        expansion = semantics.get("shared_stop_condition_reference") if isinstance(semantics, dict) else None
        if uses_shared and (not shared or not isinstance(expansion, str) or "common_hard_stops" not in expansion):
            errors.append("$: shared stop-condition reference lacks definition/expansion rule")

    boundaries = corpus.get("claim_boundaries")
    if isinstance(boundaries, list):
        text = " ".join(item.lower() for item in boundaries if isinstance(item, str))
        if "tier ceiling" not in text or "not an authorization" not in text:
            errors.append("$.claim_boundaries: must state tier ceiling is not an authorization grant")
    return errors



DECISION_STATES = {
    "AcceptReadOnly": {"CompleteForDeclaredScope"},
    "Incomplete": {"Incomplete"},
    "Reject": {"Invalid", "Expired", "Unsupported"},
    "BlockMutation": {"Blocked", "Incomplete", "Conflict", "Unsupported"},
    "RequireApproval": {"Blocked", "Expired"},
    "MarkIndeterminate": {"Indeterminate"},
    "EscalateHuman": {"Conflict", "Unsupported", "Incomplete"},
    "AbortRollout": {"Blocked", "Indeterminate", "Recovered"},
    "RecoverAndVerify": {"Recovered", "Indeterminate"},
    "ApplyAndVerify": {"AppliedAndVerified"},
}


def validate_fault_fixtures(fixtures: Any, schema: Any, task_corpus: Any) -> list[str]:
    """Validate fixture schema and invariants, including task cross-references."""
    check_schema_supported(schema)
    errors = validate_instance(fixtures, schema)
    if not isinstance(fixtures, dict):
        return errors
    if not isinstance(task_corpus, dict):
        errors.append("$: task corpus must be an object for cross-reference validation")
        return errors

    expected_corpus_id = task_corpus.get("artifact_id")
    if fixtures.get("task_corpus_artifact_id") != expected_corpus_id:
        errors.append("$.task_corpus_artifact_id: does not match the loaded task corpus")

    tasks = task_corpus.get("tasks")
    task_ids = {
        task.get("task_id")
        for task in tasks
        if isinstance(task, dict) and isinstance(task.get("task_id"), str)
    } if isinstance(tasks, list) else set()

    scenarios = fixtures.get("scenarios")
    if not isinstance(scenarios, list):
        return errors
    scenario_ids: list[str] = []
    covered_task_ids: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            continue
        scenario_id = scenario.get("scenario_id")
        if isinstance(scenario_id, str):
            scenario_ids.append(scenario_id)
        task_id = scenario.get("task_id")
        if isinstance(task_id, str):
            if task_id not in task_ids:
                errors.append(f"$.scenarios[{index}].task_id: unknown task ID {task_id!r}")
            else:
                covered_task_ids.add(task_id)

        if scenario.get("production_mutation") is not False:
            errors.append(f"$.scenarios[{index}].production_mutation: must be false")

        decision = scenario.get("expected_decision")
        state = scenario.get("expected_receipt_state")
        if isinstance(decision, str) and decision in DECISION_STATES:
            permitted_states = DECISION_STATES[decision]
            if not isinstance(state, str) or state not in permitted_states:
                errors.append(
                    f"$.scenarios[{index}]: receipt state {state!r} is inconsistent with "
                    f"decision {decision!r}; expected one of {sorted(permitted_states)}"
                )
        if decision == "ApplyAndVerify" and scenario.get("layer") != "virtual-lab":
            errors.append(
                f"$.scenarios[{index}]: ApplyAndVerify is allowed only in a virtual-lab fixture"
            )
        if state == "AppliedAndVerified" and scenario.get("layer") != "virtual-lab":
            errors.append(
                f"$.scenarios[{index}]: AppliedAndVerified is allowed only in a virtual-lab fixture"
            )

    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("$.scenarios: scenario_id values must be unique")

    uncovered = sorted(task_id for task_id in task_ids if task_id not in covered_task_ids)
    if uncovered:
        errors.append(f"$.scenarios: task IDs without any fixture: {', '.join(uncovered)}")

    invariants = fixtures.get("common_invariants")
    if isinstance(invariants, list):
        normalized = " ".join(item.lower() for item in invariants if isinstance(item, str))
        if "production network mutation is forbidden" not in normalized:
            errors.append("$.common_invariants: must prohibit production network mutation")
    return errors

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("docs/NETWORK_AUTOMATION_TASK_CORPUS_V1.json"))
    parser.add_argument("--schema", type=Path, default=Path("docs/NETWORK_AUTOMATION_TASK_CORPUS_V1.schema.json"))
    parser.add_argument("--fixtures", type=Path, default=Path("docs/NETWORK_AUTOMATION_FAULT_FIXTURES_V1.json"))
    parser.add_argument("--fixture-schema", type=Path, default=Path("docs/NETWORK_AUTOMATION_FAULT_FIXTURES_V1.schema.json"))
    args = parser.parse_args(argv)
    try:
        corpus = load_json(args.corpus)
        schema = load_json(args.schema)
        fixtures = load_json(args.fixtures)
        fixture_schema = load_json(args.fixture_schema)
        errors = validate_corpus(corpus, schema)
        fixture_errors = validate_fault_fixtures(fixtures, fixture_schema, corpus)
        errors.extend(f"fault-fixtures: {error}" for error in fixture_errors)
    except (OSError, json.JSONDecodeError, SchemaDefinitionError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("FAIL: network automation corpus/fixture validation")
        for error in errors:
            print(f" - {error}")
        return 1
    tasks = corpus["tasks"]
    unique_count = len({task["task_id"] for task in tasks})
    scenarios = fixtures["scenarios"]
    unique_scenarios = len({scenario["scenario_id"] for scenario in scenarios})
    print(
        "PASS: task corpus (schema_version={corpus['schema_version']}, tasks={len(tasks)}, "
        "unique_task_ids={unique_count})"
    )
    print(
        f"PASS: fault fixtures (scenarios={len(scenarios)}, "
        f"unique_scenario_ids={unique_scenarios}, task_references=validated)"
    )
    print("LIMIT: shape/consistency only; not operational safety, execution success, or authorization evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
