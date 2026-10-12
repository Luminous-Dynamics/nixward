"""Deterministic positive and mutation tests for the task corpus validator."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_corpus import SchemaDefinitionError, check_schema_supported, validate_corpus  # noqa: E402


CORPUS_PATH = ROOT / "docs" / "NETWORK_AUTOMATION_TASK_CORPUS_V1.json"
SCHEMA_PATH = ROOT / "docs" / "NETWORK_AUTOMATION_TASK_CORPUS_V1.schema.json"


def read_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class CorpusValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_corpus = read_json(CORPUS_PATH)
        cls.schema = read_json(SCHEMA_PATH)

    def fresh(self):
        return copy.deepcopy(self.original_corpus)

    def errors(self, corpus):
        return validate_corpus(corpus, self.schema)

    def test_repository_corpus_passes(self):
        self.assertEqual([], self.errors(self.fresh()))

    def test_duplicate_task_id_is_rejected(self):
        corpus = self.fresh()
        corpus["tasks"][1]["task_id"] = corpus["tasks"][0]["task_id"]
        self.assertTrue(any("task_id values must be unique" in error for error in self.errors(corpus)))

    def test_missing_required_postconditions_are_rejected(self):
        corpus = self.fresh()
        del corpus["tasks"][0]["postconditions"]
        self.assertTrue(any("missing required property 'postconditions'" in error for error in self.errors(corpus)))

    def test_extra_task_field_is_rejected(self):
        corpus = self.fresh()
        corpus["tasks"][0]["silent_authority"] = True
        self.assertTrue(any("additional property is not allowed" in error for error in self.errors(corpus)))

    def test_unknown_tier_is_rejected(self):
        corpus = self.fresh()
        corpus["tasks"][0]["max_tier_after_qualification"] = "A6"
        self.assertTrue(any("value is not in enum" in error for error in self.errors(corpus)))

    def test_incompatible_mode_and_tier_are_rejected(self):
        corpus = self.fresh()
        route_task = next(task for task in corpus["tasks"] if task["task_id"] == "ROUTE-001")
        route_task["max_tier_after_qualification"] = "A3"
        self.assertTrue(any("tier" in error and "incompatible with mode" in error for error in self.errors(corpus)))

    def test_duplicate_shared_hard_stop_is_rejected(self):
        corpus = self.fresh()
        corpus["common_hard_stops"].append(corpus["common_hard_stops"][0])
        self.assertTrue(any("common_hard_stops: entries must be unique" in error for error in self.errors(corpus)))

    def test_schema_version_boolean_does_not_pass_integer_const(self):
        corpus = self.fresh()
        corpus["schema_version"] = True
        self.assertTrue(any("does not match const" in error for error in self.errors(corpus)))

    def test_noncanonical_date_is_rejected(self):
        corpus = self.fresh()
        corpus["created_on"] = "2026-1-2"
        self.assertTrue(any("canonical ISO date" in error for error in self.errors(corpus)))

    def test_missing_shared_stop_expansion_rule_is_rejected(self):
        corpus = self.fresh()
        corpus["evaluation_semantics"]["shared_stop_condition_reference"] = "See another section."
        self.assertTrue(any("shared stop-condition reference" in error for error in self.errors(corpus)))

    def test_missing_authority_boundary_is_rejected(self):
        corpus = self.fresh()
        corpus["claim_boundaries"] = ["Task definitions grant execution permission."]
        self.assertTrue(any("tier ceiling is not an authorization grant" in error for error in self.errors(corpus)))

    def test_unknown_schema_keyword_fails_closed(self):
        schema = copy.deepcopy(self.schema)
        schema["unevaluatedProperties"] = False
        with self.assertRaises(SchemaDefinitionError):
            check_schema_supported(schema)

    def test_unsupported_schema_format_fails_closed(self):
        schema = copy.deepcopy(self.schema)
        schema["properties"]["created_on"]["format"] = "date-time"
        with self.assertRaises(SchemaDefinitionError):
            check_schema_supported(schema)

    def test_invalid_schema_regex_fails_closed(self):
        schema = copy.deepcopy(self.schema)
        schema["properties"]["tasks"]["items"]["properties"]["task_id"]["pattern"] = "["
        with self.assertRaises(SchemaDefinitionError):
            check_schema_supported(schema)

    def test_non_string_mode_is_rejected_without_crashing(self):
        corpus = self.fresh()
        corpus["tasks"][0]["mode"] = ["read-only"]
        errors = self.errors(corpus)
        self.assertTrue(any("expected string" in error for error in errors))

    def test_non_string_shared_stop_is_rejected_without_crashing(self):
        corpus = self.fresh()
        corpus["common_hard_stops"][0] = {"not": "a string"}
        errors = self.errors(corpus)
        self.assertTrue(any("expected string" in error for error in errors))

    def test_design_status_is_not_an_executable_authorization(self):
        corpus = self.fresh()
        self.assertEqual("qualification-design-only", corpus["status"])
        normalized = " ".join(corpus["claim_boundaries"]).lower()
        self.assertIn("not an authorization grant", normalized)
        self.assertIn("not representative", normalized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
