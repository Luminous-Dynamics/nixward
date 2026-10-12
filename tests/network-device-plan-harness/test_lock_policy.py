"""Regression tests for the dependency-free Cargo.lock security policy."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_lock_policy import KNOWN_MALICIOUS_CRATE_NAMES, KNOWN_MALICIOUS_RELEASES

POLICY = Path(__file__).with_name("check_lock_policy.py")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "0" * 64


def make_lock(*packages: tuple[str, str]) -> str:
    chunks = ["version = 4\n"]
    for name, version in packages:
        chunks.append(
            "[[package]]\n"
            f'name = "{name}"\n'
            f'version = "{version}"\n'
            f'source = "{REGISTRY}"\n'
            f'checksum = "{CHECKSUM}"\n'
        )
    # The harness itself is the only allowed source-less lockfile package.
    chunks.append(
        "[[package]]\n"
        'name = "nixward-network-device-plan-m0-harness"\n'
        'version = "0.1.0"\n'
        "dependencies = []\n"
    )
    return "\n".join(chunks)


class LockPolicyTests(unittest.TestCase):
    def run_policy(self, lock_text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "Cargo.lock"
            lock_path.write_text(lock_text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(POLICY), str(lock_path)],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_clean_arrayref_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("arrayref", "0.3.9")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_git_dependency_source_is_rejected(self) -> None:
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            f'source = "{REGISTRY}"',
            'source = "git+https://example.invalid/safe-crate#' + "a" * 40 + '"',
            1,
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unapproved dependency source", result.stderr)

    def test_alternate_registry_is_rejected(self) -> None:
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            REGISTRY, "registry+https://packages.example.invalid/index", 1
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unapproved dependency source", result.stderr)

    def test_missing_registry_checksum_is_rejected(self) -> None:
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            f'checksum = "{CHECKSUM}"\n', "", 1
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or invalid registry checksum", result.stderr)

    def test_invalid_registry_checksum_is_rejected(self) -> None:
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            CHECKSUM, "not-a-checksum", 1
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or invalid registry checksum", result.stderr)

    def test_unresolved_dependency_edge_is_rejected(self) -> None:
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            "dependencies = []", 'dependencies = ["missing-crate"]', 1
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unresolved or ambiguous dependency edge", result.stderr)

    def test_dependency_source_must_match_locked_package_source(self) -> None:
        dependency = 'safe-crate 1.0.0 (registry+https://packages.example.invalid/index)'
        lock_text = make_lock(("safe-crate", "1.0.0")).replace(
            "dependencies = []", f'dependencies = ["{dependency}"]', 1
        )
        result = self.run_policy(lock_text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unresolved or ambiguous dependency edge", result.stderr)

    def test_duplicate_package_identity_is_rejected(self) -> None:
        result = self.run_policy(
            make_lock(("safe-crate", "1.0.0"), ("safe-crate", "1.0.0"))
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate Cargo.lock package identity", result.stderr)

    def test_compromised_arrayref_release_is_rejected(self) -> None:
        result = self.run_policy(make_lock(("arrayref", "0.3.10")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_arrayref_versions_after_compromised_release_remain_blocked(self) -> None:
        result = self.run_policy(make_lock(("arrayref", "0.3.11")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("arrayref 0.3.11", result.stderr)

    def test_known_malicious_crate_name_is_rejected(self) -> None:
        result = self.run_policy(make_lock(("proc-macro1", "1.0.107")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("proc-macro1", result.stderr)

    def test_every_known_malicious_crate_name_is_rejected(self) -> None:
        for name in sorted(KNOWN_MALICIOUS_CRATE_NAMES):
            with self.subTest(name=name):
                result = self.run_policy(make_lock((name, "0.0.0")))
                self.assertEqual(result.returncode, 1, f"{name}: {result.stdout} {result.stderr}")
                self.assertIn(name, result.stderr)

    def test_every_known_malicious_release_is_rejected(self) -> None:
        for name, version in sorted(KNOWN_MALICIOUS_RELEASES):
            with self.subTest(name=name, version=version):
                result = self.run_policy(make_lock((name, version)))
                self.assertEqual(result.returncode, 1, f"{name}@{version}: {result.stdout} {result.stderr}")
                self.assertIn(f"{name}@{version}", result.stderr)

    def test_unrecognized_arrayref_version_fails_closed(self) -> None:
        result = self.run_policy(make_lock(("arrayref", "main")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("review required", result.stderr)

    def test_known_compromised_append_only_vec_release_is_rejected(self) -> None:
        result = self.run_policy(make_lock(("append-only-vec", "0.1.9")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("append-only-vec@0.1.9", result.stderr)

    def test_known_compromised_internment_release_is_rejected(self) -> None:
        result = self.run_policy(make_lock(("internment", "0.8.7")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("internment@0.8.7", result.stderr)

    def test_older_append_only_vec_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("append-only-vec", "0.1.8")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newer_append_only_vec_release_requires_review(self) -> None:
        result = self.run_policy(make_lock(("append-only-vec", "0.1.10")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_older_internment_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("internment", "0.8.6")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newer_internment_release_requires_review(self) -> None:
        result = self.run_policy(make_lock(("internment", "0.8.8")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_onering_after_compromised_release_requires_review(self) -> None:
        result = self.run_policy(make_lock(("onering", "1.4.2")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_older_onering_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("onering", "1.4.0")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_known_compromised_greentic_release_is_rejected(self) -> None:
        result = self.run_policy(
            make_lock(("greentic-setup", "1.3.1-dev.34027618345"))
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("greentic-setup@1.3.1-dev.34027618345", result.stderr)

    def test_newer_greentic_setup_requires_review(self) -> None:
        result = self.run_policy(make_lock(("greentic-setup", "1.3.2")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_older_greentic_setup_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("greentic-setup", "1.3.0")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_newer_greentic_setup_dev_requires_review(self) -> None:
        result = self.run_policy(make_lock(("greentic-setup-dev", "1.3.34027618346")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

    def test_older_greentic_setup_dev_release_is_allowed(self) -> None:
        result = self.run_policy(make_lock(("greentic-setup-dev", "1.3.34027618344")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_lockfile_is_rejected(self) -> None:
        result = self.run_policy("this is not valid TOML = [")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot read Cargo lockfile", result.stderr)


if __name__ == "__main__":
    unittest.main()
