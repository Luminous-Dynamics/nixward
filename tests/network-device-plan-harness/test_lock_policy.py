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

    def test_compromised_arrayref_release_is_rejected(self) -> None:
        result = self.run_policy(make_lock(("arrayref", "0.3.10")))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blocked pending explicit security review", result.stderr)

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

    def test_known_compromised_greentic_release_is_rejected(self) -> None:
        result = self.run_policy(
            make_lock(("greentic-setup", "1.3.1-dev.34027618345"))
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("greentic-setup@1.3.1-dev.34027618345", result.stderr)

    def test_malformed_lockfile_is_rejected(self) -> None:
        result = self.run_policy("this is not valid TOML = [")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot read Cargo lockfile", result.stderr)


if __name__ == "__main__":
    unittest.main()
