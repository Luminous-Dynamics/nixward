#!/usr/bin/env python3
"""Fail-closed checks for known Rust supply-chain incidents in a Cargo.lock.

This is a narrow supplemental policy guard, not a general malware detector.
Keep the advisory rationale and version boundary reviewed when changing it.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

# Names for which the malicious package itself was removed/identified;
# deny the name until a maintainer explicitly reviews any proposed dependency.
KNOWN_MALICIOUS_CRATE_NAMES = {
    "proc-macro1",
    "proc-macro-en",
    "aovine",
    "arone",
    "aronenao",
    "tinymember",
    "logflux",
    "exploration",
    "microsoftsystem64",
    "pretty-changelog-logger",
    "safe-agent-rs",
    "sui-execution-cut",
    "mysten-metrics",
    "logtrace",
}
# Known malicious releases where RustSec published a bounded bad version.
KNOWN_MALICIOUS_RELEASES = {
    ("append-only-vec", "0.1.9"),
    ("internment", "0.8.7"),
    ("greentic-setup", "1.3.1-dev.34027618345"),
    ("greentic-setup-dev", "1.3.34027618345"),
    ("onering", "1.4.1"),
}
ARRAYREF_REVIEW_FLOOR = (0, 3, 10)


def parse_release(version: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?", version)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} Cargo.lock", file=sys.stderr)
        return 2

    lock_path = Path(sys.argv[1])
    try:
        document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"ERROR: cannot read Cargo lockfile {lock_path}: {error}", file=sys.stderr)
        return 2

    packages = document.get("package")
    if not isinstance(packages, list):
        print("ERROR: Cargo.lock has no package array", file=sys.stderr)
        return 2

    found_names = sorted(
        {
            package.get("name")
            for package in packages
            if isinstance(package, dict)
            and package.get("name") in KNOWN_MALICIOUS_CRATE_NAMES
        }
    )
    if found_names:
        print(
            "ERROR: known malicious Rust crate name(s) in lockfile: "
            + ", ".join(found_names),
            file=sys.stderr,
        )
        return 1

    found_releases = sorted(
        (package.get("name"), package.get("version"))
        for package in packages
        if isinstance(package, dict)
        and (package.get("name"), package.get("version")) in KNOWN_MALICIOUS_RELEASES
    )
    if found_releases:
        formatted = ", ".join(f"{name}@{version}" for name, version in found_releases)
        print(f"ERROR: known malicious Rust release(s) in lockfile: {formatted}", file=sys.stderr)
        return 1

    for package in packages:
        if not isinstance(package, dict) or package.get("name") != "arrayref":
            continue
        version = package.get("version")
        release = parse_release(version) if isinstance(version, str) else None
        if release is None:
            print(f"ERROR: unrecognized arrayref version {version!r}; review required", file=sys.stderr)
            return 1
        if release >= ARRAYREF_REVIEW_FLOOR:
            print(
                f"ERROR: arrayref {version} is blocked pending explicit security review "
                "(the 0.3.10 release was part of the 2026-08-20 supply-chain attack)",
                file=sys.stderr,
            )
            return 1

    print(f"OK: {len(packages)} locked packages; known malicious names/releases absent; arrayref boundary satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
