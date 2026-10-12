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

# Reviewed against the RustSec malicious-advisory index on 2026-10-12.
# These package names were reported malicious/compromised in the RustSec catalog.
# RUSTSEC-2026-0265/-0264/-0259/-0261/-0263 (Aug. 20 campaign),
# RUSTSEC-2026-0171/-0155/-0102/-0100/-0101/-0108/-0107/-0081.
# Deny these names until an explicit dependency/security review is approved.
KNOWN_MALICIOUS_CRATE_NAMES = {
    "acceptxmr-rs",
    "aovine",
    "arone",
    "aronenao",
    "bit-flags",
    "chrono_anchor",
    "clob-sdk",
    "custom-req-on-workers",
    "dnp3times",
    "envlogger",
    "evm-units",
    "exploration",
    "finch-rst",
    "finch-rust",
    "finch_cli_rust",
    "hann-rs-service",
    "if-cfg",
    "jfrog_quotes",
    "lasso-rs",
    "lazystatic",
    "lfest-main",
    "libusb1-main",
    "littest",
    "logflux",
    "logtrace",
    "microsoftsystem64",
    "monero-api",
    "monero-rpc-rs",
    "mysten-metrics",
    "oncecell",
    "openvpn-plugin-rs",
    "polymarket-client-sdks",
    "polymarket-clients-sdk",
    "polymarkets-client-sdk",
    "polymarkets-rs-clob-client",
    "postgresderive",
    "postgress",
    "pretty-changelog-logger",
    "proc-macro-en",
    "proc-macro1",
    "rands",
    "registry-win",
    "replit_ruspty",
    "rpc-check",
    "rustdecimal",
    "safe-agent-rs",
    "serd",
    "sha-rst",
    "sha-rust",
    "sophosfirewall-python",
    "statsrelay-protobuf",
    "sui-execution-cut",
    "tauri-win-rt-notification",
    "tauri-winrt-notifications",
    "time-sync",
    "time_calibrator",
    "time_calibrators",
    "tiny-server",
    "tinymember",
    "tracing-check",
    "tracing-ethers",
    "tracing_checks",
    "tracings",
    "tree-sitter-pkl",
    "uniswap-utils",
    "win-base64-rs",
    "win-crypto",
    "win_run_rs",
    "windows-service-rs",
    "windowsservice",
    "winx-rs",
    "xrvrv",
}
# Do not blanket-deny packages whose advisory applies only to one release.
# Exact bad releases with published boundaries:
# RUSTSEC-2026-0262 append-only-vec, 0266 internment, 0281/-0280 greentic,
# and 0175 onering. RUSTSEC-2026-0260 identifies arrayref 0.3.10; below,
# ARRAYREF_REVIEW_FLOOR conservatively requires review of that version or newer.
KNOWN_MALICIOUS_RELEASES = {
    ("append-only-vec", "0.1.9"),
    ("internment", "0.8.7"),
    ("greentic-setup", "1.3.1-dev.34027618345"),
    ("greentic-setup-dev", "1.3.34027618345"),
    ("onering", "1.4.1"),
}
ARRAYREF_REVIEW_FLOOR = (0, 3, 10)
ALLOWED_REGISTRY_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+sparse+https://index.crates.io/",
}
LOCAL_HARNESS_PACKAGE = ("nixward-network-device-plan-m0-harness", "0.1.0")
CHECKSUM_RE = re.compile(r"[0-9a-f]{64}")


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
    if document.get("version") != 4:
        print("ERROR: planner harness Cargo.lock must use reviewed format version 4", file=sys.stderr)
        return 1

    # The harness intentionally uses only registry crates plus its one local
    # package. Reject Git/path/alternate-registry sources and missing checksums
    # before advisory policy: a valid-looking version is not source integrity.
    identities: set[tuple[str, str, str | None]] = set()
    package_records: list[tuple[tuple[str, str, str | None], dict[str, object]]] = []
    local_harness_count = 0
    for package in packages:
        if not isinstance(package, dict):
            print("ERROR: malformed package entry in Cargo.lock", file=sys.stderr)
            return 1
        name, version, source = package.get("name"), package.get("version"), package.get("source")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            print("ERROR: Cargo.lock package is missing a valid name/version", file=sys.stderr)
            return 1
        identity = (name, version, source if isinstance(source, str) else None)
        if identity in identities:
            print(f"ERROR: duplicate Cargo.lock package identity: {identity}", file=sys.stderr)
            return 1
        identities.add(identity)
        package_records.append((identity, package))
        if source is None:
            if (name, version) != LOCAL_HARNESS_PACKAGE:
                print(f"ERROR: unexpected source-less package: {name}@{version}", file=sys.stderr)
                return 1
            local_harness_count += 1
            if "checksum" in package:
                print("ERROR: local harness package must not have a registry checksum", file=sys.stderr)
                return 1
            continue
        if source not in ALLOWED_REGISTRY_SOURCES:
            print(f"ERROR: unapproved dependency source for {name}@{version}: {source}", file=sys.stderr)
            return 1
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or CHECKSUM_RE.fullmatch(checksum) is None:
            print(f"ERROR: missing or invalid registry checksum for {name}@{version}", file=sys.stderr)
            return 1
    if local_harness_count != 1:
        print(f"ERROR: expected exactly one local harness package, found {local_harness_count}", file=sys.stderr)
        return 1

    # Verify that every lockfile edge resolves to exactly one package identity.
    # This does not replace Cargo's own resolver; it catches truncated or
    # hand-edited lockfiles before they reach cargo-audit or cargo test.
    for identity, package in package_records:
        dependency_specs = package.get("dependencies", [])
        if not isinstance(dependency_specs, list) or any(
            not isinstance(dependency, str) for dependency in dependency_specs
        ):
            print(f"ERROR: malformed dependency list for {identity[0]}@{identity[1]}", file=sys.stderr)
            return 1
        for dependency in dependency_specs:
            match = re.fullmatch(r"(.+?) ([0-9][^ ]*)(?: \((.+)\))?", dependency)
            if match is None:
                dependency_name, dependency_version, dependency_source = dependency, None, None
            else:
                dependency_name, dependency_version, dependency_source = match.groups()
            candidates = [
                candidate
                for candidate, _record in package_records
                if candidate[0] == dependency_name
                and (dependency_version is None or candidate[1] == dependency_version)
                and (dependency_source is None or candidate[2] == dependency_source)
            ]
            if len(candidates) != 1:
                print(
                    f"ERROR: unresolved or ambiguous dependency edge "
                    f"{identity[0]}@{identity[1]} -> {dependency!r} "
                    f"(matched {len(candidates)} package identities)",
                    file=sys.stderr,
                )
                return 1

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
