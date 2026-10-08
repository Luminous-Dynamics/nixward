#!/usr/bin/env python3
"""Fail closed on the Nixward CI authority/provenance boundary."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "standalone.yml"

errors: list[str] = []

if not WORKFLOW.is_file():
    errors.append("missing .github/workflows/standalone.yml")
else:
    text = WORKFLOW.read_text(encoding="utf-8")

    # Every checkout step is untrusted-source-adjacent and must not persist the
    # GitHub token into the working tree.
    step_blocks = re.findall(
        r"(?ms)^      - name:.*?(?=^      - name:|\Z)",
        text,
    )
    checkout_count = 0
    for block in step_blocks:
        if "uses: actions/checkout@" not in block:
            continue
        checkout_count += 1
        if "persist-credentials: false" not in block:
            errors.append("actions/checkout step is missing persist-credentials: false")

    if checkout_count == 0:
        errors.append("no actions/checkout step found")

    lockfile_artifact = re.search(
        r"(?ms)^  lockfile-artifact:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    if not lockfile_artifact:
        errors.append("missing exact-head lockfile-artifact job")
    else:
        body = lockfile_artifact.group(0)
        required = [
            "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository",
            "persist-credentials: false",
            "ref: ${{ github.event.pull_request.head.sha }}",
            "Prepare exact-head Cargo.lock",
            "if [ -f Cargo.lock ]; then",
            "cargo metadata --locked --format-version=1",
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "id: upload_lockfile",
            "steps.upload_lockfile.outputs.artifact-digest",
            "steps.lockfile_digest.outputs.cargo_lock_sha256",
        ]
        for marker in required:
            if marker not in body:
                errors.append(f"lockfile-artifact job missing required marker: {marker}")
        if re.search(r"(?m)^    permissions:\n(?:      [^\n]+\n)*      contents: write\s*$", body):
            errors.append("lockfile-artifact job must not have contents: write")
        if "contents: write" in body:
            errors.append("lockfile-artifact job must never receive repository write authority")

    for job_name in ["validate", "nix"]:
        job = re.search(
            rf"(?ms)^  {job_name}:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
            text,
        )
        if job:
            body = job.group(0)
            if "- lockfile-artifact" not in body:
                errors.append(f"{job_name} job must declare lockfile-artifact as a dependency")
            if "Require trusted repository PR" not in body:
                errors.append(f"{job_name} job must explicitly reject fork pull requests")
            if "test \"${{ github.event.pull_request.head.repo.full_name }}\" = \"${{ github.repository }}\"" not in body:
                errors.append(f"{job_name} job must contain an exact PR-head repository equality test")

    for marker in [
        "nixward-cargo-lock-${{ github.event.pull_request.head.sha }}",
        "needs.lockfile-artifact.outputs.cargo_lock_sha256",
        "cargo_lock_artifact_digest",
    ]:
        if marker not in text:
            errors.append(f"workflow missing exact lockfile artifact binding: {marker}")

    # Only the lockfile bootstrap job may receive repository write authority.
    bootstrap = re.search(
        r"(?ms)^  bootstrap-lockfile:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    if not bootstrap or not re.search(
        r"(?m)^    permissions:\n      contents: write\s*$",
        bootstrap.group(0),
    ):
        errors.append("bootstrap-lockfile job must have contents: write")

    write_permission_sites = re.findall(
        r"^      contents: write\s*$",
        text,
        flags=re.M,
    )
    if len(write_permission_sites) != 1:
        errors.append("workflow must contain exactly one job-level contents: write permission")

    global_permissions = re.search(
        r"(?ms)^permissions:\n  contents: read\s*(?=\n\n|concurrency:)",
        text,
    )
    if not global_permissions:
        errors.append("workflow must default to contents: read")

    provenance = re.search(
        r"(?ms)^  provenance:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    nix_job = re.search(
        r"(?ms)^  nix:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    validate_job = re.search(
        r"(?ms)^  validate:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    if not validate_job:
        errors.append("missing validation job")
    else:
        validate_body = validate_job.group(0)
        for marker in [
            "ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
            "expected_commit=\"${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}\"",
            "test \"$actual_commit\" = \"$expected_commit\"",
        ]:
            if marker not in validate_body:
                errors.append(f"validation job missing exact-subject marker: {marker}")

    if not nix_job:
        errors.append("missing Nix packaging qualification job")
    else:
        nix_body = nix_job.group(0)
        for marker in [
            "nix flake check --no-update-lock-file --no-write-lock-file",
            "nix build .#nixward --no-update-lock-file --no-write-lock-file",
            "persist-credentials: false",
        ]:
            if marker not in nix_body:
                errors.append(f"Nix qualification job missing required marker: {marker}")

    if not provenance:
        errors.append("missing provenance job")
    else:
        body = provenance.group(0)
        expected = [
            "id-token: write",
            "attestations: write",
            "artifact-metadata: write",
            "github.event_name == 'push'",
            "github.ref == 'refs/heads/main'",
            "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            "predicate-type: https://github.com/Luminous-Dynamics/nixward/attestations/qualification/v1",
            "predicate-path: qualification-predicate.json",
            "Generate signed SLSA provenance",
            "Require committed lockfile",
            "git ls-files --error-unmatch Cargo.lock",
            "Generate signed qualification attestation",
            "nix_flake_check",
            "nix_package_build",
        ]
        for marker in expected:
            if marker not in body:
                errors.append(f"provenance job missing required marker: {marker}")

if errors:
    print("workflow authority boundary: FAIL")
    for error in errors:
        print(f" - {error}")
    sys.exit(1)

print("workflow authority boundary: PASS")
