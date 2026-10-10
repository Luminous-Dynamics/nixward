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
            "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.ref == 'validation/full-stack-qualification-2026-10-08'",
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
            if "always() && ((github.event_name == 'pull_request' && github.event.pull_request.head.ref == 'validation/full-stack-qualification-2026-10-08') || github.ref == 'refs/heads/main')" not in body:
                errors.append(f"{job_name} job must qualify only on the dedicated validation PR or main")

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

    if bootstrap:
        bootstrap_body = bootstrap.group(0)
        persist_step = re.search(
            r"(?ms)^      - name: Persist generated lockfile.*?(?=^      - name:|^  [A-Za-z_][\w-]*:|\Z)",
            bootstrap_body,
        )
        if not persist_step or "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}" not in persist_step.group(0):
            errors.append("lockfile bootstrap must map GITHUB_TOKEN into the persistence step")
        if text.count("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}") != 1:
            errors.append("workflow must map the bootstrap write token exactly once")

    draft_lockfile = re.search(
        r"(?ms)^  draft-lockfile-artifact:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    if not draft_lockfile:
        errors.append("missing draft exact-run lockfile artifact job")
    else:
        body = draft_lockfile.group(0)
        expected = [
            "github.ref == 'refs/heads/hardening/journal-owned-activation-capability-2026-10-09'",
            "ref: ${{ github.sha }}",
            "cargo generate-lockfile",
            "cargo metadata --locked --format-version=1",
            "steps.lockfile_digest.outputs.cargo_lock_sha256",
            "name: nixward-draft-cargo-lock-${{ github.run_id }}-${{ github.run_attempt }}",
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "contents: read",
        ]
        for marker in expected:
            if marker not in body:
                errors.append(f"draft lockfile artifact job missing required marker: {marker}")
        if "contents: write" in body:
            errors.append("draft lockfile artifact job must not have repository write authority")

    draft_candidate = re.search(
        r"(?ms)^  draft-candidate-check:.*?(?=^  [A-Za-z_][\w-]*:|\Z)",
        text,
    )
    if not draft_candidate:
        errors.append("missing draft candidate checks job")
    else:
        body = draft_candidate.group(0)
        expected = [
            "- draft-lockfile-artifact",
            "needs.draft-lockfile-artifact.result == 'success'",
            "test \"$branch_tip\" = \"$GITHUB_SHA\"",
            "uses: actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0",
            "needs.draft-lockfile-artifact.outputs.cargo_lock_sha256",
            "EXPECTED_CARGO_LOCK_SHA256",
            "test \"$actual\" = \"$EXPECTED_CARGO_LOCK_SHA256\"",
            "cargo test --locked --bin nixward-worker-gate",
            "git add --intent-to-add -f Cargo.lock",
            "git ls-files --error-unmatch Cargo.lock",
            "Draft hardening candidate checks (not qualification)",
            "it does not issue a qualification receipt",
        ]
        for marker in expected:
            if marker not in body:
                errors.append(f"draft candidate job missing required marker: {marker}")
        # The lockfile is created in the ephemeral CI workspace from the exact-run
        # artifact. Intent-to-add makes it visible to Git-backed Nix flake sources;
        # it does not commit or push the generated file to the branch.
        if "Require committed lockfile" in body:
            errors.append("draft candidate must not require Cargo.lock to be committed")

        if "git add --intent-to-add -f Cargo.lock" not in body:
            errors.append("draft candidate must expose its exact-run lockfile to Git-backed flake evaluation")
        if "git ls-files --error-unmatch Cargo.lock" not in body:
            errors.append("draft candidate must verify Git visibility of the exact-run lockfile")
        if "git commit" in body or "git push" in body:
            errors.append("draft candidate must not commit or push the generated lockfile")

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
            "Assert validation subject mirrors hardening head",
            "git fetch --no-tags origin hardening/full-stack-qualification-2026-10-08",
            "hardening_sha=\"$(git rev-parse FETCH_HEAD)\"",
            "test \"$hardening_sha\" = \"${{ github.event.pull_request.head.sha }}\"",
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
            "Assert validation subject mirrors hardening head",
            "git fetch --no-tags origin hardening/full-stack-qualification-2026-10-08",
            "hardening_sha=\"$(git rev-parse FETCH_HEAD)\"",
            "test \"$hardening_sha\" = \"${{ github.event.pull_request.head.sha }}\"",
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
