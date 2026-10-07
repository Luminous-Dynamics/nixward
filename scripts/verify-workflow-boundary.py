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
