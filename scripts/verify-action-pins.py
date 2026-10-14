#!/usr/bin/env python3
"""Fail closed when a remote GitHub Action is not pinned to a full commit SHA."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USE_RE = re.compile(r"^\s*uses:\s*([^\s#]+)@([^\s#]+)\s*(?:#.*)?$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

errors: list[str] = []

if not WORKFLOWS.is_dir():
    errors.append("missing .github/workflows directory")
else:
    workflow_files = sorted(
        path for path in WORKFLOWS.iterdir() if path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflow_files:
        try:
            lines = workflow.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            errors.append(f"{workflow.relative_to(ROOT)}: cannot read workflow: {exc}")
            continue

        for line_number, line in enumerate(lines, start=1):
            match = USE_RE.match(line)
            if not match:
                continue
            action_ref, revision = match.groups()
            # Local composite actions are already repository-scoped and do not
            # use the owner/repository@revision form.
            if action_ref.startswith("./"):
                continue
            if "/" not in action_ref:
                errors.append(
                    f"{workflow.relative_to(ROOT)}:{line_number}: invalid remote action reference: {action_ref}"
                )
                continue
            if not SHA40_RE.fullmatch(revision):
                errors.append(
                    f"{workflow.relative_to(ROOT)}:{line_number}: action {action_ref} "
                    f"must be pinned to a 40-hex commit SHA, got {revision!r}"
                )

if errors:
    print("action pin boundary: FAIL")
    for error in errors:
        print(f" - {error}")
    sys.exit(1)

print("action pin boundary: PASS")
