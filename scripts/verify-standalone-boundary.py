#!/usr/bin/env python3
"""Fail closed if the repository regains filesystem dependencies outside itself."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
errors: list[str] = []

with (ROOT / "Cargo.toml").open("rb") as fh:
    cargo = tomllib.load(fh)

def walk(value: object, path: str = "Cargo.toml") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "path" and isinstance(child, str):
                candidate = (ROOT / child).resolve()
                try:
                    candidate.relative_to(ROOT)
                except ValueError:
                    errors.append(f"{path}: path escapes repository: {child}")
                    continue
                if not candidate.exists():
                    errors.append(f"{path}: path does not exist: {child}")
            else:
                walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, f"{path}[{index}]")

walk(cargo)

for nix_file in ROOT.rglob("*.nix"):
    if any(part in {".git", "result", "target"} for part in nix_file.parts):
        continue
    text = nix_file.read_text(encoding="utf-8")
    if re.search(r"(^|[\s=(])\.\./", text):
        errors.append(f"{nix_file.relative_to(ROOT)}: contains parent-relative path reference")

if errors:
    print("standalone boundary: FAIL")
    for error in errors:
        print(f" - {error}")
    sys.exit(1)

print("standalone boundary: PASS")
