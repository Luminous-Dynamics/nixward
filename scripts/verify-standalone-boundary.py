#!/usr/bin/env python3
"""Fail closed if standalone source dependencies escape or drift."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
errors: list[str] = []

HEX40 = re.compile(r"^[0-9a-f]{40}$")


def repo_relative(path: str, source: pathlib.Path) -> pathlib.Path:
    candidate = (source.parent / path).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        errors.append(f"{source.relative_to(ROOT)}: path escapes repository: {path}")
    return candidate


def walk_manifest(value: object, source: pathlib.Path, path: str = "Cargo.toml") -> None:
    if isinstance(value, dict):
        if isinstance(value.get("path"), str):
            candidate = repo_relative(value["path"], source)
            if candidate.exists() and not candidate.is_file() and not candidate.is_dir():
                errors.append(
                    f"{source.relative_to(ROOT)}: path is neither file nor directory: {value['path']}"
                )
            elif not candidate.exists():
                errors.append(
                    f"{source.relative_to(ROOT)}: path does not exist: {value['path']}"
                )

        if isinstance(value.get("git"), str):
            rev = value.get("rev")
            if not isinstance(rev, str) or not HEX40.fullmatch(rev):
                errors.append(
                    f"{source.relative_to(ROOT)}: git dependency requires a 40-hex rev: {value['git']}"
                )
            if "branch" in value or "tag" in value:
                errors.append(
                    f"{source.relative_to(ROOT)}: git dependency may not use branch/tag selectors"
                )

        for key, child in value.items():
            walk_manifest(child, source, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_manifest(child, source, f"{path}[{index}]")


manifest_paths = sorted(
    p
    for p in ROOT.rglob("Cargo.toml")
    if not any(part in {".git", "target", "result"} for part in p.parts)
)

if not manifest_paths:
    errors.append("no Cargo.toml found")

for manifest in manifest_paths:
    try:
        with manifest.open("rb") as fh:
            cargo = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{manifest.relative_to(ROOT)}: cannot parse Cargo.toml: {exc}")
        continue
    walk_manifest(cargo, manifest, str(manifest.relative_to(ROOT)))


for nix_file in ROOT.rglob("*.nix"):
    if any(part in {".git", "result", "target"} for part in nix_file.parts):
        continue
    try:
        text = nix_file.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{nix_file.relative_to(ROOT)}: cannot read Nix source: {exc}")
        continue
    if re.search(r"(^|[\s=(])\.\./", text):
        errors.append(f"{nix_file.relative_to(ROOT)}: contains parent-relative path reference")


readme = ROOT / "README.md"
if readme.is_file():
    try:
        readme_text = readme.read_text(encoding="utf-8")
        if "symthaea.nixosModules.nixward" in readme_text:
            errors.append(
                "README.md: standalone module example still imports nixward through symthaea"
            )
        if 'inputs.nixward.url = "github:Luminous-Dynamics/nixward";' not in readme_text:
            errors.append(
                "README.md: standalone module example must declare the nixward flake input"
            )
    except OSError as exc:
        errors.append(f"README.md: cannot read documentation: {exc}")

if errors:
    print("standalone boundary: FAIL")
    for error in errors:
        print(f" - {error}")
    sys.exit(1)

print(
    "standalone boundary: PASS "
    f"({len(manifest_paths)} Cargo manifest(s), immutable git revisions, self-contained docs)"
)
