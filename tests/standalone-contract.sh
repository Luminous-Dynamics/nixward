#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

! grep -q 'workspace = true' Cargo.toml
! grep -q 'path = "../symthaea-core"' Cargo.toml
! grep -Eq '\.\./\.\./\.\./|monorepoRoot|sourceRoot' flake.nix Cargo.toml
grep -q 'rev = "a03379d7cea94d1c3409d258a0a6be02b2c79913"' Cargo.toml
test -s rust-toolchain.toml
! grep -q '^Cargo.lock$' .gitignore

grep -q 'type = lib.types.package;' nix/module.nix
! grep -q 'pkgs.nixward-daemon or' nix/module.nix

echo "nixward standalone contract: PASS"
