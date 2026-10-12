{ pkgs, sourceFilter }:
let
  fixtureRoot = ./fixtures;
  filteredFixtures = pkgs.lib.cleanSourceWith {
    name = "nixward-source-filter-fixtures";
    src = fixtureRoot;
    filter = sourceFilter fixtureRoot;
  };
in
assert !(sourceFilter fixtureRoot "${toString fixtureRoot}/symlink-case/.env.local" "symlink");
assert !(sourceFilter fixtureRoot "${toString fixtureRoot}/symlink-case/.ssh" "symlink");
pkgs.runCommand "nixward-source-filter-regression" { src = filteredFixtures; } ''
  set -eu

  # Safe source and checked-in templates must remain available.
  test -f "$src/keep.txt"
  test -f "$src/.env.defaults"
  test -f "$src/.env.example"
  test -f "$src/.env.sample"
  test -f "$src/.env.template"
  test -f "$src/id_rsa.pub"
  test -f "$src/symlink-case/keep.txt"

  # Credential and local configuration paths must never enter the closure.
  for path in \
    ".env" ".env.local" ".env.production" \
    ".netrc" ".npmrc" ".pypirc" \
    "application_default_credentials.json" "credentials.json" "service-account.json" \
    "id_rsa" "private.key" "bundle.p12" "bundle.pfx" \
    ".aws" ".ssh" ".docker" \
    "symlink-case/.env.local" "symlink-case/.ssh"; do
    if [ -e "$src/$path" ] || [ -L "$src/$path" ]; then
      echo "unexpected sensitive path in Nix source closure: $path" >&2
      exit 1
    fi
  done

  touch "$out"
'';
