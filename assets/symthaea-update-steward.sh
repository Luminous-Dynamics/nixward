#!/usr/bin/env bash
set -euo pipefail

ROOT="${SYMTHAEA_FLAKE_ROOT:-/etc/nixos}"
STATE="${SYMTHAEA_UPDATE_STATE:-/var/lib/symthaea-update}"
EVIDENCE="${SYMTHAEA_EVIDENCE_STATE:-/var/lib/symthaea-evidence}"
HOST="${SYMTHAEA_HOSTNAME:-$(hostname)}"
PROMOTION="${SYMTHAEA_AUTO_PROMOTION:-stage}"
NIXOS_REBUILD="${SYMTHAEA_NIXOS_REBUILD:-$(command -v nixos-rebuild || true)}"
POLICY="$ROOT/generated/update-policy.json"
SCHEMA="$ROOT/generated/schema.json"
SOURCE_POLICY="$ROOT/generated/source-policy.json"
PENDING_ACTIVATION="$EVIDENCE/pending-activation.json"
LAST_ACTIVATION="$EVIDENCE/last-activation.json"
NIX=(nix --extra-experimental-features 'nix-command flakes')

log() { printf '[symthaea-update] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_file() {
  [ -f "$1" ] || die "required file missing: $1"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

source_digest() {
  "${NIX[@]}" hash path "$ROOT"
}

canonical_system_path() {
  readlink -f "${1:-/run/current-system}"
}

last_verified_receipt_digest() {
  if [ -f "$LAST_ACTIVATION" ]; then
    sha256_file "$LAST_ACTIVATION"
  elif [ -f "$EVIDENCE/genesis.json" ]; then
    sha256_file "$EVIDENCE/genesis.json"
  else
    printf '%s\n' 'genesis-unrecorded'
  fi
}

probe_nix_binary() {
  local nix_bin="$1" nix_dir
  nix_dir="$(dirname "$nix_bin")"
  "$nix_bin" --version
  "$nix_bin" --extra-experimental-features 'nix-command flakes' flake metadata --help >/dev/null
  "$nix_bin" --extra-experimental-features 'nix-command flakes' flake update --help >/dev/null
  "$nix_bin" --extra-experimental-features 'nix-command flakes' flake check --help >/dev/null
  "$nix_bin" --extra-experimental-features 'nix-command flakes' build --help >/dev/null
  "$nix_bin" --extra-experimental-features 'nix-command flakes' eval --help >/dev/null
  "$nix_bin" --extra-experimental-features 'nix-command flakes' hash path --help >/dev/null
  [ -x "$nix_dir/nix-build" ] || die "required compatibility evaluator missing: $nix_dir/nix-build"
  "$nix_dir/nix-build" --version >/dev/null
}

build_system_nix() {
  local directory="$1" nix_build="$2"
  "$nix_build" --no-out-link "$directory/system.nix" | tail -n1
}

verify_locked_sources() {
  local lock_file="$1" input expected_type expected_owner expected_repo expected_ref actual
  require_file "$lock_file"
  while IFS=$'\t' read -r input expected_type expected_owner expected_repo expected_ref; do
    actual="$(jq -er --arg name "$input" '
      def nodekey($ref):
        if ($ref | type) == "string" then $ref
        elif (($ref | type) == "array") and (($ref | length) == 1) and (($ref[0] | type) == "string") then $ref[0]
        else error("unsupported flake.lock input reference") end;
      .nodes[.root].inputs[$name] as $ref
      | if $ref == null then error("missing root input") else . end
      | .nodes[nodekey($ref)]
      | [(.locked.type // ""), (.locked.owner // ""), (.locked.repo // ""), (.original.ref // "")] | @tsv
    ' "$lock_file")" || die "could not resolve trusted lock identity for input $input"
    IFS=$'\t' read -r actual_type actual_owner actual_repo actual_ref <<< "$actual"
    [ "$actual_type" = "$expected_type" ] \
      && [ "$actual_owner" = "$expected_owner" ] \
      && [ "$actual_repo" = "$expected_repo" ] \
      && [ "$actual_ref" = "$expected_ref" ] \
      || die "upstream source substitution for $input: expected $expected_type:$expected_owner/$expected_repo@$expected_ref, got $actual_type:$actual_owner/$actual_repo@$actual_ref"
  done < <(jq -r '.sources[] | [.input, .source_type, .owner, .repo, .declared_ref] | @tsv' "$SOURCE_POLICY")
}

probe() {
  require_file "$ROOT/flake.nix"
  require_file "$ROOT/system.nix"
  require_file "$ROOT/lib/locked-inputs.nix"
  require_file "$ROOT/flake.lock"
  require_file "$POLICY"
  require_file "$SCHEMA"
  require_file "$SOURCE_POLICY"
  probe_nix_binary "$(command -v nix)"
  jq -e '.schema_version == 2 and (.inputs | type == "array") and .entrypoints.parity == "exact-toplevel-store-path"' "$POLICY" >/dev/null \
    || die "unsupported or malformed update policy"
  jq -e '.schema_version == 1 and .sovereign_flake_schema == 3 and .update_policy_schema == 2 and .upstream_source_policy_schema == 1' "$SCHEMA" >/dev/null \
    || die "unsupported sovereign schema; migration required"
  jq -e '.schema_version == 1 and .kind == "symthaea-upstream-source-policy-v1" and (.sources | length >= 3)' "$SOURCE_POLICY" >/dev/null \
    || die "unsupported or malformed upstream source policy"
  verify_locked_sources "$ROOT/flake.lock"
}

tracked_inputs() {
  jq -r '.inputs[] | select(.auto_stage == true and .strategy == "lock-only") | .name' "$POLICY"
}

current_release() {
  jq -r '.release.current' "$POLICY"
}

write_release_proposal() {
  local latest current repo channel_base now
  current="$(current_release)"
  repo="$(jq -r '.release.discovery.git_remote' "$POLICY")"
  channel_base="$(jq -r '.release.discovery.channel_base' "$POLICY")"
  [ -n "$repo" ] && [ "$repo" != null ] || return 0
  [ -n "$channel_base" ] && [ "$channel_base" != null ] || return 0

  latest="$(
    git ls-remote --heads "$repo" 'refs/heads/nixos-*' 2>/dev/null \
      | awk '{sub("refs/heads/nixos-", "", $2); print $2}' \
      | grep -E '^[0-9]{2}\.(05|11)$' \
      | sort -V \
      | tail -n1 \
      || true
  )"
  [ -n "$latest" ] || return 0
  [ "$(printf '%s\n%s\n' "$current" "$latest" | sort -V | tail -n1)" = "$latest" ] || return 0
  [ "$latest" != "$current" ] || return 0

  # A release branch can exist before it is officially promoted. Require the
  # corresponding official NixOS channel to resolve before proposing migration.
  if ! curl -fsSL --max-time 15 -o /dev/null "$channel_base/nixos-$latest"; then
    return 0
  fi

  mkdir -p "$STATE"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n \
    --arg now "$now" \
    --arg from "$current" \
    --arg to "$latest" \
    --arg current_ref "nixos-$current" \
    --arg proposed_ref "nixos-$latest" \
    --argjson gates "$(jq '.release.required_gates' "$POLICY")" \
    '{
      schema_version: 1,
      kind: "symthaea-nixos-release-proposal-v1",
      observed_at: $now,
      from_release: $from,
      to_release: $to,
      current_nixpkgs_ref: $current_ref,
      proposed_nixpkgs_ref: $proposed_ref,
      disposition: "proposal-only",
      state_version_policy: "never-auto-bump",
      required_gates: $gates,
      source_policy: "must-remain-trusted"
    }' > "$STATE/release-proposal.json"
}

stage() {
  probe
  mkdir -p "$STATE" "$EVIDENCE"
  [ ! -f "$PENDING_ACTIVATION" ] \
    || die "a promoted generation is awaiting post-boot verification; reboot/verify before staging another candidate"

  local baseline_source baseline_lock tmp candidate_dir before_meta after_meta
  local candidate_lock target candidate_system compatibility_system candidate_nix candidate_nix_version now
  local running_system parent_receipt schema_sha256 source_policy_sha256
  baseline_source="$(source_digest)"
  baseline_lock="$(sha256_file "$ROOT/flake.lock")"
  running_system="$(canonical_system_path)"
  parent_receipt="$(last_verified_receipt_digest)"
  schema_sha256="$(sha256_file "$SCHEMA")"
  source_policy_sha256="$(sha256_file "$SOURCE_POLICY")"
  tmp="$STATE/candidate.tmp.$$"
  candidate_dir="$STATE/candidate"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  cp -a "$ROOT/." "$tmp/"
  rm -rf "$tmp/.git" "$tmp/result" "$tmp/result-"* 2>/dev/null || true

  mapfile -t inputs < <(tracked_inputs)
  [ "${#inputs[@]}" -gt 0 ] || die "update policy contains no auto-stage lock-only inputs"

  before_meta="$STATE/metadata-before.json"
  after_meta="$tmp/generated/update-metadata-after.json"
  "${NIX[@]}" flake metadata --json "path:$ROOT" > "$before_meta"

  log "checking locked inputs: ${inputs[*]}"
  "${NIX[@]}" flake update "${inputs[@]}" --flake "path:$tmp"
  verify_locked_sources "$tmp/flake.lock"
  candidate_lock="$(sha256_file "$tmp/flake.lock")"

  write_release_proposal || true

  if [ "$candidate_lock" = "$baseline_lock" ]; then
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -n \
      --arg now "$now" \
      --arg source "$baseline_source" \
      --arg lock "$baseline_lock" \
      --arg host "$HOST" \
      '{
        schema_version: 1,
        kind: "symthaea-update-candidate-v1",
        status: "current",
        checked_at: $now,
        hostname: $host,
        baseline_source_digest: $source,
        baseline_lock_sha256: $lock
      }' > "$STATE/last-check.json"
    rm -rf "$tmp"
    log "no locked-input update available"
    return 0
  fi

  "${NIX[@]}" flake metadata --json "path:$tmp" > "$after_meta"
  target="path:$tmp#nixosConfigurations.$HOST.config.system.build.toplevel"
  log "building complete candidate system before promotion"
  candidate_system="$("${NIX[@]}" build --no-link --print-out-paths --no-write-lock-file "$target")"
  [ -n "$candidate_system" ] || die "candidate build returned no system path"

  "${NIX[@]}" flake check --no-build --no-write-lock-file "path:$tmp" >/dev/null

  # Test the *next* Nix binary against every CLI surface the steward needs.
  # This is a feature probe, not a brittle version comparison.
  candidate_nix="$("${NIX[@]}" eval --raw --no-write-lock-file \
    "path:$tmp#nixosConfigurations.$HOST.config.nix.package.outPath")"
  [ -x "$candidate_nix/bin/nix" ] || die "candidate Nix binary is unavailable at $candidate_nix/bin/nix"
  probe_nix_binary "$candidate_nix/bin/nix" >/dev/null
  candidate_nix_version="$($candidate_nix/bin/nix --version)"

  compatibility_system="$(build_system_nix "$tmp" "$candidate_nix/bin/nix-build")"
  [ "$compatibility_system" = "$candidate_system" ] \
    || die "flake.nix/system.nix parity failure: $candidate_system != $compatibility_system"

  if "${NIX[@]}" store diff-closures --help >/dev/null 2>&1; then
    "${NIX[@]}" store diff-closures /run/current-system "$candidate_system" \
      > "$tmp/generated/closure-diff.txt" 2>&1 || true
  else
    printf '%s\n' 'nix store diff-closures unavailable on current Nix; candidate build still passed.' \
      > "$tmp/generated/closure-diff.txt"
  fi

  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n \
    --arg now "$now" \
    --arg host "$HOST" \
    --arg baseline_source "$baseline_source" \
    --arg baseline_lock "$baseline_lock" \
    --arg candidate_lock "$candidate_lock" \
    --arg candidate_system "$candidate_system" \
    --arg compatibility_system "$compatibility_system" \
    --arg candidate_nix "$candidate_nix_version" \
    --arg running_system "$running_system" \
    --arg parent_receipt "$parent_receipt" \
    --arg schema_sha256 "$schema_sha256" \
    --arg source_policy_sha256 "$source_policy_sha256" \
    --argjson inputs "$(printf '%s\n' "${inputs[@]}" | jq -R . | jq -s .)" \
    '{
      schema_version: 1,
      kind: "symthaea-update-candidate-v1",
      status: "ready",
      staged_at: $now,
      hostname: $host,
      tracked_inputs: $inputs,
      baseline_source_digest: $baseline_source,
      baseline_lock_sha256: $baseline_lock,
      candidate_lock_sha256: $candidate_lock,
      candidate_system: $candidate_system,
      compatibility_system: $compatibility_system,
      entrypoint_parity: "passed",
      flake_check_evaluation: "passed",
      candidate_nix_version: $candidate_nix,
      candidate_cli_compatibility: "passed",
      candidate_system_build: "passed",
      staged_running_system: $running_system,
      parent_receipt_sha256: $parent_receipt,
      sovereign_schema_sha256: $schema_sha256,
      upstream_source_policy_sha256: $source_policy_sha256,
      upstream_source_identity: "verified"
    }' > "$tmp/generated/update-candidate.json"
  sha256_file "$tmp/generated/update-candidate.json" > "$tmp/generated/update-candidate.sha256"

  rm -rf "$candidate_dir"
  mv "$tmp" "$candidate_dir"
  cp "$candidate_dir/generated/update-candidate.json" "$STATE/update-candidate.json"
  cp "$candidate_dir/generated/update-candidate.sha256" "$STATE/update-candidate.sha256"
  log "candidate ready: $candidate_system (flake/system.nix parity passed)"
}

apply_boot() {
  probe
  require_file "$STATE/update-candidate.json"
  require_file "$STATE/update-candidate.sha256"
  require_file "$STATE/candidate/flake.lock"
  [ -n "$NIXOS_REBUILD" ] && [ -x "$NIXOS_REBUILD" ] \
    || die "nixos-rebuild not available"

  local status expected_source actual_source expected_lock actual_candidate_lock
  local old_lock backup now new_source receipt pending candidate_record_sha actual_record_sha
  local expected_parent actual_parent expected_running actual_running
  status="$(jq -r '.status' "$STATE/update-candidate.json")"
  [ "$status" = ready ] || die "no ready candidate to apply"
  candidate_record_sha="$(cat "$STATE/update-candidate.sha256")"
  actual_record_sha="$(sha256_file "$STATE/update-candidate.json")"
  [ "$candidate_record_sha" = "$actual_record_sha" ] \
    || die "candidate record changed after staging"
  expected_parent="$(jq -r '.parent_receipt_sha256' "$STATE/update-candidate.json")"
  actual_parent="$(last_verified_receipt_digest)"
  [ "$expected_parent" = "$actual_parent" ] \
    || die "verified generation lineage changed since candidate staging"
  expected_running="$(jq -r '.staged_running_system' "$STATE/update-candidate.json")"
  actual_running="$(canonical_system_path)"
  [ "$expected_running" = "$actual_running" ] \
    || die "running generation changed since candidate staging"
  expected_source="$(jq -r '.baseline_source_digest' "$STATE/update-candidate.json")"
  actual_source="$(source_digest)"
  [ "$actual_source" = "$expected_source" ] \
    || die "configuration changed since candidate staging; refusing promotion"

  expected_lock="$(jq -r '.candidate_lock_sha256' "$STATE/update-candidate.json")"
  actual_candidate_lock="$(sha256_file "$STATE/candidate/flake.lock")"
  [ "$expected_lock" = "$actual_candidate_lock" ] \
    || die "candidate lock digest changed after staging"

  old_lock="$(sha256_file "$ROOT/flake.lock")"
  backup="$STATE/flake.lock.pre-promotion"
  cp -a "$ROOT/flake.lock" "$backup"
  install -m 0644 "$STATE/candidate/flake.lock" "$ROOT/flake.lock.new"
  mv -f "$ROOT/flake.lock.new" "$ROOT/flake.lock"

  # Rebuild the exact target from the live source + candidate lock and require
  # the resulting store path to match the system we staged. This catches any
  # source/candidate drift that a lock digest alone cannot express.
  local expected_system actual_system
  expected_system="$(jq -r '.candidate_system' "$STATE/update-candidate.json")"
  actual_system="$("${NIX[@]}" build --no-link --print-out-paths --no-write-lock-file \
    "path:$ROOT#nixosConfigurations.$HOST.config.system.build.toplevel")"
  if [ "$actual_system" != "$expected_system" ]; then
    log "candidate system identity changed during promotion; restoring previous lock"
    install -m 0644 "$backup" "$ROOT/flake.lock.restore"
    mv -f "$ROOT/flake.lock.restore" "$ROOT/flake.lock"
    exit 1
  fi

  local live_compatibility_system current_nix_build
  current_nix_build="$(dirname "$(command -v nix)")/nix-build"
  live_compatibility_system="$(build_system_nix "$ROOT" "$current_nix_build")"
  if [ "$live_compatibility_system" != "$expected_system" ]; then
    log "system.nix parity changed during promotion; restoring previous lock"
    install -m 0644 "$backup" "$ROOT/flake.lock.restore"
    mv -f "$ROOT/flake.lock.restore" "$ROOT/flake.lock"
    exit 1
  fi

  if ! "$NIXOS_REBUILD" boot --flake "path:$ROOT#$HOST"; then
    log "candidate promotion failed; restoring previous lock"
    install -m 0644 "$backup" "$ROOT/flake.lock.restore"
    mv -f "$ROOT/flake.lock.restore" "$ROOT/flake.lock"
    exit 1
  fi

  new_source="$(source_digest)"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  receipt="$EVIDENCE/promotion-$(date -u +%Y%m%dT%H%M%SZ).json"
  jq -n \
    --arg now "$now" \
    --arg host "$HOST" \
    --arg old_lock "$old_lock" \
    --arg new_lock "$expected_lock" \
    --arg old_source "$expected_source" \
    --arg new_source "$new_source" \
    --arg previous_system "$actual_running" \
    --arg candidate_system "$(jq -r '.candidate_system' "$STATE/update-candidate.json")" \
    --arg candidate_record_sha "$candidate_record_sha" \
    --arg parent_receipt "$expected_parent" \
    '{
      schema_version: 2,
      kind: "symthaea-update-promotion-v2",
      promoted_at: $now,
      activation: "boot-pending-verification",
      hostname: $host,
      previous_lock_sha256: $old_lock,
      promoted_lock_sha256: $new_lock,
      previous_source_digest: $old_source,
      resulting_source_digest: $new_source,
      previous_system: $previous_system,
      candidate_system: $candidate_system,
      candidate_record_sha256: $candidate_record_sha,
      parent_receipt_sha256: $parent_receipt,
      result: "boot-generation-created-awaiting-reboot"
    }' > "$receipt"

  pending="$PENDING_ACTIVATION"
  jq -n \
    --arg created "$now" \
    --arg host "$HOST" \
    --arg expected_system "$(jq -r '.candidate_system' "$STATE/update-candidate.json")" \
    --arg previous_system "$actual_running" \
    --arg promoted_lock "$expected_lock" \
    --arg source "$new_source" \
    --arg candidate_record_sha "$candidate_record_sha" \
    --arg parent_receipt "$expected_parent" \
    --arg promotion_receipt_sha "$(sha256_file "$receipt")" \
    '{
      schema_version: 1,
      kind: "symthaea-pending-activation-v1",
      created_at: $created,
      hostname: $host,
      expected_system: $expected_system,
      previous_system: $previous_system,
      promoted_lock_sha256: $promoted_lock,
      resulting_source_digest: $source,
      candidate_record_sha256: $candidate_record_sha,
      parent_receipt_sha256: $parent_receipt,
      promotion_receipt_sha256: $promotion_receipt_sha
    }' > "$pending"
  cp "$receipt" "$EVIDENCE/last-promotion.json"
  log "candidate promoted to next-boot generation; verification will finalize lineage after reboot"
}

verify_boot() {
  mkdir -p "$STATE" "$EVIDENCE"
  [ -f "$PENDING_ACTIVATION" ] || return 0

  local expected actual now receipt parent promotion_sha candidate_sha
  expected="$(jq -r '.expected_system' "$PENDING_ACTIVATION")"
  actual="$(canonical_system_path)"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$actual" != "$expected" ]; then
    receipt="$EVIDENCE/activation-failure-$(date -u +%Y%m%dT%H%M%SZ).json"
    jq -n --arg now "$now" --arg host "$HOST" --arg expected "$expected" --arg actual "$actual" \
      '{schema_version:1, kind:"symthaea-update-activation-failure-v1", observed_at:$now, hostname:$host, expected_system:$expected, actual_system:$actual, result:"mismatch"}' \
      > "$receipt"
    die "post-boot verification failed: expected $expected but running $actual"
  fi

  parent="$(jq -r '.parent_receipt_sha256' "$PENDING_ACTIVATION")"
  promotion_sha="$(jq -r '.promotion_receipt_sha256' "$PENDING_ACTIVATION")"
  candidate_sha="$(jq -r '.candidate_record_sha256' "$PENDING_ACTIVATION")"
  receipt="$EVIDENCE/activation-$(date -u +%Y%m%dT%H%M%SZ).json"
  jq -n \
    --arg now "$now" \
    --arg host "$HOST" \
    --arg actual "$actual" \
    --arg previous "$(jq -r '.previous_system' "$PENDING_ACTIVATION")" \
    --arg lock "$(jq -r '.promoted_lock_sha256' "$PENDING_ACTIVATION")" \
    --arg source "$(jq -r '.resulting_source_digest' "$PENDING_ACTIVATION")" \
    --arg parent "$parent" \
    --arg promotion "$promotion_sha" \
    --arg candidate "$candidate_sha" \
    '{
      schema_version: 1,
      kind: "symthaea-update-activation-receipt-v1",
      verified_at: $now,
      hostname: $host,
      previous_system: $previous,
      activated_system: $actual,
      promoted_lock_sha256: $lock,
      resulting_source_digest: $source,
      parent_receipt_sha256: $parent,
      promotion_receipt_sha256: $promotion,
      candidate_record_sha256: $candidate,
      result: "verified-running-generation"
    }' > "$receipt"
  cp "$receipt" "$LAST_ACTIVATION"
  cp "$receipt" "$EVIDENCE/last-update.json"
  sha256_file "$receipt" > "$EVIDENCE/last-activation.sha256"
  rm -f "$PENDING_ACTIVATION"
  rm -rf "$STATE/candidate" "$STATE/update-candidate.json" "$STATE/update-candidate.sha256"
  log "post-boot generation verified; lineage advanced to $(cat "$EVIDENCE/last-activation.sha256")"
}

cycle() {
  stage
  if [ "$PROMOTION" = boot ] && [ -f "$STATE/update-candidate.json" ] \
     && [ "$(jq -r '.status' "$STATE/update-candidate.json")" = ready ]; then
    apply_boot
  fi
}

status() {
  if [ -f "$PENDING_ACTIVATION" ]; then
    printf '%s\n' 'Pending post-boot verification:'
    jq . "$PENDING_ACTIVATION"
    printf '\n'
  fi
  if [ -f "$STATE/update-candidate.json" ]; then
    jq . "$STATE/update-candidate.json"
  elif [ -f "$STATE/last-check.json" ]; then
    jq . "$STATE/last-check.json"
  else
    printf '%s\n' 'No update check has been recorded yet.'
  fi
  if [ -f "$STATE/release-proposal.json" ]; then
    printf '\n%s\n' 'Release migration proposal:'
    jq . "$STATE/release-proposal.json"
  fi
}

case "${1:-cycle}" in
  probe) probe ;;
  stage) stage ;;
  apply|apply-boot) apply_boot ;;
  cycle) cycle ;;
  status) status ;;
  verify-boot) verify_boot ;;
  discover-release) probe; write_release_proposal ;;
  *) die "usage: symthaea-update-steward {probe|stage|apply|cycle|status|verify-boot|discover-release}" ;;
esac
