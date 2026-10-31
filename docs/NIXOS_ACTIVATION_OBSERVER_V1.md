# NixOS activation observer and proof-carrying activation v1

Status: **pure Rust evidence model authored; no NixOS command dispatch or privileged host integration**

## Why a separate observer

NixOS activation is not one indivisible transaction. The `switch`, `test`, `boot` and `dry-activate` modes have different postconditions. The official NixOS workflow delegates to `switch-to-configuration`, which performs an ordered sequence of system and service operations. Therefore a process exit code is not enough to prove that the intended system state was reached, and restoring one service is not proof that the entire generation switch was rolled back.

The model introduces a versioned, append-only activation trace. It records the immutable plan, pre-state, inhibitor decision, activation program digest, planned steps, step receipts, boot IDs, systemd unit/InvocationID identity and a post-state snapshot. An in-flight step whose result is ambiguous becomes `unknown`; it cannot silently become successful after restart. A new boot ID requires an explicit reconciliation receipt before further steps can be considered ordered.

## Mode-specific postconditions

| NixOS mode | Required running generation after operation | Required boot-default generation |
|---|---|---|
| `switch` | target | target |
| `test` | target | unchanged from pre-state |
| `boot` | unchanged from pre-state | target |
| `dry-activate` | unchanged from pre-state | unchanged from pre-state |

A `boot` activation can be verified as “the boot default was selected” while the current running OS remains unchanged. This model does not claim that the next reboot into that target has succeeded; that requires a later boot observation with a new boot ID and its own reconciliation record.

## Inhibitors and bypass

The plan records the compared old/new inhibitor-value digests, the changed-name digest, the number of checked inhibitors, and the disposition. A blocked preflight rejects the plan. A bypass is never inferred from a successful command: it requires both policy permission and a separate authorization digest, and the mechanism is recorded explicitly as `NIXOS_NO_CHECK=1`. A bypassed activation returns the distinct outcome `verified_with_inhibitor_bypass`, never an unqualified `verified`.

## Step receipts and uncertainty

- Every planned step has a stable ID and semantic kind.
- The first two steps are inhibitor checking and closure validation; the dispatch/preview follows; the final step is a post-state probe.
- Each step must start before it can complete, fail or become unknown. Planned order cannot be skipped.
- Completed step receipts are immutable. Failed/unknown states require explicit reconciliation or compensation evidence; compensation is not reported as success.
- Monotonic timestamps are compared only within the same kernel boot ID. A reboot may reset monotonic time, but the first event in the new boot must be an explicit reconciliation transition.
- Unit-related steps require a unit name. A successful completion requires the exact systemd `InvocationID`; a PIDFD-derived identity digest is also recorded when the systemd version exposes the relevant API.
- The final post-state probe must match the supplied host snapshot digest and current boot ID.

The model stores only digests and identifiers, not raw logs. A trusted evidence-ingress component must retain and authenticate the underlying journal, D-Bus/PIDFD, closure and host-state observations. A hash is an integrity link, not proof of origin.

## Compatibility strategy for NixOS 26.11

NixOS 26.05 release notes mark activation-script service reload/restart functions deprecated for removal in 26.11. The observer therefore does not require activation scripts to report restarts through those hooks. It treats the version-pinned `switch-to-configuration` program as the dispatch boundary and records actual observed effects from an external observer.

The 26.11 target is a versioned adapter that:
1. captures `nixos-version`, the exact `switch-to-configuration` executable digest, the activation semantics revision, kernel/systemd versions and boot ID;
2. performs inhibitor/preflight observation before any activation bytes are dispatched;
3. records each observed step and systemd unit identity independently of deprecated activation-script callbacks;
4. probes both running and boot-default generation pointers after the operation;
5. refuses unknown activation semantics rather than guessing a postcondition.

The current module is only the state model. It deliberately does not call `nixos-rebuild`, `switch-to-configuration`, systemd D-Bus, or a privileged helper.

## Industry comparison and intended position

| System | Strong capability | What Nixward should add rather than replace |
|---|---|---|
| NixOS | Declarative generations and native activation semantics | An independent receipt chain for preflight, each step, and exact host post-state |
| Colmena | Parallel fleet deployment, evaluation and activation | Local transaction assurance and evidence correlation; do not benchmark the local observer as a fleet scheduler |
| deploy-rs | Remote profile deployment and connectivity-triggered magic rollback | Exact per-step evidence and local host-state verification; a connectivity confirmation is not a complete state proof |
| systemd | Unit lifecycle, InvocationID and PIDFD-based unit identity APIs | Bind lifecycle evidence to the Nix generation, authority, plan and post-state |
| SLSA / in-toto | Build/source provenance and signed attestations | Carry those attestations into the local deployment receipt chain; do not invent a competing provenance format |

The architecture is **proof-carrying activation**:

`SLSA/in-toto build evidence -> exact Nix closure -> authority receipt -> inhibitor preflight -> mode-bound activation plan -> append-only step receipts -> PIDFD/InvocationID-bound service evidence -> post-state probe -> independent resolution`.

This complements NixOS, Colmena and deploy-rs. It is not a replacement orchestrator.

## Benchmark programme

Hard correctness targets:
- zero false verified resolutions;
- zero transitions from unknown directly to success without reconciliation evidence;
- zero mode/postcondition mismatches;
- zero mutation under `dry-activate`;
- zero boot-default mutations under `test`;
- zero running-system mutations under `boot`;
- every systemd completion tied to an exact unit and InvocationID;
- every inhibitor bypass explicitly authorized and separately reported.

Trial floors: 30 clean runs per mode, 100 trials for each injected failure/reboot boundary, and 1,000 observations per population before a p99 claim. Preserve all raw traces, excluded trials and reasons, exact source/flake SHAs, NixOS release, activation binary digest, kernel/systemd versions, boot ID, closure digest and storage details.

Measure:
- per-step dispatch/receipt latency and end-to-end convergence separately;
- number of unknown transitions and operator reconciliations;
- recovery time after supervisor crash, unit restart, daemon-reexec and host reboot;
- false-positive post-state verification rate;
- observer CPU/memory and trace-append overhead.

Initial engineering targets, not measured results: observer append p95 <2 ms and p99 <10 ms for ordinary step receipts; post-state verification p95 <10 ms excluding the host probes themselves. Do not weaken event ordering, receipt binding or postcondition checks to meet latency targets.

## Validation status

The module currently contains 18 deterministic Rust unit tests. They cover switch/test/boot/dry-activate postconditions, inhibitor block/bypass, ordered step transitions, boot-ID changes, monotonic-clock reset on reconciliation, systemd InvocationID identity, compensation safe-hold and trace digest stability. Tests and the focused Nix target are authored but not executed in this environment.
