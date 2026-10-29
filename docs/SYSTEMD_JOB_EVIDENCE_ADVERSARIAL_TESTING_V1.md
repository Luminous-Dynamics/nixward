# Systemd job evidence adversarial qualification v1

Status: **property-based tests and optional zbus observer authored; no runtime qualification claimed**  
Date: 2026-10-29  
Related: [PR #90](https://github.com/Luminous-Dynamics/nixward/pull/90), [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75)

## Research premise

A conventional unit test demonstrates that selected inputs produce expected outputs. It does not, on its own, establish that the implementation is robust to nearby mutations, partial identity collisions, hidden event-order races, or actual manager behavior.

The repository now has the pure contract, adversarial properties, and an optional zbus observer. These still need three distinct qualification layers:

1. **Pure contract tests** — deterministic examples and property-based mutations of transaction, attempt, unit, job ID, object path, and result.
2. **Live manager tests** — a real systemd D-Bus session/service manager and controlled harmless units, verifying subscription order and event correlation.
3. **NixOS VM fault injection** — a disposable NixOS machine where reply loss, supervisor crash, service failure, and reboot are injected around the durable intent boundary.

These layers answer different questions. Passing one does not establish the guarantees of the next.

## Added property-based tests

The module now uses the repository's existing proptest dev-dependency for five properties, each configured for 512 generated cases (2,560 generated cases per normal run):

- **One-field job identity mutation:** alter only the job ID, only the object path, or only the unit name. A partial identity collision must hold for reconciliation, never be accepted as completion and never be discarded as wholly unrelated.
- **Unknown direct reply:** after a lost/unknown StartUnit response, a subsequently presented signal cannot retroactively establish a known acknowledgement. The result remains hold-for-reconciliation.
- **Non-done and unknown manager results:** canceled, timeout, failed, dependency, skipped, and the forward-compatible unknown result are never classified as completed start jobs.
- **Recovered intent identity mutation:** independently alter transaction ID, attempt ID, purpose or the derived unit name. Recovered write-ahead evidence is rejected unless all four fields bind to the same canonical attempt identity.
- **Canonical naming:** generated non-hex identifiers produce a stable unit name with a fixed prefix and exactly 64 lowercase hexadecimal digest characters, without embedding raw identifiers.

The deterministic cases also cover explicit manager rejection, malformed/non-canonical job paths, failed pre-launch persistence, failed subscription, reply persistence failure, unknown reply, numeric ID/path inconsistency, and exact job/path/unit correlation. The live adapter installs a unit-filtered JobRemoved match before Manager.Subscribe() and StartUnit. Property cases are mutation tests over a pure model; they are not live D-Bus tests and do not prove that the data supplied by a real adapter is authentic.

## Qualification corpus for the eventual adapter

The new optional adapter provides the first live boundary but is not runtime-qualified. The caller must persist the exact pre-launch intent first; the adapter then establishes a unit-filtered JobRemoved match, calls Manager.Subscribe(), submits StartUnit once, and retains the returned job object path alongside the live signal stream. If the direct reply is unknown but the stream remains live, a matching JobRemoved signal is retained as supplemental evidence but stays hold-for-reconciliation. The caller's reply-persistence callback must succeed before the wait API consumes that stream. StartUnit's reply is an object path, not a separate numeric job ID. The JobRemoved signal carries the numeric ID, object path, unit name, and result; preserve these values from the same signal and verify the path/ID correspondence rather than joining fields from unrelated events. See the [systemd Manager API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) and [current JobRemoved emission in systemd source](https://github.com/systemd/systemd/blob/main/src/core/dbus-job.c).

A dedicated `checks.systemd-job-bus-live-vm` flake check and `pkgs.testers.runNixOSTest` harness are now authored on the follow-up branch. The harness installs a harmless `nixward-transaction@.service` template and runs one `#[ignore]` live-manager test inside the disposable VM. Its persistence callbacks are test no-ops: it qualifies only real D-Bus request ordering, manager reply shape, and JobRemoved ID/path/unit/result correlation. It does not qualify journal durability or production authorization.

Minimum live cases:

| Scenario | Required classification |
|---|---|
| Exact acknowledged job returns done | Start-job completed only |
| Exact acknowledged job returns canceled/timeout/failed/dependency/skipped | Start-job non-success |
| Unrelated job ID, path, and unit | Ignore and continue waiting |
| One field matches expected identity but others disagree | Hold for reconciliation |
| Start request reply is lost | Ambiguous; do not resubmit same attempt |
| Subscription fails or cannot be confirmed before request | Do not submit |
| Matching event arrives before the request returns | Buffer and correlate only after the returned path is known; no early success |
| Duplicate JobRemoved signal | Idempotently preserve one exact terminal manager event; flag contradictory duplicate |
| D-Bus disconnect after enqueue | Persist indeterminate state, reconnect and reconcile the canonical unit/path before any new attempt |
| Supervisor killed at every boundary | Restart reads durable intent and current manager state before deciding |
| Host reboot during one-shot operation | Treat old process identity as boot-scoped and verify actual running closure/profile separately |

The correlation contract must not be used as the sole journal or retry policy. A manager result is one evidence record in the transaction, not a decision to re-run work.

## Metrics and acceptance gates

Report every metric with exact commit SHA, pinned Nixpkgs revision, systemd version, VM configuration digest, fixture digest, kernel version, trial count, and raw per-trial classifications.

| Metric | Initial gate or report |
|---|---:|
| False completed-start claims under identity mutations | 0 |
| Same-attempt resubmission after unknown manager reply | 0 |
| Acceptance of foreign/conflicting job identity | 0 |
| False claims of transaction/activation success from manager result alone | 0 |
| Required evidence checkpoints omitted | 0 |
| Per-configuration trials for each injected fault | At least 100 |
| Property-based generated cases per property | 512 in this initial slice |
| Manager subscription-to-response latency | p50/p95/p99 |
| Response-to-matching JobRemoved latency | p50/p95/p99 |
| Job completion-to-worker receipt latency | p50/p95/p99 |
| Worker receipt-to-independent target observation latency | p50/p95/p99 |
| Safe hold frequency and operator intervention | Report separately; do not label a safe hold as success |

Security/safety gates are hard constraints. Do not trade false success or replay safety for availability or latency. A higher safe-hold rate may indicate limited recoverability rather than incorrectness; report it alongside time-to-resolution and operator workload.

## Comparing with industry

Build a reproducible harness that presents the same declarative change and same fault schedule to:
- a minimal direct systemd control baseline;
- NixOS rebuild/deployment workflows appropriate for the same host topology;
- Nixward with the full intended evidence chain.

Do not compare unlike features or infer superiority from the number of test cases. Compare post-state correctness, duplicate mutation rate, false success, safe holds, evidence completeness, recovery time, operator intervention, and deployment latency over matched trials. Capture the unmodified baseline command, config, and version so improvements are independently reproducible.

NixOS VM integration tests are the natural next step because they provide declarative virtual machine definitions and a QEMU-backed test driver. This document records the qualification plan; it does not claim that a VM test has been implemented or executed.

## Execution status

Four original properties are in PR #91's stack; PR #94 adds the fifth recovered-intent identity-mutation property. PR #95 authors the live-manager round-trip test and NixOS VM harness, but neither has been built or run here. No Rust test/build, formatter, Clippy, live D-Bus manager integration, Nix evaluation, or NixOS VM test has been executed in this environment. All targets above are proposed acceptance criteria until measured.
