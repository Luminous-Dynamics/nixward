# Systemd job evidence adversarial qualification v1

Status: **property-based contract tests authored; not executed**  
Date: 2026-10-29  
Related: [PR #90](https://github.com/Luminous-Dynamics/nixward/pull/90), [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75)

## Research premise

A conventional unit test demonstrates that selected inputs produce expected outputs. It does not, on its own, establish that the implementation is robust to nearby mutations, partial identity collisions, hidden event-order races, or actual manager behavior.

The systemd evidence contract therefore needs three distinct qualification layers:

1. **Pure contract tests** — deterministic examples and property-based mutations of transaction, attempt, unit, job ID, object path, and result.
2. **Live manager tests** — a real systemd D-Bus session/service manager and controlled harmless units, verifying subscription order and event correlation.
3. **NixOS VM fault injection** — a disposable NixOS machine where reply loss, supervisor crash, service failure, and reboot are injected around the durable intent boundary.

These layers answer different questions. Passing one does not establish the guarantees of the next.

## Added property-based tests

The module now uses the repository's existing proptest dev-dependency to add four properties, each configured for 512 generated cases:

- **One-field identity mutation:** alter only the job ID, only the object path, or only the unit name. A partial identity collision must hold for reconciliation, never be accepted as completion and never be discarded as wholly unrelated.
- **Unknown direct reply:** after a lost/unknown StartUnit response, a subsequently presented signal cannot retroactively establish a known acknowledgement. The result remains hold-for-reconciliation.
- **Non-done manager results:** canceled, timeout, failed, dependency, and skipped are never classified as a completed start job.
- **Canonical naming:** generated non-hex identifiers produce a stable unit name with a fixed prefix and exactly 64 lowercase hexadecimal digest characters, without embedding raw identifiers.

The deterministic cases also cover explicit manager rejection, malformed/non-canonical job paths, failed subscription typestate transition, unknown reply, numeric ID/path inconsistency, and exact job/path/unit correlation. Property cases are mutation tests over a pure model; they are not live D-Bus tests and do not prove that the data supplied by a real adapter is authentic.

## Qualification corpus for the eventual adapter

A production D-Bus adapter should expose a small typed boundary that can be independently tested. Capture the exact request identity before the manager call; establish the JobRemoved match and call Manager.Subscribe(); then submit StartUnit and retain the returned job object path. StartUnit's reply is an object path, not a separate numeric job ID. The JobRemoved signal carries the numeric ID, object path, unit name, and result; preserve these values from the same signal and verify the path/ID correspondence rather than joining fields from unrelated events. See the [systemd Manager API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) and [current JobRemoved emission in systemd source](https://github.com/systemd/systemd/blob/main/src/core/dbus-job.c).

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

The four property tests have been added to PR #91's stacked branch. No Rust test, build, formatter, Clippy, D-Bus manager integration, or NixOS VM test has been executed in the present environment. All targets above are proposed acceptance criteria until measured.
