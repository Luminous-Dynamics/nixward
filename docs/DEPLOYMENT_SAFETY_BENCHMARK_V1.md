# NixOS deployment safety benchmark v1

Status: **benchmark protocol and acceptance targets proposed; no comparative measurements have been run**

Date: 2026-10-30

## 1. Positioning: compare like with like

Nixward should not claim to replace the strongest feature of every NixOS deployment tool. The existing tools occupy complementary layers:

| System | Strong baseline | What this benchmark must not assume |
|---|---|---|
| `nixos-rebuild` | Native build / switch / test / boot workflow and generation rollback | That generation selection or successful command exit proves every service or application is healthy |
| `deploy-rs` | Remote flake deployment, multiple profile types, and magic rollback using a post-activation connectivity confirmation | That a connectivity probe proves which process performed a mutation or binds the process to one systemd invocation |
| Colmena | Stateless fleet deployment, node selection/tags, secrets and parallel operations | That fleet-level orchestration is a substitute for per-host process and activation evidence |
| systemd | Unit/job lifecycle, manager-owned invocation identity and PIDFD-based process-to-unit lookup on supported versions | That a job result alone proves the intended NixOS runtime/profile post-state |
| Nixward | Transaction-specific authorization, durable journal, worker identity and planned PIDFD / InvocationID correlation | That the current draft systemd observer is already production-integrated or benchmark-qualified |

Sources and version scope are recorded in the accompanying research references below. The benchmark compares operational outcomes, not marketing feature lists.

The highest-value architecture is compositional: keep Colmena or deploy-rs for fleet scheduling, let NixOS remain the generation/activation substrate, and make Nixward the local transaction/evidence enforcement layer. That is a more credible adoption path than requiring users to discard their existing fleet tool.

## 2. Paradigm shift: a mutation is a distributed transaction

There are at least three independently failing actors:

1. Nixward, which authorizes and records intent;
2. systemd, which accepts a job and creates an invocation;
3. the worker, which performs the host mutation while NixOS and service state may change.

A single boolean `success` cannot represent this lifecycle. The authoritative object should be an append-only, transaction-bound evidence history:

`AuthorizedPlan -> DurableAttemptIntent -> ManagerJob -> InvocationIdentity -> WorkerProcessReceipt -> Runtime/ProfileObservation -> TerminalDisposition`

Each edge must cite the exact predecessor identity. A missing edge yields a hold / reconciliation state, not inferred success.

### Exactly-once is not the v1 promise

A manager call can cross the external side-effect boundary while the caller loses the reply. The caller cannot infer from a timeout or missing receipt that the manager did nothing. Unless the external operation supports a durable idempotency key and deduplicates retries, exactly-once effects cannot be guaranteed by a local journal alone.

Nixward's safe v1 policy is therefore:

- at-most-once submission for one unresolved attempt;
- durable write-ahead attempt identity before StartUnit;
- never mint a second attempt ID merely because the first reply was lost;
- reconcile the exact unit, job, invocation, process and target state;
- hold when evidence is incomplete or contradictory.

A future retry is a new authorized attempt only after the preceding attempt has been conclusively resolved by the journal state machine. This is intentionally more conservative than blind retry.

## 3. Matched systems and workload

Run every system against the same prebuilt immutable NixOS closure and VM fixture:

- **B0 — native:** `nixos-rebuild test`, `switch`, and `boot` as separate outcome classes.
- **B1 — remote safety:** deploy-rs with its default magic-rollback confirmation probe.
- **B2 — fleet orchestration:** Colmena on one host first, then a small multi-host run to measure scheduling separately.
- **B3 — current Nixward:** existing journal-owned direct worker supervision.
- **B4 — Nixward/systemd:** journal-anchored start attempt plus PIDFD / InvocationID observer after the production path is integrated.

Pin NixOS / nixpkgs revision, flake.lock, system closure digest, tool versions, kernel, systemd version, VM resource limits, and the exact source SHA. Use prebuilt closures so build-cache variance does not contaminate activation-supervisor latency. Run at least 30 clean repetitions per non-fault workload and report median, p95, p99, spread and every excluded run with reason.

The initial qualification target is Linux + systemd 253 or newer for `GetUnitByPIDFD`. Older managers must take an explicit unsupported / hold path, not a PID-only fallback.

## 4. Correctness and adversarial benchmarks

The required scorecard is safety-first. A faster result with a false success is a failed benchmark.

| Benchmark | Workload | Acceptance target |
|---|---|---|
| False terminal success | Worker failed, manager says done, profile/runtime unchanged, or evidence conflicts | **0** false terminal successes |
| False no-op inference | Lose StartUnit reply, JobRemoved, worker receipt, or manager connection at each boundary | **0** cases where missing evidence is treated as proof that no mutation occurred |
| Duplicate mutation | Crash / cancel / disconnect at every write and manager boundary, then recover | **0** duplicate submissions for an unresolved attempt |
| Identity attribution | PID reuse, PID namespace mismatch, wrong unit, wrong InvocationID, recycled job ID | **0** foreign worker or invocation accepted |
| Journal integrity | Rewritten transaction ID, attempt ID, unit, purpose, plan digest, missing/extra/duplicate records | **0** mutated records accepted |
| Launch-contract integrity | Mutated gate executable, payload executable/argv, environment digest, or expected pre-release profile | **0** envelope/worker mismatches accepted; **0** caller-selected environments accepted |
| Recovery classification | Exact live, exited, absent, previous boot, unsupported manager, stale and contradictory observations | **0** unsafe resume/rollback decisions |
| Compatibility | v7 journals, direct-spawn receipts, systemd feature disabled, unsupported systemd version | No fabricated attempt identity; legacy direct-spawn receipts retain their original digest |
| Concurrency | Two Nixward clients, external profile writer, lock contention, lock owner crash | No overlapping authorized mutation; conflict is explicitly held |

Fault-injection matrix:

- Inject a crash before and after every journal write, file sync, rename, directory sync and read-back.
- Inject before the D-Bus call, after request delivery, after job creation, after reply delivery and before signal receipt.
- Inject during pidfd lookup, InvocationID property read, worker-gate release, worker exit observation and runtime/profile observation.
- Repeat with systemd manager restart, NixOS activation changing unit state, process exit, PID reuse, cgroup movement and PID namespaces.
- Run at least 100 independent trials per named fault boundary and at least 10,000 deterministic/model-generated state sequences. Publish seeds and exact evidence receipts.

All unsafe outcomes are release blockers. A hold is not a failure of correctness; it is a safe outcome whose frequency and operator resolution time must be measured.

## 5. Performance and operational targets

Measure from a common monotonic clock and separate Nix build time from activation overhead.

| Metric | Measurement | Initial target (proposal, not measured) |
|---|---|---|
| Journal cost | Atomic intent write + read-back, fsync and parent-directory sync | p95 below 100 ms on the qualification VM storage |
| Manager attribution | StartUnit request through exact PIDFD / InvocationID capture | p95 below 250 ms on a local systemd manager |
| Supervisor overhead | Nixward path minus direct worker baseline, excluding Nix build and service convergence | p95 below 5% of baseline activation time |
| Recovery classification | Crash-to-safe-disposition latency | p95 below 2 s when manager and target observations are available |
| Safe automation | Fraction of recoverable cases reaching a proved terminal state without operator intervention | Report by fault class; no aggregate target may hide a dangerous subgroup |
| Evidence completeness | Required fields present and cryptographically / structurally bound at each transition | 100% for every accepted terminal result |

These are starting targets for an initial Linux VM, not universal performance guarantees. Publish the raw distributions; do not tune correctness thresholds to improve latency.

## 6. External comparison and what would constitute a real win

Nixward only demonstrates an advantage if it beats each baseline on the same failure injection and workload:

- Against `nixos-rebuild`: show lower unsafe-outcome rate and better crash reconciliation for the same exact closure transition, not merely a richer journal.
- Against deploy-rs: show that Nixward adds exact process-to-unit/invocation attribution and local transaction recovery beyond an SSH connectivity confirmation, while retaining comparable rollback outcomes.
- Against Colmena: show that Nixward supplies per-node mutation evidence beneath parallel fleet orchestration; do not claim to outperform its scheduling throughput unless tested on the same fleet.
- Against systemd alone: show the missing authorization / transaction / NixOS post-state binding; systemd remains the source for manager-owned job and invocation facts.
- Against Nixward's own direct worker path: demonstrate whether systemd materially improves recovery observability and service ownership without adding unacceptable activation latency or lifecycle complexity.

A publishable claim requires source SHAs, pinned tool versions, VM image digest, test seeds, all raw results, negative controls, and an independently rerunnable verifier. A green CI badge or one successful deployment is not comparative evidence.

## 7. Qualification gates

1. Build and test the optional `systemd` feature with the locked Rust toolchain.
2. Resolve unit materialization and polkit authorization first. The current hash-derived unit has no matching template in `nix/module.nix`. On systemd 253+, the fixed static template + `StartUnit` route supports unit/verb-scoped polkit authorization; transient-unit authorization metadata is only passed from systemd v257 onward. The existing unprivileged Nixward daemon has no module-defined `manage-units` grant.
3. Add a disposable headless NixOS VM test on systemd 253+ that proves a scoped authorization can start only the Nixward template instance, while unrelated start/stop/restart/modify operations are denied. Then test fixed runner identity, unique invocation, post-exit evidence retention and manager-restart behavior.
4. Wire the existing Nixward interlock and transaction capability into the live start path; bind the exact authorized command / worker launch envelope, call the authorization-aware reservation API with the already-verified plan/command capability, then persist and read back the v9 attempt plus immutable launch envelope before manager submission.
5. Persist manager job / InvocationID, worker observation and runtime/profile observations as append-only, linked records.
6. Run the fault corpus and the matched baseline workload; independently validate the result bundle.
7. Only then remove the observer's crate-private / unqualified status.

No performance, superiority, exactly-once or production-readiness claim is made by this protocol itself.

## 8. Research references

- NixOS Manual, changing configuration: `nixos-rebuild switch`, `test`, `boot`, and VM testing: https://nixos.org/manual/nixos/stable/
- NixOS Wiki, `nixos-rebuild` workflow and generation operations: https://wiki.nixos.org/wiki/Nixos-rebuild
- deploy-rs README, multi-profile deployments and magic rollback based on post-activation connectivity confirmation: https://github.com/serokell/deploy-rs
- Colmena unstable manual, deployment configuration and target-side build options: https://colmena.cli.rs/unstable/reference/deployment.html
- systemd 260 D-Bus Manager API, `GetUnitByPIDFD` returns the unit path, unit ID and invocation ID and avoids PID-only lookup: https://www.freedesktop.org/software/systemd/man/260/org.freedesktop.systemd1.html
