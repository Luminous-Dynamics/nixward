# Deployment assurance benchmark targets v1

Status: **proposed qualification targets; no benchmark results are claimed**

This document defines how Nixward should compete with the NixOS deployment ecosystem. Targets below are hypotheses for a reproducible qualification programme, not measured results or release gates until validated on pinned hardware and workloads.

## Strategic positioning

Nixward should not try to win by reimplementing every deployment feature. It should provide a stronger assurance envelope around the systems that already build, schedule, activate and supervise NixOS.

| Existing system | What it already does well | Correct comparison boundary |
|---|---|---|
| `nixos-rebuild` / `switch-to-configuration` | Native local build and activation; `switch`, `test`, and `boot` have distinct semantics. `switch` activates and selects a boot default; `test` activates without changing the boot default; `boot` changes the boot default without activating the running system. | Match the exact operation mode and prebuilt closure. Never compare `test` with `switch` as if equivalent. |
| Colmena | Parallel evaluation/build/deployment for fleets; its documented default deployment limit is 10 hosts, configurable with `--limit`. | Measure fleet scheduling and convergence separately from single-host activation. Nixward must not claim a fleet throughput win until it has equivalent scheduler semantics. |
| deploy-rs | Multi-profile deployment, automatic rollback after activation failure, and `magicRollback` connectivity confirmation are established features; its documented defaults enable `autoRollback` and `magicRollback`. | Preserve and record rollback settings. Compare rollback correctness, remote reachability and recovery evidence—not only deploy-command duration. |
| systemd | D-Bus job lifecycle and result signals; `GetUnitByPIDFD` can bind a pidfd to unit and invocation identity, avoiding PID-reuse ambiguity. `JobRemoved` includes job identity and result. | Use exact job ID, unit name, InvocationID and pidfd attribution. Subscribe to `JobRemoved` before `StartUnit` and filter by the returned job. A signal or PID alone is not a terminal proof. |
| SQLite WAL | Atomic local transactions and concurrent readers; WAL still permits only one writer and is same-host only. Checkpoint work can make occasional commits slower; long-lived readers can delay checkpoint completion and grow the WAL. | Keep the admission store local to one supervisor host. Benchmark `synchronous=FULL`, commit/read-back latency, checkpoint tails and WAL high-water; do not compare it as a fleet database. |

Primary references:
- NixOS Manual, changing configuration: https://nixos.org/manual/nixos/stable/
- NixOS switch internals: https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/what-happens-during-a-system-switch.chapter.md
- Colmena parallelism: https://colmena.cli.rs/unstable/features/parallelism.html
- deploy-rs rollback and magic rollback: https://github.com/serokell/deploy-rs/blob/master/README.md
- systemd 262 D-Bus API: https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html
- SQLite WAL: https://www.sqlite.org/wal.html
- SQLite synchronous modes: https://www.sqlite.org/pragma.html#pragma_synchronous

## Research thesis: transaction assurance, not command wrapping

The proposed Nixward differentiator is a transaction protocol that binds:

1. the exact plan, target machine and immutable closure;
2. a verifier-minted authority receipt and root-managed policy epoch;
3. one atomic durable admission identity spanning replay consumption, permit, attempt reservation and journal event;
4. a one-shot dispatch barrier and exact systemd job/unit/InvocationID/pidfd worker identity;
5. durable lifecycle receipts and independently observed runtime/profile postconditions;
6. a terminal outcome that is either verified success, verified recovery, or explicit safe hold.

The transaction state must distinguish *prepared*, *authorized*, *admitted*, *dispatch submitted*, *worker attributed*, *payload released*, *observed*, *reconciled* and *finalized*. A missing acknowledgement must never authorize a second mutation. A rollback command succeeding is not proof that the predecessor is active. A systemd job completing is not proof that the expected NixOS profile and runtime are active.

The current PR stack implements parts of this model—reference admission state, a SQLite store prototype, strict authority decoding, and provenance receipts. It does not yet provide a qualified privileged supervisor or a complete execution/recovery path. The thesis remains a testable research direction, not an achieved product capability.

## Qualification tiers

### Tier 0 — deterministic safety gates

Every negative-control vector must produce the expected rejection, reconciliation or hold. Require zero:
- false terminal successes;
- unauthorized, expired, revoked or replayed admissions;
- duplicate mutation submissions for an unresolved attempt;
- foreign transaction/attempt/worker/invocation attribution;
- payload release before durable admission and durable worker identity.

A correct safe hold is a safe outcome but is not counted as successful recovery. The independent verifier must derive terminal classification from raw evidence instead of trusting the runner's summary.

### Tier 1 — engineering screen

The current corpus floors—30 clean/performance trials and 100 fault/concurrency/storage trials—are suitable for finding regressions and plumbing failures. They are not strong evidence of very low failure probabilities and are not sufficient for a high-assurance claim.

For zero observed failures in (n) independent Bernoulli trials, the one-sided 95% upper confidence bound is (1 - 0.05^{1/n}), approximately the rule-of-three (3/n):

| Trials, zero observed failures | 95% upper bound on failure probability |
|---:|---:|
| 100 | 2.95% |
| 1,000 | 0.299% |
| 10,000 | 0.0300% |
| 30,000 | 0.0100% |

This calculation assumes independent, identically distributed trials. Repeated runs on one VM are correlated; vary and block by kernel, systemd version, filesystem, storage device, VM image, fault timing and host. Report the actual trial design and use clustered or stratified analysis where appropriate. Zero observed failures is not proof of zero risk.

### Tier 2 — release-candidate assurance

Before any privileged release path:
- run at least 1,000 injected trials per critical fault family as an engineering release screen, with zero false release/duplicate dispatch/foreign attribution;
- run at least 10,000 trials for each highest-risk state transition before making a quantified reliability claim;
- include process SIGKILL at every durable boundary, supervisor restart, manager restart, VM reboot, lost D-Bus reply, reordered/dropped JobRemoved, policy epoch change, emergency revocation, expiry and storage fault;
- demonstrate deterministic replay against an independent reference model plus actual disposable-VM evidence;
- preserve every failed and excluded trial with its reason; do not discard inconvenient outliers.

For a target below 0.01% under the same independence assumptions, 30,000 zero-failure trials are a statistical starting point—not a substitute for threat modelling, formal reasoning or adversarial tests.

## Performance targets to test

Use prebuilt identical closures for activation comparisons. Separate build, copy, admission, fsync/read-back, D-Bus submission, manager job duration, worker execution, post-state verification and recovery. Report p50, p95, p99 and maximum, plus CPU, peak RSS, disk writes, sync count, WAL high-water, checkpoint duration and bytes transferred.

| Dimension | Proposed target | How to measure |
|---|---|---|
| Admission commit | p95 ≤ 25 ms and p99 ≤ 100 ms on a pinned local NVMe test host with WAL + `synchronous=FULL`; report hardware and filesystem instead of generalizing the number. | Same transaction shape; commit plus joined four-record read-back. No relaxed durability mode. |
| Supervisor overhead | p95 ≤ 5% and p99 ≤ 10% additional wall-clock time over an equivalent direct activation for the same already-built closure. | Paired randomized trials, same VM snapshot and activation operation, exclude build/copy from activation overhead and report them separately. |
| Lost-ack recovery | 100% of tested ambiguous submissions reconcile to the original attempt or safe hold; zero second StartUnit for the unresolved attempt. | Drop method reply after manager acceptance, restart the supervisor, query by exact job/unit identity and inspect the durable journal. |
| Terminal correctness | Zero false success and zero release-before-authorization/identity events at every tier. | Independent semantic verifier over raw D-Bus, pidfd, receipt, journal, Nix profile and running-system evidence. |
| Recovery quality | Report verified recovery rate, safe-hold rate, operator-intervention rate and time-to-known-state separately. | Fault matrix; do not combine safe hold with successful recovery. |
| Storage reliability | No lost committed admission under tested process/VM crashes; explicit read-back-uncertain state on ambiguous commit acknowledgement. | Local filesystem/SQLite version matrix, process kill, VM reset, WAL checkpoint and backup/restore tests. Power-loss claims require actual power-loss or validated storage fault testing. |
| Fleet operations | No Nixward throughput claim until scheduler parity; then test 1/5/10/50/100 nodes and concurrency limits. | Compare equal closure, host count, cache, network, rollout policy and failure budget. Report fleet convergence p50/p95/p99 and blast radius. |

These are initial engineering targets. If a target is not met, report the measured distribution and the bottleneck; do not weaken safety or durability to make the latency number look better. The thresholds should be revised only with published test data and an explicit trade-off review.

## Benchmark methodology

1. **Matched inputs:** same Nixpkgs revision, flake lock, source commit, closure digest, VM image, kernel, systemd, filesystem, storage cache policy, network profile and cache state.
2. **Randomized paired trials:** alternate baseline order to reduce thermal/cache/order bias. Reuse the same fault seed and trial index across comparable baselines.
3. **Separate semantic modes:** local `switch`, `test`, `boot`; remote deployment; admission-only; storage-only; systemd-supervised. Do not aggregate unlike operations.
4. **Report complete distributions:** p50/p95/p99/max, confidence intervals, warm/cold splits and all exclusions. At 30 runs, do not advertise a stable p99.
5. **Measure outcome quality:** cost per *independently verified terminal outcome*, not cost per successful command exit. A safe hold is not successful recovery.
6. **Preserve provenance:** raw logs, D-Bus event captures, pidfd/start tuple, InvocationID/job IDs, journal snapshots, profile symlink observations, runtime state, fault seeds, exact software versions and hashes.
7. **Independent analysis:** the runner emits evidence; a separate verifier recomputes hashes and scenario classification; a third reviewer can replay the raw evidence offline.
8. **No hidden exclusions:** retain aborted, timed-out, crash and anomalous trials. Pre-register exclusion rules.

## What "better than industry" should mean

Nixward should earn superiority in a narrow, independently measurable domain before making broad claims:

- **Stronger transaction correctness:** one durable admission identity and fail-closed ambiguous submission semantics.
- **Stronger attribution:** exact unit/job/InvocationID and pidfd identity, not PID or process exit alone.
- **Stronger recovery evidence:** verified predecessor/candidate post-state, not merely rollback command success or a connectivity probe.
- **Stronger auditability:** portable, hash-checked, replayable evidence bundles with policy provenance.
- **Competitive overhead:** add that assurance without materially degrading matched activation latency and resource use.
- **Honest fleet comparison:** use Colmena/deploy-rs for their scheduler/remote-deploy strengths until Nixward has equivalent capabilities.

A result is a genuine advantage only when a third party can reproduce it from pinned sources and raw trial artifacts. Until then, call it a proposed target or hypothesis—not SOTA.
