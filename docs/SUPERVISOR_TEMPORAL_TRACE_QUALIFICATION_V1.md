# Supervisor temporal trace qualification v1

Status: **pure policy/trace validator; not production recovery integration or an executed qualification result**  
Date: 2026-10-29  
Related: [PR #87](https://github.com/Luminous-Dynamics/nixward/pull/87), [PR #86](https://github.com/Luminous-Dynamics/nixward/pull/86), [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75)

## Why this increment exists

A decision table answers, “Given this snapshot of worker identity, receipt, and target state, what is the conservative next step?” It does not fully answer, “Could an unsafe sequence of individually plausible events still produce a false success?”

This module adds a separate temporal layer in `src/action/transaction_supervision_trace.rs`. It validates one event trace bound to one expected transaction ID and one expected start-attempt ID. It is pure Rust and has no host-mutating behavior.

## Invariants checked

The trace validator classifies every trace as one of three explicit dispositions: **Rejected**, **Incomplete**, or **ValidatedTerminalSuccess**. A prefix with no violation is only Incomplete until the terminal-success proof is complete; callers must not use a Boolean “safe” result as a synonym for successful execution.

The trace validator rejects:

- a manager start submitted before the write-ahead submission barrier;
- a second manager start submission under the same attempt ID;
- repeated one-shot milestones within the same attempt (authorization verification, attempt preparation, write-ahead barrier, worker identity observation/persistence, payload exit, or lifecycle validation without a newer target observation). Repeated target observations remain admissible and invalidate prior lifecycle validation.
- worker identity being persisted before observation, or payload release before authorization and durable worker identity;
- duplicate payload release or duplicate process-receipt publication;
- payload exit reported before payload release, or a receipt reported before payload exit / durable identity;
- evidence events carrying a transaction or attempt ID different from the caller-supplied identities;
- terminal success without a durable process receipt, a post-receipt candidate runtime-and-profile observation, and lifecycle postcondition validation;
- a later target observation that invalidates an earlier lifecycle validation, or any event appended after a terminal-success claim.

The expected transaction and attempt IDs must come from an already-validated durable journal. The validator does **not** authenticate event provenance, verify receipt signatures/digests, validate systemd D-Bus responses, establish that target observations are true, or check authorization cryptography. Those remain prerequisites of the caller.

## Temporal contract

For the successful path represented by the checker, the required order is:

1. Verify authorization for the exact plan.
2. Durably prepare the unique attempt and exact worker intent.
3. Persist the write-ahead barrier that submission may have occurred.
4. Submit the manager start request exactly once for this attempt.
5. Observe and durably persist the matching worker invocation identity.
6. Release the exact payload only after the authority and identity prerequisites hold.
7. Observe payload exit and durably publish a receipt bound to the persisted worker identity.
8. Perform a fresh read-only target observation after the receipt is published.
9. Validate the target state against the transaction's requested lifecycle operation.
10. Record terminal success only after every prerequisite above.

An incomplete trace can be safe so far. For example, the start request might have been submitted and then its response lost; the trace is not a success, and a caller must use the existing start-recovery decision contract. The trace checker itself does not authorize a retry or make an attempt safe to repeat. A different attempt requires the existing cross-attempt reconciliation and authorization rules.

The target observation used for terminal success must come after payload exit **and** receipt publication. An earlier observation is not promoted into qualifying evidence just because a receipt appears later. A subsequent target observation resets lifecycle validation; the newest candidate state must be validated again.

## Tests added

The Rust unit tests cover:

- a valid, fully evidenced success trace;
- a duplicate manager start;
- submission before the durable write-ahead barrier;
- payload release before worker identity durability;
- a target snapshot taken before worker exit not satisfying terminal success;
- a later mixed/unknown target observation invalidating prior candidate validation;
- event rebinding to a different attempt ID;
- a safe but incomplete trace after an ambiguous manager submission, explicitly classified as Incomplete rather than success;
- rejection of all ten one-shot milestone types when repeated in the same attempt, while allowing a new lifecycle validation only after a newer target observation;
- all **5,040 permutations** of seven critical start/release events, asserting that only the required ordering passes the ordering contract;
- **20,000 deterministic generated traces** across the event alphabet, event identities, and target observations, with an independent causal-order oracle for any accepted success trace;
- **20,000 deterministic mutation trials** of a known-valid success trace: 2,000 valid-trace controls and 18,000 mutated trials covering required-evidence deletion, identity rebinding, duplicate manager start, stale/contradictory target observations, and events after terminal success.

The 5,040-case check is exhaustive only for those seven event orderings. The generated checks are bounded deterministic test campaigns, not a proof over arbitrary-length traces, a concurrency proof, or an operating-system fault-injection campaign. The tests are authored but have not been executed in this environment; do not interpret their presence as test results.

## Next qualification gates

1. Compile and run the module tests at the exact commit; run formatting, Clippy, and the repository's locked-feature matrix.
2. Upgrade the deterministic trace generator to shrinking property-based strategies (the repository already declares Proptest as a dev dependency), and systematically enumerate unsafe terminal-success prefixes. Consider Loom for in-process concurrent coordination only if the integrated Rust synchronization layer can be modeled; Loom is not a substitute for systemd or VM crash testing.
3. Integrate the validator into the actual recovery path only after event provenance and journal binding are represented by trusted types. Do not let caller-created enums stand in for verified evidence.
4. Inject failures at every persistence and manager-call boundary, and run on disposable NixOS VMs: lost D-Bus response, supervisor SIGKILL, receipt write/fsync failure, worker stop, daemon restart, and host reboot.
5. Retain a replayable evidence bundle for every case: exact source SHA, lockfile/flake digest, kernel and systemd versions, fixture seed, ordered event log, journal/receipt digests, fault checkpoint, and independent before/after target observations.

## Non-compensatory acceptance metrics

| Measure | Proposed qualification target |
|---|---:|
| Unsafe event orderings accepted by the canonical trace suite | 0 |
| Duplicate manager start accepted for one attempt | 0 |
| Duplicate one-shot milestone event accepted within one attempt | 0 |
| Payload releases missing exact authorization or durable worker identity | 0 |
| Success claims missing receipt, fresh candidate state, or lifecycle validation | 0 |
| Trace events accepted from another transaction/attempt identity | 0 |
| False terminal success in deterministic and randomized fault-injection campaigns | 0 |
| Critical seven-event permutations checked by the authored bounded test | 5,040 |
| Deterministic generated traces checked by the authored oracle | 20,000 |
| Deterministic required-evidence mutation trials | 20,000 |
| Required-evidence removal/rebinding mutations rejected in the canonical mutation suite | 100% |
| Randomized trials per interruption checkpoint after deterministic tests stabilize | >= 100 |

These are proposed acceptance targets, not measured results. Safety gates are not averaged with latency or task-success scores.

## Industry comparison

Compare the eventual integrated Nixward protocol against `nixos-rebuild` and Colmena using the same disposable host image, NixOS release, tasks, cache/network conditions, and injected failures. Keep separate outcomes for task success, mutation replay, false-success claims, recovery time, operator effort, and latency percentiles. A safer protocol may deliberately refuse an ambiguous operation; report that loss of availability separately instead of hiding it inside a single aggregate score.

The current PR does not implement the systemd-owned privileged worker, wire this trace validator into production recovery, or qualify a NixOS VM. It is an independently reviewable safety contract intended to make temporal invariants executable before integration.

## Canonical event semantics and remaining gap

The result API intentionally avoids a single safe/success Boolean: an incomplete but non-violating trace is distinct from a rejected trace and from a fully validated terminal-success claim. The trace checker remains a policy contract; it cannot by itself authorize a mutation, permit retry, or prove that the supplied evidence is authentic.


This validator treats the milestones above as one-shot protocol transitions within a single worker-start attempt, not as a raw append-only telemetry stream. Because `TraceEvent` currently has no globally unique event ID or durable sequence number, identical repeated milestone records are rejected rather than assumed to be harmless redeliveries. If the production event transport needs at-least-once delivery, add a durable event identity and an explicit deduplication contract before allowing idempotent redelivery. Do not silently weaken the duplicate-event gate.

Repeated `TargetObserved` events are different: each is a new observation of machine state, and a later observation invalidates lifecycle validation against an earlier one. This avoids treating a stale candidate snapshot as a permanent proof.


## External engineering references

These sources inform the qualification strategy; none establishes that Nixward is already safer or faster than the referenced deployment tools.

- [systemd D-Bus manager interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html): a successful start call enqueues a job, and observing the job result requires subscribing to the relevant signal before the request and filtering by the returned job object. Transient units may be released when no longer running/referenced or after reboot.
- [NixOS VM integration testing](https://nix.dev/tutorials/nixos/integration-testing-using-virtual-machines.html): reproducible one- and multi-machine tests using pinned NixOS configurations and QEMU. Use this for service-manager integration and crash/reboot fault injection rather than treating pure Rust tests as system qualification.
- [Proptest](https://proptest-rs.github.io/proptest/): property-based generation with shrinking. Upgrade the deterministic trace campaign to shrinking strategies so a failing random trace can be reduced to a minimal reproducer.
- [Loom](https://github.com/tokio-rs/loom): explores interleavings of concurrent Rust executions under a modeled memory model. Use only for suitable in-process synchronization logic; it does not model external systemd state, journal fsync behavior, or actual NixOS reboot semantics.
- [DORA delivery metrics](https://dora.dev/guides/dora-metrics/): use delivery and recovery outcomes longitudinally, with the same application/task context, rather than a single score to rank dissimilar tools.

## Comparison protocol

For every baseline—Nixward, `nixos-rebuild`, and Colmena where the same task applies—pin hardware or VM resource allocation, NixOS/systemd/kernel versions, target configuration, closure/cache state, network conditions, and fault checkpoints. Publish per-scenario raw outcomes and all deviations. Separate (a) safety failures, (b) availability/safe refusal, (c) task utility, (d) recovery and operator effort, and (e) latency. Never allow speed or task completion to compensate for one unauthorized mutation or false-success claim.
