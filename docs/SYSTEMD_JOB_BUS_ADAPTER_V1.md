# Live systemd job observer v1

Status: **zbus adapter authored behind the optional systemd feature; not compiled or executed here**  
Date: 2026-10-29  
Related: [PR #93](https://github.com/Luminous-Dynamics/nixward/pull/93), [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75)

## Scope

The new module, src/action/systemd_job_bus.rs, implements the manager-level observation path using zbus. It does not launch the privileged worker directly, authorize a change, write the transaction journal itself, validate a worker receipt, or prove the actual NixOS runtime/profile postcondition.

The API is intentionally split so the caller owns journal publication. A caller must durably persist the write-ahead intent before creating a prepared start capability; after the manager reply arrives, it must persist that exact reply before consuming the JobRemoved stream.

## Implemented sequence

1. Construct a non-serializable StartIntent from a transaction ID, unique attempt ID, and worker purpose.
2. Pass its serializable StartIntentEvidence to the caller's durable pre-launch persistence callback. Only success returns PreparedStartIntent, which is the only type accepted by the live adapter.
3. Connect to the system bus and create a proxy for org.freedesktop.systemd1.Manager.
4. Install a JobRemoved signal subscription filtered to the canonical attempt unit, then call Manager.Subscribe(). Failure in either step prevents StartUnit from being called.
5. Invoke StartUnit with the exact derived unit name and mode fail. The adapter records the actual returned object path; it does not invent a numeric job ID.
6. Treat an explicit D-Bus method-error reply as Rejected. Treat other call errors as Unknown because a lost transport reply does not prove the manager did not enqueue the job.
7. Retain the signal stream in SubmittedStart. The caller must call persist_before_observing with the direct StartUnit reply and only then receives PersistedStart.
8. Consume that persisted ticket with a bounded wait for JobRemoved. Correlate the exact path, path-derived ID, unit and result. Unrelated units are skipped; partial identity conflicts hold for reconciliation; timeouts, stream closure, malformed signals and unknown result strings never become transaction success.
9. Preserve raw systemd result text in SystemdStartObservation, even when the result is unknown to this version of the enum.

The typestate chain is:

StartIntent → PreparedStartIntent → SubscribedStart → SubmittedStart → PersistedStart → SystemdStartObservation

This chain constrains in-process call order. It is not a security boundary: the persistence callbacks must actually write the intended journal records, and persisted evidence still requires the repository's integrity, identity and authorization checks.

## Important recovery limits

- StartUnit may have been accepted even when the method reply is lost. The adapter emits Unknown and must not resubmit that attempt.
- If reply persistence fails after StartUnit, the returned failure retains the submitted attempt and live subscription so the caller can retry publication, not the manager request.
- If JobRemoved times out or the stream closes, the result is a hold-for-reconciliation. It is not proof that the unit did not run.
- The in-memory signal stream does not survive a Nixward process crash or machine reboot. A restarted supervisor must reconcile the durable attempt and query the canonical manager unit, then independently inspect runtime/profile state. This adapter does not yet implement restart recovery or a durable event journal.
- Even JobRemoved done proves only systemd start-job completion. The process-exit receipt and host post-state verification are still separate gates.

## Qualification plan

Next, run a disposable NixOS VM with a harmless service whose lifecycle is controlled by the test driver. Capture exact Nixpkgs revision, systemd version, Nixward head SHA, VM config digest, and raw outcomes. Inject:

| Fault | Acceptance condition |
|---|---|
| Subscription registration fails | StartUnit call count remains zero |
| Manager.Subscribe fails | StartUnit call count remains zero |
| Method returns explicit D-Bus error | Rejected is persisted; no automatic retry |
| StartUnit reply is dropped after enqueue | Unknown remains indeterminate; same attempt is not replayed |
| Matching JobRemoved arrives before reply-processing completes | Event remains buffered and is correlated only after the reply is persisted |
| Unrelated unit jobs occur during wait | They do not change the result for this attempt |
| Job ID and object path disagree | Hold for reconciliation |
| JobRemoved reports a non-done result | Start-job non-success, never transaction success |
| Wait times out or the manager connection closes | Hold for reconciliation |
| Reply evidence persistence fails | No wait-stage ticket is produced; the same attempt remains available only for publication retry |
| Supervisor is killed after submission | Restart reconciles durable intent and actual machine state before any new attempt |
| Host reboots during the operation | Old boot-scoped process identity is not reused; runtime/profile are observed independently |

Hard gates: zero false-success claims, zero same-attempt retries after ambiguity, zero accepted ID/path/unit conflicts, and zero start calls before the durable preflight callback succeeds. Run at least 100 injected trials per fault/configuration. Report p50/p95/p99 separately for subscription setup, StartUnit reply, JobRemoved arrival, process receipt, and independent host postcondition. These are proposed qualification thresholds, not measured results.

## Industry comparison

Use the same harmless service, VM configuration, and fault schedule against direct systemd management and the Nixward adapter. Compare false-success, duplicate requests, evidence completeness, safe-hold frequency, resolution time, operator intervention and latency. Do not claim superiority from source-level tests or the count of test vectors; the comparison must use observed outcomes from the same reproducible corpus.

## Execution status

Static source review only. Rust tests/build, rustfmt, Clippy, live D-Bus tests, Nix evaluation, and NixOS VM fault injection have not been run in this environment. The adapter is unqualified until those checks run on the exact PR head.
