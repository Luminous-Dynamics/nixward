# Live systemd job observer v1

Status: **crate-private zbus adapter authored behind the optional systemd feature; not compiled or executed here**  
Date: 2026-10-29  
Related: [PR #93](https://github.com/Luminous-Dynamics/nixward/pull/93), [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75)

## Scope

The crate-private module src/action/systemd_job_bus.rs implements the manager submission/observation path using zbus. It performs a mutating StartUnit request and is deliberately not wired to a production caller. It must remain uncalled until the existing authorized transaction template, canonical unit definition, cross-process journal interlock, crash-reconciliation path, and disposable-VM qualification are integrated. It does not launch or qualify the privileged worker, authorize a change, write the transaction journal itself, validate a worker receipt, or prove the actual NixOS runtime/profile postcondition.

The API is intentionally split so the caller owns journal publication. A caller must durably persist the write-ahead intent before creating a prepared start capability; after the manager reply arrives, it must persist that exact reply before consuming the JobRemoved stream.

## Implemented sequence

1. Construct a non-serializable StartIntent from a transaction ID, unique attempt ID, and worker purpose.
2. Pass its serializable StartIntentEvidence to the caller's durable pre-launch persistence callback. Only success returns PreparedStartIntent, which is the only type accepted by the live adapter. When a write-ahead record is recovered after process restart, first validate the journal and authorization context independently; then call validate_start_intent_evidence_against with the transaction ID, attempt ID and purpose read from that trusted context. The structural-only validate_start_intent_evidence check is insufficient by itself because a coherently rewritten tuple can recompute its own canonical unit name.
3. Connect to the system bus and create a proxy for org.freedesktop.systemd1.Manager.
4. Install a JobRemoved signal subscription filtered to the canonical attempt unit, then call Manager.Subscribe(). Failure in either step prevents StartUnit from being called.
5. Invoke StartUnit with the exact derived unit name and mode fail. The adapter records the actual returned object path; it does not invent a numeric job ID.
6. Treat a zbus non-FDO MethodError reply as Rejected and preserve its D-Bus error name. Treat other errors, including generic/FDO-wrapped failures, as Unknown because this slice does not yet normalize their error names and a transport failure may follow enqueue.
7. Retain the signal stream in SubmittedStart. The caller must call persist_before_observing with the direct StartUnit reply and only then receives PersistedStart.
8. Consume that persisted ticket with a bounded wait for JobRemoved. Correlate the exact path, path-derived ID, unit and result. Unrelated units are skipped; partial identity conflicts hold for reconciliation; timeouts, stream closure, malformed signals and unknown result strings never become transaction success. If the direct reply is Unknown but the stream remains alive, the observer still retains a matching unit event as supplemental evidence; it never promotes that signal to confirmed completion without the direct returned job path.
9. Preserve raw systemd result text in SystemdStartObservation, even when the result is unknown to this version of the enum.

The typestate chain is:

StartIntent → PreparedStartIntent → SubscribedStart → SubmittedStart → PersistedStart → SystemdStartObservation

This chain constrains in-process call order. It is not a security boundary: the persistence callbacks must actually write the intended journal records, and persisted evidence still requires the repository's integrity, identity and authorization checks.

## PIDFD-bound invocation observation

The crate-private `observe_worker_invocation_by_pidfd()` helper first reads the kernel `Pid:` field from `/proc/self/fdinfo/<fd>` and requires it to equal the expected worker PID; it then performs a read-only `GetUnitByPIDFD` request using a zvariant UNIX_FD wrapper, queries the returned unit object's `Id` and `InvocationID` properties and its Service `MainPID`, and delegates the field-level consistency checks to the pure evidence layer. This prevents a pidfd for an auxiliary process in the same unit from being substituted.

This helper does not create a pidfd, persist the evidence, acquire the transaction lock, or wire itself into the transaction supervisor. It must be called with a pidfd for the exact live process and independently trusted transaction/attempt/purpose/PID inputs. If systemd does not implement `GetUnitByPIDFD` (version < 253), the caller must hold; it must not substitute a PID-only lookup.

## Important recovery limits

- StartUnit may have been accepted even when the method reply is lost. The adapter emits Unknown and must not resubmit that attempt. If the existing signal stream remains live, a matching JobRemoved event is retained with HoldForReconciliation; it is supplemental evidence, not a substitute for the lost direct reply.
- A recovered StartIntentEvidence record must pass validate_start_intent_evidence; the serialized transaction, attempt, purpose and canonical unit must agree. This validates identity consistency, not cryptographic authenticity or journal integrity.
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

Static source review only. Added a pre-wait classifier and test proving an unknown direct reply remains eligible for signal observation while a later Done signal is still held for reconciliation. The adapter remains crate-private and is not production-wired because it issues a real, mutating StartUnit request while still lacking integrated transaction authorization, an established unit template, durable inter-process locking/reconciliation, and VM qualification. Added a pure recovered-intent validator and mutation tests, but no Rust tests/build, rustfmt, Clippy, live D-Bus tests, Nix evaluation, or NixOS VM fault injection has been run in this environment. Rust tests/build, rustfmt, Clippy, live D-Bus tests, Nix evaluation, and NixOS VM fault injection have not been run in this environment. Do not connect it to a production caller until those gaps are closed and the exact PR head is qualified.
