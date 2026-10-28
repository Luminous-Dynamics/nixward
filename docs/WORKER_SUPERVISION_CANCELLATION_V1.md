# Worker supervision across request cancellation v1

Status: **draft implementation slice; not yet compiled or qualified**  
Related: [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75), [journal-owned activation PR #62](https://github.com/Luminous-Dynamics/nixward/pull/62), [worker-observation branch](https://github.com/Luminous-Dynamics/nixward/tree/hardening/journal-owned-worker-supervision-2026-10-28)

## The design shift

A request is not the owner of a privileged operation's truth.

Once Nixward has persisted the exact worker identity and launches the one-shot activation gate, the child handle and pidfd move into a Tokio observer task **before** the release token is written. The requesting future owns only its JoinHandle. Cancelling that future drops the join handle and detaches the observer; it does not drop the Child owned inside the observer task. The observer waits for process termination, checks pidfd exit evidence, and atomically publishes an output-free process-observation receipt.

The release write is deliberately after the observer starts. If cancellation occurs while writing the release frame, closing the pipe either leaves an incomplete frame that the inert gate rejects, or supplies EOF after the complete token and allows the gate to release. In both cases the observer already owns the child and can observe its disposition, provided the Tokio runtime itself remains alive.

This is **request-cancellation resilience**, not a claim that an in-process task survives its process or host.

## Durable sidecar receipt

The output-free luminous-nixward-worker-observation v1 sidecar binds:
- transaction ID and worker purpose;
- PID, boot ID, and process start-time ticks;
- a digest of the exact persisted activation-worker identity (including executable/argv, payload, environment and release-challenge bindings);
- optional caller-observed wall time, monotonic elapsed duration, and process disposition (exit code or signal).

The receipt is published without replacement: a mode-0600 temporary file is written and synced, an atomic same-directory hard link creates the destination only if absent, the temporary link is removed, and the parent directory is synced. A pre-existing receipt is an error, never silently overwritten. Time fields are bounded to the safe-integer range shared by JSON/JavaScript consumers.

The receipt intentionally omits stdout/stderr, credentials, and any claim of observed NixOS state. The process observation is not launch attestation: the pre-release worker identity records the gate and payload intent, and this sidecar confirms only a process disposition reported by the observer. It does not prove the desired closure is active, a boot selection is correct, or recovery succeeded.

## Failure semantics

| Fault boundary | Required interpretation |
|---|---|
| Before the worker is launched | No worker launch; the existing durable phase remains authoritative. |
| Gate launched but identity not durably published | Payload remains unreleased; terminate/reap the inert gate or leave state indeterminate if safe termination cannot be established. |
| Worker identity published, before release | Payload is not intentionally released; failure to prove that fact blocks further mutation. |
| Cancellation while writing the release frame | Release may be incomplete or complete. Never infer NotStarted; the already-running observer must record process disposition. |
| Caller task cancelled after release | Observer remains responsible while its Tokio runtime stays alive; caller receives no success assertion. Reconcile machine state independently. |
| Process exits but receipt is not published | Operation stays indeterminate. A missing sidecar is not proof the child did not run. |
| Observer task/runtime crashes or is aborted | This slice cannot ensure the sidecar exists. Treat the journal as unresolved and reconcile before retry. |
| Nixward process crashes or host reboots | This slice does not persist an independent supervising process. Boot ID and persisted process identity can help rule out a previous live worker, but do not prove the transaction's final post-state. Read-only runtime/profile observation is mandatory before any new mutation. |

During authorized recovery, Nixward now looks for the exact identity-bound sidecar and logs a validated process disposition when one exists. An absent or unreadable sidecar remains indeterminate; it never substitutes for independent read-only runtime/profile observations. The transaction journal's existing nonterminal phases remain reconciliation-required. A sidecar alone does not promote a transaction to Activated, BootSelected, or Recovered. No retry is allowed solely because the request timed out or lost its response. Do not enable generic kill-on-request-cancellation as a recovery strategy: terminating an activation midway is not evidence that the previous system state was restored.

## Tests authored in this slice

- worker_observation_round_trips_and_does_not_export_process_output: serializes a fixture process disposition, checks that no output field is present, performs no-clobber persistence, and reloads against the exact worker identity.
- worker_observation_rejects_receipt_rebinding_to_another_worker: changing the payload argv invalidates the prior receipt.
- observer_publication_collision_after_exit_preserves_existing_receipt: a controlled child exits, then a pre-existing receipt path forces publication failure; the observer must report an indeterminate error without clobbering the file.
- worker_observation_survives_request_task_cancellation: a harmless controlled child exits nonzero; cancellation of the request-facing task is injected while a detached observer owns the child, and the test expects a matching on-disk receipt.

These tests are **authored but not executed** in this environment. They must run on the exact PR head before merge. Required next tests include cancellation at each gate-frame byte boundary, receipt-publication failure after child exit, supervisor task/runtime shutdown, and a disposable NixOS VM with read-only independent postcondition observations.

## Qualification targets (proposed, not measured)

Use deterministic fault injection with a versioned corpus and retain the exact commit SHA, fixture digest, host/kernel/Tokio versions, start/end monotonic times, and per-trial evidence bundle.

| Metric | Gate before production use |
|---|---:|
| Unauthorized mutation in negative controls | 0 |
| Duplicate/replayed mutation after an indeterminate outcome | 0 |
| False claims of activation/recovery success | 0 |
| Receipt identity mismatch accepted | 0 |
| Required process-observation checkpoints with complete evidence, when observer/runtime remain alive | 100% |
| Reconciliation required on missing/contradictory receipt | 100% |
| Fault-injection campaigns | At least 100 trials per cancellation checkpoint and each supported OS/kernel profile |
| Receipt publication latency | Report p50/p95/p99; establish budget from target hardware rather than claiming an unmeasured universal threshold |

A stronger follow-up must move process ownership into a service/supervisor whose lifecycle is independent of request handling and define restart recovery. A VM campaign must separately inject service restart, supervisor crash, forced kill, host reboot, receipt-write failure and journal fsync failure. Request cancellation is not a surrogate for those fault models.

## Industry comparison

Compare Nixward with NixOS deployment tools on the same workload and machine cohort—not by broad marketing claims. Measure deployment outcome correctness, unauthorized-change rejection, interruption/reconciliation behavior, evidence completeness, rollback postconditions, throughput and operator time. Keep security hard gates independent of latency: a fast false-success is still a failure. For operational delivery, track DORA's change lead time, deployment frequency, failed-deployment recovery time, change-failure rate and deployment rework rate longitudinally, alongside Nixward-specific safety metrics. DORA metrics are service-context and trend measures, not a single universal leaderboard.

References: [Tokio process lifecycle](https://docs.rs/tokio/latest/tokio/process/struct.Command.html), [NixOS Colmena](https://github.com/zhaofengli/colmena), [DORA metrics guide](https://dora.dev/guides/dora-metrics/).
