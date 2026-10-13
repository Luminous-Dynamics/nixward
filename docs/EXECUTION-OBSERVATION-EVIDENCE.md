# Execution observation evidence contract

**Status:** additive API proposal implemented on branch `feat/execution-observation-evidence-v1`; not yet wired into the SystemTransaction wire protocol or OMSI adapter.

## Why this exists

The legacy `ExecutionResult` is optimized for callers and CLI presentation. It deliberately does not encode enough process-level detail to establish application evidence by itself. The additive `NixOSExecutor::execute_authorized_observed()` returns the same result together with an explicit `ExecutionObservation`.

## Evidence types

- `InvocationStatus::NotStarted` records why a command did not launch: dry-run, forbidden host policy, rejected authorization, incomplete replay evidence, rejected replay, or unavailable clock needed for replay protection.
- `InvocationStatus::Attempted` includes the command's BLAKE3 digest, observed wall-clock timestamps when available, monotonic elapsed time, and a process disposition.
- `ProcessDisposition::Exited` retains the actual exit code. `TerminatedWithoutExitCode` records the signal when the platform exposes one. `SpawnFailed` preserves the spawn error instead of inventing an exit code.
- An optional rollback observation retains the rollback command digest, timing, and process disposition. It does not prove that the old machine state was restored.

## Consumer rules

1. Do not infer an invocation from `ExecutionResult::Success`. Dry-run remains a legacy `Success`, but its observation says `NotStarted { reason: DryRun }`.
2. Do not infer a process exit code from `RolledBack`, `FailedNoRollback`, `Blocked`, or `PendingConfirmation`.
3. A spawn failure is not process exit status 1 or 127. Preserve `SpawnFailed` as a distinct disposition.
4. Missing wall-clock timestamps are `None`, serialized as JSON `null`. Never replace them with epoch zero or derive absolute time from elapsed duration.
5. A consumer mapping to `SystemTransaction::ApplicationReceipt` must require real exit-code evidence and present, ordered timestamps. SystemTransaction v1 cannot faithfully encode spawn failure, signal termination, dry-run, or rollback details as currently shaped. Do not coerce these into its `exit_status` field; define a versioned receipt update or a separate failure observation first.
6. A rollback command's exit code indicates only its process outcome. Verified recovery requires a fresh read-only observation of the target's post-recovery state.

## Compatibility and limits

The existing `execute_authorized()` API remains compatible and returns only `ExecutionResult`; callers that need execution evidence must opt into `execute_authorized_observed()`. The current CLI has not yet been switched to consume the new API. This is not an end-to-end transaction adapter, not a VM qualification, and not proof of restored host state.
