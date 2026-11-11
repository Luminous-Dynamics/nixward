# Execution observation evidence contract

**Status:** additive API proposal implemented on branch `feat/execution-observation-evidence-v1`; not yet wired into the SystemTransaction wire protocol or OMSI adapter.

## Why this exists

The legacy `ExecutionResult` is optimized for callers and CLI presentation. It deliberately does not encode enough process-level detail to establish application evidence by itself. The additive `NixOSExecutor::execute_authorized_observed()` returns the same result together with an explicit `ExecutionObservation`. Use `evidence_envelope()` to obtain the versioned output-free projection defined by [execution-observation-v1.schema.json](schemas/execution-observation-v1.schema.json). Three fixtures cover dry-run, spawn failure, and a nonzero exit: [dry-run](fixtures/execution-observation-dry-run-v1.json), [spawn failure](fixtures/execution-observation-spawn-failure-v1.json), and [nonzero exit](fixtures/execution-observation-nonzero-exit-v1.json).

## Evidence types

- The envelope binds the requested command's BLAKE3 digest even when it never launches, so dry-run/rejected observations cannot be detached from their intended command. `ExecutionObservation` itself is intentionally not serializable because its embedded result may contain raw stdout/stderr.
- `InvocationStatus::NotStarted` records why a command did not launch: dry-run, forbidden host policy, rejected authorization, incomplete replay evidence, rejected replay, or unavailable clock needed for replay protection.
- `InvocationStatus::Attempted` includes the **requested-command** BLAKE3 digest, caller-observed wall-clock timestamps bracketing `Command::output()` when available, monotonic elapsed time, and a process disposition. These timestamps are not an independent measurement of the kernel's exact process birth/exit times.
- `ProcessDisposition::Exited` retains the actual exit code. `TerminatedWithoutExitCode` records the signal when the platform exposes one. `SpawnFailed` preserves the spawn error instead of inventing an exit code.
- An optional rollback observation retains the rollback command digest, timing, and process disposition. It does not prove that the old machine state was restored.

## Identity boundary: request digest is not launch identity

`NixOSCommand::command_digest()` hashes the serialized `NixOSCommand` request. It binds the requested command variant and its fields; it is **not** a digest of the resolved executable, native argv bytes, environment, or a kernel process identity. In this legacy execution path, `Command::new()` can receive a bare executable name (for example, `nix` or `nixos-rebuild`) whose executable is resolved by the process environment's `PATH`. Therefore, the request digest and observed exit disposition must not be presented as proof of which executable image actually ran or as a signed/attested execution receipt.

For privileged journal-owned system activation, use the separate worker-gate transaction path rather than inferring launch identity from this envelope. That path's worker receipt is designed to bind the gate and payload executable/argv, environment digest, transaction identity, boot ID, PID/start-time identity, and release challenge before payload release. It remains a distinct integration path: this API does not acquire that identity merely because it emits an execution-observation envelope. A future native-invocation evidence version would need to capture and validate the absolute executable and exact argv/environment identity at the launch boundary, plus process identity where supported.

## Consumer rules

1. Do not infer an invocation from `ExecutionResult::Success`. Dry-run remains a legacy `Success`, but its observation says `NotStarted { reason: DryRun }`.
   The envelope's `dry_run` flag describes the reason for not launching, not merely the executor configuration: if policy or authorization rejects first, the flag remains false even when dry-run mode was configured.
2. Do not infer a process exit code from `RolledBack`, `FailedNoRollback`, `Blocked`, or `PendingConfirmation`.
3. A spawn failure is not process exit status 1 or 127. Preserve `SpawnFailed` as a distinct disposition.
4. Missing wall-clock timestamps are `None`, serialized as JSON `null`. Never replace them with epoch zero or derive absolute time from elapsed duration.
   The envelope also bounds timestamps and elapsed values to the IEEE-754 safe-integer maximum (2^53−1) so JavaScript consumers cannot silently round larger Rust `u64` values.
5. A consumer mapping to `SystemTransaction::ApplicationReceipt` must require real exit-code evidence and present, ordered timestamps. SystemTransaction v1 cannot faithfully encode spawn failure, signal termination, dry-run, or rollback details as currently shaped. Do not coerce these into its `exit_status` field; define a versioned receipt update or a separate failure observation first.
6. A rollback command's exit code indicates only its process outcome. Verified recovery requires a fresh read-only observation of the target's post-recovery state.


## Cancellation and indeterminate execution

This API does not provide durable supervision or cancellation-proof journaling. The current helper awaits Tokio `Command::output()`; Tokio's process API documents that a spawned child normally continues if its handle/future is dropped unless `kill_on_drop` is enabled ([Tokio process cancellation caveat](https://docs.rs/tokio/latest/tokio/process/struct.Command.html)). This means a caller may lose the returned observation after launch while the child continues executing.

Do not interpret a dropped/cancelled future or missing receipt as `NotStarted`, `Failed`, or evidence that no mutation occurred. Treat the outcome as **indeterminate**, keep it in a durable journal-owned supervisor, and perform read-only reconciliation against actual target state before retrying. This helper deliberately does not enable `kill_on_drop(true)`: killing a rebuild/activation at an arbitrary point also does not prove rollback or restore the prior state. A cancellation-safe worker/journal protocol must make this policy explicit and be qualified separately.

## Compatibility and limits

The existing `execute_authorized()` API remains compatible and returns only `ExecutionResult`; callers that need execution evidence must opt into `execute_authorized_observed()`. The current CLI has not yet been switched to consume the new API. This is not an end-to-end transaction adapter, not a VM qualification, and not proof of restored host state.
