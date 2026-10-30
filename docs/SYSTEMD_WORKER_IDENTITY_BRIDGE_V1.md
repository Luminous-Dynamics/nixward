# Systemd invocation to activation-worker identity bridge v1

Status: **pure identity join and v8 journal attempt anchor implemented; production supervisor wiring remains separate**

Date: 2026-10-30

## Why this bridge exists

Nixward currently has two identity records with different responsibilities:

- `ConfigTransaction::ActivationWorkerIdentity` records the process identity and approved execution envelope: transaction ID, purpose, PID, boot ID, process start-time ticks, worker-gate executable/image, gate argv digest, payload executable/argv digest, release-challenge digest and environment digest.
- `SystemdWorkerInvocationEvidence` records the canonical attempt unit and systemd's 128-bit InvocationID, joined to the worker PID.
- `ConfigTransaction::systemd_start_attempts` now stores the write-ahead transaction / attempt / purpose / unit / plan-digest tuple. A systemd-bound `ActivationWorkerIdentity` must refer back to that exact attempt ID. Legacy direct-spawn identities remain explicitly unbound after the v7-to-v8 in-memory migration.

Neither process nor manager record should replace the other. The process record describes the exact executable, argv, environment, PID, boot and start-time identity; the manager record describes the service invocation that owns the process. The journal now anchors their common attempt identifier, but the live supervisor has not yet been wired to persist and read back that record before submission.

## Explicit purpose mapping

The following purpose variants are mapped exhaustively in both directions:

- ProfileTransition
- Activation
- RecoveryProfileTransition
- RecoveryActivation

The exhaustive `From` implementations make a future enum addition a compile-time review point: both mappings must be updated rather than silently defaulting an unknown purpose.

## Join validation

`validate_systemd_worker_invocation_against_transaction()`:

1. Validates the process identity, including boot/start-time and executable/argv/environment bindings.
2. Requires the exact worker identity to be present in the supplied `ConfigTransaction` object.
3. Locates the worker's attempt ID in that same transaction's `systemd_start_attempts` collection and validates the record against the transaction ID, plan digest, canonical unit and current lifecycle phase.
4. Compares the `StartIntentEvidence`, systemd `InvocationID`, purpose, unit and exact worker PID against the journaled record.

The validator no longer accepts a free-standing expected-attempt string. Its transaction argument must be the validated journal object obtained after publication/read-back under the existing interlock. The worker's optional `systemd_attempt_id` is omitted from serialization when absent, preserving the legacy v7 direct-spawn identity wire shape and its worker-observation digest.

## Evidence limits

This bridge proves that the independently validated process identity and the independently captured systemd invocation evidence refer to the same transaction/purpose/PID and expected attempt.

It does not:
- obtain or validate a pidfd itself;
- prove that the process remains live after the capture;
- persist either record;
- acquire the cross-process Nixward transaction interlock;
- authorize the start;
- validate the process-exit receipt;
- prove NixOS runtime/profile post-state.

The live PIDFD capture must still verify `GetUnitByPIDFD`, the returned unit ID, the unit object's `Id` and `InvocationID`, and the caller-namespace pidfd target identity. Do not compare that PID numerically with systemd's manager-namespace `MainPID`: those values are not namespace-invariant. Recovery must apply the invocation-aware decision contract before resuming observation.
