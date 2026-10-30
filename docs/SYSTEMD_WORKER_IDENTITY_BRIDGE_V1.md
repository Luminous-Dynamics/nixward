# Systemd invocation to activation-worker identity bridge v1

Status: **pure identity join and v10 worker receipt with persisted systemd InvocationID implemented; production supervisor wiring remains separate**

Date: 2026-10-30

## Why this bridge exists

Nixward currently has two identity records with different responsibilities:

- `ConfigTransaction::ActivationWorkerIdentity` records the process identity and approved execution envelope: transaction ID, purpose, PID, boot ID, process start-time ticks, worker-gate executable/image, gate argv digest, payload executable/argv digest, release-challenge digest and environment digest.
- `SystemdWorkerInvocationEvidence` captures the canonical attempt unit and systemd's 128-bit InvocationID, joined to the exact worker PID via GetUnitByPIDFD.
- `ConfigTransaction::systemd_start_attempts` stores the write-ahead transaction / attempt / purpose / unit / plan-digest tuple and the immutable launch envelope introduced in v9. In v10, `ActivationWorkerIdentity` also persists the 128-bit systemd `InvocationID` observed through GetUnitByPIDFD; a new systemd-bound identity must carry both the exact attempt ID and invocation ID. Legacy v7 direct-spawn identities remain explicitly unbound; v8 attempts without an envelope and v9 worker records without an invocation ID are retained for audit only.

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
4. Validates the worker process identity against the journaled launch envelope (fixed gate, payload executable/argv and environment digest).
5. Compares the `StartIntentEvidence`, systemd `InvocationID`, purpose, unit and exact worker PID against the journaled attempt and the invocation ID persisted alongside the exact worker receipt.

The validator no longer accepts a free-standing expected-attempt string. Its transaction argument must be the validated journal object obtained after publication/read-back under the existing interlock. Both optional systemd fields are omitted from serialization when absent, preserving the legacy v7 direct-spawn identity wire shape and worker-observation digest. A migrated v9 systemd worker receipt without `systemd_invocation_id` remains readable but cannot qualify the manager/process join.

## Evidence limits

This bridge proves that the independently validated process identity and the independently captured systemd invocation evidence refer to the same transaction/purpose/PID and expected attempt.

It does not:
- obtain or validate a pidfd itself;
- prove that the process remains live after the capture;
- persist the StartUnit reply and JobRemoved lifecycle as one append-only manager-event history (the InvocationID itself is persisted with the worker identity in v10);
- acquire the cross-process Nixward transaction interlock;
- authorize the start;
- validate the process-exit receipt;
- prove NixOS runtime/profile post-state.

The envelope validator is not an authorization verifier: the caller must first validate ChangePlan freshness, machine binding, exact command and ExecutionAuthorization. It then commits a fixed launch contract; the one-time release token is minted only after the interlock and durable worker identity are established. The live PIDFD capture must still verify `GetUnitByPIDFD`, the returned unit ID, the unit object's `Id` and `InvocationID`, and the caller-namespace pidfd target identity. Do not compare that PID numerically with systemd's manager-namespace `MainPID`: those values are not namespace-invariant. Recovery must apply the invocation-aware decision contract before resuming observation.
