# Systemd invocation to activation-worker identity bridge v1

Status: **pure identity join implemented; durable attempt schema and production supervisor wiring remain separate**

Date: 2026-10-30

## Why this bridge exists

Nixward currently has two identity records with different responsibilities:

- `ConfigTransaction::ActivationWorkerIdentity` records the process identity and approved execution envelope: transaction ID, purpose, PID, boot ID, process start-time ticks, worker-gate executable/image, gate argv digest, payload executable/argv digest, release-challenge digest and environment digest.
- `SystemdWorkerInvocationEvidence` records the canonical attempt unit and systemd's 128-bit InvocationID, joined to the worker PID.

Neither record should replace the other. The first describes the exact process and approved payload; the second describes the systemd service invocation that owns the process.

## Explicit purpose mapping

The following purpose variants are mapped exhaustively in both directions:

- ProfileTransition
- Activation
- RecoveryProfileTransition
- RecoveryActivation

The exhaustive `From` implementations make a future enum addition a compile-time review point: both mappings must be updated rather than silently defaulting an unknown purpose.

## Join validation

`validate_systemd_worker_invocation_against_activation_identity()`:

1. Runs the existing `ActivationWorkerIdentity::validate_identity()`, including its process boot/start-time and executable/argv/environment checks.
2. Maps the existing worker purpose to the systemd evidence purpose.
3. Validates the recovered `StartIntentEvidence` against the worker's transaction and purpose plus an independently supplied `expected_attempt_id`.
4. Validates the systemd invocation evidence against the same transaction, attempt, purpose and exact worker PID.

The expected attempt ID must come from the independently loaded durable attempt record. This helper never infers it from the systemd evidence or the process receipt. The older `ActivationWorkerIdentity` schema remains unchanged; adding attempt ID, unit name and InvocationID to one authoritative versioned attempt record is still part of Issue #96.

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

The live PIDFD capture must still verify `GetUnitByPIDFD`, the returned unit ID, the unit object's `Id`/ `InvocationID`, and `MainPID`. Recovery must apply the invocation-aware decision contract before resuming observation.
