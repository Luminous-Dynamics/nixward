# Payload release barrier model v1

Status: **pure transition model and unit tests authored; no durable SQLite barrier or worker-release implementation**

## Why this layer exists

An authority receipt and policy archive do not solve the time-of-check/time-of-use race between policy evaluation and an external payload write. A future supervisor needs a durable release barrier serialized with policy advancement in the same local write-transaction domain.

The model defines the barrier commit as the linearization point:

1. Compare the exact admission binding with the committed transaction.
2. Compare the expected policy epoch and record digest with the current pointer.
3. Reject expired authority and emergency-revoked signers.
4. Commit one release barrier binding the admission commit, attempt, replay, permit, plan, machine, provenance digest, policy snapshot, signer, payload digest and expiry.
5. Commit a one-shot release-attempt reservation before writing external bytes.
6. Require a receipt bound to the same release ID, payload digest, worker unit and InvocationID.

Policy advancement and barrier creation serialize through BEGIN IMMEDIATE. If policy advancement wins first, a barrier request for the old epoch is rejected. If the barrier wins first, the subsequent policy update must explicitly choose whether to preserve the in-flight barrier under historical authorization or require a separate stop/recovery decision. The original barrier record is never rewritten.

## At-most-once attempt, not exactly-once delivery

The database and external worker write are separate failure domains. A crash after the durable release-attempt transition but before acknowledgement cannot prove whether bytes were delivered, partially delivered or not delivered. The model marks the outcome uncertain and refuses automatic retry or a second release attempt.

This sacrifices liveness to prevent duplicate release. A future worker-side durable idempotency receiver keyed by release ID may improve recovery, but it needs independent process/VM crash qualification. No exactly-once delivery claim is made.

The policy barrier is a local linearization point, not a TPM or remote anti-rollback anchor. A privileged root attacker or whole-disk rollback remains outside the model's guarantees. A policy update after the barrier uses a separate stop/recovery policy for already in-flight work.

## Model states

- barrier_committed: admission and current policy were checked and the unique release intent is durable.
- release_attempted: the one permitted external attempt was durably reserved; external I/O may or may not have started.
- acknowledged: exact worker receipt acknowledges the release ID, payload digest, unit and InvocationID.
- uncertain: an attempt exists but the result is ambiguous; no automatic resend.
- cancelled_before_attempt: expiry or an explicit stop/recovery policy blocked a not-yet-started release.

A late exact receipt may resolve an uncertain attempt to acknowledged. It does not perform another release.

## Acceptance tests

The Rust module contains 24 deterministic tests, covering both policy/barrier race orderings, stale policy, revocation, expiry, exact admission binding, changed payload, idempotent barrier retry, one-shot attempt, ambiguous acknowledgement, late receipt reconciliation, exact worker identity and post-barrier policy change. The JSON fixture catalogue contains 23 machine-readable positive/negative cases and includes the barrier immutability and post-policy-change retry cases.

The model is in-memory and pure. It does not prove SQLite transaction ordering, disk durability, D-Bus capture, PIDFD authenticity or worker behavior. A dedicated Nix check is authored to compile the native library test target and run only these tests; it is not executed in this environment.
