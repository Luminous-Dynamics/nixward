# Journal-anchored systemd start attempts v1

Status: **journal schema and pure identity join authored; production systemd supervisor integration and execution qualification remain open**

Date: 2026-10-30

## Problem closed by this layer

The original systemd invocation join accepted an `expected_attempt_id` string, but the existing `ActivationWorkerIdentity` did not carry an attempt ID and `ConfigTransaction` did not persist the start intent. A caller could therefore supply an ID that was consistent across the systemd evidence objects without proving that the same ID had been committed to the transaction journal.

This change makes the attempt identity a first-class journal fact.

## Journal representation

Transaction schema v8 adds an append-only `systemd_start_attempts` collection. Each record binds:

- transaction ID;
- attempt ID;
- worker purpose;
- canonical systemd unit name derived from the transaction / attempt / purpose tuple;
- the transaction plan digest.

The canonical unit name is recomputed during both record creation and journal load. The stored plan digest must match the transaction's plan digest.

`ConfigTransaction::reserve_systemd_start_attempt()` requires the transaction to be at the exact durable phase for the requested worker purpose. It rejects a second systemd attempt for the same purpose and rejects retrofitting a systemd attempt after a direct-spawn worker identity was already recorded for that purpose. The restriction is intentionally conservative: until a separately qualified resolution protocol exists, an ambiguous attempt cannot be retried by minting a new ID.

`ActivationWorkerIdentity` gains an optional `systemd_attempt_id`. A systemd-bound worker must reference an existing attempt record with the same transaction and purpose. The optional field is retained only for legacy direct-spawn worker identities.

## Backward compatibility

The loader accepts the immediately previous v7 schema and upgrades it in memory to v8. It does not infer or synthesize systemd attempt IDs for v7 journals. Existing process records load with `systemd_attempt_id = None`. The next successful journal persistence writes the v8 shape.

Unsupported schema/version pairs still fail closed.

## Required pre-submission sequence

The future supervisor integration must perform this sequence while holding the existing Nixward transaction interlock:

1. Reload and revalidate the transaction and exact authorization inputs.
2. Reserve one attempt with `reserve_systemd_start_attempt()`.
3. Persist the transaction atomically, then read it back and verify the exact attempt record and plan digest.
4. Construct the matching `StartIntent`; only after the read-back succeeds may its prepared capability be submitted to the systemd adapter.
5. After launch, capture the exact process identity and set its `systemd_attempt_id` to the reserved attempt. The journal will reject a missing, foreign, or purpose-confused join.

The method only reserves an in-memory record. Calling it is not itself evidence of persistence or permission to issue `StartUnit`. Do not submit until the durable write and independent read-back have succeeded. Invocation validation now takes the loaded `ConfigTransaction` object, locates the attempt record there, and verifies that the exact worker identity is also present in that transaction; it no longer accepts a free-standing expected-attempt string.

## Evidence boundary and remaining work

This v1 record binds the transaction, attempt, purpose, canonical unit and plan digest. The approved executable / argv / environment envelope remains in the existing process identity and must be bound to the authorized command before production manager submission is wired. The systemd `InvocationID`, StartUnit reply, JobRemoved signal, worker process receipt and fresh NixOS runtime/profile observations are not yet persisted as one append-only event history by this change.

A start intent that exists without conclusive later evidence remains unresolved. Absence of a worker receipt, unit, or JobRemoved signal is not proof that no external action occurred.

## Qualification

The source adds tests for:
- v7-to-v8 loading without fabricated attempt identities;
- canonical attempt/unit and plan binding;
- phase-scoped reservation;
- rejection of a second attempt for the same purpose;
- binding a worker identity to the exact journaled attempt;
- rejection of caller-only, absent, or foreign attempt IDs in the transaction-backed invocation join;
- rejection when the worker identity supplied to the join is not the identity journaled in that transaction;
- preservation of the legacy worker identity serialization shape when the optional systemd attempt is absent.

No Cargo, Nix, D-Bus, systemd VM, crash-injection, or power-loss test is claimed in the authoring environment. The next gates are the systemd-feature Nix derivation from PR #103, followed by a disposable NixOS VM that tests all manager and crash boundaries.
