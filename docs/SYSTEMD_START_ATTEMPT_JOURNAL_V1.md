# Journal-anchored systemd start attempts v1

Status: **journal schema, launch envelope and pure identity join authored; production systemd supervisor integration and execution qualification remain open**

Date: 2026-10-30

## Problem closed by this layer

The original systemd invocation join accepted an `expected_attempt_id` string, but the existing `ActivationWorkerIdentity` did not carry an attempt ID and `ConfigTransaction` did not persist the start intent. A caller could therefore supply an ID that was consistent across the systemd evidence objects without proving that the same ID had been committed to the transaction journal.

This change makes the attempt identity a first-class journal fact.

## Journal representation

Transaction schema v9 adds an append-only `systemd_start_attempts` collection. Each record binds:

- transaction ID;
- attempt ID;
- worker purpose;
- canonical systemd unit name derived from the transaction / attempt / purpose tuple;
- the transaction plan digest;
- an immutable launch envelope containing the fixed worker-gate executable, exact payload executable and argument vector, the digest of Nixward's fixed worker environment allowlist, and the expected pre-activation system-profile closure.

The payload argv digest is recomputed from the exact executable and argument vector. Store executable paths are checked for Nix store object identity and complete lexical traversal. The environment digest is not caller-selected: validation requires the existing fixed Nixward privileged-worker environment allowlist. The one-time worker-gate release token is deliberately not stored in the envelope; the runner must create it only after acquiring the transaction interlock and confirming durable worker identity. The canonical unit name is recomputed during both record creation and journal load. The stored plan digest must match the transaction's plan digest.

`ConfigTransaction::reserve_authorized_systemd_start_attempt()` is the production-facing method. It requires the verified `ExecutionAuthorization` and exact `NixOSCommand`, checks the transaction's plan/candidate binding (or the pre-bound rollback capability), checks that the gate executable is the installed Nixward worker gate, independently observes the current system profile, and validates the correct launch shape for profile selection, closure activation or recovery before it calls the private raw append. The raw `reserve_systemd_start_attempt()` method is private to the action module; a test-only helper is compiled only under `cfg(test)`. Reservation also requires the exact durable lifecycle phase, rejects a second systemd attempt for the same purpose, and rejects retrofitting a systemd attempt after a direct-spawn worker identity was already recorded. The restriction is intentionally conservative: until a separately qualified resolution protocol exists, an ambiguous attempt cannot be retried by minting a new ID.

`ActivationWorkerIdentity` gains an optional `systemd_attempt_id`. A systemd-bound worker must reference an existing attempt record with the same transaction and purpose, and its gate executable, payload executable/argv, and environment digest must match the journaled launch envelope. The optional field is retained only for legacy direct-spawn worker identities.

## Backward compatibility

The loader accepts v8 and v7 journals and upgrades them in memory to v9. v8 attempts are retained for audit with `launch_envelope = None`; they cannot accept a newly bound worker or qualify an InvocationID join because their exact pre-start payload contract was not recorded. v7 journals have no systemd attempts and are upgraded without synthesizing IDs. Existing process records retain their original serialization when `systemd_attempt_id` is absent. The next successful persistence writes the v9 shape.

Unsupported schema/version pairs still fail closed.

## Required pre-submission sequence

The future supervisor integration must perform this sequence while holding the existing Nixward transaction interlock:

1. Reload and revalidate the transaction and exact authorization inputs.
2. Derive the fixed launch envelope, then call `reserve_authorized_systemd_start_attempt()` with the exact command and verified `ExecutionAuthorization`. The raw append method is private.
3. Persist the transaction atomically, then read it back and verify the exact attempt record and plan digest.
4. Construct the matching `StartIntent`; only after the read-back succeeds may its prepared capability be submitted to the systemd adapter.
5. After launch, capture the exact process identity and set its `systemd_attempt_id` to the reserved attempt. The journal will reject a missing, foreign, or purpose-confused join, and the process must match the committed gate/payload/argv/environment envelope.

The authorization-aware method only reserves an in-memory record after a fresh profile observation. Calling it is not itself evidence of persistence or permission to issue `StartUnit`. Do not submit until the durable write and independent read-back have succeeded. Invocation validation now takes the loaded `ConfigTransaction` object, locates the attempt record there, and verifies that the exact worker identity is also present in that transaction; it no longer accepts a free-standing expected-attempt string.

## Evidence boundary and remaining work

This v1 record binds the transaction, attempt, purpose, canonical unit, plan digest and exact worker launch envelope. The production caller must still prove that the envelope is the command selected by the verified ChangePlan and ExecutionAuthorization before reservation; the envelope is an execution identity commitment, not an authorization credential. The systemd `InvocationID`, StartUnit reply, JobRemoved signal, worker process receipt and fresh NixOS runtime/profile observations are not yet persisted as one append-only event history by this change.

A start intent that exists without conclusive later evidence remains unresolved. Absence of a worker receipt, unit, or JobRemoved signal is not proof that no external action occurred.

## Hard integration blocker: unit materialization

The current adapter calls `Manager.StartUnit` with the canonical per-attempt unit name. The launch envelope does not yet change this adapter or create the fixed runner; production submission remains disabled. The repository's current `nix/module.nix` defines `nixward.service`, but not a matching `nixward-transaction@.service` template or another unit definition corresponding to the generated per-attempt name. systemd documents that `GetUnit` fails for a unit that has not been loaded; `StartUnit` starts a named unit but does not create its definition.

Do not wire the current `submit_start()` path into production until one of these provisioning models is implemented and independently qualified:

1. **NixOS-managed static template.** Add a narrowly privileged `nixward-transaction@.service` with a fixed Nixward runner `ExecStart`. The instance must resolve unambiguously to one validated journal attempt; it must not allow caller-controlled executable, shell command, environment or unit properties.
2. **D-Bus transient service.** Use `Manager.StartTransientUnit` to create the per-attempt service with a fixed trusted runner and constrained properties. Hash and persist the exact property/ExecStart envelope before submission. Qualify unit-name uniqueness, property signatures, caller authorization, manager restart behavior, and retention after exit. systemd documents that a transient unit is released after it is no longer running or referenced, or at reboot, so the design must explicitly manage and test references if post-exit manager evidence is required.

The static template is currently the safer compatibility choice for the advertised systemd 253+ floor. There is an important polkit version boundary:

- In systemd v253 and v256, `StartTransientUnit` calls the generic `bus_verify_manage_units_async()` authorization path without unit/verb detail. A polkit rule therefore cannot safely scope the grant to the exact transient unit through `action.lookup("unit")`; granting the action would be a broad system-unit management grant.
- In systemd v257, the transient-unit handler changed to pass the requested unit name and `start` verb through `bus_verify_manage_units_async_impl()`. A narrowly scoped polkit policy can then inspect those details, subject to testing on the exact supported release.
- The `StartUnit` path loads the named static unit and dispatches through the unit-object method, which calls `bus_verify_manage_units_async_full()` with the unit and verb. This behavior is present in v253. A policy can therefore restrict the Nixward service principal to starting only the fixed Nixward transaction template family, without granting general `manage-units`.

The existing NixOS module runs `nixward-daemon` as the unprivileged `nixward` user with an empty `CapabilityBoundingSet`; it does not define a systemd polkit rule. Systemd documents that system-unit mutation requires `org.freedesktop.systemd1.manage-units`. Production integration must explicitly test the authorization path on a clean headless NixOS VM and prove that the Nixward principal cannot start, stop, restart, or modify unrelated units. Do not add a broad `manage-units` allow rule.

For v253+, prefer a static `nixward-transaction@.service` template with a fixed Nixward runner, exact per-instance unit matching in polkit and a strict journal/attempt/interlock check inside the runner. The instance must not provide an executable or shell command. If transient units are selected, either require systemd 257+ and test the scoped polkit details, or use a separate privileged broker that exposes only a typed, journal-validated start operation. Do not silently depend on newer authorization semantics while claiming a 253+ support floor.

In either model, the worker runner must reload and validate the journal and acquire the existing transaction interlock before launching the approved worker gate. The manager unit itself must not accept arbitrary privileged commands.

Source-level version comparison:
- systemd v253 `src/core/dbus-manager.c`: `method_start_transient_unit()` calls `bus_verify_manage_units_async()`.
- systemd v256: same generic authorization call.
- systemd v257: calls `bus_verify_manage_units_async_impl(m, name, "start", ...)`.
- systemd v253 `src/core/dbus-unit.c`: unit-object start calls `bus_verify_manage_units_async_full(u, verb, ...)`.

References: https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html and https://github.com/systemd/systemd/issues/17224

## Qualification

The source adds tests for:
- v7/v8-to-v9 loading without fabricated attempt identities, with legacy v8 attempts kept audit-only;
- exact worker launch-envelope persistence and read-back;
- fixed-environment enforcement (no caller-selected `PATH` / loader / Nix config);
- separate exact command checks for profile selection and closure activation;
- rejection of payload argv, store-path traversal and worker identity drift against the envelope;
- canonical attempt/unit and plan binding;
- phase-scoped reservation;
- rejection of a second attempt for the same purpose;
- binding a worker identity to the exact journaled attempt;
- rejection of caller-only, absent, or foreign attempt IDs in the transaction-backed invocation join;
- rejection when the worker identity supplied to the join is not the identity journaled in that transaction;
- preservation of the legacy worker identity serialization shape when the optional systemd attempt is absent.

No Cargo, Nix, D-Bus, systemd VM, crash-injection, or power-loss test is claimed in the authoring environment. The next gates are the systemd-feature Nix derivation from PR #103, followed by a disposable NixOS VM that tests all manager and crash boundaries.
