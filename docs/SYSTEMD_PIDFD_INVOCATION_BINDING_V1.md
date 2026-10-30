# PIDFD-bound systemd worker invocation evidence v1

Status: **pure evidence contract authored; live D-Bus capture, journal integration and VM qualification not implemented**

Date: 2026-10-30

## Research basis

The systemd Manager D-Bus API exposes:

- `GetUnitByPIDFD(h pidfd) -> (o unit, s unit_id, ay invocation_id)`
- A unit `InvocationID` property represented as a 16-byte `ay` value.
- A service `MainPID` property.

`GetUnitByPIDFD()` was added in systemd 253. The API documentation explicitly contrasts it with PID-only `GetUnitByPID()`: using a pidfd is safer because UNIX PIDs can be recycled. See the [systemd 262 Manager API](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html), especially the Manager methods, Unit properties and version history. The [systemd InvocationID documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-id128.html) describes it as the identifier for the current service invocation.

This gives Nixward a stronger bridge between its journal-owned process identity and the systemd unit that owns that process.

## Protocol

The proposed capture path is:

1. Validate the durable transaction journal and authorization context.
2. Independently resolve the expected transaction ID, attempt ID, purpose, canonical unit name and worker PID. Do not derive these expected values from the evidence record being checked.
3. Validate the existing worker PID/boot-ID/start-time tuple and obtain a pidfd for that exact live process.
4. Call `Manager.GetUnitByPIDFD(pidfd)`. Preserve the returned unit object path, primary unit ID and 16-byte invocation ID.
5. Read `Id`, `InvocationID` and `MainPID` from the returned unit object.
6. Require the returned unit ID and unit `Id` to equal the expected canonical unit name; require both invocation-ID byte arrays to be identical and nonzero; require `MainPID` to equal the expected journal-owned worker PID.
7. Persist the resulting `SystemdWorkerInvocationEvidence` in the same append-only transaction-attempt record as the start intent, manager reply and existing worker identity.
8. Before accepting the record after restart, validate the complete record against the independently loaded journal/authorization/worker identity. The helper in this PR does not perform that persistence or loading itself.

The duplicate InvocationID read is deliberate. A unit could restart between the pidfd lookup and the property query. If the returned invocation ID and the unit's current property differ, the observer has raced a restart and must hold rather than bind the worker to a different unit invocation.

## Evidence record

`SystemdWorkerInvocationEvidence` records:

- transaction ID;
- attempt ID;
- worker purpose;
- canonical unit name;
- InvocationID encoded as exactly 32 lowercase hexadecimal characters (the canonical representation of the 16-byte D-Bus value);
- exact worker PID, which must also be checked against the journal's boot ID and process start-time identity.

The PID is not independently sufficient. It is retained as a join key to the existing worker identity record; the live capture must be performed through the pidfd API.

## Failure behavior

The pure contract rejects:

- a PIDFD-resolved unit different from the canonical attempt unit;
- a unit `MainPID` different from the expected worker PID;
- invocation ID values that are not exactly 16 bytes;
- unset all-zero invocation IDs;
- disagreement between `GetUnitByPIDFD` and the unit `InvocationID` property;
- persisted evidence whose transaction/attempt/purpose/unit/PID differs from independently trusted values;
- malformed or non-canonical encoded invocation IDs.

On systemd older than 253, Nixward must not silently treat `GetUnitByPID()` as equivalent. If the stronger pidfd-to-unit binding is required for the operation, the correct result is an explicit unsupported/hold path until an independently qualified alternative exists.

After a supervisor restart, `GetUnitByInvocationID()` can be used to look for the exact invocation where the manager still retains it. A missing unit or missing invocation lookup is not proof that the process never ran: manager unit objects can be unloaded, and the transaction must continue through worker-receipt and fresh host-state reconciliation.

## Evidence ceilings

This evidence proves only that, at the time of capture, the pidfd-referenced process was resolved by systemd to the recorded unit and service invocation, and that the service's MainPID agreed with the journal-bound worker PID.

It does **not** prove:

- the worker exited;
- the worker's output/exit receipt is valid;
- the operation was authorized (authorization is validated separately);
- the requested NixOS runtime and selected profile are active;
- the transaction can be promoted or retried.

The complete chain remains:

`authorized attempt → durable intent → manager job evidence → PIDFD/unit invocation binding → process receipt → fresh runtime/profile observation → lifecycle validation`.

## Qualification cases

The real systemd VM test should include:

| Scenario | Required result |
|---|---|
| PIDFD resolves to exact unit, InvocationID copies agree, MainPID matches | Capture invocation evidence |
| PIDFD resolves to a foreign unit | Reject/hold |
| MainPID differs from the journal-owned worker PID | Reject/hold |
| PIDFD InvocationID differs from unit property | Reject/hold as a restart/race |
| InvocationID is empty/all-zero | Reject/hold as unavailable |
| InvocationID has wrong length | Reject malformed evidence |
| Worker PID was reused before capture | pidfd must continue to identify the originally opened process; no PID-only substitution |
| Unit has restarted under the same canonical unit name | New InvocationID must not be accepted for the old attempt |
| Manager is older than v253 | Explicit unsupported/hold; no silent PID-only fallback |
| Manager has unloaded the completed unit after restart | No inference from absence; continue journal/receipt/host-state reconciliation |

## Execution status

The pure evidence types, capture/validation helpers and deterministic/property tests are authored in the follow-on PR. They have not been compiled or run. The zbus adapter is not yet wired to call `GetUnitByPIDFD`; no live D-Bus or NixOS VM result is claimed.
