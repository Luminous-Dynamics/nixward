# Systemd invocation-aware restart decisions v1

Status: **pure restart decision contract authored; production reconciler and live D-Bus integration not wired**

Date: 2026-10-30

## Problem found in the existing recovery matrix

The earlier `decide_worker_start_recovery()` classifier accepts a matching canonical unit name as enough to return `ObserveExistingMatchingUnit` for an ambiguous start. That is a useful name-level lookup result, but it does not establish that the loaded unit object is the same service invocation as the durable attempt.

A systemd unit name can be reused across service invocations. Nixward must therefore distinguish:

- canonical unit identity (which transaction attempt owns the unit name);
- systemd InvocationID (which service invocation is currently represented);
- process identity (which exact process the PIDFD/boot/start-time receipt identifies).

A name match is only the first filter.

## New stricter classifier

`decide_worker_start_recovery_with_invocation()` takes three inputs:

1. `WorkerStartIntent`: PreparedNotSubmitted, SubmissionMayHaveOccurred, or UnitInvocationIdentityPersisted.
2. `ManagerUnitObservation`: canonical unit not queried, matching, conflicting, absent or unavailable.
3. `ManagerInvocationObservation`: not queried, exact expected invocation, conflicting invocation, missing, unavailable or unsupported.

It returns a conservative directive. No result grants mutation authority or terminal transaction success.

## Normative decision rules

### PreparedNotSubmitted

A start can be submitted only when the durable journal proves the request was not previously sent, the canonical manager lookup reports the unit absent, and manager invocation support is not explicitly unsupported. A contradictory invocation identity is held. A manager that cannot provide the required PIDFD-based identity is held rather than silently downgraded.

### SubmissionMayHaveOccurred

- Manager unit not queried/unavailable: query the canonical manager unit.
- Foreign/conflicting unit: hold.
- Canonical unit absent: reconcile read-only target state before any new attempt. There is no same-attempt replay.
- Matching canonical unit with invocation not queried: query PIDFD/unit invocation identity.
- Matching unit with exact invocation: resume observation of that exact invocation only.
- Conflicting invocation: hold.
- Missing/unavailable invocation: hold for identity resolution.
- Unsupported manager: hold.

### UnitInvocationIdentityPersisted

This intent has an expected InvocationID in durable evidence. A canonical unit-name lookup that reports absent is not enough to conclude the invocation disappeared: first query the manager by the persisted InvocationID. Only an exact invocation/unit match permits observation. If the invocation lookup is unavailable or missing, proceed through read-only worker and host reconciliation; never replay the attempt.

If manager and invocation lookups contradict one another (for example, canonical name absent but exact InvocationID lookup claims a unit), hold for identity conflict rather than selecting whichever observation is more convenient.

## Important distinction: no hidden retry path

The following are the only paths that may return `ObserveExactAttemptInvocation`:

- the attempt is ambiguous or has persisted invocation identity;
- the canonical unit observation is matching;
- invocation evidence has been independently checked and is exactly the expected attempt invocation.

A matching unit name alone returns `QueryUnitInvocationIdentity`, never observation. Missing, malformed, unsupported or conflicting invocation identity never resumes observation and never triggers a same-attempt start.

## Executable test coverage

The new exhaustive contract enumerates:

- 3 durable intent states;
- 5 manager-unit states;
- 6 invocation states;

for 90 combinations. Additional tests specifically prove that:

- a canonical unit match alone cannot resume ambiguous worker observation;
- a conflicting/missing/unavailable/unsupported invocation never resumes;
- a previously persisted InvocationID is queried even when canonical name lookup says absent;
- an ambiguous intent never returns the initial-start directive;
- observation requires both a matching canonical unit and exact invocation identity.

## Scope and limitations

This is a pure decision contract only. It does not call D-Bus, acquire the Nixward interlock, load or validate the journal, obtain a pidfd, authenticate a process receipt, or inspect NixOS runtime/profile state. The production reconciler must perform those operations in the order documented by Issue #96.

The older `decide_worker_start_recovery()` remains a name-level classifier for existing tests/compatibility. It must not be used alone as the final recovery/observation gate for ambiguous systemd attempts; callers must apply the new invocation-aware decision after manager identity evidence is available.
