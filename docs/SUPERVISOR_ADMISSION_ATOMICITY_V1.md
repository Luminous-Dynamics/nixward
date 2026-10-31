# Supervisor authority admission: atomicity and recovery contract v1

Status: **qualification model and storage contract; no privileged supervisor or admission store is implemented**

Date: 2026-10-31

Related work:
- PR #108: privileged supervisor authority handoff
- PR #109: fixed worker environment at payload exec
- PR #105: immutable systemd worker launch envelope
- Issue #96: integrate systemd job evidence with journal-owned worker transactions

## 1. Decision

A supervisor admission is one logical commit containing four mutually bound durable facts:

1. One-shot approval replay consumption.
2. A machine-local, attempt-scoped verified permit.
3. A unique transaction attempt reservation.
4. A canonical journal admission entry.

All four records must carry the same transaction ID, attempt ID, replay key, plan digest, machine-binding digest, permit digest, and supervisor-generated commit ID.

The admission is not committed until the storage authority has crossed its documented durable commit point. A systemd manager call is forbidden before that point. The permit is not executable authority merely because a record can be deserialized.

This document defines a pure decision model and a recovery contract. It does not add a root service, D-Bus API, polkit rule, StartUnit path, or production storage implementation.

## 2. Existing persistence is not cross-store atomic

The existing AuthorityReplayLedger uses a SQLite database with WAL and synchronous=FULL. The ConfigTransaction journal is separately published as a file through a temporary-file, file-sync, rename, and parent-directory-sync sequence.

Those operations have distinct durability boundaries. A SQLite commit and a separate file publication do not become one ACID transaction by being called consecutively. Do not wire the existing replay consume operation and JSON journal persistence sequentially and describe the pair as atomic admission.

Two viable designs remain:

### A. One authoritative supervisor store

Place replay consumption, permit, attempt reservation, and the canonical admission journal record in one supervisor-owned transactional store. Enforce uniqueness and foreign-key constraints within that store. A single commit becomes the admission linearization point.

A JSON journal or UI-facing view may be materialized as a projection/outbox after commit, but it must not be a second source of truth for admission authority. Projection failure is reconciled from the authoritative store; it never causes a second attempt to be minted.

### B. A recoverable cross-store write-ahead protocol

If the existing file journal and replay database must remain separate, define an explicit durable prepare/commit protocol with a recovery table for every intermediate state. Every intermediate publication must be idempotent and must block worker release. A replay key consumed before attempt and journal publication must be recoverable into the same original attempt, not silently abandoned or reused.

Do not choose this option without demonstrating every crash-recovery edge. A sequence of unrelated writes is not an acceptable substitute.

## 3. Admission state model

The reference model reads four record slots:

| Slot | Meaning |
|---|---|
| replay consumption | the source approval's one-shot replay key is durably consumed |
| verified permit | the supervisor-issued machine/attempt permit is durably recorded |
| attempt reservation | the unique transaction attempt is durably reserved |
| journal entry | the canonical admission event is durably published |

The four records are complete only when all slots are present, well-formed, and byte-for-byte equal in every identity field. Zero records is an empty pre-commit state. Any partial set, malformed identity, or cross-record mismatch is inconsistent persistence and must hold.

The request carries transaction ID, replay key, plan digest, and machine-binding digest. The independent proof assessment requires all of:

- cryptographic signature validity;
- trusted signer and non-revoked authority;
- exact Nixward audience;
- exact challenge subject;
- exact local machine binding;
- exact ChangePlan / execution-intent binding;
- freshness at the supervisor's current time.

The booleans in the fixture are test inputs only. They are not a serialized capability or proof format. The root supervisor must perform real verification over the original signed approval material and local trust policy.

## 4. Recovery decisions

| Observed state | Decision | Why |
|---|---|---|
| Empty snapshot + valid proof | commit admission atomically | no durable admission exists yet |
| Complete snapshot + same replay/transaction/plan/machine | resume existing attempt | acknowledgement may have been lost after commit |
| Same replay key + changed transaction, plan, or machine | reject replay conflict | a one-shot approval cannot authorize a second intent |
| Different replay key + same transaction with unresolved attempt | hold unresolved attempt | no second mutation may overlap an unresolved attempt |
| Different replay key + resolved prior attempt | allow a new atomic admission | a fresh approval may authorize a later attempt |
| Partial records, malformed data, or mismatched commit IDs | hold inconsistent persistence | never guess which store committed |
| Invalid signature, signer, audience, subject, binding, or freshness | reject invalid proof | no durable admission may be created |

An ambiguous commit response is reconciled by reading the authoritative state:

- Complete and matching: return the original attempt and permit identity.
- Completely absent: retry admission only after re-verifying that the source proof remains fresh and the replay key remains unused.
- Partial or conflicting: hold for operator/recovery repair; do not submit a worker.

The same request must never create a new attempt just because its caller did not receive the commit acknowledgement.

## 5. Ordering relative to systemd

The admission commit is distinct from the systemd submission barrier.

1. Independently verify original approval proof, plan, machine binding, local policy, and exact launch envelope.
2. Commit replay consumption + permit + attempt reservation + canonical journal event in one durable admission transaction.
3. Read back and validate the committed identity.
4. Persist the existing write-ahead submission barrier.
5. Only then call StartUnit on the fixed Nixward unit.
6. Reconcile lost replies and manager restarts against the same attempt; never issue a second start for an unresolved attempt.
7. Continue through PIDFD / InvocationID worker attribution, process receipt, and fresh independent post-state.

This model does not weaken the pre-StartUnit barrier or replace the existing worker-lifecycle trace model. It qualifies the authority boundary before that trace begins.

## 6. Required storage invariants

The eventual supervisor store must demonstrate:

- one global unique constraint on the consumed replay key;
- one unique attempt identity;
- at most one unresolved mutation per transaction;
- permit, attempt and canonical journal rows reference one admission commit ID;
- a second writer cannot interleave admission for the same transaction/replay key;
- read-after-commit validates all four rows and their exact digests;
- crash before commit yields no partial admission;
- crash after commit but before acknowledgement returns the same existing attempt on retry;
- corruption, migration ambiguity, or partial cross-store state yields a hold;
- no permit private key or signing material appears in the Nix store, journal, process environment, or logs.

SQLite is a credible implementation candidate, not an automatic proof. Its documented atomicity assumes its storage and synchronization contracts. The actual filesystem, kernel, virtual disk, and hardware path still require fault qualification. In WAL mode, synchronous=NORMAL may lose a recently committed transaction after power loss; choose and qualify the required durability mode deliberately. The test model does not prove physical durability.

## 7. Qualification programme

The first gate is semantic, not performance. The new fixture is evaluated independently by Rust and pure Nix reference models. It includes all 16 possible presence masks for the four durable records, proof-negative controls, exact idempotent retry, replay-key rebinding, unresolved-attempt exclusion, partial publication, and conflicting commit identity.

Further implementation qualification should cover:

| Test | Initial target |
|---|---:|
| partial durable admission accepted as complete | 0 |
| invalid / expired / foreign proof admitted | 0 |
| replay key accepted for a different intent | 0 |
| duplicate attempt minted after lost commit acknowledgement | 0 |
| second unresolved attempt admitted for one transaction | 0 |
| StartUnit submitted before durable admission read-back | 0 |
| concurrent admission race produces more than one winner | 0 |
| crash points across every store write / sync / rename / commit edge | 100 trials per boundary initially |

Use process-kill and storage-failure injection first, then disposable VM reboot tests. Distinguish application-process crash, supervisor SIGKILL, kernel/VM crash, and actual power-loss testing. A subprocess test does not prove power-loss durability.

After all safety gates pass, benchmark admission commit and reconciliation separately from Nix build and activation. Report p50/p95/p99, raw trial artifacts, storage mode, filesystem, kernel, VM/device cache configuration, trial seeds, safe holds, and operator interventions. The existing proposal of sub-100 ms local journal publication may be used as a performance target, but it must not override durable commit semantics.

## 8. Model limitations

This PR's model is deliberately bounded:

- it checks decision semantics, not cryptographic signature correctness;
- it assumes the proof assessment came from an independent verifier;
- it checks record completeness and identity agreement, not the actual database transaction implementation;
- it does not emulate fsync, directory-entry durability, WAL checkpointing, or power failure;
- it does not observe systemd, PIDFD, InvocationID, worker receipts, or NixOS post-state;
- it does not authorize commands or mint runtime capabilities.

Passing the Rust and Nix models is necessary qualification for the admission design, not evidence that a privileged supervisor is ready.

## References

- SQLite, Atomic Commit: https://www.sqlite.org/atomiccommit.html
- SQLite, Transactional semantics: https://www.sqlite.org/transactional.html
- SQLite, WAL: https://www.sqlite.org/wal.html
- SQLite, synchronous pragma: https://www.sqlite.org/pragma.html
- systemd Manager API and PIDFD-based unit lookup: https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
