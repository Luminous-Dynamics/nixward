# Supervisor admission SQLite prototype v1

Status: **non-privileged storage prototype; not a supervisor, verifier, or production execution path**

Date: 2026-10-31

Related work:
- Issue #111: supervisor-owned atomic admission store
- PR #110: pure Rust/Nix admission decision model
- PR #108: privileged supervisor authority handoff
- PR #105 / #109: systemd launch identity and worker environment

## Scope

This change introduces an isolated SQLite storage prototype behind the Rust native feature. It is exercised only with temporary databases in tests. It adds no daemon command, service unit, D-Bus method, polkit policy, root-owned path, StartUnit call, or mutation executor.

The store accepts opaque approval material, permit wire bytes, and an admission event payload. It computes content digests and persists them. It does not verify approval signatures, signer trust, freshness, machine binding, permit signatures, or the caller's right to request admission. Those remain responsibilities of a future independent supervisor.

The store returns the stored permit bytes only after a single database transaction commits and a joined read-back validates the four durable records.

## Storage model

One SQLite database is the authoritative prototype store. A single BEGIN IMMEDIATE transaction writes:

1. admission_commits: exact transaction, attempt, plan, machine, approval-material digest and bytes, permit digest and bytes, event digest, and commit ID.
2. authority_replays: globally unique replay key and its exact intent binding.
3. supervisor_permits: unique permit digest / attempt binding.
4. transaction_attempts: unique attempt ID and unresolved/resolved state.
5. admission_events: the immutable admission event payload and digest.

The commit ID is a domain-separated BLAKE3 digest over the admission's stable identity and content digests. It is not a signature or authorization token. The attempt ID must be generated once by the supervisor and reused when reconciling an ambiguous acknowledgement.

Database constraints enforce:
- primary/unique replay-key, attempt-ID, permit-digest and commit-ID bindings;
- one unresolved attempt per transaction via a partial unique index;
- foreign keys from all four records to the same commit;
- immutable approval, permit, replay and admission-event rows;
- one-way transition from unresolved to resolved.

The store uses WAL, synchronous=FULL, foreign keys, trusted_schema=OFF, a five-second busy timeout, and an application/schema ID. It checks those runtime settings on every connection. It validates the stored approval, permit and event payload hashes plus the derived commit ID whenever an admission record is read; full integrity verification scans all stored commits. Database paths must be absolute and normalized, database files are set to mode 0600, and the immediate parent directory must be private (0700-equivalent on Unix). A deployment must additionally establish correct service ownership, safe path creation without TOCTOU races, and WAL/SHM sidecar access controls before privileged use.

## Admission behavior

The write path takes an IMMEDIATE transaction, checks the joined storage invariants, and reads both indexes inside that transaction:

- the global replay-key binding;
- the unresolved attempt for the requested transaction.

Outcomes:
- no replay and no unresolved attempt: insert all records and commit once;
- same replay key with the same transaction, plan, machine and approval-material digest: return the original persisted attempt and permit, even if the caller proposes new attempt/permit bytes;
- same replay key with changed intent or approval material: reject replay conflict;
- a different replay key while the transaction has an unresolved attempt: reject/hold;
- replay lookup and unresolved-transaction lookup pointing at different commits: hold inconsistent storage;
- failed commit read-back: return an explicit uncertain outcome; the caller must not submit a worker and must retry by the same replay key.

A resolved attempt remains in the audit history. A later fresh replay key may create a new attempt for that transaction. A resolved attempt cannot be reopened or have its resolution evidence replaced.

## Fault tests

The Rust unit tests exercise:
- successful write of all four records and exact joined read-back;
- idempotent retry after a committed transaction's acknowledgement is lost;
- changed plan/machine replay rejection;
- unresolved transaction exclusion;
- one-way resolution and subsequent new attempt;
- injected errors after each individual table insert and immediately before commit, followed by reopen and retry;
- injected acknowledgement loss immediately after commit, followed by reopen and recovery of the same attempt;
- concurrent same-replay requests (one creation, one existing result);
- concurrent different-replay requests for one transaction (one creation, one hold);
- concurrent independent transactions;
- WAL/FULL/foreign-key settings, private database file mode, and symlink path rejection.

The failpoints are private test hooks, not environment variables or production IPC controls. They test application transaction rollback and process reopen behavior; they do not simulate kernel crash, storage-controller cache loss, filesystem corruption, or physical power loss. A SQLite COMMIT error is surfaced as an uncertain outcome with the deterministic commit ID; the caller must stop and reconcile by the same replay key rather than submitting or generating a new attempt.

## Remaining qualification gates

Before any production supervisor integration:
1. Exact-head cargo test and nix flake check must pass.
2. Add subprocess SIGKILL/reopen tests with process termination at deterministic write boundaries.
3. Run VM crash/reboot tests on the target filesystem and VM/device-cache configuration.
4. Validate concurrency and lock behavior under multi-process load, not only threads.
5. Audit root ownership, database path creation, WAL/SHM sidecars, backup/restore, schema migration, and database corruption behavior.
6. Add real approval-material verification and machine-local permit signing outside this storage module.
7. Demonstrate that the permit cannot reach a worker before successful commit and read-back.
8. Independently review the full threat model before adding a root service or systemd submission.

SQLite FULL is a requested/checked SQLite synchronization mode, not proof that all filesystems, storage devices, virtual disks, and hardware honor durable flushes. Report the exact kernel, filesystem, mount options, SQLite build, device cache policy, and test harness when making durability claims.

## Benchmark targets

After safety tests, measure admission transaction + joined read-back separately from Nix build and activation:
- p50 / p95 / p99 latency;
- concurrent writer throughput;
- busy/timeout frequency;
- recovery latency after process death and lost acknowledgement;
- safe-hold and operator-intervention frequency;
- raw trial artifacts, seeds, database size, WAL size, filesystem, kernel and storage configuration.

Do not weaken synchronous=FULL, uniqueness constraints, or read-back to hit a latency target.
