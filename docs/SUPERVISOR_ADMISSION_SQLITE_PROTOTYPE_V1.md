# Supervisor admission SQLite prototype

Status: **non-privileged storage prototype; v4 adds durable policy-serialized release barriers but is not a supervisor or production execution path**

Date: 2026-10-31

Schema: **v4**. Existing schema-v1, schema-v2 and schema-v3 databases are refused with an unsupported-schema error. They must be explicitly reconciled/re-admitted under verified authority; this prototype does not fabricate provenance, silently migrate old permits, or infer missing policy history.

Related work:
- Issue #111: supervisor-owned atomic admission store
- PR #110: pure Rust/Nix admission decision model
- PR #108: privileged supervisor authority handoff
- PR #105 / #109: systemd launch identity and worker environment

## Scope

This change introduces an isolated SQLite storage prototype behind the Rust native feature. It is exercised only with temporary databases in tests. It adds no daemon command, service unit, D-Bus method, polkit policy, root-owned path, StartUnit call, or mutation executor.

The store accepts opaque approval material, serialized authority provenance, permit wire bytes, and an admission event payload. It computes content digests and persists these payloads. It does not parse or verify provenance, approval signatures, signer trust, policy-epoch ownership, freshness, machine binding, permit signatures, or caller admission rights. Only a trusted supervisor may construct the request from a runtime receipt minted by the authority verifier. Those remain responsibilities of a future independent supervisor.

The store returns the stored permit bytes only after a single database transaction commits and a joined read-back validates all five admission records. Policy history and its current pointer are checked independently as part of the same database integrity checks.

## Storage model

One SQLite database is the authoritative prototype store. The base admission protocol uses a single BEGIN IMMEDIATE transaction to write:

1. admission_commits: exact transaction, attempt, plan, machine, approval-material digest/bytes, authority-provenance digest/bytes, permit digest/bytes, event digest, and commit ID.
2. authority_replays: globally unique replay key and its exact intent binding.
3. supervisor_permits: unique permit digest / attempt binding.
4. transaction_attempts: unique attempt ID and unresolved/resolved state.
5. admission_events: the immutable admission event payload and digest.
6. authority_policy_epochs: append-only versioned policy snapshots, emergency-revocation sets, update provenance and previous-record digests.
7. authority_policy_current: a singleton pointer to the latest immutable policy-epoch record.

The v4 release protocol adds five append-only record families in this same database: `payload_release_barriers` (one immutable barrier per admission), `payload_release_attempts` (one unique reservation before transport), `payload_release_uncertain` (ambiguous attempt marker), `payload_release_receipts` (exact worker acknowledgement), and `payload_release_policy_decisions` (per-epoch preserve or stop/recovery decisions).

A barrier, release-attempt reservation, uncertainty marker, receipt, and policy advancement are separate transactions but all serialize through the same SQLite writer lock. Policy advancement inserts its immutable epoch snapshot, all explicit decisions for outstanding unreceipted barriers, and the new current pointer in one BEGIN IMMEDIATE transaction. Barrier creation also uses BEGIN IMMEDIATE and compares the exact current epoch/record digest. Thus whichever writer commits first defines the ordering.

The v2 admission commit ID is a domain-separated BLAKE3 digest over the admission's stable identity and content digests, including authority-provenance digest. The v3 policy-epoch archive uses a separate domain-separated record digest and a previous-record hash chain. The v4 release barrier, attempt, receipt and policy-decision records each use separate domain-separated digests. These digests provide content integrity, not signatures or authorization tokens. The attempt ID must be generated once by the supervisor and reused when reconciling an ambiguous acknowledgement.

Database constraints enforce:
- primary/unique replay-key, attempt-ID, permit-digest and commit-ID bindings;
- one unresolved attempt per transaction via a partial unique index;
- foreign keys from the four companion admission rows to the same commit;
- immutable approval, permit, replay and admission-event rows;
- one-way transition from unresolved to resolved;
- one immutable release barrier, one release-attempt reservation and one receipt per admission/release ID;
- release records foreign-keyed to the exact admission and policy snapshot;
- immutable release records and a trigger preventing a stop/recovery decision from being downgraded to preserve.

The store uses WAL, synchronous=FULL, foreign keys, trusted_schema=OFF, a five-second busy timeout, and an application/schema ID. SQLite WAL is a same-host mechanism and is not suitable for placing this database on a network filesystem such as NFS; the supervisor database must remain on a supported local filesystem. Its shared-memory and WAL sidecars must remain in the same protected directory and under the same service ownership policy. It checks those runtime settings on every connection. It validates the stored approval, permit and event payload hashes plus the derived commit ID whenever an admission record is read; full integrity verification scans all stored commits. Database paths must be absolute and normalized, database files are set to mode 0600, and the immediate parent directory must be private (0700-equivalent on Unix). A deployment must additionally establish correct service ownership, safe path creation without TOCTOU races, and WAL/SHM sidecar access controls before privileged use.

## Admission behavior

The write path takes an IMMEDIATE transaction, checks the joined storage invariants, and reads both indexes inside that transaction:

- the global replay-key binding;
- the unresolved attempt for the requested transaction.

Outcomes:
- no replay and no unresolved attempt: insert all records and commit once;
- same replay key with the same transaction, plan, machine, approval-material digest and authority-provenance digest: return the original persisted attempt and permit, even if the caller proposes new attempt/permit bytes;
- same replay key with changed intent, approval material or authority provenance: reject replay conflict;
- a different replay key while the transaction has an unresolved attempt: reject/hold;
- replay lookup and unresolved-transaction lookup pointing at different commits: hold inconsistent storage;
- failed commit read-back: return an explicit uncertain outcome; the caller must not submit a worker and must retry by the same replay key.

A resolved attempt remains in the audit history. A later fresh replay key may create a new attempt for that transaction. A resolved attempt cannot be reopened or have its resolution evidence replaced.

## Fault tests

The Rust unit tests exercise:
- successful write of all five records and exact joined read-back;
- missing authority provenance rejection;
- idempotent retry after a committed transaction's acknowledgement is lost;
- changed plan/machine replay rejection;
- changed authority provenance on the same replay key rejection;
- unresolved transaction exclusion;
- one-way resolution and subsequent new attempt;
- injected errors after each individual table insert and immediately before commit, followed by reopen and retry;
- injected acknowledgement loss immediately after commit, followed by reopen and recovery of the same attempt;
- concurrent same-replay requests (one creation, one existing result);
- concurrent different-replay requests for one transaction (one creation, one hold);
- concurrent independent transactions;
- WAL/FULL/foreign-key settings, private database file mode, and symlink path rejection;
- v1 database refusal without authority-provenance migration;
- authority-provenance tamper detection during full integrity scan;
- v2 and v3 schema refusal without explicit migration;
- release barrier creation/retry, stale policy, expired authority, revoked signer, and subject-binding rejection;
- one-shot attempt reservation across store reopen, uncertain-after-attempt no-resend, and late receipt reconciliation;
- policy-update-first versus barrier-first orderings, mandatory in-flight decisions, stop/recovery downgrade rejection, and resolution blocking until an exact worker receipt exists;
- release barrier tamper detection in the full integrity scan.

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

SQLite FULL is a requested/checked SQLite synchronization mode, not proof that all filesystems, storage devices, virtual disks, and hardware honor durable flushes. WAL auto-checkpointing can introduce occasional commit-latency spikes around its default page threshold, and long-lived readers can prevent checkpoints from completing and allow WAL growth. Benchmark commit, checkpoint and read latency together rather than reporting only mean write time. Report the exact kernel, filesystem, mount options, SQLite build, device cache policy, and test harness when making durability claims.

## Benchmark targets

After safety tests, measure admission transaction + joined read-back separately from Nix build and activation:
- p50 / p95 / p99 latency;
- concurrent writer throughput;
- busy/timeout frequency;
- recovery latency after process death and lost acknowledgement;
- safe-hold and operator-intervention frequency;
- raw trial artifacts, seeds, database size, WAL size, filesystem, kernel and storage configuration.

Do not weaken synchronous=FULL, uniqueness constraints, or read-back to hit a latency target.


## Authority provenance v2

Every new v2 `AdmissionRequest` must carry a non-empty serialized authority-provenance record, bounded to 64 KiB. The store computes its BLAKE3 digest, includes that digest in the v2 commit ID, persists bytes and digest in the same immutable `admission_commits` row, includes them in joined reads, and compares them on replay retry. A retry with the same replay key but changed provenance bytes is a replay conflict.

This is deliberately a storage-integrity rule, not a cryptographic trust decision. The future supervisor must construct the bytes by serializing its verifier-minted runtime-only `VerifiedAuthorityReceipt`. The store does not accept a boolean or infer that the bytes are genuine. The supervisor remains responsible for signature verification and current policy epoch, emergency revocation and expiry checks before payload release.

Schema v1 is refused rather than auto-migrated. Existing v1 rows did not contain versioned verifier provenance; filling that gap with a placeholder would silently upgrade an old approval into a new capability. A future explicit migration/re-admission procedure must preserve the historical row as non-releasable audit data and obtain fresh authority before a new admission.


## Authority policy epoch archive v3

Schema v3 stores policy history in the same SQLite database as admission:

- `authority_policy_epochs` is append-only. Each row contains a non-zero epoch, policy ID, exact serialized policy bytes and digest, sorted emergency-revocation key IDs and digest, previous-record digest, update-provenance bytes and digest, creation timestamp, and immutable record digest.
- `authority_policy_current` is a singleton pointer to the current epoch and record digest.
- SQLite triggers require the first record to be epoch 1 with the all-zero genesis parent, each later row to extend exactly epoch (n-1), immutable historical rows, and a current-pointer update of exactly (n → n+1) to a record whose parent digest matches the previous current record.
- Policy JSON must carry the same policy ID and non-zero epoch as the request. Its bytes must be the exact `serde_json::to_vec(&AuthorityTrustPolicy)` representation used by the verifier's policy digest. The store recomputes the same domain-separated policy digest.
- Emergency-revocation IDs must be sorted, unique, non-empty tokens. Policy JSON is capped at 1 MiB, update-provenance at 64 KiB, and the emergency revocation set at 4,096 IDs / 64 KiB serialized.
- Initialization is explicit at epoch 1. Advancement requires the exact expected current epoch and record digest, and can only create epoch (n+1). Retrying the same already-committed update returns the existing record; changing the policy, revocation set, update provenance or parent conflicts.
- Current-policy and historical-policy reads verify the immutable record digest and the full contiguous history chain. Full `verify_integrity` repeats that verification.
- The v3 schema refuses v1 and v2 databases. It does not invent policy snapshots for earlier admissions or provide an implicit migration.

The policy-update proof is opaque to this store. Only a trusted supervisor may call the crate-private epoch API after independently verifying owner authority under the current policy. The archive records the update proof/provenance for audit and restart re-verification; it does not validate Ed25519, signer trust, challenge freshness, owner enrollment, or the caller's entitlement to rotate policy.

### Threat boundary and anti-rollback

This archive provides atomic local history, immutable-row constraints, digest validation and monotonic advancement while the database state itself is trusted. It does **not** protect against a privileged root attacker who can replace the database, disable triggers offline, or restore an older complete disk image. Root-owned permissions are an access-control boundary against unprivileged callers, not a hardware anti-rollback guarantee.

A TPM2 NV monotonic counter or remote quorum anchor may provide a stronger anti-rollback root on supported systems, but neither is assumed or implemented here. Such a backend needs its own hardware compatibility, provisioning, outage, recovery and destructive-reset qualification.

### Payload-release ordering remains a separate gate

A policy check followed by a later external payload write has a time-of-check/time-of-use race. A future release-barrier change must serialize policy advancement and payload-release authorization through this same store. The durable release barrier is the linearization point: after it commits, a later policy update treats the operation as already in-flight and must use separate stop/recovery policy. SQLite cannot atomically commit and write bytes to a worker; the supervisor must enforce the barrier-before-write ordering. This v3 PR does **not** implement that barrier and therefore does not enable payload release.


## Durable payload release barrier v4

The data-only v4 implementation in the admission store adds the release protocol from issue #134:

1. **Barrier creation.** Under BEGIN IMMEDIATE, load the exact committed admission and the requested historical policy snapshot. A new barrier is accepted only when the expected policy epoch and record digest are still current, the admission is unresolved, the authority provenance's policy ID/digest/epoch, signer/issuer, change action, audience, subject, Holon and replay key match the archived policy/admission, the key is not revoked, and the expiry has not passed. The release ID binds the admission/permit/plan/machine/provenance, signer, subject/audience, policy snapshot, payload digest and expiry.
2. **Historical retry.** An exact retry returns the same immutable barrier even after policy advancement. It is a read-only recovery of the same release identity. A changed payload or authority binding is a conflict.
3. **Policy advancement.** Advancing policy while any barrier lacks an exact worker receipt requires one explicit decision per outstanding barrier in the same transaction as the new policy record and current pointer. A stop/recovery decision is monotonic and cannot later be downgraded to preserve. If policy advancement commits first, the stale barrier request fails; if barrier creation commits first, policy advancement must explicitly preserve or stop/recover it.
4. **One-shot attempt.** The unique release-attempt row must commit before the supervisor writes any external payload bytes. A second attempt is rejected, including after process reopen.
5. **Uncertain delivery.** A crash, timeout or lost acknowledgement after the attempt row may mean no bytes, partial bytes or all bytes were delivered. The store records an immutable uncertainty marker and does not authorize resend. A late exact worker receipt can reconcile the original attempt, including where the worker's receipt timestamp precedes the supervisor's timeout-observation timestamp.
6. **Resolution.** An admission cannot be resolved while any release barrier lacks an exact receipt. Once the receipt is stored, an independent verifier still needs to qualify the worker and target post-state before recording the transaction's final resolution.

The storage layer only checks the structure and digest/policy bindings of the serialized authority-provenance fields. It does **not** verify the Ed25519 signature or mint the runtime-only `VerifiedAuthorityReceipt`; only the trusted supervisor may construct the barrier request from a receipt minted by the authority verifier in #118. Similarly, the storage layer persists a receipt digest and worker identity, but the trusted supervisor must authenticate that receipt before calling the acknowledgement API.

### Explicit delivery guarantee

v4 models **at-most-one authorized external release attempt per admission**, not exactly-once delivery. SQLite and an external process write are separate failure domains; no database schema can atomically commit and transmit bytes to a worker. A durable worker-side idempotent receiver keyed by release ID may improve liveness in a later phase, but it needs independent restart and crash qualification. Until then, ambiguous post-attempt state is safe-hold/reconciliation, never automatic resend.

v4 adds no D-Bus dispatch, worker transport, privileged daemon, root service, or payload executor. It establishes the persistence contract only.
