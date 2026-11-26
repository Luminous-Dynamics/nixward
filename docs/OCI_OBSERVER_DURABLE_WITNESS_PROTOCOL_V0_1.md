# OCI Observer Durable Checkpoint and Witness Protocol v0.1

**Status:** protocol specification and qualification plan. This document does not implement a persistent store, a witness service, Merkle proofs, or runtime authorization. It is the next implementation contract for Nixward issue #169.

## 1. Objective and assurance boundary

The signed observer checkpoint prototype authenticates a provisioned Ed25519 key and binds a verifier nonce, machine/boot identity, observer sequence, exact snapshot and verified receipt-chain head, previous checkpoint digest, and validity interval. The current relying party must retain the previous digest/sequence outside the observer, but Nixward does not yet persist that state or anchor it independently.

This protocol closes the next gap: an observer/relying-party crash, a lost witness acknowledgement, local database rollback, or a split-view witness must never turn an unknown checkpoint into authority.

The invariant is:

> A consequential admission is permitted only when the relying party has a crash-durable local record of the exact verified checkpoint, a current independently verifiable witness quorum receipt for that checkpoint, and a locally retained prior state that the witness evidence proves it extends.

This is an evidence-admission protocol, not a claim that a signed checkpoint proves kernel truth. It does not replace an enforcement backend or an independent effect observer.

## 2. Trust domains and identities

Keep these domains separate:

1. **Observer:** measures the declared runtime profile and signs a checkpoint with an operator-provisioned key. It is not allowed to mint owner authority or witness receipts.
2. **Verifier / relying party (RP):** validates the observer key, nonce, snapshot, receipt chain, boot epoch and sequence. It retains accepted state outside the observer and is the only component that may mark a checkpoint admission-ready.
3. **Local durable journal:** stores pending and accepted records using crash-durable transactions. It is protected from the agent and observer, but a privileged host attacker may still restore or replace the entire journal.
4. **Witnesses:** independently operated services with separate administrative credentials, signing keys, durable high-water marks and append-only logs. They do not trust the candidate, observer or RP's claim that a head is current.
5. **Enforcer and effect observer:** remain separate. A witness acknowledgement does not establish that a BPF hook is attached or that a network request was denied.

Each observer is keyed by the tuple (observer_id, machine_id). Each checkpoint is keyed by (observer_id, boot_id, sequence, checkpoint_digest). The digest includes the exact existing signed checkpoint bytes and signature. Witness requests additionally bind a protocol version and the prior witness checkpoint.

A cgroup path, PID, container name or local database row ID is not a stable security identity. The checkpoint continues to bind the observer's machine/boot identity and exact receipt-chain terminal state; live task identity and enforcement generation must be separately bound at the task/effect layer.

## 3. State machine

A checkpoint must pass through these states. Only **WITNESS_QUORUM_CONFIRMED** is admission-eligible, and even then only while its evidence lease remains current.

| State | Meaning | New consequential authority |
|---|---|---|
| **UNSEEN** | No local record for this checkpoint | Deny |
| **PREPARED** | Exact verified checkpoint and idempotency key committed locally; witness request may be sent | Deny |
| **WITNESS_QUORUM_CONFIRMED** | Required witnesses signed the same checkpoint commitment and the RP verified their inclusion/consistency proofs | Eligible only after all task and runtime checks |
| **RECONCILIATION_REQUIRED** | Commit/ack outcome unknown, a crash occurred, or witness response is incomplete | Deny until reconciliation |
| **QUARANTINED** | Fork, rollback, equivocation, invalid proof, identity conflict, revocation or corruption detected | Deny; operator recovery required |

State transitions are monotonic. There is no implicit transition from RECONCILIATION_REQUIRED to confirmed based on a timeout, a retry count, a local timestamp, or the observer's assertion. A retry must use the same idempotency key and exact request bytes.

## 4. Checkpoint and witness protocol

### 4.1 RP verifies observer checkpoint

The RP first performs the existing observer checkpoint verification using:
- an operator-provisioned trusted observer key and current generation/revocation state;
- a fresh 32-byte nonce generated from the RP's OS CSPRNG and consumed once;
- the exact independently measured OCI snapshot digest;
- the independently verified receipt-chain head, boot ID and terminal sequence;
- the RP's last independently retained checkpoint digest/sequence;
- a bounded validity interval and RP time.

Any mismatch rejects the checkpoint before it enters the durable journal. The RP does not trust the checkpoint's own statement of its expected parent or sequence.

### 4.2 RP prepares a pending checkpoint

In one serializable local transaction, the RP:
1. checks that the current accepted head still equals the head used for verification;
2. checks that no unresolved pending checkpoint exists for this observer;
3. inserts the exact checkpoint digest, observer/machine/boot identity, sequence, chain head, prior checkpoint digest, key ID/generation, challenge digest and expiry;
4. inserts a unique idempotency key derived from the domain-separated request digest;
5. changes the observer admission state to RECONCILIATION_REQUIRED / PREPARED;
6. commits durably before making any witness network request.

A unique constraint must reject duplicate (observer_id, boot_id, sequence) values with a different checkpoint digest. Concurrent writers must serialize; a read-check-write sequence outside one transaction is not sufficient.

### 4.3 RP submits an idempotent witness request

The request is domain-separated and binds at least:
- protocol/schema version;
- observer ID and machine ID;
- boot ID and monotonic sequence;
- signed checkpoint digest;
- receipt-chain head digest and prior observer checkpoint digest;
- prior accepted witness tree size/root for this witness;
- nonce/challenge digest;
- key ID/generation and checkpoint expiry.

Witnesses return the same receipt for an exact idempotent retry. A duplicate idempotency key with different request bytes is a hard conflict and quarantines the observer. An RPC timeout is an unknown outcome, not a rejection and not success.

### 4.4 Witness validates and appends

Each witness independently verifies:
- the request signature and schema;
- observer identity and currently accepted key generation/revocation epoch;
- strict per-observer sequence and previous-checkpoint continuity;
- that the checkpoint extends the witness's own retained prior checkpoint;
- that the challenge is within the allowed freshness window;
- that an already-seen idempotency key has exactly the same request digest.

The witness appends the request commitment to an append-only Merkle log and returns:
- witness ID, key ID/generation and signature;
- exact request/checkpoint digest;
- tree size, tree root and leaf index;
- inclusion proof for the leaf;
- consistency proof from the RP's previously retained witness tree head to the returned tree head;
- witness time and bounded receipt validity;
- the exact prior witness tree size/root the request extended.

A witness must reject an append whose supplied prior head does not match its retained head, unless it can prove that the supplied head is a valid earlier prefix. It must not issue two valid signatures for conflicting roots at the same log size.

### 4.5 RP verifies witness quorum

For the high-assurance profile, require **3-of-4 independently administered witnesses**. The threat assumption is at most one Byzantine witness in the four-member set; keys, operators, storage and network paths must be meaningfully independent. Any two 3-of-4 quorums overlap in at least two witnesses, so at least one common witness is honest under this assumption. That honest witness must durably refuse to sign two different checkpoint digests for the same observer parent/sequence. A 2-of-3 rule would not guarantee an honest member in the intersection: the two quorums could overlap only at the Byzantine witness. This is not a generic consensus protocol and does not protect against two colluding or commonly compromised witnesses.

The RP requires three distinct witness receipts out of four provisioned, independently administered trust domains. One unavailable witness can be tolerated; if fewer than three can provide current consistent evidence, consequential authority remains blocked. The RP verifies every receipt against a pinned witness key set, including:
- signature, witness identity and current key generation;
- exact observer/checkpoint/request digest;
- Merkle inclusion proof;
- Merkle consistency proof from the RP's last retained root;
- monotonic tree size and accepted witness time window;
- quorum members are distinct and not a common administrative alias.

All counted witnesses must attest to the same checkpoint digest. Their log roots need not be identical because they are independent logs, but each must prove append-only continuity from its own previously retained head. A conflict or a verified fork from any trusted witness moves the observer to QUARANTINED, even when another witness returned success.

For verifier-unit tests, one- and two-witness sub-threshold evidence may be exercised, but the durable admission store rejects it. A low-assurance local-only experiment must be separately labelled and must not use the 3-of-4 admission finalization path.

### 4.6 RP finalizes locally

After quorum verification, the RP atomically:
1. stores the exact witness receipts and proof bytes;
2. stores each witness's new tree size/root and receipt digest;
3. stores the newly accepted observer checkpoint digest, boot ID and sequence;
4. marks the checkpoint WITNESS_QUORUM_CONFIRMED;
5. clears the unresolved pending marker.

Only after this transaction commits may the RP expose a verified witness-backed admission result. The task contract must bind the resulting opaque admission token to the exact task, runtime subject, policy generation and expiry. That integration is a later stage; this protocol document does not imply it exists.

## 5. Crash and unknown-outcome recovery

The RP must never allocate the next observer sequence or admit a new consequential action while a previous checkpoint is pending or uncertain.

| Failure point | Recovery behavior |
|---|---|
| Before local prepare commits | Re-run observer-chain verification against the retained head; no checkpoint is considered pending |
| Local prepare committed, request not sent | Re-send exact stored request with the same idempotency key |
| Request sent, witness did not append | Retry exact request; witness returns append or a deterministic rejection |
| Witness appended, response lost | Query/retry by idempotency key; verify the same signed receipt and proofs |
| One witness accepted, second/third unavailable | Remain pending; no new admission; retry or operator-authorized degraded-mode recovery |
| Quorum response received, local finalize not committed | Re-fetch/replay exact witness receipts and finalize idempotently |
| Local journal reports accepted but remote witness head is older | Quarantine: possible local rollback, stale witness view or restore |
| Witness reports a higher sequence/root than local journal | Quarantine and reconcile the full checkpoint ancestry |
| Conflicting roots or request digests are verified | Quarantine; preserve all conflicting receipts for investigation |
| Database missing, malformed or integrity-check fails | Quarantine; never recreate an empty store and reset sequence automatically |
| Observer key revoked or generation changed | Reject new admission; preserve historical evidence for audit only |

Recovery is a protocol operation, not a best-effort repair. If the RP cannot prove continuity from the last trusted checkpoint, no new authority is issued.

## 6. Local journal requirements

The first implementation uses the repository's existing SQLite dependency behind a native-only module, without making observer snapshot collection depend on remote witness availability. The initial source slice is now present in `src/observe/checkpoint_store.rs`: it persists PREPARED records and exact witness request bytes, enforces idempotent retry/pending-state rules, and records RECONCILIATION_REQUIRED. It deliberately cannot mark a checkpoint WITNESS_QUORUM_CONFIRMED.

Required configuration and invariants:
- one database per RP trust domain, outside the candidate/observer writable namespace;
- restrictive owner-only file and directory permissions; reject symlinked or unexpected database paths;
- WAL mode with synchronous=FULL for the durability profile, foreign keys enabled, bounded busy timeout and explicit schema version;
- one BEGIN IMMEDIATE transaction for compare-and-append/state transition; unique constraints enforce observer/boot/sequence and idempotency-key uniqueness;
- a separate transaction for witness finalization; never hold a database write transaction open across network I/O;
- store raw request/receipt bytes or canonical bytes plus exact digests, not only decoded fields;
- verify stored digests on every read used for admission;
- reject downgrade, unknown schema version, duplicate identity rows and database integrity-check failure;
- never delete old accepted heads as part of ordinary compaction; compact only after independently witnessed archive proof and a tested recovery path.

SQLite is local crash durability, not an external anti-rollback root. SQLite WAL requires same-host processes and is not suitable as a shared multi-host database. A root/administrator who can restore the database and its WAL can still roll back the local view; remote witnesses provide the independent high-water marks. SQLite documents that WAL with synchronous=NORMAL can lose a just-committed transaction after power loss, while synchronous=FULL adds a WAL sync on each commit to improve durability. The actual storage device, filesystem, virtualization and power-loss behavior still require fault-injection tests. See [SQLite WAL](https://sqlite.org/wal.html) and [SQLite synchronous pragma](https://sqlite.org/pragma.html#pragma_synchronous).

## 7. Witness independence and anti-equivocation

A remote log endpoint is not automatically an independent witness. The qualification must record operator, cloud/account, signing-key custody, data replication, DNS/control plane and administrative access for every witness. Two URLs fronting the same database and key are one trust domain.

The design uses established transparency-log primitives: an inclusion proof binds a leaf to a signed tree head; a consistency proof shows that a newer tree head extends a previously retained prefix; the RP persists the latest trusted head. This is aligned with the [Sigstore Rekor consistency-proof design](https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md#94-consistency-proofs). Witness quorum and trust-domain independence are additional Nixward policy requirements, not properties automatically supplied by Rekor.

Witness key rotation must be signed by the previous trusted key or approved through a separate operator trust-root update. Revocation must prevent new admission immediately after the RP learns the revocation epoch. A historic valid signature remains useful for audit but cannot restore current admission authority.

## 8. Required failure-injection matrix

The implementation is not qualified by happy-path tests alone. Add deterministic tests for:

1. crash before/after every SQLite transaction boundary;
2. process kill after request send and before response;
3. witness append with dropped acknowledgement;
4. idempotent retry and conflicting duplicate idempotency key;
5. two concurrent RP writers for the same observer;
6. observer process restart and host reboot with sequence continuity;
7. restore of an older database and older WAL snapshot;
8. missing, truncated, reordered and corrupted local records;
9. stale or mismatched witness tree head;
10. invalid inclusion and consistency proof;
11. one unavailable witness, one Byzantine witness, two unavailable witnesses and two conflicting witness views;
12. witness key rotation/revocation during a pending checkpoint;
13. local commit succeeds but caller sees an I/O error;
14. witness quorum succeeds but local finalization crashes;
15. full database replacement with internally consistent old rows.

A test that merely reopens the same database after a normal process restart does not qualify power-loss durability or rollback resistance. Run the crash suite in a disposable VM with snapshots and injected hard power-off. Preserve the exact image, filesystem, SQLite library, kernel, storage configuration, test seed and failure point in the evidence manifest.

## 9. Qualification targets

These are proposed hard gates, not measured performance:
- 0 admission from PREPARED, RECONCILIATION_REQUIRED or QUARANTINED;
- 0 accepted stale/revoked/forked checkpoint;
- 100% rejection of the enumerated rollback, conflicting-idempotency and proof-substitution controls;
- 100% recovery to the same accepted checkpoint after response-loss and process-crash permutations, or explicit quarantine;
- 3-of-4 witness confirmation for high-assurance profile;
- no sequence reuse after process restart or host reboot;
- p95 local journal transaction latency and p95 witness quorum latency separately measured;
- p95 time to revoke admission after key/witness revocation measured, target <1 second after revocation delivery in the isolated lab;
- publish availability and safe-denial rates during witness outages; no silent degraded mode.

A zero observed violation remains sample-limited. Report case-family counts, repeated crash seeds, per-failure-point results and confidence bounds. Do not turn deterministic fault enumeration into a production probability claim.

## 10. Implementation sequence

1. Add native-only OciObserverCheckpointStore with schema migration, compare-and-append, pending recovery, finalize, read-head and integrity-check operations.
2. Add a deterministic fake witness implementing the exact request/receipt protocol; use it to test retry, fork and crash semantics before networking.
3. Add a Merkle inclusion/consistency proof verifier with checked test vectors; do not write a custom production log until verifying interoperable vectors.
4. Add a real witness adapter behind a narrow trait and a pinned trust store; no agent-controlled endpoints or key discovery.
5. Add 3-of-4 quorum state and VM crash/restore qualification.
6. Only then expose a non-deserializable witness-backed admission token to task binding. Keep runtime activation disabled until live enforcer attachment and independent effect receipts pass separately.

## 11. Industry comparison and benchmark positioning

- [NVIDIA OpenShell v0.1.10](https://docs.nvidia.com/openshell/v0.1.10/about/architecture) documents a strong runtime layer: isolated workloads, separate trusted supervisor, mediated network requests and fail-closed supervisor disconnect behavior. Nixward must use it as a matched runtime baseline, not imply parity.
- [IETF RATS RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) separates attester, verifier and relying-party roles and explains why nonce freshness alone does not prove that each underlying claim was freshly measured after the nonce.
- [Sigstore Rekor](https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md#94-consistency-proofs) provides the transparency-log inclusion/consistency pattern and requires clients to retain the latest checkpoint.
- The October 2026 [IETF AI Agent Security Evaluation Profiles draft](https://datatracker.ietf.org/doc/html/draft-hcf-bpm-agent-security-benchmark-profiles-00) is work in progress, not a standard; it reinforces that benchmark metrics must declare the exact SUT boundary and scenario profile.

Nixward's competitive claim should be **portable, proof-carrying authority and independently witnessed effect provenance across runtime backends**. To substantiate that claim, compare identical task/model/prompt/tool/policy/seed/resource profiles across OpenShell, rootless Podman, Kubernetes and MicroVM; publish the same ATR scenario families, all unauthorized committed effects, safe completion/partial-completion, refusal/abandonment, attribution, evidence completeness, p50/p95/p99 latency and overhead. Do not collapse hard safety gates into a compensatory score.

---

**Claim boundary:** this is a proposed protocol and executable qualification specification. The SQLite store, witness API, quorum, Merkle proof verifier, crash tests, owner task-token integration and runtime enforcement are not implemented by this document.


## 12. Current implementation status (26 November 2026)

Implemented source slice:
- `src/observe/checkpoint_store.rs`, exported by `observe::checkpoint_store`.
- Owner-only directory/database path checks, SQLite WAL and `synchronous=FULL`, foreign keys, bounded busy timeout and schema version 1.
- `BEGIN IMMEDIATE` prepare transaction binding observer/machine, checkpoint digest, boot/sequence, authenticated previous-checkpoint digest, snapshot/chain digests, key ID/generation, expiry, exact request bytes, request digest and derived idempotency key.
- One unresolved checkpoint per observer. Exact byte-identical retries return `AlreadyPrepared`; different bytes for the same checkpoint quarantine; a distinct checkpoint cannot supersede a pending one.
- Explicit `RECONCILIATION_REQUIRED` transition and retrieval of the exact pending request after an uncertain witness outcome.
- Seven source-level regression tests.

Not implemented:
- witness request transport or server;
- signed witness receipts, Merkle inclusion/consistency proof verifier, witness-key lifecycle or 3-of-4 quorum;
- witness-head persistence and quorum finalization;
- any public operation producing a witness-confirmed admission token;
- task-contract consumption, runtime enforcer attachment or effect verification;
- crash/power-loss VM fault injection or Rust test execution.

The branch currently contains 104 source-level Rust test functions, none compiled or executed. The local store is not a defence against a privileged attacker restoring the DB and WAL together; external witness high-water marks remain required.


## 13. Source implementation status (26 November 2026)

The branch now contains a first executable source layer for witness verification and durable quorum finalization:

- `src/observe/witness_transparency.rs` implements RFC 9162 Merkle tree hashing, inclusion proof and consistency proof verification with SHA-256 domain prefixes; strict signed tree-head receipts; exact leaf binding to witness ID/key generation, checkpoint digest, canonical request digest and idempotency key; witness-key validity/revocation checks; and opaque per-receipt/quorum verification results.
- The signed tree-head wire structure is a **Nixward-specific, domain-separated envelope**, not the RFC 9162 Certificate Transparency v2 wire protocol. It uses the RFC 9162 tree hash/proof algorithms and includes an explicit `sha256-rfc9162` algorithm identifier in signed bytes.
- `OciObserverWitnessRequest` is an opaque request built only from `VerifiedOciObserverCheckpoint`; the store no longer accepts arbitrary caller-supplied bytes as a checkpoint request.
- `src/observe/checkpoint_store.rs` schema v2 has atomic initialization and v1→v2 migration. `finalize_witness_quorum` accepts only an opaque verified quorum, enforces a 3-of-4 profile (maximum three receipts), rechecks observer/witness key generation and revocation at commit time, checks witness-receipt age, compares each proof's prior tree head against the locally retained witness head, stores exact receipt bytes and new tree heads, and atomically advances the accepted observer checkpoint. A verified mismatch quarantines the observer.
- The test-only fixture creates real Ed25519 signatures and proof objects for store integration tests; it is not a production witness server.

The transparency verifier also includes `verify_witness_tree_head_equivocation`: it verifies two tree-head signatures under the same provisioned witness key and returns opaque evidence if the same witness/key generation signed different roots for the same tree size. **This is a detector, not a gossip transport.** The conflicting statements must be delivered through an independent gossip monitor or cross-witness channel. An isolated relying party cannot detect a split view it has never received.

The source tree contains 131 test functions (15 task contract + 24 policy containment + 27 OCI observer + 13 receipt chain + 18 signed checkpoint + 13 checkpoint store + 21 witness transparency). None has been compiled or executed. There is no production witness service, gossip transport, remote trust distribution, TEE/measured-boot integration, task-contract consumption, live enforcement, or effect verification. SQLite/WAL remains locally rollbackable by a privileged host attacker; the external witness is still needed as the independent high-water authority.


## 14. Cross-client gossip and durable equivocation quarantine

A separate relying party may never see the conflicting tree head another client received. Merkle inclusion and consistency proofs only validate one presented view against one retained prior head; they do not prove that all clients were shown the same view. RFC 9162 §11.3 explicitly leaves gossip out of scope and says clients can detect split views by comparing signed tree heads. Trillian's Gossip Hub is an experimental example of collecting and cross-comparing observer views; Sigstore's Rekor design also describes witnesses and stable checkpoints for split-view detection.

Nixward now has two receiver-side pieces:
- `verify_witness_tree_head_equivocation` cryptographically verifies two tree heads signed under the same provisioned witness key, for the same witness/key generation/tree size, and detects different roots.
- `OciObserverCheckpointStore::record_witness_equivocation` persists both raw signed heads and their digests in `witness_equivocation_evidence`, quarantines every local observer whose accepted witness state includes that witness, and prevents future finalization against the quarantined witness identity.

The gossip transport is still not implemented. A future monitor must collect signed tree heads from multiple independently operated relying parties/witnesses and deliver conflicting pairs to this receiver. Each relay or mirror must be outside the candidate's control. Do not infer global consistency merely because this local store has seen no conflict.

## 15. Quorum safety correction

The high-assurance store now requires **3-of-4**, not 2-of-3. With four trust domains and at most one Byzantine witness, two 3-member quorums intersect in at least two members, which includes at least one honest witness. Honest witnesses must bind one checkpoint digest to the observer's parent/sequence and refuse a second conflicting branch. A 2-of-3 quorum can intersect only at the single Byzantine member, so it does not provide the same quorum-intersection safety property.

The 3-of-4 profile tolerates one unavailable witness. If only two witness receipts are available, read-only work may continue under its own existing authority, but new consequential checkpoint-backed mutations remain blocked.

Current schema version is 4. Migrations from earlier un-fingerprinted schemas quarantine old pending/accepted state rather than assuming that a key ID/generation label identifies the same public key. New checkpoint and witness records bind the exact public-key hex used during signature verification, and finalization rejects same-ID/same-generation key substitution.
