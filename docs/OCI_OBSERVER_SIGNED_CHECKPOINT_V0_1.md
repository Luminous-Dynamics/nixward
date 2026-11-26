# OCI Observer Signed Checkpoint v0.1

**Status:** source-level Ed25519 checkpoint-signing and verification prototype. Not a production remote-attestation system, durable anti-rollback service, external transparency witness, or runtime-enforcement proof.

## Purpose

The in-memory receipt chain authenticates its internal structure only relative to a trusted head. This module adds an attributable, challenge-bound signature over a checkpoint that commits to:

- observer identity digest;
- provisioned key ID and generation;
- machine identity digest and canonical Linux boot UUID;
- monotonic observer sequence;
- exact runtime snapshot digest and independently verified receipt-chain head;
- previous accepted checkpoint digest;
- verifier-generated challenge nonce digest;
- issue and expiry times.

It reuses the repository's existing Ed25519 dependency and strict verification pattern. It does not add a cryptographic dependency.

## Protocol

### 1. Provisioned trust record

The relying party obtains a `TrustedOciObserverKey` from an operator-controlled trust store, not from the candidate workload. It binds:

- observer ID and machine ID;
- key ID and generation;
- Ed25519 public key;
- validity start/end;
- revocation time, if revoked.

Key provisioning and the trust-store transport are outside this module. A production deployment should protect the trust store through an owner-controlled channel and use hardware-backed key custody where available. The observer signing key must never be placed in the guest or exposed to the agent.

### 2. Freshness challenge

The verifier generates a fresh 32-byte nonce from an OS CSPRNG and sends it to the observer. The checkpoint includes a domain-separated BLAKE3 digest of that nonce. The verifier supplies the exact nonce to the verifier function and consumes it once in its own state.

This follows the nonce-based freshness model in IETF RATS architecture (RFC 9334). A nonce establishes that the signed evidence was produced after the challenge was generated; it does not prove that the underlying measurements were generated at that time. The observer must not sign stale cached claims as though newly observed.

### 3. Deterministic signature

The payload is encoded by an explicit field-order, length-prefixed binary encoder and a dedicated domain separator. JSON is only a transport format and is not the signing format. Both the envelope and payload reject unknown deserialized fields.

The Ed25519 signature authenticates the exact payload bytes under the provisioned key. The checkpoint digest separately commits to the signing bytes, public key and signature.

### 4. Verifier policy

Verification requires both a provisioned key and an explicit `OciObserverCheckpointExpectation`. The expectation contains:

- expected observer and machine identities;
- the current 32-byte challenge nonce;
- exact expected snapshot and chain-head digests, plus expected boot ID and terminal sequence, supplied only after independent chain verification;
- the previous checkpoint digest retained by the relying party;
- the minimum previously accepted sequence;
- relying-party current time and maximum permitted checkpoint lifetime.

The verifier rejects mismatched identity, key ID/generation, challenge, snapshot, chain head, previous checkpoint, or sequence. It rejects checkpoints that have not yet been issued, have expired, exceed the policy lifetime, outlive the key validity window, or use a key revoked for new admission.

A key revoked after a checkpoint was signed must not authorize a new task merely because the historical signature is mathematically valid. Historical audit verification is a separate operation and is not implemented by this admission verifier.

### 5. Returned capability

Successful verification returns an opaque `VerifiedOciObserverCheckpoint` with private fields and no deserialization implementation. It is evidence that the exact signed checkpoint passed this verifier's policy inputs.

It is **not**:
- an owner-signature or task-authorization capability;
- a proof that kernel or procfs observations are truthful;
- a measured-boot quote or TEE attestation;
- proof that the policy is attached to a live cgroup;
- a persistent anti-rollback record;
- an external timestamp or transparency-log inclusion proof.

The task contract does not consume this token yet. Schema-v3 remains `runtime-observed-not-enforced-v3`.

## Anti-rollback and witness requirement

The `previous_checkpoint_blake3` field and sequence check only prevent rollback when the relying party retains the latest accepted checkpoint digest and sequence outside the candidate/observer's mutable storage. The verifier must atomically persist the newly returned checkpoint digest and sequence before accepting the next checkpoint.

If that relying-party state is lost or rolled back, this module cannot detect whole-history replacement. A separate witness/anchor service is still required for cross-host recovery and privileged local-attacker resistance.

A future durable design should use crash-consistent local append, plus signed checkpoints or Merkle-tree consistency proofs from one or more independent witnesses. It should not trust a single local file or a single remote server's self-asserted latest head. Sigstore Rekor's architecture is a useful transparency-log reference: inclusion proofs bind entries to signed tree heads; consistency proofs establish that a later tree is an append-only extension of a previously retained checkpoint. That is a witness protocol, not something this module currently implements.

## Error handling

Every missing, malformed, expired, revoked, stale, contradictory or unsupported item is a rejection. Callers must not convert these outcomes into a warning or fallback pass. If the relying party cannot establish its previous checkpoint state, it must fail closed or perform an explicit recovery ceremony with independently reviewed authority.

## Tests

Eighteen source-level Rust tests cover:

1. valid signing and verification against a separate trust record;
2. payload tampering;
3. nonce mismatch/replay;
4. revoked-key rejection;
5. checkpoint expiry;
6. future issue time;
7. previous-checkpoint fork/rollback;
8. non-increasing sequence;
9. key-generation substitution;
10. machine identity substitution;
11. unknown envelope/payload field rejection;
12. key-validity-window enforcement;
13. maximum checkpoint lifetime;
14. snapshot digest substitution;
15. receipt-chain head substitution;
16. a valid second checkpoint extending the exact retained first checkpoint digest with a fresh nonce and increasing sequence;
17. boot-epoch substitution against the independently verified chain;
18. sequence mismatch against the independently verified chain terminal sequence.

These test functions have not been compiled or executed in this environment.

## Research alignment

- IETF RATS Architecture, [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html): attester, verifier and relying-party roles; nonce-based freshness; appraisal policy and trust-anchor separation.
- Sigstore Rekor architecture, [consistency proofs](https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md#94-consistency-proofs): retain the latest signed checkpoint and verify append-only continuity.
- NVIDIA OpenShell [v0.1.10 architecture](https://docs.nvidia.com/openshell/v0.1.10/about/architecture): runtime supervisor/workload boundary and mediated controls. This is a runtime comparator, not an attestation mechanism.

## Next qualification

1. Integrate only after the independent OCI snapshot and receipt-chain verifier have produced the exact digests passed into the expectation.
2. Add operator-provisioned key enrollment, rotation and revocation state with authenticated distribution.
3. Persist the relying party's accepted checkpoint digest and sequence with crash-consistent writes.
4. Add an independent witness protocol with signed checkpoint receipts and consistency proofs.
5. Test crash/restore, old-checkpoint replay, key rotation, revocation, nonce reuse and witness outage in a disposable NixOS VM.
6. Keep network activation disabled until A5 enforcement and A6 effect verification are separately demonstrated.

**Claim boundary:** this is a signed checkpoint prototype with verifier-supplied freshness and trust inputs. It does not implement production key custody, durable storage, remote witness/anchoring, measured boot, task-contract consumption or active runtime enforcement.


## Relying-party journal implementation update (26 November 2026)

The broader Nixward branch now contains a separate native-only `observe::checkpoint_store` module. It stores the exact verified checkpoint parent and identity fields plus exact witness request bytes in SQLite WAL with `synchronous=FULL`, and supports single-pending-checkpoint compare-and-append, exact retry, conflict quarantine, and `RECONCILIATION_REQUIRED` recovery. The opaque verified checkpoint now exposes its authenticated previous-checkpoint digest for this parent check.

This is only the durable PREPARED/reconciliation slice. There is no public witness-confirmed/finalize operation, witness transport, Merkle proof verifier, quorum or task-contract integration. Do not treat a locally prepared checkpoint as admission authority. See [OCI_OBSERVER_DURABLE_WITNESS_PROTOCOL_V0_1.md](OCI_OBSERVER_DURABLE_WITNESS_PROTOCOL_V0_1.md) and [issue #170](https://github.com/Luminous-Dynamics/nixward/issues/170).


## Downstream witness verification update (26 November 2026)

A separate `observe::witness_transparency` module now accepts only the opaque `VerifiedOciObserverCheckpoint` token to create a canonical witness request. It verifies signed witness tree heads, RFC 9162 SHA-256 Merkle inclusion/consistency proofs, exact checkpoint/request/idempotency leaf commitment, current witness key identity/generation/revocation and distinct trust-domain quorum membership. The STH/receipt envelope is Nixward-specific and domain-separated; it is not a full RFC 9162 CT v2 log wire implementation.

The native SQLite store now has a 2-of-3 finalization method that requires the opaque verified quorum and rechecks current observer and witness trust at the durable commit boundary. It compares each proof's previous tree head to the locally retained witness high-water mark and quarantines on mismatch. It persists exact receipt bytes and advances accepted state atomically.

The module can verify two conflicting validly signed same-size tree heads as equivocation evidence, but it does not yet implement gossip distribution or automatically quarantine every relying party that has not received the evidence. It also does not launch or operate real witnesses. See [OCI_OBSERVER_DURABLE_WITNESS_PROTOCOL_V0_1.md](OCI_OBSERVER_DURABLE_WITNESS_PROTOCOL_V0_1.md).


## 3-of-4 witness and exact trust-key binding update (26 November 2026)

The durable admission store now enforces 3-of-4 independent witness receipts. This is a deliberate correction to the earlier 2-of-3 proposal: for four provisioned trust domains and at most one Byzantine member, any two three-member quorums intersect in at least two members, guaranteeing at least one honest overlap. A 2-of-3 quorum can intersect only in the Byzantine witness. Honest witnesses must refuse to append conflicting checkpoint digests for the same observer parent/sequence.

The signed checkpoint token now exposes the exact verified signer public key in addition to key ID/generation. The store persists that public key and rechecks it against the current observer trust record at finalization. Witness receipt tokens likewise carry the exact verified public key; the store rechecks it against current witness trust and the retained per-witness high-water record. A reused ID/generation with changed key bytes is rejected.

The receiver-side gossip path verifies two conflicting same-size signed tree heads, persists both raw statements, and quarantines local observers that have used the witness. No network gossip transport is implemented; independent monitor delivery remains a separate requirement.
