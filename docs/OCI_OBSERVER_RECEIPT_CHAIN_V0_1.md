# OCI Observer Receipt Chain v0.1

**Status:** in-memory, domain-separated hash-chain prototype. Not durable storage, a signature system, an external anchor or proof of observer/kernel trust.

## Link contents

Each link binds:
- schema version and link kind (`snapshot` or `boot_epoch_transition`);
- observer identity digest;
- boot ID;
- monotonically increasing sequence start/end;
- snapshot digest for snapshot links;
- previous link digest (absent only for the first link).

The link digest uses a dedicated domain separator, a length-prefixed serialized payload and BLAKE3. The verifier recomputes every link digest and checks observer identity, previous-link continuity, sequence monotonicity, snapshot sequence intervals and explicit boot transitions.

## Required behavior

A snapshot can be appended only when the underlying OCI snapshot reports source agreement and temporal stability and does not claim runtime enforcement. A changed boot ID cannot be appended as a normal snapshot; the caller must first append a `boot_epoch_transition` link at a globally monotonic sequence. Snapshot intervals must satisfy start < end. Transition links consume exactly one sequence number.

Negative controls cover duplicate/rolled-back sequences, missing boot transitions, wrong observer identity, reordering and payload mutation. Six source-level Rust tests currently exercise these conditions.

## Claim ceiling

The chain is **not yet connected to persistent storage**. It has no fsync/crash-consistency contract, no append-only remote service, no signature/key lifecycle, no revocation, and no externally anchored head. Hash-chain verification detects internal modification when a trusted starting point or final head is retained independently. It cannot detect full replacement/truncation when the attacker can replace the chain and the only copy of its head.

The chain is a distinct integrity layer, not an attestation. A signature would authenticate the signing observer and its bytes, not prove kernel truth. The current Nixward task-contract schema v3 binds an `OciRuntimeConsistencySnapshot` directly; it does not yet bind a durable receipt-chain link or an external anchor.

## Next qualification

See [Nixward issue #169](https://github.com/Luminous-Dynamics/nixward/issues/169) for durable monotonic sequence allocation, fsync-safe append, boot-epoch semantics, external anchoring, observer keys/revocation and live rollback tests.

No persistence, signature, external anchor, compilation or runtime test is claimed in this version.
