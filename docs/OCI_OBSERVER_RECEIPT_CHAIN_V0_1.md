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

A snapshot can be appended only when the underlying OCI snapshot reports source agreement and temporal stability and does not claim runtime enforcement. A changed boot ID cannot be appended as a normal snapshot; the caller must first append a `boot_epoch_transition` link at a globally monotonic sequence. Snapshot intervals must satisfy start < end. Transition links consume exactly one sequence number. A transition must be preceded by a snapshot link; a further transition requires at least one snapshot from the new epoch. A boot ID cannot be reused later in the same chain, and uppercase textual aliases are rejected rather than normalized.

Negative controls cover duplicate/rolled-back sequences, missing boot transitions, wrong observer identity, reordering and payload mutation. The verifier additionally requires canonical lowercase boot UUIDs, permits a transition only immediately after a snapshot, and rejects any boot ID already seen earlier in the chain. These checks are repeated during independent chain verification, so a caller cannot bypass them merely by constructing a new link and recomputing its unkeyed digest. Eleven source-level Rust tests cover the builder and imported-chain verification paths.

## Claim ceiling

The chain is **not yet connected to persistent storage**. It has no fsync/crash-consistency contract, no append-only remote service, no signature/key lifecycle, no revocation, and no externally anchored head. Hash-chain verification detects internal modification when a trusted starting point or final head is retained independently. These structural checks do not authenticate the transition source: a process able to call the in-memory builder can still assert a reboot unless a future signed transition receipt is checked against a trusted boot/observer source. It cannot detect full replacement/truncation when the attacker can replace the chain and the only copy of its head.

The chain is a distinct integrity layer, not an attestation. A signature would authenticate the signing observer and its bytes, not prove kernel truth. The current Nixward task-contract schema v3 binds an `OciRuntimeConsistencySnapshot` directly; it does not yet bind a durable receipt-chain link or an external anchor.

## Next qualification

See [Nixward issue #169](https://github.com/Luminous-Dynamics/nixward/issues/169) for durable monotonic sequence allocation, fsync-safe append, boot-epoch semantics, external anchoring, observer keys/revocation and live rollback tests.

No persistence, signature, external anchor, compilation or runtime test is claimed in this version.
