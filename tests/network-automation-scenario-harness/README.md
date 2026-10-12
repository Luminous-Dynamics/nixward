# Network automation deterministic scenario harness

This isolated Rust package evaluates the **decision/receipt model** declared by
the checked-in task and fault-fixture corpora. It is deliberately not a
network simulator, observer, adapter, privileged broker or production safety
proof.

From the Nixward repository root:

```sh
python3 -m unittest discover -s tests/network-automation-corpus -p 'test_*.py' -v
python3 tests/network-automation-corpus/validate_corpus.py
cargo fmt --manifest-path tests/network-automation-scenario-harness/Cargo.toml -- --check
cargo test --locked --manifest-path tests/network-automation-scenario-harness/Cargo.toml --all-targets
NIXWARD_GIT_COMMIT="$(git rev-parse HEAD)" cargo run --locked --quiet --manifest-path tests/network-automation-scenario-harness/Cargo.toml --bin nixward-network-automation-scenario-harness > scenario-receipt.json
```

The emitted JSON envelope includes domain-separated BLAKE3 identities for exact
raw task corpus, task schema, fault fixtures, fixture schema, Cargo.toml,
Cargo.lock and evaluator source bytes. It includes the source revision passed
through `NIXWARD_GIT_COMMIT`, compiler and Cargo identities captured by the
build script, target OS/architecture, and a digest over the serialized receipt.
The serializer recomputes that digest and refuses to emit a receipt if the
payload no longer matches. No wall-clock timestamp or random value is included,
so repeated execution under the same source, lockfile, inputs and toolchain
yields byte-identical output. If `NIXWARD_GIT_COMMIT` is not supplied, the
receipt says `source-revision-not-injected`; that is honest but less useful
provenance than a pinned commit.

The evaluator uses an explicit fault-class-to-outcome table that is independent
of each fixture's expected decision. It fails closed for unknown fault kinds,
task/fixture identity mismatches, duplicate IDs, missing task coverage,
unsupported expected decision/state pairs and any fixture that permits
production mutation. It marks crashed or ambiguous operations Indeterminate
and fences conflicting modeled writes. The simulated-mutation field records
whether a modeled apply event occurred, including apply-before-crash or
apply-before-verified-recovery; it never means a real network write occurred.
The positive create *success oracle* is accepted only in a virtual-lab layer.

The test-only resource-fence model rejects a subsequent write to the same
resource after an Indeterminate result, permits unrelated scopes, and permits
fence removal only when a recovery-receipt digest is supplied. This is a
unit-tested in-memory model, not a distributed lock, cryptographic receipt
verifier, or real transaction journal. The modeled recovery verifier checks
declared target/post-state/read-back predicates and digest formatting only; it
does not authenticate a signature or independently read a real device.

Each fault fixture declares an `expected_transition_trace` array; the Rust
evaluator produces the actual modeled trace and compares the two as an
explicit machine check. For example, an apply-before-crash case records
modeled apply, fence installation, and a conflicting retry rejected by that
fence; a recovered case records modeled apply followed by modeled
restoration/read-back; a bounded-create positive control records modeled
desired-state apply and post-state read-back. Mutation tests forge an expected
trace and require the receipt to fail. The model has no sockets or backend
adapter and does not mutate a host network.

The natural-language assertions in the fixture document are carried through
into the receipt for traceability; they are **not** claimed as individually
executed assertions. This harness checks only the explicitly named machine
invariants and modeled decision/receipt-state transitions. An additional
simulator must later exercise protocol-level behavior, genuine independent
observation, external-writer races, management-path failure and recovery.

The Python validator remains the corpus/schema structural gate. This Rust
crate does not implement general JSON Schema 2020-12 validation. The workflow
records compiler identity and runs both the validator and this harness at the
exact PR head. Passing these checks does not qualify Netlink completeness,
Batfish semantics, containerlab protocol behavior, live mutation, hardware,
throughput, failover or production deployment.

This crate forbids unsafe Rust and has only the exact-pinned dependencies
already present in the isolated planner harness. The CLI performs no runtime
subprocess, network I/O or host mutation.
