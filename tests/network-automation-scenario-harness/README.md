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
cargo run --locked --quiet --manifest-path tests/network-automation-scenario-harness/Cargo.toml --bin nixward-network-automation-scenario-harness > scenario-receipt.json
```

The emitted JSON envelope includes BLAKE3 identities for exact raw task corpus,
task schema, fault fixtures, fixture schema, Cargo.lock and evaluator source
bytes. It includes the compiler identity captured by the build script and a
digest over the serialized receipt. No wall-clock timestamp or random value is
included so repeated execution under the same source, lockfile, inputs and
toolchain yields byte-identical output.

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

The natural-language assertions in the fixture document are carried through
into the receipt for traceability; they are **not** claimed as individually
executed assertions. This harness checks the named machine invariants and
expected decision/receipt-state oracles. An additional simulator must later
exercise concrete state transitions, external-writer races, management-path
failure and recovery.

The Python validator remains the corpus/schema structural gate. This Rust
crate does not implement general JSON Schema 2020-12 validation. The workflow
records compiler identity and runs both the validator and this harness at the
exact PR head. Passing these checks does not qualify Netlink completeness,
Batfish semantics, containerlab protocol behavior, live mutation, hardware,
throughput, failover or production deployment.

This crate forbids unsafe Rust and has only the exact-pinned dependencies
already present in the isolated planner harness. The CLI performs no runtime
subprocess, network I/O or host mutation.
