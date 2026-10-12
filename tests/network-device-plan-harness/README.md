# Network device planner M0 harness

This small Cargo package compiles the pure planner source directly so its unit
tests can run without building the entire Symthaea monorepo. The Rust source
under test remains `../../src/network_device_plan.rs`; this harness is not a
second implementation and has no networking adapter.

Run from the Nixward repository root:

```sh
cargo fmt --manifest-path tests/network-device-plan-harness/Cargo.toml -- --check
cargo test --manifest-path tests/network-device-plan-harness/Cargo.toml
```

Direct dependencies are exact-pinned. The first CI run records the resolved
transitive dependency lockfile as a run artifact; commit a reviewed lockfile
before treating the harness as a reproducible long-term conformance gate.

This harness validates only pure model/planner code. It does not validate live
Netlink observation, device ownership claims, kernel mutation, authorization,
recovery, throughput, or production readiness. A passing result is not device
or appliance qualification.
