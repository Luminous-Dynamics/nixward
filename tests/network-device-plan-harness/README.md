# Network device planner M0 harness

This small Cargo package compiles the pure planner source directly so its unit
tests can run without building the entire Symthaea monorepo. The Rust source
under test remains `../../../src/network_device_plan.rs`; this harness is not
a second implementation and has no networking adapter.

Run from the Nixward repository root:

```sh
cargo fmt --manifest-path tests/network-device-plan-harness/Cargo.toml -- --check
cargo test --locked --manifest-path tests/network-device-plan-harness/Cargo.toml --all-targets
```

Direct dependencies are exact-pinned and the harness has a committed
`Cargo.lock`. CI uses `--locked`, so dependency resolution must not silently
change the dependency graph. The workflow runs the exact same source on the
monorepo's pinned Rust 1.96.0 baseline and the currently selected Rust 1.99.0
compatibility toolchain.

This harness validates only pure model/planner code. It does not validate live
Netlink observation, device ownership claims, kernel mutation, authorization,
recovery, throughput, or production readiness. A passing result is not device
or appliance qualification.
