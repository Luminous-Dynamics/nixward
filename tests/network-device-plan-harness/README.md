# Network device planner M0 harness

This small Cargo package compiles the pure planner source directly so its unit
tests can run without building the entire Symthaea monorepo. The Rust source
under test remains `../../../src/network_device_plan.rs`; this harness is not
a second implementation and has no networking adapter.

Run from the Nixward repository root:

```sh
python3 -m unittest discover -s tests/network-device-plan-harness -p 'test_lock_policy.py'
python3 tests/network-device-plan-harness/check_lock_policy.py tests/network-device-plan-harness/Cargo.lock
cargo fmt --manifest-path tests/network-device-plan-harness/Cargo.toml -- --check
cargo test --locked --manifest-path tests/network-device-plan-harness/Cargo.toml --all-targets
```

Direct dependencies are exact-pinned and the harness has a committed
`Cargo.lock`. CI uses `--locked`, so dependency resolution must not silently
change the dependency graph. The workflow runs the exact same source on the
monorepo's pinned Rust 1.96.0 baseline and Rust 1.99.0, and records compiler
identities. The workflow also runs 11 standard-library-only regression tests for its dependency-free
policy guard, checking all listed malicious crate names/releases and verifying `arrayref 0.3.10`,
`append-only-vec 0.1.9`, `internment 0.8.7`, and the affected Greentic release.
The version policy blocks `arrayref >=0.3.10` until a maintainer reviews it. The local denylist is supplemental to `cargo-audit`, not a replacement for current advisory-database checks.
A separate job runs pinned `cargo-audit 0.22.2` against the lock file from
outside the checkout, without asking Cargo to resolve or rewrite the project's
dependencies. These are supplemental guards, not a substitute for fresh
advisory data or proof that a dependency is malware-free.

This harness validates only pure model/planner code. It does not validate live
Netlink observation, device ownership claims, kernel mutation, authorization,
recovery, throughput, or production readiness. A passing result is not device
or appliance qualification.
