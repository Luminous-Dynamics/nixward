# Systemd feature build and test qualification v1

Status: **Nix check derivation authored; no Nix evaluation or test execution claimed**

Date: 2026-10-30

## Problem

The default `nixward-cli` package intentionally sets `doCheck = false` and builds the CLI feature only. The live systemd D-Bus adapter is compiled only behind the optional `systemd` feature. Consequently, the existing package check does not compile or execute the adapter's test module.

A source-reviewed PIDFD/D-Bus implementation can therefore remain syntactically or type-invalid without the normal Nix package check noticing.

## New check

The flake now exposes:

`checks.<system>.systemd-feature-tests`

It is a separate `rustPlatform.buildRustPackage` derivation with:

- the repository's exact `Cargo.lock`;
- the Rust compiler and Cargo obtained from the version declared in `rust-toolchain.toml`;
- `buildNoDefaultFeatures = true`;
- `buildFeatures = [ "systemd" ]`;
- `checkNoDefaultFeatures = true`;
- `checkFeatures = [ "systemd" ]`;
- library-only Cargo build and test targets;
- `doCheck = true`.

The `systemd` feature itself enables `native`, so the adapter's dependencies are present without implicitly enabling the CLI, TUI or daemon features. The check runs the full library unit-test suite with systemd enabled, including the crate-private zbus adapter module and the pure job/PIDFD evidence contracts.

The package build and this test check both use the Rust toolchain parsed from `rust-toolchain.toml` via `pkgs.makeRustPlatform`, rather than silently using a separate Nixpkgs-default Rust version.

## Commands

To execute the complete matrix of flake checks:

```sh
nix flake check --show-trace
```

To build only the systemd feature test derivation on x86_64 Linux:

```sh
nix build .#checks.x86_64-linux.systemd-feature-tests --show-trace
```

The equivalent local Cargo command is:

```sh
cargo test --locked -p nixward --lib --no-default-features --features systemd
```

## Evidence boundary

A successful derivation proves that, for the exact flake input revisions and source tree, the systemd-enabled library built and its configured library tests passed in the Nix build environment.

It does **not** prove:

- real UNIX_FD transmission to systemd;
- compatibility with systemd 253+ or a particular systemd release;
- correct JobRemoved behavior against a real manager;
- restart/reboot reconciliation;
- journal durability under power loss;
- worker receipt authenticity;
- actual NixOS runtime/profile activation;
- production supervisor integration.

Those require the separate disposable NixOS VM qualification described in the PIDFD and systemd observer documents. Do not count this unit-test derivation as a live D-Bus or VM result.

## Execution status

The flake expression and derivation are authored. No `nix flake check`, `nix build`, Cargo test, build, rustfmt or Clippy command was run in this work session. The output marker is created only after the Nix build/test phases succeed, but no such output has been observed yet.
