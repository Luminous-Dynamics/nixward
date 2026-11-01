# Activation profile source harness

This small crate compiles and runs tests from the exact production source file
`src/action/activation_profile.rs` without requiring the unrelated sibling
monorepo path dependencies of the full Nixward package.

The dependency versions are pinned in Cargo.toml. CI uses Rust 1.96.0 and
generates a lockfile during the isolated test job. This is an E0/E1 source
qualification harness, not a second production crate or runtime authority.

Run:

```sh
cargo test --manifest-path research/activation-profile-check/Cargo.toml
```
