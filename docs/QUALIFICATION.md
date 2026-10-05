# Nixward Qualification

This document separates source review from executable qualification. A source
property is not called green merely because a corresponding code path exists.

| Gate | Status | Evidence required |
|---|---|---|
| Standalone Cargo topology | PASS_STATIC | No workspace-inherited dependencies or monorepo-relative paths. |
| Symthaea dependency provenance | PASS_STATIC | symthaea-core is pinned to exact commit a03379d7cea94d1c3409d258a0a6be02b2c79913. |
| Nix source boundary | PASS_STATIC | Flake builds from this repository rather than the former monorepo. |
| Daemon package binding | PASS_STATIC | NixOS module requires an explicit package. |
| Cargo dependency lock | PENDING_GENERATION | Cargo.lock must be generated and committed from the standalone manifest. |
| Nix vendor hash | PENDING_BUILD | Replace the deliberate fake hash only after a successful standalone build reports the exact value. |
| Unit/integration tests | PENDING_HOSTED | Hosted CI must execute the pinned test matrix. |
| Host mutation qualification | REVIEWED_STATIC | Exact-command, machine, freshness, replay, and rollback bindings exist in source; runtime receipts still require execution evidence. |
| Physical host execution | NOT_ATTEMPTED | No privileged execution has been performed from this review environment. |

## Sovereignty invariant

Cryptographic approval can authorize only an operation already admitted by the
host execution policy. It must never turn an architecturally forbidden
imperative or guest operation into an allowed host mutation.
