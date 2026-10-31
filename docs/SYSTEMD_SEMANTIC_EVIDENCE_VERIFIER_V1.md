# Semantic execution evidence verifier v1

Status: read-only source-level verifier and deterministic negative controls; not a live host observer or trust authenticator.

## Build and run

    cargo run --release --no-default-features --bin nixward-semantic-verify -- --input results/systemd-execution-evidence.json

Exit codes: 0 = internally consistent verified success/recovery classification; 2 = malformed input or invocation error; 3 = reconciliation required; 4 = safe hold.

The verifier is a pure Rust module and CLI. It does not open D-Bus connections, pidfds, journals, profile links or system files. It only evaluates a captured strict v1 JSON envelope. Its output always carries semantic-consistency-only-source-authentication-unverified. This program alone cannot prove that its input came from the real systemd manager, kernel or NixOS host.

## Derived operation semantics

- switch: selected profile, running system and boot default all point to the candidate closure.
- test: selected profile and boot default remain the predecessor; running system is the candidate.
- boot: selected profile and boot default point to the candidate; running system remains the predecessor.

Expected unit ActiveState/SubState/Result are part of the approved operation contract. This permits a correctly completed oneshot unit to be inactive/dead with Result=success; inactive is not automatically failure.

## Evidence rules

The evaluator requires durable admission read-back before subscription, JobRemoved subscription before StartUnit, exactly one StartUnit call, one JobNew and one matching JobRemoved for the returned object path, identical numeric job ID/unit/manager boot, PIDFD-mapped unit and InvocationID, matching transaction/attempt/commit/plan/machine digests, a durable process receipt, the declared unit state, exact NixOS profile post-state and every required runtime health check.

A failed/canceled/timeout activation is not success. It can be classified as verified recovery only with a separately authorized recovery attempt, a matching recovery receipt, independently observed predecessor selected/running/boot-default profiles and passing predecessor health checks. Otherwise it is reconciliation-required or safe-hold.

Safe-hold requires an explicit fence marker. Missing or ambiguous evidence without such a fence is reconciliation-required. Safe-hold is never scored as successful recovery.

## Deliberate limitations

- JobNew/JobRemoved and timestamps are supplied as captured observations; source authenticity is not established by the pure evaluator.
- PIDFD mapping must be performed by a trusted capture component using the systemd manager API; this verifier only checks the reported binding and boot identity.
- NixOS profile and runtime observations must be obtained by a separate privileged read-only collector and authenticated/pinned to the target host/boot.
- The record does not prove storage durability or authority signature validity. Those are checked by independent admission/provenance layers.
- The evaluator is not a supervisor and cannot retry, release payload, roll back, or un-fence a transaction.

## Tests authored

The library adds controls for switch/test/boot semantics, JobRemoved=done with wrong post-state, test changing boot default, boot activating the running candidate, lost StartUnit reply, subscription ordering, job-ID mismatch, PIDFD InvocationID mismatch, foreign worker identity, payload release before worker identity persistence, duplicate dispatch, strict unknown-field decoding and separately authorized recovery. A Nix check is added to compile and run these tests with default features disabled.

No Rust compile, unit test, flake evaluation, live systemd capture or disposable-VM test is claimed here.
