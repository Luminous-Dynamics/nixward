# Semantic execution evidence verifier v1

Status: read-only source-level verifier and deterministic negative controls; not a live host observer or trust authenticator.

## Build and run

    cargo run --release --no-default-features --bin nixward-semantic-verify -- --input results/systemd-execution-evidence.json

Exit codes: 0 = internally consistent verified success/recovery classification; 2 = malformed input or invocation error; 3 = reconciliation required; 4 = safe hold.

The verifier is a pure Rust module and CLI. It does not open D-Bus connections, pidfds, journals, profile links or system files. It only evaluates a captured strict v1 JSON envelope. Its output always carries semantic-consistency-only-source-authentication-unverified. This program alone cannot prove that its input came from the real systemd manager, kernel or NixOS host.

## Derived operation semantics

The verifier keeps three independent host-state observations:

- `selected_profile_store_path`: persistent `/nix/var/nix/profiles/system` profile target;
- `running_system_store_path`: `/run/current-system`;
- `boot_default_store_path`: independently observed bootloader default entry.

The operation contract is:

| Mode | Persistent system profile | Running system | Bootloader default |
|---|---|---|---|
| switch | candidate | candidate | candidate |
| test | predecessor | candidate | predecessor |
| boot | candidate | predecessor | candidate |

This distinguishes the test-only running state from the persistent system profile and boot target. It prevents the verifier from inferring that a candidate running in memory is also the next-boot default. See the [NixOS Manual: Changing the Configuration](https://nixos.org/manual/nixos/stable/) and the [NixOS generations and rollback documentation](https://wiki.nixos.org/wiki/Cheatsheet).

Expected unit ActiveState/SubState/Result are part of the approved operation contract. This permits a correctly completed oneshot unit to be inactive/dead with Result=success; inactive is not automatically failure.

## Evidence rules

The evaluator requires durable admission read-back, an explicit `Manager.Subscribe()` completion, and installation of D-Bus match rules for both JobNew and JobRemoved before StartUnit. It then requires exactly one StartUnit call, one JobNew and one matching JobRemoved for the returned object path, identical numeric job ID/unit/manager boot, PIDFD-mapped unit and InvocationID, matching transaction/attempt/commit/plan/machine digests, a durable process receipt, the declared unit state, exact NixOS profile post-state and every required runtime health check.

systemd documents that JobNew/JobRemoved signals are sent only after `Subscribe()` has been invoked by at least one client. The capture must therefore record both the Manager.Subscribe completion and the D-Bus match-rule installation; a match rule without Manager.Subscribe is not sufficient.

The returned D-Bus job path must encode the same numeric job ID as JobNew and JobRemoved. The PIDFD-derived worker identity must be captured while the process is still alive (before its receipt's exit timestamp), then durably persisted before the release record. The recovery path is held to the same bar: its own JobRemoved result, job path/ID, unit, InvocationID, PIDFD mapping, release ordering, process exit receipt and post-job unit snapshot must agree with the original transaction/plan/machine binding.

A failed/canceled/timeout activation is not success. It can be classified as verified recovery only with a separately authorized recovery attempt, a matching recovery receipt, independently observed predecessor selected/running/boot-default profiles and passing predecessor health checks. Otherwise it is reconciliation-required or safe-hold.

Safe-hold requires an explicit fence marker. Missing or ambiguous evidence without such a fence is reconciliation-required. Safe-hold is never scored as successful recovery.

## Deliberate limitations

- JobNew/JobRemoved and timestamps are supplied as captured observations; source authenticity is not established by the pure evaluator.
- PIDFD mapping must be performed by a trusted capture component using the systemd manager API; this verifier only checks the reported binding and boot identity.
- NixOS profile and runtime observations must be obtained by a separate privileged read-only collector and authenticated/pinned to the target host/boot.
- The record does not prove storage durability or authority signature validity. Those are checked by independent admission/provenance layers.
- The evaluator is not a supervisor and cannot retry, release payload, roll back, or un-fence a transaction.

## Tests authored

The library adds 19 controls for switch/test/boot semantics, JobRemoved=done with wrong post-state, test changing boot default, boot activating the running candidate, lost StartUnit reply, Manager.Subscribe and signal-match ordering, subscription ordering, job-ID and object-path mismatch, PIDFD InvocationID mismatch, PIDFD identity after worker exit, foreign worker identity, payload release before worker identity persistence, runtime health failure, foreign unit identity, duplicate dispatch, strict unknown-field decoding, and recovery with its own job/worker attribution. A Nix check is added to compile and run these tests with default features disabled.

No Rust compile, unit test, flake evaluation, live systemd capture or disposable-VM test is claimed here.
