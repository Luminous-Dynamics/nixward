# Systemd Transaction Crash-Cut VM Qualification v1

This qualification is a disposable NixOS/QEMU execution stage stacked on the pure crash-cut matrix in PR #117 and specified by issue #141.

## Run

```sh
nix build .#checks.x86_64-linux.systemd-transaction-crash-cut-vm --no-link -L
```

The check uses the repository's pinned flake inputs and a single headless NixOS guest. The test driver runs one fixed, harmless systemd template worker on an explicit writable qcow2 root image reused across abrupt VM termination/reboot. It does not run the Nixward daemon, invoke the host transaction API, run a NixOS activation, call a real participant, or modify the machine running the test.

## What is actually cut

The template worker writes its systemd InvocationID and a start marker under a persistent VM state directory. It then blocks at an evaluator-controlled gate in /run.

1. **Before mock effect:** the QEMU guest is terminated abruptly after the durable start marker and before the local mock-effect marker. The same guest disk is rebooted. The test requires the start marker to survive, effect and process receipt to remain absent, and the invocation count to remain one.
2. **After mock effect, before process receipt:** the worker is allowed to write its separate durable mock-effect marker and is then cut before writing its process receipt. The same guest disk is rebooted. The effect marker must remain, the receipt must remain absent, and the invocation count must remain one.
3. **Positive control:** a third attempt is released through both gates and must record one start, one effect marker and one process receipt with the same InvocationID.

Runtime gate files live under /run and disappear across reboot. Per-attempt markers and the exported campaign receipt live under /var/lib and must survive the guest crash.

## Evidence

The test derivation exports raw files and a versioned JSON campaign receipt under its Nix output. The receipt binds:
- Nixward source revision and flake.lock SHA-256;
- Nixpkgs revision, worker derivation/output and QEMU package version;
- guest NixOS, kernel and systemd versions;
- exact unit and attempt ID;
- boot IDs before/after each crash, systemd InvocationID, invocation count and marker disposition.

The evaluator requires the first two cases to remain reconciliation-required. The post-effect cut is not treated as safe-to-retry, and the pre-effect cut is not a general claim that no external participant effect could have happened. The marker is only the test fixture's local effect boundary.

## Claim ceiling

A passing run qualifies the declared QEMU guest, NixOS configuration, systemd build and virtual disk path for these exact test cuts. It does **not** establish:
- physical storage-controller power-loss behavior;
- filesystem atomicity or durability across arbitrary devices/controllers;
- Nixward's production journal fsync/rename semantics;
- live D-Bus JobAdded/JobRemoved or PIDFD observer correctness;
- actual participant idempotency or independent business-effect evidence;
- production service recovery or NixOS activation safety.

The next promotion stage must connect this VM harness to the existing Nixward transaction journal and host-owned systemd observer, preserve the participant/service-oracle separation, and separately test storage-specific failure modes. It must not create a second journal or attempt ledger.
