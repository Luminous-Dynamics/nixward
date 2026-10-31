# Signed host evidence capture and attestation v1

Status: **offline signed-bundle verifier; no live D-Bus collector or privileged mutation path**

## Purpose

The semantic verifier checks whether a captured evidence envelope is internally consistent. It cannot tell whether the JSON came from the real systemd manager, kernel or NixOS host. This module adds the next trust layer: a locally trusted host-capture key signs a canonical manifest that binds the normalized semantic envelope and every raw source artifact.

It distinguishes:
- **raw source bytes**: D-Bus event stream, journal slice, profile/boot-default observations, PIDFD mapping result and health probes;
- **capture manifest**: host/boot/manager identity, transaction bindings, source versions, sequence range, monotonic capture window, and hashes/lengths for all raw artifacts;
- **signed capture**: Ed25519 signature over a domain-separated canonical manifest;
- **verified capture receipt**: runtime-only result created only after policy, signature, artifact and semantic-binding checks.

The verified receipt is not a host-execution capability. It cannot start, stop, restart, roll back or release a worker.

## Canonical signature contract

The host capture key signs a domain-separated length-prefixed JSON encoding of the typed manifest:

    "nixward-systemd-evidence-capture-signature-v1\\0"
    || LE64(length(serde_json(manifest)))
    || serde_json(manifest)

The manifest is a strict typed struct with fixed field order. Artifact entries must be unique and lexicographically sorted by artifact ID before signing. SHA-256 is used for portable raw-artifact identity; the signature uses strict Ed25519 verification. The local trust policy binds policy ID, epoch, key IDs, public keys and revocation state.

The verifier requires:
- non-zero policy epoch and exact manifest policy ID/epoch/digest match;
- non-revoked local host key and valid Ed25519 signature;
- a UUID-format kernel boot ID, systemd version and unique D-Bus manager owner name;
- strictly ordered monotonic capture window;
- contiguous, non-empty capture sequence range (no hidden gaps);
- exact artifact ID set with byte-length and SHA-256 verification;
- a semantic envelope whose transaction, attempt, admission commit, plan, machine, boot ID and systemd version exactly match the signed manifest.

Raw artifacts are passed as bytes to the verifier. Artifact IDs and metadata alone are not evidence. Missing, extra or tampered bytes are rejected.

## Trusted collector requirements

A future host collector must use the real system-bus connection and:
1. install match rules for JobNew and JobRemoved;
2. call systemd Manager.Subscribe();
3. record completion of both steps before StartUnit is issued;
4. retain the exact StartUnit request and returned job object path;
5. capture JobNew/JobRemoved in source order, preserving unrelated jobs and the exact target job;
6. obtain a pidfd while the process is alive and call GetUnitByPIDFD, recording returned unit ID, InvocationID and unit object path;
7. bind pidfd mapping and process-start tuple to kernel boot ID and exact admission;
8. preserve manager owner changes/restarts and journal evidence rather than smoothing them away;
9. independently read /nix/var/nix/profiles/system, /run/current-system, the bootloader default and runtime health state;
10. sign the complete manifest using a locally protected host evidence key.

A standalone post-hoc observer cannot prove that subscription happened before a StartUnit call it did not control. The future supervisor must own the bus subscription/dispatch sequence and export its signed capture. This module verifies bundles produced by that trusted path; it does not implement it.

## Threat model and limits

The local capture key and root-owned trust policy must be protected, versioned and revocable. A signed capture proves that the trusted key attested to these bytes and bindings. It does not prove that a compromised root host, kernel, systemd manager, boot chain or capture binary reported the truth. TPM-backed measured boot/hardware attestation and remote challenge freshness are a separate trust tier.

Replay is constrained by transaction/attempt/commit identity, host boot ID, policy epoch, monotonic sequence and semantic-envelope bindings. A consumer must also enforce capture-ID and transaction-attempt uniqueness in its trusted evidence ledger.

The v1 offline verifier does not persist a replay ledger or establish capture liveness beyond the signed capture window. It is a verifier primitive, not an evidence-ingestion service or production supervisor.

## Tests authored

The module includes signature acceptance and semantic handoff, raw artifact tampering, policy epoch drift, revoked-key rejection, sequence-gap rejection, foreign transaction binding, strict unknown-field rejection and missing/extra artifact checks. Tests are source-only here; no Rust/Cargo/Nix execution is claimed.

No live D-Bus capture, PIDFD operation, TPM attestation, key provisioning or privileged execution is implemented by this document/module.
