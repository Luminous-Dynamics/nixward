# NixOS Activation Compatibility Profiles v0.1

This module qualifies **which activation semantics are known**, not how to execute an activation.

## Why an exact profile is required

The Nixward activation-observer work already distinguishes `switch`, `test`, `boot` and `dry-activate`, and records release, activation-semantics revision and `switch-to-configuration` binary digest. A syntactically valid tuple is not proof that the verifier has qualified that combination.

The registry in `src/action/activation_profile.rs` resolves only an exact profile key:
- NixOS release identifier;
- exact Nixpkgs source revision;
- exact `switch-to-configuration` SHA-256;
- activation-semantics revision;
- exact systemd version;
- exact observer-adapter revision;
- profile digest.

There is no nearest version, release-family, channel, fuzzy or "newest profile" fallback. Profiles must be registered through an independently reviewed release-qualification process. No real NixOS 26.11 profile is fabricated here; synthetic values appear only in unit tests.

## Mode semantics

| Mode | Running generation | Boot default | Credit boundary |
|---|---|---|---|
| `switch` | Target | Target | Both must be independently observed |
| `test` | Target | Unchanged | Boot default must remain unchanged |
| `boot` | Unchanged before reboot | Target for next boot | Running target requires a later boot observation |
| `dry-activate` | Unchanged | Unchanged | Preview only; no mutation permission |

These postconditions are verifier-owned constants. They are not accepted from the agent's plan.

## Inhibitors and identity

The profile requires an explicit inhibitor policy. Bypass is a distinct outcome and only supported when policy allows it and a separately bound authorization digest is present. InvocationID is required for exact systemd job identity; PIDFD identity is recorded as a capability when supported by the exact profile. Deprecated activation-script restart/reload callbacks cannot be required for semantic truth.

## Tests and claim ceiling

The unit tests use synthetic release pins and exercise exact matching, unknown tuple denial, profile digest mismatch, duplicate profiles, all four mode postconditions, unsupported modes, deprecated callback rejection and inhibitor policy. They do not demonstrate a qualified release.

This registry does not execute NixOS activation, verify the authenticity of release profiles, observe the running host or provide rollback guarantees. It does not create a second transaction journal. Nixward remains the sole host transaction/interlock/recovery authority.

The next qualification stage must capture real release-specific binary/systemd/observer pins on a disposable VM and register a profile only after the mode/inhibitor/reboot matrix passes. The QEMU crash-cut campaign in issue #141 is a separate prerequisite and does not prove activation semantics.
