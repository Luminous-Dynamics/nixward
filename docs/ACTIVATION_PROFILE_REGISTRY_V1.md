# NixOS activation profile registry v1

Status: **pure resolver and adversarial unit tests authored; no real NixOS release profile is qualified yet**

## Why a registry

NixOS activation must be interpreted as an exact versioned protocol, not merely a command name. `switch`, `test`, `boot` and `dry-activate` have different postconditions. A verifier must not accept a caller-supplied release string or switch binary digest merely because it is syntactically valid.

The NixOS 26.05 release notes state that reload/restart operations from activation scripts are deprecated and scheduled for removal in 26.11, and introduce switch inhibitors with an explicit force bypass via `NIXOS_NO_CHECK=1`. The 26.11 manual is now available, but an exact compatibility profile still needs the release, Nixpkgs revision, `switch-to-configuration` binary digest and measured systemd API capabilities captured from a disposable VM. We deliberately do not invent those pins. <Cite refs={["turn451126search0","turn451126search1","turn451126search10"]}/>

The repository's current flake tracks `nixos-unstable`, so it does not supply a stable NixOS release tuple suitable for registry admission. The committed registry template is intentionally empty. An empty registry denies every activation profile until a separately qualified profile is reviewed and registered.

## Exact profile key

The registry key is the entire tuple:

- exact `nixos-version` release string;
- exact Nixpkgs source revision;
- SHA-256 of the actual `switch-to-configuration` executable;
- activation-semantics revision and digest;
- exact systemd version string;
- exact observer-adapter revision.

There is no wildcard, fuzzy version match, minor-version fallback or “newest known” selection. The profile digest also binds supported modes, ordered step sequences, mode postconditions, inhibitor policy and systemd capability declarations.

## Mode postconditions

The verifier owns these semantics; a profile cannot redefine them:

| Mode | Running generation | Boot default | Mutation |
|---|---|---|---|
| `switch` | Target | Target | Runtime and boot default |
| `test` | Target | Preserve pre-state | Runtime only |
| `boot` | Preserve pre-state until reboot | Target | Boot default only |
| `dry-activate` | Preserve pre-state | Preserve pre-state | Read-only preview |

For `boot`, a later boot-ID-bound observation is required before the new running generation can be credited. For `switch`, both the running generation and boot default must independently match. A successful `switch-to-configuration` exit code or systemd job result does not replace these postconditions.

## Resolver contract

- `ActivationProfileRegistry::register_qualified_profile` accepts trusted, verifier-owned profile configuration, validates it and rejects duplicate exact keys.
- `resolve` accepts the entire exact profile query and caller-supplied expected profile digest; it returns only the exact registered profile.
- `expected_postconditions(mode)` returns the verifier-defined mode contract.
- `validate_plan` requires the exact ordered steps in the registered profile and rejects unsupported modes, mismatched postconditions, missing inhibitors and unapproved bypasses.
- `resolve_and_validate_plan` creates a domain-separated compatibility receipt tied to the exact profile and activation plan.

The registry method is not an agent-facing registration API. Profile ingestion/approval must happen through reviewed, release-qualified build configuration. The module has no I/O, no D-Bus calls and no activation executor.

## systemd identity requirements

Profiles require JobRemoved evidence and unit InvocationID. If GetUnitByPIDFD is available, that capability is recorded; if it is not, the profile must explicitly qualify a process-start-tuple fallback. Missing both PIDFD attribution and the fallback is rejected. This mirrors the safety goal of attributing a worker to an exact unit invocation rather than relying on a recyclable PID.

## Inhibitor policy

Each mode contract declares whether switch-inhibitor evidence is required or not applicable. A blocked check rejects the plan. An authorized bypass is distinct from a passed check and requires a separate authorization-receipt digest when the exact profile explicitly permits bypass. This pure module checks the presence and binding of that digest; signature verification and authority scope remain upstream responsibilities.

## Claim ceiling

A compatibility receipt establishes that the requested release/binary/semantics tuple is present in the verifier's configured registry and that the plan matches that profile. It does not prove that the profile itself was honestly qualified, the host is uncompromised, the actual activation completed, or the post-state was observed. Those are separate release-qualification, trusted-capture and semantic-host-verification stages.

No production activation or rollback path is implemented here.
