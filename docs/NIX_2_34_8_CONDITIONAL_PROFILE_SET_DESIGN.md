# Conditional system-profile set: upstream Nix 2.34.8 design

Status: **implementation proposal only; no Nix patch exists in this repository; not qualified**  
Date: 2026-10-11  
Related: [Nixward Issue #9](https://github.com/Luminous-Dynamics/nixward/issues/9), [Nixward PR #62](https://github.com/Luminous-Dynamics/nixward/pull/62), [profile mutation broker decision record](SYSTEM_PROFILE_MUTATION_BROKER.md)

## Executive decision

Patch the Nix operation that performs `nix-env --set`, not only the Nixward caller. Its candidate realization should remain outside the mutation lock. After realization, Nix itself should take the selected profile lock, compare the current resolved profile closure against a caller-supplied expected-old closure, and perform the standard generation creation and profile-link switch while still holding that lock.

This follows the existing pattern already used by other legacy `nix-env` writers. It closes the observed gap against other writers that use the same profile lock. It does **not** protect against a privileged process that intentionally bypasses Nix's supported profile-update path, nor does it establish the behavior of other Nix versions until those versions are audited and tested.

This document is a source-bounded implementation design, not a patch or test result.

## 1. Pinned source baseline

Nixward's `flake.lock` pins nixpkgs commit [`0bb7ec54c8483066ec9d7720e780a5caa71f8612`](https://github.com/NixOS/nixpkgs/tree/0bb7ec54c8483066ec9d7720e780a5caa71f8612). At that exact revision, `nixVersions.latest` and `nixVersions.stable` resolve to Nix 2.34.8 in [the package definition](https://github.com/NixOS/nixpkgs/blob/0bb7ec54c8483066ec9d7720e780a5caa71f8612/pkgs/tools/package-management/nix/default.nix#L174-L212).

In upstream Nix [2.34.8 `opSet`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L758-L801), after candidate realization, the implementation calls `createGeneration` followed by `switchLink` without taking the profile lock in this operation path. The upstream [profile implementation](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L247-L296) shows that `switchGeneration` separately takes `PathLocks` and calls `lockProfile`; this does not implicitly lock `opSet`.

The candidate should not take a long-lived profile lock during a build/download. The safe linearization boundary is after realization, immediately before rechecking expected-old state and publishing the new generation.

## 2. Source-audited writer matrix

This matrix covers the named upstream Nix 2.34.8 legacy paths inspected for this design. It is not an exhaustive claim about every Nix CLI command, wrapper, distribution patch, or direct filesystem writer.

| Operation | Relevant source behavior | Assessment for a shared-profile-lock design |
|---|---|---|
| `nix-env --set` | [`opSet`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L758-L801) calls `createGeneration` and `switchLink` without acquiring the lock | **Gap to fix** |
| `nix-env --install` | [`opInstall`/install loop](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L556-L610) captures `optimisticLockProfile`; [`createUserEnv`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/user-env.cc#L160-L179) locks, compares the token, and retries on drift | Existing cooperating writer; regression-test it |
| `nix-env --upgrade` | [`upgradeDerivations`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L614-L718) uses the optimistic-token / `createUserEnv` path | Existing cooperating writer; regression-test it |
| `nix-env --set-flag` | [`opSetFlag`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L721-L756) uses the optimistic-token / `createUserEnv` path | Existing cooperating writer; regression-test it |
| `nix-env --uninstall` | [`uninstallDerivations`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L803-L839) uses the optimistic-token / `createUserEnv` path | Existing cooperating writer; regression-test it |
| `nix-env --switch-generation` / `--rollback` | [`switchGeneration`](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L256-L281) holds `lockProfile` while selecting and switching | Existing cooperating writer; regression-test it |
| `nix-env --delete-generations` | [generation deletion operations](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L135-L220) take `lockProfile` before enumerating/deleting generations | Existing cooperating writer; regression-test it |
| `nix-env --switch-profile` | [`opSwitchProfile`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L1290-L1301) switches the configured user profile link rather than `globals.profile` | Separate target; do not treat this check as coverage of arbitrary custom-profile use |
| Newer `nix profile` subcommands, `nixos-rebuild` wrappers, and third-party tools | Not exhaustively audited by this matrix | Audit actual selected paths and their lock semantics before including them in the guarantee |

The shared lock in `createUserEnv` is especially relevant. It takes `lockProfile`, reads the current optimistic token, returns `false` if that token changed, and only then calls `createGeneration` and `switchLink`. `opSet` should use the same lock primitive but compare the explicit caller expectation, because unlike a normal package install it represents a transaction that must not silently rebase to another starting closure.

## 3. Proposed command contract

A proposed interface for discussion is:

```text
nix-env --profile /nix/var/nix/profiles/system \
  --set --expected-profile-closure /nix/store/<expected-old-system> \
  /nix/store/<candidate-system>
```

`--expected-profile-closure` is a **proposed, not currently supported** argument. The candidate remains the existing `--set` derivation argument.

Contract:

- Expected-old is a canonical immutable store path supplied by the caller and validated as an existing store path.
- After the candidate is realized, the command takes the same per-profile lock used by `lockProfile`.
- While locked, it resolves the current profile link to its actual closure. A missing, dangling, unreadable, non-canonical, or otherwise ambiguous profile is a refusal, never equivalent to an empty/default profile.
- If the observed closure differs from expected-old, the command returns an explicit expected-state mismatch and must not create a new generation or switch the link.
- If the observed closure matches expected-old, the command runs Nix's existing `createGeneration` and `switchLink` while retaining that lock.
- The check and update share one critical section. There is no unlock/relock around comparison and publication.
- A mismatch must be machine-distinguishable from build failure, permission failure, profile observation failure, and an unknown post-state. Do not make Nixward parse arbitrary human diagnostics as a security oracle.
- Dry-run validates the request and candidate but must not publish a generation.
- The ordinary `--set` behavior remains available for compatibility unless upstream chooses a breaking policy. Nixward's privileged system-transition path must use the conditional form and fail closed if the deployed Nix lacks it.

This proposal defines CAS over the **resolved profile closure**, matching the current Nixward transaction state. Switching between two generation-link names that resolve to the same closure therefore does not count as a closure-value mismatch. If a future requirement needs generation-history identity, the API must additionally bind the selected generation-link token; it must not silently claim that closure equality also proves generation-link equality.

## 4. Native mutation sequence

The implementation seam is inside `opSet`, immediately after the existing realization call and before `createGeneration`:

1. Parse the expected-old value only for `--set`; reject duplicate, missing, malformed, or unexpected occurrences.
2. Resolve/query the candidate as today and realize it as today, without holding the profile lock during expensive work.
3. Construct `PathLocks` and call `lockProfile(lock, globals.profile)`.
4. Obtain a fresh canonical resolved target for `globals.profile` under the lock. If observation fails, stop without generation mutation.
5. Compare the current resolved closure to the expected-old store path. A mismatch exits before `createGeneration`.
6. Call `createGeneration(*store2, globals.profile, drv.queryOutPath())` and `switchLink(globals.profile, generation)` while the same `PathLocks` instance remains alive.
7. Return a typed/structured result or stable error kind suitable for Nixward to distinguish expected-state mismatch from ambiguous failure. The implementation must use the error/result facilities that Nix 2.34.8 supports; this document does not prescribe an unverified C++ exception or exit-code symbol.
8. Keep the lock alive through all generation bookkeeping and the final link switch. RAII then releases it on either success or exception.

Use Nix's profile helper and the normal generation-management functions. Do not substitute a hand-written symlink update, because generation enumeration, permanent roots, garbage-collection coordination, and profile history must retain their Nix semantics.

## 5. Acceptance tests required in upstream Nix

Implement the tests in the Nix 2.34.8 functional test environment with an isolated temporary profile and controlled store fixtures, not against `/nix/var/nix/profiles/system` on the host.

1. **Happy path:** expected closure equals the selected profile closure. The command succeeds, exactly one expected generation transition is visible, and the final profile resolves to the requested candidate closure.
2. **Expected-old mismatch:** move the profile to a different closure before the command obtains the mutation lock. The command returns the explicit mismatch result, leaves the selected profile unchanged from the state observed under lock, and creates no candidate generation.
3. **Deterministic check-to-switch interleaving:** add a test-only barrier after expected-old comparison while the profile lock is held. Start a competing conditional writer with the same expected-old closure. It must not pass the lock until writer A releases it; it then observes A's candidate and rejects. Final profile is A's candidate, and writer B creates no generation.
4. **Legacy install interleaving:** start a package installation that snapshots the previous profile, then let the conditional set publish before the installation reaches `createUserEnv`. The install must detect the changed optimistic token and retry/recompute; it must not publish based on a stale snapshot.
5. **Rollback/switch interleaving:** race the conditional set with `--rollback`/generation switch. Demonstrate serial outcomes governed by the same lock. No test actor may fake compliance by using only the broker lock.
6. **Generation deletion interleaving:** confirm delete-generation operations retain their current lock behavior and cannot invalidate the selected/current generation while the conditional set's critical section is active.
7. **No-mutation rejection:** exercise wrong expected-old, malformed expected path, nonexistent/dangling profile, profile read error, and unsupported condition argument. Assert both typed result and generation inventory/profile read-back.
8. **GC/root bookkeeping:** verify successful conditional set keeps permanent-root/generation metadata correct and mismatch creates no new permanent root or generation link.
9. **Failure after publication:** inject failure/reporting uncertainty after the profile link switch. The command result must not falsely claim rollback; read-back should allow Nixward to classify current visibility separately from durability or activation state.
10. **Compatibility:** normal `nix-env --set` and user profile commands retain documented compatibility. Test a custom `--profile` target explicitly.
11. **Package identity:** build and test the exact Nix derivation intended for the Nixward deployment, including any downstream patches. Re-run this matrix for every additionally supported Nix version; do not extrapolate 2.34.8 results.

The core concurrency tests require explicit channels/FIFOs or a dedicated test seam, not timing sleeps as the only oracle. Every test must assert both the command result and filesystem/profile/generation state.

## 6. Nixward integration requirements

This upstream feature does not by itself prove Nixward uses it safely. Nixward integration must:

- Capture the exact expected prior system closure at authorization/recovery admission and persist it as transaction state.
- Construct the conditional `nix-env` request using the exact trusted executable and exact argv; never fall back silently to ordinary `--set` when the option is unknown.
- Treat expected-old mismatch as a no-mutation refusal. Do not activate the candidate and do not attribute an external profile change to the current transaction.
- Treat launch errors, timeout, process termination, malformed result, failed read-back, and post-publication errors as distinct; if the result is ambiguous, classify `Indeterminate` and require fresh runtime/profile observations in a separate recovery attempt.
- Keep the existing inert worker gate, immutable payload identity, exact argv/env checks, and transaction-owned journal. The conditional profile update does not prove that `switch-to-configuration` succeeded or that the new system booted.
- Add deterministic Nixward tests for expected-state mismatch and unknown result; then run the end-to-end test against an isolated profile and the exact packaged Nix binary.

The Nixward daemon remains unprivileged. Any privileged mutation authority must be an explicitly separate service or a carefully constrained supported call path, with its own authorization/threat model. A coordinator that simply wraps an unmodified `nix-env --set` remains coordination, not CAS.

## 7. Explicit residual boundaries

- A process with root authority can bypass the supported Nix command and directly manipulate system state. This design excludes a deliberately hostile root actor; it cannot make root subordinate to a root-owned service.
- Newer `nix profile` commands, downstream patches, custom profile paths and external management tools are outside the guarantee until audited against the same lock.
- The finding is anchored to upstream Nix tag 2.34.8 and the current Nixward locked nixpkgs package alias. Record `nix --version`, the exact Nix store path/build identity, selected `nix.package`, and source/patch set on each deployment.
- The patch, the controlled upstream tests, Nixward integration tests, and hosted qualification have not been implemented or executed by this document.

## Source references

- [Nix 2.34.8 `opSet`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L758-L801)
- [Nix 2.34.8 `createUserEnv` lock and optimistic-token check](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/user-env.cc#L160-L179)
- [Nix 2.34.8 generation deletion locks](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L135-L220)
- [Nix 2.34.8 profile switching and locking](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L247-L296)
- [Nixward locked nixpkgs version aliases](https://github.com/NixOS/nixpkgs/blob/0bb7ec54c8483066ec9d7720e780a5caa71f8612/pkgs/tools/package-management/nix/default.nix#L174-L212)
