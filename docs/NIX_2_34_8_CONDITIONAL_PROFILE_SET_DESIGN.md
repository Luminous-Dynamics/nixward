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

### Cross-check against newer Nix releases and current development source

The finding is not confined to Nixward's locked 2.34.8 baseline. As of
2026-10-11, Nix 2.35.2 is the latest tagged Nix release visible in the
[official Nix container version list](https://github.com/NixOS/nix/pkgs/container/nix/versions?filters%5Bversion_type%5D=tagged)
and the source was checked directly:

- Nix 2.35.2 [`opSet`](https://github.com/NixOS/nix/blob/2.35.2/src/nix/nix-env/nix-env.cc#L758-L800)
  still builds first and then calls `createGeneration`/`switchLink` without
  acquiring `lockProfile` or `optimisticLockProfile` in that path.
- Its [`createUserEnv`](https://github.com/NixOS/nix/blob/2.35.2/src/nix/nix-env/user-env.cc#L161-L177)
  continues to lock and check the optimistic token before generation creation
  and switch; its
  [profile-lock helpers](https://github.com/NixOS/nix/blob/2.35.2/src/libstore/profiles.cc#L235-L281)
  remain distinct operations.

I also checked the newer development revision selected by the current upstream
nixpkgs branch snapshot
[`a8211bffc562fa5950a5ad6ecbc7939ebbcaf5b3`](https://github.com/NixOS/nixpkgs/blob/a8211bffc562fa5950a5ad6ecbc7939ebbcaf5b3/pkgs/tools/package-management/nix/default.nix#L196-L234).
That source pins Nix revision
[`979a87c97bef7b96cd4ec4b142188089851e47ad`](https://github.com/NixOS/nix/tree/979a87c97bef7b96cd4ec4b142188089851e47ad)
as `2.36pre20261010_979a87c9`; the same `opSet` sequence appears at
[lines 759–801](https://github.com/NixOS/nix/blob/979a87c97bef7b96cd4ec4b142188089851e47ad/src/nix/nix-env/nix-env.cc#L759-L801).
Thus the gap persists in the locked 2.34.8 baseline, the 2.35.2 release tag,
and this inspected 2.36 development snapshot. This remains a bounded source
audit—not proof for all downstream-patched builds, Nix profile APIs, wrappers,
or direct filesystem writers.

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

### Important distinction: the existing optimistic token is not a closure

In Nix 2.34.8, `optimisticLockProfile(profile)` returns the raw
`readLink(profile).string()` value (or an empty string when the profile path
does not exist): [implementation](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L283-L292).
The `createUserEnv` path compares that same link-target token under lock after
building: [comparison and publish](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/user-env.cc#L164-L179).
That token is a profile-link/generation identity, not a resolved store closure.

Nixward's current transaction observation is the resolved system closure. The
proposed `--expected-profile-closure` therefore must compare like-for-like:
resolve `globals.profile` to a validated store path under the lock (Nix has
`Store::followLinksToStorePath` for resolving a link chain to a store path:
[API](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/include/nix/store/store-api.hh)),
then compare its canonical store-path identity with the caller expectation. Do
not compare a closure string directly to `optimisticLockProfile`'s raw symlink
text. If Nixward later requires generation-link identity as well as closure
identity, make the request bind both explicitly; do not silently redefine the
closure-only contract.

A missing, dangling or unresolvable profile must not be treated as the empty
string merely because the optimistic-token helper does so. The conditional
operation should distinguish an explicitly authorized empty/nonexistent
pre-state (if the API ever supports that mode) from failed or ambiguous
observation. For the NixOS system-profile transition in this proposal, the
expected-old profile must resolve to the caller-authorized store closure.

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

The existing Nix functional suite already exercises `nix-env --set` in
[`tests/functional/user-envs-test-case.sh`](https://github.com/NixOS/nix/blob/2.34.8/tests/functional/user-envs-test-case.sh),
which is sourced by `tests/functional/user-envs.sh` and registered from
[`tests/functional/meson.build`](https://github.com/NixOS/nix/blob/2.34.8/tests/functional/meson.build).
Extend that fixture to assert expected-closure success and mismatch/no-new-
generation behavior; put deterministic lock interleavings in the same
functional harness or a dedicated registered test rather than creating a
separate test that is never invoked by Meson.

The core concurrency tests require explicit channels/FIFOs or a dedicated test seam, not timing sleeps as the only oracle. Every test must assert both the command result and filesystem/profile/generation state.

## 6. Profile CAS is not the full activation transaction

A correct conditional profile update fixes a **profile mutation** race, but it
does not by itself close the full profile-to-runtime race tracked by Nixward
Issue #9. The update lock is normally released when `nix-env --set` exits;
activation follows as a separate command.

This is not just hypothetical architecture. In the inspected nixpkgs source
snapshot, `nixos-rebuild-ng`'s `set_profile()` calls
`nix-env -p <profile> --set <path_to_config>`, while
`switch_to_configuration()` separately invokes
`<path_to_config>/bin/switch-to-configuration <action>`:
[set operation](https://github.com/NixOS/nixpkgs/blob/13542c24f0060ce88fc074e78b1a7cbbad630b18/pkgs/by-name/ni/nixos-rebuild-ng/src/nixos_rebuild/nix.py#L687-L755).
The NixOS `switch-to-configuration-ng` implementation independently locks
`/run/nixos/switch-to-configuration.lock` around activation
([pinned source](https://github.com/NixOS/nixpkgs/blob/13542c24f0060ce88fc074e78b1a7cbbad630b18/pkgs/by-name/sw/switch-to-configuration-ng/src/main.rs#L1809-L1821)).
That serializes competing activation executions, but it does not hold the
selected system-profile lock from profile publication through activation.
A rebuild can therefore publish a different profile while another already
selected closure is waiting for, or running under, the activation lock.

### Required end-to-end linearization boundary

To claim the profile/runtime pair belongs to one transaction, the transaction
must preserve this ordering as one managed critical section:

1. Acquire a system-profile mutation lease using the same lock inode and
   locking semantics respected by supported profile writers.
2. Observe and compare expected-old closure under that lease.
3. Create/select the candidate generation and switch the system profile.
4. Keep the lease held while invoking the exact immutable candidate
   `switch-to-configuration` action and collecting its result.
5. Read back the selected profile and running closure while the lease still
   prevents a cooperating writer from changing the profile.
6. Commit the transaction disposition, then release/remove the lock using
   stale-lock semantics compatible with Nix's `PathLocks`.

An ordinary `nix-env --set --expected-profile-closure …` process that exits
before activation cannot by itself meet steps 4–5. An unrelated activation lock
is not a substitute for a profile lock. Nor is a Nixward-only lock sufficient
unless every in-scope external writer is required to honor it.

### Preferred lease protocol: keep coordinator and native Nix locks separate

The inspected Nix 2.35.2 implementation rules out a tempting shortcut: simply
open and retain the existing `<profile>.lock` descriptor across activation.
Nix's `PathLocks` opens that pathname with `O_CLOEXEC`, takes an exclusive
`flock`, checks the opened inode for the stale-file marker, and retries if
the lock pathname was unlinked. The profile-lock helper enables deletion on
unlock; unlock may unlink the path and mark the old descriptor stale. This
behavior is deliberate concurrency handling, not a stable cross-process lease
ABI ([`pathlocks.cc`](https://github.com/NixOS/nix/blob/2.35.2/src/libstore/unix/pathlocks.cc),
[`profiles.cc`](https://github.com/NixOS/nix/blob/2.35.2/src/libstore/profiles.cc)).
A second independent open of the same flock inode can also block on the lease
holder, so an unmodified Nix subprocess cannot safely be assumed to “borrow”
the held lock. `O_CLOEXEC` alone is not the core problem; inode replacement,
Nix's stale-lock protocol, independent-open locking, and lock lifetime all
need an explicit API contract.

The preferred implementation to evaluate first is a **broker-owned,
two-lock protocol**:

1. **Coordinator lease.** A single privileged system-deployment transaction
   owner takes an exclusive lock on a separate, stable per-managed-profile
   coordinator file. The key is derived from a trusted registry of managed
   profile identities and aliases—not an arbitrary caller-provided string.
   Store the lock under a root-owned runtime directory; open relative to a
   trusted directory descriptor with no-follow semantics, verify the opened
   file is a regular file with expected owner/mode, and do not unlink or
   replace its pathname while the supervisor can be alive. The kernel releases
   the flock when the final owning descriptor closes; the persistent pathname
   is not a PID-based “stale lock” and must not be deleted as cleanup.
2. **Expected-old CAS.** While retaining the coordinator lease, the owner
   performs a Nix-native conditional profile update. That Nix operation takes
   Nix's ordinary native profile lock for the short mutation critical section,
   resolves and compares the current profile closure against the exact
   expected-old closure under that lock, and either refuses without generation
   mutation or creates/selects the candidate generation and switches the
   profile before releasing the native lock.
3. **Activation under the same lease.** The transaction owner keeps the
   coordinator lock through invocation of the exact candidate's
   `switch-to-configuration`, activation-result collection, profile/runtime
   read-back, and durable journal disposition. Another managed system-profile
   transaction must acquire the same coordinator lock *before* it re-observes
   its expected-old state; it cannot publish a competing profile between A's
   publication and A's read-back.
4. **One lock order.** All managed writers take the coordinator lease first,
   then the native Nix mutation lock. No path may acquire the native profile
   lock and then wait for the coordinator lease. The transaction owner must
   call a private lease-authorized mutation API/broker endpoint rather than
   recursively reacquiring its own coordinator lock. A command-line child that
   independently tries to take the same lease would deadlock; bypassing the
   lease without authenticating the owner would be equally incorrect.

The coordinator serializes only operations that participate in this protocol.
Every in-scope writer must be migrated: Nixward, `nixos-rebuild-ng`, any
supported legacy `nixos-rebuild`, self-deploy, auto-upgrade, and configured
third-party deployment services that can select the same managed system
profile. An unintegrated writer is not “covered because it usually uses Nix”;
it is an explicit guarantee gap. Direct root mutation remains outside the
threat model, as stated below. Keep the target profile identity and supported
writer inventory as rollout evidence.

### Lease-owner lifetime and crash semantics

The lock-holder must outlive the client request and must not release its lease
while the activation it authorized can still be running. Prefer one supervised
transaction service that owns the coordinator descriptor, starts/observes the
exact activation child, and retains ownership until activation is terminal and
post-state read-back completes. If activation is launched as a separate
systemd transient service that may outlive the caller, the design must prove
that the lease owner remains alive for that unit's complete lifetime or that
owner failure reliably terminates and confirms termination of that activation
before the lease can be released. A lock released by a crashed CLI while
activation continues is a failing interleaving, not successful crash recovery.

After owner crash, signal loss, or an error after profile publication, do not
infer rollback or “not activated.” Mark the transaction outcome indeterminate;
establish that the prior activation is no longer running, collect fresh
runtime/profile and generation evidence, then admit recovery only against the
original transaction's exact allowed predecessor/candidate identities. Lock
release provides mutual exclusion, not recovery truth.

### Acceptance oracles for the two-lock protocol

- Instrument acquisition and release of the coordinator lock and native Nix
  lock separately. Assert lock order, descriptor/inode identity, lease lifetime,
  and the exact transaction owner for every phase.
- In forced A/B interleaving, pause A after publication and before activation.
  B must be blocked before its final expected-old observation/publication until
  A's activation and read-back finish; B then re-observes the new state and
  either proceeds or refuses.
- Kill or disconnect the initiating client at each boundary: before CAS, after
  profile publication, before activation exec, during activation, after
  activation exit, and during read-back. Verify the supervisor continues or
  stops activation before lease release and leaves an evidence-based recovery
  disposition.
- Exercise lock-file unlink/recreate, alias-to-profile mapping, symlink swap,
  wrong owner/mode, open failure, cancellation, and service restart. No test
  may use the live host system profile.
- Assert selected profile closure, runtime closure, activation order, generation
  links and GC-root inventory; exit codes alone are insufficient.

This is a concrete protocol proposal, not implemented behavior. The native CAS
patch, coordinator service, frontend migrations, forced-interleaving suite and
supervisor crash tests remain unimplemented and unexecuted.
 
### Integration paths that must participate

The source audit found NixOS-managed callers as well as Nix itself. At minimum,
the implementation/rollout plan must account for:

- Nixward's exact-system transition and its gated activation/recovery flow.
- `nixos-rebuild-ng`'s profile-set plus activation sequence.
- Any legacy `nixos-rebuild` path still shipped by supported deployments.
- NixOS self-deployment/system services that run `nix-env --set` then
  `switch-to-configuration` separately (for example the source match in
  [`nixos/modules/services/system/self-deploy.nix`](https://github.com/NixOS/nixpkgs/blob/13542c24f0060ce88fc074e78b1a7cbbad630b18/nixos/modules/services/system/self-deploy.nix)).
- Auto-upgrade or third-party system managers that can change the same profile.

Two plausible engineering directions are left open for an upstream design review:

- **Native transaction/lease API:** add a Nix-supported profile transaction lease
  that keeps the actual profile lock alive across conditional set, activation,
  and read-back. Nixward and supported rebuild frontends consume the lease
  through a validated inherited-FD/API contract. The lease must preserve
  `PathLocks` stale-lock/deletion rules; an ad hoc `flock` copy that ignores
  inode replacement is not acceptable.
- **One transaction owner:** move profile mutation and activation behind a
  single privileged system-deployment coordinator, and migrate every supported
  profile-changing frontend to it. Direct/root bypass remains out of scope,
  but any unintegrated supported frontend must be listed as an unresolved path.

Do not prematurely choose an FD hand-off protocol without proving its inode,
exclusive-lock, lifetime, close-on-exec, stale-file, and error-cleanup semantics.
The conditional `opSet` feature remains useful, but is only a sub-primitive
until one of these end-to-end approaches is proven.

### New mandatory interleaving test

Add a test that pauses transaction A *after its conditional profile publication
and before A invokes activation*, then requests a conflicting profile update
and activation through transaction B. B must not change the selected profile
until A has completed activation and state read-back; after A releases its
lease, B must re-read its expected-old closure and either proceed against the
new state or refuse. Assert profile closure, runtime closure, activation order,
and generation/root inventory—not just both process exit codes. Run a second
case with an unintegrated legacy writer and verify the guarantee is not claimed
for that path. Use a controlled temporary system-profile-shaped test fixture,
never the host's live system profile.

## 7. Nixward integration requirements

This upstream feature does not by itself prove Nixward uses it safely. Nixward integration must:

- Capture the exact expected prior system closure at authorization/recovery admission and persist it as transaction state.
- Construct the conditional `nix-env` request using the exact trusted executable and exact argv; never fall back silently to ordinary `--set` when the option is unknown.
- Treat expected-old mismatch as a no-mutation refusal. Do not activate the candidate and do not attribute an external profile change to the current transaction.
- Treat launch errors, timeout, process termination, malformed result, failed read-back, and post-publication errors as distinct; if the result is ambiguous, classify `Indeterminate` and require fresh runtime/profile observations in a separate recovery attempt.
- Keep the existing inert worker gate, immutable payload identity, exact argv/env checks, and transaction-owned journal. The conditional profile update does not prove that `switch-to-configuration` succeeded or that the new system booted.
- Add deterministic Nixward tests for expected-state mismatch and unknown result; then run the end-to-end test against an isolated profile and the exact packaged Nix binary.

The Nixward daemon remains unprivileged. Any privileged mutation authority must be an explicitly separate service or a carefully constrained supported call path, with its own authorization/threat model. A coordinator that simply wraps an unmodified `nix-env --set` remains coordination, not CAS.

## 8. Explicit residual boundaries

- A process with root authority can bypass the supported Nix command and directly manipulate system state. This design excludes a deliberately hostile root actor; it cannot make root subordinate to a root-owned service.
- Newer `nix profile` commands, downstream patches, custom profile paths and external management tools are outside the guarantee until audited against the same lock.
- The finding is anchored to upstream Nix tag 2.34.8 and the current Nixward locked nixpkgs package alias. Record `nix --version`, the exact Nix store path/build identity, selected `nix.package`, and source/patch set on each deployment.
- The patch, the controlled upstream tests, Nixward integration tests, the end-to-end profile-lock lease or shared transaction owner, and hosted qualification have not been implemented or executed by this document.

## Source references

- [Nix 2.34.8 `opSet`](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L758-L801)
- [Nix 2.34.8 `createUserEnv` lock and optimistic-token check](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/user-env.cc#L160-L179)
- [Nix 2.34.8 generation deletion locks](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L135-L220)
- [Nix 2.34.8 profile switching and locking](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L247-L296)
- [Nixward locked nixpkgs version aliases](https://github.com/NixOS/nixpkgs/blob/0bb7ec54c8483066ec9d7720e780a5caa71f8612/pkgs/tools/package-management/nix/default.nix#L174-L212)
