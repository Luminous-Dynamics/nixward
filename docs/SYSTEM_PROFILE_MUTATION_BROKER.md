# System Profile Mutation Broker: Decision Record

Status: **design accepted for implementation planning; not implemented; not a closure of Issue #9**  
Date: 2026-10-11  
Related: [Issue #9](https://github.com/Luminous-Dynamics/nixward/issues/9), [PR #62](https://github.com/Luminous-Dynamics/nixward/pull/62)

## Decision summary

Do not represent a preflight read, flock, or atomic symlink replacement as compare-and-set (CAS). A correct conditional profile transition requires the expected-old comparison and the profile update to share one indivisible serialization boundary. The current Nix command interface does not expose a caller-supplied expected-old profile argument for nix-env --set.

The preferred long-term primitive is a versioned Nix-native conditional profile update (upstream-supported or implemented through a supported library/API) that checks the expected current target after acquiring the native profile-update serialization and performs the generation update without dropping that serialization. A broker around the existing nix-env --set executable is not sufficient by itself: a pre-check in the parent followed by starting nix-env leaves the same gap, while holding a lock that nix-env independently needs risks blocking the child. Do not ship a hand-written symlink-only replacement that discards Nix generation, manifest, or garbage-collection semantics.

A root-owned coordinator can still serialize **cooperating managed writers**, audit requests, and funnel Nixward transactions through one mutation plane. This is useful defense in depth, but it is not a CAS guarantee against arbitrary root processes. Its guarantee must be named accordingly unless the expected-old check is performed inside the same native conditional-update operation.

## Version-pinned Nix profile-mutation audit (2026-10-11)

### Nixward's locked packaging baseline

The current Nixward `flake.lock` pins nixpkgs to commit
[`0bb7ec54c8483066ec9d7720e780a5caa71f8612`](https://github.com/NixOS/nixpkgs/tree/0bb7ec54c8483066ec9d7720e780a5caa71f8612).
At that exact nixpkgs revision, `pkgs/tools/package-management/nix/default.nix`
sets `nixVersions.latest` and `nixVersions.stable` to Nix **2.34.8**
([version and aliases](https://github.com/NixOS/nixpkgs/blob/0bb7ec54c8483066ec9d7720e780a5caa71f8612/pkgs/tools/package-management/nix/default.nix#L174-L212)).
This identifies the flake's locked Nix packaging baseline. It does **not** force
every deployed NixOS target to run that Nix binary: a system can select another
`nix.package`, and the Nixward module does not own or pin the host's Nix
installation.

### Nix 2.34.8 source result

The current source tree moved the legacy `nix-env` implementation to
`src/nix/nix-env/nix-env.cc`. At the exact upstream tag
[`2.34.8`](https://github.com/NixOS/nix/tree/2.34.8):

- `opSet` starts at line 758. After realizing the derivation, it calls
  `createGeneration(*store2, globals.profile, drv.queryOutPath())` and then
  `switchLink(globals.profile, generation)`; see the
  [exact implementation](https://github.com/NixOS/nix/blob/2.34.8/src/nix/nix-env/nix-env.cc#L758-L801).
  That operation path contains no `lockProfile` or
  `optimisticLockProfile` call.
- `createGeneration` in
  [`src/libstore/profiles.cc`](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L64-L119)
  creates/records a generation and its permanent-root behavior, but does not
  acquire the profile lock.
- `switchLink` replaces the link, while `switchGeneration` separately
  acquires `PathLocks` and calls `lockProfile`; see the
  [profile functions](https://github.com/NixOS/nix/blob/2.34.8/src/libstore/profiles.cc#L247-L296).
  The existence of that lock in a neighboring operation does not make it
  implicit in `opSet`.
- The earlier
  [Nix 2.28.5 `opSet` path](https://github.com/NixOS/nix/blob/2.28.5/src/nix-env/nix-env.cc#L723-L765)
  exhibited the same relevant sequence: generation creation followed by
  `switchLink`, without an explicit profile lock in `opSet`.

This is present in the **2.34.8 source selected by the current flake's locked
nixpkgs package aliases**, and the subsequent source check found the same
`opSet` sequence in Nix 2.35.2 and in upstream development commit
[`979a87c97bef7b96cd4ec4b142188089851e47ad`](https://github.com/NixOS/nix/blob/979a87c97bef7b96cd4ec4b142188089851e47ad/src/nix/nix-env/nix-env.cc#L759-L801),
packaged by nixpkgs commit
[`a8211bffc562fa5950a5ad6ecbc7939ebbcaf5b3`](https://github.com/NixOS/nixpkgs/blob/a8211bffc562fa5950a5ad6ecbc7939ebbcaf5b3/pkgs/tools/package-management/nix/default.nix#L196-L234)
as `2.36pre20261010_979a87c9`. The [Nix 2.35.2 release source](https://github.com/NixOS/nix/blob/2.35.2/src/nix/nix-env/nix-env.cc#L758-L800)
also calls `createGeneration` then `switchLink` without acquiring the profile
lock in `opSet`. This cross-version result reinforces the finding but is not
a substitute for the exact deployed build's source/patch audit. The host's
actual Nix executable and source revision must still be captured on each
supported target before making target-wide claims.

### Consequence for the implementation plan

The next implementation should be an upstream Nix patch or supported native
API, not a wrapper pretending the gap is closed. The required critical section
is:

1. Realize the candidate closure **before** acquiring the profile lock, avoiding
   a long-held mutation lock during build/download.
2. In the same Nix process that performs the mutation, acquire the profile lock
   that cooperating profile writers use.
3. While holding it, resolve and compare the actual current profile target with
   the request's exact expected-old value. Treat a missing profile distinctly
   from a failed observation; on mismatch, return a typed/machine-distinguishable
   refusal before creating or switching a generation.
4. On match, run Nix's existing generation-creation/permanent-root logic and
   link switch under that same lock, then release it.
5. Audit all supported profile writers at the pinned source revision and make
   each in-scope writer honor the same boundary. A caller-owned lock or
   pre-check followed by launching an unmodified `nix-env --set` does not
   satisfy this contract. Any writer outside the shared boundary must be named
   as a residual, not silently considered serialized.

An implementation option is a Nix-native conditional-set interface that takes
an expected current profile target and checks it inside `opSet`'s mutation
critical section; the final option name and representation must be designed
against the actual Nix source/API. The current Nixward guard remains a useful
mitigation, but it does not implement this operation. Do not replace Nix's
generation management with an ad hoc Rust symlink rewrite. The separate
root-owned broker remains a possible coordinator for cooperating clients, not
a protection against a root process that deliberately bypasses it.

### Source-audited implementation plan

The operation matrix and concrete upstream patch contract are now specified separately in
[`docs/NIX_2_34_8_CONDITIONAL_PROFILE_SET_DESIGN.md`](NIX_2_34_8_CONDITIONAL_PROFILE_SET_DESIGN.md).
The audit finds the named legacy install/upgrade/uninstall/flag-update paths use
`createUserEnv`, which locks and checks an optimistic token; generation
switch/rollback and generation deletion take the profile lock directly.
`opSet` is the audited gap. The design defines the conditional check as closure
equality under the profile lock, names the exact native seam after realization,
and lists upstream functional/concurrency tests. Newer `nix profile` commands,
custom profile paths, downstream patches, and direct root writes remain
separate audit boundaries. This is a design, not an upstream patch or a test pass.

## Evidence and current facts

- Nix's [Profiles manual](https://nix.dev/manual/nix/2.35/package-management/profiles.html) says the final profile symlink switch is atomic on Unix. Atomic replacement prevents partial-link visibility; it does not compare the previous target with a caller-supplied expected target.
- The [nix-env --set reference](https://nix.dev/manual/nix/2.34/command-ref/nix-env/set) describes setting the profile to contain a specified derivation. It documents no expected-old-value CAS argument.
- The existing [Issue #9 race protocol](https://github.com/Luminous-Dynamics/nixward/issues/9#issuecomment-6100261239) and the deterministic source tests in PR #62 distinguish Nixward peer exclusion, a pre-check-to-write external-writer counterexample, a divergent post-child observation, and rejection of foreign recovery state.
- The current services.nixward module launches nixward-daemon as the dedicated unprivileged nixward user. Its systemd sandbox declares profile paths read-only, disables ambient capabilities, enables NoNewPrivileges, and filters privileged syscalls. **That service must not silently become the root mutation broker or be granted broad root authority.** Any privileged broker requires a separate service identity, unit, request protocol, and threat model.

## Threat model boundaries

### Must prevent

- Two cooperating Nixward transactions from mutating system profile/runtime state concurrently.
- A stale or unsigned transaction from requesting a profile change.
- A mismatched transaction ID, plan digest, expected prior profile, candidate profile, action, or recovery binding from being accepted.
- Failed profile observation, unexpected profile state, lost worker identity, or ambiguous post-state from advancing into activation.
- A request from becoming an arbitrary command-execution surface.

### Explicitly out of scope unless the system policy changes

An arbitrary process already running as root can bypass a Nixward-only socket, lock, or API and mutate root-owned system state directly. No service-level authorization can make a hostile root process unprivileged. The deployment can reduce accidental concurrency by routing supported system-management tools through one broker and auditing bypasses, but it cannot claim protection against a root actor who deliberately bypasses that boundary.

## Proposed architecture

Separate the **unprivileged observer/recommender** from the **privileged mutation authority**.

1. **Client request (untrusted).** The client sends only a versioned transaction envelope: transaction ID, expected prior profile closure, exact candidate closure, action, plan/authority identity, recovery closure, nonce/replay identity, and required receipt digests. No shell string, arbitrary executable path, journal path, or free-form environment is accepted.
2. **Broker identity and transport.** A dedicated root-owned service uses a local Unix-domain socket and obtains peer credentials from the kernel. Socket group membership limits who can submit requests, but peer UID alone is not authorization. The broker validates the signed authority, exact ChangePlan/plan digest, expiry, replay key, machine identity, rooted candidate receipt, and journal schema itself.
3. **Native profile transition primitive (required).** Acquire the same serialization boundary used by profile writers, read the selected profile while that boundary is held, compare it byte-for-byte/canonically with the expected prior target, and create/select the candidate through Nix's supported generation-update logic without releasing/reacquiring the boundary. If Nix provides no supported way to perform all of these steps together, the broker must return UnsupportedConditionalUpdate rather than emulate CAS using a parent pre-check followed by nix-env --set.
4. **Durable evidence.** Before any activation worker can be released, persist the request identity, authority/plan digests, expected-old value, candidate, native-update result, and observed profile. If persistence is ambiguous, fail closed and require later fresh reconciliation.
5. **Activation remains separate.** Profile selection is not proof of a running-generation transition. Activation still uses the immutable closure, gated worker receipt, exact argv/environment checks, runtime/profile re-observation, and transaction-owned journal.
6. **Recovery is a new conditional request.** Recovery re-observes runtime and profile, validates the transaction's allow-set, and asks the same native conditional-update primitive to select the bound predecessor only if the expected current profile still matches. A mismatch is not overwritten; it becomes an explicit recovery refusal.

### CAS versus end-to-end system activation

A profile-level conditional update is a necessary sub-primitive, not closure of
Issue #9. The lock in `nix-env --set` would normally be released when that
process exits, while activation is launched separately. The pinned nixpkgs
snapshot shows `nixos-rebuild-ng` calling `nix-env -p <profile> --set
<path_to_config>` and then calling the candidate's `switch-to-configuration`
as a distinct step ([source](https://github.com/NixOS/nixpkgs/blob/13542c24f0060ce88fc074e78b1a7cbbad630b18/pkgs/by-name/ni/nixos-rebuild-ng/src/nixos_rebuild/nix.py#L687-L755)).
The `switch-to-configuration-ng` activation lock at
`/run/nixos/switch-to-configuration.lock` serializes activations, not profile
writers ([source](https://github.com/NixOS/nixpkgs/blob/13542c24f0060ce88fc074e78b1a7cbbad630b18/pkgs/by-name/sw/switch-to-configuration-ng/src/main.rs#L1809-L1821)).

Consequently, after A conditionally selects candidate A and releases the profile
lock, B can select candidate B before A starts activation. A then might activate
A while the selected profile names B. An immediate profile recheck narrows but
does not eliminate the final check-to-activation gap. Do not describe native
CAS alone as end-to-end transaction isolation.

To close that gap for cooperating supported writers, one privileged
transaction owner must retain a per-profile coordinator lease from before the
final expected-old observation through native CAS/publication, exact activation,
profile/runtime read-back, and durable transaction disposition. The lease
serializes *whole deployments*; the Nix-native profile lock remains a shorter
critical section for the expected-old comparison and generation publication.
These two locks have different scopes and must not be conflated.

Nix 2.35.2's actual `PathLocks` implementation makes a naive long-lived
native-profile-lock handoff unsafe: `pathlocks.cc` opens `<profile>.lock`
with `O_CLOEXEC`, takes `flock`, checks for a stale/unlinked lock inode, and
retries; `lockProfile` enables delete-on-unlock, and unlock may unlink the
lock pathname and mark the old inode stale ([source](https://github.com/NixOS/nix/blob/2.35.2/src/libstore/unix/pathlocks.cc),
[profile helper](https://github.com/NixOS/nix/blob/2.35.2/src/libstore/profiles.cc)).
An independently opened child can also block on a descriptor held by its parent.
Do not hold that lock across activation or claim that passing its FD is a valid
lease without a new Nix-supported API and explicit inode/lifetime semantics.

Preferred design: a **stable coordinator lease distinct from `<profile>.lock`**
plus a Nix-native CAS primitive. A root-owned supervisor holds a stable
per-managed-profile lock file without unlinking/replacing it during a live
transaction. It obtains the coordinator lease before the native Nix mutation
lock, asks the native API to compare expected-old and publish the profile while
the native lock is held, then retains the coordinator lease through activation
and read-back. All supported frontends that can change that managed system
profile must use the same coordinator; otherwise the guarantee is narrowed and
the unintegrated frontend remains a blocker. A private lease-authorized API or
broker endpoint is needed so the owner does not deadlock by trying to acquire
its own coordinator lock twice. The Nixward observer daemon remains
unprivileged; the privileged supervisor is a separate, explicitly reviewed
authority.

Coordinator identity must come from a trusted managed-profile registry and
must cover configured aliases to the same system profile. The coordinator
file should live in a root-owned runtime directory, be opened relative to a
trusted directory FD with no-follow checks, have its owner/mode/type validated,
and keep a stable inode/path throughout the active service lifetime. Never
use a PID file or unlink-on-exit as a lock protocol.

The lease owner must also outlive the activation it authorized. A client
disconnect cannot drop the lease while an activation can still run. The
supervisor must either retain control until the activation is terminal and
read-back is complete, or on supervisor failure ensure the activation has
terminated before releasing the lease. If an activation is started in an
independent transient systemd unit, its lifetime and the lease holder's
lifetime must be explicitly coupled and tested. A released lock is not proof
that activation stopped, and a crash after profile publication means the
outcome is indeterminate until fresh evidence permits recovery.

Unintegrated frontends and direct root bypass remain explicit residuals.

At minimum, acceptance tests must pause A after profile publication but before
activation, race B's profile transition/activation, and assert the selected
profile, running closure, activation order, generation links and GC-root
inventory throughout read-back. If B is not blocked or forced to re-observe
after A releases, the end-to-end guarantee fails even if the profile CAS test
passes.

### Error contract

Use closed, typed outcomes instead of parsing strings:

- ExpectedStateMatchedAndSelected
- ExpectedStateMismatch { observed }
- UnsupportedConditionalUpdate
- AuthorityRejected
- ReplayRejected
- NativeUpdateFailed { observed_after }
- PostStateUnknown
- JournalDurabilityUnknown

Only ExpectedStateMatchedAndSelected with durable evidence and subsequent independent verification can permit activation. A successful command exit alone is insufficient.

## Design options

| Option | Assessment | Decision |
|---|---|---|
| Keep the current guard + nix-env --set | Helps detect drift around worker release, but cannot atomically protect the expected-old check | Keep as mitigation; disclose residual |
| Parent holds profile lock then starts nix-env | May deadlock or serialize incorrectly because the child uses the native update path independently; not a conditional update | Reject unless Nix explicitly supports lock handoff |
| Rewrite only the profile symlink in Rust | Risks bypassing generation links, manifests, history, and GC-root conventions | Reject |
| Dedicated broker wrapping an unmodified nix-env --set | Serializes participating callers but leaves the pre-check-to-write gap; a wrapper lock cannot make the child operation conditional | Coordination only; reject as CAS |
| Retain Nix's existing `<profile>.lock` across activation | Conflicts with normal child locking, `O_CLOEXEC`, stale-inode detection, and profile-lock deletion semantics | Reject unless a new Nix-supported lease API changes and specifies those semantics |
| Stable per-profile coordinator lease + Nix-native conditional update | Coordinator spans publication, activation and read-back; Nix's native lock protects the narrow expected-old comparison/update; every managed writer participates | **Preferred design to implement and test** |
| Nix-native full transaction/lease API | Could unify locking only if it provides documented lock lifetime, stale-lock semantics, activation boundary, crash behavior and supported frontend integration | Valid alternative only with upstream API contract and concurrency evidence |

## Coordinator lock order and lifetime contract

The implementation contract is intentionally two-layered:

1. The privileged transaction supervisor resolves the managed-profile identity
   through a trusted registry, opens and validates the stable coordinator lock,
   and acquires the exclusive lease.
2. With the lease held, it takes a fresh pre-state observation and calls the
   Nix-native expected-old CAS. The native operation uses Nix's ordinary profile
   mutation lock only around comparison plus generation/profile publication.
3. It keeps the coordinator lease while activation runs, collects activation
   completion, re-reads profile and runtime identity, and commits the durable
   journal disposition.
4. A competing managed writer first waits for the coordinator lease, then
   re-observes expected-old. It must not cache a pre-wait observation as the
   expected-old truth.
5. The coordinator holder must not die while an independently surviving
   activation continues. Client cancellation, owner crash, systemd unit stop,
   child exec failure, read-back failure, and a service restart each have a
   specified fail-closed disposition and deterministic test oracle.

The lock file used by the coordinator is not Nix's `<profile>.lock`; its stable
pathname is never unlinked while the manager may be running. All supported
managed writers take locks in the order **coordinator → native profile lock**.
A direct/root writer that bypasses the coordinator is explicitly outside this
managed-writer guarantee; the deployment's writer inventory must say so rather
than implying universal serialization.

## Deterministic acceptance plan

Tests are mandatory before deployment. Use barrier/channel synchronization and explicit callback counts, never sleeps.

1. **Serialization:** two broker clients request changes concurrently; exactly one holds the native mutation boundary at a time. The second sees the first's committed state when it enters.
2. **Expected-old mismatch:** update the profile after request construction but before native lock acquisition. The broker, after acquiring the native boundary, sees the new profile and rejects without calling the generation-update function.
3. **CAS window is actually closed:** interpose a second writer at every available test seam between the expected-old comparison and profile selection. Prove that the native transaction keeps the comparison/update indivisible against other writers using the same native primitive. If an actor can update between them, the operation is not CAS.
4. **Legacy external writer:** run an unrelated direct Nix profile writer that does not participate in the broker. Either the platform/native primitive excludes it by a shared documented locking mechanism, or record it as outside the guarantee. Do not make test actors obey the broker merely to produce a green result.
5. **Authority:** reject wrong peer identity, invalid/missing signature, wrong machine, candidate mismatch, wrong predecessor, expired plan, reused replay key, stale receipt, path traversal, unsupported protocol version, and unknown request fields.
6. **Journal failure:** inject failure before/after native profile publication. Read back and classify current visibility separately from directory durability; never infer rollback from an error.
7. **Recovery:** inject a foreign runtime/profile pair and require the recovery mutation callback count to remain zero. A profile-only match never substitutes for runtime verification.
8. **Packaging/systemd:** verify the broker is a distinct root-owned unit with only the needed writable paths, no general shell endpoint, exact packaged Nix executable/library identity, restart/recovery behavior, and auditable request receipts.

## Rollout gates

- [ ] Choose and version the native conditional-update integration point; do not code a fake CAS adapter.
- [ ] Review lock semantics and behavior against each supported Nix version; pin supported versions.
- [ ] Add broker protocol validation and privilege-separation tests before enabling the service.
- [ ] Add barrier-driven concurrency tests and run them against an isolated temporary profile with the actual Nix update primitive.
- [ ] Publish the threat model including direct root bypass.
- [ ] Run exact-head Rust tests, formatting, Clippy, flake checks, and all packaged binaries.
- [ ] Retain Issue #9 until evidence proves the claimed managed-writer boundary and the direct-root limitation is explicitly accepted.

## Current implementation status

PR #62 has a pre-release exact-profile recheck and deterministic in-memory race simulations. Those reduce and demonstrate race windows, respectively; they do not implement this broker or native CAS. The simulations and new tests have not been compiled/executed in the current environment. No broker, upstream patch, CAS guarantee, or qualification is claimed by this decision record.


## Existing Nixward interlock: implementation and residuals (2026-10-12)

Nixward's current `NixwardTransactionInterlock` in `src/action/executor.rs`
is a machine-wide coordinator at `/run/nixward-system-transaction.lock`.
The journaled activation and recovery paths retain the guard while their
transaction function runs; overlapping Nixward operations fail closed instead
of waiting. This is a Nixward-peer exclusion boundary, not a shared boundary
for stock `nixos-rebuild`, auto-upgrade, self-deploy, or arbitrary privileged
writers.

The lock acquisition path is now hardened in source to:

- reject a symlink or non-directory parent and a group/world-writable parent; production acquisition explicitly requires parent UID 0 for `/run`;
- open with `O_NOFOLLOW | O_CLOEXEC`;
- require a regular lock file whose owner matches the trusted parent, whose
  mode grants owner read/write only, and whose link count is exactly one;
- compare the opened descriptor's device/inode against the pathname after open;
- retain the lock file and inode across unlock/reacquisition rather than
  unlinking it on drop.

Eight new Unix regression tests cover unexpected parent-owner rejection, symlink
lock-path rejection, writable-parent rejection, unsafe lock-file permissions, special-mode-bit rejection,
multiple hard links, stable path/inode across release/reacquisition, and the forced A/B
profile-publication-to-activation/read-back interleaving. The pre-existing
deterministic two-thread exclusion test remains separate. These are source changes, **not passing test
evidence**; Rust compilation and execution have not been performed here.

This remains deliberately narrower than the preferred two-lock implementation
above. The current interlock is machine-wide rather than a registry-keyed
per-profile coordinator; it does not make Nix-native expected-old CAS exist,
does not cause unmodified frontends to honor the lock, and cannot constrain a
privileged root actor that bypasses or replaces its files. The trusted runtime
directory and its ownership/mode are part of the security assumption.


## Admission check after prior coordinator loss (2026-10-12)

The current PR adds a conservative journal-admission check to journaled
activation and recovery. After taking the local Nixward interlock, those paths
scan the root-owned transaction journal directory and block on any other
nonterminal profile-transition, activation, or recovery phase. A journaled
operation exempts its own transaction ID so that recovery can proceed. The
separate non-journaled execute_authorized entry point already rejects real
exact-system activation before mutation in favor of the durable transaction
boundary; it does not depend on this scanner. The scanner itself accepts an
optional current transaction ID and blocks on every unresolved journal when no
exemption is provided. Unreadable, malformed, symlinked, noncanonical, or
filename/transaction-ID-mismatched records also block admission. Production
validates every component of the absolute journal-root path as a real
root-owned directory that is not group/world-writable. Journal files must be
root-owned, single-linked, free of special permission bits, and private from
group/other read or execute access; the scanner checks these properties before
parsing.

This reduces the risk that a replacement Nixward request proceeds merely
because the previous process's flock was released on supervisor exit while its
activation worker might still be alive. It intentionally fails closed until the
old transaction reaches a durable terminal phase. It is not a lease keeper, does
not terminate or prove the death of a surviving activation process, and does
not serialize stock rebuild/self-deploy/auto-upgrade or other non-participating
writers. It also does not close the Nix-native expected-old compare-and-set gap.

Twelve source regression oracles cover an unresolved peer after lock
reacquisition, current-transaction exemption plus a pre-mutation peer,
writable/group-readable/special-bit/multiply-linked journal rejection,
symlinked root/entry and filename/identity substitution, malformed-journal
rejection, exhaustive phase classification, and a live worker subprocess
surviving SIGKILL of the lock-owning supervisor while journal admission blocks
a second mutation. Two additional test-binary entry points support that
subprocess scenario.
No Rust test has been compiled or run at this head. The new Linux-only subprocess regression kills an isolated lock-owning test
supervisor while a separate worker process remains live, then proves journal
admission blocks another mutation and cleans up the worker via pidfd. This is
actual subprocess-survival evidence when the test executes, but it is not a test
of production systemd stop/restart behavior or the exact shipped activation
payload. The test has not been compiled or executed yet. Native CAS, the
privileged coordinator service, supported-writer migration, and exact-head
hosted qualification remain mandatory.
