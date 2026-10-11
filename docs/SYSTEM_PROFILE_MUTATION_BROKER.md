# System Profile Mutation Broker: Decision Record

Status: **design accepted for implementation planning; not implemented; not a closure of Issue #9**  
Date: 2026-10-11  
Related: [Issue #9](https://github.com/Luminous-Dynamics/nixward/issues/9), [PR #62](https://github.com/Luminous-Dynamics/nixward/pull/62)

## Decision summary

Do not represent a preflight read, flock, or atomic symlink replacement as compare-and-set (CAS). A correct conditional profile transition requires the expected-old comparison and the profile update to share one indivisible serialization boundary. The current Nix command interface does not expose a caller-supplied expected-old profile argument for nix-env --set.

The preferred long-term primitive is a versioned Nix-native conditional profile update (upstream-supported or implemented through a supported library/API) that checks the expected current target after acquiring the native profile-update serialization and performs the generation update without dropping that serialization. A broker around the existing nix-env --set executable is not sufficient by itself: a pre-check in the parent followed by starting nix-env leaves the same gap, while holding a lock that nix-env independently needs risks blocking the child. Do not ship a hand-written symlink-only replacement that discards Nix generation, manifest, or garbage-collection semantics.

A root-owned coordinator can still serialize **cooperating managed writers**, audit requests, and funnel Nixward transactions through one mutation plane. This is useful defense in depth, but it is not a CAS guarantee against arbitrary root processes. Its guarantee must be named accordingly unless the expected-old check is performed inside the same native conditional-update operation.

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
| Dedicated root broker wrapping nix-env --set | Serializes cooperating clients but still has a pre-check-to-write gap and permits root bypass | Optional coordination plane only; no CAS claim |
| Nix-native conditional update (upstream feature or supported API) | Expected-old check can happen inside Nix's profile-update serialization while preserving generation semantics | Preferred |

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
