# Nixward System Transaction Architecture

## Purpose

Nixward is the sovereign system control plane for NixOS. Installation, rebuilds,
service changes, software realization, boot promotion, recovery, and other
consequential operations should converge on one safety model:

**observe → plan → validate → authorize → snapshot → apply → verify → promote/recover**

### Exact-realization boundary

System-changing `nixos-rebuild switch/test/boot` commands are candidate/preview
vocabulary, not privileged mutation primitives. Their command text can identify
what the operator requested, but it does not by itself identify the immutable
closure that will be realized.

The privileged path therefore converges on:

`candidate source/configuration`
→ `deterministic realization`
→ `source + lock + configuration identities`
→ `exact /nix/store system closure`
→ `execution-intent authority`
→ `switch-to-configuration`
→ `post-state verification`

The CLI exposes this as a two-phase boundary:

`closure prepare` → offline detached signature → `closure activate`

Preparation is non-mutating and creates the exact ChangePlan plus authority
challenge. Activation re-verifies the execution-intent/realization pair, the
serialized plan, the detached Ed25519 authority, and the exact store closure
before invoking `switch-to-configuration`. No local `--approve` convenience
flag can substitute for this authority class.

`ActivateSystemClosure` is the canonical executor primitive for that final
mutation. This avoids a time-of-check/time-of-use gap in which the same rebuild
command could resolve different source/configuration state between review and
execution.

The goal is not to make an AI more powerful than the owner. The goal is to make
machine state transitions understandable, reproducible, cryptographically
authorized, and recoverable.

## Authority boundary

Cognitive subsystems are advisory:

- HDC similarity
- active inference
- causal reasoning
- generated explanations
- Phi / confidence / decision-quality signals
- natural-language conversation

None of these is an authorization primitive.

A consequential mutation requires explicit authorization over the exact change
intent. Natural-language phrases such as "yes", "install", or "go ahead" must
never be treated as cryptographic approval.

The current detached Ed25519 authority protocol remains the authority layer.
Owner authority and release authority remain separate.

## Canonical transaction

A system transaction is the logical unit connecting a proposed change to its
evidence and resulting state.

Conceptually:

```
Transaction
├── transaction identity
├── target identity
├── observed pre-state
├── desired-state / command intent
├── generated plan
├── validation evidence
├── authority evidence
├── rollback / recovery binding
├── application receipt
├── observed post-state
├── verification receipt
└── promotion or recovery outcome
```

The transaction must be bound to the exact target and exact mutation. A change
made after approval is a different transaction.

## Lifecycle

### 1. Observe

Collect target-side facts and retain provenance.

Each fact should be classifiable as:

- observed directly
- user specified
- derived / inferred
- defaulted
- unknown

Browser-side observations may improve the preview, but target-side observations
are authoritative for machine-affecting decisions.

### 2. Plan

Construct a typed ChangePlan. It must bind:

- machine identity
- exact configuration mutation, if any
- exact structured command, if any
- rollback binding
- nonce
- issuance time
- expiry

The plan digest is the stable subject for authorization.

### 3. Validate

Validation is read-only and should establish, as applicable:

- syntax
- Nix evaluation
- flake integrity
- target compatibility
- policy compliance
- safety constraints
- immutable closure identity
- recovery feasibility

Validation failure never becomes authorization.

### 4. Authorize

The owner/operator authorizes the exact plan.

Authority verification must establish:

- trusted signer
- non-revocation
- permitted action
- exact subject
- exact target / Holon
- exact audience
- freshness
- valid signature

Replay protection is consumed only immediately before the real mutation.

### 5. Snapshot

Before mutation, capture enough state to support safe rollback/recovery.

For configuration changes this includes exact pre-state. For generation
changes it includes the previous generation and the resulting expected
generation / closure. For destructive storage changes, the transaction must
carry an explicit recovery strategy or be blocked.

### 6. Apply

Only the already-authorized exact command/patch/capability may execute.

For an exact NixOS system closure activation, Nixward first takes its
cross-process transaction interlock before the final pre-state validation. The
authorized profile target is then set and verified, after which the exact
closure's `switch-to-configuration` action is invoked. Nixward does not hold
the Nix profile lock across the child activation: `nix-env --set` owns its
profile lock for its own mutation, while `switch-to-configuration` uses its
own activation lock. This keeps the interlocks composable rather than creating
self-deadlock. The executor must not reinterpret the approved request,
substitute an ambient generation selector, or silently redirect the profile
target.

### 7. Verify

A successful process exit is not sufficient.

Verification should observe the resulting target state and compare it with the
expected post-state. For a boot-changing transaction, post-reboot health is
part of the verification boundary.

### 8. Promote or recover

For generation-changing operations:

```
candidate → boot attempt → health assessment
                              ├─ healthy → bless/promote
                              └─ unhealthy → recover/rollback
```

Recovery must itself be bounded by the original transaction and must never
silently overwrite concurrent operator changes.

## Federated organizational profiles

Nixward should support portable policy profiles for individuals, teams,
enterprises, regulated environments, and public/community baselines.

The profile is deliberately not a second executable configuration language.
It is semantic policy that the Nixward planner resolves against authoritative
target observations and the operator's desired state.

A profile may contain:

- stable profile identity and version
- publisher and provenance metadata
- applicability constraints (architecture, environment, labels)
- composable inherited profiles identified by content digest
- semantic rules such as required/prohibited capabilities or settings
- references to external control frameworks, including OSCAL identifiers
- extension metadata that cannot silently alter rule semantics

Recommended composition:

public/industry baseline
        ↓
organization baseline
        ↓
department / workload role
        ↓
machine-specific overlay
        ↓
owner or operator intent

Composition is not "last writer wins". If two required rules conflict, the
resolver must produce a deterministic conflict record and block realization
until the conflict is resolved or an explicitly authorized exception exists.

### Standards interoperability

OSCAL should be treated as the interoperability layer for control catalogs,
baselines, parameters, and control mappings rather than as Nixward's internal
execution format. OSCAL Profiles are already designed to select and tailor
controls and can be composed from multiple catalogs/profiles.

Nixward semantic rules can reference OSCAL controls without importing OSCAL
semantics into the privileged execution engine. This preserves a small,
auditable internal model while allowing organizations to map their baselines
to established frameworks.

For distributed profile delivery, use content-addressed profile references
and an explicit trust policy. TUF is a strong candidate for repository
metadata, delegated publishers, expiration, rollback resistance, and key
compromise containment. TUF's delegated roles allow trust to be scoped to
specific targets rather than granting every publisher universal authority.

For resulting system/build evidence, prefer interoperable in-toto/SLSA
attestation structures where they fit. These should describe provenance and
verification evidence; they must not be confused with owner authorization.

### Trust boundaries

A downloaded profile is untrusted policy data until:

1. the retrieval channel's metadata is verified,
2. the expected profile digest matches,
3. the profile schema validates,
4. its applicability is checked against the target,
5. its composition is conflict-free,
6. its resulting plan is independently validated,
7. and the final exact plan is authorized.

Profile publisher trust and machine-mutation authority are separate domains.

A company can publish a mandatory engineering baseline without gaining the
ability to silently mutate a personal machine. Conversely, an enrolled
enterprise machine can receive organization authority only through an
explicit machine enrollment and authority policy.

### Exceptions

Exceptions must be first-class, time-bounded, and attached to exact rules.

An exception should identify:

- profile/rule being excepted
- reason
- scope
- issuer
- issuance and expiry
- exact affected target(s)
- evidence or compensating control
- authorization

Never encode exceptions by silently editing or deleting the inherited rule.

## Profile lifecycle

Profiles follow the same evidence discipline as system changes:

publish → retrieve → authenticate → validate → compose → plan → authorize →
apply → verify → attest

A profile update therefore cannot directly change a machine. It changes the
set of constraints from which a future SystemPlan is generated.

This creates a clean separation between policy distribution and machine control.

## Installation and management are the same model

The installer should not have a special privileged path.

An install is a high-impact System Transaction whose plan contains:

- authoritative hardware snapshot
- disk topology / Disko plan
- boot policy
- encryption policy
- generated NixOS configuration
- immutable system closure expectation
- recovery generation/media strategy
- owner authorization
- application evidence
- boot verification

The management UI should use the same transaction primitives for:

- configuration changes
- rebuilds
- service actions
- software realization
- garbage collection
- boot changes
- recovery

This removes the architecture smell of an installer plus a separate admin tool.

## Boot trust

For systems using systemd-boot/UKI style boot assessment, the transaction should
remain pending until the new generation reaches the configured boot-complete
health boundary.

A candidate generation is not "successful" merely because nixos-rebuild
returned zero. Promotion requires actual post-boot evidence.

## Recovery invariant

Every consequential transaction should answer:

**"How do we get back to the last known-good state?"**

For generation-changing system transactions, "last known-good" is not a
generation number or the ambient result of a later `--rollback` operation.
Preparation captures the exact prior running `/nix/store/...-nixos-system-*` closure
before authorization, and that closure becomes part of the signed ChangePlan's
recovery binding.

The exact recovery boundary is:

```
observe exact pre-state running closure
        ↓
authorize candidate exact closure + recovery closure
        ↓
re-check pre-state immediately before mutation
        ↓
activate exact candidate closure
        ↓
on failure, re-observe and refuse recovery if state is outside
the transaction's {prior, candidate} closure set
        ↓
activate the exact bound prior closure
        ↓
verify the observed post-recovery running closure
```

Recovery evidence records the exact closure targeted for recovery and the exact
post-recovery closure observed by Nixward.

The exact system-profile transition is now part of the privileged activation
primitive. The Nixward transaction interlock remains held across the exact
profile transition, the immutable `switch-to-configuration` action, and
post-state verification/recovery. The underlying Nix profile mutation and the
closure activation retain their own Nix-managed locks; Nixward does not hold
the profile lock across the child activation. This prevents concurrent Nixward
transactions from interleaving while preserving Nix's native activation
serialization. It does not authorize or claim to prevent arbitrary direct
filesystem mutation that bypasses Nix's locking protocol, nor does it remove
the unsupported external-writer compare-and-set gap documented in Issue #9.

Bootloader-specific next-boot selection remains a separate evidence boundary
tracked in Issue #8 and must not be silently folded into the runtime or profile
claims.

If no bounded recovery path exists, the action should either be classified as
non-reversible and require stronger explicit treatment, or be refused.

## Spore boundary

Spore remains the portable/browser embodiment.

Nixward remains the authoritative machine-management implementation.

The stable boundary should be serialized and versioned rather than exposing
Nixward implementation types directly through the Spore WASM build. The current
wire contract is defined in [docs/SYSTEM_TRANSACTION_WIRE_V1.md](SYSTEM_TRANSACTION_WIRE_V1.md)
with a machine-readable compatibility fixture in
[docs/fixtures/system-transaction-v1.json](fixtures/system-transaction-v1.json).

The existing sovereign configuration/conversation APIs are useful compatibility
seams during migration, but new privileged semantics should use the canonical
transaction protocol.

## Immediate implementation sequence

1. Keep the existing ChangePlan/ChangeAuthorization machinery as the security
   foundation.
2. Add transaction/receipt types only where they collapse an actual duplicated
   lifecycle; do not introduce a second parallel authorization model.
3. Treat direct system rebuilds as candidate/validation operations only; privileged
   mutation must consume an exact realized closure through ActivateSystemClosure.
4. Add target-state observation and post-state verification to high-impact
   operations.
5. Connect generation-changing transactions to boot health and promotion.
6. Convert installer and management UIs to display transaction identity,
   provenance, authorization, verification, and recovery.
6. Complete the Spore/Nixward boundary extraction after contract fixtures prove
   compatibility.

## Current hardening note

ChangePlan freshness now rejects future-dated plans, malformed freshness
windows, policy-overlong TTLs, and zero nonces. This protects against a valid
but not-yet-effective plan becoming executable before its declared issuance
time.



## Configuration/activation split hardening (2026-10-08)

The configuration writer and NixOS activation are separate transactional domains.
The Rust configuration primitive may atomically commit durable source bytes, but
that commit is never interpreted as proof that a running generation changed.
Conversely, once activation begins, the source file is not an automatic rollback
subject because restoring source bytes cannot undo an already-running generation.

The native transaction vocabulary is defined in src/action/config_transaction.rs:

`Prepared -> InputFrozen -> CandidateBuilt -> SourceCommitted -> ActivationStarted`

with terminal/exception states for `Activated`, `FailedBeforeActivation`,
`IndeterminateActivation`, `RecoveryRequired`, and `Recovered`.
Post-attempt runtime evidence is represented separately from child exit status.

`FrozenConfigSource` snapshots the complete intended source tree, including
imported files, through a deterministic manifest digest. Symbolic links are not
admissible inside the snapshot. The snapshot can be revalidated before realization
to detect source drift.

The config writer's authoritative replacement primitive now uses an exclusive
same-directory candidate, durable candidate data, no-follow target opens, a
Nixward writer lock, atomic replacement, parent-directory synchronization, and
post-replacement read-back verification. Git commits are outside this primitive
and remain only as a compatibility no-op on the writer API.

System activation consumes the exact immutable store-path command only after the
system-profile transition has separately succeeded and been observed. The
Nix-generated activation artifact remains Nix-owned; Nixward supplies exact
identity, authorization, coordination, and observation.

## Frozen-source realization and retention hardening (2026-10-08)

`FrozenConfigSource` is now explicitly separated from the Nix store identity it
protects. The semantic source digest is never treated as a substitute for a Nix
store path or NAR identity.

`NixSourceRealizer` revalidates the complete frozen source immediately before
materialization, invokes an immutable Nix executable by exact store identity with
a minimal explicit environment, parses only a canonical `/nix/store/...` result,
and compares the realized tree against the frozen manifest before accepting it.

The resulting store path is retained by a transaction-scoped GC root under
`/nix/var/nix/gcroots/nixward/<transaction-id>`. Root creation is descriptor-bound
to the GC-root namespace, synchronized durably, and followed by independent
read-back verification. A journaled `Rooted` state therefore means that the live
root was observed, not merely that a serialized record claimed it.

This is an input-retention boundary, not yet a complete candidate-build binding:
the next privileged build step must consume the exact retained source store path
and bind its resulting system closure to the same transaction without resolving
the source from the mutable working tree.

## Immutable candidate-build binding (2026-10-08)

The frozen-source retention boundary is now connected to an actual candidate-build primitive.
`NixCandidateBuilder` refuses unrooted or stale source realizations, accepts only a `.#...`
flake-relative installable, rewrites that installable against the exact retained source
store path, and invokes Nix through its immutable `/nix/store` executable identity.

Candidate stdout is accepted only when exactly one canonical store path is emitted, and
that path must equal the externally authorized `expectedOutPath`. The builder then rechecks
the retained source and emits `CandidateBuildReceipt`, which binds the source digest, exact
source store path, candidate store path, and realization-plan digest.

`ConfigTransaction::advance(CandidateBuilt)` and `SourceCommitted` now require that receipt.
A legacy serialized candidate path can remain readable for migration evidence, but it cannot
grant candidate-build or activation authority.

The validation PR is also topology-bound: its hosted validation job fetches
`hardening/full-stack-qualification-2026-10-08` and requires its live SHA to equal the
validation PR head before qualification proceeds. A moving hardening branch therefore cannot
silently qualify an older validation mirror.

## Pidfd-backed worker receipts and launch environment (2026-10-09)

Exact profile-transition, activation, and recovery children are spawned through the journal-aware worker runner. Before waiting for process completion, the runner opens a Linux pidfd, cross-checks `/proc/<pid>/stat` start time across acquisition, records the boot ID + PID + start-time + exact executable + invocation digest + environment digest, appends the receipt to the transaction, and fsyncs the journal.

Recovery reacquires a pidfd for each recorded worker and checks boot identity and process start time both before and after acquisition. A matching live worker blocks further mutation; missing pidfd support or an ambiguous observation fails closed. PID alone is never treated as a stable process identity.

The invocation digest covers the executable and each length-framed argument, including boundaries. The process environment is cleared and rebuilt from a fixed allow-list (`HOME`, locale, `NIX_USER_CONF_FILES`, `PATH`, terminal/color, and XDG config). The environment digest is stored with the worker receipt so the exact launch policy is auditable. NixOS's generated activation script establishes its own PATH from declared system dependencies; the worker PATH is only the launcher environment, not a substitute for that build-time dependency closure.

The transaction journal schema is now `luminous-nixward-config-transaction-v6`. Worker receipts without the required environment digest and observed process image are intentionally invalid; the executor will not silently promote an older incomplete receipt to current worker authority.

Qualification is still contingent on a completed hosted run for the exact synchronized hardening/validation head. Pidfd semantics are grounded in Linux `pidfd_open(2)` (stable task handle and pollable exit indication) and the current Rust/Tokio process APIs; the implementation uses the Linux syscall path because Rust's standard-library pidfd wrapper remains experimental.

The worker receipt distinguishes the declared launcher from the observed `/proc/<pid>/exe` image. Native executables must match exactly. NixOS's generated `switch-to-configuration` wrapper is handled by a narrowly parsed path: its immutable script must have a store-backed interpreter, exactly one direct store-backed `exec` target, and exact `"$@"` argument forwarding (optionally `exec -a "$0"`). The observed image and `/proc/<pid>/cmdline` must match either the interpreter-before-exec state or the wrapper's actual target after exec. Generic shells, PATH lookup, extra exec arguments, shell expansion, and unrecognized wrapper forms fail closed.

Both `nix store add` and `nix build` clear inherited environment and suppress root user Nix configuration via `NIX_USER_CONF_FILES=/dev/null` and `XDG_CONFIG_HOME=/var/empty`; neither is allowed to inherit `NIX_CONFIG`, `NIX_PATH`, loader variables, or shell startup environment.

Worker purposes are now separate for `ProfileTransition`, `Activation`, `RecoveryProfileTransition`, and `RecoveryActivation`. A receipt carrying one PID + boot ID + process start time cannot be relabeled as a different purpose in the same journal, and recovery admission requires evidence for the phase it is recovering.

## Activation launcher grammar and identity binding (2026-10-09)

The worker verifier now parses the complete NixOS `switch-to-configuration` shell wrapper before it accepts the observed executable/argv pair. It does not merely find a plausible final `exec`: it allows only one direct `exec`, exact argument forwarding, a fixed set of environment exports, no duplicate assignments, no shell substitutions/escapes, and no executable statements before or after the handoff.

The accepted exports include the current Nixpkgs `SYSTEMD` setting in addition to `OUT`, `TOPLEVEL`, `DISTRO_ID`, `INSTALL_BOOTLOADER`, `PRE_SWITCH_CHECK`, and optional `LOCALE_ARCHIVE`. `OUT` and `TOPLEVEL` must match the declared system closure root; helper paths must resolve lexically to canonical Nix store objects. A wrapper that does not satisfy that exact topology is rejected rather than normalized or guessed.

The unit fixture covers the current direct-exec wrapper plus rejection of wrong `OUT`/`TOPLEVEL` binding, mutable helper paths, pre-exec payloads, command substitution, forbidden environment exports, shell `-c` indirection, and argument drift.

Qualification remains evidence-gated: this source review is not a compiler result. Exact-head hosted validation must run the real test matrix before the branch can be classified as qualified.

## Journal-owned activation capability (2026-10-09)

The public activation and recovery entry points treat command, signed
authorization, and transaction ID as inputs to journal admission, not as a
standalone execution capability. A shared journal validator binds the
transaction identity and plan digest to the retained candidate receipt, exact
installable selector, realization-plan digest, selected profile, and permitted
phase before an ephemeral capability can be issued. The mutation routines
accept only their corresponding non-cloneable, non-serializable capability
while the transaction interlock remains held. Primary activation and recovery
use different capability types so recovery admission cannot be relabelled as
new activation.

Dry-run mode now rejects both privileged entry points before journal loading,
transition, or worker spawn. Dry-run is a non-mutating preview, not a
transactional activation success.

This is a source-level architectural change, not a qualification receipt. The
hardening and validation PR heads must remain exactly synchronized, and the
exact head still requires completed hosted compiler/test evidence before a
qualified status can be claimed.
