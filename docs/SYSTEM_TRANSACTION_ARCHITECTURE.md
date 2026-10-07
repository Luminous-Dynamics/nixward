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

The executor must not reinterpret the approved request or substitute a new
command.

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
Preparation captures the exact prior `/nix/store/...-nixos-system-*` closure
before authorization, and that closure becomes part of the signed ChangePlan's
recovery binding.

The exact recovery boundary is:

```
observe exact pre-state closure
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
verify the observed post-recovery closure
```

Recovery evidence records the exact closure targeted for recovery and the exact
post-recovery closure observed by Nixward.

This does not make direct `switch-to-configuration` execution equivalent to
the complete NixOS system-profile transition. The profile/boot transition remains
a separate hardening boundary tracked in Issue #6 and must not be silently folded
into the recovery claim.

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

