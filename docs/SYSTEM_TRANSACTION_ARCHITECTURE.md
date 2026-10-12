# Nixward System Transaction Architecture

## Purpose

Nixward is the sovereign system control plane for NixOS. Installation, rebuilds,
service changes, software realization, boot promotion, recovery, and other
consequential operations should converge on one safety model:

**observe → plan → validate → authorize → snapshot → apply → verify → promote/recover**

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

#### AI proposal provenance

When an AI proposal participates in validation, the validation receipt may commit
to an `AiProposalValidationEvidence` envelope. The envelope joins the exact
ChangePlan digest, the ordinary validation-evidence digest, and the digest of
an `AiProposalBinding` that names the model artifact, input, policy, proposal
output, verifier artifact, and evaluation evidence.

Nixward's `record_validation_with_ai_proposal` path rechecks the proposal
binding against the exact plan and supplied artifact bytes before changing the
transaction to `Validated`. It then records the envelope digest in the existing
validation receipt and returns the typed envelope so the caller can persist it
alongside the referenced evidence. Digest fields use strict 64-character
lowercase hexadecimal JSON strings; see
`docs/fixtures/ai-proposal-validation-evidence-v1.json` for the wire shape.

This preserves the existing transaction wire shape and does not add a new
authorization primitive. Provenance is not approval: the normal detached
authority protocol, freshness and replay handling, exact-command enforcement,
and observed post-state verification remain required.

Schema-v1 proposal output is a typed AiProposalOutputIntent: its bound
representation is canonical, compact serde_json bytes containing the machine
identity, optional full configuration patch (target, original and modified
contents, description), and optional structured NixOSCommand. Callers ingesting
provider JSON may use from_json_bytes to accept harmless whitespace/key-order
variation; it compares the parsed JSON value with the typed schema so unknown
or unrepresented fields cannot be silently discarded, then callers bind
canonical_bytes. The transaction validator requires canonical bytes and checks
the structured fields against ChangePlan::matches_intent before validation can
advance. A cross-language producer should follow the schema and exact byte
fixture at
[docs/fixtures/ai-proposal-output-intent-v1.json](fixtures/ai-proposal-output-intent-v1.json).

This establishes equality between the supplied structured intent and the exact
ChangePlan; it does not prove that free-form model text was faithfully converted
into that structure, that inputs are true, a policy is appropriate, an AI or
cryptographic proof is sound, or a real-world action is safe. The component
translating model output into the structured representation remains an
independent trust boundary. Callers must preserve the returned validation
envelope and the referenced artifacts/evidence needed to resolve its digest.

For consumers that need to evidence the *raw-response-to-structure* step, the
higher-assurance path is `AiProposalResolutionReceipt` plus
`SystemTransaction::record_validation_with_resolved_ai_proposal`:
the built-in JSON resolver hashes the exact model-produced JSON content bytes
(not the surrounding provider HTTP/API envelope), identifies the resolver
contract and embedded resolver-source bytes, canonicalizes the typed intent,
checks that intent against the exact plan, and emits a receipt joining the raw
model-output digest, source digest, canonical-intent digest, and plan digest.
The resolved validation envelope commits the receipt digest alongside ordinary
validation evidence and the proposal binding in the existing transaction receipt.

Only structured model-output JSON matching schema v1 is supported; this
component does not extract content from provider-specific response envelopes or
infer commands from free-form prose. Both raw ingestion and canonical output
serialization enforce a 4 MiB maximum so oversized payloads fail before parsing
or envelope construction. Persist the exact model-output bytes, canonical intent,
resolution receipt, resolved validation envelope, proposal binding, and
referenced evidence. Interchange fixtures are in
[docs/fixtures/ai-proposal-resolution-receipt-v1.json](fixtures/ai-proposal-resolution-receipt-v1.json)
and
[docs/fixtures/ai-proposal-resolved-validation-evidence-v1.json](fixtures/ai-proposal-resolved-validation-evidence-v1.json).

The resolver-source digest identifies source bytes embedded in the build. It
does not attest that the running executable is untampered or prove deployment
provenance. Establishing which binary actually ran still requires a separate
trusted build/release and runtime-attestation mechanism. The receipt proves a
reproducible resolution under the identified source implementation—not the
truth of model claims, the suitability of a policy, or real-world safety.

For deployments that need to check which executable is participating in resolution,
use AiProposalResolutionReceipt::verify_current_runtime and
SystemTransaction::record_validation_with_runtime_verified_ai_proposal.
This reuses Nixward's existing offline Ed25519 SignedReleaseManifest verifier:
the caller supplies the release manifest and a trusted release public key obtained
from an independently provisioned trust root. Verification checks the signature,
the declared release tree's artifact bytes/sizes/executable modes, that the current
process's Linux /proc/self/exe bytes match the manifest-listed executable, and
that a manifest-listed resolver source file matches the source digest in the
resolution receipt. The resulting opaque in-memory runtime binding is committed
through AiProposalRuntimeVerifiedValidationEvidence into the existing transaction
validation digest before the transaction may advance.

The signed release tree must include both the executable and the exact resolver
source artifact, for example at a documented path under
share/nixward/src/action/ai_proposal_binding.rs. The release signing process must
bind source_revision to the reviewed source revision under its own release policy;
the field is a signed release-root assertion, not independent proof of a build.

**Important build-provenance limit:** this verifies that the trusted release signer
signed both the current executable bytes and the matching resolver-source artifact
as members of the same release. It does not independently prove that those source
bytes were compiled to produce that executable. A stronger source-to-binary claim
requires a controlled/reproducible build with independent rebuild comparison or
a separately trusted build-provenance verifier whose claim binds the exact source
revision and executable digest. The release signer must not be treated as proof of
that relationship unless its build process actually establishes it.

This path uses the existing offline signing root; it adds no CI OIDC permission and
does not trust a public key merely because the manifest embeds it. It provides
software-level evidence under the assumption that the running OS/kernel and
process memory are trustworthy. It is **not** TPM/secure-boot measured runtime
attestation, proof against a compromised kernel, proof of reproducible source-to-
binary linkage, or proof that the model's claims are true. Those remain separate
assurance claims.

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
3. Add target-state observation and post-state verification to high-impact
   operations.
4. Connect generation-changing transactions to boot health and promotion.
5. Convert installer and management UIs to display transaction identity,
   provenance, authorization, verification, and recovery.
6. Complete the Spore/Nixward boundary extraction after contract fixtures prove
   compatibility.

## Current hardening note

ChangePlan freshness now rejects future-dated plans, malformed freshness
windows, policy-overlong TTLs, and zero nonces. This protects against a valid
but not-yet-effective plan becoming executable before its declared issuance
time.

