# MSP Read-Only Observation Contract v0.1

**Status:** Integration design. No production adapter is implied by this document.

## 1. Purpose

Expose a least-privilege, read-only view of NixOS machine state to Luminous Platform and Symthaea while preserving Nixward as the only authority for consequential NixOS host transactions.

This contract is deliberately separate from `SYSTEM_TRANSACTION_ARCHITECTURE.md` and `SYSTEM_TRANSACTION_WIRE_V1.md`:

- Observation exports allow a control plane to understand current state.
- Change plans and signed acts authorize a specific mutation.
- Participant receipts establish what Nixward actually attempted or committed.
- Independent service observations establish whether the customer-facing service recovered.

A read-only observation credential must not imply mutation permission.

## 2. Security boundary

The exported view is a tenant-filtered projection, not a copy of the entire host.

Requirements:

1. The target host derives machine identity locally and authenticates the observation source.
2. Every observation is bound to one machine identity, tenant binding and source instance.
3. Facts include source time, observation time, monotonic sequence, schema version and evidence digest.
4. Unknown, unavailable, stale and permission-denied states are explicit values; they are never silently converted into healthy or empty.
5. Credentials, secrets, private keys, tokens, environment variables, raw home-directory paths and arbitrary log payloads are excluded by default.
6. Raw telemetry remains local unless a separate, purpose-limited disclosure policy authorizes a specific payload.
7. Observation adapters are read-only. They must not expose generic shell, arbitrary systemd, package installation, Nix daemon or filesystem write capabilities.
8. A missing tenant binding, invalid source identity, stale sequence or failed integrity check rejects the observation as untrusted.

The observation API does not replace Nixward's owner authority, release authority, act authorization or transaction receipts.

## 3. Envelope

A versioned export should contain:

| Field | Meaning |
|---|---|
| `schema` | Exact contract schema, initially `luminous.msp.observation.v1` |
| `observation_id` | Unique ID for this envelope |
| `machine_id` | Stable Nixward-controlled machine identity |
| `tenant_binding` | Tenant identifier plus binding provenance; not self-asserted by the AI |
| `source_id` | Authenticated Nixward observer identity |
| `source_epoch` | Monotonic observer epoch; new epoch after trusted state reset/re-enrollment |
| `sequence` | Monotonic sequence within the epoch |
| `observed_at` | Source-observed timestamp |
| `ingested_at` | Control-plane receive timestamp, kept distinct from source time |
| `boot_id` | Boot instance identity, where safely available |
| `generation` | Current NixOS generation and booted generation, when available |
| `configuration_digest` | Digest of the evaluated/realized configuration identity, not secret config contents |
| `observations` | Typed facts, each with its own source/provenance/freshness |
| `previous_digest` | Previous envelope digest for sequence-linked continuity |
| `digest` | Canonical digest of the exact envelope under the pinned schema/algorithm |

The envelope must use a strict, versioned canonicalization profile. Unknown fields are rejected for v1 admission rather than being silently ignored. Sequence numbers, epochs and high-precision timestamps should use an exact integer representation supported by the chosen wire profile.

## 4. Observation classes

Initial v1 facts should be conservative and operationally useful:

### Machine identity and platform

- Nixward machine ID.
- OS / NixOS release and kernel version.
- CPU architecture and coarse hardware inventory.
- Boot instance ID.
- Current, booted and previous known NixOS generation IDs.
- Current system closure/configuration digest.

### Services

- Allowlisted systemd unit names.
- Unit active/sub state and result.
- Last transition time, when available.
- Restart count or failure counter only where the source is reliable.
- Whether the unit is managed by a declared NixOS configuration.

Do not export arbitrary service environment, command arguments or secret-bearing unit contents.

### Software and configuration

- Declared package names and versions from the Nix store closure.
- Store path digest/identity, not an unrestricted path listing.
- Flake/configuration input revisions where public and policy-permitted.
- Configuration drift against the declared system profile.
- Pending rebuild, boot promotion or rollback state.

### Resource and health observations

- CPU, memory, disk capacity and coarse I/O health.
- Filesystem free/used thresholds without arbitrary path disclosure.
- Hardware and kernel health indicators, where available.
- Network interface state and address class; actual addresses are withheld unless a scoped support policy requires them.
- Time synchronization and clock-quality indication.

Each fact should be represented as a typed value with:
- `status`: `observed`, `derived`, `unknown`, `stale`, `unavailable`, `permission_denied` or `invalid`.
- `source`: subsystem / command / kernel API identity and version.
- `observed_at`, `ingested_at` where relevant.
- `valid_until` or explicit maximum-age policy.
- `quality`: source reliability / parse status; not an AI confidence score.
- `evidence_digest`: digest of the immutable underlying receipt or normalized observation.

## 5. Freshness and sequence rules

Freshness is policy-bound and domain-specific; a five-minute-old CPU sample is not equivalent to a five-minute-old revocation status.

- Preserve source event time, ingest time and processing time separately.
- Reject sequence regression within a source epoch.
- Sequence gaps produce an explicit incomplete-observation state; do not infer that omitted events did not happen.
- An epoch change requires a trusted re-enrollment/reset record.
- Clock uncertainty is carried with timestamps; time alone must not establish freshness where clock quality is unknown.
- Topology and service dependencies carry their own epochs. A plan built against an older epoch must be revalidated before it can reach authorization.

## 6. Tenant and data minimization

The MSP control plane must not infer tenant ownership from hostname, DNS suffix, IP address or human-readable labels.

Tenant binding must originate from a trusted enrollment/assignment mechanism and remain independently verifiable.

The adapter should export pseudonymous IDs where the operational task does not require a human-readable asset name. User identifiers, session details, local file paths and raw logs require separate policy and data classification.

No cross-tenant training or search is enabled by this contract. Any later federation requires explicit purpose, approved destination, data classification, minimization, retention and tenant consent. A regex scrubber alone is not proof of anonymization.

## 7. Relationship to consequential actions

This read-only contract MUST NOT accept an action or mutation request.

Consequential NixOS changes continue to use the canonical Nixward lifecycle:

**observe → plan → validate → authorize → snapshot → apply → verify → promote/recover**

An action contract must bind:
- machine identity and tenant binding;
- exact plan and operation digest;
- pre-state and topology/configuration epoch;
- exact target participant and audience;
- one-use act handle and expiry;
- snapshot/recovery binding;
- participant-owned attempt/effect receipt;
- independently observed post-state and service health.

An approval for an earlier plan, different machine, changed configuration or different audience does not authorize a later act. Unknown outcomes require reconciliation before retry.

The MSP agent must never invoke privileged shell or Nix operations directly around Nixward. A caller-provided `verified=true` is never evidence.

## 8. Offline conformance fixtures

Before a live adapter is qualified, add deterministic fixtures for:

1. Correct machine/tenant/source binding.
2. Wrong tenant, wrong machine and source-identity substitution.
3. Stale envelope and stale topology/configuration epoch.
4. Sequence replay, regression, gap and source epoch reset.
5. Event-time versus ingest-time disagreement and clock uncertainty.
6. Unknown field/schema version/canonical digest mismatch.
7. Secret/path/credential redaction and disallowed raw payload.
8. Permission-denied versus absent/empty observation.
9. Changed plan digest after an otherwise valid authorization.
10. Cross-tenant alias collision and identifier confusion.

Negative controls must prove that each invalid case is rejected, not simply logged as a warning.

## 9. Integration sequence

### Stage 1 — schema and fixtures

Publish a schema and Rust types with parser/serializer tests, canonical digests and negative controls. No network listener or mutation API is required.

### Stage 2 — local read-only exporter

Implement an allowlisted Nixward observation exporter. Verify that its systemd sandbox and filesystem permissions cannot mutate machine state.

### Stage 3 — platform collector

Luminous Platform ingests authenticated observations, applies tenant policy, stores immutable provenance and computes a temporal asset/service graph. Symthaea receives a filtered snapshot, not a direct host capability.

### Stage 4 — participant receipts

Bind Nixward's existing exact-plan, authorization, snapshot, apply, verification and recovery receipts to the MSP episode/run IDs. Keep the act and observation channels separate.

### Stage 5 — isolated field qualification

Exercise a disposable NixOS target with source authentication, clock drift, observation gaps, stale epochs and failed postconditions. Independently verify no mutation is possible through the read-only credential.

## 10. Claim ceiling

A schema or local fixture does not establish a working fleet RMM agent. A successful observation export does not establish source authenticity until the target identity and transport are verified. A signed observation does not establish that the observed fact is true. A host state receipt does not establish customer service recovery.

The first qualified claim should be narrow: **a named Nixward version can export an authenticated, tenant-scoped, read-only observation set with explicit provenance and freshness on a tested NixOS version and configuration.**
