# Network Observation Evidence Contract (M1)

**Status:** Design contract; not implemented or qualified  
**Date:** 2026-10-12  
**Parent:** [Sovereign Network OS architecture](SOVEREIGN_NETWORK_OS_ARCHITECTURE.md)  
**Scope:** Read-only inventory and evidence verification for a Linux network namespace. This specification is a prerequisite for any write-capable network adapter.

## 1. Purpose and decision rule

The collector produces observations. The verifier decides whether the observation evidence is acceptable for a stated use. The planner consumes only a verified snapshot and produces a proposal. No component may infer that the inventory is complete merely because the collector returned success, because a digest matches, or because the current inventory agrees with desired state.

The default is **not safe to plan mutation**. A snapshot may become eligible for read-only planning only when all policy-required source families have evidence that satisfies this contract. A future mutation authorization layer must impose stricter freshness, ownership and target-specific rules again immediately before the operation.

Use distinct outcomes:

- **CompleteForDeclaredScope:** every required family/dump completed according to its family-specific protocol, raw evidence is verifiable, no loss/interruption/integrity flags were observed, required fields are understood, and the stated coherence policy passed.
- **Incomplete:** required evidence is absent, a dump was interrupted/truncated/lost, parsing or verification failed, target identity changed, a required resource kind is not covered, or temporal coherence cannot be established to the declared policy.
- **Unsupported:** the collector/backend explicitly cannot observe a required family or semantic field on this target/version.
- **Invalid:** structurally malformed, identity-mismatched, digest-mismatched, noncanonical or contradictory evidence.
- **Expired:** the evidence was valid when collected but is too old for the caller's freshness policy.

Only CompleteForDeclaredScope allows the planner to treat the observed set as complete **within the enumerated scope and known limitations**. None of these statuses proves that a buggy or compromised kernel, driver, firmware, manager or collector told the truth. The trust boundary and trusted computing base must be documented.

## 2. Core non-claim: no implicit global atomic snapshot

A multi-source network inventory is not assumed to be an atomic snapshot.

Linux Netlink can mark a dump with NLM_F_DUMP_INTR when a kernel-side iteration may be inconsistent; the userspace client should retry that dump. A lost Netlink message, including ENOBUFS, or a truncated receive is also not evidence that a missing object does not exist. Even if all individual dumps complete, link, address, route, neighbor, nftables, WireGuard, FRR, systemd-networkd and NetworkManager observations occur through distinct interfaces and at different times.

Therefore:

1. Record a time interval and provenance for every source request, not just one timestamp for the whole snapshot.
2. Expose separate dimensions for source integrity/completeness and cross-source temporal coherence.
3. Never advertise a global atomic-snapshot property unless the backend provides and the verifier proves such a property.
4. If policy requires stable cross-source coherence but the collector cannot demonstrate it, return Incomplete rather than silently downgrading to a weaker assertion.
5. Do not treat a complete inventory as proof that each manager has a unique writer, or that the inventory still matches by the time a later mutation starts.

## 3. Trust roles

### Collector
A bounded, read-only program that gathers raw source replies and notifications. It owns no network mutation capability. It records failure conditions rather than repairing, normalizing away or silently dropping them.

### Evidence packager
Builds a schema-versioned envelope containing raw evidence references/digests, parser inputs, collector build identity, request/response outcomes and target identity. It may canonicalize for deterministic comparison but retains raw artifacts needed to reproduce the canonicalization.

### Independent verifier
Validates envelope schema, digests, exact artifact bytes, collector/target identity, family-specific completion rules, parser version, required fields, duplicate/conflicting entries and coherence rules. It must not trust the collector's self-reported complete=true field. It recomputes acceptance from raw evidence and policy.

### Planner
Accepts only a verifier output bound to the exact evidence-envelope digest, target identity, scope, verification-policy version and declared limitations. The existing M0 planner's input digest binding is a useful integrity boundary, but is not the verifier itself.

### Mutation broker (future, out of scope for M1)
Would require fresh target evidence, current owner/authority agreement, specific authorization and resource-scoped capabilities; it may not rely only on an old planner artifact.

The collector and verifier may share schemas and generated decoders, but they must not share an unchecked boolean as the basis for completeness. For high assurance, make a second independent collection or authoritative cross-check part of policy for critical resource families. This reduces common-mode implementation risk but does not protect against a compromised kernel or two observers that use the same faulty source.

## 4. Evidence envelope

Every envelope must validate against a pinned schema version and bind at least:

### Envelope identity
- Schema identifier and version.
- Collection identifier: random or otherwise collision-resistant identity for one attempt.
- Stable logical target identity and exact target class.
- Host boot ID for local Linux collection.
- Network namespace inode identity and the mechanism used to pin/verify the namespace for the collection lifetime.
- Collector identifier, package/store/build identity, executable digest and source revision when available.
- Collector protocol version, parser/canonicalizer version and verifier-policy version.
- Start/end wall-clock timestamps plus monotonic start/end offsets where available; record clock source/quality. Wall time alone is not a freshness or ordering proof.
- Effective UID/GID, effective/permitted capability evidence, relevant LSM/systemd sandbox identity, and whether the collector has any mutation-capable file descriptor or API. M1 should be read-only by construction.
- Exact requested scope and required resource kinds, including family/version/feature coverage expected by policy.

### Per-source operation record
For each request/dump/API observation:
- Source ID, family/API name, target/namespace identity and request kind.
- Request sequence identifier where the protocol supports one; socket/family identity and relevant flags.
- Start/end monotonic time and source timestamp/version/generation identifier when available.
- Raw request and response artifact digests plus byte lengths; retain exact artifact bytes or immutable content-addressed references with access controls and documented retention.
- Completion condition actually observed, such as a valid Netlink NLMSG_DONE and its status, a gNMI initial-sync marker for a subscription snapshot, or the backend's documented equivalent. Do not infer completion from timeout, socket close, empty data set or API call returning without a parse error.
- Every message type/flag, error/ack, drop counter, truncation indicator, interrupted-dump indicator, malformed message and retry history.
- Parser outcome, unknown attributes/fields, duplicate IDs, canonicalization digest and count before/after normalization.
- Completeness state computed by verification; any collector-supplied status is advisory only.

### Envelope digests
- A raw-artifact digest over each byte-exact source artifact.
- A canonical semantic digest over a schema-versioned, deterministically encoded resource set, preserving distinctions that matter to the domain.
- A separate envelope digest binding metadata, scope, artifact references, raw/canonical digests, outcomes, coherence status and verifier policy.
- Domain-separated digests; never reuse a digest across semantically different object types without the domain being part of the preimage.

A digest proves byte identity relative to a supplied digest. Authenticity requires a trusted origin/signature or local protected provenance; completeness requires the family-specific evidence checks below.

## 5. Resource coverage contract

The collection policy must enumerate resource families and required fields for the intended use. An absent family can never be treated as an empty family unless an authoritative, complete response expressly establishes that the family was observed and contained zero objects.

Initial candidate families:
- links and link attributes;
- IPv4/IPv6 addresses and prefix/lifetime/state attributes;
- IPv4/IPv6 routes, route rules, nexthops and required routing attributes;
- bridge/VLAN membership and relevant port attributes;
- neighbors where they matter to the target invariant;
- nftables tables/chains/rules/set metadata through an authoritative supported interface;
- WireGuard interface/peer metadata while preventing private keys or PSKs from entering artifacts;
- systemd-networkd and NetworkManager managed/unmanaged/ownership state;
- FRR running/candidate configuration and relevant operational state for routing scopes;
- host firewall, policy-routing and namespace boundaries that could affect the requested change.

This list is not a claim that M1 has implemented all these families. Each family must be explicitly required, optional, unsupported or out-of-scope by a versioned collection profile. An optional family still records why it was not collected. A required family that cannot be collected causes an unsupported/incomplete result, not a pass.

Secrets are excluded at source: do not capture WireGuard private keys, peer PSKs, credentials or bearer tokens in raw/logging artifacts. If a backend's raw output contains secrets, use a separately specified redaction/evidence method and prove it preserves the fields needed for completeness; do not casually hash/strip text and assume semantic validity.

## 6. Netlink/rtnetlink family acceptance

This section defines minimum requirements for the first Linux collector, not an implementation claim.

For each multipart dump:

1. Use a unique request sequence and verify all replies belong to the expected family/request/sequence and target socket context. Validate message lengths, alignment, framing and attribute structure before parsing.
2. Record every reply, including non-resource control messages. Require the family-appropriate successful terminal signal, normally NLMSG_DONE, and parse any error/status embedded in it according to the API contract.
3. Inspect NLM_F_DUMP_INTR on every message, including terminal messages. Any occurrence makes the attempt inconsistent; discard it as complete and retry under a bounded policy.
4. Treat NLMSG_ERROR, a negative dump completion status, a short/malformed message, unexpected sequence, MSG_TRUNC, socket receive loss/ENOBUFS, parser overflow or unexplained socket termination as failed evidence. Retain a failure record and retry only within the explicit retry/deadline budget.
5. Treat unknown attributes as a policy decision: unknown optional fields may be preserved as opaque raw data when they cannot affect the requested invariant; unknown or missing fields that could affect that invariant mean Unsupported or Incomplete. Do not ignore them silently.
6. Detect conflicting duplicate identities instead of selecting a convenient last value. Preserve raw ordering and also compute the defined canonical ordering for comparison.
7. Set hard bounds on message count, total bytes, object count, individual attribute length, retries and collection duration. Hitting a limit is incomplete evidence, not successful truncation.
8. Never request NLM_F_ATOMIC and then assume that it guarantees a system-wide atomic inventory. It does not solve coherence across separate families, kernel APIs or managers, and any atomic-dump capability must be documented per family and kernel.
9. Subscribe to relevant notifications before the dump only if the collection policy defines how to record/replay them; track loss and errors. If mutation events arrive during a required stable-window capture, mark the snapshot temporally unstable unless the algorithm has a proven reconciliation rule. A notification stream by itself is not a snapshot.
10. Repeat critical dumps or compare a start/end version/notification fence where supported. If the kernel does not expose a reliable version fence for that family, label the result a bounded observation window, not atomic.

Retry only a bounded number of times. Exhausted retries produce Incomplete. Do not return the last partially failed sample as accepted just because its parse succeeded.

## 7. gNMI/OpenConfig and manager-specific observations

gNMI is a useful management interface, but it has its own semantics. The verifier must bind the target's reported capability/model versions and requested paths. It must distinguish:
- Get replies from Subscribe initial synchronization;
- ONCE, POLL and ongoing STREAM semantics;
- initial synchronization completion from periodic/ongoing updates;
- timestamp sampled for the snapshot from client receipt time;
- target/model/path coverage from an empty response;
- a complete reply for requested paths from completeness of the entire device state.

The gNMI specification says Get is intended for relatively small complete objects and is not suited to very large tables such as complete routing tables; Subscribe with ONCE may be appropriate for large enumerations. Streaming update messages do not necessarily represent one coherent global snapshot. Unsupported or omitted required model paths must be reported.

For FRR, prefer its documented management framework where the selected release and daemon feature support it. FRR MGMTd documents candidate/running/operational data stores, validation/commit operations and backend-specific support. Do not assume every YANG subtree or every daemon is managed by MGMTd on every version. Pin FRR version and query/test the declared capability matrix. Configuration state and operational routing state remain distinct evidence families.

For systemd-networkd, NetworkManager, nftables, WireGuard and any ASIC SDK, define separate family adapters and verifiers. Never infer their state from the kernel link dump alone; an effective kernel value does not identify the policy authority that will next rewrite it. If intent authority is unknown or two managers claim the same resource, mark ownership Conflict or Unknown and block mutation.

## 8. Temporal coherence and freshness

The envelope reports at least:
- source interval per family;
- maximum source skew;
- whether a change was observed during collection;
- whether loss or a gap was detected;
- coherence class, using names such as per-source-complete-only, bounded-observation-window, event-fenced-stable-window, or a future explicitly proven backend-specific atomic class.

Do not call a bounded-observation-window atomic. If no change event is observed, that is evidence only subject to notification-loss guarantees and source semantics.

The collection profile sets maximum age and skew based on proposed operation. Route inspection or a dashboard may tolerate a longer interval than editing a default route, firewall management access or changing an address on the management interface. The planner can report a useful stale proposal, but any mutation broker must re-observe its critical predicates immediately before applying. Fresh pre-observation still does not close a race with external writers; ownership coordination or a backend conditional operation is separately required.

## 9. Ownership and authority evidence

Inventory answers “what is present?”; it does not answer “who is allowed to change it?” Collect authority and runtime ownership separately, using source-specific evidence:
- NixOS declared intent and exact evaluated source/closure identity;
- systemd-networkd effective configuration and link-to-network file provenance when available;
- NetworkManager device/profile state;
- FRR configured versus operational state;
- kernel effective state and namespace identity;
- vendor controller/SAI state for hardware-backed resources.

Ownership records must name source and evidence method, not just a string label. If two active managers can reconcile the same resource, report conflict. Do not automatically choose Nixward as the new owner simply because it can parse a resource. Adopting ownership is a separate explicit migration transaction.

## 10. Verification algorithm and acceptance outputs

The independent verifier should:
1. Validate schema/version and reject unknown security-critical fields.
2. Recompute every raw digest from exact artifacts.
3. Parse raw source replies with the pinned parser contract; reproduce canonical resources and their digest.
4. Verify target, boot, namespace, collector and policy identity are internally consistent and match the caller's requested scope.
5. Recompute per-operation outcomes from terminal markers, flags, errors, drops, truncation, bounds and retry history.
6. Verify every required family is covered by an accepted source attempt and every claimed resource kind maps to a family that can actually observe it.
7. Recompute cross-family skew, change/loss evidence, freshness and the named coherence policy.
8. Check duplicates, contradictory fields, unknown attributes and ownership conflicts.
9. Emit a signed or locally protected verification receipt bound to the envelope digest, verifier build/policy digest, target identity, scope, status, limitations and explicit rejection reasons.

The receipt must not say merely pass=true. It should report dimensions separately:
- Integrity: valid or invalid.
- Coverage: complete, incomplete or unsupported.
- Temporal coherence: class plus measured bounds.
- Freshness: valid or expired.
- Ownership: consistent, conflict or unknown.
- Limitations: explicit list.
- Decision: CompleteForDeclaredScope, Incomplete, Unsupported, Invalid or Expired.

A future mutation broker validates the exact receipt and rechecks target identity, freshness and authority; it must not accept a status from a different envelope or verifier policy.

## 11. Required deterministic test corpus

Implement a frozen fixture set where each case names raw input, expected verifier output and rejection reason. Include at least:

1. A valid empty object table with valid terminal marker versus a zero-byte/no-terminal response.
2. A valid one-object and many-object multipart dump.
3. NLM_F_DUMP_INTR on an intermediate message and on NLMSG_DONE.
4. NLMSG_ERROR and negative completion status.
5. ENOBUFS or explicit loss counter, MSG_TRUNC, unexpected EOF and malformed lengths/alignment.
6. Wrong sequence/family/namespace/boot ID.
7. Unknown optional attribute preserved versus unknown decision-critical attribute rejected.
8. Duplicate identical object versus conflicting duplicate identity.
9. Missing required family versus complete empty family.
10. Retry succeeds within budget versus retry exhausted.
11. Change notification observed during dump; event-buffer overflow/loss; no falsely labelled global atomic snapshot.
12. Stale envelope, excessive skew, clock discontinuity and mismatched policy version.
13. Raw artifact digest mismatch, canonicalization mismatch, tampered target identity and detached receipt mismatch.
14. Conflicting ownership between NixOS, systemd-networkd, NetworkManager, FRR or an explicit adapter.
15. Secret-redaction tests demonstrating no WireGuard private key/PSK or management credential is persisted.
16. Oversized message/object/attribute/deadline bounds.
17. Semantically empty response caused by unsupported path versus authoritative empty resource family.
18. Parser regression fixtures across supported kernel/interface versions.

Use property tests/fuzzing for message framing, nested attributes, canonical resource encoding and receipt parsing. Deterministic fixtures need exact expected outcomes. A failed verifier test, missing corpus case or unclassified error path blocks the gate.

## 12. Staged implementation gates

### M1a: envelope and verifier, no live kernel writes
Implement schema types, canonical encoding, raw artifact preservation, deterministic fixture verifier and receipt. Collector may be a fixture producer. No mutation APIs.

### M1b: read-only Linux Netlink collector
Implement one resource-family adapter at a time; start with links and addresses, then routes/rules. Capture all control messages and errors. Compare against independent commands/libraries in a temporary namespace. Any loss, interrupted dump or mismatch blocks completeness.

### M1c: ownership and manager inventory
Integrate nftables, WireGuard and one declared manager at a time. Do not conflate kernel state with configuration authority. FRR must have its own configuration/operational coverage matrix.

### M1 exit gate
The exact source revision passes formatting, unit/property/fuzz tests, deterministic fixture corpus and independent namespace integration tests. Raw evidence and verifier receipt are captured with exact toolchain/build IDs. No host mutation adapter ships as part of this gate.

A passing M1 gate says only that the selected read-only observer has demonstrated evidence properties for the tested scope and platforms. It does not qualify network mutation, routing convergence, throughput, HA, ASIC support or comparison against Cisco.

## 13. Research references

- Linux kernel Netlink introduction, including dump consistency and NLM_F_DUMP_INTR: https://kernel.org/doc/html/next/userspace-api/netlink/intro.html
- Linux Netlink UAPI flags: https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h
- netlink(7) message framing/flags and dump semantics: https://man7.org/linux/man-pages/man7/netlink.7.html
- OpenConfig gNMI specification (Capabilities, Get, Set, Subscribe and initial sync): https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md
- FRRouting MGMTd candidate/running/operational data and commit behavior: https://docs.frrouting.org/en/latest/mgmtd.html
- FRRouting gRPC northbound (feature stage and transport constraints are version-sensitive): https://docs.frrouting.org/en/latest/grpc.html
- SONiC SAI interface and vendor-implemented ASIC SDK boundary: https://github.com/sonic-net/SONiC/wiki/SAI
- FD.io VPP architecture and supported use cases: https://docs.fd.io/vpp/25.10/index.html

All links are research anchors, not implementation evidence for Nixward.
