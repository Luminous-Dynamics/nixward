# Network Policy Containment v0.1

**Status:** Conservative deterministic Rust reference implementation with unit tests added. Not yet compiled or executed in the current environment; not an authorization primitive or runtime enforcement proof.

## Goal

Before an owner authorizes a changed agent task policy, verify that the proposed NetworkPolicyPlan is contained within a separately supplied operator boundary.

The question is narrowly defined:

**Can the candidate grant any workload, direction, protocol, destination or port tuple that is absent from the declared boundary?**

The v0.1 checker answers this for exact WorkloadIdentity digests, egress-only TCP/UDP, canonical IPv4/IPv6 CIDRs and explicit port ranges. Ingress, Listen and all-address routes are unsupported.

## Result states

- Within — every modeled candidate network tuple is contained by the boundary.
- Exceeds — a candidate workload or a concrete network tuple is outside the boundary. The report includes a counterexample witness.
- Unsupported — input contains a selector or policy shape outside the modeled domain, or validation is insufficient to prove a subset.
- Inconclusive — deterministic work limits are exceeded. V0.1 caps policy sizes and comparison work at 100,000 estimated CIDR/port/boundary-rule interactions.

Only Within is eligible to proceed to a separate owner authorization step. The checker never signs, authorizes, consumes a replay key, launches a workload or activates enforcement.

## Containment semantics

For each candidate workload, the exact WorkloadIdentity digest must exist in the boundary. For each candidate capability, the checker matches boundary rules on exact workload digest, direction and protocol. It then checks each candidate CIDR × port rectangle against the union of matching boundary CIDR/port rectangles.

The port axis is partitioned at boundary interval edges; for each port segment the active boundary rules are constant. The checker then performs an interval-union coverage test on the IP axis. This allows, for example, two adjacent /25 boundary rules to cover one /24 candidate rule, without widening the boundary.

If an uncovered tuple exists, the report contains a specific destination host and port. Candidate capabilities with the same access but a changed capability ID are still shown in the policy delta, but can remain Within if their effective access is contained.

## Explicit unsupported domain

- Hostname selectors: require an authenticated DNS/CNAME/TTL/connect-time resolution covenant.
- Network zones: broad semantic selectors must first be compiled into a proven finite set.
- ICMP and protocol Any: not modeled by v0.1.
- Malformed or non-canonical CIDRs.
- Missing port ranges or unbounded/unsupported policy shapes.
- Invalid, unknown or unparseable boundary data.

Unsupported never silently becomes Within.

## What it does not prove

- That the operator boundary is signed/authenticated. The authority-signature layer must verify the exact boundary separately.
- That provider credentials or tokens are attached only to permitted destinations. NetworkPolicyPlan currently has no complete credential-binding model; this is explicitly outside the v0.1 proof claim.
- That a binary identity is bound to each network connection. That requires a trusted runtime process observer and digest pinning.
- That a policy is semantically safe or non-destructive. Containment asks what the policy permits, not whether a permitted API operation is harmful.
- That the declared plan is active in the runtime. NetworkEnforcementPlan remains disabled until separate target-host proof and owner-authorized activation.
- That the agent's task itself is safe.

## Tests added

Twenty-four Rust tests cover the current finite proof domain, including three exhaustive 4-element differential corpora:
1. identical policy and the permanent non-runtime-enforcement claim;
2. narrower CIDR/port policy;
3. IPv4 CIDR-union coverage;
4. IPv6 adjacent-prefix union coverage;
5. adjacent port-range union coverage;
6. concrete destination and port expansion witnesses;
7. first-uncovered-address witness for partial CIDR overlap;
8. protocol isolation (TCP does not cover UDP);
9. a broad `Any` protocol boundary remains Unsupported rather than becoming a false expansion, while explicit supported coverage still proves Within; report digests are deterministic and bind the decision and evidence fields;
10. workload identity expansion;
11. hostname and zone selectors;
12. ingress and all-address selectors;
13. malformed/non-canonical CIDR;
14. oversized input returns Inconclusive;
15. exhaustive small IPv4 address-set inclusion (225 boundary/candidate pairs);
16. exhaustive small port-set inclusion (225 pairs);
17. exhaustive small destination×port tuple-set inclusion (225 pairs).

These are source-level test cases only until executed with the pinned Rust toolchain. No compilation, clippy, formatting, Nix build or CI pass is claimed.

## Next integration stages

1. Authenticate the operator boundary and include its signature/issuer/revocation/expiry in the verification envelope.
2. Integrate the boundary digest and proof report into AgentTaskNetworkContract. The owner-signable challenge must bind boundary digest, candidate digest, task/workload digest and prover version. A post-proof change invalidates the proof and authorization.
3. Model provider/credential attachments and check newly credentialed reach.
4. Add trusted per-connection executable identity and digest pinning; a path or command-line string is not identity.
5. Add authenticated DNS resolution and redirect/connect-time binding before allowing hostnames.
6. Differential/property tests against an independent reference model; later compare with an optional Z3/SMT backend. Unsupported solver shapes/timeouts remain fail-closed.

## OpenShell comparison

NVIDIA OpenShell's open-source prover models selected credentialed-reach and capability-expansion questions with Z3. Its docs explicitly distinguish formal permission reach from semantic destructiveness. Nixward v0.1 starts with a simpler exact finite-set reference checker; it should remain a trustworthy oracle for the supported subset before an SMT backend is added.

Pinned review source: OpenShell commit 9f7cc51329c775441b953499633ab765831cff38.


The module also exposes `verify_policy_within_boundary`, which recomputes the containment result and returns a `VerifiedPolicyContainment` token only for `Within`. The token has private fields and commits to the exact boundary-policy digest, candidate-policy digest, prover version and report digest. `Exceeds`, `Unsupported` and `Inconclusive` return the full report instead. The token is suitable as a future input to the task authorization subject, but it is not an owner signature and does not establish runtime enforcement.
