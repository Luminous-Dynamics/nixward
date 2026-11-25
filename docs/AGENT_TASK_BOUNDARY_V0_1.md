# Agent Task Boundary v0.1

**Status:** typed binding and offline conformance contract. Not a production task runner, live egress enforcer, or security certification.

## 1. Purpose

Bind a high-risk agent task to one exact execution identity and one separately authorized network policy. The intended object is:

`tenant / Holon + task + principal + task-plan digest + pinned guest artifact + realized launch receipt + workload identity + network policy + compiled policy + expiry + owner signature`

The contract is designed for the ARTEX-like capability class: planner/worker systems that may spawn children, enumerate assets, invoke tools, retain task memory and iterate after an initial goal. It does not depend on ARTEX names, ports, User-Agents, model providers, or scanner signatures.

## 2. Current Nixward primitives reused

| Existing primitive | What it establishes | What it does not establish |
|---|---|---|
| Software Ingress Covenant | S2/S3 artifact identity, guest permissions, digest-bound plan | That an agent task is authorized or that every runtime control is active |
| Rootless OCI guest launcher | Rootless Podman command, digest-pinned image, read-only root option, no host network mode | Per-task egress enforcement when networking is enabled |
| GuestRealizationReceipt | Structural consistency between the requested OCI plan, artifact identity and launch-contract fields | Actual runtime rootless/read-only/no-host-network state or cryptographic authenticity of the observation source |
| WorkloadIdentity | Holon + guest-plan digest + artifact identity + launch-authority digest | That the network policy is attached to the intended live cgroup |
| NetworkPolicyPlan | Exact workload-scoped declared egress; host ingress/forward default deny; no reasoning authority | Workload egress is still marked declared, not runtime-enforced |
| NetworkEnforcementPlan | Exact rules, required kernel hooks, cgroup bindings and fail-closed runtime proof contract | It is not activated by compilation or by lab readiness |
| AuthorityVerifier | Ed25519 signature over an exact action, subject, Holon and audience | Replay consumption or actual execution; the participant must consume the replay key atomically |

## 3. AgentTaskNetworkContract

The new `agent_workload` module binds:

- one human-readable Holon / tenant identifier and its domain-separated digest;
- one task ID, agent-principal digest, and full task-plan digest;
- one OCI S2 guest plan, a re-derived GuestRealizationReceipt, and the immutable artifact identity;
- one WorkloadIdentity whose guest plan, artifact and launch-contract digests match;
- exactly one workload in the NetworkPolicyPlan;
- the exact policy digest, compiled enforcement-plan digest and allowed-destination-set digest;
- issuance time, expiry (maximum 15 minutes), and nonce digest;
- an explicit status of `bound-not-runtime-enforced-v1`.

The owner-signable challenge uses `AuthorityAction::NetworkActivate` and signs the digest of the entire contract. A changed task, principal, artifact, workload, policy, destination set or expiry changes the subject and invalidates an earlier signature.

The contract also carries the machine-readable receipt scope `plan-consistency-and-artifact-identity-only-not-runtime-isolation-proof-v1`. This is required because the current `observe_oci` adapter checks the image digest but populates rootless, host-network, read-only and mount observations partly from the requested plan. It does not independently inspect the live container configuration. The receipt can bind the requested artifact and launch plan, but it must not be used as runtime isolation proof.

The nonce entropy passed to the constructor must come from the host OS CSPRNG. This module does not generate entropy or consume the replay key. The participant must atomically consume the verifier's replay key immediately before any consequential act.

## 4. High-risk workload profile v0.1

The initial contract deliberately supports a narrow profile:

- OCI S2 only, rootless Podman, read-only root, no host network;
- zero host filesystem mounts, devices, raw secrets or privileged capabilities;
- no host PID, host-root write, Docker socket or Nix daemon access;
- one tenant / one task / one workload identity per contract;
- egress only, TCP or UDP, explicit ports, maximum 32-port span;
- explicit canonical IPv4/IPv6 CIDRs only; all-address routes and hostname entries are rejected;
- no ingress or listen capabilities;
- guest network permission must agree with whether any egress capabilities are declared;
- unresolved rules, a mismatched compiled plan, fail-open state, or a reasoning-authority claim are rejected.

Why hostnames are rejected: the current compiler does not have an authenticated resolution binding. DNS changes, CNAME chains, rebinding, redirects, proxies and the final connect destination must be bound to one resolution/connection policy before hostname egress can safely be admitted. Silently resolving a hostname during compilation would not solve rebinding at connection time.

## 5. Critical non-claims

This v0.1 contract does **not**:

- run an agent, launch a guest, or attach a cgroup/BPF program;
- prove that a source observation is cryptographically authentic merely because it is structurally valid;
- prove production egress enforcement or task isolation from a test fixture;
- implement a DNS, redirect, proxy, TLS-SNI or QUIC policy;
- implement dynamic lease issuance/revocation or replay-key consumption;
- grant Symthaea host shell access or automatic remediation authority.

The network-enforcement plan must remain `disabled-until-runtime-proof-v40`. A passing runtime-lab report is only backend maturity evidence; target-host feature probes, exact cgroup bindings and a separate owner-authorized activation path are still required.

## 6. Tests added

Ten Rust unit tests cover:

1. exact one-tenant / one-task / one-artifact / one-policy binding;
2. wildcard CIDR rejection;
3. hostname rejection without a resolution proof;
4. invalid and non-canonical CIDR rejection;
5. wrong workload binding;
6. substituted guest-receipt rejection;
7. owner signature over the complete task-bound network contract;
8. task mutation invalidating the earlier owner signature;
9. expiry rejection;
10. host mount and unsafe guest profile rejection.

These are source-level tests only until executed with the pinned Rust toolchain. No compile, clippy, Nix evaluation, runtime-lab or CI pass is claimed here.

## 7. Next qualification increments

### P0 — source and artifact authenticity
Bind the local guest inspection to an authenticated Nixward host receipt and exact machine/boot identity. Verify registry signature/provenance and OCI digest before guest start. Never treat a tag or self-reported digest as authority.

### P1 — per-task egress enforcement
Extend the runtime backend so exact task cgroups—not merely workload-plan identities—are bound to the live task. Add negative tests for cgroup swap, policy update race, process migration, alternate network namespace, UDP, IPv6, proxy bypass and enforcer restart.

### P2 — authenticated name resolution
Add a resolution contract binding hostname, DNSSEC/trusted resolver policy, answer set, TTL, CNAME chain, resolver identity, task/policy digest, and connection-time destination. Revalidate redirects and connect targets. Where L7 semantics matter, use a separately authenticated egress proxy rather than pretending an L3 CIDR allowlist validates HTTPS hostnames.

### P3 — isolated runtime replay
Run only synthetic fixtures in a disposable NixOS VM. Record target-host kernel probes, cgroup identity, actual packet allow/deny receipts, process lineage, guest observation and independent service oracle. A model statement such as `blocked=true` is never a receipt.

### P4 — task security benchmark
Use Platform ATR-001..ATR-020 and report hard-gate effects, task completion, false refusals, false assurance, attribution, p50/p95 detection and containment, resource budget and provenance. Keep evaluator-private ground truth outside the candidate boundary.

## 8. External alignment

- OASB-1 / OASB Eval: map identity/provenance, capability authorization, supply chain, credential protection, operational controls and monitoring. Do not reuse self-labelled benign samples to estimate false-positive rates.
- IETF draft `draft-hcf-bpm-agent-security-benchmark-profiles-00`: declare the system-under-test boundary and scenario profile with every metric; its status is work in progress, not a final standard.
- MITRE ATT&CK Evaluations: map technique coverage, detection/protection outcomes and source-of-action disclosure, but compare only matched configurations and scenarios.
- AgentDojo / indirect-injection work: report attack success and legitimate-task utility together; safe abandonment is not successful task completion.

## 9. Claim ceiling

The correct current claim is narrow:

**Nixward now has a typed, expiring, owner-signable contract that binds one OCI guest plan and its plan-consistency receipt to one tenant workload and one exact declared egress policy, while refusing unresolved hostnames and unsafe guest profiles. This is not a runtime isolation attestation.**

This is not evidence that production network enforcement is active. That requires the target/runtime qualification sequence above.
