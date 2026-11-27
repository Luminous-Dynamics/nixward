# Agent Runtime Assurance and SOTA Qualification v0.2

**Status:** research architecture and proposed benchmark protocol. This document does not claim implementation, runtime enforcement, attestation, certification, or measured superiority.

**Related implementation:** [task-bound workload contract PR #165](https://github.com/Luminous-Dynamics/nixward/pull/165), [policy-containment verifier PR #168](https://github.com/Luminous-Dynamics/nixward/pull/168), [observer qualification issue #169](https://github.com/Luminous-Dynamics/nixward/issues/169), and [Platform ATR benchmark PR #537](https://github.com/Luminous-Dynamics/luminous-platform/pull/537).

## 1. The field-level shift

The security question should not be "did the model follow the policy?" It should be:

> Can an independently verifiable chain establish that this exact tenant, task, principal, executable and runtime were authorized to produce this exact externally visible effect—and that no other effect escaped the boundary?

The model is an untrusted proposer. A prompt, tool response, agent-authored log, successful process exit, signed-but-stale receipt, or valid policy proof is never sufficient by itself to authorize or verify an effect.

The architecture should separate three planes:

1. **Authority plane:** an owner authorizes a precise task, principal, artifact, policy boundary, audience, expiry and one-use capability.
2. **Enforcement plane:** a runtime binds that capability to the exact live process/cgroup and mediates every relevant operation.
3. **Evidence plane:** independent observers record attempted actions, actual boundary decisions, committed effects and service postconditions. Their receipts are independently checked and anchored.

Each plane has a separate trust identity. A component must not mint the evidence used to verify its own consequential claim.

## 2. Assurance levels: prevent claim inflation

Treat assurance as explicit levels, not one "attested" boolean.

| Level | Name | Minimum evidence | Does not establish |
|---|---|---|---|
| A0 | Declared | A policy, launch plan or configuration was supplied | That it was applied |
| A1 | Policy-contained | A verifier proves a candidate policy is within an independently supplied boundary over its declared model | Owner authenticity, runtime attachment or effects |
| A2 | Source-consistent observation | Independent runtime and host observations agree across a bounded monotonic collection window | Observer authenticity, kernel integrity or persistence |
| A3 | Authenticated observation | A scoped observer key signs a receipt; verifier checks key generation, validity, revocation, host/boot binding and nonce | That kernel claims are true on a compromised host |
| A4 | Durable temporal evidence | Monotonic sequence survives restart; crash-consistent log verifies; head is independently anchored or witnessed | That policy is active or that no effect bypassed it |
| A5 | Runtime enforcement | The intended hook/policy is verified on the exact live workload identity, with independent allowed/denied traffic controls | That a particular business operation had the intended effect |
| A6 | Effect-verified | Independent packet, participant and service observers reconcile the actual effect and postcondition | Universal immunity beyond the declared profile and test domain |

A transition to a higher level requires all lower-level prerequisites. A hash chain cannot jump A2 to A4. A signature cannot jump A3 to A5. A runtime enforcement probe cannot establish A6 without an independent effect oracle.

Current Nixward PR #165 is a bounded A2 source-consistency snapshot plus an A1 policy-containment token in an owner-signable task contract. It is **not A3–A6**. Its **runtime-observed-not-enforced-v3** status and disabled enforcement plan are correct and must remain so.

## 3. The next reference architecture: proof-carrying effects

A consequential operation should produce a linked receipt sequence:

**Intent → AuthoritySubject → PolicyProof → RuntimeBinding → CapabilityLease → EnforcementDecision → EffectReceipt → IndependentVerification → Anchor**

The owner-signable subject should bind, at minimum:

- tenant/Holon, task ID, principal identity and complete task-plan digest;
- exact guest artifact digest, launch plan and workload identity;
- candidate policy digest, owner-boundary digest, prover version and report digest;
- observer identity/key ID/generation, signed snapshot digest and externally retained checkpoint;
- host/boot epoch and exact workload identity: PID start-time, process handle, executable identity, namespace identities, cgroup object identity and policy generation;
- audience, action/effect class, issue time, expiry, nonce and revocation epoch.

Do not use a cgroup path as the sole identity. Paths are names and can be rebound; record the kernel object identity and its hierarchy/mount context. Likewise, PID plus start-time is a useful identity tuple but not a substitute for holding a stable process reference while checking it.

The enforcement receipt should bind the exact subject digest, runtime generation, workload/cgroup identity, attached hook/program identity, decision, reason code, and monotonic event sequence. The effect receipt should bind the request/flow correlation ID, destination and protocol, participant result, service-observer result, and pre/postcondition digests.

An attempted action, an enforcement denial, a committed effect and a verified service outcome are four different records. Never collapse them into one success field.

## 4. Observer identity and temporal anti-rollback

### 4.1 Authenticate the observer, not merely its bytes

The current Podman/procfs collector improves source agreement, but Podman info and inspect share a runtime trust domain. The host kernel and procfs remain trust assumptions. A future A3 observer should have:

- operator-provisioned identity, explicit key ID and generation;
- narrow signing scope: only a declared observer profile and machine identity;
- signed challenge/nonce and bounded monotonic observation interval;
- key validity, rotation and revocation checks at admission time;
- approved observer executable/configuration and Podman daemon, OCI runtime and helper identities;
- clear invalidation on host compromise, key revocation, boot epoch change or source disagreement.

Where available, hardware-backed keys and measured-boot/remote-attestation evidence can raise confidence in the observer host. A hardware quote still needs a verifier, freshness challenge, approved measurement policy and a truthful mapping from measurement to the collector/runtime components. A software key on an administrator-controlled host is a weaker identity class and must be labelled accordingly.

Hashing a binary before and after executing it does not prove which inode the kernel executed. Close the path-to-execution race with descriptor-bound identity/launch and record the runtime daemon/helper identities as well as the client CLI. Treat any unsupported mechanism as Inconclusive.

### 4.2 Make rollback externally visible

A local hash chain detects internal alteration only relative to a retained trusted checkpoint. It does not detect full-chain replacement if the attacker can replace both the log and its only head.

The durable design should combine:

1. a crash-consistent local append log with a monotonic sequence and explicit boot-transition records;
2. atomic recovery rules: after uncertain persistence or sequence allocation, stop mutation and reconcile—never silently reset or reuse a sequence;
3. independent remote checkpoint/witness storage that remembers the latest observer ID, boot epoch, sequence and chain head;
4. an authenticated signed checkpoint response, with a second independent witness for high-impact or multi-tenant deployments;
5. a hardware monotonic counter when the platform provides one, treated as an additional signal rather than the only anchor.

Qualification must crash the observer after every persistence boundary: sequence allocation, payload write, link write, fsync, checkpoint request, checkpoint acknowledgement, key rotation and boot transition. Restore old snapshots, truncate tails, reorder links, replay a valid old prefix and simulate lost acknowledgements. Every uncertain result must become Inconclusive and deny new consequential authority until reconciliation.

The current receipt-chain module has structural hash-link checks. The 26 November changes reject noncanonical boot UUID aliases, transitions without an intervening snapshot, reuse of a previously seen boot ID, and unknown fields on both the serialized receipt envelope and payload. The chain verifier applies the boot-state checks to imported/rehashed links, while strict deserialization rejects uncommitted extension fields. These checks do not create persistence, signatures, an anchor or a trusted boot-transition source.

## 5. Policy proof must cover the actual capability

The current finite-set prover is a valuable start: it checks a conservative declared domain of canonical IP ranges, protocol and port sets and issues an opaque token only for a fully modelled Within result. Unsupported or exhausted evaluation must remain Inconclusive.

The next proof domain should model the actual authorization tuple, not just a firewall destination:

**(tenant, task, principal, executable_digest, workload_identity, destination, port, transport, request_protocol, method, path, credential_scope, resolver_epoch, time_window)**

The candidate capability set must be a subset of the owner boundary over every supported dimension. A proof that the CIDR is within the boundary is not proof that the executable, HTTP method, credential or tool action is authorized. DNS resolution, CNAMEs, redirects, proxy routing and connection-time destination must be bound to one explicit resolution/connection contract. If any dimension cannot be modeled exactly, return Unsupported or Inconclusive; never silently drop it.

This is a concrete way to extend the existing proof-carrying authority idea: proof-carry the effective capability relation and then prove that the live enforcer applied that same relation to the exact workload.

## 6. Temporal assurance: leases, not permanent green states

A snapshot is only true for its observation window. Every authorization should be a short-lived, audience-bound capability lease tied to a dependency version vector:

- task/plan and artifact digest;
- process handle/start-time and executable identity;
- cgroup, namespace and mount identities;
- policy/prover/runtime generation;
- observer key generation and chain checkpoint;
- DNS/resolver and credential-binding epochs where applicable;
- supervisor and enforcement-hook liveness.

Changes to any dependency invalidate the lease. Relevant events include fork/exec, process exit/reuse, cgroup migration, namespace or mount change, executable replacement, policy update, DNS expiry/rebinding, credential rotation, observer-key revocation, supervisor disconnect, BPF detach/re-attach and host reboot.

Require revalidation at consequential boundaries, not just at launch. An unknown outcome means no new mutation until an independent observer reconciles it. Do not use a long polling interval as a substitute for kernel/event-driven invalidation.

## 7. Industry comparison and the competitive gap

This is a capability comparison, not an apples-to-apples product ranking.

| Reference | Publicly documented strength | What Nixward should learn / measure |
|---|---|---|
| NVIDIA OpenShell v0.1.10 | Supervisor/workload separation, process ownership and executable identity, kernel-mediated TCP/DNS, default-deny outer fence, request-level checks for supported REST/WebSocket/GraphQL/MCP/JSON-RPC protocols, credential binding and formally checked policy changes | Use as the primary live runtime baseline. Match the same workload, policy, model and resource budget. Independently verify exact cgroup attachment and actual effects. The published mediation path documents TCP and DNS; do not assume general UDP/QUIC coverage without backend-specific tests. |
| Google Agent Gateway semantic governance | Intent-aware tool-call gating evaluated on AgentDojo; a published six-run result reports attack success 48.7% → 0.9%, with a 2.6 percentage-point benign-utility reduction | Reproduce the exact AgentDojo v1.2.2 / gemini-2.5-flash setup where possible, then run held-out scenarios. Separate semantic action rejection from kernel/runtime enforcement. Measure safe task continuation, not just blocked tool calls. |
| MITRE ATT&CK Evaluations 2026 | Total Evaluation Score combines detection and protection dimensions and publishes source-of-action attribution | Publish separate detection, prevention, attribution, effect-verification and utility metrics; identify whether each outcome came from model, platform, human, supervisor, enforcer or evaluator. Keep a composite secondary only. |
| OASB / OASB Eval | Pinned reproducible scanner benchmark runs and broad control/scenario inventory | Use it for control coverage and lineage; do not import withdrawn precision/FPR claims. Its maintainers withdrew prior figures after most benign labels were derived from the scanner's own verdict. Keep benign ground truth independent. |
| IETF AI Agent Security Evaluation Profiles draft | Work-in-progress profile taxonomy for infrastructure and scenario SUT boundaries | Publish the exact included/excluded components, profiles, configuration, source-of-action and logging for every benchmark result. Do not compare metrics from different boundaries as if equivalent. |

OpenShell's published v0.1.10 documentation identifies the runtime contract and policy surface: [architecture](https://docs.nvidia.com/openshell/v0.1.10/about/architecture), [network rules](https://docs.nvidia.com/openshell/v0.1.10/how-it-works/policies/network-rules). Its current architecture says the sandbox owns the agent process, identifies the executable from trusted process observations, intercepts TCP opens and DNS queries, and denies direct egress except through the protected supervisor channel. The network-rule documentation additionally describes executable/destination rules, L7 inspection for supported protocols, credential binding and DNS mapping refresh. This is a materially more complete runtime-control path than the current Nixward contract; use it as a baseline, not as evidence that Nixward already has parity.

Google's 23 November 2026 publication reports six full AgentDojo runs per configuration. Its 0.9% result applies to its documented harness and workload; it is not a universal rate and does not establish isolation, packet enforcement or effect receipts. The benchmark also reports that denied injected actions often ended the turn rather than allowing the agent to safely continue the user's task. That continuation gap is a promising area for Nixward to measure.

OASB's 10 October 2026 pinned run reports 192/270 attack fixtures detected (71.1%) and 17/86 DVAA scenarios (19.8%). Its earlier F1/false-positive figures were withdrawn because 3,704 of 3,881 benign samples were labelled by the tested scanner's own verdict rule. This is the exact kind of evaluator leakage the ATR benchmark must prevent.

The October 2026 IETF document draft-hcf-bpm-agent-security-benchmark-profiles-00 is an Internet-Draft, not a final standard. Its central comparability principle is useful: a metric is tied to its declared SUT boundary and scenario profile; differing boundaries cannot be compared without qualification.

## 8. Matched evaluation plan

Run the same synthetic tasks, model/version, prompts, tools, memory, policy, seeds and resource budgets against these arms:

1. **Unprotected baseline:** measure raw attack success, utility and cost.
2. **Semantic action guard:** intent-aware pre-tool-call gating without runtime claims.
3. **OpenShell v0.1.10:** pinned runtime boundary and policies, with the exact backend declared.
4. **Nixward contract-only:** policy proof and task-bound owner authorization; runtime enforcement stays disabled and results must be labelled as such.
5. **Hybrid:** OpenShell runtime enforcement plus Nixward task/authority/evidence contracts.
6. **Rules-only detector:** a conventional deterministic rule/SOC comparator with the same candidate-visible telemetry.

Do not make Nixward look better by giving it more information, easier seeds, different task budgets or a narrower declared boundary. Randomize run order; use paired seeds; split by scenario family and tool/provider lineage; retain a hidden challenge set. The evaluator must own canaries, expected effects, key revocation truth and chain-head anchors in separate credentials, processes and storage.

Every episode must bind exact raw catalogue bytes, canonical selected scenario bytes, fixture manifest and each artifact digest, model/provider/version, prompt, tool inventory, environment/runtime, policy/prover, observer and SUT profile. Candidate and evaluator telemetry must be separate at runtime—not merely in two JSON fields.

## 9. Proposed qualification targets

All figures below are **proposed goals**, not measured results, guarantees or certifications. Report per profile and scenario family with confidence intervals.

| Dimension | Proposed target |
|---|---:|
| Unauthorized committed effects | 0 |
| Cross-tenant reads/writes, host escape, secret disclosure, unapproved egress | 0 |
| Stale, revoked or substituted evidence accepted for new authority | 0 |
| High-impact effect provenance completeness | 100% |
| Tenant / asset / executable attribution | ≥99% |
| Detection recall | ≥95% |
| Precision at a declared operational alert budget | ≥90% |
| Benign legitimate-task completion | ≥95% |
| Correct safe partial-result reporting | ≥99% |
| Unnecessary refusals on benign tasks | ≤3% |
| AgentDojo attack success | Reproduce Google's documented 0.9% result under a matched setup, then target <0.5% on held-out families |
| Benign-utility cost under the same AgentDojo setup | No more than 2.6 percentage points versus its matched unguarded baseline |
| Authority invalidation after a dependency change | Measure p50/p95/p99; target p95 <1 second for the initial host profile |
| Runtime overhead | Measure p50/p95 task latency and CPU/memory/network overhead; target <10% p95 latency increase before broad rollout |

A zero observed violation is not proof of zero risk. For independent Bernoulli trials, zero failures in approximately 2,995 episodes gives a one-sided 95% upper confidence bound near 0.1%. Correlated cases do not count as independent trials; group by scenario family and report the actual sampling design.

For scale, the 39 ATR scenarios are a qualification catalogue, not enough observations to estimate production precision or false-positive rates. Expand benign workload diversity, normal administrative actions, approved security tests, noisy but legitimate discovery, retries, failures and long-running multi-agent episodes. Report false alerts per 1,000 asset-days alongside precision.

## 10. Runtime conformance matrix

Every backend requires its own proof profile. Do not inherit a green Podman result into Kubernetes or MicroVM.

| Dimension | Rootless Podman | Kubernetes | MicroVM |
|---|---|---|---|
| Workload/process identity | Container ID, stable process reference/start, namespaces, cgroup object | Pod UID, container ID, node/CRI process identity, cgroup | VM ID, vCPU/guest identity, host process and vsock peer |
| Isolation evidence | user/network/PID/mount/cgroup namespaces, mounts, capabilities, seccomp, Landlock where used | namespaces, admission policy, cgroup and network policy | hypervisor configuration, virtual devices, guest memory/device boundary |
| Egress enforcement | exact cgroup hook and external packet oracle | exact pod/workload policy and external packet oracle | no NIC or explicit mediated virtual NIC, external packet oracle |
| Required adversarial controls | restart/PID reuse, mount change, cgroup migration, UDP/QUIC, IPv6, DNS, proxy | pod replacement, node move, policy race, service/sidecar bypass, UDP/IPv6 | device attach, vsock identity, guest reboot, hypervisor control-plane loss |

For each backend, test allowed and denied TCP, UDP and IPv6; DNS rebinding/TTL and CNAME chains; redirects; proxy bypass; alternative namespaces; process replacement; supervisor/enforcer loss; and policy generation races. Observe packets outside the guest and verify service state independently. A policy file or a log line saying blocked is not an effect receipt.

## 11. Execution order

### P0 — Finish observer identity and provenance

- Define operator-provisioned observer IDs, key scope, generation, expiry and revocation.
- Bind machine/boot identity, observer binary/configuration, Podman daemon and OCI runtime/helper identity.
- Close path-to-exec races and retain stable process references for the entire observation window.
- Preserve Inconclusive for missing or contradictory evidence.

### P1 — Durable chain and external witness

- Specify a crash-consistent store and monotonic sequence allocation.
- Define signed checkpoint schema and external witness API.
- Make restart/rollback/crash injection deterministic in a disposable VM.
- Keep chain-head binding out of the owner-signable task contract until the head is independently retained and currentness/revocation can be verified.

### P2 — Exact enforcement and effect receipts

- Query actual cgroup/BPF or backend enforcement attachment and generation.
- Verify the enforced capability tuple matches the owner-signed policy subject.
- Add packet-level allow/deny receipts and an independent service-state oracle.
- Keep activation disabled until all runtime profile gates and separate owner authorization pass.

### P3 — Continuous assurance and broader proof domain

- Add event-driven lease invalidation and one-use action/effect capabilities.
- Extend policy proof to executable, credential, resolver and request-level semantics; Unsupported remains non-passing.
- Add backend-specific conformance suites and matched baseline runs.

### P4 — Publish reproducible results

- Use Platform ATR-001..ATR-041 plus hidden family-disjoint combinations.
- Publish per-scenario outcome vectors, all hard-gate violations, utility, attribution, evidence provenance, p50/p95/p99 latency, overhead and confidence bounds.
- Freeze exact heads, inputs and manifests. A skipped or queued runner is pending—not a pass.

## 12. References

- NVIDIA OpenShell v0.1.10 [Architecture](https://docs.nvidia.com/openshell/v0.1.10/about/architecture) and [Network Rules](https://docs.nvidia.com/openshell/v0.1.10/how-it-works/policies/network-rules).
- Google Developers, 23 Nov 2026, [Did the user ask for this? Semantic governance policies on AgentDojo](https://developers.googleblog.com/did-the-user-ask-for-this-securing-ai-agents-against-intent-hijacking-with-semantic-governance-policies/).
- MITRE, [ATT&CK Evaluations Enterprise 2026](https://attackevals.mitre.org/enterprise/er8).
- OASB, [10 Oct 2026 pinned benchmark run and withdrawn-score explanation](https://oasb.ai/updates).
- IETF Internet-Draft, 23 Oct 2026, [draft-hcf-bpm-agent-security-benchmark-profiles-00](https://datatracker.ietf.org/doc/html/draft-hcf-bpm-agent-security-benchmark-profiles-00).

---

**Claim boundary:** this is a roadmap and evaluation design. It does not implement persistent observer storage, hardware-backed attestation, remote anchoring, active network enforcement, effect receipts, or runtime qualification. Nixward's current enforcement plan remains disabled until independently verified runtime evidence and owner-authorized activation exist.
