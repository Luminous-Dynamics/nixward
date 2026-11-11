# Network Administration Automation and Xenia Integration

**Status:** Design proposal; not implemented or qualified  
**Date:** 2026-10-12  
**Parent:** [Sovereign Network OS architecture](SOVEREIGN_NETWORK_OS_ARCHITECTURE.md)  
**Observation prerequisite:** [Network Observation Evidence Contract](NETWORK_OBSERVATION_EVIDENCE_CONTRACT.md)  
**Tracked implementation:** [Issue #69](https://github.com/Luminous-Dynamics/nixward/issues/69)  
**Design PR:** [PR #67](https://github.com/Luminous-Dynamics/nixward/pull/67)

## Executive answer

We can aim to automate a very large share of recurring network-administration tasks: inventory, drift detection, routine configuration, policy validation, testing, change preparation, monitoring, fault correlation, safe rollouts, evidence capture and much of first-line triage. Many deterministic tasks can eventually run end-to-end inside pre-authorized limits when the network is well-modelled and observations are trustworthy.

That does not mean it is responsible to claim that almost every role can be replaced or to give an autonomous agent unrestricted network-administrator authority. Network operations includes ambiguous incidents, outage trade-offs, security-risk acceptance, physical plant, vendor/platform failures, regulatory commitments, customer communications and accountability. These require clear human ownership, and some events require human action even when the system can generate a recommended response.

**Recommended objective:** automate repeatable work as far as evidence and guardrails allow; retain accountable human control over risk boundaries, exceptions and high-impact changes. Measure the share of tasks that are eligible and safely auto-completed rather than announcing an unsupported percentage of roles automated.

## 1. What Xenia can contribute

The current [xenia-peer README](https://github.com/Luminous-Dynamics/xenia-peer/blob/main/README.md) describes a peer-to-peer remote-session stack with role-based operator authorization, explicit consent, host fingerprint pinning, revocation and a signed/hash-chained audit trail. Its security model describes roles including Viewer, Approver, Operator and Admin, and per-action authorization. These are useful design ingredients for human access, approval and emergency support.

However, the same repository labels Xenia pre-alpha and says it is not yet a finished or production-ready product. The separate [xenia-wire README](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/README.md) says the wire format is pre-alpha, not frozen, and awaits independent review and cross-implementation validation. The [OSI security-plane architecture](https://github.com/Luminous-Dynamics/xenia-peer/blob/main/docs/architecture/OSI_SECURITY_PLANE.md) explicitly leaves IP routing, addressing, NAT, link and physical networking to underlying carriers.

So we should use Xenia as a potential **human operator session, consent, approval and emergency-access component**, not assume it is a network orchestrator or a production-ready network-change authorization protocol today.

### Good future uses for Xenia

- A human accesses a target console through an explicitly enrolled, authenticated, consent-bearing remote session.
- An operator reviews an exact Nixward-generated plan, its impact summary, preconditions, test results and rollback readiness.
- A properly authorized and signed approval is bound to an immutable plan identity rather than a generic “yes” or remote keystroke.
- When automation becomes uncertain, Xenia provides a path for bounded human investigation and decision, subject to separate access policy and logging.
- Xenia's operator revocation and audit patterns inform fleet operator lifecycle management.

### Uses to prohibit

- Do not interpret permission to view a screen or inject keyboard/mouse input as permission to make a network change.
- Do not automate a terminal by clicking UI coordinates when a versioned typed API or backend adapter is available.
- Do not reuse Xenia's existing screen/input consent response as network-change approval: those semantics authorize a remote-control session, not a router mutation.
- Do not let Xenia's UI be the final root authority. Nixward's privileged broker must revalidate its own policy, target identity, plan digest, live preconditions and authorization immediately before execution.
- Do not expose a generic root shell or unrestricted network-management API to the remote-session stack.
- Do not deploy pre-alpha Xenia as a production access dependency until its protocol, platform support, security review and deployment threat model pass their own gates.

## 2. Division of responsibilities

| Component | Responsible for | Must not be allowed to |
|---|---|---|
| NixOS | Reproducible host, packages and declared service state | Claim runtime correctness from build success alone |
| Nixward observer/verifier | Typed inventory, evidence provenance, completeness, freshness and ownership | Mutate network state or self-certify incomplete evidence |
| Nixward planner | Deterministic plans and pre/postconditions | Grant its own execution authority |
| Symthaea | Anomaly correlation, causal hypotheses, risk forecasts, explanations and candidate remediations | Mint capabilities, change authorization or bypass deterministic policy |
| Nixward broker | Enforce capabilities, risk tier, live preconditions, serialization, execution, read-back and recovery | Execute unsupported operations because an AI recommends them |
| Xenia, future integration | Human access, consent, signed plan-specific approval and emergency-session UX | Become the network adapter or sole authority for mutation |
| FRR / kernel / nftables / WireGuard / vendor backend | Apply specific supported behavior and expose authoritative state | Be treated as interchangeable APIs without backend-specific tests |
| Mycelix, optional governance integration | Policy/delegation provenance or multi-party governance where needed | Become a packet-forwarding dependency or bypass local authorization |

These components should communicate through narrow, versioned contracts. The data plane should keep forwarding its last valid state if Symthaea, Xenia, the management API or the orchestration controller restarts, wherever the selected backend supports this.

## 3. Task-level automation matrix

Automation eligibility depends on device, evidence and impact—not merely on the task label. This is the target design, not a statement that these tasks are currently implemented.

| Task family | Target autonomy | Preconditions |
|---|---|---|
| Inventory, topology and configuration backup | Fully automated read-only collection | Required sources covered; failures, loss and freshness explicitly represented |
| Telemetry, alert deduplication and anomaly correlation | Fully automated detection | Source provenance, bounded queues, sequence handling and alert suppression auditable |
| Documentation, config rendering and review diffs | Automated draft generation | Immutable intended-state input, supported model and secret-safe rendering |
| Compliance/intent drift checks | Automated detection and evidence collection | Policy pinned; unknown device/model fields are not treated as compliant |
| Routine known-good provisioning | Pre-authorized closed-loop execution | Exact template, bounded scope, unique owner, tested rollback, fresh pre-state and verified read-back |
| Low-risk deterministic repairs | Pre-authorized closed-loop execution within strict budgets | Enumerated failure modes, idempotent action, no management-path impact and independent health checks |
| Capacity planning and route-policy suggestions | Automated forecast and recommendation | Predictions uncertainty-labelled; confidence never grants authority |
| Incident triage and probable-cause analysis | Automated triage; escalate ambiguity/high impact | Reproducible evidence bundle and explicit competing hypotheses |
| Security containment and firewall changes | Bounded playbook or human-approved execution | Explicit impact boundary, management path preserved, recovery tested and safety monitor active |
| Planned rolling updates | Automated candidate build, canary and test; gated progression | Hardware/backend compatibility, health thresholds, blast-radius caps, abort and rollback behavior |
| Default route, core BGP policy, management firewall or multi-site changes | Automated plan/simulation; strong change-specific approval for high risk | Fresh/coherent evidence, independent tests, reachable recovery, exact-plan approval and monitoring |
| Novel protocol behavior, unknown failure or control-plane split-brain | Recommend and collect evidence; human-led decision | No known-good bounded playbook or ownership conflict |
| Physical faults, optics, cabling, power and damaged equipment | Assist, diagnose and coordinate | Telemetry is evidence, not proof of physical condition |
| Risk acceptance, architecture trade-offs, regulatory/customer commitments | Human accountable; AI-assisted analysis | Named owner and recorded rationale |

Detection can usually be more autonomous than remediation. Reversible operations are not automatically low risk: a technically reversible BGP or firewall change may still create irreversible customer, safety or security impact while active.

## 4. Autonomy levels and authority boundaries

Use explicit per-operation autonomy tiers, not one global autonomy switch.

- **A0 — Manual:** no agent action beyond logging.
- **A1 — Observe:** collect, correlate, alert and preserve evidence; no mutation.
- **A2 — Recommend:** produce candidate plans with impact, uncertainty and alternatives; no mutation.
- **A3 — Pre-authorized bounded action:** execute only policy-enumerated operations with exact targets/parameters, fresh evidence, limited blast radius, tested rollback and independent verification.
- **A4 — Change-specific approval:** a qualified human authorizes the exact plan, target set, risk envelope and expiry; changing the plan or target invalidates approval.
- **A5 — Human-led exceptional operation:** the agent may observe, simulate and advise, but the human leads the high-impact decision and execution remains inside enforced capability limits.

The permitted tier is the lower of the risk-policy allowance and the evidence/backend capability. An AI confidence score cannot raise it. Unknown state, stale/incomplete observations, owner conflicts, unsupported schemas, unresolved incidents or failed recovery checks lower the tier or block execution.

### Preconditions for A3/A4

1. Exact device, namespace/fabric and backend identity are pinned.
2. Required observations are independently verified, fresh and sufficiently coherent. Integrity and completeness remain separate statuses.
3. One authorized configuration owner is identified for each affected resource.
4. Desired state, plan digest, policy version, risk class, change window and rollback plan are frozen.
5. Plan simulation/tests pass on exact versioned inputs; unsupported models/semantics are blocked.
6. Device count, resource scope, affected routes/peers and duration stay inside pre-declared blast-radius budgets.
7. The broker freshly checks preconditions and coordinates cooperating writers immediately before applying. A final read before a write does not eliminate an external-writer race; a supported conditional mutation or shared writer coordinator is still needed.
8. Recovery/confirmation is armed before a potentially disconnecting operation and does not depend solely on the initiating UI, session or agent surviving.
9. Independent post-state read-back and health checks determine success. Command exit, RPC success, queued CI or model predictions are not sufficient.
10. Every operation has a durable receipt; ambiguous outcomes become Indeterminate and block conflicting writes.

Rollback can restore configuration but cannot erase lost packets, broken sessions, customer impact or data already exposed. Risk limits must account for impact while the change is active.

## 5. Proposed Xenia plan-approval contract — not implemented

A future integration should introduce a typed NetworkChangeApprovalV1 concept rather than overloading remote-control consent. It should bind:

- Exact Nixward plan digest and schema version.
- Exact target identity or frozen device-set digest.
- Human-readable impact summary rendered from the same verified plan bytes.
- Operations/resource kinds and maximum blast-radius/risk class.
- Policy and evidence-receipt digests reviewed by the approver.
- Expected preconditions, maintenance window, expiry and one-time approval nonce.
- Approver identity, enrolled key identity, role/capability, authenticated Xenia session fingerprint and authorization-policy version.
- Decision (approve/reject) with defined sequence/time semantics.

The approval must be signed by the enrolled operator and verifiable without trusting the UI. It must not transfer to another target, plan, policy or session; it needs replay-protected one-use semantics and an auditable record after session closure. A valid approval only records that an authorized person approved that exact proposal. Nixward must still enforce policy, current target state and executor capability.

### Required cross-repository work

1. Keep the protocol boundary: do not add a network-change payload to Xenia until Nixward plan/evidence/approval types are stable and reviewable.
2. Define a versioned, canonical, domain-separated signed transcript in the shared Xenia operator protocol. Do not treat the current screen/input consent transcript as equivalent.
3. Add explicit network-change approve/reject actions with capability checks, replay protection, expiry, revocation, safe rendering and durable audit event types.
4. Have the Nixward broker verify the approval independently and bind it to the exact proposal. The broker remains the only component able to turn it into execution.
5. Test plan changes after approval, target substitution, stale evidence, expired/revoked operator, key rotation, replay, malformed transcript, misleading/truncated UI rendering, broker restart and connection loss.
6. Keep a no-Xenia local/out-of-band recovery path and a noninteractive machine API for pre-authorized low-risk operations.
7. If Xenia is unavailable, remote approval becomes unavailable; the system must not silently authorize a change or stop forwarding.

**Maturity note:** the current Xenia repositories describe pre-alpha software. Existing roles, consent, pinning and audit patterns are design inputs, not evidence of an implemented, independently audited or production-qualified network-approval flow.

## 6. Closed-loop workflow

1. Telemetry and authoritative observations detect a condition.
2. The evidence verifier marks dimensions complete, stale, conflicting or unknown.
3. Symthaea produces ranked hypotheses and candidate remedies with expected impact and uncertainty.
4. The deterministic planner computes a plan from frozen target, desired-state and evidence inputs.
5. A simulator/offline verifier checks route reachability, management path, dependencies, policy and postconditions.
6. Risk policy selects A0–A5. A3 can run only for enumerated low-risk cases; A4 requests approval bound to the exact plan; A5 remains human-led.
7. The privileged broker re-observes and validates preconditions, then applies a narrow backend-specific delta.
8. Independent read-back and health checks test postconditions. A separately supervised confirmation controller confirms or recovers within a bounded timeout.
9. Journal outcome is AppliedAndVerified, Recovered, Rejected or Indeterminate; only the first two carry successful terminal evidence of their respective outcomes.
10. Outcome data can improve later diagnosis but cannot retroactively change an issued plan's authority.

## 7. Measuring “almost all” responsibly

Do not start with a headline percentage. Build a frozen task corpus from representative network work; label each task's risk, manual effort, evidence quality, prerequisites, eligible autonomy tier, execution outcome and residual human time. Measure both event count and operational impact, because thousands of low-risk tasks must not hide a few catastrophic high-risk failures.

Track:
- Eligible tasks auto-completed with independently verified postconditions.
- False automatic remediations and prevented unsafe mutations.
- Human interventions/escalations/approvals by task and risk tier.
- Change failure, rollback and indeterminate rates.
- Mean time to detect, diagnose and restore, plus p50/p95/p99.
- Management-path loss, packet loss and routing-convergence behavior during changes.
- Time spent maintaining policies/playbooks and handling new devices/versions.
- Evidence completeness/freshness and ownership-conflict rates.
- Task coverage by vendor, protocol, hardware and model version.
- Audit completeness, key/revocation response and operator override success.

Report denominators, sample size, platform coverage and qualification window. Simulation, lab and production results are separate evidence classes. A strong result on one simulated topology does not establish fleet-wide reliability.

The initial machine-readable seed is [`NETWORK_AUTOMATION_TASK_CORPUS_V1.json`](NETWORK_AUTOMATION_TASK_CORPUS_V1.json), paired with [`NETWORK_AUTOMATION_TASK_CORPUS_V1.schema.json`](NETWORK_AUTOMATION_TASK_CORPUS_V1.schema.json). The corpus defines 16 candidate tasks with evidence prerequisites, preconditions, stop conditions, independent postconditions, recovery expectations, required fault fixtures and measurement units. It is deliberately marked `qualification-design-only`: the tier ceiling is not authority, the seed is not representative, and structural validation does not establish operational safety.

A dependency-free validator plus 25 standard-library unit/mutation tests now live under `tests/network-automation-corpus/`, and [`network-automation-task-corpus.yml`](../.github/workflows/network-automation-task-corpus.yml) checks out the exact triggering SHA with read-only repository permission, no persisted checkout credential, and no external Python dependency. The mutation tests include malformed-type handling, duplicate identifiers, tier/mode incompatibility, unknown schema keywords, invalid schema patterns and loss of authority-boundary text. The validator implements only the keywords used by the checked-in schemas and fails closed on unknown schema keywords; it is not a general JSON Schema implementation or operational-safety proof.

The corpus now has a cross-referenced fault fixture set: [`NETWORK_AUTOMATION_FAULT_FIXTURES_V1.json`](NETWORK_AUTOMATION_FAULT_FIXTURES_V1.json) and [its schema](NETWORK_AUTOMATION_FAULT_FIXTURES_V1.schema.json). It defines 25 deterministic scenario contracts, covers every task ID in the task corpus, specifies expected decision/receipt-state pairs, and fixes `production_mutation=false` for every case. Positive controls distinguish a genuine empty-but-complete observation from missing data and exercise a simulated-only bounded VLAN create; fault cases cover dump interruption/loss, target substitution, owner conflicts, plan tampering, writer races, management-path loss, crash/recovery uncertainty, approval replay, route leaks, secrets, telemetry gaps and physical ambiguity.

The validator cross-checks task references, scenario-ID uniqueness, decision/state consistency, virtual-lab-only success cases, complete task coverage and the production-mutation prohibition. These artifacts and the cross-check logic have been structurally inspected, but the Python unit tests have not been run locally in this environment. The current exact-head CI run must complete successfully before the validator/tests are described as passing. Even after CI passes, the fixture set defines expected assertions; it does not yet execute an actual network observer, Batfish query, containerlab topology or privileged transaction broker.

## 8. Rollout stages

### Stage 0 — Read-only inventory and change intelligence
Keep PR #65 within its pure M0 boundary. Finish exact-head CI and establish M1a's independent verifier via [Issue #68](https://github.com/Luminous-Dynamics/nixward/issues/68). Build collectors, fixtures, ownership/conflict detection and evidence receipts. No live network mutation.

### Stage 1 — Offline simulator and candidate plans
Create network-namespace/FRR labs, inject external writers and observation loss, replay changes and test recovery without production impact. Establish a versioned task corpus and plan-review UX.

### Stage 2 — Low-risk closed-loop automation
On a disposable lab or non-critical pilot, support narrowly typed pre-authorized create/update operations. No arbitrary shell, generic delete/flush, sole-management-path changes or fleet rollout before backend-specific fault tests and exact-head qualification pass.

### Stage 3 — Xenia approval for selected changes
After Xenia readiness gates and the cross-repo plan-approval contract are complete, add exact-plan approval for selected medium/high-risk changes. Keep the broker and Nixward policy authoritative.

### Stage 4 — Progressive fleet autonomy
Canary by device class/site; cap concurrent changes; pause on unexpected state, health degradation, competing changes or any Indeterminate result. Require a separate acceptance package per backend/hardware/firmware family.

### Stage 5 — Exceptional incident assistance
Use Symthaea to synthesize evidence and response options for novel incidents. Human operators remain accountable for exceptions, safety/security risk acceptance and physical interventions. Maintain tested local/out-of-band recovery.

## 9. Research anchors and limits

- [Xenia peer README — architecture and pre-alpha status](https://github.com/Luminous-Dynamics/xenia-peer/blob/main/README.md)
- [Xenia operator security model — roles, per-action authorization, revocation and audit](https://github.com/Luminous-Dynamics/xenia-peer/blob/main/docs/security/OPERATOR_SECURITY_MODEL.md)
- [Xenia OSI/security-plane architecture](https://github.com/Luminous-Dynamics/xenia-peer/blob/main/docs/architecture/OSI_SECURITY_PLANE.md)
- [Xenia Wire README — pre-alpha, non-frozen format](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/README.md)
- [Cisco IOS XE model-driven telemetry, September 2026 documentation](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/26x/26x-programmability-cg/model-driven-telemetry.html)
- [NetBox network source of truth](https://netboxlabs.com/docs/netbox/)
- [NIST SP 800-82 Rev. 4 initial public draft, September 21, 2026](https://csrc.nist.gov/pubs/sp/800-82/r4/ipd), relevant where networks interact with operational technology. This is a draft, not final guidance.

Research links contextualize the design; they do not establish that the proposed integration is implemented or qualified.

## Decision

Build an evidence-first network automation platform where routine, bounded tasks become hands-off only after qualification. Use Xenia to make human access and exact-plan approval safer, not as a keyboard macro or bypass around deterministic policy. Keep people accountable for uncertainty and consequences, and measure automation at the task level before making claims about replacing roles.
