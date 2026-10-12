# Sovereign Network OS on NixOS and Rust — Architecture and Evidence Roadmap

**Status:** Research / architecture proposal, 2026-10-12  
**Decision:** Pursue a NixOS-based, Rust-controlled network appliance in bounded stages. Do not claim feature parity with Cisco or build a new packet-forwarding stack before measuring a specific need.  
**Scope:** Routers, edge firewalls and small-to-medium switching/edge systems. This proposal is separate from Nixward's workload-level cgroup/BPF enforcement and PR #62's system-activation hardening.

## Executive conclusion

Yes—NixOS and Rust can underpin a network operating environment that is better than a Cisco platform for specific goals: reproducible builds, auditable configuration, cross-vendor automation, transparent control boundaries, recoverable changes, and long-lived deployments on commodity hardware. That is a credible product direction.

It is not currently defensible to claim we could outperform Cisco IOS XE, IOS XR or NX-OS overall. Cisco has decades of routing and switching behavior, production hardening, ASIC/line-card support, hardware redundancy, protocol interoperability, field support and operational tooling. NX-OS documentation describes plane/process isolation, stateful restarts, supervisor switchover on supported chassis and in-service software upgrades. IOS XE already supports model-driven YANG telemetry and NETCONF/RESTCONF/gNMI. IOS XR itself runs on Linux on newer platforms. Linux plus Rust alone is therefore not the differentiator.

The opportunity is a more transparent and reproducible network transaction system, built on a careful NixOS foundation, with Rust for authority and orchestration, mature routing/forwarding implementations, standards-based management, and evidence that each change is safe for the stated target. Start with a software router/edge firewall on x86 hardware, not a claim to replace a modular carrier chassis.

## What “better” means

Do not compare a general-purpose NixOS host to “Cisco OS” as one thing. Cisco ships distinct operating systems and management products for different domains. Select the product class and workload first.

| Dimension | Credible NixOS + Rust opportunity | Cisco advantage to respect |
|---|---|---|
| Reproducibility | Exact flake/lock closure, build identity, deterministic configuration artifacts and auditable diffs | Product-specific image and configuration workflows integrated with validated hardware |
| Configuration safety | Typed desired state, explicit ownership, stale-state rejection, staged changes, durable receipts and confirmation deadlines | Mature platform-specific commit, rollback, ISSU and operational semantics where supported |
| Hardware choice and cost | Commodity x86/ARM, flexible NICs, open software and use-specific sizing | Integrated ASICs, PHYs, optics, environmental sensors, switching fabrics, line cards and validated BOMs |
| Routing coverage | Delegate to FRRouting and verify the needed feature matrix | Broad platform-specific feature matrices and interoperability history |
| High availability | Measure process restart, redundant-node failover, and safe deployment semantics | Established chassis/supervisor redundancy and non-stop forwarding/upgrade features on supported platforms |
| Management | Fleet intent plus OpenConfig/gNMI and gNOI-compatible APIs where supported | Large installed-base workflows, vendor tooling, support contracts and existing operations integration |
| Auditability | Open model/transaction code and reproducible host closure | Vendor-controlled components and platform-specific interfaces; Cisco also has well-developed programmable interfaces |
| Support | Transparent build inputs and a community/partner model | Established enterprise support, certification, validated platforms and escalation paths |

This is a target matrix, not a scorecard asserting that Nixward already achieves these outcomes.

## Proposed architecture

### 1. Reproducible host and image layer — NixOS

NixOS is the OS composition and packaging layer: locked inputs, immutable store-backed artifacts, explicit services, users, sandboxing, Secure Boot integration where supported, and generation-based deployment. Keep the router build minimal and appliance-specific.

Separate configuration intent from effective runtime state. A Nix expression stating that a link should exist is not evidence that the link currently exists, that its driver is healthy, or that another manager is not changing it.

### 2. Rust management and safety control plane — Nixward

Rust owns the typed network resource model, desired-state planner, ownership graph, plan verification, change authorization, deterministic transaction receipt, operator API and recovery decision logic. Keep the planner pure and deterministic. Keep policy/model prediction advisory: Symthaea may explain risks, recommend a change window or rank proposed remediations, but must not mint execution authority or bypass the deterministic checker.

Use a narrow privileged broker for mutation. The CLI, daemon, web UI and API should submit the same authenticated plan identity to that broker rather than each having a separate route to change host networking. The broker rechecks exact plan digest, target identity, live pre-state, ownership and authorization immediately before mutation.

### 3. Observation and ownership layer

Use Netlink/rtnetlink for kernel links, addresses, routes, neighbors, rules and supported link attributes; use authoritative interfaces for firewall, WireGuard, systemd-networkd, NetworkManager and FRR state. Snapshot collection records collector build identity, boot ID, time/sequence, target/namespace identity, resource-kind coverage, and explicit failure/truncation/interruption evidence.

A digest proves only that bytes match the digest. It does not prove that the collector saw every resource or that a claimed completeness artifact is true. An independent verifier must validate raw evidence and completeness claims before an adapter can enable writes. Interrupted Netlink dumps, loss, parse errors, namespace changes, permission errors or unknown ownership mean incomplete observation: retry under a bounded policy or block mutation. Never convert “not observed” into “does not exist.”

Model separately:
- Configuration authority (for example, NixOS declarative config).
- Runtime owner (for example, systemd-networkd, NetworkManager, FRR or an explicit Nixward adapter).
- Kernel/hardware executor (Linux kernel, nftables or an ASIC SDK).
- Observation provenance and completeness.

Conflicting owners must be surfaced, not silently adopted. A resource must not be concurrently managed by NixOS declarations, NetworkManager and Nixward. Prefer integration with the declared manager rather than racing it with raw Netlink writes.

### 4. Routing and forwarding layer — reuse before rewriting

Initial target: Linux kernel forwarding plus nftables and WireGuard where needed, and FRRouting (FRR) for mature protocols such as BGP, OSPF and IS-IS according to FRR's feature matrix. Nixward should generate and validate typed intent and integrate with FRR through a supported bounded interface; it should not reimplement BGP/OSPF just to establish a Rust identity.

For demanding software-routing throughput, evaluate FD.io VPP and DPDK on the intended hardware. VPP uses a vectorized packet-processing graph and supports software routers, gateways, vSwitches and firewalls. Compare CPU, latency, jitter, throughput, loss, queue behavior, driver compatibility, operations cost and recovery before selecting it. Linux kernel forwarding is the simpler baseline; VPP is an optional data-plane profile, not a universal default.

For merchant-silicon switches, do not assume a Rust process can program an ASIC without a compatible SDK. Prefer an explicit hardware abstraction path such as SONiC's Switch Abstraction Interface (SAI) and supported vendor implementations, or upstream drivers with known feature coverage. SONiC documentation notes that an SAI implementation can depend on vendor SDKs that remain binary-only. Hardware support, platform drivers, fans, power, thermal sensors, optics and transceiver diagnostics are separate qualification scopes.

### 5. Standards-based management surface

Define a versioned typed internal model and map supported fields to OpenConfig YANG where appropriate. Target gNMI for modeled configuration/state and streaming telemetry, and gNOI for supported operational actions where semantics fit. Add NETCONF/RESTCONF only when required for interoperability and the implementation/test matrix can maintain them. Protocol exposure does not imply complete model coverage: publish a per-model/per-path capability matrix, reject unsupported paths, and do not acknowledge a configuration as applied until verified backend read-back meets the defined postcondition.

Provide a noninteractive API and readable local CLI. Use signed plan/receipt identities, capability-based access, protected credentials, audit attribution, replay protection, explicit API/schema versions and rate limits. API compatibility needs versioned contract tests against actual clients.

### 6. Network change transaction system — principal differentiator

Treat remote networking changes as transactions with explicit uncertainty, not as successful command invocations.

1. **Bind intent.** Freeze exact target identity, namespace, desired-state digest, software/backend versions, authorization and maintenance constraints.
2. **Observe.** Collect full required pre-state and verified evidence; reject incomplete or stale snapshots.
3. **Plan.** Deterministically derive an action DAG with preconditions, dependencies, ordering and postconditions. Verify the submitted plan by recomputing it from exact frozen inputs.
4. **Simulate.** Exercise the plan in network namespaces and virtual topologies; record expected route reachability and management-path invariants.
5. **Stage.** Render and validate backend configuration before committing. Use an isolated namespace or supported staging facility where available. Do not pretend multiple Netlink operations are atomic.
6. **Arm recovery first.** Before a potentially disconnecting change, persist an owner-bound transaction journal and arm an independent confirmation deadline. The recovery owner must outlive client disconnect and either supervise/terminate the worker or keep authority fenced until it reaches a terminal state.
7. **Apply narrowly.** Apply only the authorized delta through the one declared backend. No broad flushes, hidden deletions or shell fallback.
8. **Verify.** Independently read back relevant link/address/route/firewall state, routing adjacencies and route state as applicable, DNS and management reachability, counters and target SLOs. Command exit status is necessary but insufficient.
9. **Confirm or recover.** Require operator confirmation, or automatic confirmation only after all postconditions pass. On failure, restore exact prior state through the same owner-aware backend if it remains valid. If a foreign writer changed state or rollback cannot be proven safe, mark Indeterminate and stop conflicting mutation.
10. **Retain evidence.** Persist desired/pre/post digests, raw evidence references, backend identity, exact operations/results, timing, confirmation, recovery outcome and verifier version. A queued job, planned change or successful API response is not a pass.

**Remote access guard:** the first live mutation path must not silently sever its management session. Require a verified out-of-band console/local recovery route or a separately tested confirmed-commit/rollback mechanism. A timer alone is insufficient if its process can die with the client, rollback cannot reach the device, or a competing writer changes state.

### 7. Resilience and availability

Do not make the full control plane a forwarding dependency. If Nixward restarts or Symthaea is unavailable, the kernel/FRR/ASIC should continue forwarding the last valid state whenever the selected backend supports that behavior. Isolate routing protocol processes, management APIs, telemetry collectors and advisory AI from the minimal forwarding path.

Plan HA in layers: process restart and state reconstruction; link/path redundancy; redundant power and hardware monitoring where supported; dual-device routing/VRRP or equivalent failover; then redundant controller nodes and coordinated changes. A replicated database is not, by itself, safe network HA. Use monotonically fenced transaction epochs for cooperating controllers, explicit ownership and idempotent operations. If control authority is ambiguous, do not let two controllers write the same resource.

Do not claim hitless upgrades merely because Nix can build the next generation. A Nix generation rollback, process restart, control-plane restart, routing convergence and a hitless line-card/forwarding upgrade are different properties and require different measurements.

## Security model

- **Control versus data plane:** unprivileged observers and APIs cannot directly mutate networking. A narrow privileged broker validates exact typed capabilities.
- **Fail closed on uncertainty:** unknown owner, partial dump, stale target, schema mismatch, unknown backend semantics, failed verifier or lost receipt blocks mutation.
- **Least authority:** backend-specific capabilities cover resource kinds and operations; no generic arbitrary-command escape hatch. Keep secrets outside argv, logs, plan JSON and evidence bundles.
- **Immutable provenance:** bind host image, Nix lock, Rust binaries, adapter/backend version, schema version, policy version and evidence verifier to each operation.
- **Crash/replay safety:** journal before irreversible operations; idempotency keys and epochs; recovery based on fresh live observation. Test crashes at every durable boundary.
- **Supply chain:** locked dependencies, pinned actions/toolchains, reproducible builds where feasible, SBOM, vulnerability response, signed release artifacts and separation of qualification from advisory telemetry.
- **No AI authority:** Symthaea may propose, diagnose and forecast; a deterministic verifier and authorized policy govern execution.
- **Security boundary:** this does not defend against a malicious root administrator or compromised firmware/ASIC unless additional hardware-backed constraints establish that guarantee.

## Phased roadmap and qualification gates

### M0 — Pure, read-only planner

An in-flight proposal is [Nixward PR #65](https://github.com/Luminous-Dynamics/nixward/pull/65), head `7f107b28b9010b69452f686d2cf5e396d86aa5ff`. Its intended boundary is deterministic planning for links, addresses, routes, bridges, VLANs, firewall tables and WireGuard devices, with no adapter, socket, subprocess, authorization path or executor. The PR reports 18 authored unit tests and an exact-lockfile harness. At the time of this research, it states exact-head CI is queued and passing compile/test evidence is not available yet. The proposal explicitly says it binds completeness-evidence digests but does not validate the referenced artifacts. Therefore, even a pure-planner pass is not evidence that live inventory is complete or safe to mutate.

**Gate:** exact-head format/test success in CI; deterministic replay; plan-tamper rejection; property/fuzz tests for canonical encoding; independent evidence-verifier contract specified before any write adapter.

### M1 — Read-only Linux observation

Implement one network-namespace-scoped collector. No mutation. Validate Netlink multipart sequencing, interruption, ENOBUFS, truncation, namespace identity, duplicate/conflicting objects and comparison against independent kernel interfaces. Generate fixtures for missing/extra resources. The completeness verifier validates evidence bytes; the planner cannot self-certify its own collector.

**Gate:** the test matrix demonstrates all partial/lost/malformed states remain incomplete; exact snapshot identity and independent verification reproduce the result.

The new [Network Observation Evidence Contract](NETWORK_OBSERVATION_EVIDENCE_CONTRACT.md) makes the M1 gate concrete: separate per-source integrity and coverage from cross-source temporal coherence; never silently label a multi-source inventory globally atomic; retain byte-exact evidence; recompute acceptance in an independent verifier; model manager authority separately from effective kernel state; and fail closed on interrupted/lost/malformed dumps or unknown decision-critical fields. The contract is a specification, not implemented code or passing test evidence.

### M2 — Closed-loop simulator

Use network namespaces, veth pairs, nftables fixtures, FRR labs and a topology harness to exercise routing-policy and ownership changes. Inject collector loss, conflicting writers, link loss, route withdrawal, process termination and stale snapshots. No production-host mutation.

**Gate:** deterministic topology replay; fault-injection outcomes; expected reachability/path invariants and recovery-or-block decisions; frozen configuration corpus and machine-readable receipts.

### M3 — One narrowly scoped live adapter

Start with a non-remote-critical x86 appliance and a limited explicit resource subset. Initially support create/update only; no generic delete or flush. Use a root broker, exact plan binding, independent read-back, durable journal, fencing and confirmed rollback. Preserve an out-of-band recovery route.

**Gate:** forced external-writer races; crash injection before/after every operation boundary; remote-session-loss test; rollback verification; no mutation with incomplete snapshots or conflicting authority.

### M4 — FRR router profile and management APIs

Integrate selected FRR capabilities, test only the BGP/OSPF/IS-IS features actually required, and expose the selected OpenConfig/gNMI/gNOI subset with explicit gaps. Add conformance/interoperability testing against external implementations; compiling Rust bindings is not proof of protocol compliance.

**Gate:** per-feature interoperability report and regression corpus; measured convergence/failure behavior for declared topologies; versioned API contract tests.

### M5 — Appliance operations and HA

Qualify selected NIC/driver/firmware combinations, boot recovery, power cycles, watchdog, thermal/interface monitoring, redundant links, dual-device failover, controller restart and upgrade/rollback behavior. Publish exact hardware/support matrix and service SLOs.

**Gate:** sustained lab soak, reproducible failover, packet-loss/latency distributions, upgrade/recovery test records and explicit unsupported states. Set numeric targets before performance runs instead of choosing targets after seeing results.

### M6 — Switch ASIC integration

Proceed only after selecting an affordable documented platform and confirming compatible SAI/SDK/driver support. Evaluate SONiC/SAI and upstream components before creating a new vendor-specific ASIC driver stack.

**Gate:** exact platform/ASIC/SDK matrix; port/optic/thermal tests; forwarding-feature table; hardware reset/firmware recovery; measured throughput and failover. Software-only tests cannot qualify hardware forwarding.

## Minimum comparative benchmark against a Cisco reference

Choose a named Cisco platform/release and comparable topology before claiming superiority. Compare the reference and candidate using the same traffic profiles and failure cases. Publish raw outcomes and configurations.

Measure throughput by packet size; p50/p99/p99.9 latency and jitter under load; loss during route/link failure; BGP convergence and route scale; control-plane CPU/memory; startup/reboot recovery; upgrade/rollback interruption; management reachability; deployment success/rollback rate; telemetry completeness/lag; time to diagnose a fault; hardware compatibility; power and total operating cost. Label each observation as simulated, software-only, lab hardware or production.

A credible early win could be safer audited changes, reproducible fleet provisioning and lower commodity-appliance cost. A claim to beat a carrier router must separately demonstrate protocol scale, throughput, convergence, redundancy and lifecycle behavior on the target hardware.

## Network administration automation and Xenia

The companion [Network Administration Automation and Xenia Integration](NETWORK_ADMIN_AUTOMATION_AND_XENIA_INTEGRATION.md) describes task-level autonomy tiers and a future, exact-plan approval integration with Xenia. It explicitly keeps Xenia's current remote-control consent semantics separate from network-change authority and acknowledges that Xenia remains pre-alpha. The follow-on implementation is tracked in [Issue #69](https://github.com/Luminous-Dynamics/nixward/issues/69); the independent evidence verifier remains [Issue #68](https://github.com/Luminous-Dynamics/nixward/issues/68).

## Decision and immediate next work

1. Keep PR #65 strictly read-only M0; do not add a mutation adapter to it.
2. Specify an independently verifiable network observation evidence contract: raw input bytes, collector identity/build, namespace and boot identity, resource-kind coverage, sequence/drop/interruption state, canonical parser/version, digest, completeness verifier and rejection rules.
3. Build M1 as a separately qualified read-only backend with fixtures and independently checked evidence.
4. Reuse FRR and kernel forwarding before testing VPP/DPDK; evaluate SONiC/SAI for merchant-silicon hardware.
5. Design the network transaction broker with the same evidentiary discipline used for Nixward system transactions, while keeping network resource locks, ownership, confirmation and rollback semantics separate from system-profile transactions.

No code, live adapter, hardware qualification, throughput result or Cisco feature parity is claimed by this proposal.

## Research references

- Cisco IOS XE model-driven telemetry: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/26x/26x-programmability-cg/model-driven-telemetry.html
- Cisco NX-OS high availability / stateful restart / ISSU overview: https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/high-availability/cisco-nexus-9000-series-nx-os-high-availability-and-redundancy-guide-106x/m-overview.html
- Cisco IOS XR architecture and Linux workflows: https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xr-software/datasheet-c78-743014.html
- NixOS manual: https://nixos.org/manual/nixos/stable/
- NixOS networking and firewall: https://wiki.nixos.org/wiki/Networking ; https://wiki.nixos.org/wiki/Firewall
- FRRouting guide / feature matrix: https://docs.frrouting.org/en/latest/index.html
- OpenConfig documentation: https://www.openconfig.net/docs/
- gNMI specification, including telemetry update semantics: https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md
- SONiC architecture, SAI and device support: https://github.com/sonic-net/SONiC/wiki/Architecture ; https://github.com/sonic-net/SONiC/wiki/SAI ; https://github.com/sonic-net/SONiC/wiki/Supported-Devices-and-Platforms
- FD.io VPP architecture / vector packet processing: https://docs.fd.io/vpp/25.10/index.html ; https://wiki.fd.io/view/VPP/Software_Architecture
