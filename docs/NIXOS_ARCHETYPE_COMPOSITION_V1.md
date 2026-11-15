# Composable NixOS Archetypes v1

**Status:** design proposal / implementation contract  
**Date:** 2026-11-15  
**Scope:** public Nixward NixOS module and Luminous infrastructure composition  
**Non-claim:** this document does not assert that the proposed archetypes, evaluator, benchmarks, or deployment guarantees have been implemented or qualified.

## 1. Executive proposition

Luminous should build a small, reusable library of NixOS modules and capability profiles rather than a collection of copied host configurations or a new configuration language.

The proposed architecture is **capability-first, archetype-second, host-composition-last**:

1. **Capabilities** describe individual services, resources, security boundaries, and operational properties.
2. **Archetypes** are curated compositions of capabilities for recurring roles.
3. **Host compositions** combine archetypes with hardware facts, local policy, secrets, and operator intent.
4. **Nixward transactions** validate and authorize consequential changes, apply an exact plan, independently observe the result, and promote or recover it.
5. **Evidence** binds source, inputs, policy, build outputs, target identity, and observed outcomes.

The paradigm shift is not “more flakes.” It is **a verifiable contract between the intended machine, the evaluated configuration, the realized closure, and the observed running system**.

NixOS's module system remains the primary composition engine. Flakes are distribution and pinning interfaces. Optional tools such as flake-parts may organize flake outputs, but must not become a mandatory runtime dependency of the module library.

## 2. Design principles

### 2.1 Modules are the product; flakes are adapters

The core modules should be ordinary NixOS modules that can be imported by a consumer's existing configuration. A consuming flake chooses and pins its own nixpkgs revision.

Required properties:

- Modules do not fetch arbitrary resources at evaluation time.
- Modules do not silently select a nixpkgs revision or override the consumer's package set.
- Modules do not depend on undeclared files outside their published source tree.
- A module can be imported without adopting flake-parts, flake-utils, or the Luminous deployment workflow.
- The distribution flake exposes NixOS modules, checks, templates, and optional development shells without hiding the module API.

This follows the Nix documentation's advice to keep flakes thin where possible and recognizes the documented trade-offs of recursive flake inputs and follows relationships: https://nix.dev/concepts/flakes.

### 2.2 Capability contracts precede archetypes

A capability is a stable, reviewable statement of what a host can provide or what a workload requires. Examples include:

- network.egress-controlled
- storage.encrypted-at-rest
- secrets.runtime-delivery
- identity.non-root-service
- service.systemd-sandboxed
- build.reproducible-inputs
- gpu.cuda-runtime
- observability.local-journal
- recovery.previous-generation
- deployment.ssh-transport

These identifiers are illustrative, not a finalized registry.

Capabilities must distinguish:

- **provided** — a module configures the capability;
- **required** — a workload cannot operate correctly without it;
- **prohibited** — policy forbids it;
- **observed** — target-side evidence says it is present;
- **unknown** — evidence is missing or insufficient.

A declaration that a capability is provided is not proof that it is active on a target. Evaluation evidence, build evidence, runtime observation, and qualification remain separate.

### 2.3 Archetypes are curated compositions, not inheritance magic

An archetype is a named, versioned set of ordinary modules plus its capability requirements and constraints. It is not an independent language and must not redefine NixOS option merging.

Initial archetypes:

| Archetype | Intended role | Typical capability families |
|---|---|---|
| base | Minimal common foundation | reproducible inputs, core hardening, observability, recovery |
| workstation | Interactive daily-use system | desktop/session, audio, user environment, developer ergonomics |
| builder | Trusted build and CI worker | isolated builds, resource limits, cache trust, build evidence |
| server | Long-running headless services | network policy, service sandboxing, backup, monitoring |
| research | Scientific and AI workloads | compiler toolchains, GPU/accelerator, datasets, experiment provenance |
| edge | ARM, embedded and robotics hosts | constrained resources, remote observability, staged updates, recovery |
| secure-worker | Bounded execution environment | minimal filesystem, no ambient credentials, network restrictions, workload identity |
| recovery | Repair and reinstallation environment | bootable recovery, known-good closure, disk-layout and restore procedures |

Hardware support is a separate composition axis. For example, research plus gpu.nvidia is a different composition from research plus cpu-only; an edge archetype must not silently import workstation or server hardware assumptions.

A secure-worker archetype must be a real isolation boundary, not merely a separate HOME, XDG directory, or D-Bus session. Its default principal should be a dedicated unprivileged Unix identity outside wheel, docker, libvirtd, and Nix trusted-users. Filesystem write paths, secrets, network egress, device access, daemon sockets, and resource budgets must be explicit. VM qualification must test actual denied access, not just inspect the declared systemd properties.

### 2.4 Composition is monotonic for mandatory constraints

Recommended policy layers:

~~~
public baseline
    -> organization baseline
        -> workload role
            -> host/hardware facts
                -> owner/operator intent
~~~

Mandatory constraints accumulate. They are not resolved by “last writer wins.”

The design should classify policy declarations as:

- require: a condition that must be true;
- forbid: a condition that must be false;
- prefer: a non-binding selection hint;
- exception: a narrowly scoped, expiring, authorized deviation.

A conflict between mandatory rules produces a deterministic conflict record and blocks realization. An exception must bind the exact rule, target scope, rationale, issuer, evidence/compensating control, and expiry. Removing or weakening an inherited rule is not an implicit exception.

The first implementation should use NixOS module options, module-system assertions, and pure validation functions. Do not introduce a parallel resolver until there is a demonstrated limitation in the module system.

### 2.5 Profiles are data, not remote Nix code

Downloaded organizational or workload profiles must be data-only policy documents. Evaluating an arbitrary remote Nix expression is code execution, not safe policy ingestion.

A profile is untrusted until:

1. its source/repository metadata is authenticated under a local trust policy;
2. its expected content digest matches;
3. its schema and version validate strictly;
4. its applicability matches the target;
5. its composition is conflict-free;
6. the resulting Nix evaluation succeeds;
7. the resulting plan passes independent validation;
8. the exact plan is authorized by the machine owner/operator.

No profile publisher gains machine-mutation authority merely by publishing a profile.

OSCAL can provide control-catalog and baseline interoperability, while Nixward retains a small internal policy model. TUF is a candidate for delegated profile distribution and rollback-resistant repository metadata; in-toto/DSSE can carry authenticated build or capture evidence. These are integration candidates, not claims that the present code already implements the complete chain.

## 3. Proposed repository shape

The following is a target organization, not a request to move every existing file immediately:

~~~text
nix/
  module.nix                    # existing Nixward service module; preserve compatibility
  modules/
    foundation/
    capabilities/
      networking/
      storage/
      identity/
      observability/
      secrets/
      recovery/
      build/
      gpu/
    archetypes/
      base.nix
      workstation.nix
      builder.nix
      server.nix
      research.nix
      edge.nix
      secure-worker.nix
      recovery.nix
    hardware/
      x86_64/
      aarch64/
      gpu/
    policy/
      assertions.nix
      capability-contracts.nix
  tests/
    evaluation/
    composition/
    security/
    vm/
  examples/
    workstation/
    builder/
    server/
    edge/
~~~

Keep the current public module path stable while adding the library incrementally. Use aliases or compatibility imports where needed. A structural reorganization is not itself a feature and must not obscure the public API.

## 4. Illustrative consumer interface

The intended experience should remain recognizable to NixOS users:

~~~nix
{
  imports = [
    inputs.luminous-infra.nixosModules.archetypes.base
    inputs.luminous-infra.nixosModules.archetypes.workstation
    inputs.luminous-infra.nixosModules.capabilities.observability
    inputs.luminous-infra.nixosModules.hardware.gpu.nvidia
  ];

  # Illustrative policy API; not implemented by this document.
  luminous.policy = {
    require = [
      "recovery.previous-generation"
      "observability.local-journal"
    ];
    forbid = [
      "identity.root-ssh-login"
    ];
  };
}
~~~

The host remains responsible for its own bootloader, filesystems, hardware configuration, machine identity, network trust, and secret sources. An archetype must never guess destructive disk targets, invent machine identity, or provide default secrets.

## 5. Nixward security and authority boundary

Nixward's system-transaction architecture already establishes the correct lifecycle:

**observe → plan → validate → authorize → snapshot → apply → verify → promote/recover**

Cognitive inference, HDC similarity, predictions, generated explanations, and natural-language conversation remain advisory. They cannot authorize a machine mutation. The exact plan, target, command, authority evidence, recovery binding, and observed post-state must remain linked to one transaction.

This proposal preserves that boundary:

- An archetype cannot grant root access or execution authority.
- A profile cannot turn an advisory proposal into an authorized operation.
- A successful Nix evaluation or build cannot be reported as a successful deployment.
- A command's zero exit status cannot substitute for independent target observation.
- A missing or ambiguous result remains unknown; it cannot trigger a blind retry or a new mutation.
- Recovery and promotion are separate outcomes. A rollback command is not proof that the old state was restored.

**Contract mismatch to resolve:** the current public nix/module.nix exposes support.autonomyLevel values named advisory, semi-autonomous, and full-autonomous, with descriptions suggesting automatic execution. That vocabulary is in tension with the system-transaction architecture's statement that cognitive signals never authorize machine mutation. This source-level mismatch is not, by itself, proof that the daemon can perform privileged mutations; the actual executor path and runtime permissions must be reviewed. Before archetypes expose this option as a recommended setting, reconcile the contract: keep execution authority in the explicit transaction/authorization subsystem, and make any autonomous behavior a separately bounded, explicitly authorized capability. Do not treat a watchdog or a Phi/confidence score as owner authorization. The required source-to-runtime audit is tracked in [issue #155](https://github.com/Luminous-Dynamics/nixward/issues/155).

## 6. Evidence contract

Every supported archetype composition should be able to produce a machine-readable qualification record containing, at minimum:

- archetype ID and version;
- ordered module identities and source tree digest;
- Nix version and exact nixpkgs revision;
- flake.lock digest, where a flake is used;
- target architecture and declared hardware facts;
- policy/profile identities, versions, and content digests;
- Nix evaluation result and diagnostics;
- derivation identities and realized closure/store paths;
- relevant build provenance and trust-policy result;
- host identity and pre-state evidence for deployment;
- independent post-state observation;
- transaction terminal disposition: promoted, recovered, failed, or unresolved.

Each field must retain its evidence class: directly observed, user-specified, derived, defaulted, or unknown.

A digest proves the identity of bytes, not their truth or authority. Signature validity proves a signature under a key, not that a build was performed honestly. Build provenance, owner authorization, and runtime state are distinct evidence domains.

## 7. Benchmark and qualification programme

Do not claim “better than SOTA” before running matched, independently reviewable comparisons. The aim is to win on measurable assurance and usability without sacrificing the deployment features that existing tools already provide.

### 7.1 Composition correctness

Workloads:

- each archetype alone;
- every supported pairwise composition;
- selected high-value triples (for example, base plus builder plus secure-worker);
- incompatible mandatory policies;
- missing hardware capability;
- unknown capability identifier;
- conflicting providers;
- expired or out-of-scope exception;
- profile schema/version mismatch.

Hard gates:

- 100% of declared mandatory conflicts are rejected;
- 100% of unsupported or unknown mandatory capabilities fail closed;
- 100% of allowed compositions evaluate on the declared NixOS/toolchain matrix;
- deterministic conflict reports for identical pinned inputs;
- no prefer rule may override require or forbid.

Report supported-composition coverage rather than an unqualified count of “working profiles.”

### 7.2 Reproducibility and portability

Measure:

- clean-checkout evaluation success;
- hermetic build success with network disabled after input acquisition;
- derivation and closure identity across independent builders;
- closure availability from the configured trusted cache;
- locked-input drift and transitive Nixpkgs duplication;
- evaluation time, peak memory, and input-fetch cost;
- x86_64-linux and aarch64-linux support where hardware/build infrastructure exists.

Run cold-cache and warm-cache trials separately. Report exact Nix, kernel, nixpkgs, and builder identities. Reproducibility is not established by two evaluations on the same mutable working tree.

### 7.3 Security and isolation

Evaluate each service and archetype with:

- systemd unit properties and systemd-analyze security as an advisory score;
- exact Linux capability sets;
- filesystem write/read boundaries;
- namespace and syscall restrictions;
- network egress policy;
- secret visibility and lifetime;
- privilege-escalation negative controls;
- service identity and process ownership.

The systemd-analyze security score is not a proof of isolation. The primary results are explicit allowed/denied behaviors and independent tests of the boundaries.

Hard gates include zero unauthorized mutations, zero host-secret disclosure in guest workloads, zero policy bypasses, and zero promotion after a failed or unknown health check.

### 7.4 Deployment and recovery

Use the existing matched deployment-assurance programme in [issue #113](https://github.com/Luminous-Dynamics/nixward/issues/113), its independent evidence verifier in [issue #119](https://github.com/Luminous-Dynamics/nixward/issues/119), and the NixOS activation-semantics qualification work in [issue #143](https://github.com/Luminous-Dynamics/nixward/issues/143). Do not create a competing benchmark harness. The earlier evaluation-diagnostics prototype in [PR #152](https://github.com/Luminous-Dynamics/nixward/pull/152) is closed and unmerged; inspect and reuse its branch work if that capability is revived rather than duplicating the diagnostic core.

Compare semantically matched workloads against:

- native NixOS rebuild modes (dry-activate, test, boot, switch) reported separately;
- Colmena for parallel evaluation and multi-host deployment;
- deploy-rs for profile deployment and connectivity-confirmed rollback;
- Nixward's direct and supervised transaction paths, only when each path is implemented and qualified.

Pin the same source revision, nixpkgs lock, target closure, machine image, kernel/systemd, cache state, storage, and network conditions. Separate build, copy/substitution, activation, transaction-control, independent verification, and recovery times.

Keep the existing benchmark's hard safety gates: zero false terminal-success claims, zero duplicate submissions for one unresolved attempt, zero unauthorized acceptance, and a complete evidence chain for every successful terminal disposition. A safe hold is not a successful recovery. Fault-injection campaigns must report the exact fault model; process cancellation, SIGKILL, VM crash, kernel crash, reboot, and physical power loss are not interchangeable.

### 7.5 Usability and maintainability

Measure:

- time and steps to compose each archetype from a clean checkout;
- number of host-specific overrides;
- number of duplicated module definitions;
- unexplained option conflicts;
- documentation task completion by a new NixOS user;
- time to reproduce and recover a known failure;
- number of required flake inputs and total evaluated input graph.

A smaller host configuration is not automatically better if it hides ten layers of indirection. Count the abstractions and the debugging burden as well as lines of code.

### 7.6 Provisional targets versus measured results

The existing deployment benchmark issue proposes initial, provisional latency goals for local transaction control. Those should remain hypotheses until matched baseline measurements exist.

For this archetype programme, set hard correctness and security gates first. Establish evaluation-time and resource baselines before setting optimization targets. Workstation-versus-builder Nix concurrency qualification is tracked in [issue #157](https://github.com/Luminous-Dynamics/nixward/issues/157). Publish raw per-trial observations, version fingerprints, confidence intervals, and negative-control results. Never convert a target into a measured result or a prototype into a production qualification.

## 8. Competitive positioning

| Existing ecosystem | What it already does well | Luminous/Nixward opportunity |
|---|---|---|
| NixOS module system | Declarative module composition, option typing, assertions | Publish well-tested capability contracts and role archetypes on top of it |
| flake-parts | Modular composition of flake outputs | Keep our module library usable without requiring it |
| Colmena | Parallel evaluation and multi-host deployment | Add verified authority-to-effect evidence; do not claim fleet-throughput superiority without a matched scheduler |
| deploy-rs | Profile deployment and connectivity-based rollback | Add transaction identity, exact authorization binding, durable reconciliation, and independent post-state verification |
| disko | Declarative disk partitioning and filesystem layouts | Compose it as a specialist capability; do not reinvent disk-layout semantics |
| nixos-anywhere | Remote NixOS installation workflows | Integrate installation with the same transaction and recovery evidence model |
| Clan / other infrastructure managers | Broader fleet and service-management workflows | Interoperate where useful; differentiate on evidence and owner-controlled authority |

Relevant project references:

- NixOS module system: https://nixos.org/manual/nixos/stable/
- flake-parts: https://flake.parts/
- Colmena: https://colmena.cli.rs/
- deploy-rs: https://github.com/serokell/deploy-rs
- disko: https://github.com/nix-community/disko
- nixos-anywhere: https://github.com/nix-community/nixos-anywhere

The strategy is not to replace these projects. It is to assemble them behind a consistent, auditable contract and prove where the integrated system provides additional guarantees.

## 9. Public-flake portability gate

The current main-branch flake.nix reads ../../../rust-toolchain.toml and sets its source to ../../../.. . This assumes a larger monorepo checkout and is a portability risk for consumers cloning Luminous-Dynamics/nixward as a standalone repository. This is not an untracked issue: open PR #2 (https://github.com/Luminous-Dynamics/nixward/pull/2) explicitly proposes the standalone extraction, removal of monorepo-relative source discovery, and repository-local dependency/toolchain declarations. Coordinate this RFC with PR #2; do not duplicate its implementation. The archetype release gate must be rerun on whichever supported standalone/monorepo boundary results from that PR.

Before publishing archetypes as a reusable flake, qualify both supported modes explicitly:

1. **Standalone mode:** a clean clone of the public Nixward repository can evaluate and build the public package/module using only declared, locked inputs and files inside the repository.
2. **Monorepo integration mode:** the Symthaea workspace can consume the same module/package without path assumptions escaping the declared source boundary.

If one mode is not supported, document the limitation and provide a deliberate adapter. Do not silently rely on sibling files, a developer's parent directory, or an undeclared workspace checkout. PR #2 remains open at the time this proposal was authored, so its current head and exact-head CI outcome must be inspected before treating the standalone boundary as established.

The clean-clone gate should include nix flake metadata, nix flake show, evaluation of exported modules, and the relevant package/dev-shell checks from a fresh checkout. This proposal has not executed those commands; the main-branch path dependency is a source audit finding, while the proposed fix is tracked in PR #2 and still requires exact-head qualification.

## 10. Incremental implementation plan

### M0 — Contract and portability audit

- Reconcile the autonomy vocabulary in nix/module.nix with the transaction authority model.
- Verify standalone versus monorepo flake behavior from clean checkouts.
- Inventory current Nix modules, inputs, outputs, and public compatibility paths.
- Capture the first reproducible evaluation/build baseline.

**Exit:** no ambiguous authority claim; supported repository consumption modes are explicit.

### M1 — Minimal capability model

- Define a versioned, data-only capability vocabulary.
- Add a pure composition validator and deterministic conflict records.
- Create negative fixtures for unknown capabilities, required/forbidden collisions, and invalid exceptions.
- Keep authorization outside profile evaluation.

**Exit:** deterministic, offline tests pass; every negative fixture fails for the intended reason.

### M2 — First archetype family

Implement only base, workstation, and builder initially. Add server and edge after the first family proves the module API. Add research/GPU only with explicit architecture, driver, and hardware compatibility.

**Exit:** every supported example evaluates; VM tests exercise the service and security contracts; no unsupported hardware assumption is implicit.

### M3 — Evidence and qualification

- Bind module/profile identities to source digests.
- Connect evaluated configuration and closure evidence to the existing Nixward transaction envelope.
- Use existing DSSE/in-toto and signature-policy work rather than inventing new trust primitives.
- Publish independent verification outputs and known limitations.

**Exit:** source, configuration, authorization, deployment, and runtime evidence remain distinct but linked.

### M4 — Matched comparison and field hardening

- Reuse benchmark #113 and verifier #119.
- Run native NixOS, Colmena, deploy-rs, and Nixward matched trials.
- Inject faults in disposable VMs and record the exact fault model.
- Publish raw results and negative controls.

**Exit:** any superiority claim is limited to a measured workload and a named evidence level.

## 11. Immediate next actions

1. Reproduce or disprove the public-flake parent-path dependency from a clean clone.
2. Resolve the autonomyLevel documentation/API mismatch before recommending any autonomous archetype.
3. Inventory existing module options and move duplicated configuration only when a stable capability boundary exists.
4. Implement the pure capability-contract and negative-fixture prototype tracked in [issue #156](https://github.com/Luminous-Dynamics/nixward/issues/156) before adding more profiles.
5. Reuse the existing transaction benchmark and trust/evidence architecture; avoid a second deployment engine or signature format.

The first release should be intentionally small. Three useful archetypes with clear capability contracts, clean-checkout builds, negative controls, and recovery evidence are more valuable than eight aspirational archetypes that have only been written down.
