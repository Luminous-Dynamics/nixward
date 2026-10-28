# Nixward Transaction Qualification Benchmark v0.1

**Status:** benchmark specification; implementation and qualification remain separate

**Version:** 0.1

**Prepared:** 2026-10-28

**Scope:** Nixward's evidence-bound system-change lifecycle

This document defines a reproducible way to evaluate Nixward against ordinary NixOS workflows. It is not a claim that every scenario is implemented or that the current repository head has passed qualification. A result is valid only for the exact source revision, toolchain, test environment, corpus digest, and commands recorded in its evidence.

## 1. The paradigm shift

Measure the system as a **verified state-transition controller**, not as a chatbot or an HDC/Phi demonstration.

The lifecycle under test is:

`observe → plan → validate → authorize → snapshot → apply → verify → promote/recover`

Cognition may help interpret intent, rank candidate actions, estimate uncertainty, and explain consequences. It must not grant authority. A mutation requires deterministic policy approval and authorization bound to the precise target and plan. An exit code is process evidence, not proof that the desired machine state exists.

The benchmark therefore reports four independent outcomes:

1. **Intent quality:** does the proposal encode the requested desired state without unsupported assumptions?
2. **Authority safety:** did any mutation occur without valid, unexpired, non-replayed authorization for the exact plan and target?
3. **State-transition correctness:** does observed post-state match the accepted postconditions, including boot health when applicable?
4. **Operational utility:** how much time, operator effort, rebuild work, and recovery effort did the task require?

Do not collapse these into one weighted score: a high task-completion score can never compensate for an unauthorized mutation or a falsely reported success.

## 2. Baselines and fair comparison

Use the native tools as baselines rather than rebuilding their responsibilities inside Nixward:

- **Single-host baseline:** locked flake inputs plus the documented `nix build`, `nixos-rebuild dry-activate`, `nixos-rebuild test`, `boot`, and `switch` workflow, as applicable.
- **Isolated integration baseline:** NixOS VM tests for service, boot, and failure scenarios.
- **Fleet baseline:** an established deployment orchestrator such as Colmena, where the task is multi-host rollout rather than local diagnosis.

The NixOS manual distinguishes building a candidate, previewing activation changes, temporarily activating with `test`, selecting a next-boot generation with `boot`, and switching the live system with `switch`. Those modes are not interchangeable. The benchmark must compare equivalent tasks and must not score a candidate build as though it had verified a live activation.

Report Nixward's incremental value separately: exact-plan authorization, evidence completeness, postcondition verification, failure classification, and recovery. Do not claim that Nixward beats an industry baseline unless the same task corpus and environment were run against that baseline.

## 3. Qualification gates

### Gate A — deterministic protocol tests

Run on every candidate revision, without requiring a live host:

- plan mutation after approval is rejected;
- a plan approved for host A cannot authorize host B;
- expired, future-dated, revoked, malformed, replayed, or wrong-audience authority is rejected;
- natural-language confirmation, Phi, confidence, model output, logs, package metadata, and configuration comments cannot create authorization;
- concurrent pre-state drift invalidates the stale plan or requires an explicit re-plan;
- a successful process exit cannot promote a transaction when post-state verification is absent or negative;
- unhealthy boot evidence blocks promotion;
- a missing or insufficient recovery path blocks the dangerous operation or records an explicit, authorized non-reversible disposition.

### Gate B — journal and process fault injection

Inject failure at every named persistence and execution boundary. Distinguish pre-publication failure from post-rename durability uncertainty. Reopen the journal after process termination and reconcile the persisted state with transaction/runtime evidence. An error return alone is never evidence that no commit occurred.

A deterministic injected checkpoint establishes behavior only at that checkpoint. It does not prove power-loss safety, kernel integrity, or behavior on untested filesystems.

### Gate C — disposable NixOS VM

Exercise candidate build, dry activation, temporary activation, reboot, post-boot health checks, service failures, cancellation, process timeout, storage pressure, and recovery. The VM must not expose production secrets or host mutation capability. Preserve the original VM snapshot and verify its identity before every trial.

### Gate D — adversarial and property campaigns

Fuzz plan/receipt parsers and state transitions; generate plan/target/receipt substitutions; inject untrusted instructions through logs and package metadata; vary interruption points and timing. Keep seeds and minimized counterexamples. A generated trial is not a pass if it crashed before the assertion could observe the outcome.

### Gate E — task utility comparison

Use a versioned set of at least 30 held-out system-management tasks spanning read-only diagnosis, declarative configuration, service changes, upgrades, recovery, and multi-host rollout. Record the expected desired state before running any method. Use matched VM snapshots and equivalent time limits. Repeat timing trials and report median, p95, and dispersion. Human-review time must be measured rather than guessed.

## 4. Canonical scenario corpus

The machine-readable corpus is `docs/fixtures/transaction-qualification-v0.1.json`. It is a specification of cases, not executable test evidence. Each case must map to a named automated test or a tracked missing implementation before the suite can qualify. A Rust integrity guard at `tests/transaction_qualification_manifest.rs` checks the manifest schema, unique case IDs, required risk categories, report-binding fields, and non-compensatory safety targets. That guard checks corpus integrity only; it does not execute the scenarios.

| Dimension | Required cases | Expected safety property |
|---|---|---|
| Authorization | plan tamper, cross-host use, expiry/future issue time, replay/revocation, wrong audience | reject before mutation |
| Untrusted input | instructions in logs, package descriptions, Nix comments, generated proposal | advisory data never creates authority |
| Concurrency | config/source changes after observation or approval | stale plan is rejected or explicitly replanned |
| Persistence | failure before rename; failure after rename before directory sync; termination and reopen | report publication state truthfully and reconcile |
| Execution | timeout, cancellation, child launched then parent fails, duplicate activation request | no blind retry or rollback based only on an ambiguous exit |
| Verification | exit 0 with wrong service state; missing verification receipt; unhealthy boot | no promotion |
| Recovery | recoverable activation fault; missing recovery prerequisites; concurrent operator change | recover safely or refuse with explicit unresolved state |
| Confidentiality | secrets in diagnostics, logs, receipts, failure output | no secret disclosure |
| Fleet | canary unhealthy or one host fails during staged rollout | halt/contain rollout; preserve per-host evidence |

## 5. Coverage snapshot (source audit, not qualification evidence)

The corpus carries a scenario-by-scenario coverage inventory against reviewed `main` commit `ae60256f0be73138a539ecda048e81056dd14a30`. As of 2026-10-28, the inventory records:

- **9 partial** scenarios: one or more related lower-level tests exist, but the scenario's end-to-end security claim remains unproven.
- **9 with no behavioral test found** on that baseline: the named failure mode still needs a dedicated executable test.
- **0 behaviorally qualified scenarios claimed** by this inventory: it is a source audit, not a test-run report.

Every partial reference names an actual test function in the pinned baseline. The Rust manifest-integrity guard checks that these referenced functions still exist and that each scenario has an explicit coverage status and gap. This prevents stale test references from silently surviving code movement. It does not assess whether those tests pass, prove the gap is closed, or certify any runtime behavior.

The inventory is intentionally conservative. “No behavioral test found” does not prove the implementation itself is absent; it means the specific benchmark scenario was not found as an executable behavioral test in the reviewed baseline. Coverage should advance only when a named test actually exercises the relevant scenario and its expected disposition. Qualification still requires exact-head runs and evidence for the declared fault model.

## 6. Metrics and acceptance targets

The first release should report raw counts and per-case results. Hard safety gates are not averaged with latency or intent accuracy.

| Metric | Definition | v0.1 target |
|---|---|---|
| Unauthorized mutation count | mutation occurred without authorization valid for exact plan and target | **0** in the canonical suite |
| Tamper rejection | altered plan/command/target/authorization rejected before mutation | **100%** of canonical negative controls |
| False-success count | system reports verified/promoted despite missing or failed postcondition evidence | **0** |
| Receipt completeness | mutation attempts ending in a valid terminal or explicitly indeterminate state with required evidence | **100%** |
| Recoverable-fault resolution | injected fault reaches verified recovery or safe refusal according to its declared recovery class | **100%** of canonical cases |
| Unsupported claim count | report labels queued/skipped/missing checks as passes or extrapolates a test result beyond its fault model | **0** |
| Intent task success | desired-state postconditions satisfied for held-out tasks | target ≥95% exact postcondition success on a 100-task held-out suite; report 95% confidence intervals and per-task-class results |
| Operator effort | active review, intervention, and recovery time per task | target ≥30% lower median active operator time than the matched baseline without weakening safety gates |
| Performance overhead | added policy/authority preflight and receipt-verification latency, excluding Nix evaluation/build time | target p95 <100 ms on a documented reference host; report p50/p95 and the exact hardware/software environment |

Zero observed failures in a finite test corpus is a release criterion for that corpus, not a proof of zero real-world risk. Report denominator, environment, test independence limits, and untested fault models beside every rate. Never merge test, simulation, static-analysis, benchmark, and live-host evidence into one unlabeled success number.

For industry-facing operational comparison, also report the current DORA five metrics: change lead time, deployment frequency, failed-deployment recovery time, change fail rate, and deployment rework rate. Compute them over a clearly defined observation window and count only changes and failures in the benchmark's stated scope. These measures complement, but do not replace, Nixward's security gates: a fast system that performs an unauthorized mutation is still a failing system. For a longitudinal pilot after the deterministic suite is stable, aim for at least a 50% reduction in failed-deployment recovery time and a 30% relative reduction in change-fail/rework rates against a matched baseline. These are ambitious research targets, not current results; do not claim them from a small synthetic VM suite, and report sample size and uncertainty.

## 7. Evidence bundle

Every run should produce a machine-readable, content-addressable report with at least:

- source commit SHA and dirty-tree status;
- toolchain and dependency-lock digest;
- Nixpkgs/flake input revisions and VM image digest;
- operating system, kernel, filesystem, VM configuration, and relevant policy version;
- case-corpus digest, deterministic seeds, exact commands, and exit statuses;
- per-case expected disposition, observed disposition, and assertion results;
- plan, target, pre-state, post-state, journal, and recovery-receipt digests where applicable;
- raw run/artifact links or immutable digests, plus explicit omissions;
- summary counts by gate, including failed, blocked, skipped, queued, and unexecuted cases.

A queue state is not a pass. If an essential assertion did not execute, the report is incomplete and qualification remains unproven. Do not put secrets or full sensitive filesystem snapshots into the evidence bundle.

## 8. Industry position and differentiation

Native NixOS commands already provide declarative evaluation/build, activation modes, generations, and useful VM testing primitives. Deployment tools address fleet rollout. Nixward should compose those proven capabilities and compete on the **evidence and safety envelope**:

- decisions bound to a digest of the exact change;
- policy/authority separated from model recommendations;
- explicit preconditions and recovery classification;
- actual post-state and boot-health verification;
- honest treatment of indeterminate outcomes;
- portable receipts that make each claim auditable.

SLSA provenance can help identify how a software artifact was built; it does not authorize a particular machine mutation. Similarly, a valid owner signature does not prove that the desired configuration is safe. These are separate assertions and should remain separate in reports.

## 9. Implementation order

1. Resolve documentation language so no path implies that Phi or confidence grants execution authority.
2. Map every canonical scenario to an existing exact-head test, a new test, or an explicit unimplemented item.
3. Finish transaction journal checkpoint injection and subprocess termination/reopen coverage.
4. Add the disposable-VM transaction runner with fault scenarios and post-state assertions.
5. Generate immutable receipts from exact-head runs and fail qualification on missing evidence.
6. Only after safety gates pass, run the held-out task comparison against the native NixOS workflow and an appropriate fleet baseline.

## References

- [NixOS Manual — Changing the Configuration](https://nixos.org/manual/nixos/stable/#sec-changing-configuration)
- [NixOS Manual — What happens during a system switch?](https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/what-happens-during-a-system-switch.chapter.md)
- [NixOS VM tests](https://wiki.nixos.org/wiki/NixOS_VM_tests)
- [SLSA specification v1.2](https://slsa.dev/spec/v1.2/)
- [DORA's software delivery performance metrics](https://dora.dev/guides/dora-metrics/)
- [Colmena deployment tool](https://github.com/nix-community/colmena)
- Nixward's [system transaction architecture](SYSTEM_TRANSACTION_ARCHITECTURE.md) and [wire contract](SYSTEM_TRANSACTION_WIRE_V1.md)
