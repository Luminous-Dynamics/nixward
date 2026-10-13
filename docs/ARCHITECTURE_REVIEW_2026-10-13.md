# Nixward Architecture and Qualification Review

**Review date:** 2026-10-13  
**Reviewed default-branch commit:** `ae60256f0be73138a539ecda048e81056dd14a30`  
**Scope:** Nixward Rust execution, transaction and authority boundaries, build/CI qualification, NixOS module integration, Luminous Edge, and the currently open hardening/AI/network work.  
**Review type:** Source and repository-state review. This is not a formal penetration test, complete line-by-line audit, or qualification result.

## Executive assessment

Nixward's intended architecture is strong: cognitive and natural-language systems are advisory; a typed plan binds a change to a machine; authority can be bound to the exact plan; a persistent one-shot replay ledger exists; immutable Nix store closures provide a useful activation subject; and the transaction contract explicitly distinguishes application from verification and promotion.

The primary risk is the gap between these intended invariants and the current default-branch implementation/integration. The next milestone should be a **small, end-to-end qualified transaction kernel**, not more actuation features. The default branch must enforce one canonical privileged mutation path, every consequential operation must have durable execution observations and recoverable/indeterminate outcomes, and qualification must exercise real state transitions in a disposable NixOS VM before broadening autonomy or network actuation.

No qualification pass is established by this review. The reviewed default-branch commit has no check-runs. Several current hardening PRs have queued or absent check-runs, and a previously inspected exact-head qualification candidate failed Rust compilation and Nix packaging due to an unclosed delimiter in `src/action/plan_executor.rs`.

## Architecture principles to retain

1. **Cognition is advisory; authority is deterministic.** HDC, active inference, Phi/confidence, model output, and natural-language assent cannot independently authorize system mutation.
2. **Owner authority and release authority are distinct.** An artifact provenance signature is not permission to mutate a machine; machine approval is not proof that the executable is the trusted release.
3. **One typed plan, one exact target, one immutable subject.** Bind the machine, candidate realization, configuration/lock/source identities, command, freshness, nonce, pre-state and recovery strategy before approval.
4. **A process result is not a state result.** “Started,” “exited 0,” “profile changed,” “new closure is running,” “boot health passed,” and “promoted” are different claims.
5. **Ambiguity is a first-class outcome.** Lost observations, cancellation, supervisor death, reboot uncertainty, and incomplete recovery must be `indeterminate`, not success, failure-by-assumption, or safe-to-retry.
6. **The privileged path is smaller than the observer.** Keep planning, parsing, cognition, network inventory, UI, and remote orchestration unprivileged. If privilege is needed, expose a small broker with narrow typed operations and OS-enforced boundaries.
7. **Reproducible inputs are not qualification.** A pinned revision or digest proves which input was named; it does not prove the source builds, a test ran, a receipt is authentic, or recovery works on a machine.

## Findings and recommendations

### NWD-001 — Direct rebuild variants remain permitted on `main` (P0)

**Evidence:** `src/action/executor.rs`, `NixOSCommand::host_execution_policy()`: the default branch groups `RebuildSwitch`, `RebuildTest`, and `RebuildBoot` with allowed operations. Those structured commands serialize to `nixos-rebuild` and accept extra arguments. The open [PR #2](https://github.com/Luminous-Dynamics/nixward/pull/2) changes these variants to fail closed and directs privileged system changes through an exact `ActivateSystemClosure` store path and execution-intent authority.

**Risk:** The default branch's enforcement does not match its stated Software Ingress Covenant and immutable-closure model. Policy documents alone do not prevent a caller from reaching the legacy variants.

**Required correction:** Land the direct-rebuild denial and make it an executor invariant tested at the final enforcement boundary, not only at CLI argument parsing. Keep `nixos-rebuild` use for read-only observation or candidate realization only where its exact behavior is explicitly bounded. Mutation must invoke only the authorized closure's immutable `switch-to-configuration` action. Add regression tests that pass a structurally valid approval to every forbidden variant and prove execution is blocked before spawn.

### NWD-002 — Approval constructors blur local consent and cryptographic authority (P0)

**Evidence:** `src/action/change_covenant.rs` exposes `ChangeAuthorization::from_verified_approval(plan, issuer, evidence_digest)`; its documented transitional path accepts a non-zero caller-supplied digest after freshness checks. The CLI uses this constructor for explicit `--approve` and configuration application. The daemon/watchdog path in `src/bin/nixward_daemon.rs` also derives such an authorization from the plan digest for an issuer named `nixward:tui-watchdog`. The separate `src/action/authority_approval.rs` path does invoke `AuthorityVerifier` and checks signer trust, action, subject, target/Holon, audience, freshness, and signature.

**Risk:** A digest of a plan plus a caller-provided issuer is not cryptographic approval evidence. The interactive CLI may intentionally represent local operator consent, but the code and receipts must not make it indistinguishable from detached Ed25519 authority. In particular, a daemon/watchdog approval needs an explicit statement of which local authority made the decision, the policy granting it, the scope and TTL, and whether it is an unattended authorization.

**Required correction:** Split authorization/evidence types by trust class, for example `LocalInteractiveConsent`, `PolicyGrant`, and `VerifiedAuthoritySignature`. Only the authority verifier may produce the type advertised as cryptographically verified. For local interactive consent, require a concrete TTY/session binding, plan fingerprint display, expiry, operation class and auditable provenance. For watchdog or unattended actions, replace synthesized owner approval with an explicit enrolled policy grant: typed action allowlist, target binding, max risk/destructiveness, time/rate budget, expiration, and hard stop conditions. Never let model confidence or a generic “approved” Boolean create owner authority. Keep the exact-closure activation path fail-closed unless the approved authority mode is explicitly supported and tested.

### NWD-003 — `PlanStep.verify` is not enforced, and rollback counts are ambiguous (P1)

**Evidence:** `src/action/plan_executor.rs` declares `PlanStep.verify` as “Whether to verify state after execution,” and its builders initialize it to false. The execution loop marks a step `Completed` from the executor's result; it does not consult the `verify` flag or run a postcondition observer. In `rollback_completed`, `rolled_back_count` increases for failed or unexpected rollback results as well as success. The returned `steps` list does not reconcile completed steps with rollback disposition.

**Risk:** Callers can request verification without receiving it, and “rolled back” metrics can count attempts that failed. The result object can preserve stale `Completed` statuses after rollback attempts. This is a semantic reliability problem in addition to an observability problem.

**Required correction:** Either implement typed postconditions for every supported step or remove the misleading flag until they exist. Use statuses that distinguish `Applied`, `PostconditionPassed`, `RollbackAttempted`, `RestoredAndVerified`, `RollbackFailed`, and `Indeterminate`. Report attempted and verified-restored counts separately. Every rollback must be followed by fresh target-state observation; a zero process status alone cannot mark state restored. Disallow multi-step rollback for operations with no bounded compensating action.

### NWD-004 — Wire transaction methods can record claims without authenticating their evidence (P1)

**Evidence:** `src/action/system_transaction.rs` intentionally accepts supplied digests for validation, pre-state, application, and post-state evidence. `validate_wire()` checks schema, lengths, and basic structural constraints; it does not authenticate the evidence behind those digests. `promote()` rejects an explicitly unhealthy boot but permits `boot_healthy = None`. `recover()` can move a transaction from `Failed` or `Verified` to `Recovered` using a reason string and snapshot presence, without requiring a recovery application receipt, a prior-state digest read-back, or verified proof that the target was restored.

**Risk:** A well-formed envelope can be mistaken for an authenticated history. A transaction can be labeled recovered without evidence of restoration, or promoted with unknown boot health when boot health is a required predicate.

**Required correction:** Treat the serialized envelope as untrusted claims until independent consumers verify their referenced evidence. Introduce typed evidence-verification results that cannot be constructed from arbitrary digest strings. Make phase invariants operation-specific: if the operation changes the booted system, promotion requires a successful boot-transition witness and explicit healthy result; unknown is not healthy. Model recovery with a separate receipt binding the original transaction, exact recovery action, process outcome, observed restored profile and running closure, verifier identity/version, and evidence digest. Only `RestoredAndVerified` may produce `Recovered`. If the process ran but the observation is missing or contradictory, preserve `Indeterminate` and reconcile instead of retrying.

The v1 wire schema should remain a compatibility boundary, not become a second authorization system. If it cannot encode a truthful execution outcome, introduce a versioned extension or v2 rather than coercing observations into `exit_status: i32`.

### NWD-005 — Execution observation, cancellation, and the durable journal are not integrated end to end (P1)

**Evidence:** [PR #73](https://github.com/Luminous-Dynamics/nixward/pull/73) adds an additive observation API that distinguishes blocked-before-launch, spawn failure, exit code and signal; it also explicitly states that the current CLI still uses the legacy result-only API, v1 receipts are lossy, and dropping the observation future can lose the receipt while a child continues running. [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75) tracks durable cancellation/reconciliation. [PRs #60–#62](https://github.com/Luminous-Dynamics/nixward/pulls) explore journal-bound workers and parent-gated activation, but their branches are based on a separate qualification-hardening branch rather than `main`. The PR descriptions report that current-head checks/tests are not yet a qualification pass.

**Risk:** The system has a strong transaction vocabulary but no demonstrated end-to-end guarantee that every real mutation has a durable, recoverable record before a supervisor can disappear. Cancellation or crash can leave execution continuing after its caller loses the result. A fresh retry could overlap with or duplicate the first operation.

**Required correction:** Make a durable journal/supervisor own the worker lifetime. Persist a write-ahead intent and exact command/closure identity before release to the actuator, persist launch/worker identity before the irreversible step, and durably record the observation before advancing the state machine. Separate `NotStarted`, `Attempted`, `Exited`, `SignalTerminated`, `ObservationUnavailable`, `RecoveryAttempted`, `RestoredAndVerified`, and `Indeterminate`. On restart, reconcile the transaction against actual profile, running-closure, service, and boot observations before permitting another mutation. Do not “solve” cancellation only with `kill_on_drop`: killing a process midway is not proof of restoration.

### NWD-006 — Standalone packaging and platform integration need an executable qualification gate (P0)

**Evidence:** The current `Cargo.toml` includes `symthaea-core = { path = "../symthaea-core" }` and inherited `workspace = true` dependency declarations. The current `flake.nix` reads `../../../rust-toolchain.toml`, uses the monorepo root as source, and references the monorepo lockfile. [PR #2](https://github.com/Luminous-Dynamics/nixward/pull/2) addresses this extraction. `luminous-edge/flake.lock` pins Nixward to the reviewed `main` SHA, but `luminous-edge/flake.nix`'s visible default check builds `sporeBootTools` and does not build/test the Nixward CLI/daemon as an independent artifact.

**Risk:** Consumers can pin an exact revision that does not reproduce as an independent repository or whose relevant feature set was never built. This prevents confident deployment and complicates security review.

**Required correction:** Make Nixward a genuinely standalone Rust/Nix project: repository-local toolchain, explicit dependencies, repository-local Cargo.lock and no path escape/workspace coupling. Verify the filtered Nix source does not need secrets or sibling files. Build and test the default, CLI, daemon, TUI, and relevant systemd/observability feature combinations. In `luminous-edge`, add checks that compile the exact pinned Nixward packages and evaluate the actual NixOS module. Use a clean checkout with the pinned lockfile to reproduce them. Keep any monorepo development integration separate from published standalone packaging.

### NWD-007 — Qualification and promotion are not currently demonstrated (P0)

**Evidence:** The reviewed `main` SHA has zero GitHub check-runs and the repository tree inspected for that SHA did not expose the expected `.github/workflows` qualification workflow. PR #64 has a queued check; PRs #65–#67 also had queued checks; PR #73 reported zero check-runs. The exact-head candidate in [PR #59](https://github.com/Luminous-Dynamics/nixward/pull/59) had failed Rust and Nix checks because of the `plan_executor.rs` parse error; later run records included skipped/cancelled jobs. The branch-protection API could not be read through the current integration (403); the accessible rulesets query returned an empty list. Therefore branch protection status is **not confirmed** by this review.

**Risk:** A PR can look mature because it contains extensive evidence-oriented code and tests, while the exact code to be shipped has not actually been built or tested. A skipped, queued, cancelled, failed, or absent run must not become a green qualification claim.

**Required correction:** Put reproducible qualification workflows on the actual candidate and make promotion require successful checks bound to exactly one source SHA and artifact digest. Emit a signed qualification predicate that identifies source, toolchain, lockfiles, build artifact, test suite/corpus, platform, completed run IDs, and results. Separate untrusted PR validation from trusted release signing. Audit branch protection/rulesets manually or with an appropriately privileged integration before relying on them; require the trusted qualification check and review policy for main promotion.

### NWD-008 — Privileged service design needs a documented, enforceable privilege split (P1)

**Evidence:** `nix/module.nix` starts the daemon under configurable `nixward` user/group, with `ProtectSystem = "strict"`, `NoNewPrivileges = true`, an empty `CapabilityBoundingSet`, and read-only host paths. This is good isolation for observation and planning. The worker/helper and journal-owned activation design appears in draft PRs #60–#62, not as an integrated, qualified main-branch actuation path.

**Risk:** A secure unprivileged observer and a privileged host actuator have different needs. Weakening the daemon's systemd sandbox to make activation work would enlarge the trusted computing base.

**Required correction:** Retain an unprivileged daemon for UI, cognition, parsing, network inventory, and plan drafting. Put mutation into a separately packaged, root-owned, minimal helper with no generic shell interface. Expose typed requests with bounded inputs; independently verify signatures, policy, expiry, target identity, exact store paths, replay state, durable journal state, and pre-state under the privileged boundary. Restrict IPC to a root-owned socket with peer credentials and explicit authorization. Unit tests should verify the daemon cannot mutate host state even when model output or IPC content is adversarial.

### NWD-009 — Replay-ledger filesystem boundary warrants a race-resistant hardening pass (P2)

**Evidence:** `src/action/authority_replay.rs` checks for symlink path components, then opens the SQLite database by pathname with create/read/write flags, and adjusts file permissions afterward. The ledger has useful properties—SQLite immediate transaction, insert-if-absent replay consumption, WAL, and full synchronous durability—but the check/open/chmod sequence is pathname-based.

**Risk:** Where an untrusted local actor can manipulate a parent directory or the database path, a check-to-open race or ownership mistake may undermine the intended replay ledger. Whether this is exploitable depends on the service's real filesystem ownership and deployment model; this review does not claim a demonstrated exploit.

**Required correction:** Specify the directory/file ownership model explicitly and validate owner as well as mode. Prefer creation beneath a root-owned, non-writable parent with no-follow, descriptor-based operations (or an equivalent well-audited SQLite/filesystem strategy); verify the opened object by descriptor, not only by a prior pathname check. Exercise concurrent consumption, pre-created symlink/hardlink, replacement races, DB corruption, full disk, and crash recovery in tests.

### NWD-010 — Public descriptions still blur cognitive assistance with authority (P2)

**Evidence:** The default `README.md` describes “consciousness-gated command execution,” while `docs/SYSTEM_TRANSACTION_ARCHITECTURE.md` correctly says HDC similarity, active inference, Phi/confidence, explanations, and natural language are advisory only. The platform README also describes a “fail-open, consciousness-aware runtime,” while current platform guidance elsewhere separates optional boot availability from fail-closed mutation authority.

**Risk:** Users and integrators may reasonably infer that a cognitive signal gates or confers permission. This creates an unsafe conceptual contract even if one code path has explicit enforcement.

**Required correction:** Use one formulation everywhere: *cognition proposes and explains; deterministic policy decides; explicit authority permits; the executor applies; independent observation verifies; a bounded recovery mechanism reconciles.* “Fail-open” must be scoped to optional availability/boot behavior, never to privileged mutation.

## Target architecture

```text
                 Symthaea / Phi / AI models
                propose, predict, explain only
                              |
                              v
 Untrusted UI / IPC -> typed intent -> deterministic policy
                                      | rejects conflicts, defaults,
                                      | unknown facts, forbidden effects
                                      v
                        exact immutable realization
                    source + lock + config + closure digest
                                      |
                   validation evidence + recovery plan
                                      |
               local consent OR verified authority grant
                  (explicitly distinguished trust classes)
                                      |
                              durable journal
                         write-ahead / one transaction
                                      |
                      narrow privileged actuator
                         exact store-path action
                                      |
                       typed process observation
                                      |
                       fresh target-state observer
                   profile + running closure + services
                    boot witness + required health checks
                                      |
                          verified decision point
                           /                    \
                    promote/reconcile       recover exact prior
                                           state and verify again
```

Cross-cutting requirements: exact SHA/artifact binding, typed evidence verifiers, expiration/revocation and replay policy, crash-safe journals, redacted outputs, append-only audit history, and a claim ceiling that refuses to upgrade an unobserved event into a success.

## Recommended order of work

### Gate 0 — Close the current security contract

- Land or rebase the direct-rebuild fail-closed change from PR #2, retaining exact-closure activation as the only privileged system mutation path.
- Separate local interactive consent from cryptographically verified authority. Audit every call of `from_verified_approval`, especially daemon/watchdog calls. Add adversarial tests that prove synthesized digests cannot be represented as Ed25519 authority.
- Fix or disable `PlanStep.verify` until real postconditions exist, and report rollback attempts separately from verified restoration.
- Correct transaction promotion/recovery invariants and add negative tests for unknown health, fabricated restoration, contradictory outcomes, command/plan substitution, and stale pre-state.

### Gate 1 — Make execution observable and recoverable

- Integrate the typed execution-observation API into the CLI/daemon and the transaction protocol.
- Implement journal-owned workers and cancellation/crash reconciliation; ensure the durable journal records intent before actuator release.
- Model missing receipts as `Indeterminate`; require read-only state reconciliation before retry.
- Add exact prior-closure and selected-profile recovery receipts, followed by fresh state observation. Do not use generic `nixos-rebuild --rollback` as a substitute for exact recovery.

### Gate 2 — Reproducible build and exact-head qualification

- Finish the standalone extraction and local toolchain/lockfile.
- Ensure CI workflows validate the exact PR head, do not silently promote merge refs or stale artifacts, and have least-privilege permissions.
- Build/test each shipping feature/package; verify the NixOS module and packages through `luminous-edge`.
- Promotion requires completed passing checks for the exact subject, trusted signed release/provenance, and review—not the presence of authored tests or a queued run.

### Gate 3 — Disposable-VM system test and boot qualification

Use QEMU or a disposable NixOS VM with a deterministic fault harness before enabling production mutation. Minimum cases:

- normal candidate realization, activation, state verification and promotion;
- evaluation/build failure and precondition drift before mutation;
- command spawn failure, non-zero exit and signal termination;
- supervisor cancellation or crash before launch, after journal publication, after profile change, during activation, and after activation but before receipt persistence;
- machine/plan/command/artifact substitution and expired/replayed authority;
- concurrent Nixward requests and external profile writers;
- rollback process failure, incorrect restored closure/profile and missing observer;
- boot selection disagreement, failed reboot, boot health failure and successful recovery;
- journal/database corruption, permissions changes, full disk and abrupt restart.

Each fixture must specify the expected *decision, process outcome, observed state, transaction phase, and durable receipt*. A fault test passing its schema check is not the same as actually executing the fault against the executor.

### Gate 4 — Expand to remote management and network automation

The current read-only network planner and evidence-verifier work are sensible preparatory steps. Keep their raw observation artifacts independently verifiable; a digest alone does not establish inventory completeness, freshness, or a temporally coherent snapshot. Before adding network mutation adapters:

- qualify a read-only rtnetlink collector in isolated namespaces;
- test namespace/permission boundaries and source coverage;
- distinguish per-source evidence integrity, coverage, freshness, and cross-source time coherence;
- use a typed operation catalog with explicit postconditions and recovery expectations;
- separate network forwarding availability from the Nixward control plane so the forwarding path does not depend on cognitive services or an online coordinator;
- keep Symthaea advisory and bind any Xenia/remote-operator consent to the same exact change plan Nixward authorizes.

Do not combine the first network actuator with the first end-to-end system-recovery milestone.

## Qualification matrix

| Gate | Required proof | Current review disposition |
|---|---|---|
| Mutation boundary | All forbidden legacy commands rejected at the final executor boundary | Not satisfied on reviewed `main`; PR #2 carries the intended change |
| Authority semantics | Local consent, policy grants and verified cryptographic signatures are distinct and tested | Needs explicit source-of-authority reconciliation, especially daemon/watchdog |
| Transaction receipts | Process outcome and state observations independently verified; no success on missing evidence | Partial API work in PR #73; not wired/qualified on its described head |
| Recovery | Exact previous state restored and independently re-observed | Not established end to end by this review |
| Build integrity | Clean standalone build/test for shipped features, exact SHA | Not demonstrated for reviewed `main` |
| CI/promotion | Successful exact-head checks and trusted provenance before main/release promotion | Not demonstrated; current main check-runs absent |
| VM lifecycle | Fault-injected activation, crash/cancellation, reboot and recovery tests | Required next qualification gate |
| Network expansion | Authenticated, fresh, complete observations; no actuation before transaction qualification | Keep read-only while M0/M1 evidence work is qualified |

## Final recommendation

Make a small integrated branch the qualification candidate and stop widening the security surface until Gates 0–3 are green on one exact source SHA. Consolidate the current stacked PR sequence so that every accepted invariant lives on the shipping branch, then run the same VM scenario corpus against that integrated head. Keep draft AI provenance and network work moving only when it does not weaken or bypass the transaction kernel.

The test of success is not the number of security features or evidence records. It is whether Nixward can demonstrate, under injected failure and independent observation, that it either performed the one authorized state transition and verified it, restored the exact prior state and verified that, or honestly reported an indeterminate outcome without retrying or claiming success.
