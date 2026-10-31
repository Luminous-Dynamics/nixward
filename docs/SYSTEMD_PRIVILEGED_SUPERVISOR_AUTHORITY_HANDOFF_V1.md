# Privileged systemd supervisor: authorization handoff and lifecycle contract v1

Status: **architecture decision / implementation gate; no root worker or supervisor is implemented by this document**

Date: 2026-10-31

Related work:
- [Issue #96: integrate systemd job evidence with journal-owned worker transactions](https://github.com/Luminous-Dynamics/nixward/issues/96)
- [Issue #75: journal and reconcile command execution across task cancellation](https://github.com/Luminous-Dynamics/nixward/issues/75)
- [PR #104: journal-anchor systemd attempts](https://github.com/Luminous-Dynamics/nixward/pull/104)
- [PR #105: immutable launch envelope](https://github.com/Luminous-Dynamics/nixward/pull/105)

## 1. Decision

Do not add a root-run static systemd template that trusts a transaction journal merely because it can deserialize one. Keep the current nixward daemon unprivileged. Introduce a small, root-owned, single-purpose transaction supervisor as the only component allowed to accept privileged transaction requests, own privileged journal/replay state, submit the fixed systemd worker unit, and reconcile its outcome.

The supervisor must accept a **verifiable authorization handoff**, not an ExecutionAuthorization JSON blob. It independently verifies the original approval proof and exact ChangePlan, then mints a machine-local, attempt-scoped permit. Only a successfully verified permit can advance to a systemd start attempt.

The existing ExecutionAuthorization and ChangeAuthorization intentionally derive Serialize but not Deserialize. Preserve that property. A future implementation must not add generic deserialization to either runtime capability type as a shortcut.

This is an architectural gate, not a claim that the current PR chain implements the supervisor.

## 2. Why the existing launch envelope is not enough

PR #105 records an immutable executable contract before a manager start: exact Nix-store worker gate; payload executable and exact argv; fixed worker environment digest; expected pre-release system profile; and transaction, purpose, attempt and plan digest through the journal.

This prevents the observed worker from defining its own expected command after launch. It does **not** prove that a newly started process may trust the approval which led to that command.

Source audit on the PR #105 head found:

- ExecutionAuthorization derives Serialize, not Deserialize.
- ChangeAuthorization derives Serialize, not Deserialize.
- The in-memory execution capability is passed to execute_journaled_activation.
- The current executor still owns the child wait in the request-bound async call.
- The nixward system service is configured as an unprivileged user with an empty CapabilityBoundingSet.
- The existing nixward-worker-gate accepts only a parent executable from an allowlist (nixward, nixward-tui, nixward-daemon), which will need an explicit reviewed extension if a new supervisor/worker binary becomes its parent.

A static template that receives only an attempt ID cannot reconstruct the non-deserializable approval capability from the transaction. Conversely, adding Deserialize would make attacker-controlled journal bytes look like runtime authority unless every field were independently re-verified. An envelope digest is not an approval signature.

There is a second important boundary: VerifiedSignatureEvidence is verifier-produced evidence metadata. A future independent supervisor must be given the original signed approval material (or a separately verifiable permit), not merely serialized verifier output or an evidence digest that cannot reproduce verification.

## 3. Trust boundary and process roles

### Unprivileged controller

The controller may formulate a plan and candidate, show the exact command, target and recovery binding, collect approval material, request a typed transaction operation, cancel its own request and query transaction status.

It may not write the root-owned transaction journal or replay ledger; choose a worker executable, shell, environment, arbitrary unit, or systemd unit properties; submit StartUnit directly; or claim success from a D-Bus reply, process exit code, or UI timeout.

### Root-owned Nixward transaction supervisor

A dedicated systemd service owns the privileged control plane. It exposes a narrow, versioned D-Bus API (or an equivalently authenticated local IPC contract) with typed operations such as prepare, submit, query, and reconcile. It does not expose a generic command-execution method.

It must:
1. Authenticate the caller at the OS boundary.
2. Parse the supplied plan and approval proof as untrusted data.
3. Independently re-verify approval signatures / interactive approval context, signer trust, challenge, replay key, subject, expiry, machine binding, plan digest, execution-intent and realization binding.
4. Validate exact operation policy and the launch envelope using trusted local paths and a fresh system-profile observation.
5. Serialize admission under the existing /run/nixward-system-transaction.lock interlock.
6. Persist a root-owned permit and exact attempt before submitting systemd.
7. Own systemd subscription, submission, reply persistence, InvocationID / PIDFD correlation, worker lifecycle observation, and post-state reconciliation.
8. Survive controller disconnection without transferring mutation ownership back to the request task.

A compromised unprivileged controller must not be able to manufacture a permit by writing a JSON file. The root supervisor is the trust anchor for local machine policy and permit issuance.

### Fixed systemd transaction unit

A static NixOS-managed template remains a reasonable worker isolation mechanism for the systemd 253+ compatibility floor, but it is subordinate to the supervisor:

- Fixed ExecStart into one immutable Nixward package.
- No arbitrary executable or shell parameter.
- One canonical attempt identifier only.
- No caller-controlled environment or unit properties.
- Strict NoNewPrivileges, ProtectSystem, ProtectHome, device and syscall policy appropriate to the operation.
- No restart policy that silently reruns a one-shot mutation.
- Explicit cgroup / KillMode semantics and tests.
- The worker reloads the root-owned journal/permit, acquires the existing interlock, validates the attempt, and re-observes the pre-release profile before gate release.

The root supervisor, not the unprivileged monitoring daemon, calls the systemd Manager API. This avoids turning a polkit grant on the nixward monitoring user into a broad privileged unit-management interface. The D-Bus API exposed by the supervisor is the narrow authorization boundary; unit starts are an internal implementation detail.

Do not change services.nixward to run as root, add broad CAP_* privileges, or grant the monitoring account general org.freedesktop.systemd1.manage-units.

## 4. The permit is a new type, not serialized authority

Introduce a separately versioned SupervisorPermit wire record and a non-serializable VerifiedSupervisorPermit runtime type.

The wire record is untrusted on read. It must carry enough signed material or a reference to a root-owned verified approval object for the supervisor to independently establish:

| Binding | Required content |
|---|---|
| Transaction | transaction ID, unique attempt ID, purpose |
| Plan | canonical plan digest and machine-binding digest |
| Operation | exact Nix command digest and activation stage |
| Launch | digest of the complete PR #105 launch envelope |
| Preconditions | exact expected current runtime/profile and target profile |
| Approval | approval class, signer/key ID or authenticated interactive principal, evidence digest, challenge/subject, expiry |
| Replay | one-shot replay identity and its durable consumption state |
| Policy | permit schema/version and local policy epoch |
| Freshness | issued/accepted timestamps and supervisor-generated nonce |

The supervisor must verify the source proof before issuing a local permit. A plain evidence digest, client-chosen issuer string, reconstructed ExecutionAuthorization, or caller-supplied verified=true flag is not enough.

The local permit should be authenticated by a root-held machine key or another mechanism whose authority is unavailable to the controller. The private key must not enter the Nix store, journal payloads, environment, or logs. A permit signature only proves that the local supervisor issued the permit; it does not replace verification of the original user/authority approval.

The new runtime type is minted only after signature, policy, replay, transaction and launch-envelope validation. Deserialization yields only an untrusted wire DTO; it never yields VerifiedSupervisorPermit.

### Replay and persistence ordering

Approval replay consumption, permit issuance, attempt reservation and journal publication form one authorization admission transaction. Do not implement them as an unsafe sequence of unrelated writes with no crash-repair design.

Either:
- Commit the permit, transaction attempt and replay consumption in one supervisor-owned transactional store; or
- Define a recoverable write-ahead protocol with a single authoritative state machine and explicit crash recovery for every intermediate publication.

A duplicate submission after an ambiguous manager reply must reconcile the original attempt, not consume the approval again or mint a second attempt. Derived rollback authority remains distinct: it is bound to the original plan's exact predecessor action and must not reuse the original one-shot replay key (the replay-key invariant fixed in PR #105 must remain intact).

For ordinary interactive approval that has no portable cryptographic proof, the supervisor must use an OS-authenticated user-approval flow and persist its own receipt. Do not treat an arbitrary caller-provided evidence digest as equivalent to a signed approval. If a proof cannot be verified after process restart, refuse detached execution rather than silently downgrade the authorization model.

## 5. Ownership and recovery model

The key paradigm change is that **the transaction outlives the request**. The client request is a command to a supervisor; it is not the supervisor.

| Fault boundary | Required owner / outcome |
|---|---|
| Client disconnect or request cancellation | Supervisor keeps observing; cancellation does not kill or duplicate the worker |
| Controller process crash | Root supervisor and systemd unit continue; client can query the same transaction |
| Supervisor process crash | systemd remains the process manager; on restart, reacquire the interlock and reconcile the same attempt before any new mutation |
| systemd manager restart | Treat missing signals as unknown; re-query exact unit / InvocationID and worker identity where still available; otherwise observe host state and retain an indeterminate disposition |
| Host reboot | Previous pidfds are invalid and old PIDs are not evidence. Compare boot ID, journal, current runtime and profile; old worker liveness is unknown until independently resolved |
| Journal write or directory-sync failure | No later mutation. Read back only to classify current visibility; do not claim crash durability from read-back after failed sync |
| Rollback invocation | A separate journaled attempt. Exit status does not prove recovery; predecessor runtime and profile postconditions do |

Never infer NotStarted from an absent JobRemoved signal, Failed from a missing process receipt, or Recovered from a successful rollback process exit.

A request cancellation is not a supervisor crash. A supervisor crash is not a host reboot. Each needs its own injection point, identity oracle, and expected disposition. A detached Tokio task on the same daemon runtime does not satisfy this model.

## 6. Paradigm-shift opportunities

### Proof-carrying mutations

Move from “run this command because an in-memory caller said it was approved” to “execute exactly this operation because the local supervisor verified a machine-bound, single-use, plan-bound permit.” The approval, plan, executable, argv, profile precondition and postcondition become one inspectable object graph.

### Intent-to-effect evidence chain

Treat a mutation as a causal chain, not a command result:

approval proof → supervisor permit → durable attempt → systemd job → invocation identity → PIDFD worker identity → payload exit → process receipt → fresh host post-state → terminal disposition

Every edge must be independently checkable. Missing evidence yields incomplete / indeterminate, not a guessed success or failure.

### Reconciliation before retry

Replace “retry the command when the API timed out” with “reconcile the last committed attempt, then authorize a new attempt only after its disposition is known.” The safe guarantee is at-most-once submission per unresolved attempt, not exactly-once execution.

### Policy-aware transaction planning

Use deterministic policy to decide what may execute. Symthaea may recommend or rank candidate plans, but it must not mint authority. A learned model must never lower a hard policy gate, expand the envelope, or relabel unknown evidence as success.

### Composable reliability layer

Nixward should first become a provable local transaction/evidence layer that can complement nixos-rebuild, Colmena and deploy-rs. Fleet scheduling, parallel rollout, remote closure distribution and multi-profile orchestration are separate axes; do not claim to replace them.

## 7. Qualification and benchmark programme

All targets below are **proposed acceptance targets**, not measured results.

### Hard safety gates

| Metric | Initial target |
|---|---:|
| False terminal-success claims under injected faults | 0 |
| Duplicate systemd starts for one unresolved attempt | 0 |
| Accepted foreign transaction / attempt / purpose / unit / InvocationID / PID binding | 0 |
| Payload releases before verified permit + durable worker identity | 0 |
| Mutations after failed write-ahead publication or failed subscription setup | 0 |
| Terminal successes missing process receipt or fresh post-state | 0 |
| Unresolved attempts admitted for a second mutation | 0 |
| Recovery classifications unsupported by independent post-state evidence | 0 |

### Fault injection

Run at least 100 randomized trials for each boundary in the disposable NixOS VM:

1. Client cancellation before request admission.
2. Client cancellation after permit commit.
3. Cancellation immediately before and after manager submission.
4. Manager accepts StartUnit but the reply is lost.
5. Reply persisted but JobRemoved is lost or reordered.
6. Supervisor SIGKILL before worker release.
7. Supervisor SIGKILL after worker release.
8. Worker exits before process-receipt publication.
9. Journal temp write, file sync, rename and directory sync failures.
10. systemd manager restart while the worker is active.
11. Host reboot after profile selection but before activation completes.
12. Candidate, predecessor, mixed, unavailable and contradictory runtime/profile post-states.
13. Duplicated / stale / expired / foreign / tampered permits.
14. Concurrent attempts for the same transaction and different transactions.

Negative controls must include a coherently rewritten unsigned permit, a valid permit for a different plan, a stale machine binding, a consumed replay key, a wrong stage, an altered argv, and a payload attempting to change its own expected reference.

### Comparative performance

Use the same pinned Nixpkgs revision, machine profile, closure, network/cache state and change set. Separate Nix build/copy/activation time from Nixward control-plane overhead. Run matched trials against:

- nixos-rebuild local activation;
- Colmena single-node deployment (and fleet concurrency separately);
- deploy-rs single-node deployment with its normal magic-rollback path;
- Nixward's existing direct-spawn transaction path;
- Nixward's future systemd-supervised path.

Report raw per-trial artifacts and p50/p95/p99 with confidence intervals for prepare / permit verification; journal publication and read-back; manager submission and reply; JobRemoved observation; PIDFD / InvocationID attribution; worker exit receipt; fresh runtime/profile observation; reconciliation time after every fault; controller overhead excluding build and activation; operator interventions and safe-hold rate.

Proposed engineering targets after baseline measurement:
- Journal publication + read-back p95 <100 ms on the reference local SSD.
- Manager / InvocationID attribution p95 <250 ms on the reference VM.
- Normal-path control-plane overhead <5% of activation wall time (also report absolute milliseconds).
- Reconciliation p95 <2 s for cases resolvable entirely from local manager/journal/profile evidence.
- Zero false success and zero duplicate mutation remain hard gates regardless of latency.

Do not optimize by weakening evidence, widening authority, skipping sync, or treating queued as complete. Safe holds count as safe behavior, not successful recovery.

### Evidence package

Every benchmark run should pin and record:
- Nixward commit SHA and tree digest;
- Nixpkgs revision, systemd version, kernel version and VM definition digest;
- exact transaction, approval, plan and envelope digests;
- fault injection ID and injection point;
- raw manager events, journal snapshots, process identity and post-state observations;
- benchmark harness SHA, host profile, trial seed and result digest.

A benchmark summary without per-trial evidence is not a qualification result.

## 8. Industry comparison and competitive position

The current industry tools solve adjacent problems:

- **Colmena** is explicitly a stateless NixOS deployment tool and emphasizes parallel fleet deployment. Its documented parallel controls include a default deployment limit of 10, with experimental parallel evaluation. Nixward should not claim superiority on fleet throughput or stateless simplicity.
- **deploy-rs** provides multi-profile Nix-flake deployments, remote activation, concurrency and magic rollback using a post-deploy connectivity confirmation. This is a strong availability-oriented baseline; Nixward should test against that behavior, not a weaker hand-written SSH loop.
- **nixos-rebuild** is the native local activation baseline. It remains the right comparison for single-host build/activation overhead.

Nixward's differentiator should be narrower and deeper: verifiable approval-to-effect provenance, no false success under ambiguous execution, no blind replay after cancellation or manager failure, and independently verified post-state. A measured Nixward result can be better on these dimensions without being a faster fleet deployer.

The correct path is integration, not a premature all-in-one claim: demonstrate a reliable local transaction engine first, then expose it as a reusable activation backend for fleet tools. Only after a multi-host scheduler, bounded parallelism, partial-failure semantics and cross-host evidence are implemented should Nixward be benchmarked as a full fleet competitor.

## 9. Implementation sequence and stop conditions

1. Add a typed root supervisor API and threat model; keep the unprivileged daemon unchanged.
2. Define and test raw approval-proof import and independent verification. Do not deserialize existing runtime capability types.
3. Define the versioned permit DTO and non-serializable verified permit; test tamper, replay, expiry and cross-machine rejection.
4. Design a single-writer authority/replay/attempt persistence protocol and crash-recovery oracle.
5. Add a fixed supervisor package binary and static template only after steps 1–4 are accepted.
6. Wire manager observer and worker gate to the supervisor; preserve the existing Nixward interlock and journal durability machinery.
7. Add NixOS VM tests for request cancellation, supervisor SIGKILL, systemd restart, reboot and power-loss boundaries.
8. Enable production execution only after exact-head Rust tests, Nix feature check, clean VM fault corpus and independent negative controls pass.

**Stop conditions:** no root unit, polkit rule, general manage-units grant, or production StartUnit wiring while the supervisor cannot independently verify approval proof and persist/recover the permit + replay state. No claim of request-independent supervision until cancellation tests prove the root supervisor continues to own the operation.


## References

Reviewed 2026-10-31. These sources define the comparison envelope; they do not establish Nixward's benchmark results.

- Colmena describes itself as a stateless NixOS deployment tool with parallel deployment: https://github.com/nix-community/colmena
- Colmena's parallelism manual documents bounded deployment concurrency (default 10) and experimental parallel evaluation: https://colmena.cli.rs/unstable/features/parallelism.html
- deploy-rs documents multi-profile deployment, concurrent targets and magic rollback via a post-deploy connectivity confirmation: https://github.com/serokell/deploy-rs
- systemd's D-Bus API documents GetUnitByPIDFD and why it is safer than PID-only lookup because PIDs can be recycled: https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html
