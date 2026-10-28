# Systemd-owned transaction supervision v1

Status: **architecture proposal and decision contract; privileged worker service not implemented or qualified**  
Date: 2026-10-28  
Related: [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75), [PR #62](https://github.com/Luminous-Dynamics/nixward/pull/62), [PR #86](https://github.com/Luminous-Dynamics/nixward/pull/86)

## Decision

Move the lifetime of a privileged activation worker out of the request-handling future and, next, out of the Nixward daemon's process tree. Use the system service manager as the owner of a per-transaction worker unit, while retaining Nixward's content-bound journal as the source of transaction intent and lifecycle evidence.

This document does not claim that adding a systemd unit alone creates crash safety. The unit manager's transient runtime state, the worker's process disposition, the durable Nixward journal, and the independently observed machine state are separate evidence sources. All must be reconciled, and no one source by itself proves that activation or recovery succeeded.

## Existing service boundary

The current NixOS module defines services.nixward as an awareness daemon under a dedicated unprivileged user, with read-only access to Nix state, ProtectSystem=strict, NoNewPrivileges=true, and an empty capability bounding set. That is a valuable separation: do not simply grant the existing cognition/awareness daemon root authority to solve process lifetime.

The next implementation should add a separate privileged transaction-worker boundary, with its own socket/API, process identity, durable journal binding, and hardening profile. An HTTP/UI request must never become an implicit root command request.

## Proposed architecture

### 1. Unprivileged intent/control plane

The UI, CLI, cognition system, and ordinary awareness daemon submit a versioned request that identifies:
- the exact transaction ID and immutable plan digest;
- the approved store-backed worker executable and exact argument vector;
- the authorization evidence already required by the transaction protocol;
- the expected predecessor and candidate closure identities;
- the journal path/identity and the bounded deadline for the caller's response.

The control plane can query status and request read-only reconciliation. It does not receive a reusable root shell, arbitrary executable selection, ambient PATH resolution, or a capability to mutate NixOS state just because a Phi/confidence score is high.

### 2. Narrow privileged supervisor

A separate root-owned supervisor validates the request against the durable transaction journal and existing authorization rules. It acquires the cross-process Nixward interlock, refuses unresolved peer transactions, validates that the exact worker capability has not been consumed, and asks systemd to start a transaction-specific service through the manager API (prefer a typed D-Bus interface such as StartTransientUnit over shell-composed systemctl/systemd-run command strings).

The service name is derived from a canonical transaction identifier and cannot be supplied as an arbitrary unit name by the caller. The service executes only the immutable gate or another already-approved store-backed exact worker entry point, with explicit environment and exact argv. Its environment is cleared and rebuilt from a small allowlist. All unit properties are generated from a typed schema, never copied from client-controlled arbitrary key/value input.

The worker unit has a different lifecycle from the supervisor's request/session and Nixward awareness daemon. The service manager can observe, stop, and account for the worker independently of whether the original requester remains connected. Do not automatically restart a completed or failed mutation unit: a one-shot activation is not an idempotent daemon heartbeat, and retrying after an ambiguous result may replay a mutation.

The current systemd service-management contract documents Restart=on-failure as appropriate for long-running services, but that does not mean a one-shot privileged transaction should be restarted automatically. Worker retries require an explicit reconciliation decision and, when necessary, fresh authorization. See [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).

### 3. Persist-before-start and durable identity

The ordering is:
1. Validate request and exact authorization against the journal.
2. Persist the Starting/mutation-boundary record and exact worker intent.
3. Ask systemd to start the uniquely named worker unit.
4. Capture returned unit invocation identity and query the unit's main process identity where supported.
5. Bind process identity to the transaction; persist it before any release capability can authorize a worker payload.
6. Observe the unit/process disposition independently and write a no-clobber process observation receipt.
7. Perform a fresh read-only observation of both the running closure and selected system profile.
8. Advance the transaction only through the existing transaction state machine after its postconditions are satisfied.

If the supervisor crashes at any boundary, restart begins with reconciliation, not with repeating step 3. A unit start response that was lost may mean the unit was created. Query the canonical unit name and invocation ID before considering any retry.

### 4. Stop, restart, and reboot semantics

The per-transaction worker unit, not the caller's request, owns the activation process. The selected systemd kill policy must be explicit and tested. systemd documents KillMode=control-group as terminating remaining processes in the service control group when the unit is stopped; it warns against KillMode=process or none because they can allow processes to escape service-manager lifetime/resource management. Do not choose a weaker kill policy merely to make a child survive a supervisor bug. See [systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html).

There are distinct fault models:

| Fault | Protocol response |
|---|---|
| Client/UI request cancelled | Worker unit remains manager-owned; client receives no success assertion. |
| Nixward awareness daemon restarts | Worker remains separately managed; restarted control plane queries the existing transaction/unit and must not duplicate it. |
| Privileged supervisor restarts | Reopen durable journals, query canonical unit identity/state, test worker identity, and reconcile before creating any replacement worker. |
| Worker exits but receipt publication fails | Transaction remains indeterminate; never infer success/failure from the missing receipt. |
| Unit disappears from manager state | Do not infer that the operation never ran. Use persisted journal and fresh machine observations. |
| Host reboots | Old boot-scoped process identity cannot remain the same live process. This does not prove whether the pre-reboot activation completed or which profile/runtime is now active. Observe current runtime and profile and classify state conservatively. |
| Runtime/profile evidence is mixed or unavailable | Block additional mutations and retain the unresolved journal for more read-only evidence/operator investigation. |

This design deliberately keeps the unit's process disposition, transaction lifecycle phase, and actual NixOS postcondition distinct. systemd restart policy improves service supervision; it is not a substitute for a durable transaction protocol.

### 5. Startup reconciler

A startup/restart reconciler scans only canonical journal paths under a root-owned, non-writable journal directory. It validates the journal schema, content identities, worker receipts, sidecar paths, ownership and permissions. It uses a stable interlock before making any disposition decision.

The reconciler may:
- continue observing an exact live worker;
- query a systemd unit by its canonical transaction-derived name;
- acquire exact pidfd/boot/start-time evidence where available;
- perform read-only observations of running closure and selected profile;
- record an observation and say which lifecycle validation remains necessary;
- stop and require manual investigation if identity/evidence contradicts.

It may **not** automatically replay a mutation just because a caller timed out, a sidecar is missing, a unit is inactive, or the host boot ID changed. A candidate state observed after reboot still must be interpreted under the transaction's requested action (switch/test/boot) and existing lifecycle requirements.

## Executable decision contract added

The new module src/action/transaction_supervision.rs contains a pure function that maps:
- worker identity status (ExactWorkerLive, exited/no longer present, previous boot, unknown);
- process-receipt status (validated exit code/signal, missing, invalid);
- target observation (not attempted, candidate active, predecessor active, boot candidate selected, mixed/unknown, unavailable);

to a conservative reconciliation directive. None of the result variants grants mutation authority or marks a transaction terminal.

The cross-product test covers 5 worker states × 5 receipt states × 6 target states = 150 combinations. It specifically asserts that unknown identity dominates, a receipt claiming exit while the exact worker is live is contradictory, missing receipts still require target observation, and a boot-selected profile is not reported as a running candidate.

A second pure contract covers the systemd start-response crash window. Before the D-Bus call, the supervisor must durably record that submission may have occurred. On restart, a matching canonical unit is observed; a conflicting unit identity is held; an absent unit after an ambiguous submission triggers read-only target reconciliation instead of replay. The start-recovery test covers 3 durable intent states × 5 manager lookup states = 15 combinations. This is deliberately at-most-once-biased: when the evidence cannot distinguish “the request was never delivered” from “the unit ran and was later unloaded,” availability is sacrificed to avoid a duplicate privileged mutation.

This pure decision contract is not yet connected to the production recovery path. That integration requires the separate supervisor implementation and exact-head compilation/behavioral tests. It is a testable contract for the next integration step, not a claim that the architecture is already deployed.

## Qualification plan

### Mandatory hard gates

| Measure | Acceptance target |
|---|---:|
| Unauthorized privileged worker launches in negative controls | 0 |
| Duplicate launches for one transaction/invocation after ambiguous start response | 0 |
| Automatic replays after missing receipt, caller timeout, unit loss, or reboot | 0 |
| Identity mismatch accepted as the persisted worker | 0 |
| False terminal transaction claims when target evidence is absent or mixed | 0 |
| Decision-contract cases that violate the conservative matrix | 0 |
| Independent target-state observations required after worker termination | 100% |

### Fault-injection campaign

For each supported NixOS/systemd/kernel profile, test request cancellation before start, after request submission, after systemd accepts StartTransientUnit but before its response reaches Nixward, before/after worker identity publication, during activation, after process exit before receipt publication, supervisor SIGKILL, awareness-daemon restart, worker-unit stop, journal fsync failure, and host reboot. Retain the exact Nixward commit SHA, flake.lock digest, NixOS closure identities, systemd/kernel versions, test seed, fault checkpoint, journal/receipt digests, and independently observed pre/post-state.

Run at least 100 randomized trials per interruption checkpoint after deterministic cases are stable. These are proposed targets, not results. No production-host mutations should be used to qualify the state machine.

### Performance and operator utility

Measure worker-start latency and receipt latency at p50/p95/p99; reconciliation completion time; unresolved-transaction rate; operator intervention minutes; duplicate/false-success rate; and time-to-recover from genuinely failed deployments. Keep safety hard gates separate from latency targets: speed cannot compensate for false success or unauthorized mutation.

For industry comparisons, use the same hardware, NixOS release, deployment tasks, network/cache settings, and injected faults across Nixward, standard nixos-rebuild, and Colmena where the workload fits. Colmena's deployment/concurrency behavior is a useful baseline, but comparisons must report the scenario differences. Track DORA's five metrics (change lead time, deployment frequency, failed-deployment recovery time, change-failure rate, deployment rework rate) longitudinally rather than turning one aggregate score into a universal ranking. DORA cautions that disparate service comparisons and a single metric used as a target can mislead; the main goal is improving the same system over time. See [DORA's metric guide](https://dora.dev/guides/dora-metrics/).

## External references reviewed

- [systemd.service: restart and unit behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [systemd.kill: control-group and process kill modes](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
- [systemd.exec: service sandboxing and state directories](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Tokio process caveats](https://docs.rs/tokio/latest/tokio/process/)
- [Colmena](https://github.com/zhaofengli/colmena)
- [DORA metrics](https://dora.dev/guides/dora-metrics/)

