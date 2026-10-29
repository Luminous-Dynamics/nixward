# Systemd start-job evidence contract v1

Status: **pure contract plus optional zbus observer authored; not compiled or runtime-qualified**  
Date: 2026-10-29  
Related: [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75), [PR #87](https://github.com/Luminous-Dynamics/nixward/pull/87), [PR #89](https://github.com/Luminous-Dynamics/nixward/pull/89)

## Why this contract exists

A systemd StartUnit response means a start job was enqueued, not that the unit finished starting. systemd's manager API documents a race-free observation order: subscribe to JobRemoved before making the request, retain the returned job object and ID, and filter the signal by that exact job identity. JobRemoved's result is one of done, canceled, timeout, failed, dependency, or skipped.

Nixward must preserve that distinction in typed evidence. It must not turn a successful method reply into a successful job result, a done start job into proof of worker exit, or worker exit into proof of the intended NixOS post-state. Those are independent checkpoints.

Reference: [systemd D-Bus manager interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).

## Implemented in this slice

The module src/action/systemd_job_evidence.rs defines the pure evidence contract. The optional module src/action/systemd_job_bus.rs now provides a live zbus observation path, but it has not been compiled or exercised against a real manager. The contract:

- Derives a template unit name from transaction ID, unique attempt ID, and worker purpose using domain-separated SHA-256 and length-prefixed fields. User-provided IDs never appear directly in the privileged unit name.
- Matches the actual D-Bus signature: an enqueued StartUnit reply contains the job object path, not a separate numeric job ID. The contract validates the canonical path suffix and derives the numeric ID only to cross-check it against the later JobRemoved signal.
- Uses the extended non-serializable typestate chain `StartIntent -> PreparedStartIntent -> SubscribedStart -> SubmittedStart -> PersistedStart`. The pre-launch persistence callback must succeed before the adapter accepts the intent; signal subscription must succeed before StartUnit; the direct manager reply must pass a separate persistence callback before the stream can be consumed.
- Retains the signal stream alongside the submitted ticket, so the subscription is not dropped between StartUnit and JobRemoved observation.
- The persistence callback is a caller-owned contract, not a proof of durability. The journal implementation must actually provide the intended no-clobber and fsync/parent-directory durability guarantees. Persisted or externally supplied evidence still needs integrity, identity and authorization validation.
- Correlates JobRemoved using the exact returned object path and expected canonical unit name, and holds if the signal's numeric job ID disagrees with the ID encoded in its object path.
- Ignores an unrelated job only when its job ID, object path, and unit name are all foreign to the expected job; any conflict sharing one of those identifiers requires reconciliation.
- Maps only JobRemoved done to MatchedStartJobCompleted. Every other known result is explicitly non-success.
- Treats a lost StartUnit reply as indeterminate even if a signal is later presented without an authenticated exact acknowledgement.

The new module is exported from src/action/mod.rs and includes unit tests for canonical identity binding, each non-done manager result, exact signal correlation, unrelated signals, conflicting job identity, malformed paths, lost replies, and failed subscription transitions, and reply recording only from the transient subscribed capability.

## Deliberate limits

The live adapter is authored but not qualified. Typestate makes the intended in-process order explicit, but cannot prove that the callback really persisted the journal record or that a future journal implementation is crash-durable. Live manager tests must confirm match registration, Manager.Subscribe(), the actual StartUnit signature and JobRemoved order. The adapter observes only manager job lifecycle; it does not launch or authorize the privileged worker, write transaction journal records by itself, verify cryptographic provenance, or prove host state.

The existing temporal trace contract in PR #88 and cross-language fixture gate in PR #89 remain separate. The StartUnit method reply is modeled as its actual returned object path only; the numeric job ID appears in JobRemoved's signal tuple (signature `uoss`) and is checked against the canonical job path. See the [systemd manager API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) and [systemd's current JobRemoved emission](https://github.com/systemd/systemd/blob/main/src/core/dbus-job.c). This model must eventually feed a provenance-bound event recorder; it must not replace process identity, the output-free process receipt, or fresh read-only profile/runtime observation.

## Qualification plan

The production integration should use a disposable NixOS VM and a controlled harmless transient unit. It must capture the exact source revision, Nixpkgs revision, systemd version, VM configuration digest, test vector digest, and per-trial outcome. It must exercise at least:

| Fault or behavior | Required outcome |
|---|---|
| Signal subscription is established before the request | Matching job can be correlated by returned ID and object path |
| An unrelated JobRemoved arrives first | Ignore it and continue waiting for the exact job |
| StartUnit succeeds but the response is deliberately dropped | Hold and reconcile the canonical unit; do not resubmit the same attempt |
| StartUnit returns an explicit D-Bus error | Record the manager rejection; do not call it transaction success |
| JobRemoved is done | Record only start-job completion; await worker/process/post-state evidence |
| JobRemoved is canceled, timeout, failed, dependency, or skipped | Non-success result; no terminal transaction claim |
| Numeric JobRemoved ID conflicts with the ID encoded in its object path | Hold for reconciliation |\n| Correct object path with conflicting unit, or a foreign path claiming the expected unit | Hold for reconciliation |
| Supervisor process dies before/after request | Restart must inspect durable intent and existing unit identity before any new request |
| Host reboots during an attempt | Treat boot-scoped process identity as stale; independently observe current runtime and profile |

Hard gates: zero false-success claims; zero same-attempt replay after an ambiguous start reply; zero acceptance of foreign job ID/path/unit evidence; every unresolved or contradictory case remains blocked pending reconciliation. Report timing distributions for subscription, start request, matching signal, and post-state observation separately; do not trade these safety gates against latency.

## Industry comparison

Compare with other declarative deployment managers on identical disposable-VM scenarios. A meaningful result is not the number of trace vectors or the number of retries: it is the rate of false-success, duplicate mutation, unresolved-but-safely-blocked trials, evidence completeness, recovery correctness, and operator intervention. Safety-critical outcomes are gates; latency and throughput are only optimized after those gates hold.

Suggested baselines include direct systemd service management and established NixOS deployment tools such as [Colmena](https://github.com/zhaofengli/colmena). Do not claim superiority until the same fault corpus has been run against both and independently checked.

## Execution status

The deterministic/property tests and adapter unit test are authored but have not been compiled or run here. No Rust test, formatter, Clippy, live D-Bus test, Nix evaluation, or NixOS VM test is claimed. The next step is a `testers.runNixOSTest` fixture that exercises the optional adapter against a real systemd manager, including lost replies and supervisor interruption.
