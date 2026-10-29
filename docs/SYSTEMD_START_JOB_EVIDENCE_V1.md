# Systemd start-job evidence contract v1

Status: **pure Rust contract; no D-Bus client or privileged worker is implemented by this slice**  
Date: 2026-10-29  
Related: [Issue #75](https://github.com/Luminous-Dynamics/nixward/issues/75), [PR #87](https://github.com/Luminous-Dynamics/nixward/pull/87), [PR #89](https://github.com/Luminous-Dynamics/nixward/pull/89)

## Why this contract exists

A systemd StartUnit response means a start job was enqueued, not that the unit finished starting. systemd's manager API documents a race-free observation order: subscribe to JobRemoved before making the request, retain the returned job object and ID, and filter the signal by that exact job identity. JobRemoved's result is one of done, canceled, timeout, failed, dependency, or skipped.

Nixward must preserve that distinction in typed evidence. It must not turn a successful method reply into a successful job result, a done start job into proof of worker exit, or worker exit into proof of the intended NixOS post-state. Those are independent checkpoints.

Reference: [systemd D-Bus manager interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).

## Implemented in this slice

The new module, src/action/systemd_job_evidence.rs, introduces a pure correlation contract:

- Derives a template unit name from transaction ID, unique attempt ID, and worker purpose using domain-separated SHA-256 and length-prefixed fields. User-provided IDs never appear directly in the privileged unit name.
- Represents manager reply states separately: enqueued with exact job ID and object path, known rejection, or unknown/lost reply.
- Uses a non-serializable `StartIntent -> SubscribedStart` typestate transition. The crate-internal transition awaits a subscription closure and only yields `SubscribedStart` if that closure succeeds; its constructor is not exposed to downstream crates.
- Allows `SubscribedStart::record_reply` to create the durable `SystemdStartEvidence` record only after the transient capability exists. The record itself remains data, not authority: persisted or externally supplied evidence still needs provenance validation at the adapter/journal boundary.
- Correlates a JobRemoved event only when job ID, object path, and canonical unit name agree.
- Ignores an unrelated job only when its job ID, object path, and unit name are all foreign to the expected job; any conflict sharing one of those identifiers requires reconciliation.
- Maps only JobRemoved done to MatchedStartJobCompleted. Every other known result is explicitly non-success.
- Treats a lost StartUnit reply as indeterminate even if a signal is later presented without an authenticated exact acknowledgement.

The new module is exported from src/action/mod.rs and includes unit tests for canonical identity binding, each non-done manager result, exact signal correlation, unrelated signals, conflicting job identity, malformed paths, lost replies, and failed subscription transitions, and reply recording only from the transient subscribed capability.

## Deliberate limits

This is an executable contract, not a D-Bus adapter. The typestate seam makes the intended in-process order explicit, but it cannot authenticate a serialized record or prove that a future adapter's subscription closure actually registered the correct systemd signal match and called Manager.Subscribe(). That must be checked in the real adapter and live manager tests. The module neither launches nor authorizes a worker, writes transaction journals, verifies cryptographic provenance, nor proves host state.

The existing temporal trace contract in PR #88 and cross-language fixture gate in PR #89 remain separate. This model must eventually feed a provenance-bound event recorder; it must not replace process identity, the output-free process receipt, or fresh read-only profile/runtime observation.

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
| Correct ID with conflicting path/unit or vice versa | Hold for reconciliation |
| Supervisor process dies before/after request | Restart must inspect durable intent and existing unit identity before any new request |
| Host reboots during an attempt | Treat boot-scoped process identity as stale; independently observe current runtime and profile |

Hard gates: zero false-success claims; zero same-attempt replay after an ambiguous start reply; zero acceptance of foreign job ID/path/unit evidence; every unresolved or contradictory case remains blocked pending reconciliation. Report timing distributions for subscription, start request, matching signal, and post-state observation separately; do not trade these safety gates against latency.

## Industry comparison

Compare with other declarative deployment managers on identical disposable-VM scenarios. A meaningful result is not the number of trace vectors or the number of retries: it is the rate of false-success, duplicate mutation, unresolved-but-safely-blocked trials, evidence completeness, recovery correctness, and operator intervention. Safety-critical outcomes are gates; latency and throughput are only optimized after those gates hold.

Suggested baselines include direct systemd service management and established NixOS deployment tools such as [Colmena](https://github.com/zhaofengli/colmena). Do not claim superiority until the same fault corpus has been run against both and independently checked.

## Execution status

The unit and property tests are authored but have not been compiled or run in this environment. Two Tokio-gated tests exercise the subscription typestate seam when the `native` feature is enabled; they do not prove live D-Bus behavior. No D-Bus test, NixOS VM test, Rust test, formatter, or Clippy pass is claimed. The next implementation step is a typed D-Bus adapter and a `testers.runNixOSTest` fixture that exercises it against a real systemd manager.
