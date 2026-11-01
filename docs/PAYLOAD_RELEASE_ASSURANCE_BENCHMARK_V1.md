# Payload-release assurance benchmark corpus v1

Status: **27 machine-readable scenarios, proposed and not executed**

## What it qualifies

This corpus measures the schema-v4 release protocol as a local transaction-assurance layer: exact authorization binding, policy/barrier serialization, at-most-once attempt reservation, immutable receipt recovery, uncertainty handling, and WAL/checkpoint overhead.

The benchmark deliberately separates the local SQLite barrier from system build/closure transfer/NixOS activation and from fleet scheduling. It is not a contest to replace the deployment orchestrator.

## Baseline roles

- **SQLite FULL control** isolates the cost of a prepared durable write/read-back on the same device and database settings.
- **Nixward admission-only** measures the earlier atomic-admission layer without the policy archive/release barrier. It must be rebuilt at the same compiler, storage and device settings.
- **Nixward release v4** is the candidate.
- **NixOS rebuild** remains the native activation baseline; compare switch, test and boot separately.
- **Colmena** is a fleet scheduler. It should be measured for closure deployment/activation throughput with exact `--limit`, evaluator settings and hardware, not mislabelled as a same-host transaction-barrier baseline.
- **deploy-rs** is a remote profile deployment tool with magicRollback availability confirmation. Record its exact autoRollback/magicRollback settings; connectivity rollback is not equivalent to the Nixward durable worker receipt.
- **SQLite WAL NORMAL** is an intentionally non-durable performance diagnostic only. It must never win a safety or durability comparison and must never be used as a release configuration.

in-toto and SLSA should be interoperability targets for artifact/build evidence, not treated as local deployment-barrier competitors. Nixward should consume verifiable build/source provenance as inputs, then append its own local admission, policy, release and post-state evidence. SLSA 1.2 explicitly separates source and build tracks; in-toto's layout/functionary/link model provides a useful pattern for authorized steps and signed evidence.

## Trial floors and report format

Clean baselines: at least 30 trials. Fault, concurrency and durability: at least 100 trials per scenario. Do not make a p99 claim with fewer than 1,000 samples. Preserve every raw trial, excluded trial and exclusion reason, fault seed, source SHA, flake.lock, kernel/SQLite versions, filesystem, mount options, device model/firmware, WAL/checkpoint settings and monotonic timestamps.

Always separate writer-lock wait, barrier commit, attempt reservation, policy advance, WAL checkpoint and worker/activation time. Report p50/p95/p99/max; include throughput windows, uncertainty rate and operator-reconciliation rate. Do not count a safe hold as successful deployment or recovery.

## Engineering targets (aspirational, not results)

On a disclosed local PCIe NVMe reference profile with WAL + synchronous=FULL:

| Metric | Initial target |
|---|---:|
| Barrier commit p95 / p99 | ≤20 ms / ≤50 ms |
| Attempt reservation p95 / p99 | ≤20 ms / ≤50 ms |
| Combined barrier + attempt p95 / p99 | ≤40 ms / ≤100 ms |

These are engineering targets to test, not claims. Revisit them only with a published distribution and hardware profile. Do not weaken synchronous=FULL, provenance validation, unique constraints, or read-back to meet them.

Hard correctness targets are absolute: zero unauthorized barriers accepted, zero duplicate attempts, zero stop-to-preserve downgrades, zero resolutions without exact receipts, and zero lost acknowledged commits on supported power-cut test profiles. If any occurs, the benchmark fails regardless of latency.

## Paradigm shift: proof-carrying deployment

Every trial must include the exact local policy-epoch archive, including original policy JSON bytes, update-provenance bytes, emergency revocations, and the chained record digests. This makes key/action/audience snapshots independently re-derived rather than accepted from the benchmark runner. The archive is still unsigned evidence at this stage; source authenticity is a separate gate.

The desired architecture is not another command runner. It is an independently verifiable evidence chain:
`source/build provenance -> exact closure digest -> owner authority receipt -> current policy epoch -> atomic admission -> immutable release barrier -> one-shot attempt -> PIDFD/InvocationID-bound worker receipt -> NixOS switch/test/boot post-state -> independent resolution`.

This composes with (rather than replaces) NixOS, Colmena and deploy-rs. The potential field-level contribution is an interoperable local transaction-assurance layer with explicit linearization, evidence ceilings and honest uncertain-delivery semantics.

## Safety limits

- A successful SQLite FULL commit does not make the external payload write atomic.
- Attempt-without-receipt is ambiguous and cannot be auto-retried.
- A local hash chain does not protect against root compromise or whole-disk rollback.
- No test corpus, schema replay or benchmark runner is a live VM/power-loss qualification.
