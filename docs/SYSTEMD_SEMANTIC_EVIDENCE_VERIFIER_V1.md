# Executable systemd/NixOS semantic evidence verifier v1

Status: **pure Rust semantic evaluator and CLI authored; host-evidence authenticity is not established**

## Build and run

```sh
cargo run --release --no-default-features --bin nixward-systemd-evidence-verify -- \
  --input evidence/systemd-execution.json
```

Exit codes: 0 verified success; 10 verified recovery; 20 reconciliation required; 30 safe hold; 2 malformed input or usage error. The JSON report includes the outcome and reasons.

## Derived checks

The pure library function `nixward::systemd_evidence::verify_execution` checks authority-provenance structural binding, transaction identities across worker/receipt/host observations, admission-before-subscription-before-StartUnit ordering, exact returned job-path correlation, unique JobNew/JobRemoved with consistent job ID/unit/manager boot, PIDFD-derived unit attribution, InvocationID and process-start tuple, durable identity persistence before payload release, final unit state and independent operation-specific host postconditions.

v1 supports only switch, test and boot. Expected running/profile semantics:

| Mode | Active profile / boot default | Running system |
|---|---|---|
| switch | candidate | candidate |
| test | predecessor | candidate |
| boot | candidate | predecessor |

Worker units are deliberately limited to `Type=oneshot`: successful execution requires inactive/dead, Result=success and exit status zero. Other service types need a separately versioned contract; they are not silently accepted.

## Outcomes

- `verified_success`: exact manager job, PIDFD worker, durable receipt, oneshot result and operation-specific NixOS post-state agree.
- `verified_recovery`: execution did not qualify as success, but predecessor profile/running system/boot default and runtime health are independently observed.
- `reconciliation_required`: evidence is missing or ambiguous.
- `safe_hold`: identity, ordering, event or post-state contradictions violate an invariant.

Safe hold/reconciliation are never successful deployment. JobRemoved=done alone is insufficient.

## Trust boundary

This is a semantic consistency evaluator, not a signature verifier or trusted capture agent. It does not verify Ed25519 signatures, authenticate D-Bus peer credentials, open pidfds, inspect a live host or prove who supplied observations. The eventual capture/supervisor layer must call systemd Manager.GetUnitByPIDFD, validate admission/provenance and current policy epoch before release, and collect host observations over trusted channels. The raw records and source digests are still untrusted until that layer establishes provenance.

The fixture catalogue lists 23 positive/negative-control cases. Rust unit tests construct complete evidence objects and execute the evaluator. They are model tests, not disposable-VM, power-loss or runtime qualification. No host-mutating command or D-Bus action is included.
