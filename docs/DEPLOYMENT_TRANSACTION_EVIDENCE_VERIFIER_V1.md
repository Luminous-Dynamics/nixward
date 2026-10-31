# Deployment transaction evidence verifier v1

Status: **read-only artifact-integrity verifier; not a deployment runner or semantic verifier**

Build and run:

```sh
cargo run --release --bin nixward-benchmark-verify -- \
  --corpus docs/fixtures/deployment-transaction-benchmark-corpus-v1.json \
  --records results/trials.json \
  --artifact-root results/raw
```

Use `--require-complete` to return exit code 3 while an available baseline/scenario has fewer than the corpus-defined minimum trials. Invalid records return 2. A valid but incomplete set returns 0 by default with status `integrity-valid-incomplete`; a complete available-baseline set returns 0 with status `integrity-valid-minimum-trials-met`. A gated systemd baseline is rejected unless `--allow-gated` is explicitly supplied. Opt-in records remain classified as gated and never become available baselines.

## Trial contract

Each trial is one JSON object in a `--records` JSON array following `deployment-transaction-trial-v1.schema.json`. It binds the exact raw corpus SHA-256, scenario and baseline IDs, trial index and seed, all corpus-required evidence fields, matched-environment fingerprint, declared observation labels, strictly increasing monotonic phase timestamps, safety counters, terminal classification, a raw artifact manifest and canonical `record_sha256`.

Artifact paths are relative to `--artifact-root`. Absolute paths, traversal components and symlinks are rejected. The verifier reads bytes and recomputes SHA-256 and byte length. The record digest is SHA-256 of `serde_json::to_vec` over the JSON object with `record_sha256` removed; serde_json's default map representation serializes object keys deterministically. For evidence that does not apply, use a reason such as `not-applicable: systemd is not used by this baseline`; bare `n/a` and empty reasons are rejected. The raw-record digest field must be `verifier-derived` because the verifier computes it.

Available-baseline records with the same scenario and trial index must share the same trial seed and environment fingerprint. Prototype-only baselines remain separately classified and are not promoted to industry comparisons. Gated baselines require explicit exploratory opt-in and remain gated.

## Critical trust boundary

A passing result means only that the records are pinned to this exact corpus and that their referenced bytes match declared hashes. It does **not** prove:
- the trial ran on the claimed host, VM, kernel, systemd manager or profile;
- runner-declared safety counters or observation labels are truthful;
- a command caused the observed state;
- who produced the record (a record hash is not a digital signature);
- recovery, rollback, at-most-once submission or activation semantics are correct;
- that Nixward is faster, safer, or better than any industry baseline.

A later semantic verifier must parse the raw manager events, process receipts, journals, Nix profile links, runtime observations and fault-injection witnesses independently and derive terminal outcomes itself. This tool never executes deployment commands and never mutates a host.
