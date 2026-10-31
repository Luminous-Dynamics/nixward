# Independent payload-release trial verifier v1

Status: **read-only Rust verifier and input schema authored; tests and runtime use are not yet qualified**

## CLI

```sh
nixward-payload-release-benchmark-verify \
  --corpus docs/fixtures/payload-release-assurance-benchmark-v1.json \
  --manifest trials/manifest.json \
  --artifacts-root trials/artifacts \
  --output trials/verification-report.json
```

Exit status:
- `0`: structurally valid trial set and every scenario has its minimum number of trials.
- `10`: one or more trials violate an invariant or scenario expectation.
- `20`: no unsafe trial was found, but at least one scenario is below its sample floor.
- `2`: malformed input, unsupported schema, missing artifact, bad digest, path escape or other verifier input error.

The JSON report independently gives each trial a `valid` flag, scenario expectation result and violation list. Dataset completeness is separate from safety. A clean but under-sampled set is incomplete, not a pass.

## Input binding

The manifest binds the exact corpus SHA-256, source commit SHA and flake.lock SHA-256, plus kernel boot ID, kernel, systemd, SQLite, Nix, filesystem/mount and device metadata. Each trial carries its own initial policy ID, epoch, policy digest and policy-record digest.

Event sequences are typed and ordered. The verifier requires contiguous sequence numbers and nondecreasing monotonic timestamps bounded by the trial interval. Expiry uses separate UTC epoch milliseconds captured at barrier/attempt operations; it is never compared to monotonic nanoseconds. Historical read-only barrier retries may be retrieved after expiry, but new barrier commits and external attempts may not occur after expiry. `events_sha256` is SHA-256 over the exact compact JSON bytes produced by serializing the typed event array with the same schema field order. Producers must use the published schema and byte contract; do not hash a pretty-printed alternative.

Each artifact receipt is relative to the artifact root, includes an artifact kind and SHA-256 over the exact file bytes. Absolute paths, parent traversal and symlink escapes are rejected. Scenarios that require raw evidence must include artifact kinds `raw_sqlite` and `supervisor_log`.

Unknown fields are rejected. There is deliberately no `passed`, `success` or runner-supplied percentile property in the manifest or event schema.

## Independent derivation

The verifier recomputes the release ID using the same NUL-terminated domain separator and length-prefixed field order as the durable store, including transaction, attempt, admission, replay, permit, plan, machine, authority provenance, signer, subject, audience, payload, policy ID/epoch/digests and expiry. It matches a barrier commit to the preceding request and current policy snapshot; checks that retries refer to the exact historic barrier; verifies contiguous policy epochs and decision coverage; rejects stop-to-preserve and emergency-revoked preservation; and ensures the one-shot attempt precedes payload write.

Worker receipts must follow an attempt and match the exact release and payload digest. A late receipt may reconcile an earlier uncertain attempt when the worker-completion timestamp precedes the receipt-persistence timestamp. Resolution without that exact receipt is unsafe. A runner cannot make an invalid sequence valid by supplying a positive summary.

Artifacts are hash-checked, not authenticated. The verifier does not prove that a log was produced by the claimed machine; capture provenance and signature verification belong to a separately trusted evidence-ingress layer. The verifier itself makes no D-Bus calls, executes no shell command and changes no host state.

## Statistics

Percentiles use nearest-rank: one-based rank (\lceil p \cdot n \rceil). p50 is shown from one sample, p95 is suppressed below 30 samples, and p99 is suppressed below the corpus threshold (1,000 by default). Reported p99 claims are gated per scenario sample count, not by the total number of unrelated trials.

Latency is derived only from matching request and commit events. The report separately summarizes barrier creation, attempt reservation, policy advancement, checkpoint duration and writer-lock wait. It does not mix those with Nix build, closure transfer, system activation or fleet scheduling times.

## Test status

The binary contains deterministic negative controls for duplicate release attempts, payload write before attempt reservation, resolution before receipt, uncertainty followed by a late receipt, emergency-revoked signer preservation, percentile suppression, path traversal and unknown runner-summary fields. Cargo tests and the Nix test target are authored but not executed in this environment.
