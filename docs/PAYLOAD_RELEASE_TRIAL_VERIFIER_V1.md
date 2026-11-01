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

The manifest binds the exact corpus SHA-256, source commit SHA and flake.lock SHA-256, plus kernel boot ID, kernel, systemd, SQLite, Nix, filesystem/mount and device metadata. Each trial carries its initial policy ID, epoch, policy digest, policy-record digest, per-key revocation/action set, allowed audiences and the separate emergency-revocation set. The report records both corpus and manifest SHA-256.

Event sequences are typed and ordered. The verifier requires contiguous sequence numbers and nondecreasing monotonic timestamps bounded by the trial interval. Expiry uses separate UTC epoch milliseconds captured at barrier/attempt operations; it is never compared to monotonic nanoseconds. Historical read-only barrier retries may be retrieved after expiry, but new barrier commits and external attempts may not occur after expiry. `events_sha256` is SHA-256 over the exact compact JSON bytes produced by serializing the typed event array with the same schema field order. Producers must use the published schema and byte contract; do not hash a pretty-printed alternative.

Each artifact receipt is relative to the artifact root, includes an artifact kind and SHA-256 over the exact file bytes. Artifact content is streamed rather than loaded into the JSON buffer; each artifact is capped at 8 GiB, while corpus/manifest JSON is capped at 64 MiB. Absolute paths, parent traversal and symlink escapes are rejected. Every trial must include exactly one each of `raw_sqlite`, `supervisor_log` and `dsse_source_attestation`.

The `source_manifest` is a compact JSON document with schema `org.luminousdynamics.nixward.source-evidence`, version 1, and the exact `source_commit_sha`, `flake_lock_sha256` and `corpus_sha256` values from the trial manifest. The verifier checks the artifact SHA-256 and then compares all three values. It is an integrity/consistency receipt, not a signature or proof that the claimed binary was built from those inputs. A separate trusted capture/signature layer is still required to authenticate the producer.

The `raw_sqlite` artifact must be a **standalone consistent backup snapshot**, not a byte-copy of a live WAL database. Capture it using SQLite's online backup API into a new database, change the destination journal mode to `DELETE`, close it and hash that exact file. Do not copy only the live main DB while WAL may contain committed pages. The verifier stages the hash-checked artifact into a private temporary file and opens that staged file read-only. It verifies application ID, schema version, journal mode, SQLite `integrity_check`, `foreign_key_check`, and the exact v4 40-object schema inventory. It recomputes the policy epoch hash chain and admission commit IDs, then cross-checks the stored admission/replay/permit/transaction records and all five release-record families against the typed event stream.

The legacy-schema refusal scenario is the only normal scenario that accepts a schema-v3 database snapshot. The two intentional corruption scenarios accept only their specific stored digest mismatch (barrier-record digest or attempt-record digest), paired with the matching integrity-rejection event. Other database inconsistencies make the trial unsafe. Keep the artifact root immutable during verification: path canonicalization plus descriptor-based hashing does not make a concurrently writable artifact tree a trusted capture boundary.

Unknown fields are rejected. There is deliberately no `passed`, `success` or runner-supplied percentile property in the manifest or event schema. Rejection events must identify the canonical operation, request ID and target: barrier creation reuses the barrier-request ID and admission commit ID; policy advancement reuses the policy-request ID and expected policy-record digest; attempt reservation reuses the attempt-request ID and release ID. Receipt, resolution and integrity observations use `ack:<release-id>`, `resolve:<release-id>` and `integrity:<release-id>` request IDs respectively. Legacy schema refusal uses `open-store:<trial-id>` and a target of `schema-v1`, `schema-v2` or `schema-v3`.

## Independent derivation

The verifier recomputes the release ID using the same NUL-terminated domain separator and length-prefixed field order as the durable store, including transaction, attempt, admission, replay, permit, plan, machine, authority provenance, signer, subject, audience, payload, policy ID/epoch/digests and expiry. It verifies that the signer is in the initial per-key policy snapshot, is not revoked, and has the `change` action; it matches a barrier commit to the preceding request and current policy snapshot; checks that retries refer to the exact historic barrier; verifies contiguous policy epochs and decision coverage; rejects stop-to-preserve and emergency-revoked preservation; and ensures the one-shot attempt precedes payload write. Emergency revocation is checked independently from a key's policy-local revoked flag.

Worker receipts must follow an attempt and a completed write of the same payload, and match the exact release and payload digest. A new write-start after uncertainty is rejected; a late receipt may still reconcile the original attempt when the worker-completion timestamp precedes the receipt-persistence timestamp. Resolution without that exact receipt is unsafe. A runner cannot make an invalid sequence valid by supplying a positive summary.

Artifacts are hash-checked, not authenticated. The verifier does not prove that a log was produced by the claimed machine; capture provenance and signature verification belong to a separately trusted evidence-ingress layer. The verifier itself makes no D-Bus calls, executes no shell command and changes no host state. The report includes the exact event-stream digest and the artifact paths, kinds and digests for each trial. A report output must be outside the artifact root, must not alias the corpus or manifest, and must not already exist; the verifier never overwrites source evidence.

## Statistics

Trial floors are fixed by the verifier: 30 clean, 100 fault/concurrency/durability, and 1,000 for p99 claims. Lower values in a supplied corpus are rejected.

Percentiles use nearest-rank: one-based rank (\lceil p \cdot n \rceil). p50 is shown from one sample, p95 is suppressed below 30 samples, and p99 is suppressed below the corpus threshold (1,000 by default). Reported p99 claims are gated per scenario sample count, not by the total number of unrelated trials.

Latency is derived only from matching request and commit events. The report separately summarizes barrier creation, attempt reservation, policy advancement, checkpoint duration and writer-lock wait. The long-reader checkpoint scenario is only accepted when the raw event records active readers, a nonzero oldest-reader age, and WAL frames remaining after the checkpoint pass; merely observing a checkpoint call is not enough. It does not mix those with Nix build, closure transfer, system activation or fleet scheduling times.

## Test status

The binary contains **32 authored deterministic Rust tests** (the symlink escape test is Unix-gated), including negative controls for duplicate release attempts, payload write before reservation, write restart after uncertainty, receipt without completed write, resolution before receipt, uncertainty followed by a late receipt, emergency-revoked signer preservation, stale policy snapshots, percentile suppression, path traversal, outside-root symlink escape, wall-clock rollback, release-ID mutation, wrong-operation/target rejection events, unknown runner-summary fields, streaming artifact hashing, exact source-manifest checks, source-manifest field rejection and raw SQLite schema-v3 classification. Cargo tests and the Nix test target are authored but not executed in this environment.
