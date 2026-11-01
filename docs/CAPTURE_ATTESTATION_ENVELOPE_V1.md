# Authenticated capture evidence v1 — design and schemas

Status: **design contract and machine-readable schemas; no signature or TPM verification is implemented by this change**

## Why a second trust layer is needed

The raw-trial verifier in PR #140 establishes consistency and integrity: the event stream, source manifest, SQLite snapshot and artifacts must agree. It cannot establish who produced those bytes. A host or runner that fabricates both the log and database snapshot can still produce a self-consistent false trial.

This layer authenticates the capture claim independently of deployment authority:

`artifact hashes -> in-toto Statement -> DSSE signature -> out-of-band capture trust policy -> one-use challenge/use receipt -> optional TPM quote and remote freshness witness`.

The owner authority signature continues to authorize a deployment. The capture signature says who attested to evidence collection. **Neither is interchangeable with the other.**

The in-toto Statement v1 separates subjects, predicate type and predicate. The DSSE envelope authenticates the exact payload type and payload bytes using pre-authentication encoding (PAE). This design uses those standard layers rather than inventing a Nixward-only signed JSON format.

## 1. DSSE envelope

`capture-dsse-envelope-v1.schema.json` defines:

- `payloadType` = `application/vnd.in-toto+json`;
- `payload` = base64-encoded exact UTF-8 bytes of an in-toto Statement v1;
- one or more `signatures` with optional `keyid` hints and base64 signatures.

Verify the DSSE PAE exactly:

```text
PAE(payloadType, payload) =
  "DSSEv1 " || len(UTF8(payloadType)) || " " || payloadType ||
  " " || len(payload) || " " || payload
```

Lengths are decimal byte lengths, not Unicode character counts. Ed25519 signatures cover the PAE bytes. Do not parse and reserialize the payload before verifying; preserve and verify the exact byte string from the envelope. A signature's `keyid` is an unauthenticated lookup hint, not a trust anchor. The verifier must select keys from its locally pinned capture policy and verify the signature cryptographically.

## 2. in-toto Statement and Nixward capture predicate

The Statement's subject set must bind exact SHA-256 digests for:

- corpus JSON;
- trial manifest;
- canonical event stream;
- raw SQLite snapshot;
- supervisor log;
- source manifest;
- flake.lock bytes;
- optional TPM event log.

The custom predicate URI is `https://luminousdynamics.io/attestations/nixward/capture/v1`. It binds the trial/scenario/run IDs, challenge ID and nonce, source/flake/corpus digests, kernel boot ID, kernel/systemd/SQLite/Nix versions, filesystem/mount/device metadata, capture-agent binary digest, monotonic and wall-clock bounds, clock source and declared uncertainty.

The predicate also states the capture assurance class:

- `software_only`: a configured capture key signed the evidence. This does **not** prove the host or capture process was uncompromised.
- `tpm2_quote`: declares quote bytes, AIK chain, PCR selection/values and event-log digest. This mode is not considered verified until a qualified TPM adapter validates the quote signature, nonce, AK trust chain and event-log replay against policy reference values.

Unknown machine-attestation modes fail closed. No software-only result may be promoted to hardware-attested.

## 3. Capture trust policy is out of band

`capture-trust-policy-v1.schema.json` is an administrator-managed trust-root file. It must be installed or pinned independently of the trial artifact directory (for example, by a Nix store path and configuration-management revision). Never accept a trust policy packaged inside the evidence bundle.

Capture keys have separate identity, issuer, key ID, public key, validity interval, revocation state and allowed machine/scenario scopes. A threshold is explicit. A key ID only narrows lookup; the signature must verify against a key in this out-of-band policy. Revoked, expired, out-of-scope, duplicate or unknown signers do not count toward the threshold. Key rotation requires an explicit policy epoch/revision and a retained old-key revocation record.

The owner-deployment authority's Ed25519 keys must not be reused as capture keys. A capture signature cannot authorize a change, and a deployment permit cannot authenticate evidence collection.

## 4. One-use challenges and freshness

A separately trusted coordinator issues a random nonce challenge bound to:

- unique challenge ID and nonce;
- exact corpus digest, source commit and flake.lock digest;
- allowed scenario IDs and capture-key scope;
- issue and expiry times.

The challenge is signed by the coordinator key pinned in the capture trust policy. The capture predicate must echo the exact challenge ID, nonce and bindings. Expired, mismatched or replayed nonces are rejected.

After capture, the coordinator returns a signed **nonce-use receipt** binding the challenge ID/nonce digest to the exact DSSE envelope digest, trial ID, capture signer and consumption time. The coordinator must enforce one-use semantics in its own persistent service-side ledger. A local verifier may detect duplicate challenge IDs within one report, but a local file alone cannot prove global non-replay or prevent whole-disk rollback.

A remote timestamp/transparency witness is a separate field and verification result. Do not substitute the host wall clock for an external freshness witness.

## 5. TPM 2.0 extension

The optional hardware-attestation adapter must verify:

1. AIK certificate chain and key usage against independently provisioned TPM manufacturer/endorsement trust;
2. quote signature over the selected PCR composite;
3. exact verifier nonce in the quote's qualifying data;
4. PCR selection and values against the signed capture predicate;
5. event-log digest, parsing, replay and final PCR values;
6. configured reference values and boot policy.

TPM quotes and event logs can provide evidence about measured boot, but do not automatically prove arbitrary runtime log statements. A compromised process may still lie unless the capture agent and its signing key are isolated and the measurement policy covers them. TPM mode is a declaration until this complete verification path exists.

## 6. Report semantics

The eventual report must keep these results separate:

- `integrity_verified`: hashes, schemas, DB state and event replay are internally consistent;
- `capture_signature_verified`: the DSSE signatures meet the pinned capture-key policy;
- `machine_attestation_verified`: the TPM/other protected-machine evidence was fully validated;
- `freshness_witness_verified`: the coordinator's nonce-use receipt or external witness was verified.

Expected classifications:

| Evidence | Integrity | Capture signature | Machine attestation | Freshness |
|---|---|---|---|---|
| Hashes only | true | false | false | false |
| Signed software-only capture + consumed nonce | true | true | false | true |
| Signed capture + validated TPM quote + consumed nonce | true | true | true | true |

A valid software-only signature must never be described as a hardware-attested machine. A capture signature must never override an unsafe event sequence or invalid SQLite snapshot.

## 7. Phased implementation gates

- **Phase A (this change):** DSSE, Statement/predicate, trust-policy, challenge and nonce-receipt schemas; exact PAE test vector; positive/negative fixtures; threat model.
- **Phase B:** Rust-native DSSE PAE/signature validation against out-of-band trust policy; signature threshold, signer scope, validity, rotation and revocation tests; separate result fields.
- **Phase C:** coordinator challenge issuance and single-use consumption receipts, remote transparency/timestamp integration and replay tests.
- **Phase D:** TPM adapter using a reviewed TPM 2.0 implementation, certificate-chain validation, quote verification, event-log replay and reference-value policy. Until Phase D passes, TPM claims remain unsupported and fail closed.

## Standards references

- DSSE protocol: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- in-toto Attestation Framework: https://github.com/in-toto/attestation
- in-toto Statement v1: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- TPM remote attestation model: https://www.rfc-editor.org/rfc/rfc9683.html

This design does not claim that any current trial is authenticated. PR #140 remains an integrity verifier until Phase B/C are implemented and its report reflects the separate results above.
