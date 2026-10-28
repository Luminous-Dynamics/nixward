# System Transaction Wire Contract v1

Schema identifier: luminous-nixward-system-transaction-v1
Version: 1

This is the stable serialized boundary for consequential Nixward system changes.
It wraps the existing ChangePlan and ChangeAuthorization identities. It does not
replace cryptographic authorization, introduce a second signer model, or grant
execution capability.

## Privacy boundary

The wire envelope is digest-addressed and must not contain passwords, LUKS
passphrases, private keys, bearer tokens, raw secret material, or raw full
filesystem snapshots. State, configuration, recovery material, and attestation
payloads should be referenced by cryptographic digests or separately authorized
content locations.

## Lifecycle

planned -> validated -> authorized -> snapshotted -> applied -> verified -> promoted

Failure may terminate at failed, followed by bounded recovered when a valid
recovery binding exists. Promotion is forbidden when boot-health evidence is false.

## Identity

transaction_id is derived from the exact ChangePlan digest and ChangePlan nonce.
target_machine_digest binds the transaction to the ChangePlan machine binding.
plan_digest is the digest of the exact ChangePlan.
These fields identify the transaction; they do not grant authority by themselves.

## Evidence

The envelope may carry authorization evidence identity and expiry; validation
evidence; pre-state and recovery binding digests; the exact command digest plus
timing and process result; post-state and verification evidence; and optional
boot-health observation.

An evidence digest proves identity of an evidence record. It does not by itself
assert that the evidence is trustworthy; verification and authority policy remain
separate concerns.

## State-machine invariants

Consumer state transitions are ordered as planned -> validated -> authorized ->
snapshotted -> applied -> verified -> promoted.

A consumer must reject unsupported schema/version, plan or target mismatches,
validation after authorization, snapshot without authorization plus validation,
application without authorization/validation/snapshot, command-digest mismatches,
verification before successful application, promotion before verification, unhealthy
promotion, and recovery without snapshot/recovery evidence.

A transaction is terminal only in promoted, recovered, or failed.

## Receipt/phase consistency (normative)

A syntactically valid envelope is not necessarily a valid lifecycle history. Consumers must validate the receipt set against the declared phase and reject inconsistent combinations before they use the envelope to drive another transition.

- `planned`: no validation, authorization, snapshot, application, verification, or outcome receipt.
- `validated`: validation receipt only.
- `authorized`: validation and authorization receipts.
- `snapshotted`: validation, authorization, and snapshot receipts.
- `applied`: the preceding receipts plus an application receipt whose exit status is zero; no verification or outcome receipt yet.
- `verified`: the applied receipts plus verification; no terminal outcome yet.
- `promoted`: verified receipts plus a promoted outcome that has no failure reason.
- `failed`: the validated/authorized/snapshotted receipts plus a nonzero application exit status, no verification receipt, and a failed outcome with a non-empty reason.
- `recovered`: the validated/authorized/snapshotted receipts plus a recovered outcome with a non-empty reason. If application exited zero, verification must be present; if application exited nonzero, verification must be absent.

For terminal phases, `outcome.phase` must equal the envelope's `phase`. Nonterminal phases must not carry a terminal outcome. These checks establish internal lifecycle consistency only: digest syntax and phase consistency do not establish that the evidence is truthful or that the post-state digest satisfies the desired-state contract.

The library's transition methods validate the incoming envelope before advancing it, so callers cannot use a manually edited public `phase` field to bypass lifecycle prerequisites. This tightens acceptance of malformed v1 envelopes without changing their serialized field layout.

## Provenance boundary

This envelope is operational lifecycle evidence, not a replacement for build
provenance. When software/build provenance is available, reference in-toto/SLSA
evidence by digest. SLSA describes how artifacts were produced; this transaction
records whether a particular target was authorized, changed, verified, and
promoted. Keeping those subjects separate prevents provenance from being confused
with owner authority.