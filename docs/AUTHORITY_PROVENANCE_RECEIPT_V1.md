# Authority provenance receipt v1

Status: **typed verifier receipt and provenance record implemented; no privileged supervisor integration is enabled**

## Security model

Nixward distinguishes three objects:

1. `DetachedAuthoritySignature` is untrusted input and remains deserializable under strict unknown-field rejection.
2. `VerifiedAuthorityReceipt` is a runtime-only capability. Its fields are private and it has no `Serialize` or `Deserialize` implementation. Only successful `AuthorityVerifier` execution can create it.
3. `AuthorityProvenanceRecord` is durable audit data. It is serializable and deserializable by design, so a copy recovered from a journal is untrusted until independently re-verified.

This is not a second signature protocol. It reuses the existing Ed25519 challenge, policy, subject, audience, Holon binding, freshness, signer-revocation and action checks.

## Required bindings

A provenance record retains policy ID, digest and non-zero policy epoch; signer key ID and issuer; action, audience, exact subject and Holon identity; challenge digest and replay key; parsed signature-evidence digest; domain-separated digest of the exact input proof bytes and those bytes themselves; challenge issuance/expiry; and verifier timestamp.

The raw JSON byte path is `AuthorityVerifier::verify_json` and the Nixward wrappers `verify_general_change_authority_json` / `verify_execution_intent_change_authority_json`. Typed compatibility wrappers serialize an already-decoded DTO and cannot preserve its original wire whitespace or representation. Use byte-oriented functions at an ingress boundary.

The local `policy_epoch` is optional in a legacy policy so read-only verification can continue. It is mandatory and non-zero before a durable receipt can be minted. It must come from a monotonic root-managed policy source, not caller input or signer claims. The epoch is included in the trust-policy digest.

## Restart and release semantics

A deserialized `AuthorityProvenanceRecord` is not a capability. First run its integrity checks, then load the exact archived policy identified by policy ID/digest/epoch and call `reverify_historical_provenance`. Historical re-verification uses the original verifier timestamp; it does not treat historical validity as current release permission.

Immediately before payload release, call `VerifiedAuthorityReceipt::validate_release_at` with the current machine-local policy epoch, emergency-revocation set, and current clock. It fails closed on policy-epoch drift, signer revocation or expiry. This deliberately requires fresh authorization after a policy change unless a future, separately reviewed policy explicitly supports safe permit migration.

After payload release, the admission record remains a historical fact. Any stop, compensation or recovery operation requires a separate authority policy; a policy update must not rewrite the old verification record.

## Negative controls added

- missing policy epoch: receipt creation rejected;
- exact raw proof bytes survive receipt -> durable record -> re-verification;
- tampered raw proof bytes rejected by integrity validation;
- historical re-verification requires the matching policy digest and epoch;
- policy epoch drift blocks release;
- emergency revocation blocks release;
- expired proof blocks release.

## Qualification boundary

The receipt does not itself consume replay state or commit an admission permit. Those must be written in the same authoritative atomic transaction described by supervisor-admission work. The root supervisor must load the trust policy and epoch from a root-owned source, derive the expected plan and local machine/Holon binding itself, and never accept a client-supplied policy.

No D-Bus, polkit, systemd StartUnit, worker execution, root daemon or production permit release is enabled here.

No compile, unit-test, VM, crash or CI result is claimed in this authoring environment.
