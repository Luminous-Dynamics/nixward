# Strict detached-authority wire decoding v1

Status: **wire-format hardening; no supervisor service or admission integration is implemented**

The existing authority implementation already provides the right capability boundary:

- \`DetachedAuthoritySignature\`, \`AuthorityChallenge\`, \`AuthorityTrustPolicy\`, and \`TrustedAuthorityKey\` are untrusted deserializable input records.
- \`AuthorityVerifier\` independently checks the Ed25519 signature, signer membership, revocation, action allowlist, local Holon binding, audience, subject, TTL, and freshness.
- \`VerifiedSignatureEvidence\` has no Serialize or Deserialize implementation. It can only be produced by successful verifier execution.
- \`ChangeAuthorization\` and \`ExecutionAuthorization\` intentionally do not derive Deserialize.

This change adds \`serde(deny_unknown_fields)\` to the four untrusted wire/config types. The versioned protocol now rejects unknown envelope, challenge, trust-policy and signer-key fields instead of silently discarding them.

The root supervisor integration must:
1. Read the trust policy from a root-owned, locally configured source; never accept a caller-selected trust policy.
2. Deserialize the original detached signature under strict field rules.
3. Derive the expected ChangePlan subject and local Holon/machine identity itself.
4. Use the supervisor's current clock for freshness.
5. Call the existing \`verify_general_change_authority\` or \`verify_execution_intent_change_authority\` path and retain the non-deserializable verified result.
6. Bind the resulting policy digest, signer, challenge, subject, replay key, action, audience and expiry into the supervisor permit/admission record.
7. Consume the one-shot replay key in the same atomic admission commit; never deserialize a \`ChangeAuthorization\` or \`ExecutionAuthorization\` from journal JSON.

A future protocol extension must increment the authority schema version and update the signature/canonicalization rules deliberately. Adding a new field without changing the version is not a compatibility strategy.

## Verification scope

The added tests are unit-level deserialization negative controls. They do not test filesystem trust-policy ownership, root supervisor IPC, permit signing, replay-store integration or systemd submission. No build or test run is claimed in this authoring environment.
