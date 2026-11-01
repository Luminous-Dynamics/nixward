# Offline DSSE and in-toto verification v1

Status: **reusable Rust verifier authored; not yet integrated into the trial CLI or host-capture verifier, and not yet compiled/tested in this environment**

## Standards profile

This module implements the DSSE v1 envelope and the in-toto Statement v1 layer. It intentionally does not invent a Nixward-specific signature container.

- Envelope payload type is exactly `application/vnd.in-toto+json`.
- Signature input is DSSE Pre-Authentication Encoding (PAE):
  `DSSEv1 SP LEN(type) SP type SP LEN(payload) SP payload`.
- Lengths count bytes. PAE binds the payload type and exact payload bytes.
- Standard and URL-safe Base64 are accepted, with or without padding.
- The in-toto statement type is exactly `https://in-toto.io/Statement/v1`.
- The requested predicate type and one exact subject name plus SHA-256 digest are checked after signature verification.

The optional envelope `keyid` is an unauthenticated hint. Nixward ignores it for authorization, tries locally trusted keys, and reports only the key IDs derived from keys that actually verified a signature. The threshold counts distinct trusted Ed25519 public keys, not signature entries.

## Trust policy

The trust policy is a separate local file, not an artifact under the evidence root. The caller supplies its expected SHA-256 digest from a separately pinned local configuration. The module checks:

- schema/version, policy identity and epoch;
- the exact validity interval against caller-supplied UTC epoch milliseconds;
- distinct Ed25519 keys whose key IDs equal SHA-256 of the raw 32-byte public key;
- revoked status, key validity interval and per-key predicate allowlists;
- global payload/predicate allowlists and the distinct-signer threshold.

The trust policy itself is not authenticated by its own key list. Its digest pin and rotation/anti-rollback mechanism belong to the trusted local configuration or root-owned supervisor policy. This module does not discover keys, contact a transparency service, fetch certificates, or implement Sigstore identity verification.

## API and evidence ceiling

`verify_in_toto_dsse` returns a runtime-only `VerifiedDsseAttestation` with private fields and no serialization implementation. Its payload accessor returns the exact byte sequence whose PAE was verified and which was parsed into the Statement. Callers must consume that object rather than re-read or re-parse the untrusted envelope.

This generic layer checks envelope authentication, Statement v1, predicate type, subject name and subject digest. It does **not** by itself prove the claims inside a predicate. An application-specific profile must separately validate repository URI, commit, flake.lock digest, benchmark corpus digest, builder identity and artifact/closure digest before granting any higher-level capability.

A SLSA predicate type does not establish a SLSA level. Nixward must validate the selected SLSA predicate fields, builder trust and provenance expectations before reporting any SLSA conformance.

## Why this improves the architecture

Nixward can keep its stronger local semantics—policy epoch, permit, release barrier, one-shot attempt, worker invocation and host post-state—while interoperating with standardized upstream attestations for source and build provenance. The format is no longer a competing signature protocol. The local verifier remains the policy enforcement point.

## Implemented negative controls

Fourteen Rust tests are authored for byte-length PAE, exact payload verification, untrusted keyid hints, altered payload, payload-type confusion, trust-policy pin mismatch, untrusted signer, duplicate signer threshold, distinct signer threshold, revoked signer, policy/key expiry, wrong predicate/subject, per-key predicate restriction and URL-safe unpadded Base64.

The Nix target is a pure library test target with default/native features disabled. It is authored but has not been executed; no compile, test, or runtime result is claimed.
