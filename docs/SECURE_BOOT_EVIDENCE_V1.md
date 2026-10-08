# Secure Boot Evidence V1

This document defines the firmware-policy observation boundary for UEFI Secure Boot.

## Non-equivalence

These facts are separate:

- firmware reports Secure Boot enabled;
- firmware reports Setup Mode;
- a UKI image has an exact byte identity;
- a UKI image carries a valid signature;
- the signer is authorized;
- the signed image embeds the authorized NixOS system closure;
- the image is selected for next boot;
- the system actually boots;
- post-boot health passes.

One fact must never satisfy another predicate implicitly.

## Evidence record

| Field | Meaning |
| --- | --- |
| state | Enabled, Disabled, SetupMode, or Unknown |
| secure_boot_variable | exact boolean observed from the global EFI SecureBoot variable, when present |
| setup_mode_variable | exact boolean observed from the global EFI SetupMode variable, when present |
| observed_at_ms | host observation timestamp |
| evidence_digest | BLAKE3 digest over the normalized observation |

Missing EFI state is `Unknown`, not disabled.

For operator evidence, prefer the unified `observe secure-boot-snapshot` surface. It binds SecureBoot/SetupMode state, `db`, and `dbx` payload identities to one observation timestamp and BLAKE3 digest. The narrower state/database observations remain useful diagnostics but should not be treated as a single correlated snapshot.

## Observation

`src/action/secure_boot.rs` reads only the global UEFI `SecureBoot` and `SetupMode`
variables from efivarfs. It performs no firmware mutation and invokes no signing
or key-management operation.

The observer requires the exact efivarfs payload shape: four attribute bytes plus
one boolean data byte. Unsupported values, malformed lengths, missing EFI state,
and ambiguous variable instances fail closed.

The separate `observe secure-boot-databases` surface reads the UEFI `db` and `dbx`
signature-database variables under the EFI image-security database GUID and emits
exact BLAKE3 payload identities. The broader snapshot surface includes those same
identities alongside the firmware policy state. Missing databases are represented as `Absent`,
while unreadable or malformed state is an observation error and must be treated as
Unknown by callers. These raw database digests do not establish that a particular
certificate is authorized or non-revoked.

A separate `secure_boot_signature` evidence subject inspects the exact PE Authenticode
certificate table of an observed UKI. It records the image BLAKE3 digest, table
location/size, per-certificate revision/type/length, and per-certificate/table
digests. An absent table is distinct from malformed data. This proves only that
certificate bytes are present in the exact image; it does not prove cryptographic
signature validity, signer authorization, firmware trust acceptance, or revocation.

The same module can run a certificate-pinned `sbverify --cert` verification against
the exact image. `Verified` is emitted only when the verifier exits successfully
and the image bytes are unchanged across the verification call. When the supplied
certificate comes from UEFI `db`, success establishes verification to that exact
certificate as a trust anchor; this is evidence of a certificate-chain anchor, not
a blanket statement that firmware would accept the image. The verifier can also
be run against certificates observed in `dbx`: success is definite chain-level
revocation evidence for that exact revoked certificate. Tool absence or verifier
failure is never converted into a pass.

For UEFI `EFI_CERT_SHA256_GUID` database records, the image subject is the PE/COFF
Authenticode SHA-256, not the flat file SHA-256. The implementation therefore
uses the exact Authenticode hash procedure for `db`/`dbx` image-hash comparisons. citeturn927442search0turn927442search1

X.509 TBS hash records in `dbx` carry a revocation time. An exact TBS match is
therefore recorded as a potential revocation until the signed-image timestamp and
certificate-chain semantics are evaluated; it is not collapsed into an immediate
veto. The current implementation deliberately leaves this as a separate
`PotentialDbxTbsRevocation` state.

## Certificate-chain trust boundary

The verification path now distinguishes five materially different outcomes:

- `VerifiedAgainstDbCertificate`: the exact image cryptographically verifies to a certificate observed in `db`;
- the verifier also records the exact X.509 certificate chain embedded in the image signature, including signer identities and chain-member TBS/issuer/serial digests;
- `ForbiddenByDbxCertificateChain`: an X.509 certificate observed in `dbx` has the same Issuer, Serial Number, and To-Be-Signed hash as a certificate in the image's verified signing chain;
- `PotentialDbxTbsRevocation`: an exact X.509 TBS hash in `dbx` exists but its revocation-time semantics have not been evaluated;
- `UnknownDbxCertificateRules`: an unsupported/uninterpreted `dbx` rule prevents a trust conclusion.

For live-host evidence, Nixward reads `db` and `dbx` before verification and re-reads both after verification. A database digest change invalidates the verification result rather than allowing evidence from one database snapshot to qualify another. The image itself is checked for byte stability during verifier invocation and is re-read once more before any terminal trust result is returned. A final image-digest mismatch clears the derived chain and matching fields and produces `ImageChangedDuringVerification`, preventing a receipt from combining chain evidence from one image instance with signature evidence from another. X.509 revocation is correlated against actual signing-chain members rather than merely asking whether a dbx certificate can independently verify the image.

This closes more of the chain-anchor evidence boundary without pretending to reproduce the firmware's complete certificate-policy engine. Same-Issuer/Serial/TBS matching is now implemented for X.509 `dbx` records. Timestamp-aware TBS revocation evaluation remains explicit next-stage work because UEFI associates those records with an EFI_TIME and may require RFC 3161 timestamp validation.

## Separate signature subject

Signature verification is intentionally not included in this state observer. A
future signature evidence adapter must independently establish:

- exact selected UKI image identity;
- signature presence and cryptographic validity;
- signer/certificate identity;
- applicable firmware trust policy;
- revocation/status where authoritative evidence exists.

That adapter must then be compared against the already-observed UKI digest and
candidate closure binding. Signature validity alone is never proof of system
closure provenance or physical boot success.

## Current implementation boundary

Secure Boot state observation is available through the read-only CLI observation
surface. Signature verification, signer authorization, UKI provenance, boot
selection, physical boot, and post-boot health remain separate evidence layers.
