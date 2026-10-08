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

## Observation

`src/action/secure_boot.rs` reads only the global UEFI `SecureBoot` and `SetupMode`
variables from efivarfs. It performs no firmware mutation and invokes no signing
or key-management operation.

The observer requires the exact efivarfs payload shape: four attribute bytes plus
one boolean data byte. Unsupported values, malformed lengths, missing EFI state,
and ambiguous variable instances fail closed.

The separate `observe secure-boot-databases` surface reads the UEFI `db` and `dbx`
signature-database variables under the EFI image-security database GUID and emits
exact BLAKE3 payload identities. Missing databases are represented as `Absent`,
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
and the image/certificate bytes are unchanged across the verification call. Tool
absence or verifier failure is never converted into a pass.

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
