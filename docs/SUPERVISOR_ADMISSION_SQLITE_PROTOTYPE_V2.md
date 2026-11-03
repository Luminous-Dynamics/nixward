# Supervisor admission SQLite prototype v2: authority provenance

Status: **non-privileged storage prototype; verifier-minted authority receipt is required at admission; no production supervisor or worker-release path**

## Security model

This version joins the detached-authority work to the atomic admission-store prototype. It intentionally distinguishes:

1. `DetachedAuthoritySignature`: untrusted wire input.
2. `VerifiedAuthorityReceipt`: runtime-only, non-serializable capability minted by `AuthorityVerifier`.
3. `AuthorityProvenanceRecord`: serializable, durable audit data. It is untrusted after deserialization and cannot itself authorize admission or payload release.

The store's `AdmissionRequest` now requires a `VerifiedAuthorityReceipt`. A client cannot fabricate this capability by deserializing JSON. The supervisor must first load the machine-local trust policy and epoch, derive the expected ChangePlan subject and Holon identity locally, and call the byte-oriented verifier. The exact input JSON proof bytes retained by that receipt must equal the approval bytes passed to the store.

## Admission binding

Before writing, the store validates:
- authority action is `change`;
- audience is exactly `nixward-change-v1` or `nixward-execution-intent-v1`;
- receipt subject and Holon identity equal supervisor-derived expected values;
- replay key equals the challenge-derived replay key in the receipt;
- current policy digest and non-zero epoch supplied by the supervisor equal the receipt's verified policy digest and epoch;
- verifier time is no later than admission time, and admission time does not exceed signed expiry;
- exact raw proof bytes in the provenance record equal the approval material;
- provenance hashes, duplicated challenge/replay/subject/signer bindings and the record schema are internally consistent.

For the ordinary change audience, the signed subject must equal the exact ChangePlan digest. For the execution-intent audience, the caller must derive the subject from the exact verified execution-intent and realization bundle; the storage layer checks it against the locally supplied expected subject but does not parse/recreate the framework bundle.

This is not a substitute for a trusted supervisor. `expected_authority_subject`, `expected_authority_holon_id`, current policy digest and epoch must come from root-owned/local state, never client-supplied request fields at an IPC boundary.

## Schema v2 and atomic write

A single SQLite `BEGIN IMMEDIATE` transaction now commits the original five rows plus the authority provenance row:

1. `admission_commits`: stable transaction, attempt, replay, plan, machine, approval, permit, event and commit identities.
2. `authority_replays`: globally unique replay key and intent binding.
3. `supervisor_permits`: permit / attempt / commit binding.
4. `transaction_attempts`: unresolved/resolved state.
5. `admission_events`: immutable event payload and digest.
6. `authority_provenance_records`: serialized audit record and its content digest, joined to the same commit ID.

The v2 domain-separated commit ID includes the authority-provenance digest. The provenance table is immutable and has a foreign key to the commit. All three admission lookup paths join the provenance row; the joined read-back returns and validates the original provenance record. Idempotent replay matching includes its digest, so a retry returns the original provenance, attempt and permit rather than adopting newly prepared material.

The new row has a dedicated transaction failpoint. The pre-commit failure matrix includes failure after writing provenance; that error must roll back every row. A lost acknowledgement after commit is reconciled with the same replay key and returns the original durable provenance and permit.

## Migration behavior

A schema-v1 database containing one or more admissions is refused with `LegacyAdmissionsRequireReauthorization`. The store does not synthesize provenance, infer a signer, or silently bless legacy approval bytes. A v1 database with no admissions may be upgraded to v2; newly written admissions still require a fresh verifier-minted receipt.

## Restart and release

The stored `AuthorityProvenanceRecord` is not a runtime capability. After restart, the supervisor must:
1. load the exact immutable historical policy identified by policy ID, digest and epoch;
2. call `AuthorityVerifier::reverify_historical_provenance` to mint a new runtime receipt;
3. compare that receipt against the current machine-local policy epoch and emergency-revocation set immediately before payload release;
4. recheck signed expiry and exact transaction/attempt/plan/machine bindings;
5. release the payload only after the admission commit, worker identity and release barrier have all been durably read back.

Policy-epoch drift before release blocks release and requires fresh authorization. After payload release, the original admission remains historical evidence; stop/recovery requires its own separately authorized policy and evidence path.

## Negative controls authored

The native Rust test target now includes:
- verifier-minted Ed25519 receipt generation rather than fabricated approval strings;
- exact raw proof-byte preservation and request binding;
- expected subject/Holon mismatch;
- current policy digest and epoch mismatch;
- schema-v1 database with existing admission rows refused;
- tampered persisted provenance detected by the integrity scan;
- failure injection after the provenance insert;
- lost-ack retry returning the same attempt, permit and provenance;
- same-replay race, different-replay unresolved exclusion, resolution and integrity-scan coverage inherited from the v1 prototype.

There are 22 store unit tests in this source revision. They are authored, not executed in this authoring environment.

## Qualification boundary

This remains storage/authentication-boundary prototype code only. It does not implement:
- a root-owned trust-policy file loader or monotonic policy epoch store;
- a privileged supervisor, D-Bus or polkit interface;
- systemd StartUnit, worker execution or payload release;
- descriptor-relative path creation, openat2/O_NOFOLLOW hardening or service ownership;
- subprocess SIGKILL, multi-process crash, VM reboot or physical power-loss qualification.

WAL, `synchronous=FULL`, filesystem and sidecar settings must still be tested on the target storage stack. SQLite WAL is local-host storage, not a network-filesystem coordination protocol. No compilation, test, flake, VM or power-loss result is claimed.
