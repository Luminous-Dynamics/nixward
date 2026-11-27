# Observer Trust and Witness Research v0.1

**Status:** research synthesis and proposed qualification design. No hardware attestation, remote witness, persistent anti-rollback store or runtime enforcement is claimed.

## 1. Why a signature is not an attestation

The signed-checkpoint prototype authenticates the observer key and exact checkpoint bytes. It does not prove that the claims inside the signed payload are true. A compromised host can still sign a coherent lie if the observer's signing environment and measurement sources are compromised together.

Use the role separation in IETF RATS Architecture (RFC 9334):

- **Attester:** produces evidence about a target environment.
- **Verifier:** appraises evidence against trust anchors, endorsements/reference values and an appraisal policy.
- **Relying party:** decides whether to accept an operation based on the verifier result and its own policy.

Nixward currently contains a source collector plus a software-key signature verifier prototype. The RATS split implies these should not be collapsed into one trusted component. A future design should separate the observer/attester process, verifier, owner-controlled trust store and relying party/participant.

### Freshness

RFC 9334's nonce-based approach has a useful property: the appraising party generates an unpredictable nonce and requires it to be returned in the signed evidence. This can show that the evidence was signed after the challenge. It does **not** show that every claim was freshly measured after the challenge; the attester might sign stale cached data. Therefore the collector must re-observe after the challenge and bind the exact snapshot digest into the signed payload.

The new Nixward module uses a 32-byte verifier challenge, a domain-separated digest and exact snapshot/chain-head expectations. The caller must generate that nonce with an OS CSPRNG, consume it once, and refuse cached snapshot data. Timestamp and monotonic sequence checks are additional controls, not substitutes for nonce freshness.

## 2. Root of trust: key custody and measured state

A provisioned Ed25519 public key gives the verifier a stable identity for one observer generation. It does not establish that the private key remains in an uncompromised environment.

Progression should be explicit:

1. **Software-provisioned key:** private key stored outside the guest/agent boundary, with operator enrollment and revocation.
2. **Protected key service:** key held by a TPM, HSM, secure enclave or isolated signer service; export of private material is denied.
3. **Measured observer:** signed claims bind the approved boot/runtime/observer measurements and a verifier challenge.
4. **Appraised attester:** a verifier checks evidence against trusted endorsements/reference values and an explicit appraisal policy.
5. **Relying-party enforcement:** only a verifier-approved, current result can be consumed by a participant at the point of effect.

A TPM quote or TEE attestation must still be appraised. The quote's nonce, measurement register selection, event log, reference values, firmware/boot chain, device endorsement and freshness policy all matter. Hardware possession alone is not an assurance level.

The current Nixward module implements only the first protocol shape: a software Ed25519 signer/verifier interface with external key metadata. It does not enroll keys, call a TPM, measure boot, verify event logs or produce a hardware quote.

## 3. Why a local hash chain is insufficient

A hash chain detects modification relative to a retained trusted head. If an attacker can rewrite the only log and the only saved head, the attacker can restore a valid old prefix or replace the complete history.

The next system therefore needs two distinct mechanisms:

- **Local durable history:** append-only receipt records, crash-consistent writes, monotonic sequence allocation and explicit restart/boot transitions.
- **Independent witness:** a service outside the observer host retains checkpoint state and refuses a presented parent that is not the latest accepted checkpoint.

The verifier should remember at least `(observer_id, machine_id, key_generation, boot_id, sequence, chain_head, checkpoint_digest)`. After an ambiguous write or lost acknowledgement, the observer must query/reconcile the witness before signing the next checkpoint. Unknown outcome means no new mutation.

## 4. Transparency-log precedent

Sigstore Rekor is a useful model for remote evidence anchoring. Its transparency-log design uses Merkle inclusion proofs to show that an entry is committed to a signed tree head, and consistency proofs to show that a later tree is an append-only extension of an earlier checkpoint. Clients retain the latest accepted checkpoint and verify consistency before advancing it.

Nixward should adopt the protocol properties, not necessarily deploy Rekor as the trust anchor:

- a checkpoint is signed by a witness key distinct from the observer key;
- the response binds the checkpoint/tree size and root;
- inclusion proves the event is present in the checkpoint;
- consistency proves no prior entries were removed or rewritten;
- relying parties retain the latest witness checkpoint;
- independent witnesses/gossip detect split views or equivocation;
- witness identity, key rotation and recovery are themselves governed by an explicit trust policy.

A single remote server returning its own signed head is not sufficient against that server equivocating. High-impact deployments should use multiple independent witnesses or a gossip/monitor path.

The first Nixward durable prototype should be deliberately small: one observer-specific append stream, one primary witness, one secondary monitor, explicit recovery procedures and synthetic crash/rollback injection. Do not attempt to turn a general transparency network into the first implementation.

## 5. Runtime comparison: OpenShell and Sentry

NVIDIA OpenShell is the most relevant runtime comparator. Its current public documentation lists stable v0.1.10 and describes a supervisor/workload split, process ownership and program identity, mediated TCP/DNS, policy checks and an outer egress fence. It is materially ahead of Nixward on runtime enforcement; the task-bound Nixward contract is not enforcement parity.

NVIDIA's Open Agent Safety Platform expands the comparison beyond the local sandbox. The September 28, 2026 announcement describes OpenShell and Sentry, with Sentry as an out-of-band watchdog reference design using a BlueField-4 DPU to monitor agent behavior. NVIDIA announced on November 10 that OpenShell was being contributed to CNCF; CNCF lists the project at Sandbox maturity as of its September 26 acceptance.

This suggests a stronger industry direction: **in-band enforcement plus out-of-band observation**. A workload should not be solely responsible for reporting whether its own boundary remains intact. Nixward can research the same separation without requiring a DPU in the first prototype:

- in-band backend enforces exact per-workload policy;
- host observer collects independent kernel/runtime evidence;
- out-of-band witness stores the latest checkpoint and detects rollback/equivocation;
- owner/participant consumes an expiring verified capability only after all independent checks.

A DPU/TPM/TEE is a later hardware profile, not a prerequisite for defining the software interfaces.

## 6. Luminous opportunity

The competitive opportunity is not to duplicate OpenShell's sandbox or NVIDIA's DPU watchdog. It is to build a composable proof-carrying evidence and authorization layer that can sit above multiple backends:

- OpenShell;
- rootless Podman;
- Kubernetes;
- MicroVM/Firecracker;
- a future out-of-band DPU/TEE profile.

The same owner-signable task subject should commit to the policy proof, workload identity, attester identity, verified checkpoint, runtime enforcement generation and effect receipt. Backend-specific observers produce evidence; a neutral verifier appraises it; the participant enforces the authorization.

Do not infer equivalence between backends. Every backend needs its own conformance profile and independent packet/effect observations.

## 7. New qualification experiments

### Observer/key plane

- valid signature, wrong trusted key;
- key ID substitution;
- generation rollback;
- revocation after signature but before admission;
- expired validity interval;
- verifier nonce replay, substitution and reuse;
- future timestamp and expired checkpoint;
- snapshot digest mismatch;
- chain-head mismatch;
- parent-checkpoint fork or rollback;
- observer/machine/boot identity substitution.

### Witness/durability plane

- crash after sequence allocation;
- crash after payload write but before link write;
- crash after link write but before fsync;
- crash after fsync but before remote append;
- witness accepted entry but acknowledgement was lost;
- truncate or restore local log after a newer checkpoint was witnessed;
- restore local database and local head together;
- witness split-view/equivocation;
- key rotation and recovery with missing local state.

All experiments must use synthetic evidence and isolated lab infrastructure. A no-network or missing-witness control must deny new consequential admission rather than degrade to local-only success.

## 8. Proposed acceptance levels

| Level | Qualification claim | Required evidence |
|---|---|---|
| O0 | Source-consistent observation | Current two-snapshot Podman/procfs checks |
| O1 | Authenticated software checkpoint | Ed25519 challenge-bound checkpoint, trusted key and revocation check |
| O2 | Durable anti-rollback | Crash-consistent sequence/log and external parent checkpoint |
| O3 | Witnessed transparency | Signed witness checkpoint, inclusion/consistency verification and retained latest head |
| O4 | Hardware-appraised observer | TPM/TEE/measured-boot evidence plus verifier appraisal/reference values |
| O5 | Runtime-enforced observer | Exact live workload hook/attachment and independently observed allowed/denied effects |

The new Nixward module is an **O1 protocol prototype only**, not a completed O1 deployment: key enrollment, key custody and a relying-party persistent trust store are not implemented. Existing task authorization remains schema v3 and explicitly runtime-not-enforced.

## 9. References

- IETF [RFC 9334 — Remote ATtestation procedureS (RATS) Architecture](https://www.rfc-editor.org/rfc/rfc9334.html), especially roles and nonce-based freshness.
- Sigstore [Rekor architecture — consistency proofs](https://github.com/sigstore/architecture-docs/blob/main/rekor-spec.md#94-consistency-proofs).
- NVIDIA OpenShell [v0.1.10 architecture](https://docs.nvidia.com/openshell/v0.1.10/about/architecture).
- NVIDIA [Open Agent Safety Platform announcement, 28 September 2026](https://investor.nvidia.com/news/press-release-details/2026/NVIDIA-Launches-Open-Agent-Safety-Platform-to-Secure-Agents-From-Testing-to-Deployment/).
- NVIDIA [OpenShell CNCF contribution announcement, 10 November 2026](https://blogs.nvidia.com/blog/open-source-openshell-infrastructure/).
- CNCF [OpenShell project status](https://www.cncf.io/projects/openshell/).

---

**Claim boundary:** this document is a research and qualification proposal. It does not implement hardware attestation, durable storage, witness services, transparency proofs, out-of-band watchdogs or active runtime enforcement.
