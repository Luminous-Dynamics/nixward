# OCI Runtime Observer v0.1

**Status:** Linux source collector and source-consistency prototype. Not a signed host attestation, continuous monitor, or runtime-enforcement proof.

## Purpose

The collector addresses a narrow but critical gap: a declared OCI plan and a Podman inspect document must not be treated as proof of the live process's isolation state. It obtains two bounded observations and reconciles Podman metadata with host procfs evidence.

## Collection model

The Linux-only `collect_live_pair` API requires:

- an explicit absolute Podman executable path, canonicalized before use;
- the full immutable container ID;
- the exact expected image manifest digest (Podman's `ImageDigest`; distinct from its local image ID in `Image`);
- the expected task cgroup path;
- an effective-capability allowlist (zero for the strictest profile);
- a caller-allocated persistent observer sequence.

For each sample, the collector:

1. hashes the configured Podman executable before and after invoking it, and invokes it without a shell;
2. reads `podman info --format json` for rootless state and UID/GID mappings;
3. reads `podman inspect --type container <full-id>` for the full container ID, separate local `Image` ID and `ImageDigest`, process PID, running state, read-only-root configuration, host network/PID modes, privilege, `Mounts`, `HostConfig.Binds` and `HostConfig.Tmpfs`;
4. independently reads the live host-side `/proc/<pid>` status, stat, cgroup, mountinfo, UID/GID maps and namespace links for user, network, PID, mount and cgroup namespaces;
5. reads the host boot ID and hashes the machine ID with a domain-separated BLAKE3 digest.

Both samples use one process-local monotonic clock. The observer rejects non-increasing sequences/times and any change in container ID, image, PID, process-start ticks, cgroup, namespace inodes, host boot/machine identity, Podman executable digest, ID mappings, procfs mount digest or other captured source data.

## Fail-closed checks

- Podman reports a running container with the expected immutable container ID and expected `ImageDigest`. The local `Image` ID is preserved separately and is not confused with the registry manifest digest.
- Podman reports rootless execution, a read-only root, no privileged mode, an isolated network mode from the supported allowlist, a private/default PID mode, a private cgroup mode, and no additional user-declared `Mounts`, `Binds` or `Tmpfs`. `container:<id>` and `ns:<path>` sharing modes are rejected, not merely the literal `host` mode. Podman's inspect `Mounts` list alone is insufficient: `Binds` and `Tmpfs` are separate `HostConfig` fields, and tmpfs is not included in the ordinary mount list.
- Podman's UID/GID mappings match the process's live `uid_map` and `gid_map`.
- The live root mount is read-only.
- User, network, PID, mount and cgroup namespace inodes differ from the host observer's namespaces.
- The process is in the exact expected cgroup.
- `NoNewPrivs` is set, `Seccomp` is in filter mode (`2`), and **effective, permitted, bounding and ambient** capability sets are all within the configured mask.
- Process start-time ticks, boot ID, machine identity, mountinfo digest and observer sequence are present and stable.

Missing, malformed, unsupported, stale or contradictory evidence returns an error. A partial source set does not yield a snapshot.

## What the result establishes

An `OciRuntimeConsistencySnapshot` is an opaque, read-only result constructible only by the collector/reconciliation code. Its digest binds the exact collected facts. It establishes that the collected Podman and procfs sources agreed on the declared identities and isolation observations during one bounded collection interval.

It can support ATR-034 (restart/PID-reuse/namespace/cgroup drift) and ATR-036 (source disagreement) as a real observation primitive.

## What it does not establish

The snapshot is **not** a cryptographic attestation of the host or kernel. Podman `info` and `inspect` are two views exposed by the same runtime, not two independent trust authorities. The process hashes the Podman executable before/after calls but does not prove which inode the kernel executed, protect against a hostile replacement race, or attest helper binaries and the daemon. Procfs content is only as trustworthy as the host kernel and observer context.

It also does not prove:

- that the observer itself is uncompromised or has a trusted signing identity;
- that the expected cgroup path or image digest was approved by the owner;
- that the process remains unchanged after the observation window;
- that a cgroup/BPF/network policy is attached or enforcing;
- that DNS, proxy, redirect, QUIC or credential-provider paths are constrained;
- that the actual mount graph is fully equivalent to the intended OCI plan. The collector rejects user-declared `Mounts`, `Binds` and `Tmpfs`, but its current mountinfo parser validates records and root-read-only state rather than fully reconciling every mount source, propagation attribute and runtime-created mount against the complete plan.

A signed snapshot would authenticate the observer key and bytes; it would not make false kernel claims true. Runtime enforcement and ongoing observation remain separate qualification gates.

## Known limitations and next work

1. Add an observer identity/key lifecycle, boot-bound sequence persistence and signed append-only receipts.
2. Pin the Podman executable by file descriptor/inode or an equivalent execution identity mechanism, and attest the Podman service/daemon and helper binaries.
3. Fully reconcile every mountinfo entry—including propagation, root, source, filesystem type and options—with Podman's `Mounts`, `Binds`, `Tmpfs` and the exact OCI mount plan. Current code rejects declared user mounts and structurally validates mountinfo, but is not yet a complete mount-graph equivalence verifier.
4. Independently observe cgroup v2 membership, controllers and attached BPF programs, then test packet allow/deny effects using evaluator-owned service oracles.
5. Reobserve at each consequential action and on lifecycle notifications; a single pair is not continuous monitoring.
6. Add negative controls for PID reuse, container replacement, image mutation, namespace swaps, cgroup migration, stale boot identity, mount drift, capability expansion, Podman binary replacement and observer restart.

The OCI runtime collector currently has 25 source-level Rust tests. The separately exported in-memory receipt-chain prototype has six tests; it detects link tampering/reordering and sequence rollback relative to a trusted head, but is not yet durable or externally anchored. No Rust compiler or runner was available during this change. No compilation, clippy, formatting, Nix build or live Podman collection is claimed.


## Receipt-chain prototype

The separate `observe::receipt_chain` module appends a domain-separated link containing observer identity digest, boot epoch, sequence interval, snapshot digest and previous-link digest. It rejects duplicate/non-increasing snapshot sequence numbers, payload mutation, link reordering and a boot-epoch change without an explicit transition record. The verifier recomputes every link digest.

This chain is currently an in-memory structure. It does not persist with fsync/crash consistency, sign links, retain an observer key, or compare its head with an external anchor. Consequently it detects modifications relative to a trusted chain/head supplied to the verifier, but cannot detect an attacker replacing or truncating the entire chain and its head together. Persistent anti-rollback, observer-key revocation and external anchoring are tracked in Nixward issue #169. The task contract schema v3 currently binds a snapshot, not a durable chain link.
