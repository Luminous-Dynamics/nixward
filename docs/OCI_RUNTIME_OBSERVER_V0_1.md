# OCI Runtime Observer v0.1

**Status:** Linux source collector and source-consistency prototype. Not a signed host attestation, continuous monitor, or runtime-enforcement proof.

## Purpose

The collector addresses a narrow but critical gap: a declared OCI plan and a Podman inspect document must not be treated as proof of the live process's isolation state. It obtains two bounded observations and reconciles Podman metadata with host procfs evidence.

## Collection model

The Linux-only `collect_live_pair` API requires:

- an explicit absolute Podman executable path, canonicalized before use;
- the full immutable container ID;
- the exact expected image ID/digest;
- the expected task cgroup path;
- an effective-capability allowlist (zero for the strictest profile);
- a caller-allocated persistent observer sequence.

For each sample, the collector:

1. hashes the configured Podman executable before and after invoking it, and invokes it without a shell;
2. reads `podman info --format json` for rootless state and UID/GID mappings;
3. reads `podman inspect --type container <full-id>` for container/image identity, process PID, running state, read-only-root configuration, host network/PID modes, privilege and declared mounts;
4. independently reads the live host-side `/proc/<pid>` status, stat, cgroup, mountinfo, UID/GID maps and namespace links;
5. reads the host boot ID and hashes the machine ID with a domain-separated BLAKE3 digest.

Both samples use one process-local monotonic clock. The observer rejects non-increasing sequences/times and any change in container ID, image, PID, process-start ticks, cgroup, namespace inodes, host boot/machine identity, Podman executable digest, ID mappings, procfs mount digest or other captured source data.

## Fail-closed checks

- Podman reports a running container with the expected immutable container and image IDs.
- Podman reports rootless execution, a read-only root, no privileged mode, no host network or host PID mode, and no additional declared mounts.
- Podman's UID/GID mappings match the process's live `uid_map` and `gid_map`.
- The live root mount is read-only.
- User, network, PID and mount namespace inodes differ from the host observer's namespaces.
- The process is in the exact expected cgroup.
- `NoNewPrivs` is set and effective capabilities are within the configured mask.
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
- that no hidden bind mount exists beyond what the current Podman/procfs checks can identify.

A signed snapshot would authenticate the observer key and bytes; it would not make false kernel claims true. Runtime enforcement and ongoing observation remain separate qualification gates.

## Known limitations and next work

1. Add an observer identity/key lifecycle, boot-bound sequence persistence and signed append-only receipts.
2. Pin the Podman executable by file descriptor/inode or an equivalent execution identity mechanism, and attest the Podman service/daemon and helper binaries.
3. Parse and classify every mountinfo entry, including propagation and source identity, and compare with the exact OCI mount plan.
4. Independently observe cgroup v2 membership, controllers and attached BPF programs, then test packet allow/deny effects using evaluator-owned service oracles.
5. Reobserve at each consequential action and on lifecycle notifications; a single pair is not continuous monitoring.
6. Add negative controls for PID reuse, container replacement, image mutation, namespace swaps, cgroup migration, stale boot identity, mount drift, capability expansion, Podman binary replacement and observer restart.

The current source module contains 18 Rust tests. They are source-level only; no Rust compiler or runner was available during this change. No compilation, clippy, formatting, Nix build or live Podman collection is claimed.
