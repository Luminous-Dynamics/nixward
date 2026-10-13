# M1a offline network-observation evidence verifier

This crate is the first implementation slice for [Issue #68](https://github.com/Luminous-Dynamics/nixward/issues/68). It is deliberately **offline and read-only**: it accepts a JSON evidence envelope, reconstructs the raw bytes from lowercase hex, verifies digests, parses a bounded Linux rtnetlink link dump, and emits a deterministic receipt. It opens no Netlink socket, calls no privileged API, starts no subprocess, and cannot mutate a network.

## What the v1 profile checks

- Exact envelope schema ID/version and strict typed fields (unknown fields are rejected).
- Stable target ID, boot ID and network-namespace inode copied consistently through the envelope and each source attempt.
- Collector build-digest shape, a verifier-pinned policy ID/version and hard maximum ceilings for freshness, monotonic source-window duration, raw bytes, messages, objects and retries. Tighter caller limits are allowed, but no ceiling can be raised. The non-weakenable critical-attribute floor is exactly the basic projection the verifier understands: `IFLA_ADDRESS`, `IFLA_IFNAME` and `IFLA_MTU`. Callers can declare more attributes decision-critical, but the verifier returns `Unsupported` when it encounters one the projection cannot interpret.
- Domain-separated BLAKE3 over byte-exact raw Netlink artifacts, a separately recomputed canonical semantic digest, deterministic receipt bytes, and a receipt digest rechecked before serialization.
- Netlink header bounds/alignment, sequence binding, message limits, `NLM_F_DUMP_INTR`, `NLM_F_DUMP_FILTERED`, `NLMSG_ERROR`, successful `NLMSG_DONE` terminal status, multipart flags, exact unfiltered `RTM_GETLINK` request framing, rejection of `NLM_F_ATOMIC` and unexpected request flags, and no bytes/messages after the terminal marker. It validates `ifinfomsg` family/padding and requires `ifi_change = 0`, as used for kernel link-dump rows.
- rtnetlink `RTM_NEWLINK`/`ifinfomsg`/`rtattr` framing, required `IFLA_IFNAME` and `IFLA_MTU`, optional link-layer address bytes, duplicate attribute rejection, duplicate interface identity checks, bounded objects, and policy-declared decision-critical attributes.
- Explicit outcomes for valid-empty vs no response, interrupted/lost/truncated evidence, target/sequence substitution, unsupported critical semantics, stale evidence and altered digests.

A collector's `complete` boolean is not part of the envelope contract and cannot determine acceptance. Transport-loss indicators (`ENOBUFS`, `MSG_TRUNC`, drop counters) are only negative evidence: when present they block acceptance. Their absence is **not cryptographically authenticated**, so it is not independent proof that a kernel socket had no loss.

## Deliberate limits

This is an M1a verifier profile, not the live M1 observer.

- Only `linux.rtnetlink.links.v1` is supported. Address/route/rule dumps, nftables, WireGuard, NetworkManager, systemd-networkd, FRR, gNMI and hardware-specific sources are unsupported.
- The canonical link projection covers ifindex, interface name, hardware link type, flags, MTU, and optional link-layer address bytes. Ordinary kernel fields such as qdisc, tx queue length, operational state, parent/master relationships, link-kind details, and namespace/physical-port metadata remain bound by the exact raw-artifact digest but are not represented in the canonical semantic projection by this v1 basic profile. If the intended decision depends on one of those fields, the caller must mark that attribute ID decision-critical; verification will fail closed as `Unsupported` until parsing and canonicalization for it are implemented. This deliberately limits the accepted semantic claim instead of silently treating those omitted fields as understood.
- A single bounded source window is not a global atomic snapshot. A complete result means only that this verifier accepted the supplied bytes and metadata for the one declared profile.
- `ownership` is always `Unknown`. A link dump does not prove which manager has write authority.
- A BLAKE3 digest proves equality against a supplied value, not who produced it or whether the kernel/collector told the truth. This receipt is not a signature, hardware attestation or protected local provenance.
- `captured_at_unix_ms` and `verification_time_unix_ms` are supplied inputs to make freshness deterministic. They are not a trusted clock. The verifier doesn't prove the source stayed in a namespace for the entire collection; it only binds and cross-checks the declared identity.
- This does not authorize the planner or a mutation broker. No write adapter is included.

## Run

From the repository root:

```sh
cargo fmt --manifest-path tests/network-observation-verifier/Cargo.toml -- --check
cargo test --locked --manifest-path tests/network-observation-verifier/Cargo.toml --all-targets
cargo run --locked --manifest-path tests/network-observation-verifier/Cargo.toml --bin emit_synthetic_evidence > /tmp/m1a-synthetic-envelope.json
cargo run --locked --manifest-path tests/network-observation-verifier/Cargo.toml --bin nixward-network-observation-verifier -- --target-id synthetic-lab-router --boot-id synthetic-boot-id --netns-inode 4026533001 /tmp/m1a-synthetic-envelope.json > /tmp/m1a-receipt.json
```

The synthetic fixture generator is explicitly named and emits a fabricated `NLMSG_DONE(status=0)` for a valid empty link dump. It is useful only to prove deterministic serialization and control flow; it is not collected network state. The verifier exits `0` for `CompleteForDeclaredScope`, `1` for a parsed envelope that does not qualify, and `2` for I/O or malformed-JSON errors. Non-complete decisions still produce a receipt where the envelope can be parsed.

## Evidence progression

M1a must not be confused with the next gates:

1. M1a: fixture-driven envelope and raw rtnetlink framing verifier (this PR).
2. M1b: separate read-only Linux Netlink collector, bound socket/namespace identity, drop/error reporting, bounded retry and an integration test inside a disposable network namespace.
3. M1c: independent manager/ownership observations for firewall, WireGuard and one declared manager at a time.
4. Planner acceptance must bind the exact raw envelope digest, scope, target, policy and verifier identity; the mutation broker must refresh target/pre-state/authority again immediately before any future mutation.

No production network, live socket, external writer, or kernel state is touched by this package.
