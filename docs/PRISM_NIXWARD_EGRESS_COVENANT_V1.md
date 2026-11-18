# Prism ↔ Nixward Egress Covenant v1

Status: cross-repository integration proposal and wire-contract draft. No production broker, DNS resolver, kernel loader, or runtime integration is implemented by this document.

## 1. Executive decision

Prism and Nixward solve different halves of the same problem. They should compose, not converge into one oversized networking crate.

- **Prism is the application authority plane.** It authorizes an exact HTTP(S) operation: origin, URL, method, allowed headers/body, DNS snapshot, expiry, byte/time budgets, redirect/retry decisions, TLS hostname identity, response consumption and application receipt.
- **Nixward is the workload enforcement plane.** It binds an approved network policy to an exact workload identity and cgroup, compiles workload-level network rules, enforces socket admission in the kernel, records metadata-only observations, and separates lab evidence from owner-authorized production activation.
- **The kernel is the outer boundary.** A process that bypasses Prism must still be unable to open arbitrary sockets from the protected workload cgroup.
- **The owner policy is the root of authority.** Prism, Symthaea reasoning, DNS observations, and telemetry cannot broaden an owner-approved workload capability.

The intended composition is:

`owner policy → workload capability → authenticated resolution lease → kernel address/port admission → Prism pinned HTTP request → peer/TLS verification → correlated evidence`

The core principle is **one DNS decision, two independently enforced planes**: the same exact approved address set must constrain the HTTP transport and the workload's kernel socket boundary.

## 2. Existing implementation inventory

This proposal reuses existing Nixward work:

| Existing component | Current role | Boundary that remains |
|---|---|---|
| `src/network_covenant.rs` | Typed `WorkloadIdentity`, `NetworkCapability`, `NetworkPolicyPlan`, expiring `NetworkCapabilityLease` | The current lease does not carry a DNS answer snapshot or resolved socket set |
| `src/network_enforcement.rs` | Compiles workload policy into a fail-closed cgroup-BPF enforcement plan; requires kernel feature probe and exact cgroup binding | `DestinationSet::Hostnames` is explicitly unresolved until an authenticated DNS/resolution covenant exists |
| `src/network_runtime_lab.rs` | Validates an isolated runtime report with 14 required cases and emits a lab attestation | Lab attestation is not target-host activation evidence |
| `tests/network-runtime-lab/` | Disposable NixOS VM; test-only cgroup-BPF object; real IPv4/IPv6 TCP/UDP allow/deny, lease expiry, generation swap, cgroup binding, stale replay and attach-failure cases | The current test BPF program is a small port/mode/generation/lease laboratory, not a production implementation of the typed CIDR/hostname policy compiler |
| `src/network_activation.rs` | Exact owner-authorized activation intent and post-activation receipt contract | The existence of the receipt type does not itself prove that a production target has attached the reviewed program |
| `src/network_telemetry.rs` | Bounded, metadata-only BLAKE3 hash-chained network telemetry; no payload capture or enforcement authority | Hash chaining provides integrity linkage, not collector authenticity or independent proof of successful remote connection |

Prism's current implementation in Mycelix PR #6299 already has a one-use application capability, complete bounded DNS address-set validation, `resolve_to_addrs` pinning, original-host Host/SNI/certificate checks, a required `remote_addr()` membership check, manual per-hop redirect authorization, disabled ambient proxies/retries, bounded response bodies, and retained-body memory leases. Its receipts are currently application receipts, not signed or kernel-attested claims.

References:
- Nixward network architecture / task corpus: https://github.com/Luminous-Dynamics/nixward/pull/67
- Nixward deterministic fault-scenario harness: https://github.com/Luminous-Dynamics/nixward/pull/71
- Nixward offline rtnetlink observation verifier: https://github.com/Luminous-Dynamics/nixward/pull/72
- Prism egress implementation: https://github.com/Luminous-Dynamics/mycelix/pull/6299
- Symthaea browser preflight policy: https://github.com/Luminous-Dynamics/symthaea/blob/main/crates/domains/symthaea-browser/src/safety.rs
- Iroh patch uses DNS-pinned Reqwest for relay probes: https://github.com/Luminous-Dynamics/symthaea/blob/main/patches/iroh/iroh/src/net_report/reportgen.rs

## 3. Critical gap discovered

Nixward's current `NetworkEnforcementPlan::compile_capability` rejects hostname destinations with the reason:

> hostname capabilities require an authenticated DNS/resolution covenant before kernel pinning

This is the correct fail-closed behavior. A hostname string is not an IP policy, and a DNS response is not automatically trusted merely because it was observed.

The bridge must not work around this by silently resolving a hostname in an untrusted caller and passing its IPs into a privileged map writer. It must establish:

1. Which owner-authorized parent capability allowed the hostname, protocol and port?
2. Which exact workload and cgroup made the request?
3. Which resolver/namespace/profile produced the A/AAAA/CNAME answer set?
4. What was the complete answer set and its validity interval?
5. Which policy filtered every address, and why?
6. Which one-shot request/hop is the temporary lease for?
7. Which kernel generation contains that exact allow-set?
8. Did Prism actually connect to a peer in the same set and validate the original hostname's TLS identity?

**Important:** the current `NetworkCapability` hostnames variant carries names, not an explicit address-classification policy. Before a production hostname lease is possible, the parent policy must gain an explicit address scope (for example, public-unicast-only or an explicit approved CIDR set) and a versioned resolver policy. Do not infer that `Hostnames` implicitly means globally reachable IP addresses.

## 4. Authority model and trust boundaries

### 4.1 Parent authority

A resolution lease is a strict *narrowing* of an existing owner-authorized `NetworkCapability`. It never creates a new hostname, port, protocol, workload, or address scope.

The parent capability should bind:
- exact workload identity digest and Holon;
- egress direction;
- transport protocol;
- exact hostname or explicit hostname pattern semantics;
- permitted port(s);
- explicit resolved-address scope/classification policy;
- policy version and owner/delegation authority.

A lease for `api.example.org:443/tcp` is invalid unless the parent policy grants that destination and the exact workload. Wildcard/subdomain matching must be explicit in the parent policy; v1 should prefer exact canonical hostnames.

### 4.2 Resolver authority

**Preferred v1 model:** Nixward's trusted resolver service obtains the complete A and AAAA set once, validates it against the parent policy, and returns a short-lived signed/digest-bound snapshot. Prism consumes those exact addresses for its socket pinning. It must not independently resolve again.

The resolver adapter must identify its trust profile and the network namespace in which it resolved. It must return complete answer-set semantics, including:
- A and AAAA answers (including a valid NODATA result for one family);
- CNAME chain identity and loop/chain bounds;
- duplicate elimination and answer-count ceiling;
- TTL/valid-until for all accepted records;
- DNS failure, timeout, malformed response and truncated UDP/TCP fallback outcomes;
- a digest of the normalized resolver transcript.

If an adapter cannot establish a usable validity bound, the broker must refuse a dynamic lease under the strict profile. A guessed/default TTL is not DNS evidence.

The production resolver adapter is an explicit implementation milestone. The current OS `ToSocketAddrs` path in Prism does not expose authoritative TTL/CNAME/DNSSEC metadata; the test-only Hickory fixture does not make Hickory the production resolver. Split-DNS, systemd-resolved, hosts-file and VPN behavior require platform-specific tests before declaring compatibility.

### 4.3 Address-set policy

The resolver service evaluates the entire set, not only the first address. If one answer violates the parent address scope, reject the whole set. Do not silently drop a private/metadata answer and keep the public one.

For Prism public-web traffic, the parent scope should be public-unicast-only and reject loopback, private, link-local, metadata, multicast, unspecified, special-use and transition ranges according to the reviewed policy corpus. LAN/browser navigation is a different workload and authority profile; it must not inherit public-web exceptions or vice versa.

Every approved address is bound to the exact transport port. A lease cannot authorize arbitrary ports on an approved IP.

### 4.4 Local broker identity

The privileged Nixward broker—not the Prism request handler—owns kernel map updates. It must authenticate the requesting service over a local IPC channel and bind that caller to:
- exact systemd unit / guest runtime identity;
- stable cgroup-v2 identity (and inode/path observation);
- exact NixOS system closure / workload artifact identity;
- current parent policy digest and generation.

Do not rely on a caller-supplied PID or cgroup path as proof. Resolve process identity using a race-resistant OS mechanism, then verify the cgroup binding at the mutation boundary. A stale PID, moved process, changed cgroup, or unknown workload blocks the lease.

The Prism service gets no BPF map file descriptor, bpffs write permission, or general firewall mutation API.

### 4.5 Separate policy from reasoning

Symthaea, HDC similarity, Phi, anomaly detection and natural-language approval can recommend or explain. They never mint or widen a network capability. Existing Nixward `reasoning_authority = "none"` and telemetry `network_enforcement_authority = false` invariants remain mandatory.

## 5. Proposed versioned wire contract

The JSON Schema is `docs/schema/prism-nixward-resolution-lease-v1.schema.json`; a valid illustrative instance is `docs/fixtures/prism-nixward-resolution-lease-v1.json`.

The lease binds:
- schema/version and unique lease ID;
- Holon, workload digest, network policy digest and parent capability digest;
- exact canonical A-label hostname;
- TCP protocol and exact destination port;
- sorted, unique, complete IPv4/IPv6 address list;
- resolver profile and resolver snapshot digest;
- issue time and expiry;
- parent policy generation and one-shot nonce;
- opaque logical request ID and redirect-hop index.

The lease intentionally excludes URL path, query, credentials, request/response bodies, cookies, Authorization headers, and other payload content. A public IP and hostname may still be sensitive operational metadata; storage/telemetry should use a digest or short-lived encrypted record where possible.

The wire object is **not authority by itself**. The broker accepts it only with authenticated IPC caller identity and a verified owner/delegation authorization for the exact parent capability. Any detached signature/evidence envelope must bind the canonical lease bytes and the parent authority evidence. A BLAKE3 digest alone does not prove who issued a lease.

### 5.1 Lease lifetime

The effective expiry is the minimum of:
- resolver snapshot `valid_until`;
- parent capability / delegation expiry;
- Prism's own short capability expiry;
- the Nixward policy's configured maximum resolution-lease duration.

A starting design target is a **maximum 5-second lease**, but the actual value must never exceed the resolver-derived validity. This is a proposal, not an existing guarantee.

At broker activation, convert the remaining wall-clock validity into a kernel monotonic deadline using the broker's own clock. Never trust a caller-supplied monotonic timestamp. When the DNS validity is unknown or expired, require a new resolution snapshot.

A lease covers one logical HTTP hop and its bounded authorized connection attempts to the same address set. A redirect, application retry, authority change, or policy-generation change requires a new lease. Prism currently disables implicit transport retries; keep that invariant.

### 5.2 DNSSEC is not implied

An authenticated local resolution lease proves that the Nixward broker issued a bounded decision under its configured resolver/trust policy. It does not automatically mean DNSSEC was validated. The resolver profile must separately report DNSSEC state (validated / not validated / unsupported / indeterminate); the policy decides whether it is required. Do not label a lease DNSSEC-authenticated unless the resolver actually validates the chain and the evidence binds that validation.

## 6. State machine

```text
Prism requests hostname + parent capability + logical hop identity
  → Nixward authenticates caller and exact workload/cgroup
  → validates parent owner/delegation authority and policy generation
  → resolves A/AAAA and obtains CNAME/TTL/validity metadata
  → validates complete address set against explicit scope
  → constructs canonical lease and consumes nonce
  → stages per-workload IP:port rules in an inactive map generation
  → verifies map contents/digest and binding
  → atomically switches active generation
  → returns verified lease to Prism
  → Prism pins HTTP transport to the exact addresses and original hostname
  → kernel cgroup hooks admit only the leased IP:port set until monotonic expiry
  → Prism verifies actual remote_addr membership and TLS hostname
  → both planes emit redacted, correlated evidence
  → lease expires or is explicitly revoked; stale map entries are inert
```

### Atomicity and failure behavior

- A partially staged map generation must never become active.
- If map population, digest verification, cgroup binding, program attachment, generation switch or receipt persistence has an unknown outcome, the broker reconciles actual map/attachment state before retrying.
- Unknown outcome means no new grant. Preserve the previous known-good static NixOS/nftables baseline; do not silently replace it with a broader allow rule.
- The cgroup program must deny destinations not in the active set, including IPv4 and IPv6 paths and the relevant TCP socket hooks.
- UDP/QUIC/HTTP/3 must remain denied unless explicitly modeled, tested and parent-authorized. Prism's current v1 transport profile is TCP HTTP(S).
- A lease expiry must be enforced by kernel monotonic time, not by a userspace timer alone.
- A resolver change, cgroup move, workload restart, policy-generation change or owner revocation invalidates outstanding dynamic leases.
- Preserve deliberate LAN access only under a distinct workload and explicit user-navigation capability. Do not globally allow RFC1918 to make browser navigation work.

## 7. Evidence model

Prism and Nixward should emit separate records with a shared opaque `logical_request_id` and per-hop identifier.

**Prism application receipt**
- exact authority/policy version and sanitized origin;
- address-set digest, peer address and `remote_addr` check;
- TLS hostname/certificate result, protocol, status;
- redirect hop, retry decision, bytes, duration and body-lease lifecycle;
- binary/source revision and egress-capability ID.

**Nixward kernel lease/activation evidence**
- parent capability/policy digests and generation;
- workload digest, cgroup identity and kernel/BPF program identity;
- resolver profile/snapshot digest and validity interval;
- staged/active map generation and exact address/port rule digest;
- metadata-only connect/sendmsg admission observation and lease expiry/revocation outcome.

A cgroup `connect4/connect6` hook is an admission/connection-attempt observation point; it does not on its own prove that a TCP handshake completed or identify the authenticated TLS peer. Prism's transport-level peer observation remains necessary. The kernel observation is independent corroboration that the protected workload could not bypass the approved address/port set.

Network telemetry remains payload-free. Avoid storing URL paths, query strings, cookies, headers, bodies or raw user identifiers in the shared ledger. The existing five-minute telemetry time bucket is appropriate for general monitoring, but a bounded short-lived incident correlation record may need a separate, access-controlled retention policy; do not weaken the default telemetry policy globally.

Hash chains and digests establish integrity/linkage, not issuer authenticity. Signed attestations require a concrete signing/verifying provider, key custody, trust policy, rotation/revocation and offline verifier. Production activation still requires the existing exact owner-authorized Nixward activation flow.

## 8. Security and conformance corpus

The new fixture file defines positive and negative cases for the bridge. The executable implementation should extend the current 14-case runtime lab with, at minimum:

1. exact authorized FQDN + IPv4/IPv6 set + port admitted;
2. public + private mixed answer set rejected as a whole;
3. metadata/loopback/link-local/special-use answer rejected under public-only scope;
4. A/AAAA NODATA handling and incomplete answer-set rejection;
5. CNAME chain, loop, excessive chain and malformed DNS response;
6. UDP TC=1 followed by TCP retry to the same resolver;
7. TTL expiry while a request is waiting to connect;
8. DNS rebinding after lease issuance; no new address can connect;
9. redirect to a second approved public hostname obtains a new lease;
10. redirect to private/metadata/localhost obtains no second lease;
11. lease bound to a different workload, cgroup, parent capability or policy generation is rejected;
12. expired/revoked/replayed nonce rejected, including after broker restart;
13. partially staged map update and failed generation swap preserve fail-closed state;
14. IPv4/IPv6/TCP socket attempts from a second process in the same cgroup are denied outside the set;
15. moving a process to an unbound cgroup does not inherit another workload's authority;
16. broker restart, stale maps, cgroup rebind and attachment loss fail closed;
17. Prism's observed peer must belong to the exact lease set and original hostname TLS checks remain active;
18. no raw payload or URL secrets appear in telemetry/evidence.

The existing lab's port-only BPF map is useful for testing cgroup hook semantics, lease clocks and generation swaps. It must be extended to exact IPv4/IPv6 address sets and port matching before it can qualify this integration. Do not describe the current lab as already enforcing this entire protocol.

## 9. Benchmark plan: PEAB × Nixward runtime lab

Compare four distinct configurations on the same machine, same fixtures and same policy corpus:

| Profile | Application controls | Kernel/workload controls |
|---|---|---|
| A | Hardened Reqwest reference | None (baseline only) |
| B | Prism egress capability + DNS pinning | None |
| C | No Prism application policy | Nixward workload/cgroup egress policy |
| D | Prism + Nixward resolution lease + cgroup BPF | Both |

Profile A without hardening is a performance floor only. Profile C is not a valid HTTP-authority control; it should fail application-layer SSRF scenarios that require URL/method/redirect interpretation. Profile D is the target layered architecture.

Measure:
- unauthorized socket attempts and successful connections outside the lease set (hard gate: zero);
- policy/authority mismatch, stale lease, DNS rebinding and redirect escape outcomes;
- resolver p50/p95/p99 and DNS query count;
- lease issuance/map staging/atomic generation switch p50/p95/p99;
- added connect latency and total HTTP-hop p50/p95/p99;
- throughput, CPU, BPF map occupancy/update rate, task/FD count and cgroup memory;
- recovery latency after broker restart, map failure, cgroup rebind and policy revocation;
- resolver-outage behavior, availability and false-positive rate for the allowed corpus.

Use cold/warm DNS and cold/warm connections as separate strata. Use at least five independent runs per configuration, retain raw samples and failed runs, randomize configuration order, and publish 95% confidence intervals. Start with 10,000 seeded adversarial sequences per scenario family; grow to one million for the long-running campaign. No weighted aggregate score can compensate for a security-gate failure.

Industry comparisons should include:
- Envoy Dynamic Forward Proxy with `resolved_address_filter` and its documented DNS cache/stale-refresh behavior;
- Cilium FQDN policy with its DNS-proxy/trusted-resolver assumptions;
- Prism alone and Nixward cgroup enforcement alone;
- the composed Prism+Nixward design.

This is a stronger comparison than feature counts: it distinguishes application authority, kernel containment, operational cost and what each plane cannot prove.

## 10. Work sequence and acceptance gates

### M0 — Contract (this PR)
- Freeze the JSON schema and examples.
- Review parent policy address-scope semantics and resolver trust profile.
- Agree on nonce, exact workload identity, map-generation and privacy fields.

### M1 — Pure Nixward model (no kernel writes)
- Add a typed `NetworkResolutionLeaseV1` model and canonical digest.
- Validate exact policy/workload/parent-capability binding, hostname, TCP port, addresses, expiry, nonce, generation, and full-set policy.
- Verify signed/delegated authority separately from schema validity.
- Add property/mutation tests for all lease fields and policy mismatches.

### M2 — Resolver broker
- Add an explicit resolver adapter with complete A/AAAA/CNAME/TTL semantics.
- Add deterministic DNS wire tests for mixed answers, malformed/slow replies, rebinding, TTL, UDP truncation/TCP fallback and resolver-profile changes.
- Do not issue a kernel lease without a trusted resolver snapshot and valid expiry.

### M3 — Kernel address-set runtime lab
- Extend the test-only cgroup-BPF map from one port/mode to bounded IPv4/IPv6 address+port sets and exact workload bindings.
- Add atomic multi-entry generation transitions and monotonic lease expiry.
- Exercise the second-process bypass and failure/recovery cases in disposable NixOS VMs.

### M4 — Prism adapter
- Obtain one Nixward lease before a logical HTTP hop.
- Pass the exact lease address set directly into `resolve_to_addrs`; never perform an independent second DNS lookup.
- Preserve the original hostname for Host/SNI/certificate verification; require peer membership.
- Renew for every redirect/retry/authority transition.
- Correlate receipts with the kernel lease while keeping payloads/URL secrets out of telemetry.

### M5 — Owner-authorized pilot
- Require exact target system closure, reviewed BPF object digest, target-host feature/binding proof, allow/deny smoke tests, preservation of baseline firewall, and detached owner authority for `network-activate`.
- Begin with one disposable NixOS VM and one noncritical Prism workload.
- No fleet-wide activation or default policy broadening.

**Release blockers:** no production use until the resolver source and DNS TTL are authenticated under the selected trust model; parent policy has an explicit address scope; cgroup enforcement is tested against exact IP sets; stale/replay/failure modes are independently observed; and the owner-authorized target-host activation receipt is verified.

## 11. Explicit non-claims

This proposal does not claim:
- that Nixward currently enforces Prism hostname/IP leases in production;
- that the existing 14-case runtime lab checks exact DNS-derived IP sets;
- that Prism receipts are currently signed or independently kernel-attested;
- that DNSSEC is validated by the current resolver;
- that cgroup socket hooks prove completed TCP connections or TLS identity;
- that an owner-approved hostname is automatically a safe public destination;
- that a passing lab is production activation authority;
- that the combined system is faster or more secure than Envoy/Cilium before matched PEAB runs.

## 12. References

- Nixward network OS architecture and existing task/evidence corpus: https://github.com/Luminous-Dynamics/nixward/pull/67
- Nixward deterministic fault harness: https://github.com/Luminous-Dynamics/nixward/pull/71
- Nixward offline Netlink evidence verifier: https://github.com/Luminous-Dynamics/nixward/pull/72
- Nixward current network covenant, enforcement, runtime lab, telemetry and activation modules: `src/network_covenant.rs`, `src/network_enforcement.rs`, `src/network_runtime_lab.rs`, `src/network_telemetry.rs`, `src/network_activation.rs`
- Prism implementation and PEAB protocol: https://github.com/Luminous-Dynamics/mycelix/pull/6299
- Symthaea browser URL preflight: https://github.com/Luminous-Dynamics/symthaea/blob/main/crates/domains/symthaea-browser/src/safety.rs
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Envoy Dynamic Forward Proxy DNS cache: https://www.envoyproxy.io/docs/envoy/v1.40.0/api-v3/extensions/common/dynamic_forward_proxy/v3/dns_cache.proto
- Cilium DNS-based policy: https://docs.cilium.io/en/stable/security/dns/


## 13. Industry semantics reviewed on 2026-11-18

The comparison is not that Envoy or Cilium lacks DNS security. Both have mature mechanisms and important trade-offs PEAB must model.

### Envoy Dynamic Forward Proxy

Envoy resolves asynchronously, can use the DNS record TTL with a configured minimum refresh interval (documented default 5 seconds), supports a resolver timeout, host-cache bounds and pending-request circuit breakers, and can filter resolved addresses. Its TLS integration can set SNI and verify the upstream SAN against the resolved hostname.

A critical semantic: if a refresh returns only addresses excluded by `resolved_address_filter`, Envoy treats resolution as failed and retains the previously resolved host entry. This is documented behavior, not automatically a vulnerability. It makes the stale-answer transition a mandatory PEAB test: determine whether an older cached address remains usable, whether active connections survive, and how expiry/host removal interacts with a request.

### Cilium FQDN policy

Cilium obtains IPs by observing DNS proxy responses, caches them with DNS TTL semantics and turns matching names into L3 CIDR-like policy entries, which can be combined with L4 port restrictions. The threat model explicitly trusts the intercepted DNS responses from configured cluster DNS servers. Documentation also notes that IP observations from multiple pods managed by the Cilium instance can be used for the matching domain. This is a workload-policy learning model, not a per-HTTP-request signed resolution lease.

Cilium's conntrack lifecycle is another important distinction: expired DNS entries may remain deferred while connection tracking determines whether an existing flow still uses them. Existing connections can remain allowed; a new connection after expiry requires refreshed DNS state. PEAB should measure both existing-flow and new-flow behavior around TTL expiry and DNS-proxy/agent restart.

### What the proposed composition should test differently

- Scope each lease to an exact workload identity, parent capability, hostname, port, policy generation and one logical HTTP hop.
- Carry the same complete A/AAAA snapshot into both Prism's `resolve_to_addrs` pin and Nixward's exact IP:port cgroup rule.
- Expire on the earliest of resolver validity, parent-authority expiry, Prism capability expiry and the local policy maximum. Envoy's minimum DNS refresh interval is not a substitute for a per-request lease expiry.
- Require a fresh lease on each redirect or retry; do not inherit the first hop's IP set or trust context.
- Keep both existing-flow and new-flow semantics explicit: a kernel cgroup lease is intended to bound new socket admission; it does not terminate an already established socket by itself. If the policy requires revocation of existing sessions, that needs a separate, tested connection teardown mechanism.

References:
- Envoy v1.40.0 DNS cache: https://www.envoyproxy.io/docs/envoy/v1.40.0/api-v3/extensions/common/dynamic_forward_proxy/v3/dns_cache.proto
- Envoy HTTP dynamic forward proxy architecture: https://www.envoyproxy.io/docs/envoy/v1.40.0/intro/arch_overview/http/http_proxy
- Cilium DNS policy and trusted DNS assumption: https://docs.cilium.io/en/stable/security/dns/
- Cilium Layer 7 DNS proxy / FQDN policy: https://docs.cilium.io/en/stable/security/policy/layer7/
- Cilium FQDN cache / conntrack expiry behavior: https://docs.cilium.io/en/latest/contributing/development/debugging/
- OWASP SSRF guidance: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
