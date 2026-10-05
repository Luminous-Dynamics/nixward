# V42 Network Enforcement Runtime Lab

This is a disposable NixOS VM acceptance harness for the reviewed V40
`cgroup-sockaddr-bpf-contract-v40` backend. It is deliberately **not** a
production loader.

The lab must prove all mandatory V42 cases before the backend can receive a
`runtime-lab-proven-v42` attestation. Even a passing lab does not activate a
production Holon; target-host feature/binding proof plus a separate owner
covenant are still required.

Required cases:

1. feature probe
2. IPv4 allow
3. IPv4 deny
4. IPv6 allow
5. IPv6 deny
6. UDP allow
7. UDP deny
8. lease active
9. lease expired
10. policy swap
11. cgroup rebind
12. enforcer restart
13. stale-policy replay rejection
14. attachment failure fails closed

`network_guard.bpf.c` is intentionally tiny and test-only. The runtime test
compiles it inside the NixOS VM against the exact test closure and uses bpftool
to attach it to disposable cgroups. No packet payload capture is needed.
