#!/usr/bin/env python3
import json, re, sys
from pathlib import Path

REQUIRED = {
    "feature-probe", "ipv4-allow", "ipv4-deny", "ipv6-allow", "ipv6-deny",
    "udp-allow", "udp-deny", "lease-active", "lease-expired", "policy-swap",
    "cgroup-rebind", "enforcer-restart", "stale-policy-replay",
    "attach-failure-fail-closed",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

if len(sys.argv) != 2:
    raise SystemExit("usage: verify-runtime-report.py REPORT.json")
obj = json.loads(Path(sys.argv[1]).read_text())
assert obj["schema_version"] == 1
assert obj["backend"] == "cgroup-sockaddr-bpf-contract-v40"
assert obj["status"] == "isolated-runtime-lab-v42"
assert obj["isolated_environment"] is True
assert obj["payload_capture"] is False
assert obj["production_activation_performed"] is False
assert obj["reasoning_authority"] == "none"
assert obj["nixos_system"].startswith("/nix/store/")
assert HEX64.fullmatch(obj["harness_blake3"])
cases = obj["cases"]
assert {c["kind"] for c in cases} == REQUIRED
for case in cases:
    assert case["passed"] is True, case
    assert HEX64.fullmatch(case["evidence_blake3"])
v44 = obj.get("v44_execution")
assert v44 and v44["status"] == "executed-runtime-lab-v44"
assert v44["required_case_count"] == 14
assert v44["production_activation"] is False
assert HEX64.fullmatch(v44["runner_blake3"])
assert HEX64.fullmatch(v44["bpf_object_blake3"])
print("V44 runtime report: 14 required cases executed and passing; production activation not claimed")
