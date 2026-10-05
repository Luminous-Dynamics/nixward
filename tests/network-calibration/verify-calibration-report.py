#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
HEX64 = re.compile(r"^[0-9a-f]{64}$")
if len(sys.argv) != 2:
    raise SystemExit("usage: verify-calibration-report.py REPORT.json")
r = json.loads(Path(sys.argv[1]).read_text())
assert r["schema_version"] == 1
assert r["model_family"] == "hdc-behavior-distance-v1"
assert HEX64.fullmatch(r["corpus_blake3"])
assert r["status"] == "measurement-only-v43"
assert r["threshold_selection"] == "explicit-candidate-not-auto-optimized-v43"
assert r["autonomous_response_eligible"] is False
assert r["quarantine_authority"] is False
assert r["network_enforcement_authority"] is False
assert r["evaluated_model_samples"] == r["true_positive"] + r["false_positive"] + r["true_negative"] + r["false_negative"]
for key in ["novelty_threshold_milli", "precision_milli", "recall_milli", "false_positive_rate_milli", "false_negative_rate_milli", "median_novelty_milli", "p95_novelty_milli"]:
    assert 0 <= r[key] <= 1000
print("V43 calibration report: measurement-only evidence is internally consistent")
