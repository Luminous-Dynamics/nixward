# V43 Network Cognition Calibration Corpus

V43 measures the existing `hdc-behavior-distance-v1` model without granting it
any authority. A calibration set has an explicit baseline split and an explicit
evaluation split.

Evaluation labels have different meanings:

- **in-distribution** — expected behavior similar to the baseline;
- **benign-novel** — legitimate behavior that may look unusual and therefore
  directly measures false-positive pressure;
- **synthetic-anomaly** — a deterministic test behavior used to measure whether
  novelty evidence can separate the fixture from expected behavior;
- **policy-contradiction** — reported separately, never counted as an AI/model
  true positive because the Network Covenant already knows it is unauthorized.

No threshold produced by V43 can enable blocking, quarantine, capability
minting or autonomous response. Threshold candidates are explicit inputs rather
than automatically optimized against the evaluation set.
