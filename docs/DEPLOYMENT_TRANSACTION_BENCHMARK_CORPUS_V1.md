# Deployment transaction benchmark corpus v1

Status: **machine-readable workload definitions; proposed, not executed**

This corpus makes the deployment benchmark reproducible at the scenario-definition layer. It is deliberately separate from a runner: it contains no commands that can mutate a host, no credentials, and no automatic test execution.

## Comparison model

The benchmark compares an approved transaction and its observed effect, not just a deploy command's elapsed time.

Baseline roles are intentionally different:
- NixOS rebuild is the native activation baseline. \`switch\`, \`test\`, and \`boot\` must remain separate outcome classes.
- Colmena is the fleet-scheduling baseline. Start with one node, then measure concurrency separately.
- deploy-rs is the remote multi-profile and connectivity-confirmed rollback baseline.
- Nixward direct-spawn is its current transaction path.
- Nixward systemd is explicitly gated until the authority, persistence and VM requirements have been met.
- SQLite admission is only a storage microbenchmark.

## Scenarios

The 19 scenarios cover:
- no-op admission and normal exact-closure switch;
- Colmena and deploy-rs fleet-throughput baselines at concurrency limits of 1, 5 and 10, without making an unsupported Nixward fleet claim;
- NixOS test vs boot semantics;
- successful activation and failed activation reconciliation;
- lost StartUnit response and missing/reordered JobRemoved;
- supervisor death before and after payload release;
- systemd manager restart and host reboot;
- remote confirmation network loss;
- independent and contending transaction admission;
- pre-commit database failure, lost commit acknowledgement and WAL/checkpoint performance.

Each scenario includes preconditions, an explicit fault boundary where relevant, required independent observations, allowed terminal disposition, forbidden claims, supported comparison baselines, metric tags, a trial class and minimum trial count. Clean latency baselines and performance profiles require at least 30 trials; fault, concurrency and storage-correctness profiles require at least 100.

## Trial and evidence rules

- Clean functional latency baselines and explicitly tagged performance profiles start at 30 trials.
- Fault, concurrency and storage correctness screens start at 100 trials per scenario.
- Use at least 1,000 trials for stable p99 estimates where tail latency is a release claim. The fleet-throughput baseline is a clean performance profile (minimum 30 repetitions) and must keep the Nixward fleet result explicitly unavailable until a comparable scheduler exists.
- Preserve raw data, all excluded trials and reasons, fault seeds, source SHAs and the exact VM/storage configuration.
- Separate build, closure copy, profile selection, activation, admission, worker attribution, post-state observation and reconciliation.
- Report safe holds independently from successful recovery. A correct hold is not a successful recovery.
- A benchmark corpus passing structural validation is not a benchmark run and is not evidence of a production supervisor.

## Structural checks

The companion JSON Schema defines the data format. The Nix flake check additionally enforces the normative scenario IDs, vector count, category, operation mode, minimum trials, required fault descriptions and allowed baseline identifiers.

## Next implementation gate

Issue #113 tracks the executable harness. The implementation should consume this corpus and produce one canonical per-trial record, then an independent verifier should recompute scenario classification from raw observations rather than trusting the runner's summary.
