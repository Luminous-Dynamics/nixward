# Systemd-Owned Transaction Crash-Cut Qualification v1

**Status:** research plan and machine-readable matrix only. No disposable-VM crash campaign has run; no journal durability, privileged worker, systemd runtime or power-loss guarantee is claimed.

## 1. Why this qualification exists

The pure Rust systemd_job_evidence contract and pure Nix supervisor-temporal-trace reference model encode ordering and identity rules. PR #94 adds a crate-private zbus observer for StartUnit and JobRemoved. These are useful layers, but none of them establishes behavior across an actual process crash, system-manager re-exec, VM reboot, or failed storage write.

The new matrix in docs/fixtures/systemd-transaction-crash-cuts-v1.json decomposes the transaction into irreversible boundaries. The objective is not "did systemd return done?" The objective is whether Nixward can recover one exact attempt, prevent duplicate payload execution, and prove the actual target postcondition—or remain safely indeterminate.

## 2. Four fault models; do not conflate them

### A. Supervisor process crash

Only Nixward's control/supervisor process is killed. The system manager, worker process, kernel and virtual disk remain alive. This tests ownership separation and whether the restarted supervisor can reconcile surviving state.

### B. System-manager restart/re-exec

The service manager's process/runtime state is deliberately disrupted inside an isolated disposable guest. The exact semantics depend on the systemd build and the chosen test mechanism. This is not equivalent to a Nixward daemon restart. The journal remains the Nixward transaction authority; manager signals and transient unit state are supplementary observations.

### C. VM reboot or abrupt virtual poweroff

The entire guest loses volatile memory and process state. A graceful guest shutdown is not a power-cut test. An abrupt hypervisor termination followed by booting the same captured virtual disk can test the behavior of the exact guest filesystem and virtual storage stack, but does not establish real physical device power-loss guarantees.

### D. Storage I/O failure

Errors are injected around temporary-file write, file fsync, atomic rename, parent-directory fsync, and terminal-receipt publication. A successful write or file fsync call alone is not the full publication protocol. The exact guarantees depend on the filesystem, mount options, kernel, virtual block device and host storage stack. Record the entire stack and do not generalize results beyond it.

## 3. Non-negotiable invariants

- The existing Nixward transaction journal and cross-process interlock remain the sole Nixward transaction authority. This qualification adds no second journal or lock.
- The system manager owns worker process lifetime; it is not treated as a durable transaction ledger.
- StartUnit returning a job object path means a start job was enqueued, not that the worker ran or that a host operation succeeded.
- JobRemoved completion means a manager job completed, not that the process receipt exists or the running NixOS closure/profile is correct.
- A lost StartUnit reply remains ambiguous. Never replay the same attempt. Missing unit/signal after reboot is not proof that the attempt never ran.
- The exact worker InvocationID and process identity must be durably bound to the attempt before a payload-release capability is consumed.
- Once payload release is possible, participant effects are reconciled against that same attempt; transport retries cannot imply safe operation retries.
- Terminal success requires a durable process-exit receipt and a fresh independent observation of the running closure and selected profile.
- No live NixOS activation is executed in v1 qualification. Use only a harmless, fixed, test-only one-shot worker and mock participant.

## 4. Corpus design

The machine-readable matrix defines 15 cuts (C001–C015), plus controls:

| Cut family | IDs | What must be established |
|---|---|---|
| Before/after write-ahead publication | C001–C003 | StartUnit cannot precede a successful durable barrier; once the barrier exists, recovery—not replay—is required |
| Ambiguous manager submission and job evidence | C004–C006 | Exact direct reply, job object path and JobRemoved are separately persisted and reconciled |
| Worker identity and payload release | C007–C009 | The payload cannot execute before the exact unit invocation/process identity is durably bound |
| Exit and target-state verification | C010–C012 | Process exit, fresh target observation and terminal journal commit are separate |
| Manager restart, VM reboot, storage failure | C013–C015 | Volatile manager state loss and partial disk writes never erase attempt ambiguity |

Each cut includes the fault type, injection point, durable prefix, manager/process state, allowed disposition, required evidence and safety invariant. Every cut explicitly forbids same-attempt replay. C001 is the only cut where a new attempt may be prepared, because the write-ahead boundary has not yet been crossed and the manager call is forbidden.

The matrix is a specification corpus, not an executable VM test result. The Rust regression test only guards the corpus structure and safety declarations.

## 5. Qualification stages

### Stage 0 — pure contract

Run the existing systemd_job_evidence Rust tests, the pure Nix temporal vectors, and the new crash-cut corpus test. These validate the model and matrix only.

### Stage 1 — fake D-Bus adapter

Drive the adapter against a controlled fake manager implementing the exact relevant D-Bus method/signal surface. Inject:
- subscription registration failure;
- Manager.Subscribe failure;
- explicit StartUnit method rejection;
- accepted request with dropped direct reply;
- matching and unrelated JobRemoved orderings;
- mismatched job ID/object path/unit identity;
- duplicate start request for one canonical unit.

Check the actual number of StartUnit calls. A rejected/ambiguous case must never trigger an automatic second call.

### Stage 2 — disposable NixOS VM

Pin and retain:
- Nixward exact head SHA and Cargo.lock digest;
- flake.lock and Nixpkgs revision;
- kernel and systemd versions;
- VM config digest and virtual disk base-image digest;
- worker executable derivation/store path and digest;
- journal format/version and test policy;
- injected fault ID and deterministic injection marker.

Declare a static test-only one-shot systemd unit in the NixOS VM. It must run one fixed store-path executable, have a fixed argument vector, a bounded deadline, least privilege, no agent-supplied unit properties, and no live NixOS activation capability. The test worker reports its own invocation identity and produces a deterministic harmless output. The mock participant has a separate attempt/effect ledger.

For every crash cut, preserve the exact pre-crash journal bytes and digest, systemd unit/job state, InvocationID, process/cgroup identity where available, payload-release marker, participant attempt/effect ledger, process receipt, target probe output and final verifier report. The harness must retain every started trial, including crashes, timeouts and indeterminate cases.

### Stage 3 — abrupt VM poweroff and storage errors

Use a disposable virtual disk and an explicitly documented hypervisor/block-device fault model. Inject abrupt VM termination at deterministic points after write-ahead publication and around storage commit boundaries. Reboot the exact disk image and compare recovered journal state with the independent mock participant ledger and manager/runtime observations.

Do not infer physical power-loss guarantees from QEMU process termination. For a meaningful claim, record whether the test only covers guest process termination, guest kernel reboot, hypervisor termination, virtual block-cache loss, or a documented host storage power-cut model.

## 6. Evidence schema for each run

A per-cut receipt should contain:
- campaign_id, cut_id, trial_id, seed, and expected disposition;
- exact Nixward, Nixpkgs, kernel, systemd, QEMU/hypervisor and VM config pins;
- initial virtual disk digest and captured post-crash disk digest;
- journal record sequence, content digests and publication outcome at each boundary;
- transaction ID, attempt ID, purpose, canonical unit name and exact StartUnit reply;
- JobRemoved tuple from the same signal: numeric job ID, object path, unit name and result;
- systemd InvocationID, main-process identity/cgroup, exit code and timestamps when available;
- payload-release evidence and number of payload invocations;
- participant accepted/effect/reconciliation records;
- fresh running-closure and selected-profile observation;
- verifier version/digest, raw output digest, and final valid / invalid / indeterminate disposition.

Never store secrets, private keys, bearer tokens or raw customer data in the public corpus. Keep identifiers synthetic and content-addressed.

## 7. Promotion gates

The initial VM corpus is qualified only when:
1. Every declared crash cut and positive/negative control has executed on the exact recorded environment.
2. No StartUnit call occurs before the durable write-ahead barrier.
3. Zero duplicate worker payload releases or duplicate mock participant effects occur in canonical fault cases.
4. An ambiguous manager reply never produces same-attempt replay.
5. No payload is released before exact worker identity and authorization binding is durable.
6. No terminal success is recorded without process-exit receipt and fresh target observation.
7. Missing or contradictory evidence remains rejected or indeterminate; no case is silently omitted.

A power-loss durability claim requires a separate, narrowly stated qualification of the exact filesystem, kernel, mount, virtual/physical block device, controller and power-failure model. A successful synthetic or VM run is not a universal storage guarantee.

## 8. Relationship to the current PRs

- PR #94 provides the optional crate-private observer; it remains unwired until the worker/unit, journal-owned supervisor and VM campaign are qualified.
- The existing pure Rust and Nix reference models remain useful, but neither substitutes for live systemd or storage tests.
- The Platform #174 verifier consumes producer evidence and checks causal/attempt semantics. It does not take ownership of Nixward's host transaction journal.
- Platform Saga coordinates cross-service effects; it must not duplicate Nixward's local host transaction authority.
