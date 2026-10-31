# Systemd and NixOS semantic execution evidence v1

Status: **specification and deterministic verifier contract; no live supervisor integration**

This specification follows the artifact-integrity verifier (#119/#120). It defines how a future independent semantic verifier derives transaction outcomes from raw systemd manager events, process identity, durable admission records and actual NixOS host state. The verifier must not trust runner-authored success labels, summary counters or an exit code as ground truth.

## 1. Evidence sources and authority

The semantic verifier consumes independently captured sources:

1. Nixward admission-store read-back and immutable event journal, including transaction, attempt, replay, permit, plan and machine-binding digests.
2. The supervisor's D-Bus subscription/start request/reply trace.
3. systemd manager JobNew/JobRemoved events and unit property snapshots.
4. PIDFD-to-unit attribution from the systemd manager, plus a process start tuple tied to the kernel boot ID.
5. Raw journal entries and worker receipt bytes.
6. NixOS active profile, running-system path, boot-default profile, and post-activation service/runtime observations.
7. The exact plan operation mode, expected closure and the policy/provenance receipt.

The independent verifier is read-only. It does not start, stop, restart or repair services, call StartUnit, mutate profiles, or rewrite an admission record.

## 2. Race-free systemd job correlation

The manager API documents that callers should subscribe to JobRemoved before calling StartUnit, then filter the returned job to observe the actual start operation. JobRemoved reports the job ID, job object path, primary unit name and result. Results include done, canceled, timeout, failed, dependency and skipped.

The minimum acceptable dispatch sequence is:

1. Commit and read back the single admission identity. No payload is released yet.
2. Establish the D-Bus JobRemoved subscription and record the manager connection/boot context and monotonic subscription time.
3. Call StartUnit exactly once for the expected unit and mode; retain the returned job object path and request/reply timestamps.
4. Correlate only the JobNew/JobRemoved events for that exact returned job object, numeric job ID and expected unit. Ignore unrelated jobs even when they refer to the same unit name.
5. Capture the final unit property snapshot and InvocationID. A manager event from a different manager epoch or kernel boot cannot complete this attempt.
6. Do not treat JobRemoved=done as transaction success. Continue to worker and NixOS post-state checks.

An absent StartUnit reply is ambiguous: the manager may have accepted the job while the response was lost. The same transaction/replay must be reconciled against the existing job and attempt; never blindly submit a second StartUnit.

The verifier must preserve the raw event order. A reordered, missing, duplicated or uncorrelated JobRemoved event is not silently repaired by sorting or selecting the most convenient event. It becomes reconciliation-required unless a uniquely attributable manager snapshot closes the ambiguity.

## 3. Worker identity and PID reuse

A PID is not a durable identity. systemd 253+ exposes Manager.GetUnitByPIDFD, which accepts a Linux pidfd and returns the unit ID, invocation ID and unit object path. This is safer than GetUnitByPID because the numeric PID may be recycled.

For a qualified Nixward worker path:

- obtain a pidfd while the worker is known to be alive;
- ask the manager to map that pidfd to its unit identity;
- retain the returned unit ID, InvocationID and object path;
- bind these to transaction ID, attempt ID, admission commit ID, plan digest and machine binding before releasing the payload;
- also record the kernel boot ID, numeric PID and process start-time tuple for durable audit/reconciliation;
- never use a PID-only match, unit-name-only match or caller-supplied InvocationID as proof.

A pidfd is a live file descriptor, not a durable object that can be restored after supervisor restart. Persist the manager-derived unit/invocation values and process-start tuple; after restart, re-query the manager and re-establish identity. If the original invocation cannot be uniquely distinguished, hold rather than substitute a new worker.

If the deployment target uses a service type whose main process is expected to exit (for example, a oneshot worker), ActiveState=inactive is not automatically failure. Derive the expected unit state from the declared service type and operation contract, and require Result, InvocationID, journal and worker receipt to agree.

## 4. NixOS post-state is operation-specific

The NixOS Manual distinguishes these operations:

| Operation | Running system | Boot default |
|---|---|---|
| switch | activate candidate | candidate |
| test | activate candidate | predecessor remains default |
| boot | do not activate candidate now | candidate |
| build | no activation/profile switch | unchanged |

The semantic verifier must compare the observed active and boot profiles against the exact intended semantics. A generic assertion that "candidate generation is current" is wrong for boot-only and build-only operations. For switch/test/boot, record the precise candidate and predecessor store paths and independently read the system profile, /run/current-system and bootloader/default-generation evidence. A symlink path string alone is not enough: resolve it, confirm it refers to the expected immutable store path, and bind the observation to the same boot/attempt context.

The running service state must be checked separately. A completed system switch does not prove every service reached its expected state. Collect manager state (ActiveState, SubState, Result, InvocationID), relevant journal window, and domain-specific health probes. For NixOS switch, the manual also notes that user services are not generally started/stopped automatically by nixos-rebuild; do not infer user-service success from system-level activation.

## 5. Derived terminal classifications

The verifier derives one of four outcomes:

- **verified-success** — exact durable admission, one attributable dispatch, matching job result, correct worker/unit invocation, exact operation-specific NixOS post-state and all required runtime health checks.
- **verified-recovery** — the candidate failed or was rolled back, and the predecessor's active/boot/runtime state is independently verified according to the recovery contract.
- **reconciliation-required** — an operation may have been accepted or partially executed, but the evidence cannot yet determine the unique state or identity.
- **safe-hold** — no further mutation is authorized; the system remains fenced pending explicit recovery/inspection.

Safe-hold and reconciliation-required are not success. A rollback command exit code, systemd result=done, health endpoint alone, or active-profile symlink alone cannot produce verified-success.

## 6. Negative-control matrix

The semantic verifier must reject false success for at least these cases:

| Injected condition | Required classification |
|---|---|
| JobRemoved arrives before subscription or is missing | reconciliation-required / safe-hold |
| JobRemoved refers to a different job ID/object path | reject event; do not close attempt |
| JobRemoved unit name differs from the requested unit | reconciliation-required |
| JobRemoved result is canceled, timeout, failed, dependency or skipped | not verified-success |
| Manager restarts or boot ID changes before attribution is complete | re-query; otherwise reconciliation-required |
| PID is reused but pidfd-derived InvocationID differs | reject worker attribution |
| GetUnitByPIDFD returns another unit or invocation | reject worker attribution |
| Job result is done but worker receipt or post-state is absent | reconciliation-required |
| Candidate profile is present but /run/current-system is predecessor | classify according to operation; never guess success |
| test changes boot default unexpectedly | invariant violation |
| boot activates candidate in the running system unexpectedly | invariant violation |
| switch leaves active profile or expected runtime wrong | not verified-success |
| rollback command succeeds but predecessor profile/runtime is not verified | reconciliation-required |
| lost StartUnit reply and duplicate request is attempted | duplicate dispatch invariant violation |
| evidence references a foreign transaction/attempt/permit | reject bundle |

Each negative control must include an expected classification and a test proving the verifier does not upgrade it to success.

## 7. Evidence record outline

A normalized event envelope should preserve source-native data while adding only correlation metadata:

```json
{
  "schema": "org.luminousdynamics.nixward.systemd-execution-evidence",
  "version": 1,
  "transaction_id": "…",
  "attempt_id": "…",
  "admission_commit_id": "…",
  "plan_digest": "…",
  "machine_binding_digest": "…",
  "kernel_boot_id": "…",
  "systemd_version": "…",
  "subscription": {
    "established_monotonic_ns": 0,
    "match_rule": "JobRemoved"
  },
  "start_unit": {
    "request_monotonic_ns": 0,
    "reply_monotonic_ns": 0,
    "returned_job_object_path": "…",
    "unit_name": "…",
    "mode": "replace"
  },
  "manager_events": [],
  "worker_identity": {
    "pidfd_mapping_unit_id": "…",
    "invocation_id": "…",
    "pid": 0,
    "process_start_ticks": 0
  },
  "unit_snapshot": {
    "active_state": "…",
    "sub_state": "…",
    "result": "…",
    "invocation_id": "…"
  },
  "nixos_post_state": {
    "operation": "test",
    "candidate_store_path": "…",
    "predecessor_store_path": "…",
    "active_profile_store_path": "…",
    "running_system_store_path": "…",
    "boot_default_store_path": "…"
  },
  "runtime_observations": [],
  "raw_artifacts": []
}
```

The record is a transport shape, not a trust token. The semantic verifier must validate identities and derive the outcome from raw observations. A record digest is not a signature. A root supervisor must separately validate the admission/provenance record and current release policy before using any receipt.

## 8. Acceptance and performance

First acceptance is correctness, not speed: every deterministic positive fixture derives its exact expected state and every negative control avoids false success. After semantic correctness, benchmark independent parsing time and evidence volume separately from deployment time. Report parser cost, memory, bytes consumed, source/event counts and time-to-classification. Never hide a slow or incomplete semantic verifier inside the activation-latency number.

The official systemd D-Bus reference is at https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html and NixOS activation semantics are at https://nixos.org/manual/nixos/stable/ and https://github.com/NixOS/nixpkgs/blob/master/nixos/doc/manual/development/what-happens-during-a-system-switch.chapter.md.

No semantic implementation, production supervisor, live D-Bus action or runtime qualification is claimed by this specification.
