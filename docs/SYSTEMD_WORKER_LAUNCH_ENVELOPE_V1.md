# Systemd worker launch envelope v1

Status: **immutable launch contract and pure command validators authored; authorization-to-envelope reservation and the live runner remain integration work**

Date: 2026-10-30

## Why this is a separate object

The process receipt captured after spawn cannot, by itself, prove what should have been executed. If the expected command is learned only from the observed process identity, a perfectly coherent but unauthorized process can become its own reference.

The launch envelope reverses that direction. It is committed in the transaction journal before systemd submission and before the worker process exists. Later PIDFD-bound process evidence must match it exactly.

The envelope is not an authorization credential. The caller must first validate the exact `ChangePlan`, local `MachineBinding`, plan freshness, approval evidence, and `ExecutionAuthorization`. The envelope binds the execution object selected by that already-verified authority.

## v1 fields

Each systemd start attempt can contain one `SystemdWorkerLaunchEnvelope`:

| Field | Meaning |
|---|---|
| `worker_gate_executable` | Exact immutable Nix-store path to the Nixward worker gate |
| `payload_executable` | Exact immutable Nix-store path to the command which will run after gate release |
| `payload_args` | Exact argument vector; never a shell string |
| `payload_argv_digest` | Domain-separated, length-framed digest recomputed from executable and argument vector |
| `environment_digest` | Digest of Nixward's fixed privileged-worker environment allowlist |
| `expected_system_profile` | Exact profile that must be observed immediately before releasing this worker's one-time gate token |

Store paths are validated through their store object and the complete lexical suffix. Traversal, empty path components, control characters and noncanonical paths are rejected. Argument count, aggregate argument size and NUL bytes are bounded.

The environment digest is not caller-selectable. Validation compares it to the digest produced by the existing Nixward worker environment definition. The launch envelope does not accept arbitrary environment key/value pairs. This avoids turning a constrained worker-launch API into a privileged environment injection interface.

The one-time release token is intentionally absent from the journal. The trusted runner must generate it only after it has acquired the transaction interlock, validated the journal and captured/persisted the exact worker identity.

## Two different operations, two different envelopes

A NixOS activation transaction contains two distinct mutations. They must not be conflated:

1. **System-profile selection** executes the trusted `nix-env` executable with the exact argv:

   `-p /nix/var/nix/profiles/system --set <authorized-profile-store-path>`

   Its `expected_system_profile` is the independently observed profile before the selection operation.

2. **Closure activation** executes:

   `<authorized-closure>/bin/switch-to-configuration <switch|test|boot>`

   Its `expected_system_profile` is the exact selected profile that must already be active before the activation gate releases.

The source contains pure validators for both command shapes. The profile-selection validator checks the trusted `nix-env` executable, exact argument vector, target profile and prior profile guard. The activation validator checks the exact authorized closure path, exact verb, selected profile and pre-release profile guard.

Recovery uses its own exact pre-bound predecessor closure/profile and action. It must produce separate envelopes with the recovery target and the independently observed current profile. It may not reuse the primary candidate's launch contract.

## Journal binding

Transaction schema v9 stores the envelope inside the append-only `systemd_start_attempts` record. Record validation checks the transaction ID, plan digest, canonical attempt unit, worker purpose, lifecycle phase and envelope shape.

After launch, `ActivationWorkerIdentity` must match the envelope's:
- gate executable and observed inert gate process image;
- payload executable;
- exact payload argument vector and its digest;
- fixed worker environment digest.

The invocation validator additionally requires the exact worker identity and attempt to exist in the same validated transaction journal, then checks the systemd unit and 128-bit InvocationID observations against that attempt.

An absent envelope is not silently synthesized. v8 attempts are migrated to v9 for audit with `launch_envelope = None`; they cannot accept a new worker identity or qualify a complete systemd InvocationID join. v7 direct-spawn worker identities retain their previous serialized shape when `systemd_attempt_id` is absent.

## Required pre-submission order

A future static-template runner must execute this sequence while holding the existing `/run/nixward-system-transaction.lock` interlock:

1. Load and validate the transaction journal; perform fresh recovery observations when the transaction was loaded after restart.
2. Revalidate the exact signed ChangePlan / machine binding / execution-intent realization / ExecutionAuthorization.
3. Derive the launch envelope from the command and authorization. Do not let an IPC caller choose the executable, argument vector, environment, or profile guard independently.
4. Reserve the attempt with that envelope and persist the transaction atomically.
5. Reload the journal and compare the exact attempt and envelope with the expected values.
6. Only then submit the prepared systemd start request for the fixed template instance.
7. The static unit runner reloads the same journal, validates the attempt and unit instance, acquires the same interlock, observes the expected pre-release profile, captures and persists the exact PIDFD-bound worker identity, and only then generates/writes the one-time release token.
8. Observe systemd job completion, worker exit receipt and fresh runtime/profile state. Only the complete event history may reach terminal success.

The current code implements the envelope, its validators, transaction storage, migration behavior, and pure tests. It does not yet implement steps 2–8 as a live systemd path. In particular, the existing executor still uses direct-spawn supervision; the new systemd envelope builders are not yet called by production execution.

## Qualification and limits

Authored negative controls cover payload argument mutation, worker identity drift despite internally recomputed argv digests, gate path traversal, arbitrary environment digest rejection, mismatched switch/test/boot actions, wrong profile guards, profile-target drift and v8 audit-only migration.

No Cargo/Nix/rustfmt/Clippy/D-Bus/systemd VM/crash/power-loss test has run in this authoring environment. The envelope's presence does not prove the caller verified authorization, the manager launched the expected static unit, the runner obeyed the interlock, or the resulting NixOS state is correct. Those are separate integration and VM qualification gates.
