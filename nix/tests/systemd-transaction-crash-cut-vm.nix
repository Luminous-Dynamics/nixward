{ pkgs
, nixwardSourceRevision ? "unknown"
, workflowCheckoutRevision ? "unknown"
, nixpkgsRevision ? "unknown"
, flakeLockSha256 ? "unknown"
}:

let
  worker = pkgs.writeShellScriptBin "nixward-crash-cut-fixture" ''
    set -euo pipefail

    : "''${FIXTURE_ATTEMPT:?systemd template instance is required}"
    : "''${INVOCATION_ID:?systemd must provide InvocationID}"

    state="/var/lib/nixward-crash-cut-vm/$FIXTURE_ATTEMPT"
    runtime="/run/nixward-crash-cut-vm-$FIXTURE_ATTEMPT"

    install -d -m 0700 "$state"
    printf '%s\n' "$INVOCATION_ID" >> "$state/invocations"
    printf '%s\n' "$INVOCATION_ID" > "$state/invocation-id"
    printf '{"event":"started","attempt":"%s","invocation_id":"%s"}\n' \
      "$FIXTURE_ATTEMPT" "$INVOCATION_ID" >> "$state/events.jsonl"
    : > "$state/started"

    while [ ! -e "$runtime/allow-effect" ]; do
      sleep 0.05
    done

    printf '{"event":"mock_effect_committed","attempt":"%s","invocation_id":"%s"}\n' \
      "$FIXTURE_ATTEMPT" "$INVOCATION_ID" >> "$state/events.jsonl"
    printf '%s\n' "$INVOCATION_ID" > "$state/effect-committed"
    : > "$runtime/effect-written"

    while [ ! -e "$runtime/allow-exit" ]; do
      sleep 0.05
    done

    printf '{"event":"process_receipt","attempt":"%s","invocation_id":"%s"}\n' \
      "$FIXTURE_ATTEMPT" "$INVOCATION_ID" >> "$state/events.jsonl"
    printf '%s\n' "$INVOCATION_ID" > "$state/process-receipt"
  '';
in
pkgs.testers.runNixOSTest {
  name = "nixward-systemd-transaction-crash-cut-vm-v1";

  nodes.machine = { ... }: {
    systemd.services."nixward-crash-cut-fixture@" = {
      description = "Nixward crash-cut test-only harmless worker";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${worker}/bin/nixward-crash-cut-fixture";
        Environment = "FIXTURE_ATTEMPT=%i";
        StateDirectory = "nixward-crash-cut-vm";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "nixward-crash-cut-vm-%i";
        RuntimeDirectoryMode = "0700";
        TimeoutStartSec = "120s";
        TimeoutStopSec = "2s";
        Restart = "no";
        KillMode = "control-group";

        # The fixture has no network, activation, host-management or device access.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        RestrictAddressFamilies = [ "AF_UNIX" ];
      };
    };

    # Small, headless disposable VM. The flake lock pins Nixpkgs/systemd.
    virtualisation = {
      graphics = false;
      memorySize = 1024;
      cores = 2;
      # runNixOSTest defaults to a tmpfs root in the disposable guest. Use
      # one explicit qcow2 image so /var/lib survives machine.crash()/reboot.
      # The test driver reuses this exact image between VM starts.
      diskImage = "nixward-crash-cut-vm.qcow2";
      diskSize = 4096;
    };

    system.stateVersion = "26.05";
  };

  testScript = ''
    import base64
    import json
    import re
    from pathlib import Path

    # Keep one stable test-driver state directory for every abrupt guest
    # termination/reboot. The QEMU disk image and its write overlay must be
    # reused rather than recreated from the pristine store image.
    machine.state_dir = Path("/tmp/nixward-crash-cut-vm-state")
    machine.state_dir.mkdir(parents=True, exist_ok=True)
    machine.start()
    machine.wait_for_unit("multi-user.target", timeout=120)
    # The root must be a real writable image, not runNixOSTest's tmpfs mode.
    root_fs = machine.succeed("findmnt -n -o FSTYPE /").strip()
    assert root_fs not in ["tmpfs", "ramfs"], root_fs

    state_root = "/var/lib/nixward-crash-cut-vm"
    attempts = []

    def state_path(attempt, name):
        return f"{state_root}/{attempt}/{name}"

    def runtime_path(attempt, name):
        return f"/run/nixward-crash-cut-vm-{attempt}/{name}"

    def boot_id():
        return machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()

    def invocation_id(attempt):
        value = machine.succeed(
            f"cat {state_path(attempt, 'invocation-id')}"
        ).strip()
        assert re.fullmatch(r"[0-9a-fA-F]{32}", value), value
        return value

    def invocation_count(attempt):
        return int(machine.succeed(
            f"wc -l < {state_path(attempt, 'invocations')}"
        ).strip())

    def start_blocked_worker(attempt):
        unit = f"nixward-crash-cut-fixture@{attempt}.service"
        before_boot = boot_id()
        # StartUnit runs in the background because the harmless oneshot remains
        # blocked at its test-only gate until the evaluator permits the next step.
        machine.execute(
            f"systemctl start {unit} >/dev/null 2>&1 </dev/null &",
            check_return=False,
        )
        machine.wait_for_file(state_path(attempt, "started"), timeout=120)
        invocation = invocation_id(attempt)
        assert invocation_count(attempt) == 1
        return {
            "attempt_id": attempt,
            "unit_name": unit,
            "boot_id_before": before_boot,
            "invocation_id": invocation,
        }

    def abrupt_guest_crash_and_reboot():
        # NixOS test-driver crash terminates QEMU without guest shutdown. The
        # same test VM disk is then booted again by the next machine operation.
        machine.crash()
        machine.wait_for_unit("multi-user.target", timeout=120)

    # Cut A: the invocation/start record is synchronously flushed, but the
    # test-only mock participant effect has not been committed before guest loss.
    before_effect = start_blocked_worker("cut-before-effect")
    # Flush the invocation/start record to the virtual disk before cutting power.
    machine.succeed("sync")
    abrupt_guest_crash_and_reboot()
    before_effect["boot_id_after"] = boot_id()
    assert before_effect["boot_id_before"] != before_effect["boot_id_after"]
    assert invocation_count("cut-before-effect") == 1
    machine.succeed(f"test -f {state_path('cut-before-effect', 'started')}")
    machine.fail(f"test -e {state_path('cut-before-effect', 'effect-committed')}")
    machine.fail(f"test -e {state_path('cut-before-effect', 'process-receipt')}")
    before_effect["effect_marker_persisted"] = False
    before_effect["process_receipt_persisted"] = False
    before_effect["invocation_count_after_reboot"] = invocation_count("cut-before-effect")
    before_effect["observed_invocation_count"] = invocation_count("cut-before-effect")
    before_effect["disposition"] = "attempt_started_effect_not_recorded_reconciliation_required"
    attempts.append(before_effect)

    # Cut B: the mock participant effect is synchronously flushed, but the
    # process receipt has not been published when the guest is terminated.
    after_effect = start_blocked_worker("cut-after-effect-before-receipt")
    machine.succeed(f"touch {runtime_path('cut-after-effect-before-receipt', 'allow-effect')}")
    machine.wait_for_file(
        state_path("cut-after-effect-before-receipt", "effect-committed"),
        timeout=120,
    )
    # The mock participant effect is considered durable only after this flush.
    machine.succeed("sync")
    abrupt_guest_crash_and_reboot()
    after_effect["boot_id_after"] = boot_id()
    assert after_effect["boot_id_before"] != after_effect["boot_id_after"]
    assert invocation_count("cut-after-effect-before-receipt") == 1
    machine.fail(
        f"test -e {runtime_path('cut-after-effect-before-receipt', 'allow-effect')}"
    )
    machine.succeed(
        f"test -s {state_path('cut-after-effect-before-receipt', 'effect-committed')}"
    )
    machine.fail(
        f"test -e {state_path('cut-after-effect-before-receipt', 'process-receipt')}"
    )
    after_effect["effect_marker_persisted"] = True
    after_effect["process_receipt_persisted"] = False
    after_effect["invocation_count_after_reboot"] = invocation_count(
        "cut-after-effect-before-receipt"
    )
    after_effect["observed_invocation_count"] = invocation_count(
        "cut-after-effect-before-receipt"
    )
    after_effect["disposition"] = "effect_committed_receipt_missing_reconciliation_required"
    attempts.append(after_effect)

    # Positive control: the harmless worker reaches effect and process receipt
    # on one exact invocation, with an independent read-only post-observation.
    positive = start_blocked_worker("positive-control")
    machine.succeed(f"touch {runtime_path('positive-control', 'allow-effect')}")
    machine.wait_for_file(state_path("positive-control", "effect-committed"), timeout=120)
    machine.succeed(f"touch {runtime_path('positive-control', 'allow-exit')}")
    machine.wait_for_file(state_path("positive-control", "process-receipt"), timeout=120)
    machine.wait_until_succeeds(
        "systemctl show nixward-crash-cut-fixture@positive-control.service "
        "--property=ActiveState --value | grep -qx inactive",
        timeout=30,
    )
    assert invocation_count("positive-control") == 1
    positive["boot_id_after"] = boot_id()
    positive["effect_marker_persisted"] = True
    positive["process_receipt_persisted"] = True
    positive["invocation_count_after_completion"] = invocation_count("positive-control")
    positive["observed_invocation_count"] = invocation_count("positive-control")
    positive["disposition"] = "complete_positive_control"
    attempts.append(positive)

    campaign = {
        "schema": "org.luminousdynamics.nixward.systemd-crash-cut-vm-campaign",
        "version": 1,
        "status": "executed_disposable_qemu_guest",
        "claim_ceiling": "The campaign exercises the pinned disposable guest and virtual disk only; it does not establish physical power-loss durability or production Nixward journal semantics.",
        "nixward_source_revision": "${nixwardSourceRevision}",
        "workflow_checkout_revision": "${workflowCheckoutRevision}",
        "nixpkgs_revision": "${nixpkgsRevision}",
        "flake_lock_sha256": "${flakeLockSha256}",
        "worker_derivation": "${worker.drvPath}",
        "worker_output": "${worker}",
        "guest_kernel": machine.succeed("uname -r").strip(),
        "guest_nixos_version": machine.succeed("nixos-version").strip(),
        "guest_systemd_version": machine.succeed("systemctl --version | head -n 1").strip(),
        "guest_qemu_version": "${pkgs.qemu.version}",
        "attempts": attempts,
    }

    encoded = base64.b64encode(json.dumps(campaign, sort_keys=True).encode()).decode()
    machine.succeed(
        f"printf %s {encoded} | base64 -d > {state_root}/campaign.json"
    )
    machine.copy_from_machine(state_root, "raw-evidence")
    assert len(attempts) == 3
    assert [a["disposition"] for a in attempts] == [
        "attempt_started_effect_not_recorded_reconciliation_required",
        "effect_committed_receipt_missing_reconciliation_required",
        "complete_positive_control",
    ]
  '';
}
