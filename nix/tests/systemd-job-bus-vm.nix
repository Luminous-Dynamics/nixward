{ pkgs, testBinary }:

pkgs.testers.runNixOSTest {
  name = "nixward-systemd-job-bus-live";

  nodes.machine = { pkgs, ... }: {
    # A deliberately harmless template unit. The Rust test derives the
    # instance name from the transaction/attempt identity and starts it via
    # the actual system manager; only this disposable VM contains the template.
    systemd.units."nixward-transaction@.service" = {
      text = ''
        [Unit]
        Description=Nixward disposable observer qualification unit

        [Service]
        Type=oneshot
        ExecStart=${pkgs.writeShellScript "nixward-transaction-test-action" ''
          case "$1" in
            62a0ce8ee10e06ec5458889470c2ade5a65ec0d24342559ce8fdcfc6a8d5f95f)
              exec ${pkgs.coreutils}/bin/true
              ;;
            48640a16e1f913986d538d126bd971ba3a6b4dd48cf880411dad47124e2fe770)
              exec ${pkgs.coreutils}/bin/false
              ;;
            *)
              echo "unexpected test transaction instance: $1" >&2
              exit 64
              ;;
          esac
        ''} %i
      '';
    };

    environment.systemPackages = [ testBinary ];
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl daemon-reload")
    machine.succeed("systemctl cat nixward-transaction@.service")
    machine.succeed(
      "${testBinary}/bin/nixward-systemd-tests "
      "--ignored --exact "
      "action::systemd_job_bus::tests::live_systemd_start_job_round_trip "
      "--nocapture"
    )
    machine.succeed(
      "${testBinary}/bin/nixward-systemd-tests "
      "--ignored --exact "
      "action::systemd_job_bus::tests::live_systemd_failed_start_is_not_success "
      "--nocapture"
    )
  '';
}
