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
        ExecStart=${pkgs.coreutils}/bin/true
      '';
    };

    environment.systemPackages = [ testBinary ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl daemon-reload")
    machine.succeed("systemctl cat nixward-transaction@.service")
    machine.succeed(
      "${testBinary}/bin/nixward-systemd-tests "
      "--ignored --exact "
      "action::systemd_job_bus::tests::live_systemd_start_job_round_trip "
      "--nocapture"
    )
  '';
}
