# Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable V44 executed acceptance lab. Passing proves isolated backend
# behavior only; it never constitutes production activation authority.
{ pkgs, ... }:
let
  source = ./bpf/network_guard.bpf.c;
  runner = ./run-runtime-lab.py;
  verifier = ./verify-runtime-report.py;
  compileGuard = pkgs.writeShellScript "compile-symthaea-network-guard-v44" ''
    set -euo pipefail
    install -D -m 0644 ${source} /run/symthaea-lab/network_guard.bpf.c
    ${pkgs.clang}/bin/clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include \
      -c /run/symthaea-lab/network_guard.bpf.c \
      -o /run/symthaea-lab/network_guard.bpf.o
  '';
in
pkgs.testers.runNixOSTest {
  name = "symthaea-network-runtime-lab-v44";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 1;
    environment.systemPackages = with pkgs; [ bpftools clang libbpf linuxHeaders iproute2 jq python3 b3sum ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /run/symthaea-lab")
    machine.succeed("${compileGuard}")
    machine.succeed("test -s /run/symthaea-lab/network_guard.bpf.o")
    machine.succeed("install -m 0755 ${runner} /run/symthaea-lab/run-runtime-lab.py")
    machine.succeed("install -m 0755 ${verifier} /run/symthaea-lab/verify-runtime-report.py")
    machine.succeed("python3 /run/symthaea-lab/run-runtime-lab.py --object /run/symthaea-lab/network_guard.bpf.o --output /run/symthaea-lab/report.json")
    machine.succeed("python3 /run/symthaea-lab/verify-runtime-report.py /run/symthaea-lab/report.json")
    machine.copy_from_vm("/run/symthaea-lab/report.json", "network-runtime-lab-v44-report.json")
  '';
}
