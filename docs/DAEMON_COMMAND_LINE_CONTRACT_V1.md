# Daemon command-line contract v1

Status: **strict dispatch implemented; daemon runtime tests not executed in the authoring environment**

Date: 2026-10-30

## Accepted invocation forms

The daemon has exactly three accepted invocation classes:

| Arguments | Action |
|---|---|
| no arguments | Start the ordinary long-running awareness daemon |
| `--help` or `-h` | Print usage and exit successfully |
| `--version` or `-V` | Print the package version and exit successfully |

Every other argument vector is rejected with exit status 2. More than one argument is rejected. Non-UTF-8 arguments are rejected rather than lossily normalized into a command name.

## Why this is a safety boundary

A systemd service's `ExecStart` is part of its authority boundary. Silently ignoring an unknown mode can make a mistyped or not-yet-implemented privileged worker invocation start the ordinary daemon instead. A unit can then appear to have started successfully while the requested operation never occurred.

The daemon therefore uses an explicit command enum and an exhaustive dispatch match. A future `systemd-transaction-worker` mode must be added intentionally, with its own exact argument parser and authorization/evidence path. It must not be introduced as a catch-all positional mode.

## Scope and non-claims

This change establishes command dispatch only. It does not add the transaction worker, static systemd template, polkit policy, or systemd production execution path. The ordinary daemon remains the unprivileged service configured by `nix/module.nix`.

The parser's unit tests cover default invocation, help/version aliases, unknown worker-mode rejection, extra arguments, and non-UTF-8 arguments. Those tests are authored but have not been executed here. This contract does not establish process isolation or authorization; those remain separate systemd/NixOS VM qualification gates.
