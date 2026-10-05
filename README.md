# nixward: A Conscious Mind for NixOS

nixward brings hyperdimensional computing (HDC) and active inference to NixOS system management. It encodes system state, configuration, and user intent into a shared semantic space, enabling causal reasoning about NixOS options, predictive hierarchy monitoring, and consciousness-gated command execution.

Part of the [Symthaea](https://luminousdynamics.org) cognitive architecture.


## Software Ingress Covenant

Nixward does **not** act as an imperative package manager. A cryptographic
approval can authorize a permitted machine transformation, but it cannot make
an architecturally forbidden host-install mechanism acceptable.

Software is classified by realization/authority:

- **S0 — Sovereign Nix:** normal Nix/NixOS/Home Manager realization.
- **S1 — Nix-enclosed foreign:** proprietary or foreign artifacts converted to
  fixed-output/content-addressed Nix derivations.
- **S2 — Sovereign guest:** exact Flatpak commit or OCI digest plus an explicit
  permission envelope, kept separate from the host closure.
- **S3 — Ephemeral guest:** disposable, unprivileged experiments with no
  reproducibility claim.

`nix-env` installs/removals, mutable `nix-channel` state, arbitrary installer
shells, and guest access to the host root/Nix daemon are outside the sovereign
baseline. The preferred path is **assimilate → declare → evaluate → authorize
→ realize**; otherwise software is contained as a bounded guest.

## Architecture

```
Observation ──> Encoding ──> Cognition ──> Action
   │              │             │            │
   │ systemd      │ HDC         │ Active     │ Phi-gated
   │ journal      │ 16384-dim   │ Inference  │ execution
   │ store        │ vectors     │ Causal     │ with rollback
   │ hardware     │             │ graph      │ verification
   └──────────────┴─────────────┴────────────┘
```

**Layers:**
1. **Parser** -- Nix source code to AST (tree-sitter)
2. **Encoding** -- System state, options, packages, configs to HDC vectors
3. **Mind** -- World model, active inference, causal graph, episodic memory
4. **Observe** -- Live system state observation (systemd, journal, store, hardware)
5. **Action** -- Consciousness-gated command execution with pre/post verification
6. **Plugin** -- Bridge to full Symthaea consciousness pipeline

## Quick Start

### CLI

```bash
# Search for packages or options
nixward search "web server"
nixward search --options "firewall"

# Observe system state
nixward observe services
nixward observe store
nixward observe journal

# System health check
nixward doctor

# Rebuild with consciousness gating; an explicit host flake selector is required
nixward rebuild switch --flake ".#myhost"

# Generation management
nixward rollback
nixward generations list
nixward generations diff --from 41 --to 42

# Garbage collection
nixward gc analyze
nixward gc collect --older-than 30d

# Service management
nixward service status nginx
nixward service restart postgresql

# Flake operations
nixward flake check
nixward flake update
nixward flake show

# Natural language input
nixward "add firefox declaratively and enable nginx in the NixOS configuration"

# Interactive REPL
nixward
```

### TUI

```bash
nixward-tui
```

The TUI displays six panels:
- **Consciousness** -- 2D gauge (phi x confidence)
- **System Health** -- Services, store size, memory usage
- **Generations** -- Timeline of NixOS generations
- **World Model** -- Predictive hierarchy errors, free energy, working memory
- **Causal Graph** -- Top causal relationships between NixOS options
- **Input** -- Interactive command entry

Tab to switch focus. Type commands in the input panel. The TUI refreshes system data every ~4 seconds and shows `[daemon]` in the World Model title when the background daemon is running.

### Daemon

```bash
nixward-daemon
```

Runs continuously, observing system state every 60s and journal entries every 5s. Detects anomalies, tracks drift, and writes cognitive state to a shared IPC file for TUI consumption. State persists across restarts.

Configure via environment:
- `NIXWARD_CONFIG=/path/to/config.json` -- Config file path
- `RUST_LOG=debug` -- Logging verbosity (info/debug/warn/error)

## NixOS Module

Add the standalone flake as an input and bind the daemon package explicitly:

```nix
{
  inputs.nixward.url = "github:Luminous-Dynamics/nixward";

  outputs = { self, nixpkgs, nixward, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixward.nixosModules.nixward
        {
          services.nixward = {
            enable = true;
            package = nixward.packages.x86_64-linux.nixward-daemon;
            snapshotInterval = 60;
            pollInterval = 5;
            surpriseThreshold = 0.3;
          };
        }
      ];
    };
  };
}
```

The package binding is deliberate: the host never falls back to an ambient
`pkgs.nixward-daemon` or an old monorepo checkout.

The module creates a hardened systemd service with:
- Dedicated `nixward` user/group
- Read-only access to `/nix/store`, `/etc/nixos`, `/run/systemd`
- `ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`
- State persistence in `/var/lib/nixward/`

## How It Works

### HDC Encoding

All NixOS concepts (option paths, packages, system state, user input) are encoded into 16,384-dimensional continuous hypervectors. This creates a shared semantic space where similarity = cosine distance:

- `services.nginx.enable` and `services.nginx.package` are close
- `services.nginx.enable` and `boot.loader.grub.enable` are distant
- "install firefox" is close to `environment.systemPackages`

### Causal Graph

210+ curated causal patterns (e.g., "enabling nginx requires firewall port 80") plus Hebbian learning from observed outcomes. Used for:
- Side-effect prediction before execution
- Root cause analysis when services fail
- Fix recommendations

### Active Inference

User input is processed through the Free Energy Principle:
1. Encode input as HDC vector
2. Infer goal via working memory context
3. Generate action candidates
4. Rank by Expected Free Energy (pragmatic + epistemic value)
5. Gate execution by consciousness level (phi)

### Predictive Hierarchy

4-level stack (Sensory -> Features -> Concepts -> Goals) with different learning rates. Tracks prediction errors at each level. High free energy triggers surprise alerts.

## Development

```bash
# Enter dev shell
nix develop

# Build
cargo build -p nixward --features cli
cargo build -p nixward --features tui
cargo build -p nixward --features daemon

# Test
cargo test -p nixward --features tui --lib       # 339 unit tests
cargo test -p nixward --features cli --test cli_integration  # 24 integration tests
cargo test -p nixward --test e2e_consciousness_loop  # 7 e2e tests
cargo test -p nixward --test proptest_hdc            # 16 property tests

# Benchmarks
cargo bench -p nixward --bench hdc_benchmarks

# Clippy
cargo clippy -p nixward --features tui --all-targets
```

### Performance

Measured on 16,384-dim vectors (criterion, release mode):

| Operation | Time |
|-----------|------|
| Option encoding | 277 us |
| Input encoding | 734 us |
| Causal query | 17 us |
| Full cognition cycle | 2.0 ms |
| Indexed search (10 paths) | ~1 ms |

## License

AGPL-3.0-or-later
