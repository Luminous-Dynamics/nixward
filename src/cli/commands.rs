// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! CLI Command Definitions and Dispatch
//!
//! Defines the top-level commands for the `nixward` CLI tool.
//! Natural language is the primary interface — subcommands exist
//! as convenience shortcuts for common goals.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// nixward: A conscious NixOS management tool.
///
/// Natural language is the primary interface. Any argument without a
/// leading `--` is treated as a natural language request:
///
///   nixward "install firefox"
///   nixward "why did my rebuild fail?"
///   nixward "make my system faster"
///
/// Subcommands provide shortcuts for common operations.
#[derive(Parser, Debug)]
#[command(
    name = "nixward",
    version,
    about = "A conscious NixOS management tool powered by HDC and active inference",
    long_about = None,
)]
pub struct Cli {
    /// Natural language input (e.g. "install firefox", "why did my rebuild fail?").
    /// When provided, bypasses subcommands and routes through the cognitive core.
    #[arg(trailing_var_arg = true, allow_hyphen_values = false)]
    pub input: Vec<String>,

    /// Enable dry-run mode (no system changes, only show what would happen).
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Set verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug).
    #[arg(short, long, global = true, default_value = "1")]
    pub verbose: u8,

    /// Output format.
    #[arg(long, global = true, default_value = "human")]
    pub format: OutputFormat,

    /// Override the consciousness level (Φ) for cognition/telemetry.
    /// This value never grants execution authority.
    #[arg(long, global = true)]
    pub phi: Option<f64>,

    /// Approve an exact modifying command when the host execution policy permits it.
    /// This never bypasses policy or cryptographic exact-realization requirements.
    #[arg(long, global = true)]
    pub approve: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Output format for CLI results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output with consciousness metrics.
    Human,
    /// JSON output for scripting.
    Json,
    /// Minimal output (just the essential result).
    Minimal,
}

/// Subcommands for nixward.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Search packages and options in HDC space.
    Search {
        /// Search query.
        query: String,
        /// Search packages (default) or options.
        #[arg(long)]
        options: bool,
        /// Maximum results to show.
        #[arg(short = 'n', long, default_value = "10")]
        limit: usize,
    },

    /// Preview a NixOS rebuild candidate.
    ///
    /// Direct nixos-rebuild system mutation is not permitted through this command.
    /// Privileged activation must use an exact realized closure via ActivateSystemClosure.
    Rebuild {
        /// Rebuild mode.
        #[arg(value_enum, default_value = "switch")]
        mode: RebuildMode,
        /// Flake reference (e.g. ".#hostname").
        #[arg(long)]
        flake: Option<String>,
        /// Extra arguments to pass to nixos-rebuild.
        #[arg(last = true)]
        extra_args: Vec<String>,
    },

    /// Prepare or activate an exact realized NixOS system closure.
    ///
    /// The prepare phase verifies the framework execution-intent/realization-plan
    /// pair and emits an immutable ChangePlan plus detached authority challenge.
    /// The challenge can be signed offline with nixward-owner-key. Activation
    /// re-verifies the complete evidence chain before executing the exact store
    /// closure's switch-to-configuration action.
    Closure {
        #[command(subcommand)]
        op: ClosureCommand,
    },

    /// Roll back to a previous generation.
    Rollback {
        /// Specific generation number (default: previous).
        generation: Option<u32>,
    },

    /// Observe the current system state.
    Observe {
        /// Show specific domain only.
        #[arg(value_enum)]
        domain: Option<ObserveDomain>,
    },

    /// Run system diagnostics.
    Doctor,

    /// List and manage NixOS generations.
    Generations {
        /// Show diff between generations.
        #[arg(long)]
        diff: bool,
        /// First generation for diff.
        #[arg(long)]
        from: Option<u32>,
        /// Second generation for diff.
        #[arg(long)]
        to: Option<u32>,
        /// Delete old generations.
        #[arg(long)]
        delete_older_than: Option<u32>,
    },

    /// Flake operations.
    Flake {
        /// Flake operation.
        #[command(subcommand)]
        op: FlakeCommand,
    },

    /// Intelligent garbage collection.
    Gc {
        /// Just analyze, don't actually collect.
        #[arg(long)]
        analyze: bool,
        /// Delete generations older than N days.
        #[arg(long)]
        older_than: Option<u32>,
        /// Aggressive mode: delete all old generations.
        #[arg(long)]
        aggressive: bool,
    },

    /// Manage systemd services.
    Service {
        /// Service operation.
        #[command(subcommand)]
        op: ServiceCommand,
    },

    /// Enter interactive conscious REPL.
    Repl,

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Run health assessment on the system.
    Health {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Predict future system state using LTC temporal model.
    Predict {
        /// Time horizons to predict (hours).
        #[arg(long, default_value = "1,6,24,168")]
        horizons: String,
    },

    /// Start post-rebuild watchdog monitor.
    Watch {
        /// Monitoring timeout in seconds.
        #[arg(long, default_value = "300")]
        timeout: u64,
        /// Check interval in seconds.
        #[arg(long, default_value = "10")]
        interval: u64,
    },

    /// Privacy-scrub a log file or stdin.
    Scrub {
        /// File to scrub (reads stdin if omitted).
        file: Option<String>,
    },

    /// Search NixOS knowledge base for solutions.
    Knowledge {
        /// Search query (error message or description).
        query: String,
        /// Maximum results to show.
        #[arg(short = 'n', long, default_value = "5")]
        limit: usize,
    },

    /// Preview or apply configuration.nix edits via a reviewable diff.
    ///
    /// Always prints the resulting diff. Without `--apply`, nothing is
    /// written -- this is a pure preview. `--staging <dir>` redirects the
    /// read/write target to a directory other than `/etc/nixos` (e.g. a
    /// scratch copy of your config), so you can try an edit without any
    /// real-system risk at all. This is separate from the capability-authorized
    /// command executor (`Rebuild`/`Rollback`/etc.) -- it never runs a
    /// shell command, only produces validated, git-backed, atomic file
    /// patches via `ConfigWriter`.
    Config {
        #[command(subcommand)]
        op: ConfigCommand,
    },
}

/// Rebuild modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RebuildMode {
    /// Candidate/preview mode; privileged switch activation is blocked.
    Switch,
    /// Candidate/preview mode; privileged test activation is blocked.
    Test,
    /// Candidate/preview mode; privileged boot activation is blocked.
    Boot,
}

/// Activation actions for one already-realized NixOS system closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ClosureAction {
    /// Make the realized closure current.
    Switch,
    /// Test the realized closure without making it the boot default.
    Test,
    /// Make the realized closure the next boot entry.
    Boot,
}

impl ClosureAction {
    pub fn to_system_activation(self) -> nixward::action::SystemActivation {
        match self {
            Self::Switch => nixward::action::SystemActivation::Switch,
            Self::Test => nixward::action::SystemActivation::Test,
            Self::Boot => nixward::action::SystemActivation::Boot,
        }
    }
}

/// Exact-realization preparation/activation commands.
#[derive(Subcommand, Debug)]
pub enum ClosureCommand {
    /// Verify an exact framework execution-intent/realization pair and emit
    /// an immutable activation plan plus detached authority challenge.
    Prepare {
        /// Canonical framework execution-intent JSON.
        #[arg(long)]
        intent: PathBuf,
        /// Canonical Nix realization-plan JSON.
        #[arg(long)]
        realization_plan: PathBuf,
        /// Activation action for the exact realized closure.
        #[arg(value_enum, default_value = "switch")]
        action: ClosureAction,
        /// Framework Holon identity as a 64-character hex digest.
        #[arg(long)]
        holon_id: String,
        /// Output path for the serialized ChangePlan.
        #[arg(long)]
        plan_out: PathBuf,
        /// Output path for the detached authority challenge.
        #[arg(long)]
        challenge_out: PathBuf,
        /// Authorization TTL in milliseconds.
        #[arg(long, default_value_t = 60_000)]
        ttl_ms: u64,
    },

    /// Verify a signed exact-realization authority and activate the immutable
    /// NixOS system closure named by the realization plan.
    Activate {
        /// Canonical framework execution-intent JSON.
        #[arg(long)]
        intent: PathBuf,
        /// Canonical Nix realization-plan JSON.
        #[arg(long)]
        realization_plan: PathBuf,
        /// Serialized ChangePlan produced by closure prepare.
        #[arg(long)]
        plan: PathBuf,
        /// Detached authority signature produced by nixward-owner-key sign.
        #[arg(long)]
        signature: PathBuf,
        /// JSON authority trust policy containing the trusted signing key.
        #[arg(long)]
        policy: PathBuf,
        /// Framework Holon identity as a 64-character hex digest.
        #[arg(long)]
        holon_id: String,
    },
}

/// Observation domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ObserveDomain {
    /// Systemd services.
    Services,
    /// Installed packages.
    Packages,
    /// Nix store.
    Store,
    /// System generations.
    Generations,
    /// Hardware info.
    Hardware,
    /// Flake inputs.
    Flakes,
    /// Effective next-boot selection evidence (read-only).
    BootSelection,
}

/// Flake subcommands.
#[derive(Subcommand, Debug)]
pub enum FlakeCommand {
    /// Check the flake for errors.
    Check,
    /// Update all flake inputs.
    Update {
        /// Only update specific inputs.
        inputs: Vec<String>,
    },
    /// Show flake outputs.
    Show,
    /// Display flake metadata.
    Info,
}

/// Service subcommands.
#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Show status of a service.
    Status {
        /// Service name.
        name: String,
    },
    /// Start a service.
    Start {
        /// Service name.
        name: String,
    },
    /// Stop a service.
    Stop {
        /// Service name.
        name: String,
    },
    /// Restart a service.
    Restart {
        /// Service name.
        name: String,
    },
    /// List failed services.
    Failed,
}

/// Config-editing subcommands (see `Command::Config`).
#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Add a package to `environment.systemPackages`.
    AddPackage {
        /// Package attribute name (e.g. `htop`).
        package: String,
        /// Read/write configuration.nix from this directory instead of
        /// `/etc/nixos`.
        #[arg(long)]
        staging: Option<String>,
        /// Actually write the change (default: preview diff only).
        #[arg(long)]
        apply: bool,
    },
    /// Remove a package from `environment.systemPackages`.
    RemovePackage {
        /// Package attribute name.
        package: String,
        #[arg(long)]
        staging: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Set a NixOS option to a value.
    SetOption {
        /// Option path (e.g. `services.openssh.enable`).
        option_path: String,
        /// Value expression (e.g. `true`, `"my-hostname"`).
        value: String,
        #[arg(long)]
        staging: Option<String>,
        #[arg(long)]
        apply: bool,
    },
}

impl Cli {
    /// Whether the user provided natural language input (not a subcommand).
    pub fn has_natural_input(&self) -> bool {
        !self.input.is_empty() && self.command.is_none()
    }

    /// Get the natural language input as a single string.
    pub fn natural_input(&self) -> String {
        self.input.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_natural_language() {
        let cli = Cli::parse_from(["nixward", "install", "firefox"]);
        assert!(cli.has_natural_input());
        assert_eq!(cli.natural_input(), "install firefox");
    }

    #[test]
    fn test_parse_search_subcommand() {
        let cli = Cli::parse_from(["nixward", "search", "editor"]);
        assert!(matches!(cli.command, Some(Command::Search { .. })));
    }

    #[test]
    fn test_parse_rebuild_switch() {
        let cli = Cli::parse_from(["nixward", "rebuild"]);
        if let Some(Command::Rebuild { mode, .. }) = cli.command {
            assert_eq!(mode, RebuildMode::Switch);
        } else {
            panic!("Expected Rebuild command");
        }
    }

    #[test]
    fn test_parse_exact_closure_prepare() {
        let cli = Cli::parse_from([
            "nixward",
            "closure",
            "prepare",
            "--intent",
            "intent.json",
            "--realization-plan",
            "plan.json",
            "--holon-id",
            "11",
            "--plan-out",
            "change.json",
            "--challenge-out",
            "challenge.json",
        ]);
        assert!(matches!(
            cli.command,
            Some(Command::Closure {
                op: ClosureCommand::Prepare {
                    action: ClosureAction::Switch,
                    ..
                }
            })
        ));
    }

    #[test]
    fn test_parse_dry_run_flag() {
        let cli = Cli::parse_from(["nixward", "--dry-run", "rebuild"]);
        assert!(cli.dry_run);
    }

    #[test]
    fn test_parse_gc_analyze() {
        let cli = Cli::parse_from(["nixward", "gc", "--analyze"]);
        if let Some(Command::Gc { analyze, .. }) = cli.command {
            assert!(analyze);
        } else {
            panic!("Expected Gc command");
        }
    }

    #[test]
    fn test_parse_generations_diff() {
        let cli = Cli::parse_from([
            "nixward",
            "generations",
            "--diff",
            "--from",
            "42",
            "--to",
            "43",
        ]);
        if let Some(Command::Generations { diff, from, to, .. }) = cli.command {
            assert!(diff);
            assert_eq!(from, Some(42));
            assert_eq!(to, Some(43));
        } else {
            panic!("Expected Generations command");
        }
    }

    #[test]
    fn test_parse_service_restart() {
        let cli = Cli::parse_from(["nixward", "service", "restart", "nginx"]);
        if let Some(Command::Service {
            op: ServiceCommand::Restart { name },
        }) = cli.command
        {
            assert_eq!(name, "nginx");
        } else {
            panic!("Expected Service Restart command");
        }
    }

    #[test]
    fn test_parse_repl() {
        let cli = Cli::parse_from(["nixward", "repl"]);
        assert!(matches!(cli.command, Some(Command::Repl)));
    }

    #[test]
    fn test_output_format_json() {
        let cli = Cli::parse_from(["nixward", "--format", "json", "search", "vim"]);
        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn test_parse_health() {
        let cli = Cli::parse_from(["nixward", "health"]);
        assert!(matches!(cli.command, Some(Command::Health { json: false })));

        let cli = Cli::parse_from(["nixward", "health", "--json"]);
        assert!(matches!(cli.command, Some(Command::Health { json: true })));
    }

    #[test]
    fn test_parse_predict() {
        let cli = Cli::parse_from(["nixward", "predict"]);
        assert!(matches!(cli.command, Some(Command::Predict { .. })));
    }

    #[test]
    fn test_parse_watch() {
        let cli = Cli::parse_from(["nixward", "watch", "--timeout", "60", "--interval", "5"]);
        if let Some(Command::Watch {
            timeout, interval, ..
        }) = cli.command
        {
            assert_eq!(timeout, 60);
            assert_eq!(interval, 5);
        } else {
            panic!("Expected Watch command");
        }
    }

    #[test]
    fn test_parse_scrub() {
        let cli = Cli::parse_from(["nixward", "scrub", "/var/log/syslog"]);
        if let Some(Command::Scrub { file }) = cli.command {
            assert_eq!(file, Some("/var/log/syslog".to_string()));
        } else {
            panic!("Expected Scrub command");
        }
    }

    #[test]
    fn test_parse_knowledge() {
        let cli = Cli::parse_from(["nixward", "knowledge", "hash mismatch"]);
        if let Some(Command::Knowledge { query, limit }) = cli.command {
            assert_eq!(query, "hash mismatch");
            assert_eq!(limit, 5);
        } else {
            panic!("Expected Knowledge command");
        }
    }
}
