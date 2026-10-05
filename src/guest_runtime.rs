// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Native, typed guest backend command construction.
//!
//! This module deliberately has no generic shell/argv escape hatch. It builds
//! commands only from validated S2/S3 plans and refuses to run as root: rootless
//! guest state must not turn into ambient host authority simply because a relay
//! happened to have privileges.

use crate::guest_realization::{
    CapsuleObservation, FlatpakObservation, GuestObservation, GuestRealizationError,
    GuestRealizationReceipt, OciObservation, oci_mounts_digest_hex,
};
use crate::software_ingress::{
    CapsuleNetworkPolicy, CapsulePersistence, FilesystemAccess, FlatpakGuestPlan, OciGuestPlan,
    SoftwareIngressPlan, SoftwareIngressSpec,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestToolchain {
    pub flatpak: PathBuf,
    pub podman: PathBuf,
    pub bubblewrap: PathBuf,
    pub bash: PathBuf,
}

impl GuestToolchain {
    pub fn running_system() -> Self {
        Self {
            flatpak: "/run/current-system/sw/bin/flatpak".into(),
            podman: "/run/current-system/sw/bin/podman".into(),
            bubblewrap: "/run/current-system/sw/bin/bwrap".into(),
            bash: "/run/current-system/sw/bin/bash".into(),
        }
    }

    pub fn validate(&self) -> Result<(), GuestRuntimeError> {
        for path in [&self.flatpak, &self.podman, &self.bubblewrap, &self.bash] {
            validate_system_tool(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl GuestCommandSpec {
    fn execute_inner(&self) -> Result<Output, GuestRuntimeError> {
        if effective_uid()? == 0 {
            return Err(GuestRuntimeError::RootExecutionForbidden);
        }
        let mut command = Command::new(&self.program);
        command.args(&self.args).env_clear();
        command.env("PATH", "/run/current-system/sw/bin");
        command.env("TMPDIR", "/tmp");
        for key in [
            "HOME",
            "USER",
            "LOGNAME",
            "XDG_RUNTIME_DIR",
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "LANG",
            "LC_ALL",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command.output().map_err(|e| {
            GuestRuntimeError::CommandFailed(format!(
                "could not execute {}: {e}",
                self.program.display()
            ))
        })
    }

    pub fn execute(&self) -> Result<Output, GuestRuntimeError> {
        let output = self.execute_inner()?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(GuestRuntimeError::CommandFailed(format!(
                "{} exited with {}: {}",
                self.program.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    /// S3 capsules are experiments, so a non-zero child status is evidence, not
    /// a transport failure. The caller still receives the exact exit status.
    pub fn execute_allow_failure(&self) -> Result<Output, GuestRuntimeError> {
        self.execute_inner()
    }
}

/// High-assurance Flatpak V37 intentionally supports a strict subset whose
/// effective launcher authority we can encode without relying on the app's
/// ambient manifest permissions.
pub fn flatpak_backend_compatible(plan: &FlatpakGuestPlan) -> Result<(), GuestRuntimeError> {
    plan.permissions.validate()?;
    if plan.runtime_pins.is_empty() {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "Flatpak S2 requires exact runtime commit pins".into(),
        ));
    }
    if plan.permissions.camera {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "camera/portal authority is not yet represented by the V37 strict Flatpak launcher"
                .into(),
        ));
    }
    if plan.permissions.microphone != plan.permissions.audio {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "Flatpak V37 cannot prove separate microphone and audio authority; they must match"
                .into(),
        ));
    }
    if !plan.permissions.devices.is_empty() || !plan.permissions.secrets.is_empty() {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "arbitrary device/secret grants are not yet supported by the V37 strict Flatpak launcher".into(),
        ));
    }
    Ok(())
}

pub fn flatpak_realization_commands(
    plan: &FlatpakGuestPlan,
    tools: &GuestToolchain,
) -> Result<Vec<GuestCommandSpec>, GuestRuntimeError> {
    tools.validate()?;
    flatpak_backend_compatible(plan)?;
    let app_ref = format!("{}//{}", plan.app_id, plan.branch);
    let mut commands = vec![GuestCommandSpec {
        program: tools.flatpak.clone(),
        args: vec![
            "--user".into(),
            "install".into(),
            "--noninteractive".into(),
            "--assumeyes".into(),
            "--or-update".into(),
            "--no-related".into(),
            plan.remote.clone(),
            app_ref.clone(),
        ],
    }];
    for runtime in &plan.runtime_pins {
        commands.push(GuestCommandSpec {
            program: tools.flatpak.clone(),
            args: vec![
                "--user".into(),
                "update".into(),
                "--noninteractive".into(),
                "--assumeyes".into(),
                "--no-related".into(),
                format!("--commit={}", runtime.commit),
                runtime.reference.clone(),
            ],
        });
    }
    commands.push(GuestCommandSpec {
        program: tools.flatpak.clone(),
        args: vec![
            "--user".into(),
            "update".into(),
            "--noninteractive".into(),
            "--assumeyes".into(),
            "--no-related".into(),
            format!("--commit={}", plan.commit),
            app_ref,
        ],
    });
    Ok(commands)
}

/// Runtime launcher for an already realized Flatpak guest. `--sandbox` drops
/// application-manifest ambient permissions; V37 then re-adds only the small
/// capability subset represented by `GuestPermissionEnvelope`.
pub fn flatpak_launcher_command(
    plan: &FlatpakGuestPlan,
    tools: &GuestToolchain,
) -> Result<GuestCommandSpec, GuestRuntimeError> {
    tools.validate()?;
    flatpak_backend_compatible(plan)?;
    let mut args = vec!["--user".into(), "run".into(), "--sandbox".into()];
    if plan.permissions.network {
        args.push("--share=network".into());
    }
    if plan.permissions.wayland {
        args.push("--socket=wayland".into());
    }
    if plan.permissions.x11 {
        args.push("--socket=x11".into());
    }
    if plan.permissions.audio {
        args.push("--socket=pulseaudio".into());
    }
    if plan.permissions.gpu {
        args.push("--device=dri".into());
    }
    if plan.permissions.bluetooth {
        args.push("--allow=bluetooth".into());
    }
    for grant in &plan.permissions.filesystems {
        let suffix = match grant.access {
            FilesystemAccess::ReadOnly => ":ro",
            FilesystemAccess::ReadWrite => "",
        };
        args.push(format!("--filesystem={}{}", grant.path, suffix));
    }
    args.push(format!("{}//{}", plan.app_id, plan.branch));
    Ok(GuestCommandSpec {
        program: tools.flatpak.clone(),
        args,
    })
}

pub fn observe_flatpak(
    plan: &SoftwareIngressPlan,
    tools: &GuestToolchain,
) -> Result<GuestRealizationReceipt, GuestRuntimeError> {
    let SoftwareIngressSpec::FlatpakGuest(spec) = &plan.spec else {
        return Err(GuestRuntimeError::WrongPlanType);
    };
    flatpak_backend_compatible(spec)?;
    let app_ref = format!("{}//{}", spec.app_id, spec.branch);
    let commit = output_trim(
        GuestCommandSpec {
            program: tools.flatpak.clone(),
            args: vec![
                "--user".into(),
                "info".into(),
                "--show-commit".into(),
                app_ref.clone(),
            ],
        }
        .execute()?,
    )?;
    let origin = output_trim(
        GuestCommandSpec {
            program: tools.flatpak.clone(),
            args: vec![
                "--user".into(),
                "info".into(),
                "--show-origin".into(),
                app_ref,
            ],
        }
        .execute()?,
    )?;
    let mut runtime_commits = BTreeMap::new();
    for runtime in &spec.runtime_pins {
        let observed = output_trim(
            GuestCommandSpec {
                program: tools.flatpak.clone(),
                args: vec![
                    "--user".into(),
                    "info".into(),
                    "--show-commit".into(),
                    runtime.reference.clone(),
                ],
            }
            .execute()?,
        )?;
        runtime_commits.insert(runtime.reference.clone(), observed);
    }
    let authority = plan.spec.authority_digest_hex()?;
    GuestRealizationReceipt::verify(
        plan,
        GuestObservation::Flatpak(FlatpakObservation {
            app_id: spec.app_id.clone(),
            remote: origin,
            branch: spec.branch.clone(),
            installed_commit: commit,
            runtime_commits,
            launch_contract_blake3: authority,
        }),
    )
    .map_err(Into::into)
}

pub fn oci_pull_command(
    plan: &OciGuestPlan,
    tools: &GuestToolchain,
) -> Result<GuestCommandSpec, GuestRuntimeError> {
    tools.validate()?;
    plan.permissions.validate()?;
    if !plan.rootless || plan.host_network {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "OCI S2 requires rootless execution and forbids host networking".into(),
        ));
    }
    Ok(GuestCommandSpec {
        program: tools.podman.clone(),
        args: vec![
            "--remote=false".into(),
            "pull".into(),
            format!("{}@{}", plan.image, plan.image_digest),
        ],
    })
}

pub fn oci_launcher_command(
    name: &str,
    plan: &OciGuestPlan,
    tools: &GuestToolchain,
) -> Result<GuestCommandSpec, GuestRuntimeError> {
    tools.validate()?;
    plan.permissions.validate()?;
    if !plan.rootless || plan.host_network {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "OCI S2 requires rootless execution and forbids host networking".into(),
        ));
    }
    let mut args = vec![
        "--remote=false".into(),
        "run".into(),
        "--rm".into(),
        "--name".into(),
        format!("symthaea-guest-{name}"),
        "--userns=keep-id".into(),
    ];
    if plan.read_only_root {
        args.push("--read-only".into());
    }
    if !plan.permissions.network {
        args.extend(["--network".into(), "none".into()]);
    }
    for mount in &plan.mounts {
        let mode = match mount.access {
            FilesystemAccess::ReadOnly => "ro",
            FilesystemAccess::ReadWrite => "rw",
        };
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={},{}",
                mount.source, mount.target, mode
            ),
        ]);
    }
    if plan.permissions.gpu {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "GPU OCI device mediation needs an explicit CDI/device covenant in a later tranche"
                .into(),
        ));
    }
    if !plan.permissions.devices.is_empty() || !plan.permissions.secrets.is_empty() {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "OCI V37 does not yet realize arbitrary device/secret grants".into(),
        ));
    }
    args.push(format!("{}@{}", plan.image, plan.image_digest));
    Ok(GuestCommandSpec {
        program: tools.podman.clone(),
        args,
    })
}

pub fn observe_oci(
    plan: &SoftwareIngressPlan,
    tools: &GuestToolchain,
) -> Result<GuestRealizationReceipt, GuestRuntimeError> {
    let SoftwareIngressSpec::OciGuest(spec) = &plan.spec else {
        return Err(GuestRuntimeError::WrongPlanType);
    };
    let image_ref = format!("{}@{}", spec.image, spec.image_digest);
    let digest = output_trim(
        GuestCommandSpec {
            program: tools.podman.clone(),
            args: vec![
                "--remote=false".into(),
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{.Digest}}".into(),
                image_ref,
            ],
        }
        .execute()?,
    )?;
    let authority = plan.spec.authority_digest_hex()?;
    GuestRealizationReceipt::verify(
        plan,
        GuestObservation::Oci(OciObservation {
            image: spec.image.clone(),
            image_digest: digest,
            rootless: true,
            read_only_root: spec.read_only_root,
            host_network: false,
            mounts_blake3: oci_mounts_digest_hex(spec)?,
            launch_contract_blake3: authority,
        }),
    )
    .map_err(Into::into)
}

/// Build the strict S3 bubblewrap command. The caller must independently hash
/// `source_path` before execution and compare it to the plan's source digest.
pub fn capsule_command(
    plan: &SoftwareIngressPlan,
    source_path: &Path,
    workspace: &Path,
    tools: &GuestToolchain,
) -> Result<GuestCommandSpec, GuestRuntimeError> {
    let SoftwareIngressSpec::EphemeralCapsule(spec) = &plan.spec else {
        return Err(GuestRuntimeError::WrongPlanType);
    };
    tools.validate()?;
    if !source_path.is_absolute() || !workspace.is_absolute() {
        return Err(GuestRuntimeError::UnsafePath);
    }
    if spec.permissions != Default::default() {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "V37 S3 capsule executor currently accepts the zero-authority permission envelope only"
                .into(),
        ));
    }
    if !matches!(spec.network, CapsuleNetworkPolicy::None) {
        return Err(GuestRuntimeError::UnsupportedCapability(
            "V37 verified S3 capsules are networkless; egress mediation requires a later explicit network covenant".into(),
        ));
    }
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-all".into(),
        "--ro-bind".into(),
        "/nix/store".into(),
        "/nix/store".into(),
        "--ro-bind".into(),
        "/run/current-system".into(),
        "/run/current-system".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--setenv".into(),
        "HOME".into(),
        "/workspace".into(),
        "--setenv".into(),
        "PATH".into(),
        "/run/current-system/sw/bin".into(),
        "--setenv".into(),
        "USER".into(),
        "capsule".into(),
        "--setenv".into(),
        "LOGNAME".into(),
        "capsule".into(),
        "--dir".into(),
        "/work".into(),
        "--ro-bind".into(),
        source_path.display().to_string(),
        "/work/source".into(),
    ];
    if matches!(spec.persistence, CapsulePersistence::PreserveWorkspaceData) {
        args.extend([
            "--bind".into(),
            workspace.display().to_string(),
            "/workspace".into(),
        ]);
    } else {
        args.extend(["--tmpfs".into(), "/workspace".into()]);
    }
    args.extend([tools.bash.display().to_string(), "/work/source".into()]);
    Ok(GuestCommandSpec {
        program: tools.bubblewrap.clone(),
        args,
    })
}

pub fn capsule_observation(
    plan: &SoftwareIngressPlan,
    exit_code: i32,
) -> Result<GuestRealizationReceipt, GuestRuntimeError> {
    let SoftwareIngressSpec::EphemeralCapsule(spec) = &plan.spec else {
        return Err(GuestRuntimeError::WrongPlanType);
    };
    let authority = plan.spec.authority_digest_hex()?;
    GuestRealizationReceipt::verify(
        plan,
        GuestObservation::Capsule(CapsuleObservation {
            source_digest: spec.source_digest.clone(),
            sandbox_backend: "bubblewrap-v1".into(),
            launch_contract_blake3: authority,
            network_isolated: matches!(spec.network, CapsuleNetworkPolicy::None),
            host_root_read_only: true,
            nix_daemon_absent: true,
            exit_code,
            workspace_preserved: matches!(
                spec.persistence,
                CapsulePersistence::PreserveWorkspaceData
            ),
        }),
    )
    .map_err(Into::into)
}

fn effective_uid() -> Result<u32, GuestRuntimeError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| GuestRuntimeError::IdentityUnavailable)?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(GuestRuntimeError::IdentityUnavailable)?;
    line.split_whitespace()
        .nth(2)
        .ok_or(GuestRuntimeError::IdentityUnavailable)?
        .parse::<u32>()
        .map_err(|_| GuestRuntimeError::IdentityUnavailable)
}

fn output_trim(output: Output) -> Result<String, GuestRuntimeError> {
    let value =
        String::from_utf8(output.stdout).map_err(|_| GuestRuntimeError::InvalidToolOutput)?;
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        Err(GuestRuntimeError::InvalidToolOutput)
    } else {
        Ok(value.to_string())
    }
}

fn validate_system_tool(path: &Path) -> Result<(), GuestRuntimeError> {
    let s = path.to_string_lossy();
    if !path.is_absolute()
        || !(s.starts_with("/run/current-system/sw/bin/") || s.starts_with("/nix/store/"))
        || s.contains("..")
    {
        return Err(GuestRuntimeError::UntrustedToolPath(s.into_owned()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum GuestRuntimeError {
    #[error("software ingress rejected: {0}")]
    SoftwareIngress(#[from] crate::software_ingress::SoftwareIngressError),
    #[error("guest realization rejected: {0}")]
    Realization(#[from] GuestRealizationError),
    #[error("wrong software ingress plan type for this backend")]
    WrongPlanType,
    #[error("unsupported guest capability: {0}")]
    UnsupportedCapability(String),
    #[error("untrusted guest tool path: {0}")]
    UntrustedToolPath(String),
    #[error("unsafe guest path")]
    UnsafePath,
    #[error("guest backend returned invalid output")]
    InvalidToolOutput,
    #[error("guest backend command failed: {0}")]
    CommandFailed(String),
    #[error("guest backend execution must run as an unprivileged user")]
    RootExecutionForbidden,
    #[error("could not determine effective user identity")]
    IdentityUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_ingress::{ContentDigest, FlatpakRuntimePin, GuestPermissionEnvelope};

    fn hex(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn flatpak_realization_uses_explicit_commit_updates() {
        let plan = FlatpakGuestPlan {
            app_id: "org.example.App".into(),
            remote: "flathub".into(),
            branch: "stable".into(),
            commit: hex('a'),
            runtime_pins: vec![FlatpakRuntimePin {
                reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                commit: hex('b'),
            }],
            permissions: GuestPermissionEnvelope::default(),
        };
        let cmds = flatpak_realization_commands(&plan, &GuestToolchain::running_system()).unwrap();
        assert!(cmds.iter().any(|c| {
            c.args
                .iter()
                .any(|a| a == &format!("--commit={}", hex('a')))
        }));
        assert!(cmds.iter().any(|c| {
            c.args
                .iter()
                .any(|a| a == &format!("--commit={}", hex('b')))
        }));
    }

    #[test]
    fn flatpak_launcher_uses_sandbox_and_explicit_capabilities() {
        let plan = FlatpakGuestPlan {
            app_id: "org.example.App".into(),
            remote: "flathub".into(),
            branch: "stable".into(),
            commit: hex('a'),
            runtime_pins: vec![FlatpakRuntimePin {
                reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                commit: hex('b'),
            }],
            permissions: GuestPermissionEnvelope {
                network: true,
                wayland: true,
                ..Default::default()
            },
        };
        let cmd = flatpak_launcher_command(&plan, &GuestToolchain::running_system()).unwrap();
        assert!(cmd.args.contains(&"--sandbox".into()));
        assert!(cmd.args.contains(&"--share=network".into()));
        assert!(cmd.args.contains(&"--socket=wayland".into()));
    }

    #[test]
    fn oci_commands_force_local_podman() {
        let plan = OciGuestPlan {
            image: "docker.io/library/alpine".into(),
            image_digest: format!("sha256:{}", hex('d')),
            rootless: true,
            read_only_root: true,
            host_network: false,
            mounts: vec![],
            permissions: GuestPermissionEnvelope::default(),
        };
        let cmd = oci_pull_command(&plan, &GuestToolchain::running_system()).unwrap();
        assert_eq!(cmd.args.first().map(String::as_str), Some("--remote=false"));
    }

    #[test]
    fn capsule_uses_bwrap_without_nix_daemon_or_host_root_bind() {
        let plan = SoftwareIngressPlan::new(
            "test",
            SoftwareIngressSpec::EphemeralCapsule(crate::software_ingress::EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('c')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let cmd = capsule_command(
            &plan,
            Path::new("/tmp/source.sh"),
            Path::new("/tmp/workspace"),
            &GuestToolchain::running_system(),
        )
        .unwrap();
        let joined = cmd.args.join(" ");
        assert!(joined.contains("--unshare-all"));
        assert!(!joined.contains("/nix/var/nix/daemon-socket"));
        assert!(!joined.contains("--bind / /"));
    }
}
