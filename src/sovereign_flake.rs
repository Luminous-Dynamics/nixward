// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical sovereign flake bundle generation.
//!
//! The flake is intentionally a thin wrapper around ordinary NixOS modules.
//! This keeps generated systems understandable without Nixward, makes each
//! security-relevant layer reviewable in isolation, and gives Spore a stable
//! file manifest to bind into an installation covenant.
//!
//! V47 adds privacy-preserving hash-chained real-flow telemetry while keeping observation non-authoritative.

use crate::evaluator_witness::evaluator_policy_json;
use crate::guest_realization::GUEST_REALIZATION_SCHEMA_VERSION;
use crate::network_activation::{
    NETWORK_ACTIVATION_SCHEMA_VERSION, network_activation_policy_json,
};
use crate::network_calibration::{
    NETWORK_CALIBRATION_SCHEMA_VERSION, network_calibration_policy_json,
};
use crate::network_cognition::{NETWORK_COGNITION_SCHEMA_VERSION, network_cognition_policy_json};
use crate::network_covenant::{NETWORK_COVENANT_SCHEMA_VERSION, network_policy_json_for_holon};
use crate::network_enforcement::{
    NETWORK_ENFORCEMENT_SCHEMA_VERSION, network_enforcement_policy_json,
};
use crate::network_runtime_lab::{
    NETWORK_RUNTIME_LAB_SCHEMA_VERSION, network_runtime_lab_policy_json,
};
use crate::network_telemetry::{NETWORK_TELEMETRY_SCHEMA_VERSION, network_telemetry_policy_json};
use crate::reconstitution::continuity_policy_json;
use crate::software_assimilation::{
    SOFTWARE_ASSIMILATION_SCHEMA_VERSION, assimilation_policy_json,
};
use crate::software_ingress::{
    GuestPlanDocument, GuestStateManifest, SOFTWARE_INGRESS_SCHEMA_VERSION, SoftwareIngressPlan,
    SoftwareTrustClass, empty_guest_plan_document_json, empty_guest_state_manifest_json,
    software_ingress_policy_json,
};
use crate::sovereign_config::{HardwareProfile, UserChoices};
use crate::storage_intent::{AUTHORITATIVE_STORAGE_STATUS, StoragePlan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const SOVEREIGN_FLAKE_SCHEMA_VERSION: u32 = 18;
pub const UPDATE_POLICY_SCHEMA_VERSION: u32 = 2;
pub const SOVEREIGN_SCHEMA_MANIFEST_VERSION: u32 = 1;
pub const UPSTREAM_SOURCE_POLICY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_NIXPKGS_REF: &str = "nixos-26.05";
pub const DEFAULT_EDGE_NIXPKGS_REF: &str = "nixos-unstable";
pub const DEFAULT_DISKO_REF: &str = "v1.13.0";
pub const DEFAULT_STATE_VERSION: &str = "26.05";
pub const STORAGE_REALIZATION_STATUS: &str = "storage-intent-required-v27";
pub const DEFAULT_UPDATE_PROMOTION: &str = "stage";
const BUNDLE_DOMAIN: &[u8] = b"symthaea-sovereign-flake-bundle-v18\0";
const UPDATE_STEWARD_SCRIPT: &str = include_str!("../assets/symthaea-update-steward.sh");

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SovereignFlakeError {
    #[error("invalid hostname {0:?}: expected a lowercase RFC-1123 style label")]
    InvalidHostname(String),
    #[error("unsupported target architecture {0:?}")]
    UnsupportedArchitecture(String),
    #[error("invalid storage plan: {0}")]
    InvalidStoragePlan(String),
    #[error("invalid software ingress state: {0}")]
    InvalidSoftwareIngress(String),
    #[error("invalid network covenant: {0}")]
    InvalidNetworkCovenant(String),
}

/// A deterministic set of files that together define one NixOS system.
///
/// `files` is a BTreeMap so serialization and hashing are stable across runs.
/// The generated manifest is included in `files` at
/// `generated/manifest.json`, but the bundle digest is computed over all
/// other files to avoid self-reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SovereignFlakeBundle {
    pub schema_version: u32,
    pub hostname: String,
    pub system: String,
    pub nixpkgs_ref: String,
    pub edge_nixpkgs_ref: String,
    pub disko_ref: String,
    pub state_version: String,
    pub storage_realization_status: String,
    pub storage_plan_blake3: Option<String>,
    pub update_promotion: String,
    pub entrypoint_mode: String,
    pub bundle_digest_blake3: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SovereignFlakeManifest {
    schema_version: u32,
    hostname: String,
    system: String,
    nixpkgs_ref: String,
    edge_nixpkgs_ref: String,
    disko_ref: String,
    state_version: String,
    storage_realization_status: String,
    storage_plan_blake3: Option<String>,
    update_promotion: String,
    entrypoint_mode: String,
    bundle_digest_blake3: String,
    files_blake3: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UpdatePolicy {
    schema_version: u32,
    kind: &'static str,
    release: ReleasePolicy,
    inputs: Vec<InputUpdatePolicy>,
    promotion: PromotionPolicy,
    compatibility: CompatibilityPolicy,
    entrypoints: EntrypointPolicy,
    lineage: LineagePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReleasePolicy {
    current: String,
    migrations: &'static str,
    state_version: &'static str,
    discovery: ReleaseDiscovery,
    required_gates: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReleaseDiscovery {
    git_remote: &'static str,
    channel_base: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct InputUpdatePolicy {
    name: &'static str,
    lane: &'static str,
    strategy: &'static str,
    auto_stage: bool,
    auto_boot_eligible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PromotionPolicy {
    default: &'static str,
    source_drift: &'static str,
    activation: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CompatibilityPolicy {
    mode: &'static str,
    required_capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EntrypointPolicy {
    canonical: &'static str,
    compatibility: &'static str,
    parity: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LineagePolicy {
    mode: &'static str,
    post_boot_verification: bool,
    receipt_hash: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UpstreamSourcePolicy {
    schema_version: u32,
    kind: &'static str,
    sources: Vec<TrustedUpstreamSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustedUpstreamSource {
    input: &'static str,
    source_type: &'static str,
    owner: &'static str,
    repo: &'static str,
    declared_ref: &'static str,
    trust_class: &'static str,
    movement: &'static str,
}

impl SovereignFlakeBundle {
    pub fn flake_nix(&self) -> Option<&str> {
        self.files.get("flake.nix").map(String::as_str)
    }

    pub fn file(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }

    /// Bind the exact trusted storage plan into this bundle. This must happen
    /// before lock/evaluation preflight. The plan replaces the non-destructive
    /// placeholder and becomes part of the bundle digest/manifest.
    pub fn bind_storage_plan(&mut self, plan: &StoragePlan) -> Result<(), SovereignFlakeError> {
        plan.intent
            .validate()
            .map_err(|e| SovereignFlakeError::InvalidStoragePlan(e.to_string()))?;
        if plan.realization != AUTHORITATIVE_STORAGE_STATUS {
            return Err(SovereignFlakeError::InvalidStoragePlan(format!(
                "unexpected realization status {:?}",
                plan.realization
            )));
        }

        self.files.remove("generated/manifest.json");
        self.files
            .insert("disko/default.nix".into(), plan.disko_module.clone());
        self.files
            .insert("generated/storage-plan.json".into(), plan.receipt_json());
        self.storage_realization_status = plan.realization.clone();
        self.storage_plan_blake3 = Some(plan.plan_digest_blake3.clone());
        refresh_bundle_manifest(self);
        Ok(())
    }

    /// Bind exact S2/S3 guest plans and their expected state identity into the
    /// sovereign source tree. Realized external guest state remains separate
    /// and must be proven through `generated/guest-realization.json`.
    /// S0/S1 plans are rejected here because they belong in the Nix realization
    /// graph rather than the guest manifest.
    pub fn bind_guest_state(
        &mut self,
        plans: &[SoftwareIngressPlan],
    ) -> Result<String, SovereignFlakeError> {
        for plan in plans {
            plan.validate()
                .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?;
            if !matches!(
                plan.trust_class(),
                SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
            ) {
                return Err(SovereignFlakeError::InvalidSoftwareIngress(format!(
                    "{} is {} and belongs in the Nix realization graph, not guest-state.json",
                    plan.name,
                    plan.trust_class().code()
                )));
            }
        }

        let plan_document = GuestPlanDocument::from_plans(plans)
            .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?;
        let manifest = GuestStateManifest::from_plans(plans)
            .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?;
        let digest = manifest
            .digest_hex()
            .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?;
        let plan_json = serde_json::to_string_pretty(&plan_document)
            .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?
            + "\n";
        let state_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| SovereignFlakeError::InvalidSoftwareIngress(e.to_string()))?
            + "\n";

        self.files.remove("generated/manifest.json");
        self.files
            .insert("generated/guest-plans.json".into(), plan_json);
        self.files
            .insert("generated/guest-state.json".into(), state_json);
        refresh_bundle_manifest(self);
        Ok(digest)
    }
}

/// Build the canonical file hierarchy for a newly provisioned Symthaea host.
///
/// The hierarchy borrows the proven shape of the Luminous workstation config:
/// hosts contain machine facts, profiles compose reusable policy, modules own
/// concerns, and generated decisions stay isolated from hand-maintained rules.
/// A stable nixpkgs branch owns the system baseline while an explicit edge
/// input exists for packages that truly need it.
///
/// Hardware and boot files are placeholders at generation time. Storage is more
/// strict in V27: the placeholder deliberately fails system evaluation until
/// the trusted relay binds a typed `StoragePlan` to a stable `/dev/disk/by-id`
/// target. Only then does the bundle advertise `authoritative-disko-v1`.
pub fn build_sovereign_flake_bundle(
    hardware: &HardwareProfile,
    choices: &UserChoices,
    sovereign_module: &str,
) -> Result<SovereignFlakeBundle, SovereignFlakeError> {
    let hostname = canonical_hostname(&choices.hostname)?;
    let system = canonical_system(&hardware.arch)?;

    let mut files = BTreeMap::new();
    files.insert(
        "flake.nix".into(),
        render_flake(
            &hostname,
            &system,
            DEFAULT_NIXPKGS_REF,
            DEFAULT_EDGE_NIXPKGS_REF,
            DEFAULT_DISKO_REF,
        ),
    );
    files.insert("system.nix".into(), render_system_nix(&hostname, &system));
    files.insert("lib/locked-inputs.nix".into(), render_locked_inputs());
    files.insert("lib/mk-host.nix".into(), render_mk_host());
    files.insert(
        format!("hosts/{hostname}/default.nix"),
        render_host_module(&hostname),
    );
    files.insert(
        format!("hosts/{hostname}/hardware-configuration.nix"),
        render_hardware_placeholder(),
    );
    files.insert("profiles/base/default.nix".into(), render_base_profile());
    files.insert(
        "modules/core/default.nix".into(),
        render_core_module(&hostname),
    );
    files.insert("modules/boot/default.nix".into(), render_boot_placeholder());
    files.insert(
        "modules/security/default.nix".into(),
        render_security_module(),
    );
    files.insert(
        "modules/network-covenant/default.nix".into(),
        render_network_covenant_module(),
    );
    files.insert(
        "modules/network-enforcement/default.nix".into(),
        render_network_enforcement_module(),
    );
    files.insert(
        "modules/network-observe/default.nix".into(),
        render_network_observe_module(),
    );
    files.insert(
        "modules/network-runtime-lab/default.nix".into(),
        render_network_runtime_lab_module(),
    );
    files.insert(
        "modules/network-calibration/default.nix".into(),
        render_network_calibration_module(),
    );
    files.insert(
        "modules/network-activation/default.nix".into(),
        render_network_activation_module(),
    );
    files.insert(
        "modules/network-telemetry/default.nix".into(),
        render_network_telemetry_module(),
    );
    files.insert(
        "modules/software/default.nix".into(),
        render_software_ingress_module(),
    );
    files.insert(
        "modules/guests/default.nix".into(),
        render_guest_state_module(),
    );
    files.insert(
        "modules/maintenance/default.nix".into(),
        render_maintenance_module(),
    );
    files.insert(
        "modules/maintenance/update-steward.nix".into(),
        render_update_steward_module(),
    );
    files.insert(
        "modules/generated/default.nix".into(),
        sovereign_module.trim_end().to_string() + "\n",
    );
    files.insert(
        "scripts/symthaea-update-steward.sh".into(),
        UPDATE_STEWARD_SCRIPT.to_string(),
    );
    files.insert("disko/default.nix".into(), render_disko_placeholder());
    files.insert(
        "generated/update-policy.json".into(),
        render_update_policy(),
    );
    files.insert(
        "generated/source-policy.json".into(),
        render_upstream_source_policy(),
    );
    files.insert(
        "generated/evaluator-policy.json".into(),
        evaluator_policy_json(),
    );
    files.insert(
        "generated/continuity-policy.json".into(),
        continuity_policy_json(),
    );
    files.insert(
        "generated/network-policy.json".into(),
        network_policy_json_for_holon(&hostname)
            .map_err(|e| SovereignFlakeError::InvalidNetworkCovenant(e.to_string()))?,
    );
    files.insert(
        "generated/network-enforcement-policy.json".into(),
        network_enforcement_policy_json(),
    );
    files.insert(
        "generated/network-cognition-policy.json".into(),
        network_cognition_policy_json(),
    );
    files.insert(
        "generated/network-runtime-lab-policy.json".into(),
        network_runtime_lab_policy_json(),
    );
    files.insert(
        "generated/network-calibration-policy.json".into(),
        network_calibration_policy_json(),
    );
    files.insert(
        "generated/network-activation-policy.json".into(),
        network_activation_policy_json(),
    );
    files.insert(
        "generated/network-telemetry-policy.json".into(),
        network_telemetry_policy_json(),
    );
    files.insert(
        "generated/software-ingress-policy.json".into(),
        software_ingress_policy_json(),
    );
    files.insert(
        "generated/assimilation-policy.json".into(),
        assimilation_policy_json(),
    );
    files.insert(
        "generated/guest-plans.json".into(),
        empty_guest_plan_document_json(),
    );
    files.insert(
        "generated/guest-state.json".into(),
        empty_guest_state_manifest_json(),
    );
    files.insert("generated/schema.json".into(), render_schema_manifest());
    files.insert("README.md".into(), render_readme(&hostname));

    let files_blake3 = files
        .iter()
        .map(|(path, content)| {
            (
                path.clone(),
                blake3::hash(content.as_bytes()).to_hex().to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let bundle_digest_blake3 = bundle_digest(&files_blake3);

    let manifest = SovereignFlakeManifest {
        schema_version: SOVEREIGN_FLAKE_SCHEMA_VERSION,
        hostname: hostname.clone(),
        system: system.clone(),
        nixpkgs_ref: DEFAULT_NIXPKGS_REF.into(),
        edge_nixpkgs_ref: DEFAULT_EDGE_NIXPKGS_REF.into(),
        disko_ref: DEFAULT_DISKO_REF.into(),
        state_version: DEFAULT_STATE_VERSION.into(),
        storage_realization_status: STORAGE_REALIZATION_STATUS.into(),
        storage_plan_blake3: None,
        update_promotion: DEFAULT_UPDATE_PROMOTION.into(),
        entrypoint_mode: "flake-plus-system-nix-parity".into(),
        bundle_digest_blake3: bundle_digest_blake3.clone(),
        files_blake3,
    };
    // Serializing this fixed data model should not fail. If serde_json ever
    // changes that assumption, a compact valid JSON object is safer than
    // silently omitting the provenance file.
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"error\":\"manifest serialization failed\"}}",
            SOVEREIGN_FLAKE_SCHEMA_VERSION
        )
    });
    files.insert("generated/manifest.json".into(), manifest_json + "\n");

    Ok(SovereignFlakeBundle {
        schema_version: SOVEREIGN_FLAKE_SCHEMA_VERSION,
        hostname,
        system,
        nixpkgs_ref: DEFAULT_NIXPKGS_REF.into(),
        edge_nixpkgs_ref: DEFAULT_EDGE_NIXPKGS_REF.into(),
        disko_ref: DEFAULT_DISKO_REF.into(),
        state_version: DEFAULT_STATE_VERSION.into(),
        storage_realization_status: STORAGE_REALIZATION_STATUS.into(),
        storage_plan_blake3: None,
        update_promotion: DEFAULT_UPDATE_PROMOTION.into(),
        entrypoint_mode: "flake-plus-system-nix-parity".into(),
        bundle_digest_blake3,
        files,
    })
}

fn canonical_hostname(input: &str) -> Result<String, SovereignFlakeError> {
    let hostname = if input.trim().is_empty() {
        "guardian"
    } else {
        input.trim()
    };

    let bytes = hostname.as_bytes();
    let valid = bytes.len() <= 63
        && !bytes.is_empty()
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && (bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');

    if valid {
        Ok(hostname.to_string())
    } else {
        Err(SovereignFlakeError::InvalidHostname(hostname.into()))
    }
}

fn canonical_system(arch: &str) -> Result<String, SovereignFlakeError> {
    match arch.trim() {
        "" | "x86_64" | "x86_64-linux" | "amd64" => Ok("x86_64-linux".into()),
        "aarch64" | "aarch64-linux" | "arm64" => Ok("aarch64-linux".into()),
        other => Err(SovereignFlakeError::UnsupportedArchitecture(other.into())),
    }
}

fn bundle_digest(files: &BTreeMap<String, String>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BUNDLE_DOMAIN);
    for (path, digest) in files {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&(digest.len() as u64).to_le_bytes());
        hasher.update(digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn refresh_bundle_manifest(bundle: &mut SovereignFlakeBundle) {
    bundle.files.remove("generated/manifest.json");
    let files_blake3 = bundle
        .files
        .iter()
        .map(|(path, content)| {
            (
                path.clone(),
                blake3::hash(content.as_bytes()).to_hex().to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    bundle.bundle_digest_blake3 = bundle_digest(&files_blake3);

    let manifest = SovereignFlakeManifest {
        schema_version: bundle.schema_version,
        hostname: bundle.hostname.clone(),
        system: bundle.system.clone(),
        nixpkgs_ref: bundle.nixpkgs_ref.clone(),
        edge_nixpkgs_ref: bundle.edge_nixpkgs_ref.clone(),
        disko_ref: bundle.disko_ref.clone(),
        state_version: bundle.state_version.clone(),
        storage_realization_status: bundle.storage_realization_status.clone(),
        storage_plan_blake3: bundle.storage_plan_blake3.clone(),
        update_promotion: bundle.update_promotion.clone(),
        entrypoint_mode: bundle.entrypoint_mode.clone(),
        bundle_digest_blake3: bundle.bundle_digest_blake3.clone(),
        files_blake3,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| {
        format!(
            "{{\"schema_version\":{},\"error\":\"manifest serialization failed\"}}",
            SOVEREIGN_FLAKE_SCHEMA_VERSION
        )
    });
    bundle
        .files
        .insert("generated/manifest.json".into(), manifest_json + "\n");
}

fn render_flake(
    hostname: &str,
    system: &str,
    nixpkgs_ref: &str,
    edge_nixpkgs_ref: &str,
    disko_ref: &str,
) -> String {
    format!(
        r#"{{
  description = "Symthaea Sovereign System — {hostname}";

  inputs = {{
    # Stable system baseline. `flake.lock` moves this within the supported
    # release line; release-line migrations are proposal-only.
    nixpkgs.url = "github:NixOS/nixpkgs/{nixpkgs_ref}";

    # Explicit escape hatch for selected fast-moving packages. The base system
    # never follows this input implicitly.
    nixpkgs-edge.url = "github:NixOS/nixpkgs/{edge_nixpkgs_ref}";

    disko = {{
      url = "github:nix-community/disko/{disko_ref}";
      inputs.nixpkgs.follows = "nixpkgs";
    }};
  }};

  outputs = inputs@{{ self, nixpkgs, ... }}:
    let
      system = "{system}";
      mkHost = import ./lib/mk-host.nix;
      pkgsEdge = import inputs.nixpkgs-edge {{
        inherit system;
        config.allowUnfree = true;
      }};
      evalNixos = args: inputs.nixpkgs.lib.nixosSystem args;
    in
    {{
      nixosConfigurations."{hostname}" = mkHost {{
        inherit evalNixos pkgsEdge system;
        diskoModule = inputs.disko.nixosModules.disko;
        hostname = "{hostname}";
      }};

      # A candidate update must build this exact toplevel before promotion.
      checks."{system}".system =
        self.nixosConfigurations."{hostname}".config.system.build.toplevel;

      # Re-export the Disko package from the *locked* input. `nix run .#disko`
      # may execute package outputs directly, and the installer never fetches
      # an unpinned `latest` Disko during destructive work.
      packages."{system}".disko = inputs.disko.packages."{system}".disko;
    }};
}}
"#
    )
}

/// Non-flake compatibility entrypoint introduced in NixOS 26.05.
///
/// It consumes the same `flake.lock` but evaluates through nixpkgs' ordinary
/// `eval-config.nix`, so update preflight can require store-path parity between
/// flake and non-flake entrypoints. This is a compatibility oracle, not a
/// second independently pinned dependency graph.
fn render_system_nix(hostname: &str, system: &str) -> String {
    format!(
        r#"let
  pins = import ./lib/locked-inputs.nix {{ }};
  mkHost = import ./lib/mk-host.nix;
  system = "{system}";
  pkgsEdge = import pins.nixpkgsEdge {{
    inherit system;
    config.allowUnfree = true;
  }};
  evalNixos = args: import (pins.nixpkgs + "/nixos/lib/eval-config.nix") args;
in
(mkHost {{
  inherit evalNixos pkgsEdge system;
  diskoModule = import (pins.disko + "/module.nix");
  hostname = "{hostname}";
}}).config.system.build.toplevel
"#
    )
}

fn render_locked_inputs() -> String {
    r#"{ lockFile ? ../flake.lock }:
let
  lock = builtins.fromJSON (builtins.readFile lockFile);
  root = lock.nodes.${lock.root};

  nodeKey = ref:
    if builtins.isString ref then ref
    else if builtins.isList ref && builtins.length ref == 1 && builtins.isString (builtins.head ref)
    then builtins.head ref
    else throw "Symthaea system.nix: unsupported flake.lock input reference";

  nodeFor = name:
    if !(builtins.hasAttr name root.inputs)
    then throw "Symthaea system.nix: flake.lock is missing required input '${name}'"
    else lock.nodes.${nodeKey root.inputs.${name}};

  fetchGithub = name:
    let
      node = nodeFor name;
      locked = node.locked or (throw "Symthaea system.nix: '${name}' is not locked");
    in
      if (locked.type or "") != "github"
      then throw "Symthaea system.nix: '${name}' must remain a locked GitHub input"
      else if !(locked ? owner && locked ? repo && locked ? rev && locked ? narHash)
      then throw "Symthaea system.nix: '${name}' lacks owner/repo/rev/narHash"
      else builtins.fetchTarball {
        url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
        sha256 = locked.narHash;
      };
in
{
  nixpkgs = fetchGithub "nixpkgs";
  nixpkgsEdge = fetchGithub "nixpkgs-edge";
  disko = fetchGithub "disko";
}
"#
    .into()
}

fn render_mk_host() -> String {
    r#"{ evalNixos, diskoModule, hostname, pkgsEdge, system }:
evalNixos {
  inherit system;
  specialArgs = {
    inherit pkgsEdge;
  };
  modules = [
    diskoModule
    (../hosts + "/${hostname}")
  ];
}
"#
    .into()
}

fn render_host_module(hostname: &str) -> String {
    format!(
        r#"{{ ... }}:
{{
  imports = [
    ./hardware-configuration.nix
    ../../profiles/base
    ../../modules/boot
    ../../modules/generated
    ../../disko
  ];

  networking.hostName = "{hostname}";

  # This is the compatibility baseline for a NEW installation. Do not bump it
  # automatically on later upgrades; NixOS stateVersion is not a release pin.
  system.stateVersion = "{state_version}";
}}
"#,
        state_version = DEFAULT_STATE_VERSION
    )
}

fn render_hardware_placeholder() -> String {
    r#"# Replaced by the trusted installer after target hardware discovery.
# Keeping this as a valid empty module allows pure flake evaluation before
# destructive installation begins.
{ ... }:
{
}
"#
    .into()
}

fn render_disko_placeholder() -> String {
    r#"# Replaced by the trusted relay with a typed, stable-device StoragePlan.
# A sovereign bundle is intentionally not buildable for installation until the
# target has been bound. This prevents an empty Disko placeholder from being
# mistaken for an authoritative storage configuration.
{ ... }:
{
  assertions = [ {
    assertion = false;
    message = "Symthaea storage intent has not been bound to a stable target disk";
  } ];
}
"#
    .into()
}

fn render_base_profile() -> String {
    r#"{ ... }:
{
  imports = [
    ../../modules/core
    ../../modules/security
    ../../modules/network-covenant
    ../../modules/network-enforcement
    ../../modules/network-observe
    ../../modules/network-runtime-lab
    ../../modules/network-calibration
    ../../modules/network-activation
    ../../modules/network-telemetry
    ../../modules/software
    ../../modules/guests
    ../../modules/maintenance
  ];
}
"#
    .into()
}

fn render_core_module(hostname: &str) -> String {
    format!(
        r#"{{ pkgs, ... }}:
{{
  networking.networkmanager.enable = true;

  # The owner account starts password-locked. The trusted installer may set a
  # password or enroll stronger credentials after the system closure is installed.
  users.users.{hostname} = {{
    isNormalUser = true;
    extraGroups = [ "wheel" "video" "networkmanager" ];
    initialHashedPassword = "!";
  }};

  environment.systemPackages = with pkgs; [
    age
    curl
    git
    vim
  ];

  nix = {{
    settings = {{
      experimental-features = [ "nix-command" "flakes" ];
      auto-optimise-store = true;
    }};
    gc = {{
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 30d";
    }};
  }};

  # Keep both flake.nix and system.nix evaluation byte-for-byte equivalent.
  # Exact source/lock identity lives in signed update/install evidence rather
  # than being injected differently by one evaluator.
  system.configurationRevision = "symthaea-sovereign-v18";
}}
"#
    )
}

fn render_boot_placeholder() -> String {
    r#"# Replaced by the trusted installer with boot policy derived from the
# locally observed firmware mode and the exact authorized target disk.
{ ... }:
{
}
"#
    .into()
}

fn render_security_module() -> String {
    r#"{ ... }:
{
  networking.firewall.enable = true;
  security.apparmor.enable = true;
  security.protectKernelImage = true;

  # Remote access is available for Xenia/owner enrollment without allowing
  # password-based remote administration by default.
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };
}
"#
    .into()
}

fn render_network_covenant_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkCovenant;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
  covenant = policy.policy or {};
in
{
  options.symthaea.networkCovenant = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-policy.json;
      description = "Typed Symthaea Network Covenant bound into this Holon generation.";
    };
  };

  config = {
    # V39 deliberately uses the boring NixOS host firewall as the mandatory
    # baseline. Workload/cgroup enforcement is a separate V40 proof boundary.
    networking.firewall.enable = true;
    networking.nftables.enable = true;

    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea Network Covenant schema; explicit migration required";
      }
      {
        assertion = (covenant.host_ingress_default or "") == "deny";
        message = "sovereign Network Covenant requires default-deny host ingress";
      }
      {
        assertion = (covenant.host_forward_default or "") == "deny";
        message = "sovereign Network Covenant requires default-deny forwarding";
      }
      {
        assertion = (covenant.reasoning_authority or "") == "none";
        message = "Symthaea reasoning/anomaly evidence may not become firewall authority";
      }
      {
        assertion = !(covenant.payload_capture_default or false);
        message = "payload capture must remain explicit opt-in, never baseline telemetry";
      }
    ];

    environment.etc."symthaea/network-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_enforcement_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkEnforcement;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
in
{
  options.symthaea.networkEnforcement = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-enforcement-policy.json;
      description = "Proof-gated workload-aware kernel network enforcement policy.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea network-enforcement schema; explicit migration required";
      }
      {
        assertion = (policy.status or "") == "compiled-contract-runtime-lab-and-target-proof-required-v42";
        message = "V42 kernel enforcement requires both isolated lab proof and target runtime proof";
      }
      {
        assertion = (policy.activation or "") == "disabled-until-runtime-proof-v40";
        message = "V40/V42 kernel network enforcement must remain disabled until runtime proof and owner authorization exist";
      }
      {
        assertion = !(policy.fail_open or true);
        message = "workload-aware network enforcement may not be configured fail-open";
      }
      {
        assertion = (policy.reasoning_authority or "") == "none";
        message = "Symthaea reasoning may not activate or mutate kernel network enforcement";
      }
    ];

    environment.etc."symthaea/network-enforcement-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_activation_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkActivation;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
in
{
  options.symthaea.networkActivation = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-activation-policy.json;
      description = "Owner-authorized production network activation covenant.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea network-activation schema; explicit migration required";
      }
      {
        assertion = (policy.status or "") == "owner-authorized-production-activation-v46";
        message = "network activation policy drifted from the reviewed V46 covenant";
      }
      {
        assertion = (policy.source_claim or "") == "not-activated-by-generated-source";
        message = "generated source may require activation but may never self-claim production activation";
      }
      {
        assertion = !((policy.automatic_activation or true));
        message = "production network activation always requires a separate owner-authorized action";
      }
      {
        assertion = (policy.reasoning_authority or "") == "none";
        message = "Symthaea reasoning may not become production network activation authority";
      }
      {
        assertion = (((policy.post_activation or {}).preserve-nftables-baseline or false));
        message = "V46 activation must preserve the ordinary NixOS/nftables baseline";
      }
    ];

    environment.etc."symthaea/network-activation-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_telemetry_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkTelemetry;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
in
{
  options.symthaea.networkTelemetry = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-telemetry-policy.json;
      description = "Privacy-preserving metadata-only network telemetry policy.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea network-telemetry schema; explicit migration required";
      }
      {
        assertion = (policy.status or "") == "metadata-only-hash-chain-v47";
        message = "V47 telemetry status drifted from the reviewed metadata-only contract";
      }
      {
        assertion = !(policy.payload_capture or true);
        message = "V47 network telemetry may not capture payload bytes";
      }
      {
        assertion = !(policy.raw_destination_storage or true);
        message = "V47 default telemetry stores destination identity only as a digest";
      }
      {
        assertion = !(policy.exact_timestamp_storage or true);
        message = "V47 default telemetry stores only coarse time buckets";
      }
      {
        assertion = !(policy.network_enforcement_authority or true);
        message = "telemetry evidence may never become network-enforcement authority";
      }
    ];

    environment.etc."symthaea/network-telemetry-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_observe_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkObserve;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
  authority = policy.authority or {};
  telemetry = policy.telemetry or {};
in
{
  options.symthaea.networkObserve = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-cognition-policy.json;
      description = "Observe-only Symthaea network cognition policy.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.status or "") == "observe-only-v41";
        message = "network cognition must remain observe-only in V41";
      }
      {
        assertion = !(authority.network_enforcement or true);
        message = "network cognition may not hold firewall/kernel enforcement authority";
      }
      {
        assertion = !(authority.quarantine or true);
        message = "network cognition may not autonomously quarantine workloads";
      }
      {
        assertion = !(authority.capability_lease_minting or true);
        message = "network cognition may not mint network capability leases";
      }
      {
        assertion = !(telemetry.payload_capture_default or true);
        message = "network cognition payload capture must remain opt-in and disabled by default";
      }
    ];

    environment.etc."symthaea/network-cognition-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_runtime_lab_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkRuntimeLab;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
  separation = policy.evidence_separation or {};
  authority = policy.authority or {};
in
{
  options.symthaea.networkRuntimeLab = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-runtime-lab-policy.json;
      description = "V42 disposable runtime-lab evidence contract for the workload-aware network backend.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea network runtime-lab schema; explicit migration required";
      }
      {
        assertion = (policy.status or "") == "runtime-lab-required-v42";
        message = "V42 generated source may require the runtime lab but may not claim it has run";
      }
      {
        assertion = (policy.generated_source_claim or "") == "not-run";
        message = "a generated Holon may not self-attest a V42 runtime-lab result";
      }
      {
        assertion = (separation.lab_does_not_prove or "") == "production-holon-activation";
        message = "V42 lab evidence must remain distinct from production activation evidence";
      }
      {
        assertion = !(authority.production_activation or true);
        message = "runtime-lab policy may not hold production network activation authority";
      }
      {
        assertion = (authority.reasoning or "") == "none";
        message = "Symthaea reasoning may not become runtime-lab or production activation authority";
      }
      {
        assertion = !((policy.privacy or {}).payload_capture or true);
        message = "V42 network runtime lab must not require packet payload capture";
      }
    ];

    environment.etc."symthaea/network-runtime-lab-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_network_calibration_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.networkCalibration;
  policy = builtins.fromJSON (builtins.readFile cfg.policyFile);
  authority = policy.authority or {};
  threshold = policy.threshold or {};
in
{
  options.symthaea.networkCalibration = {
    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/network-calibration-policy.json;
      description = "V43 measurement-only calibration/drift contract for network cognition.";
    };
  };

  config = {
    assertions = [
      {
        assertion = (policy.schema_version or 0) == 1;
        message = "unsupported Symthaea network calibration schema; explicit migration required";
      }
      {
        assertion = (policy.status or "") == "measurement-only-v43";
        message = "V43 calibration must remain measurement-only";
      }
      {
        assertion = (policy.model_family or "") == "hdc-behavior-distance-v1";
        message = "V43 calibration must measure the reviewed V41 HDC model family";
      }
      {
        assertion = !(threshold.automatic_tuning or true);
        message = "V43 must not auto-tune an anomaly threshold against the evaluation corpus";
      }
      {
        assertion = !(authority.network_enforcement or true);
        message = "calibration evidence may not hold network-enforcement authority";
      }
      {
        assertion = !(authority.quarantine or true);
        message = "calibration evidence may not hold quarantine authority";
      }
      {
        assertion = !(authority.autonomous_response_eligible or true);
        message = "V43 calibration cannot make autonomous network response eligible";
      }
      {
        assertion = !((policy.telemetry or {}).payload_capture or true);
        message = "V43 calibration must remain payload-free";
      }
    ];

    environment.etc."symthaea/network-calibration-policy.json".source = cfg.policyFile;
  };
}
"#
    .into()
}

fn render_software_ingress_module() -> String {
    r#"{ config, lib, ... }:
let
  cfg = config.symthaea.softwareIngress;
in
{
  options.symthaea.softwareIngress = {
    allowAmbientHostMutation = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Emergency compatibility switch. Sovereign profiles require this to remain false.";
    };

    policyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/software-ingress-policy.json;
      description = "Machine-readable S0-S3 software ingress policy bound into this system source.";
    };

    guestPlanFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/guest-plans.json;
      description = "Exact typed S2/S3 guest plans expected by this Holon generation.";
    };

    guestStateFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/guest-state.json;
      description = "Expected content/authority identity for S2/S3 guest state.";
    };

    assimilationPolicyFile = lib.mkOption {
      type = lib.types.path;
      default = ../../generated/assimilation-policy.json;
      description = "Proposal-only S3 to S1/S2 assimilation policy; it grants no mutation authority.";
    };

  };

  config = {
    assertions = [
      {
        assertion = !cfg.allowAmbientHostMutation;
        message = "Symthaea sovereign systems forbid ambient host package/install mutation; use S0/S1 declarative realization or an S2/S3 guest enclosure";
      }
    ];

    # Surface exactly the policy bytes evaluated by this generation. Guest
    # runtime state remains a separate evidence domain from the Nix closure.
    environment.etc."symthaea/software-ingress-policy.json".source = cfg.policyFile;
    environment.etc."symthaea/guest-plans.json".source = cfg.guestPlanFile;
    environment.etc."symthaea/guest-state.json".source = cfg.guestStateFile;
    environment.etc."symthaea/assimilation-policy.json".source = cfg.assimilationPolicyFile;
  };
}
"#
    .into()
}

fn render_guest_state_module() -> String {
    r#"{ config, lib, pkgs, ... }:
let
  guestPlans = builtins.fromJSON (builtins.readFile config.symthaea.softwareIngress.guestPlanFile);
  guestState = builtins.fromJSON (builtins.readFile config.symthaea.softwareIngress.guestStateFile);
  allowedKinds = [ "flatpak-guest" "oci-guest" "ephemeral-capsule" ];
  allowedClasses = [ "sovereign-guest" "ephemeral-guest" ];
  className = entry: entry.trust_class or "";
  specKind = plan: (plan.spec.kind or "");
in
{
  # Guest engines are ordinary S0 host capabilities. External applications and
  # images remain S2/S3 state and are never silently folded into the Nix closure.
  # Runtime realization receipts live under /var/lib/symthaea-spore and are
  # intentionally not written back into this immutable/declarative source tree.
  services.flatpak.enable = true;
  virtualisation.podman.enable = true;
  environment.systemPackages = with pkgs; [ bubblewrap util-linux ];

  assertions = [
    {
      assertion = (guestPlans.schema_version or 0) == 2;
      message = "unsupported Symthaea guest-plan schema; explicit migration required";
    }
    {
      assertion = builtins.all (plan: builtins.elem (specKind plan) allowedKinds) (guestPlans.plans or []);
      message = "guest-plans.json may contain only S2/S3 realization plans";
    }
    {
      assertion = (guestState.schema_version or 0) == 2;
      message = "unsupported Symthaea guest-state schema; explicit migration required";
    }
    {
      assertion = builtins.all (entry: builtins.elem (className entry) allowedClasses) (guestState.entries or []);
      message = "guest-state.json may contain only S2/S3 guest entries; S0/S1 belong in the Nix realization graph";
    }
  ];
}
"#
    .into()
}

fn render_maintenance_module() -> String {
    r#"{ ... }:
{
  imports = [ ./update-steward.nix ];

  nix.optimise = {
    automatic = true;
    dates = [ "03:00" ];
  };

  services.symthaeaUpdateSteward.enable = true;
}
"#
    .into()
}

fn render_update_steward_module() -> String {
    r#"{ config, lib, pkgs, ... }:
let
  cfg = config.services.symthaeaUpdateSteward;
  steward = pkgs.writeShellApplication {
    name = "symthaea-update-steward";
    runtimeInputs = [
      config.nix.package
      pkgs.coreutils
      pkgs.curl
      pkgs.findutils
      pkgs.gitMinimal
      pkgs.gnugrep
      pkgs.gnused
      pkgs.jq
    ];
    text = builtins.readFile ../../scripts/symthaea-update-steward.sh;
  };
in
{
  options.services.symthaeaUpdateSteward = {
    enable = lib.mkEnableOption "candidate-built Symthaea/NixOS update stewardship";

    flakeRoot = lib.mkOption {
      type = lib.types.str;
      default = "/etc/nixos";
      description = "Canonical local flake root managed by the update steward.";
    };

    schedule = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "systemd calendar expression for update discovery/staging.";
    };

    randomizedDelaySec = lib.mkOption {
      type = lib.types.str;
      default = "45min";
      description = "Random delay to avoid synchronized update checks.";
    };

    promotion = lib.mkOption {
      type = lib.types.enum [ "stage" "boot" ];
      default = "stage";
      description = ''
        `stage` automatically discovers, locks, compatibility-probes and builds
        candidates but never mutates the installed flake. `boot` additionally
        promotes a passing same-release candidate to the next boot generation.
        Release-line migrations remain proposal-only in both modes.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ steward ];

    systemd.services.symthaea-update-steward = {
      description = "Stage and validate Symthaea/NixOS updates";
      after = [ "network-online.target" "symthaea-update-verify-boot.service" ];
      wants = [ "network-online.target" ];
      environment = {
        SYMTHAEA_FLAKE_ROOT = cfg.flakeRoot;
        SYMTHAEA_UPDATE_STATE = "/var/lib/symthaea-update";
        SYMTHAEA_EVIDENCE_STATE = "/var/lib/symthaea-evidence";
        SYMTHAEA_HOSTNAME = config.networking.hostName;
        SYMTHAEA_AUTO_PROMOTION = cfg.promotion;
        SYMTHAEA_NIXOS_REBUILD = "${config.system.build.nixos-rebuild}/bin/nixos-rebuild";
      };
      serviceConfig = {
        Type = "oneshot";
        StateDirectory = [ "symthaea-update" "symthaea-evidence" ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        # Staging is heavily sandboxed. `boot` promotion is an explicitly
        # pre-authorized privileged operation and must allow nixos-rebuild to
        # update profiles, boot files and firmware state as required.
        ProtectSystem = if cfg.promotion == "stage" then "strict" else false;
        ReadWritePaths = [
          "/var/lib/symthaea-update"
          "/var/lib/symthaea-evidence"
        ] ++ lib.optional (cfg.promotion == "boot") cfg.flakeRoot;
        ReadOnlyPaths = lib.optional (cfg.promotion == "stage") cfg.flakeRoot;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
      script = "${steward}/bin/symthaea-update-steward cycle";
    };

    # A boot generation is not considered successful merely because
    # `nixos-rebuild boot` created it. On the next boot, finalize the evidence
    # chain only if /run/current-system is the exact staged store path.
    systemd.services.symthaea-update-verify-boot = {
      description = "Verify activated Symthaea/NixOS generation";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      before = [ "symthaea-update-steward.service" ];
      environment = {
        SYMTHAEA_FLAKE_ROOT = cfg.flakeRoot;
        SYMTHAEA_UPDATE_STATE = "/var/lib/symthaea-update";
        SYMTHAEA_EVIDENCE_STATE = "/var/lib/symthaea-evidence";
        SYMTHAEA_HOSTNAME = config.networking.hostName;
      };
      serviceConfig = {
        Type = "oneshot";
        StateDirectory = [ "symthaea-update" "symthaea-evidence" ];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadOnlyPaths = [ cfg.flakeRoot "/run/current-system" ];
        ReadWritePaths = [
          "/var/lib/symthaea-update"
          "/var/lib/symthaea-evidence"
        ];
        RestrictAddressFamilies = [ "AF_UNIX" ];
      };
      script = "${steward}/bin/symthaea-update-steward verify-boot";
    };

    systemd.timers.symthaea-update-steward = {
      description = "Periodic Symthaea/NixOS update discovery";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule;
        Persistent = true;
        RandomizedDelaySec = cfg.randomizedDelaySec;
      };
    };
  };
}
"#
    .into()
}

fn render_update_policy() -> String {
    let policy = UpdatePolicy {
        schema_version: UPDATE_POLICY_SCHEMA_VERSION,
        kind: "symthaea-update-policy-v1",
        release: ReleasePolicy {
            current: DEFAULT_NIXPKGS_REF.trim_start_matches("nixos-").into(),
            migrations: "proposal-only",
            state_version: "never-auto-bump",
            discovery: ReleaseDiscovery {
                git_remote: "https://github.com/NixOS/nixpkgs.git",
                channel_base: "https://channels.nixos.org",
            },
            required_gates: vec![
                "explicit-source-ref-migration",
                "trusted-upstream-origin",
                "flake-check",
                "full-system-build",
                "dual-entrypoint-parity",
                "vm-boot-validation",
                "owner-change-authorization",
                "post-boot-verification",
            ],
        },
        inputs: vec![
            InputUpdatePolicy {
                name: "nixpkgs",
                lane: "stable-system",
                strategy: "lock-only",
                auto_stage: true,
                auto_boot_eligible: true,
            },
            InputUpdatePolicy {
                name: "nixpkgs-edge",
                lane: "edge-packages",
                strategy: "manual-lock",
                auto_stage: false,
                auto_boot_eligible: false,
            },
            InputUpdatePolicy {
                name: "disko",
                lane: "storage-schema",
                strategy: "source-ref-migration",
                auto_stage: false,
                auto_boot_eligible: false,
            },
        ],
        promotion: PromotionPolicy {
            default: DEFAULT_UPDATE_PROMOTION,
            source_drift: "refuse-if-source-changed-since-stage",
            activation: "boot-not-switch",
        },
        compatibility: CompatibilityPolicy {
            mode: "feature-probe",
            required_capabilities: vec![
                "nix flake metadata",
                "nix flake update",
                "nix flake check",
                "nix build",
                "nix eval",
                "nix hash path",
                "nix-build system.nix",
            ],
        },
        entrypoints: EntrypointPolicy {
            canonical: "flake.nix",
            compatibility: "system.nix",
            parity: "exact-toplevel-store-path",
        },
        lineage: LineagePolicy {
            mode: "hash-chained-generation-receipts",
            post_boot_verification: true,
            receipt_hash: "sha256",
        },
    };

    serde_json::to_string_pretty(&policy)
        .map(|json| json + "\n")
        .unwrap_or_else(|_| {
            "{\"schema_version\":2,\"error\":\"update policy serialization failed\"}\n".into()
        })
}

fn render_upstream_source_policy() -> String {
    let policy = UpstreamSourcePolicy {
        schema_version: UPSTREAM_SOURCE_POLICY_SCHEMA_VERSION,
        kind: "symthaea-upstream-source-policy-v1",
        sources: vec![
            TrustedUpstreamSource {
                input: "nixpkgs",
                source_type: "github",
                owner: "NixOS",
                repo: "nixpkgs",
                declared_ref: DEFAULT_NIXPKGS_REF,
                trust_class: "official-nixos",
                movement: "lock-only-within-declared-release-line",
            },
            TrustedUpstreamSource {
                input: "nixpkgs-edge",
                source_type: "github",
                owner: "NixOS",
                repo: "nixpkgs",
                declared_ref: DEFAULT_EDGE_NIXPKGS_REF,
                trust_class: "official-nixos-edge",
                movement: "manual-policy-only",
            },
            TrustedUpstreamSource {
                input: "disko",
                source_type: "github",
                owner: "nix-community",
                repo: "disko",
                declared_ref: DEFAULT_DISKO_REF,
                trust_class: "pinned-storage-schema",
                movement: "explicit-source-ref-migration",
            },
        ],
    };

    serde_json::to_string_pretty(&policy)
        .map(|json| json + "\n")
        .unwrap_or_else(|_| {
            "{\"schema_version\":1,\"error\":\"source policy serialization failed\"}\n".into()
        })
}

fn render_schema_manifest() -> String {
    let schema = serde_json::json!({
        "schema_version": SOVEREIGN_SCHEMA_MANIFEST_VERSION,
        "kind": "symthaea-sovereign-schema-v1",
        "sovereign_flake_schema": SOVEREIGN_FLAKE_SCHEMA_VERSION,
        "update_policy_schema": UPDATE_POLICY_SCHEMA_VERSION,
        "upstream_source_policy_schema": UPSTREAM_SOURCE_POLICY_SCHEMA_VERSION,
        "storage_plan_schema": crate::storage_intent::STORAGE_PLAN_SCHEMA_VERSION,
        "reconstitution_schema": crate::reconstitution::RECONSTITUTION_SCHEMA_VERSION,
        "software_ingress_schema": SOFTWARE_INGRESS_SCHEMA_VERSION,
        "guest_realization_schema": GUEST_REALIZATION_SCHEMA_VERSION,
        "software_assimilation_schema": SOFTWARE_ASSIMILATION_SCHEMA_VERSION,
        "network_covenant_schema": NETWORK_COVENANT_SCHEMA_VERSION,
        "network_enforcement_schema": NETWORK_ENFORCEMENT_SCHEMA_VERSION,
        "network_cognition_schema": NETWORK_COGNITION_SCHEMA_VERSION,
        "network_runtime_lab_schema": NETWORK_RUNTIME_LAB_SCHEMA_VERSION,
        "network_calibration_schema": NETWORK_CALIBRATION_SCHEMA_VERSION,
        "network_activation_schema": NETWORK_ACTIVATION_SCHEMA_VERSION,
        "network_telemetry_schema": NETWORK_TELEMETRY_SCHEMA_VERSION,
        "network_covenant": {
            "host_firewall": "nixos-firewall+nftables",
            "host_ingress_default": "deny",
            "host_forward_default": "deny",
            "workload_egress": "declared-not-runtime-enforced-v39",
            "reasoning_authority": "none",
            "payload_capture_default": false
        },
        "network_enforcement": {
            "backend": "cgroup-sockaddr-bpf-contract-v40",
            "status": "compiled-contract-runtime-lab-and-target-proof-required-v42",
            "activation": "disabled-until-runtime-proof-v40",
            "fail_open": false,
            "reasoning_authority": "none"
        },
        "network_cognition": {
            "status": "observe-only-v41",
            "network_enforcement_authority": false,
            "quarantine_authority": false,
            "payload_capture_default": false
        },
        "network_runtime_lab": {
            "status": "runtime-lab-required-v42",
            "generated_source_claim": "not-run",
            "execution_harness": "executable-runner-v44",
            "production_activation_authority": false,
            "target_host_runtime_proof_required": true
        },
        "network_telemetry": {
            "status": "metadata-only-hash-chain-v47",
            "payload_capture": false,
            "raw_destination_storage": false,
            "exact_timestamp_storage": false,
            "network_enforcement_authority": false
        },
        "network_activation": {
            "status": "owner-authorized-production-activation-v46",
            "source_claim": "not-activated-by-generated-source",
            "automatic_activation": false,
            "reasoning_authority": "none",
            "preserve_nftables_baseline": true
        },
        "network_calibration": {
            "status": "measurement-only-v43",
            "model_family": "hdc-behavior-distance-v1",
            "automatic_threshold_tuning": false,
            "held_out_required": true,
            "threshold_selection": "externally-selected-before-held-out-v45",
            "autonomous_response_eligible": false,
            "network_enforcement_authority": false,
            "quarantine_authority": false
        },
        "software_ingress": {
            "ambient_host_mutation": "forbidden",
            "guest_realization": "typed-receipts-v37",
            "promotion": "proposal-only-v38-requires-change-covenant"
        },
        "storage_realization": {
            "unbound": STORAGE_REALIZATION_STATUS,
            "authoritative": AUTHORITATIVE_STORAGE_STATUS,
            "migration": "explicit-storage-schema-migration"
        },
        "entrypoints": {
            "canonical": "flake.nix",
            "compatibility": "system.nix",
            "parity": "exact-toplevel-store-path"
        },
        "migration": {
            "unknown_future_schema": "refuse-and-propose-migration",
            "state_version": "never-auto-bump",
            "release_line": "proposal-only"
        }
    });
    serde_json::to_string_pretty(&schema)
        .map(|json| json + "\n")
        .unwrap_or_else(|_| {
            "{\"schema_version\":1,\"error\":\"schema serialization failed\"}\n".into()
        })
}

fn render_readme(hostname: &str) -> String {
    format!(
        r#"# Symthaea Sovereign System: {hostname}

This directory is generated as a reviewable NixOS system definition. Its shape
is intentionally compatible with the conventions used by larger Luminous
workstations: host-local facts stay under `hosts/`, reusable policy is composed
through `profiles/`, modules own one concern, and generated decisions are kept
separate from stable policy.

## Layout

- `flake.nix` — thin dependency/output wrapper.
- `system.nix` — non-flake recovery/compatibility entrypoint over the same lock.
- `lib/locked-inputs.nix` — strict adapter from `flake.lock` to pinned source trees.
- `lib/mk-host.nix` — host constructor and explicit stable/edge package split.
- `hosts/{hostname}/` — host identity and hardware facts.
- `profiles/base/` — reusable baseline composition.
- `modules/core/` — stable operating-system baseline and owner account.
- `modules/boot/` — target-local boot policy generated by the trusted installer.
- `modules/security/` — security policy kept separate from convenience policy.
- `modules/network-covenant/` — deterministic host firewall baseline and network-authority constitution.
- `modules/network-enforcement/` — proof-gated workload/cgroup kernel-enforcement contract; activation disabled by default.
- `modules/network-observe/` — observe-only HDC/anomaly cognition policy with zero firewall/quarantine authority.
- `modules/network-runtime-lab/` — V42 lab-evidence boundary; generated source may require tests but never self-claim they passed.
- `modules/network-calibration/` — V43 measurement-only calibration/drift contract; no autonomous-response authority.
- `modules/network-activation/` — V46 owner-authorized production activation covenant; generated source can never self-claim activation.
- `modules/network-telemetry/` — V47 metadata-only, bounded, hash-chained network evidence; no payload/enforcement authority.
- `modules/software/` — machine-enforced Software Ingress Covenant.
- `modules/guests/` — guest-state evidence boundary; realization backends are promoted separately.
- `modules/maintenance/` — GC/optimisation and candidate-built update stewardship.
- `modules/generated/` — Symthaea/Nixward reasoned choices.
- `scripts/symthaea-update-steward.sh` — reviewable update candidate engine.
- `disko/` — authoritative storage-policy boundary after a typed V27 StoragePlan is bound.
- `generated/update-policy.json` — machine-readable update lanes and migration rules.
- `generated/source-policy.json` — allowed upstream input identities and trust classes.
- `generated/network-policy.json` — typed workload/capability network intent; reasoning has no enforcement authority.
- `generated/network-enforcement-policy.json` — required cgroup/BPF proof gates; does not claim a program was loaded.
- `generated/network-cognition-policy.json` — privacy-preserving observe-only HDC reasoning contract.
- `generated/network-runtime-lab-policy.json` — isolated backend-lab requirements; production activation remains a separate covenant.
- `generated/network-calibration-policy.json` — explicit corpus/threshold/drift rules; policy contradictions are not counted as AI ground truth.
- `generated/network-activation-policy.json` — V46 target activation/rollback invariants; owner signature and runtime post-checks required.
- `generated/network-telemetry-policy.json` — V47 privacy/retention/hash-chain contract for real-flow evidence and calibration export.
- `generated/software-ingress-policy.json` — S0–S3 realization/authority constitution.
- `generated/assimilation-policy.json` — proposal-only S3→S1/S2 promotion rules and required proof gates.
- `generated/guest-state.json` — guest provenance/authority manifest (empty by default).
- `generated/schema.json` — explicit schema/migration compatibility contract.
- `generated/manifest.json` — BLAKE3 provenance for the generated bundle.

## Update model

The running system does **not** blindly run `nix flake update` in place.
`symthaea-update-steward` copies the current flake into an isolated candidate,
updates only policy-approved lock entries, verifies every locked input still comes
from its allowed upstream owner/repository, builds the complete candidate NixOS
toplevel, evaluates `system.nix`, requires both entrypoints to resolve to the same
store path, probes the candidate Nix CLI capabilities, and records a receipt.

The default `promotion = "stage"` never mutates `/etc/nixos`. Owners who
explicitly configure `promotion = "boot"` pre-authorize passing same-release
lock-only updates to become the next boot generation. The current running system
is not switched underneath the user, and normal NixOS generations remain the
rollback mechanism.

Release-line changes such as `26.05 -> 26.11` are discovered from the official
NixOS/nixpkgs Git refs and confirmed against the official channel endpoint, but
are **proposal-only** because they can remove/rename modules and options.
`system.stateVersion` is never bumped automatically.

`flake.lock` is intentionally created by the trusted installer during preflight,
before destructive disk operations. The resulting lock digest should be bound to
the installation ChangePlan/Genesis receipt.

The generated flake is deliberately boring: Symthaea may reason about the desired
system, but ordinary NixOS modules remain the auditable source of truth. The
manifest's `storage_realization_status` must be consulted before making claims
about fully declarative disk reproduction.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardware(arch: &str) -> HardwareProfile {
        HardwareProfile {
            arch: arch.into(),
            ..Default::default()
        }
    }

    fn choices(hostname: &str) -> UserChoices {
        UserChoices {
            hostname: hostname.into(),
            ..Default::default()
        }
    }

    #[test]
    fn bundle_has_reference_quality_layout() {
        let bundle = build_sovereign_flake_bundle(
            &hardware("x86_64"),
            &choices("holon-01"),
            "{ ... }: { networking.firewall.enable = true; }",
        )
        .unwrap();

        assert_eq!(bundle.schema_version, 18);
        assert_eq!(bundle.system, "x86_64-linux");
        assert_eq!(bundle.state_version, "26.05");
        assert_eq!(bundle.nixpkgs_ref, "nixos-26.05");
        assert_eq!(bundle.edge_nixpkgs_ref, "nixos-unstable");
        assert_eq!(bundle.update_promotion, "stage");
        assert_eq!(
            bundle.storage_realization_status,
            "storage-intent-required-v27"
        );
        assert!(bundle.storage_plan_blake3.is_none());
        for path in [
            "flake.nix",
            "system.nix",
            "lib/locked-inputs.nix",
            "lib/mk-host.nix",
            "hosts/holon-01/default.nix",
            "hosts/holon-01/hardware-configuration.nix",
            "profiles/base/default.nix",
            "modules/core/default.nix",
            "modules/boot/default.nix",
            "modules/security/default.nix",
            "modules/network-covenant/default.nix",
            "modules/network-enforcement/default.nix",
            "modules/network-observe/default.nix",
            "modules/network-runtime-lab/default.nix",
            "modules/network-calibration/default.nix",
            "modules/network-activation/default.nix",
            "modules/network-telemetry/default.nix",
            "modules/software/default.nix",
            "modules/guests/default.nix",
            "modules/maintenance/default.nix",
            "modules/maintenance/update-steward.nix",
            "modules/generated/default.nix",
            "scripts/symthaea-update-steward.sh",
            "disko/default.nix",
            "generated/update-policy.json",
            "generated/source-policy.json",
            "generated/network-policy.json",
            "generated/network-enforcement-policy.json",
            "generated/network-cognition-policy.json",
            "generated/network-runtime-lab-policy.json",
            "generated/network-calibration-policy.json",
            "generated/network-activation-policy.json",
            "generated/network-telemetry-policy.json",
            "generated/evaluator-policy.json",
            "generated/continuity-policy.json",
            "generated/software-ingress-policy.json",
            "generated/assimilation-policy.json",
            "generated/guest-plans.json",
            "generated/guest-state.json",
            "generated/schema.json",
            "generated/manifest.json",
        ] {
            assert!(bundle.files.contains_key(path), "missing {path}");
        }
        assert!(bundle.flake_nix().unwrap().contains("nixos-26.05"));
        assert!(bundle.flake_nix().unwrap().contains("nixos-unstable"));
        assert!(bundle.flake_nix().unwrap().contains("disko/v1.13.0"));
        assert_eq!(bundle.entrypoint_mode, "flake-plus-system-nix-parity");
        assert!(
            bundle
                .file("system.nix")
                .unwrap()
                .contains("locked-inputs.nix")
        );
    }

    #[test]
    fn update_policy_separates_stable_edge_and_release_migrations() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value =
            serde_json::from_str(bundle.file("generated/update-policy.json").unwrap()).unwrap();
        assert_eq!(policy["release"]["current"], "26.05");
        assert_eq!(policy["release"]["migrations"], "proposal-only");
        assert_eq!(policy["release"]["state_version"], "never-auto-bump");
        assert!(
            policy["release"]["required_gates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gate| gate == "vm-boot-validation")
        );
        assert_eq!(policy["promotion"]["default"], "stage");
        assert_eq!(policy["compatibility"]["mode"], "feature-probe");
        assert_eq!(policy["entrypoints"]["parity"], "exact-toplevel-store-path");
        assert_eq!(policy["lineage"]["post_boot_verification"], true);
        assert_eq!(policy["inputs"][0]["name"], "nixpkgs");
        assert_eq!(policy["inputs"][0]["auto_stage"], true);
        assert_eq!(policy["inputs"][1]["name"], "nixpkgs-edge");
        assert_eq!(policy["inputs"][1]["auto_stage"], false);
        assert_eq!(policy["inputs"][2]["name"], "disko");
        assert_eq!(policy["inputs"][2]["strategy"], "source-ref-migration");
    }

    #[test]
    fn bundle_is_deterministic() {
        let first = build_sovereign_flake_bundle(
            &hardware("aarch64"),
            &choices("spore-arm"),
            "{ ... }: { }",
        )
        .unwrap();
        let second = build_sovereign_flake_bundle(
            &hardware("aarch64"),
            &choices("spore-arm"),
            "{ ... }: { }",
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn hostile_hostname_cannot_become_nix_syntax_or_path() {
        for hostile in [
            "../etc/shadow",
            "Guardian",
            "host\"; builtins.abort \"boom",
            "-leading",
            "trailing-",
            "host/name",
        ] {
            assert!(matches!(
                build_sovereign_flake_bundle(
                    &hardware("x86_64"),
                    &choices(hostile),
                    "{ ... }: { }"
                ),
                Err(SovereignFlakeError::InvalidHostname(_))
            ));
        }
    }

    #[test]
    fn dual_entrypoints_share_one_module_graph() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let flake = bundle.file("flake.nix").unwrap();
        let system = bundle.file("system.nix").unwrap();
        let constructor = bundle.file("lib/mk-host.nix").unwrap();
        let core = bundle.file("modules/core/default.nix").unwrap();

        assert!(flake.contains("mkHost = import ./lib/mk-host.nix"));
        assert!(system.contains("mkHost = import ./lib/mk-host.nix"));
        assert!(system.contains("nixos/lib/eval-config.nix"));
        assert!(constructor.contains("diskoModule"));
        assert!(!core.contains("inputs."));
    }

    #[test]
    fn upstream_source_policy_pins_expected_organizations() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value =
            serde_json::from_str(bundle.file("generated/source-policy.json").unwrap()).unwrap();
        assert_eq!(policy["sources"][0]["owner"], "NixOS");
        assert_eq!(policy["sources"][0]["repo"], "nixpkgs");
        assert_eq!(policy["sources"][0]["declared_ref"], "nixos-26.05");
        assert_eq!(policy["sources"][2]["owner"], "nix-community");
        assert_eq!(policy["sources"][2]["repo"], "disko");
    }

    #[test]
    fn evaluator_policy_keeps_tvix_observer_only() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value =
            serde_json::from_str(bundle.file("generated/evaluator-policy.json").unwrap()).unwrap();
        assert_eq!(policy["generated_subset"]["name"], "SNS-1");
        assert_eq!(policy["generated_subset"]["divergence"], "block");
        assert_eq!(policy["authoritative_realizer"], "cpp-nix");
        assert_eq!(policy["witnesses"][0]["name"], "tvix");
        assert_eq!(policy["witnesses"][0]["enabled"], false);
        assert_eq!(policy["witnesses"][0]["authority"], "none");
    }

    #[test]
    fn schema_manifest_requires_migration_for_unknown_future_schema() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(schema["sovereign_flake_schema"], 18);
        assert_eq!(schema["update_policy_schema"], 2);
        assert_eq!(
            schema["migration"]["unknown_future_schema"],
            "refuse-and-propose-migration"
        );
    }

    #[test]
    fn storage_plan_binding_replaces_placeholder_and_refreshes_manifest() {
        use crate::storage_intent::{StableDiskIdentity, StorageIntent, StorageLayout};

        let mut bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let before = bundle.bundle_digest_blake3.clone();
        let plan = StorageIntent {
            layout: StorageLayout::SingleBtrfs,
            primary: StableDiskIdentity {
                by_id: "/dev/disk/by-id/nvme-test".into(),
                model: "test".into(),
                serial: "serial".into(),
                wwn: "wwn".into(),
                size: "1T".into(),
            },
        }
        .into_plan()
        .unwrap();

        bundle.bind_storage_plan(&plan).unwrap();
        assert_eq!(
            bundle.storage_realization_status,
            AUTHORITATIVE_STORAGE_STATUS
        );
        assert_eq!(
            bundle.storage_plan_blake3.as_deref(),
            Some(plan.plan_digest_blake3.as_str())
        );
        assert_ne!(bundle.bundle_digest_blake3, before);
        assert!(
            bundle
                .file("disko/default.nix")
                .unwrap()
                .contains("/dev/disk/by-id/nvme-test")
        );
        assert!(bundle.files.contains_key("generated/storage-plan.json"));
        let manifest: serde_json::Value =
            serde_json::from_str(bundle.file("generated/manifest.json").unwrap()).unwrap();
        assert_eq!(manifest["storage_plan_blake3"], plan.plan_digest_blake3);
    }

    #[test]
    fn sovereign_flake_binds_network_covenant_without_granting_ai_authority() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value =
            serde_json::from_str(bundle.file("generated/network-policy.json").unwrap()).unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["policy"]["holon_id"], "holon-01");
        assert_eq!(policy["policy"]["host_ingress_default"], "deny");
        assert_eq!(policy["policy"]["host_forward_default"], "deny");
        assert_eq!(policy["reasoning"]["authority"], "none");
        assert_eq!(policy["reasoning"]["payload_capture_default"], false);
        assert_eq!(schema["network_covenant_schema"], 1);
        let module = bundle.file("modules/network-covenant/default.nix").unwrap();
        assert!(module.contains("networking.firewall.enable = true"));
        assert!(module.contains("networking.nftables.enable = true"));
        assert!(module.contains("reasoning/anomaly evidence may not become firewall authority"));
    }

    #[test]
    fn sovereign_flake_carries_proof_gated_network_enforcement_without_claiming_activation() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-enforcement-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(
            policy["status"],
            "compiled-contract-runtime-lab-and-target-proof-required-v42"
        );
        assert_eq!(policy["activation"], "disabled-until-runtime-proof-v40");
        assert_eq!(policy["fail_open"], false);
        assert_eq!(policy["reasoning_authority"], "none");
        assert!(
            policy["not_claimed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "bpf-program-loaded")
        );
        assert_eq!(schema["network_enforcement_schema"], 1);
        let module = bundle
            .file("modules/network-enforcement/default.nix")
            .unwrap();
        assert!(module.contains("disabled-until-runtime-proof-v40"));
        assert!(!module.contains("bpftool prog load"));
    }

    #[test]
    fn sovereign_flake_binds_observe_only_network_cognition_without_quarantine_authority() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-cognition-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["status"], "observe-only-v41");
        assert_eq!(policy["authority"]["network_enforcement"], false);
        assert_eq!(policy["authority"]["quarantine"], false);
        assert_eq!(policy["telemetry"]["payload_capture_default"], false);
        assert_eq!(schema["network_cognition_schema"], 1);
        let module = bundle.file("modules/network-observe/default.nix").unwrap();
        assert!(module.contains("observe-only-v41"));
        assert!(!module.contains("nft add rule"));
        assert!(!module.contains("bpftool"));
    }

    #[test]
    fn sovereign_flake_requires_network_runtime_lab_without_self_attesting_success() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-runtime-lab-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["status"], "runtime-lab-required-v42");
        assert_eq!(policy["generated_source_claim"], "not-run");
        assert_eq!(policy["authority"]["production_activation"], false);
        assert_eq!(policy["authority"]["reasoning"], "none");
        assert_eq!(policy["privacy"]["payload_capture"], false);
        assert_eq!(schema["network_runtime_lab_schema"], 1);
        assert_eq!(schema["sovereign_flake_schema"], 18);
        let module = bundle
            .file("modules/network-runtime-lab/default.nix")
            .unwrap();
        assert!(module.contains("generated_source_claim"));
        assert!(module.contains("production network activation authority"));
    }

    #[test]
    fn sovereign_flake_binds_measurement_only_network_calibration() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-calibration-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["status"], "measurement-only-v43");
        assert_eq!(policy["model_family"], "hdc-behavior-distance-v1");
        assert_eq!(policy["threshold"]["automatic_tuning"], false);
        assert_eq!(policy["authority"]["network_enforcement"], false);
        assert_eq!(policy["authority"]["quarantine"], false);
        assert_eq!(policy["authority"]["autonomous_response_eligible"], false);
        assert_eq!(schema["network_calibration_schema"], 1);
        assert_eq!(schema["sovereign_flake_schema"], 18);
    }

    #[test]
    fn sovereign_flake_binds_owner_authorized_network_activation_policy() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-activation-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(
            policy["status"],
            "owner-authorized-production-activation-v46"
        );
        assert_eq!(policy["source_claim"], "not-activated-by-generated-source");
        assert_eq!(policy["automatic_activation"], false);
        assert_eq!(policy["reasoning_authority"], "none");
        assert_eq!(schema["network_activation_schema"], 1);
        assert_eq!(schema["sovereign_flake_schema"], 18);
    }

    #[test]
    fn sovereign_flake_binds_metadata_only_network_telemetry_policy() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/network-telemetry-policy.json")
                .unwrap(),
        )
        .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["status"], "metadata-only-hash-chain-v47");
        assert_eq!(policy["payload_capture"], false);
        assert_eq!(policy["raw_destination_storage"], false);
        assert_eq!(policy["exact_timestamp_storage"], false);
        assert_eq!(policy["network_enforcement_authority"], false);
        assert_eq!(schema["network_telemetry_schema"], 1);
        assert_eq!(schema["sovereign_flake_schema"], 18);
    }

    #[test]
    fn sovereign_flake_binds_software_ingress_constitution_without_overclaiming_guest_realization()
    {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value = serde_json::from_str(
            bundle
                .file("generated/software-ingress-policy.json")
                .unwrap(),
        )
        .unwrap();
        let guests: serde_json::Value =
            serde_json::from_str(bundle.file("generated/guest-state.json").unwrap()).unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();

        assert_eq!(
            policy["guest_realization_status"],
            "typed-realization-evidence-v37"
        );
        assert_eq!(guests["entries"].as_array().unwrap().len(), 0);
        assert_eq!(schema["software_ingress_schema"], 2);
        assert_eq!(
            schema["software_ingress"]["ambient_host_mutation"],
            "forbidden"
        );
        assert!(
            bundle
                .file("modules/software/default.nix")
                .unwrap()
                .contains("allowAmbientHostMutation")
        );
        assert!(
            bundle
                .file("modules/guests/default.nix")
                .unwrap()
                .contains("services.flatpak.enable = true")
        );
    }

    #[test]
    fn assimilation_policy_is_proposal_only_and_source_bound() {
        let bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let policy: serde_json::Value =
            serde_json::from_str(bundle.file("generated/assimilation-policy.json").unwrap())
                .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(bundle.file("generated/schema.json").unwrap()).unwrap();
        assert_eq!(policy["status"], "proposal-only-v38");
        assert_eq!(policy["automatic_promotion"], false);
        assert_eq!(schema["software_assimilation_schema"], 1);
        assert!(
            bundle
                .file("modules/software/default.nix")
                .unwrap()
                .contains("assimilationPolicyFile")
        );
    }

    #[test]
    fn guest_state_binding_accepts_only_s2_s3_and_refreshes_bundle_identity() {
        use crate::software_ingress::{
            CapsuleNetworkPolicy, CapsulePersistence, ContentDigest, EphemeralCapsulePlan,
            GuestPermissionEnvelope, SoftwareIngressSpec,
        };

        let mut bundle =
            build_sovereign_flake_bundle(&hardware("x86_64"), &choices("holon-01"), "{ ... }: { }")
                .unwrap();
        let before = bundle.bundle_digest_blake3.clone();
        let plan = SoftwareIngressPlan::new(
            "scratch",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let guest_digest = bundle.bind_guest_state(&[plan]).unwrap();
        assert_eq!(guest_digest.len(), 64);
        assert_ne!(bundle.bundle_digest_blake3, before);
        let guests: serde_json::Value =
            serde_json::from_str(bundle.file("generated/guest-state.json").unwrap()).unwrap();
        assert_eq!(guests["entries"].as_array().unwrap().len(), 1);

        let s0 = SoftwareIngressPlan::new(
            "git",
            SoftwareIngressSpec::SovereignNix(crate::software_ingress::SovereignNixPackage {
                attribute: "git".into(),
            }),
        )
        .unwrap();
        assert!(matches!(
            bundle.bind_guest_state(&[s0]),
            Err(SovereignFlakeError::InvalidSoftwareIngress(_))
        ));
    }

    #[test]
    fn target_architecture_is_not_hard_coded() {
        let arm =
            build_sovereign_flake_bundle(&hardware("arm64"), &choices("holon-arm"), "{ ... }: { }")
                .unwrap();
        assert!(arm.flake_nix().unwrap().contains("aarch64-linux"));
    }
}
