// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Software Ingress Covenant.
//!
//! Nixward protects the sovereign baseline. Software may enter that baseline
//! only through a reproducible declarative realization. Everything else must
//! execute inside an explicitly bounded guest environment whose state and
//! authority remain distinct from the host.
//!
//! The trust classes are deliberately about *realization and authority*, not
//! where software originated:
//!
//! - S0 [`SoftwareTrustClass::SovereignNix`] — ordinary Nix/NixOS realization.
//! - S1 [`SoftwareTrustClass::NixEnclosedForeign`] — foreign/proprietary input
//!   assimilated into a content-addressed Nix derivation.
//! - S2 [`SoftwareTrustClass::SovereignGuest`] — content-pinned Flatpak/OCI
//!   guest with an explicit permission envelope.
//! - S3 [`SoftwareTrustClass::EphemeralGuest`] — intentionally non-reproducible
//!   experiment contained away from the sovereign baseline.
//!
//! No class grants permission to imperatively rewrite the host.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const PLAN_DOMAIN: &[u8] = b"symthaea:nixward:software-ingress-plan:v1\0";
const PERMISSION_DOMAIN: &[u8] = b"symthaea:nixward:guest-permission-envelope:v1\0";
const GUEST_MANIFEST_DOMAIN: &[u8] = b"symthaea:nixward:guest-state-manifest:v1\0";

pub const SOFTWARE_INGRESS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum SoftwareTrustClass {
    /// Exact software state is part of the Nix/NixOS realization graph.
    SovereignNix,
    /// Non-nixpkgs software is converted into an exact Nix derivation.
    NixEnclosedForeign,
    /// Software remains outside the Nix store but is content-pinned and
    /// capability-contained by a declarative guest plan.
    SovereignGuest,
    /// Unmanaged experiment; no persistence/reproducibility claim is made.
    EphemeralGuest,
}

impl SoftwareTrustClass {
    pub fn code(self) -> &'static str {
        match self {
            Self::SovereignNix => "S0",
            Self::NixEnclosedForeign => "S1",
            Self::SovereignGuest => "S2",
            Self::EphemeralGuest => "S3",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SovereignNix => "sovereign-nix",
            Self::NixEnclosedForeign => "nix-enclosed-foreign",
            Self::SovereignGuest => "sovereign-guest",
            Self::EphemeralGuest => "ephemeral-guest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
    Sha256,
    Blake3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentDigest {
    pub algorithm: DigestAlgorithm,
    /// Lowercase 64-hex digest without an algorithm prefix.
    pub hex: String,
}

impl ContentDigest {
    pub fn sha256(hex: impl Into<String>) -> Result<Self, SoftwareIngressError> {
        Self::new(DigestAlgorithm::Sha256, hex)
    }

    pub fn blake3(hex: impl Into<String>) -> Result<Self, SoftwareIngressError> {
        Self::new(DigestAlgorithm::Blake3, hex)
    }

    pub fn new(
        algorithm: DigestAlgorithm,
        hex: impl Into<String>,
    ) -> Result<Self, SoftwareIngressError> {
        let hex = hex.into();
        validate_hex_digest("content digest", &hex)?;
        Ok(Self { algorithm, hex })
    }

    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        validate_hex_digest("content digest", &self.hex)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemGrant {
    /// Logical host path. The sovereign baseline may never grant `/` read-write.
    pub path: String,
    pub access: FilesystemAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPermissionEnvelope {
    pub network: bool,
    pub wayland: bool,
    pub x11: bool,
    pub audio: bool,
    pub camera: bool,
    pub microphone: bool,
    pub gpu: bool,
    pub bluetooth: bool,
    /// Explicit filesystem grants. Absence means no host filesystem access.
    pub filesystems: Vec<FilesystemGrant>,
    /// Explicit device names/paths. High-assurance profiles should keep this empty.
    pub devices: Vec<String>,
    /// Explicit secret identifiers; never raw secret values.
    pub secrets: Vec<String>,
    /// These four fields are negative invariants. They are represented in the
    /// evidence model so a policy diff can show that a guest attempted to gain
    /// ambient host authority.
    pub privileged: bool,
    pub host_pid_namespace: bool,
    pub host_root_write: bool,
    pub nix_daemon_access: bool,
}

impl Default for GuestPermissionEnvelope {
    fn default() -> Self {
        Self {
            network: false,
            wayland: false,
            x11: false,
            audio: false,
            camera: false,
            microphone: false,
            gpu: false,
            bluetooth: false,
            filesystems: Vec::new(),
            devices: Vec::new(),
            secrets: Vec::new(),
            privileged: false,
            host_pid_namespace: false,
            host_root_write: false,
            nix_daemon_access: false,
        }
    }
}

impl GuestPermissionEnvelope {
    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        if self.privileged {
            return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                "privileged guest".into(),
            ));
        }
        if self.host_pid_namespace {
            return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                "host PID namespace".into(),
            ));
        }
        if self.host_root_write {
            return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                "host root write access".into(),
            ));
        }
        if self.nix_daemon_access {
            return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                "Nix daemon socket access".into(),
            ));
        }

        let mut seen_paths = BTreeSet::new();
        for grant in &self.filesystems {
            validate_absolute_guest_path(&grant.path)?;
            if grant.path == "/" && grant.access == FilesystemAccess::ReadWrite {
                return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                    "read-write host root filesystem".into(),
                ));
            }
            if !seen_paths.insert((&grant.path, grant.access)) {
                return Err(SoftwareIngressError::DuplicateGrant(grant.path.clone()));
            }
        }
        validate_token_list("device", &self.devices)?;
        validate_token_list("secret identifier", &self.secrets)?;
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, SoftwareIngressError> {
        self.validate()?;
        hash_json(PERMISSION_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignNixPackage {
    /// A safe nixpkgs or flake package attribute such as `firefox` or
    /// `legacyPackages.x86_64-linux.foo` after trusted resolution.
    pub attribute: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NixEnclosedForeignPackage {
    pub pname: String,
    pub version: String,
    /// Exact upstream source identifier. Network retrieval is still performed
    /// by a Nix fixed-output derivation, never by the privileged host executor.
    pub source: String,
    pub source_digest: ContentDigest,
    /// Digest of the generated/approved derivation source itself.
    pub derivation_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakRuntimePin {
    /// Full runtime ref such as `org.freedesktop.Platform/x86_64/24.08`.
    pub reference: String,
    /// Exact OSTree commit for the runtime.
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakGuestPlan {
    pub app_id: String,
    pub remote: String,
    /// Explicit branch; high-assurance realization never relies on remote default resolution.
    pub branch: String,
    /// Exact application OSTree commit/checksum. Tracking `latest` is not sovereign guest state.
    pub commit: String,
    /// Exact runtime closure required by this app. V37 requires at least one
    /// runtime pin before a Flatpak guest can claim exact realization.
    pub runtime_pins: Vec<FlatpakRuntimePin>,
    pub permissions: GuestPermissionEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciMount {
    pub source: String,
    pub target: String,
    pub access: FilesystemAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciGuestPlan {
    /// Repository/name without relying on a mutable tag for identity.
    pub image: String,
    /// Exact OCI digest, e.g. `sha256:<64 hex>`.
    pub image_digest: String,
    pub rootless: bool,
    pub read_only_root: bool,
    pub host_network: bool,
    pub mounts: Vec<OciMount>,
    pub permissions: GuestPermissionEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapsuleNetworkPolicy {
    None,
    EgressOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapsulePersistence {
    DestroyOnExit,
    PreserveWorkspaceData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralCapsulePlan {
    /// Digest of the source/archive/script presented to the capsule. This is
    /// evidence, not a reproducibility claim.
    pub source_digest: ContentDigest,
    pub network: CapsuleNetworkPolicy,
    pub persistence: CapsulePersistence,
    pub permissions: GuestPermissionEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SoftwareIngressSpec {
    SovereignNix(SovereignNixPackage),
    NixEnclosedForeign(NixEnclosedForeignPackage),
    FlatpakGuest(FlatpakGuestPlan),
    OciGuest(OciGuestPlan),
    EphemeralCapsule(EphemeralCapsulePlan),
}

impl SoftwareIngressSpec {
    pub fn trust_class(&self) -> SoftwareTrustClass {
        match self {
            Self::SovereignNix(_) => SoftwareTrustClass::SovereignNix,
            Self::NixEnclosedForeign(_) => SoftwareTrustClass::NixEnclosedForeign,
            Self::FlatpakGuest(_) | Self::OciGuest(_) => SoftwareTrustClass::SovereignGuest,
            Self::EphemeralCapsule(_) => SoftwareTrustClass::EphemeralGuest,
        }
    }

    fn validate(&self) -> Result<(), SoftwareIngressError> {
        match self {
            Self::SovereignNix(pkg) => validate_nix_attr(&pkg.attribute),
            Self::NixEnclosedForeign(pkg) => {
                validate_identifier("package name", &pkg.pname)?;
                validate_identifier("package version", &pkg.version)?;
                validate_nonempty("source", &pkg.source)?;
                pkg.source_digest.validate()?;
                validate_hex_digest("derivation digest", &pkg.derivation_blake3)
            }
            Self::FlatpakGuest(guest) => {
                validate_flatpak_id(&guest.app_id)?;
                validate_identifier("Flatpak remote", &guest.remote)?;
                validate_identifier("Flatpak branch", &guest.branch)?;
                validate_hex_digest("Flatpak commit", &guest.commit)?;
                if guest.runtime_pins.is_empty() {
                    return Err(SoftwareIngressError::InvalidValue {
                        field: "Flatpak runtime pins",
                        value: "at least one exact runtime commit is required for S2 realization"
                            .into(),
                    });
                }
                let mut runtime_refs = BTreeSet::new();
                for runtime in &guest.runtime_pins {
                    validate_nonempty("Flatpak runtime ref", &runtime.reference)?;
                    if runtime.reference.contains('\0') || runtime.reference.len() > 512 {
                        return Err(SoftwareIngressError::InvalidValue {
                            field: "Flatpak runtime ref",
                            value: runtime.reference.clone(),
                        });
                    }
                    validate_hex_digest("Flatpak runtime commit", &runtime.commit)?;
                    if !runtime_refs.insert(runtime.reference.as_str()) {
                        return Err(SoftwareIngressError::DuplicateGrant(
                            runtime.reference.clone(),
                        ));
                    }
                }
                guest.permissions.validate()
            }
            Self::OciGuest(guest) => {
                validate_nonempty("OCI image", &guest.image)?;
                validate_oci_digest(&guest.image_digest)?;
                if !guest.rootless {
                    return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                        "rootful OCI container".into(),
                    ));
                }
                if guest.host_network {
                    return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                        "host network namespace".into(),
                    ));
                }
                let mut targets = BTreeSet::new();
                for mount in &guest.mounts {
                    validate_absolute_guest_path(&mount.source)?;
                    validate_absolute_guest_path(&mount.target)?;
                    if mount.source == "/" && mount.access == FilesystemAccess::ReadWrite {
                        return Err(SoftwareIngressError::ForbiddenGuestAuthority(
                            "OCI read-write host root mount".into(),
                        ));
                    }
                    if !targets.insert(mount.target.as_str()) {
                        return Err(SoftwareIngressError::DuplicateGrant(mount.target.clone()));
                    }
                }
                guest.permissions.validate()
            }
            Self::EphemeralCapsule(capsule) => {
                capsule.source_digest.validate()?;
                capsule.permissions.validate()
            }
        }
    }

    pub fn artifact_identity(&self) -> String {
        match self {
            Self::SovereignNix(pkg) => format!("nix-attr:{}", pkg.attribute),
            Self::NixEnclosedForeign(pkg) => format!(
                "foreign:{}:{}:{:?}:{}",
                pkg.pname, pkg.version, pkg.source_digest.algorithm, pkg.source_digest.hex
            ),
            Self::FlatpakGuest(guest) => {
                format!("flatpak:{}@{}", guest.app_id, guest.commit)
            }
            Self::OciGuest(guest) => format!("oci:{}@{}", guest.image, guest.image_digest),
            Self::EphemeralCapsule(capsule) => format!(
                "ephemeral:{:?}:{}",
                capsule.source_digest.algorithm, capsule.source_digest.hex
            ),
        }
    }

    pub fn authority_digest_hex(&self) -> Result<String, SoftwareIngressError> {
        match self {
            Self::FlatpakGuest(g) => g.permissions.digest_hex(),
            Self::OciGuest(g) => g.permissions.digest_hex(),
            Self::EphemeralCapsule(g) => g.permissions.digest_hex(),
            Self::SovereignNix(_) | Self::NixEnclosedForeign(_) => {
                hash_json(PERMISSION_DOMAIN, &"host-authority:declarative-only")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareIngressPlan {
    pub schema_version: u32,
    pub name: String,
    pub spec: SoftwareIngressSpec,
}

impl SoftwareIngressPlan {
    pub fn new(
        name: impl Into<String>,
        spec: SoftwareIngressSpec,
    ) -> Result<Self, SoftwareIngressError> {
        let plan = Self {
            schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
            name: name.into(),
            spec,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn trust_class(&self) -> SoftwareTrustClass {
        self.spec.trust_class()
    }

    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        if self.schema_version != SOFTWARE_INGRESS_SCHEMA_VERSION {
            return Err(SoftwareIngressError::UnsupportedSchema(self.schema_version));
        }
        validate_nonempty("software name", &self.name)?;
        self.spec.validate()
    }

    pub fn digest_hex(&self) -> Result<String, SoftwareIngressError> {
        self.validate()?;
        hash_json(PLAN_DOMAIN, self)
    }

    pub fn guest_entry(&self) -> Result<Option<GuestStateEntry>, SoftwareIngressError> {
        if !matches!(
            self.trust_class(),
            SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
        ) {
            return Ok(None);
        }
        Ok(Some(GuestStateEntry {
            name: self.name.clone(),
            trust_class: self.trust_class(),
            plan_blake3: self.digest_hex()?,
            artifact_identity: self.spec.artifact_identity(),
            authority_blake3: self.spec.authority_digest_hex()?,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPlanDocument {
    pub schema_version: u32,
    pub kind: String,
    pub plans: Vec<SoftwareIngressPlan>,
}

impl GuestPlanDocument {
    pub fn from_plans(plans: &[SoftwareIngressPlan]) -> Result<Self, SoftwareIngressError> {
        let mut guest_plans = Vec::new();
        for plan in plans {
            plan.validate()?;
            if !matches!(
                plan.trust_class(),
                SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
            ) {
                return Err(SoftwareIngressError::InvalidPromotion(format!(
                    "{} is {} and is not external guest state",
                    plan.name,
                    plan.trust_class().code()
                )));
            }
            guest_plans.push(plan.clone());
        }
        guest_plans.sort_by(|a, b| a.name.cmp(&b.name));
        let mut names = BTreeSet::new();
        for plan in &guest_plans {
            if !names.insert(plan.name.as_str()) {
                return Err(SoftwareIngressError::DuplicateGuest(plan.name.clone()));
            }
        }
        Ok(Self {
            schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
            kind: "symthaea-guest-plan-document-v2".into(),
            plans: guest_plans,
        })
    }

    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        if self.schema_version != SOFTWARE_INGRESS_SCHEMA_VERSION
            || self.kind != "symthaea-guest-plan-document-v2"
        {
            return Err(SoftwareIngressError::UnsupportedSchema(self.schema_version));
        }
        let canonical = Self::from_plans(&self.plans)?;
        if &canonical != self {
            return Err(SoftwareIngressError::InvalidValue {
                field: "guest plan document",
                value: "plans are not in canonical unique order".into(),
            });
        }
        Ok(())
    }

    pub fn plan(&self, name: &str) -> Option<&SoftwareIngressPlan> {
        self.plans.iter().find(|plan| plan.name == name)
    }
}

pub fn empty_guest_plan_document_json() -> String {
    let doc = GuestPlanDocument {
        schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
        kind: "symthaea-guest-plan-document-v2".into(),
        plans: Vec::new(),
    };
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| {
        "{\"schema_version\":2,\"kind\":\"symthaea-guest-plan-document-v2\",\"plans\":[]}".into()
    }) + "\n"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestStateEntry {
    pub name: String,
    pub trust_class: SoftwareTrustClass,
    pub plan_blake3: String,
    pub artifact_identity: String,
    /// Digest of the guest's effective authority/permission envelope.
    pub authority_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestStateManifest {
    pub schema_version: u32,
    pub entries: Vec<GuestStateEntry>,
}

impl GuestStateManifest {
    pub fn from_plans(plans: &[SoftwareIngressPlan]) -> Result<Self, SoftwareIngressError> {
        let mut entries = Vec::new();
        for plan in plans {
            plan.validate()?;
            if let Some(entry) = plan.guest_entry()? {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.plan_blake3.cmp(&b.plan_blake3)));
        let mut names = BTreeSet::new();
        for entry in &entries {
            if !names.insert(entry.name.as_str()) {
                return Err(SoftwareIngressError::DuplicateGuest(entry.name.clone()));
            }
        }
        Ok(Self {
            schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
            entries,
        })
    }

    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        if self.schema_version != SOFTWARE_INGRESS_SCHEMA_VERSION {
            return Err(SoftwareIngressError::UnsupportedSchema(self.schema_version));
        }
        let mut names = BTreeSet::new();
        let mut previous: Option<(&str, &str)> = None;
        for entry in &self.entries {
            validate_nonempty("guest name", &entry.name)?;
            validate_hex_digest("guest plan digest", &entry.plan_blake3)?;
            validate_hex_digest("guest authority digest", &entry.authority_blake3)?;
            if !matches!(
                entry.trust_class,
                SoftwareTrustClass::SovereignGuest | SoftwareTrustClass::EphemeralGuest
            ) {
                return Err(SoftwareIngressError::InvalidValue {
                    field: "guest state class",
                    value: entry.trust_class.as_str().into(),
                });
            }
            if !names.insert(entry.name.as_str()) {
                return Err(SoftwareIngressError::DuplicateGuest(entry.name.clone()));
            }
            if let Some((prev_name, prev_digest)) = previous {
                if (entry.name.as_str(), entry.plan_blake3.as_str()) < (prev_name, prev_digest) {
                    return Err(SoftwareIngressError::InvalidValue {
                        field: "guest state order",
                        value: entry.name.clone(),
                    });
                }
            }
            previous = Some((entry.name.as_str(), entry.plan_blake3.as_str()));
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> Result<String, SoftwareIngressError> {
        self.validate()?;
        hash_json(GUEST_MANIFEST_DOMAIN, self)
    }
}

/// Legacy V35 proposal hint retained for source compatibility only.
///
/// It is not trusted promotion evidence because it does not bind a Holon,
/// trusted S3 realization receipt, proof gates, or declarative change covenant.
/// New code must use `software_assimilation::AssimilationProposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionProposal {
    /// Exact ephemeral source being promoted.
    pub source_digest: ContentDigest,
    /// Proposed reproducible enclosure.
    pub target: SoftwareIngressSpec,
}

impl PromotionProposal {
    pub fn validate(&self) -> Result<(), SoftwareIngressError> {
        self.source_digest.validate()?;
        self.target.validate()?;
        if matches!(self.target, SoftwareIngressSpec::EphemeralCapsule(_)) {
            return Err(SoftwareIngressError::InvalidPromotion(
                "promotion target must improve reproducibility".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SoftwareIngressPolicyDocument {
    schema_version: u32,
    kind: &'static str,
    constitutional_rule: &'static str,
    classes: Vec<SoftwareIngressClassPolicy>,
    forbidden_ambient_mutations: Vec<&'static str>,
    guest_negative_capabilities: Vec<&'static str>,
    guest_realization_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SoftwareIngressClassPolicy {
    code: &'static str,
    name: &'static str,
    realization: &'static str,
    reproducibility_claim: &'static str,
    host_mutation: &'static str,
}

/// Machine-readable Software Ingress Covenant embedded into sovereign flakes.
pub fn software_ingress_policy_json() -> String {
    let policy = SoftwareIngressPolicyDocument {
        schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
        kind: "symthaea-software-ingress-policy-v1",
        constitutional_rule: "software enters the sovereign baseline only through reproducible declarative realization; all other software remains a bounded guest and may not imperatively rewrite the host",
        classes: vec![
            SoftwareIngressClassPolicy {
                code: "S0",
                name: "sovereign-nix",
                realization: "nix/nixos/home-manager",
                reproducibility_claim: "exact-declarative-realization",
                host_mutation: "declarative-only",
            },
            SoftwareIngressClassPolicy {
                code: "S1",
                name: "nix-enclosed-foreign",
                realization: "fixed-output/content-addressed-nix-derivation",
                reproducibility_claim: "content-addressed-derivation",
                host_mutation: "declarative-only",
            },
            SoftwareIngressClassPolicy {
                code: "S2",
                name: "sovereign-guest",
                realization: "pinned-flatpak-or-oci-plus-permission-envelope-plus-realization-receipt",
                reproducibility_claim: "guest-manifest-identity",
                host_mutation: "forbidden",
            },
            SoftwareIngressClassPolicy {
                code: "S3",
                name: "ephemeral-guest",
                realization: "disposable-unprivileged-capsule",
                reproducibility_claim: "none",
                host_mutation: "forbidden",
            },
        ],
        forbidden_ambient_mutations: vec![
            "nix-env-install-remove",
            "nix-profile-install-remove-upgrade",
            "mutable-nix-channel",
            "curl-pipe-shell",
            "unmanaged-dpkg-rpm-pacman",
            "unmanaged-language-global-install",
            "guest-self-update-outside-policy",
        ],
        guest_negative_capabilities: vec![
            "privileged",
            "host-pid-namespace",
            "host-root-write",
            "nix-daemon-access",
        ],
        guest_realization_status: "typed-realization-evidence-v37",
    };
    serde_json::to_string_pretty(&policy).unwrap_or_else(|_| {
        "{\"schema_version\":2,\"error\":\"software ingress policy serialization failed\"}".into()
    }) + "\n"
}

/// Deterministic empty guest state used until explicit S2/S3 plans are bound.
pub fn empty_guest_state_manifest_json() -> String {
    let manifest = GuestStateManifest {
        schema_version: SOFTWARE_INGRESS_SCHEMA_VERSION,
        entries: Vec::new(),
    };
    serde_json::to_string_pretty(&manifest)
        .unwrap_or_else(|_| "{\"schema_version\":2,\"entries\":[]}".into())
        + "\n"
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SoftwareIngressError {
    #[error("unsupported software-ingress schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
    #[error("invalid digest for {0}")]
    InvalidDigest(&'static str),
    #[error("forbidden guest authority: {0}")]
    ForbiddenGuestAuthority(String),
    #[error("duplicate filesystem/device/secret grant: {0}")]
    DuplicateGrant(String),
    #[error("duplicate guest name in manifest: {0}")]
    DuplicateGuest(String),
    #[error("invalid promotion: {0}")]
    InvalidPromotion(String),
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String, SoftwareIngressError> {
    let encoded = serde_json::to_vec(value).map_err(|_| SoftwareIngressError::InvalidValue {
        field: "canonical JSON",
        value: "serialization failed".into(),
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_hex_digest(label: &'static str, value: &str) -> Result<(), SoftwareIngressError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(SoftwareIngressError::InvalidDigest(label))
    }
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), SoftwareIngressError> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.len() <= 512 && !trimmed.contains('\0') {
        Ok(())
    } else {
        Err(SoftwareIngressError::InvalidValue {
            field,
            value: value.into(),
        })
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), SoftwareIngressError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b':'));
    if valid {
        Ok(())
    } else {
        Err(SoftwareIngressError::InvalidValue {
            field,
            value: value.into(),
        })
    }
}

fn validate_nix_attr(value: &str) -> Result<(), SoftwareIngressError> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
        });
    if valid {
        Ok(())
    } else {
        Err(SoftwareIngressError::InvalidValue {
            field: "Nix package attribute",
            value: value.into(),
        })
    }
}

fn validate_flatpak_id(value: &str) -> Result<(), SoftwareIngressError> {
    let valid = value.len() <= 255
        && value.split('.').count() >= 3
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(SoftwareIngressError::InvalidValue {
            field: "Flatpak application id",
            value: value.into(),
        })
    }
}

fn validate_oci_digest(value: &str) -> Result<(), SoftwareIngressError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SoftwareIngressError::InvalidDigest("OCI image digest"));
    };
    validate_hex_digest("OCI image digest", hex)
}

fn validate_absolute_guest_path(value: &str) -> Result<(), SoftwareIngressError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.split('/').any(|segment| segment == "..")
        || value.len() > 4096
    {
        return Err(SoftwareIngressError::InvalidValue {
            field: "guest filesystem path",
            value: value.into(),
        });
    }
    Ok(())
}

fn validate_token_list(field: &'static str, values: &[String]) -> Result<(), SoftwareIngressError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_nonempty(field, value)?;
        if !seen.insert(value) {
            return Err(SoftwareIngressError::DuplicateGrant(value.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn sovereign_nix_is_s0() {
        let plan = SoftwareIngressPlan::new(
            "firefox",
            SoftwareIngressSpec::SovereignNix(SovereignNixPackage {
                attribute: "firefox".into(),
            }),
        )
        .unwrap();
        assert_eq!(plan.trust_class(), SoftwareTrustClass::SovereignNix);
        assert_eq!(plan.trust_class().code(), "S0");
        assert!(plan.guest_entry().unwrap().is_none());
    }

    #[test]
    fn foreign_binary_can_be_nix_enclosed() {
        let plan = SoftwareIngressPlan::new(
            "vendor-agent",
            SoftwareIngressSpec::NixEnclosedForeign(NixEnclosedForeignPackage {
                pname: "vendor-agent".into(),
                version: "4.2.7".into(),
                source: "https://vendor.invalid/agent-4.2.7.tar.gz".into(),
                source_digest: ContentDigest::sha256(hex('a')).unwrap(),
                derivation_blake3: hex('b'),
            }),
        )
        .unwrap();
        assert_eq!(plan.trust_class(), SoftwareTrustClass::NixEnclosedForeign);
    }

    #[test]
    fn flatpak_requires_exact_commit_and_bounded_permissions() {
        let plan = SoftwareIngressPlan::new(
            "signal",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.signal.Signal".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: hex('c'),
                runtime_pins: vec![FlatpakRuntimePin {
                    reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                    commit: hex('d'),
                }],
                permissions: GuestPermissionEnvelope {
                    network: true,
                    microphone: true,
                    filesystems: vec![FilesystemGrant {
                        path: "/home/owner/Downloads".into(),
                        access: FilesystemAccess::ReadWrite,
                    }],
                    ..Default::default()
                },
            }),
        )
        .unwrap();
        assert_eq!(plan.trust_class(), SoftwareTrustClass::SovereignGuest);
        let entry = plan.guest_entry().unwrap().unwrap();
        assert!(
            entry
                .artifact_identity
                .starts_with("flatpak:org.signal.Signal@")
        );
    }

    #[test]
    fn mutable_flatpak_label_is_not_a_commit() {
        let err = SoftwareIngressPlan::new(
            "signal",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.signal.Signal".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: "latest".into(),
                runtime_pins: vec![FlatpakRuntimePin {
                    reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                    commit: hex('d'),
                }],
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, SoftwareIngressError::InvalidDigest(_)));
    }

    #[test]
    fn oci_requires_digest_rootless_and_no_host_network() {
        let good = SoftwareIngressPlan::new(
            "postgres",
            SoftwareIngressSpec::OciGuest(OciGuestPlan {
                image: "docker.io/library/postgres".into(),
                image_digest: format!("sha256:{}", hex('d')),
                rootless: true,
                read_only_root: true,
                host_network: false,
                mounts: vec![],
                permissions: GuestPermissionEnvelope {
                    network: true,
                    ..Default::default()
                },
            }),
        );
        assert!(good.is_ok());

        let bad = SoftwareIngressPlan::new(
            "postgres",
            SoftwareIngressSpec::OciGuest(OciGuestPlan {
                image: "postgres".into(),
                image_digest: format!("sha256:{}", hex('d')),
                rootless: false,
                read_only_root: false,
                host_network: true,
                mounts: vec![],
                permissions: GuestPermissionEnvelope::default(),
            }),
        );
        assert!(matches!(
            bad,
            Err(SoftwareIngressError::ForbiddenGuestAuthority(_))
        ));
    }

    #[test]
    fn guest_cannot_receive_nix_daemon_or_host_root_write() {
        for permissions in [
            GuestPermissionEnvelope {
                nix_daemon_access: true,
                ..Default::default()
            },
            GuestPermissionEnvelope {
                host_root_write: true,
                ..Default::default()
            },
            GuestPermissionEnvelope {
                filesystems: vec![FilesystemGrant {
                    path: "/".into(),
                    access: FilesystemAccess::ReadWrite,
                }],
                ..Default::default()
            },
        ] {
            assert!(matches!(
                permissions.validate(),
                Err(SoftwareIngressError::ForbiddenGuestAuthority(_))
            ));
        }
    }

    #[test]
    fn ephemeral_is_evidence_not_reproducibility_claim() {
        let plan = SoftwareIngressPlan::new(
            "try-weird-script",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('e')).unwrap(),
                network: CapsuleNetworkPolicy::EgressOnly,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        assert_eq!(plan.trust_class(), SoftwareTrustClass::EphemeralGuest);
        assert_eq!(plan.trust_class().code(), "S3");
    }

    #[test]
    fn guest_manifest_is_order_independent_for_input_order() {
        let a = SoftwareIngressPlan::new(
            "alpha",
            SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('a')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let b = SoftwareIngressPlan::new(
            "beta",
            SoftwareIngressSpec::FlatpakGuest(FlatpakGuestPlan {
                app_id: "org.example.Beta".into(),
                remote: "flathub".into(),
                branch: "stable".into(),
                commit: hex('b'),
                runtime_pins: vec![FlatpakRuntimePin {
                    reference: "org.freedesktop.Platform/x86_64/24.08".into(),
                    commit: hex('c'),
                }],
                permissions: GuestPermissionEnvelope::default(),
            }),
        )
        .unwrap();
        let one = GuestStateManifest::from_plans(&[a.clone(), b.clone()]).unwrap();
        let two = GuestStateManifest::from_plans(&[b, a]).unwrap();
        assert_eq!(one, two);
        assert_eq!(one.digest_hex().unwrap(), two.digest_hex().unwrap());
    }

    #[test]
    fn promotion_cannot_target_another_ephemeral_capsule() {
        let proposal = PromotionProposal {
            source_digest: ContentDigest::blake3(hex('a')).unwrap(),
            target: SoftwareIngressSpec::EphemeralCapsule(EphemeralCapsulePlan {
                source_digest: ContentDigest::blake3(hex('a')).unwrap(),
                network: CapsuleNetworkPolicy::None,
                persistence: CapsulePersistence::DestroyOnExit,
                permissions: GuestPermissionEnvelope::default(),
            }),
        };
        assert!(matches!(
            proposal.validate(),
            Err(SoftwareIngressError::InvalidPromotion(_))
        ));
    }

    #[test]
    fn machine_policy_is_explicit_about_non_realized_guest_backends() {
        let value: serde_json::Value =
            serde_json::from_str(&software_ingress_policy_json()).unwrap();
        assert_eq!(
            value["guest_realization_status"],
            "typed-realization-evidence-v37"
        );
        assert_eq!(value["classes"][0]["code"], "S0");
        assert_eq!(value["classes"][3]["code"], "S3");
        assert!(
            value["forbidden_ambient_mutations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "nix-env-install-remove")
        );
    }
}
