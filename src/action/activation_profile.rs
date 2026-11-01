// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Verifier-owned compatibility registry for NixOS activation semantics.
//!
//! This module is pure policy/plan validation. It does not invoke NixOS
//! activation, call systemd, mutate host state, or own transaction history.
//! An exact, independently qualified release profile is required; unknown
//! release/binary/semantics tuples fail closed.

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::BTreeSet;

pub const ACTIVATION_PROFILE_SCHEMA: &str = "nixward-activation-profile-v0.1";
pub const ACTIVATION_PROFILE_VERSION: u16 = 1;
const PROFILE_DIGEST_DOMAIN: &[u8] = b"nixward-activation-profile-v0.1\0";

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b':')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationMode {
    Switch,
    Test,
    Boot,
    DryActivate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationExpectation {
    Target,
    Unchanged,
    TargetAfterNextBoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModePostconditions {
    pub running_generation: GenerationExpectation,
    pub boot_default_generation: GenerationExpectation,
    pub requires_post_reboot_observation: bool,
    pub runtime_mutation_permitted: bool,
    pub boot_default_mutation_permitted: bool,
}

impl ModePostconditions {
    pub const fn for_mode(mode: ActivationMode) -> Self {
        match mode {
            ActivationMode::Switch => Self {
                running_generation: GenerationExpectation::Target,
                boot_default_generation: GenerationExpectation::Target,
                requires_post_reboot_observation: false,
                runtime_mutation_permitted: true,
                boot_default_mutation_permitted: true,
            },
            ActivationMode::Test => Self {
                running_generation: GenerationExpectation::Target,
                boot_default_generation: GenerationExpectation::Unchanged,
                requires_post_reboot_observation: false,
                runtime_mutation_permitted: true,
                boot_default_mutation_permitted: false,
            },
            ActivationMode::Boot => Self {
                running_generation: GenerationExpectation::Unchanged,
                boot_default_generation: GenerationExpectation::TargetAfterNextBoot,
                requires_post_reboot_observation: true,
                runtime_mutation_permitted: false,
                boot_default_mutation_permitted: true,
            },
            ActivationMode::DryActivate => Self {
                running_generation: GenerationExpectation::Unchanged,
                boot_default_generation: GenerationExpectation::Unchanged,
                requires_post_reboot_observation: false,
                runtime_mutation_permitted: false,
                boot_default_mutation_permitted: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InhibitorPolicy {
    RequiredComparison,
    RequiredComparisonWithExplicitBypass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationProfile {
    pub schema: String,
    pub version: u16,
    pub profile_id: String,
    /// Exact NixOS release identifier, not a channel alias such as unstable.
    pub nixos_release: String,
    /// Exact Nixpkgs source commit used to build the guest/host closure.
    pub nixpkgs_revision: String,
    /// SHA-256 of the exact switch-to-configuration executable bytes.
    pub switch_to_configuration_sha256: String,
    /// Versioned semantic adapter identity, not inferred from a release label.
    pub activation_semantics_revision: String,
    /// Exact systemd version observed in the qualified environment.
    pub systemd_version: String,
    /// Exact observer implementation revision that interprets manager/worker events.
    pub observer_adapter_revision: String,
    pub supported_modes: BTreeSet<ActivationMode>,
    pub inhibitor_policy: InhibitorPolicy,
    /// 26.11-compatible profiles must not rely on deprecated activation-script
    /// restart/reload callbacks for semantic truth.
    pub requires_deprecated_activation_callbacks: bool,
    pub requires_invocation_id: bool,
    pub supports_pidfd_identity: bool,
}

impl ActivationProfile {
    pub fn validate(&self) -> Result<(), ActivationProfileError> {
        if self.schema != ACTIVATION_PROFILE_SCHEMA || self.version != ACTIVATION_PROFILE_VERSION {
            return Err(ActivationProfileError::UnsupportedSchema);
        }
        if !valid_token(&self.profile_id)
            || !valid_token(&self.nixos_release)
            || !valid_token(&self.nixpkgs_revision)
            || !valid_sha256(&self.switch_to_configuration_sha256)
            || !valid_token(&self.activation_semantics_revision)
            || !valid_token(&self.systemd_version)
            || !valid_token(&self.observer_adapter_revision)
            || self.supported_modes.is_empty()
            || !self.requires_invocation_id
            || self.requires_deprecated_activation_callbacks
        {
            return Err(ActivationProfileError::MalformedOrUnsafeProfile);
        }
        if self.supported_modes.contains(&ActivationMode::DryActivate)
            && self.requires_deprecated_activation_callbacks {
            return Err(ActivationProfileError::DeprecatedCallbackDependency);
        }
        Ok(())
    }

    /// Deterministic digest over the exact profile record, domain separated from
    /// plans and activation traces. Profile fields are scalar or BTreeSet ordered.
    pub fn profile_digest(&self) -> Result<String, ActivationProfileError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ActivationProfileError::SerializationFailure)?;
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DIGEST_DOMAIN);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(hex_lower(&hasher.finalize()))
    }

    pub fn expected_postconditions(
        &self,
        mode: ActivationMode,
    ) -> Result<ModePostconditions, ActivationProfileError> {
        self.validate()?;
        if !self.supported_modes.contains(&mode) {
            return Err(ActivationProfileError::UnsupportedMode);
        }
        Ok(ModePostconditions::for_mode(mode))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationProfileQuery<'a> {
    pub nixos_release: &'a str,
    pub nixpkgs_revision: &'a str,
    pub switch_to_configuration_sha256: &'a str,
    pub activation_semantics_revision: &'a str,
    pub systemd_version: &'a str,
    pub observer_adapter_revision: &'a str,
    pub expected_profile_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCompatibilityReceipt {
    pub schema: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub nixos_release: String,
    pub nixpkgs_revision: String,
    pub switch_to_configuration_sha256: String,
    pub activation_semantics_revision: String,
    pub systemd_version: String,
    pub observer_adapter_revision: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationProfileError {
    UnsupportedSchema,
    MalformedOrUnsafeProfile,
    DeprecatedCallbackDependency,
    SerializationFailure,
    DuplicateProfile,
    UnknownProfile,
    ProfileDigestMismatch,
    UnsupportedMode,
    InhibitorBlocked,
    InhibitorBypassDenied,
    InhibitorBypassMissingAuthorization,
}

#[derive(Debug, Clone, Default)]
pub struct ActivationProfileRegistry {
    profiles: Vec<ActivationProfile>,
}

impl ActivationProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        profile: ActivationProfile,
    ) -> Result<String, ActivationProfileError> {
        profile.validate()?;
        let digest = profile.profile_digest()?;
        if self.profiles.iter().any(|existing| {
            existing.nixos_release == profile.nixos_release
                && existing.nixpkgs_revision == profile.nixpkgs_revision
                && existing.switch_to_configuration_sha256
                    == profile.switch_to_configuration_sha256
                && existing.activation_semantics_revision
                    == profile.activation_semantics_revision
                && existing.systemd_version == profile.systemd_version
                && existing.observer_adapter_revision == profile.observer_adapter_revision
        }) {
            return Err(ActivationProfileError::DuplicateProfile);
        }
        self.profiles.push(profile);
        Ok(digest)
    }

    /// Exact matching only. No release-family, semver, channel, "newest profile",
    /// or partial binary-digest fallback is permitted.
    pub fn resolve_exact(
        &self,
        query: &ActivationProfileQuery<'_>,
    ) -> Result<(&ActivationProfile, ActivationCompatibilityReceipt), ActivationProfileError> {
        let profile = self.profiles.iter().find(|p| {
            p.nixos_release == query.nixos_release
                && p.nixpkgs_revision == query.nixpkgs_revision
                && p.switch_to_configuration_sha256 == query.switch_to_configuration_sha256
                && p.activation_semantics_revision == query.activation_semantics_revision
                && p.systemd_version == query.systemd_version
                && p.observer_adapter_revision == query.observer_adapter_revision
        }).ok_or(ActivationProfileError::UnknownProfile)?;

        let digest = profile.profile_digest()?;
        if digest != query.expected_profile_digest {
            return Err(ActivationProfileError::ProfileDigestMismatch);
        }

        let receipt = ActivationCompatibilityReceipt {
            schema: ACTIVATION_PROFILE_SCHEMA.into(),
            profile_id: profile.profile_id.clone(),
            profile_digest: digest,
            nixos_release: profile.nixos_release.clone(),
            nixpkgs_revision: profile.nixpkgs_revision.clone(),
            switch_to_configuration_sha256: profile.switch_to_configuration_sha256.clone(),
            activation_semantics_revision: profile.activation_semantics_revision.clone(),
            systemd_version: profile.systemd_version.clone(),
            observer_adapter_revision: profile.observer_adapter_revision.clone(),
        };
        Ok((profile, receipt))
    }

    pub fn len(&self) -> usize { self.profiles.len() }
    pub fn is_empty(&self) -> bool { self.profiles.is_empty() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InhibitorObservation {
    Passed,
    Blocked,
    Bypassed,
}

pub fn validate_inhibitor_observation(
    policy: InhibitorPolicy,
    observation: InhibitorObservation,
    bypass_authorization_digest: Option<&str>,
) -> Result<(), ActivationProfileError> {
    match observation {
        InhibitorObservation::Passed => {
            if bypass_authorization_digest.is_some() {
                return Err(ActivationProfileError::InhibitorBypassDenied);
            }
            Ok(())
        }
        InhibitorObservation::Blocked => Err(ActivationProfileError::InhibitorBlocked),
        InhibitorObservation::Bypassed => {
            if policy != InhibitorPolicy::RequiredComparisonWithExplicitBypass {
                return Err(ActivationProfileError::InhibitorBypassDenied);
            }
            if !bypass_authorization_digest.map(valid_sha256).unwrap_or(false) {
                return Err(ActivationProfileError::InhibitorBypassMissingAuthorization);
            }
            Ok(())
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ActivationProfile {
        ActivationProfile {
            schema: ACTIVATION_PROFILE_SCHEMA.into(),
            version: ACTIVATION_PROFILE_VERSION,
            profile_id: "fixture-nixos-release-A".into(),
            nixos_release: "fixture-release-A".into(),
            nixpkgs_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            switch_to_configuration_sha256: "a".repeat(64),
            activation_semantics_revision: "fixture-activation-semantics-v1".into(),
            systemd_version: "261".into(),
            observer_adapter_revision: "fixture-systemd-observer-v1".into(),
            supported_modes: [
                ActivationMode::Switch,
                ActivationMode::Test,
                ActivationMode::Boot,
                ActivationMode::DryActivate,
            ].into_iter().collect(),
            inhibitor_policy: InhibitorPolicy::RequiredComparisonWithExplicitBypass,
            requires_deprecated_activation_callbacks: false,
            requires_invocation_id: true,
            supports_pidfd_identity: true,
        }
    }

    fn query<'a>(p: &'a ActivationProfile, digest: &'a str) -> ActivationProfileQuery<'a> {
        ActivationProfileQuery {
            nixos_release: &p.nixos_release,
            nixpkgs_revision: &p.nixpkgs_revision,
            switch_to_configuration_sha256: &p.switch_to_configuration_sha256,
            activation_semantics_revision: &p.activation_semantics_revision,
            systemd_version: &p.systemd_version,
            observer_adapter_revision: &p.observer_adapter_revision,
            expected_profile_digest: digest,
        }
    }

    #[test]
    fn exact_profile_tuple_resolves_and_emits_receipt() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        let digest = registry.register(p.clone()).unwrap();
        let (resolved, receipt) = registry.resolve_exact(&query(&p, &digest)).unwrap();
        assert_eq!(resolved.profile_id, p.profile_id);
        assert_eq!(receipt.profile_digest, digest);
        assert_eq!(receipt.nixos_release, p.nixos_release);
    }

    #[test]
    fn unknown_or_changed_profile_identity_never_falls_back() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        let digest = registry.register(p.clone()).unwrap();
        for mutate in 0..7 {
            let mut altered = p.clone();
            match mutate {
                0 => altered.nixos_release.push_str("-unknown"),
                1 => altered.nixpkgs_revision = "f".repeat(40),
                2 => altered.switch_to_configuration_sha256 = "b".repeat(64),
                3 => altered.activation_semantics_revision.push_str("-unknown"),
                4 => altered.systemd_version = "262".into(),
                5 => altered.observer_adapter_revision.push_str("-unknown"),
                6 => altered.profile_id.push_str("-different"),
                _ => unreachable!(),
            }
            let q = query(&altered, &digest);
            assert_eq!(registry.resolve_exact(&q).unwrap_err(),
                ActivationProfileError::UnknownProfile);
        }
    }

    #[test]
    fn profile_digest_mismatch_is_not_accepted() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register(p.clone()).unwrap();
        let wrong = "0".repeat(64);
        assert_eq!(registry.resolve_exact(&query(&p, &wrong)).unwrap_err(),
            ActivationProfileError::ProfileDigestMismatch);
    }

    #[test]
    fn duplicate_profile_key_is_rejected() {
        let p = profile();
        let mut registry = ActivationProfileRegistry::new();
        registry.register(p.clone()).unwrap();
        let mut duplicate = p;
        duplicate.profile_id = "a-second-name".into();
        assert_eq!(registry.register(duplicate), Err(ActivationProfileError::DuplicateProfile));
    }

    #[test]
    fn all_activation_modes_have_non_compensatory_postconditions() {
        let p = profile();
        assert_eq!(p.expected_postconditions(ActivationMode::Switch).unwrap(),
            ModePostconditions {
                running_generation: GenerationExpectation::Target,
                boot_default_generation: GenerationExpectation::Target,
                requires_post_reboot_observation: false,
                runtime_mutation_permitted: true,
                boot_default_mutation_permitted: true,
            });
        assert_eq!(p.expected_postconditions(ActivationMode::Test).unwrap().boot_default_generation,
            GenerationExpectation::Unchanged);
        assert_eq!(p.expected_postconditions(ActivationMode::Boot).unwrap().running_generation,
            GenerationExpectation::Unchanged);
        assert!(p.expected_postconditions(ActivationMode::Boot).unwrap().requires_post_reboot_observation);
        assert_eq!(p.expected_postconditions(ActivationMode::DryActivate).unwrap().running_generation,
            GenerationExpectation::Unchanged);
        assert!(!p.expected_postconditions(ActivationMode::DryActivate).unwrap().runtime_mutation_permitted);
    }

    #[test]
    fn unsupported_mode_is_denied() {
        let mut p = profile();
        p.supported_modes.remove(&ActivationMode::Boot);
        assert_eq!(p.expected_postconditions(ActivationMode::Boot),
            Err(ActivationProfileError::UnsupportedMode));
    }

    #[test]
    fn deprecated_activation_callback_dependency_is_denied() {
        let mut p = profile();
        p.requires_deprecated_activation_callbacks = true;
        assert_eq!(p.validate(), Err(ActivationProfileError::MalformedOrUnsafeProfile));
    }

    #[test]
    fn missing_invocation_identity_is_denied() {
        let mut p = profile();
        p.requires_invocation_id = false;
        assert_eq!(p.validate(), Err(ActivationProfileError::MalformedOrUnsafeProfile));
    }

    #[test]
    fn inhibitor_comparison_and_bypass_are_separate() {
        assert_eq!(validate_inhibitor_observation(
            InhibitorPolicy::RequiredComparisonWithExplicitBypass,
            InhibitorObservation::Passed, None), Ok(()));
        assert_eq!(validate_inhibitor_observation(
            InhibitorPolicy::RequiredComparison,
            InhibitorObservation::Blocked, None), Err(ActivationProfileError::InhibitorBlocked));
        assert_eq!(validate_inhibitor_observation(
            InhibitorPolicy::RequiredComparison,
            InhibitorObservation::Bypassed, Some(&"f".repeat(64))),
            Err(ActivationProfileError::InhibitorBypassDenied));
        assert_eq!(validate_inhibitor_observation(
            InhibitorPolicy::RequiredComparisonWithExplicitBypass,
            InhibitorObservation::Bypassed, None),
            Err(ActivationProfileError::InhibitorBypassMissingAuthorization));
    }

    #[test]
    fn thirty_two_activation_profile_negative_vectors_are_denied() {
        for vector in 0..32 {
            let mut p = profile();
            let mut registry = ActivationProfileRegistry::new();
            let digest = registry.register(p.clone()).unwrap();
            let mut q = query(&p, &digest);

            let denied = match vector {
                0 => { p.schema.push_str("-unknown"); p.validate().is_err() }
                1 => { p.version = 2; p.validate().is_err() }
                2 => { p.profile_id.clear(); p.validate().is_err() }
                3 => { p.nixos_release.clear(); p.validate().is_err() }
                4 => { p.nixpkgs_revision = "not-a-revision".into(); p.validate().is_err() }
                5 => { p.switch_to_configuration_sha256 = "xyz".into(); p.validate().is_err() }
                6 => { p.activation_semantics_revision.clear(); p.validate().is_err() }
                7 => { p.systemd_version.clear(); p.validate().is_err() }
                8 => { p.observer_adapter_revision.clear(); p.validate().is_err() }
                9 => { p.supported_modes.clear(); p.validate().is_err() }
                10 => { p.requires_deprecated_activation_callbacks = true; p.validate().is_err() }
                11 => { p.requires_invocation_id = false; p.validate().is_err() }
                12 => { q.nixos_release = "unknown-release"; registry.resolve_exact(&q).is_err() }
                13 => { q.nixpkgs_revision = "ffffffffffffffffffffffffffffffffffffffff"; registry.resolve_exact(&q).is_err() }
                14 => { q.switch_to_configuration_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; registry.resolve_exact(&q).is_err() }
                15 => { q.activation_semantics_revision = "unknown-semantics"; registry.resolve_exact(&q).is_err() }
                16 => { q.systemd_version = "262"; registry.resolve_exact(&q).is_err() }
                17 => { q.observer_adapter_revision = "unknown-observer"; registry.resolve_exact(&q).is_err() }
                18 => { q.expected_profile_digest = "0000000000000000000000000000000000000000000000000000000000000000"; registry.resolve_exact(&q).is_err() }
                19 => { let duplicate = p.clone(); registry.register(duplicate).is_err() }
                20 => { registry = ActivationProfileRegistry::new(); registry.resolve_exact(&q).is_err() }
                21 => { q.nixos_release = "fixture-release-A-26.11"; registry.resolve_exact(&q).is_err() }
                22 => { q.nixpkgs_revision = "0123456789abcdef0123456789abcdef01234568"; registry.resolve_exact(&q).is_err() }
                23 => { q.switch_to_configuration_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"; registry.resolve_exact(&q).is_err() }
                24 => { q.activation_semantics_revision = "fixture-activation-semantics-v2"; registry.resolve_exact(&q).is_err() }
                25 => { q.systemd_version = "260"; registry.resolve_exact(&q).is_err() }
                26 => { q.observer_adapter_revision = "fixture-systemd-observer-v2"; registry.resolve_exact(&q).is_err() }
                27 => { q.expected_profile_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; registry.resolve_exact(&q).is_err() }
                28 => { p.requires_deprecated_activation_callbacks = true; registry.register(p).is_err() }
                29 => { p.requires_invocation_id = false; registry.register(p).is_err() }
                30 => { p.supported_modes.remove(&ActivationMode::DryActivate); p.expected_postconditions(ActivationMode::DryActivate).is_err() }
                31 => validate_inhibitor_observation(
                    InhibitorPolicy::RequiredComparison,
                    InhibitorObservation::Bypassed,
                    Some(&"f".repeat(64)),
                ).is_err(),
                _ => unreachable!("the conformance corpus is fixed"),
            };
            assert!(denied, "activation profile negative vector {vector} was accepted");
        }
    }

    #[test]
    fn mode_postconditions_are_not_agent_supplied() {
        for mode in [ActivationMode::Switch, ActivationMode::Test, ActivationMode::Boot, ActivationMode::DryActivate] {
            let expected = ModePostconditions::for_mode(mode);
            match mode {
                ActivationMode::Switch => assert!(expected.runtime_mutation_permitted && expected.boot_default_mutation_permitted),
                ActivationMode::Test => assert!(expected.runtime_mutation_permitted && !expected.boot_default_mutation_permitted),
                ActivationMode::Boot => assert!(!expected.runtime_mutation_permitted && expected.boot_default_mutation_permitted),
                ActivationMode::DryActivate => assert!(!expected.runtime_mutation_permitted && !expected.boot_default_mutation_permitted),
            }
        }
    }
}
