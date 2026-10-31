// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Canonical environment contract for privileged Nixward worker payloads.
//!
//! Keep the contract in the library so the executor and the worker-gate binary
//! use the same allowlist. The digest in worker identity records is derived
//! from these exact pairs; the gate reapplies them immediately before exec so
//! a systemd unit's ambient environment cannot silently reach the payload.

/// The complete environment inherited by a privileged worker payload.
///
/// Do not add variables here without reviewing loader, Nix configuration,
/// shell, locale, and PATH implications and updating the environment digest
/// contract/tests.
pub fn pairs() -> &'static [(&'static str, &'static str)] {
    &[
        ("HOME", "/root"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("NIX_USER_CONF_FILES", "/dev/null"),
        (
            "PATH",
            "/run/current-system/sw/bin:/run/current-system/sw/sbin:/run/wrappers/bin",
        ),
        ("SYSTEMD_COLORS", "0"),
        ("TERM", "dumb"),
        ("XDG_CONFIG_HOME", "/var/empty"),
    ]
}

/// Clear all inherited variables and apply the canonical worker payload
/// environment. This is deliberately performed by the gate immediately
/// before the irreversible exec, not only by its parent launcher.
pub fn configure_payload_environment(command: &mut std::process::Command) {
    command.env_clear();
    command.envs(pairs().iter().copied());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_environment_is_a_unique_fixed_allowlist() {
        let values = pairs();
        let mut names = values.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), values.len(), "worker environment keys must be unique");
        assert_eq!(values.len(), 8, "changing the allowlist requires an explicit contract revision");
        assert!(values.iter().any(|(name, value)| *name == "NIX_USER_CONF_FILES" && *value == "/dev/null"));
        assert!(values.iter().any(|(name, value)| *name == "PATH" && value.starts_with("/run/current-system/sw/bin:")));
    }
}
