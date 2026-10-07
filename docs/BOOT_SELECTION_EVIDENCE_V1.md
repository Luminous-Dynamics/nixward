# Boot Selection Evidence V1

This document defines the read-only evidence boundary for proving that an exact
authorized NixOS system closure is selected for the next boot.

## Non-equivalence

The following are distinct facts:

- candidate closure was realized;
- system profile points at the candidate closure;
- a bootloader was updated successfully;
- a next-boot entry is selected;
- a boot attempt occurred;
- the candidate boot completed successfully;
- post-boot health checks passed.

No predicate may be satisfied by evidence belonging to a different predicate.

## Evidence record

| Field | Meaning |
| --- | --- |
| bootloader_family | systemd-boot, grub, or unknown |
| selection_kind | one-shot, persistent default, generated default, or unknown |
| selected_entry_id | exact loader/menu entry identity |
| selected_entry_source | authoritative EFI variable, loader state, GRUB environment, or generated configuration source |
| candidate_closure | exact /nix/store/...-nixos-system-* path, or absent when no exact binding is possible |
| boot_count_state | good, indeterminate, bad, or unknown |
| observed_at | observation timestamp |
| evidence_digest | digest over the complete observation |

A human-readable title, generation number, menu position, or arbitrary filename is
not sufficient to establish candidate_closure.

## systemd-boot

For UAPI.1 Type #1 entries, resolve the effective entry identifier to the exact
$BOOT/loader/entries/<id>.conf file. For UKIs, resolve the selected EFI image
identity separately.

The effective selection is:

1. an observed one-shot selection, when present;
2. otherwise an exact persistent default;
3. otherwise Unknown.

Pattern defaults such as nixos-* are selection rules, not exact observed entry
identity and therefore require further resolution before qualification.

Boot-counting metadata is retained independently. +tries-left and optional
-tries-done state must not be collapsed into a generic selected boolean.

## GRUB

Read the generated configuration and GRUB environment without mutation.

A one-shot next_entry takes precedence when present. Otherwise resolve an exact
generated default. Numeric defaults are rejected as Unknown because they are menu
positions rather than stable identities.

The selected menu entry must then be mapped to an exact NixOS closure. Labels
alone do not qualify.

## Unknown

Use explicit Unknown when:

- the bootloader family cannot be established;
- loader state is unavailable or ambiguous;
- the selected entry cannot be mapped to the exact candidate closure;
- multiple selection sources disagree;
- boot-counting state is not admissible under the qualification policy;
- Secure Boot or UKI metadata prevents exact image binding.

Unknown is evidence of insufficiency, not evidence of success.

## Current implementation boundary

src/action/boot_selection.rs contains deterministic parsers and pure selection
resolvers only. Host-side acquisition of EFI, $BOOT, and GRUB state must be
implemented as a separate privileged read-only adapter and must feed these
resolvers rather than duplicate selection semantics.

## Test fixtures

The parser suite covers exact Type #1 parsing, boot-count state, one-shot
precedence, pattern-default rejection, numeric GRUB default rejection, and
exact menu-entry mapping. Subsequent host adapters should add fixtures for
missing loader state, conflicting selection state, UKI identity mismatch, and
boot-count exhaustion.