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
| selection_kind | one-shot, preferred default, persistent default, generated default, or unknown |
| selected_entry_id | exact loader/menu entry identity |
| selected_entry_source | authoritative EFI variable, loader state, GRUB environment, or generated configuration source |
| candidate_closure | exact /nix/store/...-nixos-system-* path, or absent when no exact binding is possible |
| selected_image_path | exact selected EFI image path for Type #2 UKI observations, otherwise absent |
| selected_image_blake3 | exact BLAKE3 identity of the selected EFI image, otherwise absent |
| boot_count_state | good, indeterminate, bad, not-tracked, or unknown |
| observed_at | observation timestamp |
| evidence_digest | digest over the complete observation |

A human-readable title, generation number, menu position, or arbitrary filename is
not sufficient to establish candidate_closure.

## systemd-boot

For UAPI.1 Type #1 entries, resolve the effective entry identifier to the exact
$BOOT/loader/entries/<id>.conf file. For NixOS entries, the exact system closure
may be exposed by the entry's kernel command-line options through an
init=/nix/store/...-nixos-system-.../init binding; this binding is preferred
over kernel/initrd artifact paths, which identify boot artifacts rather than the
whole system closure. Type #2 UKIs require a separate exact image observation and image-to-system
binding. The evidence record carries the selected EFI path and BLAKE3 image
identity separately from the embedded `init=/nix/store/...-nixos-system-.../init`
system-closure binding. A valid image digest or Secure Boot signature alone does
not establish the system-closure subject.

The effective selection is:

1. an observed one-shot selection, when present;
2. otherwise an exact LoaderEntryPreferred selection when present;
3. otherwise an exact persistent default;
4. otherwise Unknown.

LoaderEntryPreferred is not interchangeable with LoaderEntryDefault: systemd-boot
uses the preferred entry with boot assessment applied, while the default entry
ignores boot-assessment failures. The observer therefore records the source
separately as PreferredDefault rather than hiding the policy distinction.

Pattern defaults such as nixos-* are selection rules, not exact observed entry
identity and therefore require further resolution before qualification.

Boot-counting metadata is retained independently. +tries-left and optional
-tries-done state must not be collapsed into a generic selected boolean. An entry
without boot-counting metadata is `not-tracked`, not `good`.

## Physical reboot correlation

The systemd-boot current-entry witness proves which entry the loader reports
as selected. A separate boot-transition correlation proves that the machine
actually crossed a reboot boundary and that the resulting running OS and kernel
command line bind to the exact expected NixOS closure.

The correlation requires a pre-reboot kernel `boot_id` captured before the boot
request and a post-reboot `boot_id` that differs. It independently checks
`/run/current-system` and the kernel's `init=/nix/store/...-nixos-system-.../init`
binding. This is useful for GRUB too: it proves the exact closure was physically
booted without pretending GRUB exposes the same current-entry UAPI witness as
systemd-boot.

Only the state `BootTransitionState::VerifiedReboot` satisfies this physical
reboot predicate. Same-boot, missing-ID, runtime mismatch, and command-line
mismatch states remain non-qualified.

## Current-boot witness

For systemd-boot, LoaderEntrySelected is the authoritative identifier written by
the boot loader for the entry used for the current boot. Nixward's post-reboot
witness correlates that value with the exact selected-entry NixOS closure, the
read-only /run/current-system closure, the kernel's
init=/nix/store/...-nixos-system-.../init binding from /proc/cmdline, and the
kernel boot ID. Only an exact agreement across those subjects produces
BootWitnessState::Verified.

This is stronger than observing that a future boot selection exists: it is
current boot identity evidence. It still does not prove service health,
application correctness, or long-term stability. GRUB remains separate because
it does not provide the same current-entry witness in the systemd-boot UAPI.

## GRUB

Read the generated configuration and GRUB environment without mutation.

A one-shot next_entry takes precedence when present. Otherwise resolve an exact
generated default. Numeric defaults are rejected as Unknown because they are menu
positions rather than stable identities.

Current NixOS generated GRUB configuration emits each system configuration as a
menuentry and places the exact system closure in the entry's kernel command via
init=/nix/store/...-nixos-system-.../init. The parser therefore binds to that
exact init closure rather than treating the menu title as the subject identity.

The selected menu entry must then be mapped to an exact NixOS closure. Labels
alone do not qualify. Duplicate menuentry titles fail closed because a title-only
selector would otherwise be ambiguous.

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

src/action/boot_selection.rs contains deterministic parsers and selection
resolvers plus read-only systemd-boot and UEFI-GRUB host observers. Type #2 UKI
identity/binding is implemented in `src/action/uki_evidence.rs` and composes with
the systemd-boot selector when an exact `.efi` subject is selected. The observers
obtain only bootloader selection/configuration state and feed the pure resolvers.
The systemd-boot observer reads UEFI selection variables and the authoritative BLS
root; the GRUB observer reads NixOS-generated grub.cfg and the GRUB environment
through read-only grub-editenv. BIOS-only GRUB remains explicit Unknown.

## Test fixtures

The parser suite covers exact Type #1 parsing, boot-count state, one-shot
precedence, preferred-entry precedence, pattern-default rejection, numeric GRUB
default rejection, and exact menu-entry mapping. The current-boot witness also
has deterministic parsing coverage for exact kernel init bindings. Subsequent
host qualification should exercise real reboots and correlate a pre-reboot
expected entry/closure with the post-reboot witness.