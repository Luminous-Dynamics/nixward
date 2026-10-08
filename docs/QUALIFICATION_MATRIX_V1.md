# Nixward Qualification Matrix V1

This matrix is the boundary between implementation evidence and qualification.
`Implemented` means the code path exists and has deterministic tests or source
validation. `Observed` means a host or workflow produced evidence. `Qualified`
requires exact-head evidence satisfying the predicate's acceptance contract.

| Predicate | Exact subject | Evidence | Current state |
| --- | --- | --- | --- |
| realization | exact NixOS system closure | verified execution-intent + realization-plan `expectedOutPath`, source/config/lock digests | Implemented |
| runtime pre-state | exact `/run/current-system` closure | read-only store-path observation | Implemented |
| selected profile pre-state | exact `/nix/var/nix/profiles/system` closure | read-only profile-path observation | Implemented |
| profile transition | exact candidate profile closure | Nix-supported exact profile set + immediate exact re-observation | Implemented; external-writer CAS remains open |
| activation | exact candidate closure + action | exact `<store>/bin/switch-to-configuration <action>` | Implemented |
| recovery | exact prior runtime + profile + action | bound recovery command + post-recovery exact state | Implemented |
| Nixward transaction serialization | Nixward-owned activation transaction | native cross-process interlock | Implemented |
| next-boot selection | exact boot entry | read-only systemd-boot/GRUB selection observation | Implemented; overall qualification remains open |
| Type #1 NixOS binding | exact system closure | BLS `init=/nix/store/...-nixos-system-.../init` | Implemented |
| Type #2 UKI binding | exact EFI image + system closure | UKI BLAKE3 + `.cmdline` + exact `init=` binding | Implemented |
| Secure Boot firmware state | exact UEFI policy variables | `SecureBoot` + `SetupMode` raw observations | Implemented |
| firmware trust databases | exact `db`/`dbx` payloads | raw EFI variable digests | Implemented; authorization mapping remains open |
| PE signature table | exact UKI image | certificate-table offset/size/type/revision/payload digests | Implemented |
| certificate-pinned signature verification | exact image + exact verification cert | `sbverify --cert`, exact image/certificate digests, image-stability recheck | Implemented; live surface additionally requires enabled/stable firmware policy |
| Secure Boot signer authorization | exact signer + firmware policy | embedded X.509 chain identity + cryptographically verified `db` anchor identity + `dbx` image/chain vetoes + zero-time TBS hard veto | Partially implemented — Issue #17; timestamp semantics open |
| external-writer CAS | exact profile state | supported compare-and-set or equivalent privileged boundary | Open — Issue #9 |
| effective next boot | physical loader selection | bootloader-specific authoritative observation on real host | Open — Issue #8 |
| physical boot success | exact candidate boot | post-reboot runtime/boot-success evidence | Open — Issue #8 |
| hosted compiler/tests | exact Git commit | completed workflow with qualification receipt | Pending; no qualification claim |

## Rules

1. A queued, cancelled, skipped, or stale workflow is not a qualification pass.
2. A human-readable generation label is not an immutable closure identity.
3. An EFI image digest is not system-closure provenance.
4. A valid signature is not firmware trust authorization.
5. Firmware Secure Boot state is not proof that a selected image booted.
6. Successful `switch-to-configuration boot` is not proof of effective next-boot selection.
7. Physical reboot success is not post-boot health.
8. Unknown or unsupported evidence must remain explicit Unknown rather than being coerced into Pass.
9. Certificate-chain verification to a `db`/`dbx` anchor does not establish firmware-wide policy equivalence.
10. A live `db`/`dbx` verification is invalidated if either trust database changes across the verification boundary.
11. LoaderEntrySelected establishes current systemd-boot entry identity; it does not establish post-boot health.
12. A verified current-boot witness remains non-qualified until the expected pre-reboot state and the exact post-reboot witness are captured on the target host.
13. An X.509 `dbx` certificate veto is valid only when the stored certificate identity matches a certificate in the exact signing chain.
14. A TBS-hash `dbx` record remains non-vetoing until its EFI_TIME/timestamp semantics are evaluated.
15. A `db` trust anchor is not eligible to authorize the image until the exact image cryptographically verifies to that anchor; that verified anchor is then subject to the same `dbx` chain rules.
16. A live Secure Boot verification cannot qualify while firmware policy is Disabled, SetupMode, Unknown, or changed during the verification window.
9. Certificate-chain verification to a `db`/`dbx` anchor does not establish firmware-wide policy equivalence.
10. A live `db`/`dbx` verification is invalidated if either trust database changes across the verification boundary.

## Current qualification gate

Until a successful exact-head workflow produces the repository's qualification
receipt, implementation and deterministic fixture evidence remain non-qualified.
The current GitHub-hosted workflows are queued before their first steps; this is
not compiler/test evidence.
