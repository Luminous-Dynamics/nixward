# Nixward Profile Transition Evidence V1

This document defines the concurrency boundary around the exact NixOS system
profile transition.

## Non-equivalence

These facts are distinct:

- Nixward observed an exact prior profile closure;
- Nixward acquired its own transaction interlock;
- Nix acquired the profile mutation lock;
- Nixward requested an exact candidate profile closure;
- the profile was observed to contain the candidate afterwards;
- the immutable closure activation succeeded;
- the post-activation profile and runtime still match the authorized transaction.

Atomic replacement of the profile target is not a compare-and-set against the
previously observed value.

## Current privileged sequence

The exact activation path is:

```
exact prior runtime/profile observation
        |
Nixward transaction interlock
        |
exact nix-env --set candidate
        |
immediate exact profile re-observation
        |
exact immutable switch-to-configuration
        |
post-activation runtime/profile verification
        |
bound recovery if required
```

Nix documents `nix-env --set` as setting the current generation of a profile to
the specified derivation. Nixward therefore treats that command as the mutation
primitive while keeping the observation and attribution boundary outside it.

## External-writer race matrix

| External writer position | Nixward evidence result |
| --- | --- |
| Before pre-state observation | Abort before mutation |
| After pre-state observation, before `nix-env --set` | CandidateWriteMasksExternalWriter |
| After `nix-env --set`, before post-set verification | Detect post-set profile drift |
| After post-set verification, before activation | Detect pre-activation profile drift |
| After activation, before post-state verification | Detect post-activation profile drift |
| No external writer | Clean transition |

The `CandidateWriteMasksExternalWriter` case is the irreducible residual:
Nixward can observe prior state X, an external writer can temporarily change X to
Y, and Nixward can then successfully set the authorized candidate Z. The final
observation of Z cannot prove that Y never existed. A separate lock owned by
Nixward cannot make a root/external writer respect it.

This is therefore not labeled CAS.

## Deterministic simulation

`src/action/profile_transition.rs` contains the exact six-case state-machine
fixture. It is intentionally separate from the production mutation path so that
the fixture demonstrates the security boundary without pretending to control
Nix's external writers.

The simulation is useful as a review invariant:

**detected race -> fail closed**

**undetectable race -> explicit residual**

**never -> inferred CAS**

## Qualification boundary

A successful deterministic race simulation is implementation evidence only.
Qualification still requires exact-head hosted compilation/tests and, for the
real host, observed exact profile/runtime transitions.

The residual external-writer window remains an Issue #9 limitation until Nix or
the privileged architecture exposes a supported compare-and-set/equivalent
authorization boundary.
