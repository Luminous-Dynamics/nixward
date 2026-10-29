# Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
#
# Independent Nix reference model for supervisor temporal-trace conformance.
# This is intentionally pure: it classifies trace evidence and never executes
# commands, authorizes a mutation, or performs recovery.
{ lib }:
{ expected_transaction_id, expected_attempt_id, events }:
let
  isBlank = value: builtins.match "[[:space:]]*" value != null;

  initial = {
    authorization_verified = false;
    attempt_prepared = false;
    submission_barrier_persisted = false;
    manager_start_submitted = false;
    worker_identity_observed = false;
    worker_identity_persisted = false;
    payload_released = false;
    payload_exited = false;
    process_receipt_persisted = false;
    target_observed_after_exit = null;
    lifecycle_postcondition_validated = false;
    lifecycle_validation_seen_for_current_target = false;
    terminal_success_claimed = false;
    violations =
      (if isBlank expected_transaction_id then [ "empty_expected_transaction_id" ] else [])
      ++ (if isBlank expected_attempt_id then [ "empty_expected_attempt_id" ] else []);
  };

  step = state: event:
    let
      kind = event.kind;
      append = names: state // { violations = state.violations ++ names; };
    in
      if event.transaction_id != expected_transaction_id
        || event.attempt_id != expected_attempt_id
      then
        append [ "event_identity_binding_mismatch" ]
      else if state.terminal_success_claimed then
        append [ "event_after_terminal_success" ]
      else if kind == "authorization_verified" then
        state // {
          authorization_verified = true;
          violations = state.violations
            ++ (if state.authorization_verified then [ "duplicate_authorization_verification" ] else []);
        }
      else if kind == "attempt_prepared_durably" then
        state // {
          attempt_prepared = true;
          violations = state.violations
            ++ (if state.attempt_prepared then [ "duplicate_attempt_preparation" ] else [])
            ++ (if !state.authorization_verified then [ "attempt_prepared_without_verified_authorization" ] else []);
        }
      else if kind == "submission_barrier_persisted" then
        state // {
          submission_barrier_persisted = true;
          violations = state.violations
            ++ (if state.submission_barrier_persisted then [ "duplicate_submission_barrier" ] else [])
            ++ (if !state.attempt_prepared then [ "submission_barrier_without_prepared_attempt" ] else [])
            ++ (if !state.authorization_verified then [ "attempt_prepared_without_verified_authorization" ] else []);
        }
      else if kind == "manager_start_submitted" then
        state // {
          manager_start_submitted = true;
          violations = state.violations
            ++ (if !state.submission_barrier_persisted then [ "start_submission_without_write_ahead_barrier" ] else [])
            ++ (if state.manager_start_submitted then [ "duplicate_manager_start_submission" ] else []);
        }
      else if kind == "worker_identity_observed" then
        state // {
          worker_identity_observed = true;
          violations = state.violations
            ++ (if state.worker_identity_observed then [ "duplicate_worker_identity_observation" ] else [])
            ++ (if !state.manager_start_submitted then [ "worker_identity_observed_before_start_submission" ] else []);
        }
      else if kind == "worker_identity_persisted" then
        state // {
          worker_identity_persisted = true;
          violations = state.violations
            ++ (if state.worker_identity_persisted then [ "duplicate_worker_identity_persistence" ] else [])
            ++ (if !state.worker_identity_observed then [ "worker_identity_persisted_before_observation" ] else []);
        }
      else if kind == "payload_released" then
        state // {
          payload_released = true;
          violations = state.violations
            ++ (if !state.authorization_verified then [ "payload_released_without_authorization" ] else [])
            ++ (if !state.manager_start_submitted then [ "payload_released_before_start_submission" ] else [])
            ++ (if !state.worker_identity_persisted then [ "payload_released_before_durable_worker_identity" ] else [])
            ++ (if state.payload_released then [ "duplicate_payload_release" ] else []);
        }
      else if kind == "payload_exited" then
        state // {
          payload_exited = true;
          violations = state.violations
            ++ (if state.payload_exited then [ "duplicate_payload_exit" ] else [])
            ++ (if !state.payload_released then [ "payload_exit_before_payload_release" ] else []);
        }
      else if kind == "process_receipt_persisted" then
        state // {
          process_receipt_persisted = true;
          violations = state.violations
            ++ (if state.process_receipt_persisted then [ "duplicate_process_receipt_publication" ] else [])
            ++ (if !state.payload_exited then [ "receipt_before_payload_exit" ] else [])
            ++ (if !state.worker_identity_persisted then [ "receipt_without_durable_worker_identity" ] else []);
        }
      else if lib.hasPrefix "target_observed:" kind then
        if state.payload_exited && state.process_receipt_persisted then
          state // {
            target_observed_after_exit = lib.removePrefix "target_observed:" kind;
            lifecycle_postcondition_validated = false;
            lifecycle_validation_seen_for_current_target = false;
          }
        else
          state
      else if kind == "lifecycle_postcondition_validated" then
        let
          candidate_post_state =
            state.target_observed_after_exit == "candidate_runtime_and_profile_active";
        in
          state // {
            lifecycle_postcondition_validated = state.payload_exited && candidate_post_state;
            lifecycle_validation_seen_for_current_target = true;
            violations = state.violations
              ++ (if state.lifecycle_validation_seen_for_current_target then [ "duplicate_lifecycle_validation" ] else [])
              ++ (if !state.payload_exited then [ "lifecycle_validation_before_payload_exit" ] else [])
              ++ (if state.target_observed_after_exit == null then [ "lifecycle_validation_without_post_exit_target_observation" ] else [])
              ++ (if !candidate_post_state then [ "lifecycle_validation_without_candidate_post_state" ] else []);
          }
      else if kind == "terminal_success_recorded" then
        state // {
          terminal_success_claimed = true;
          violations = state.violations
            ++ (if !state.process_receipt_persisted then [ "terminal_success_without_process_receipt" ] else [])
            ++ (if state.target_observed_after_exit != "candidate_runtime_and_profile_active" then [ "terminal_success_without_candidate_post_state" ] else [])
            ++ (if !state.lifecycle_postcondition_validated then [ "terminal_success_without_lifecycle_validation" ] else []);
        }
      else
        append [ "unknown_event_kind" ];

  final = lib.foldl' step initial events;
  disposition =
    if final.violations != [] then "rejected"
    else if final.terminal_success_claimed then "validated_terminal_success"
    else "incomplete";
in
{
  inherit disposition;
  terminal_success_claimed = final.terminal_success_claimed;
  violations = lib.sort builtins.lessThan final.violations;
}
