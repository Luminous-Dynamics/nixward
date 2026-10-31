# Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
# SPDX-License-Identifier: AGPL-3.0-or-later
{
  description = "Nixward: sovereign NixOS management via HDC and active inference";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    let
      nixosModules.default = import ./nix/module.nix;
      nixosModules.nixward = nixosModules.default;
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchainToml = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
        rustChannel = rustToolchainToml.toolchain.channel;
        rustToolchain = pkgs.rust-bin.stable.${rustChannel}.default;

        commonBuildInputs = with pkgs; [
          pkg-config
          openssl
          openssl.dev
          sqlite
          tree-sitter
          dbus
        ];

        commonNativeBuildInputs = with pkgs; [
          pkg-config
          cmake
        ];

        mkNixwardPackage = { name, features, binName ? name }:
          pkgs.rustPlatform.buildRustPackage {
            pname = name;
            version = "0.1.0";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };

            buildInputs = commonBuildInputs;
            nativeBuildInputs = commonNativeBuildInputs;

            env.HOME = "$TMPDIR";
            env.RUSTC_WRAPPER = "";

            cargoBuildFlags = [
              "-p" "nixward"
              "--bin" binName
              "--bin" "nixward-worker-gate"
              "--features" features
            ];

            doCheck = false;

            installPhase = ''
              mkdir -p $out/bin
              cp target/release/${binName} $out/bin/
              cp target/release/nixward-worker-gate $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "Nixward NixOS management tool (${name})";
              homepage = "https://luminousdynamics.org";
              license = licenses.agpl3Plus;
            };
          };
      in {
        nixosModules = {
          default = nixosModules.default;
          nixward = nixosModules.nixward;
        };

        packages = {
          nixward = mkNixwardPackage {
            name = "nixward";
            features = "cli";
            binName = "nixward";
          };
          nixward-tui = mkNixwardPackage {
            name = "nixward-tui";
            features = "tui";
            binName = "nixward-tui";
          };
          nixward-daemon = mkNixwardPackage {
            name = "nixward-daemon";
            features = "daemon";
            binName = "nixward-daemon";
          };
          default = self.packages.${system}.nixward;
        };

        apps = {
          nixward = flake-utils.lib.mkApp { drv = self.packages.${system}.nixward; };
          nixward-tui = flake-utils.lib.mkApp { drv = self.packages.${system}.nixward-tui; };
          default = self.apps.${system}.nixward;
        };

        checks.standalone-module-evaluation =
          pkgs.runCommand "nixward-standalone-module-evaluation" {} ''
            test -f ${./Cargo.toml}
            test -f ${./rust-toolchain.toml}
            test -f ${./nix/module.nix}
            touch $out
          '';

        checks.nixward-cli = self.packages.${system}.nixward;

        # Validate the shared supervisor temporal corpus during nix flake check.
        # A separate pure Nix reference model replays each vector, providing a
        # cross-language semantic check without compiling the Rust test binary.
        # This is still a model check over fixtures, not OS/receipt authenticity.
        checks.supervisor-temporal-qualification-vectors =
          let
            corpus = builtins.fromJSON (builtins.readFile ./docs/fixtures/supervisor-temporal-qualification-v1.json);
            vectors = corpus.vectors;
            ids = map (vector: vector.id) vectors;
            expectedViolations = pkgs.lib.concatLists (map (vector: vector.expected_violations) vectors);
            referenceTraceCheck = import ./nix/supervisor-temporal-trace.nix { inherit (pkgs) lib; };
            validDispositions = [
              "rejected"
              "incomplete"
              "validated_terminal_success"
            ];
            knownEventKinds = [
              "authorization_verified"
              "attempt_prepared_durably"
              "submission_barrier_persisted"
              "manager_start_submitted"
              "worker_identity_observed"
              "worker_identity_persisted"
              "payload_released"
              "payload_exited"
              "process_receipt_persisted"
              "lifecycle_postcondition_validated"
              "terminal_success_recorded"
              "target_observed:not_attempted"
              "target_observed:candidate_runtime_and_profile_active"
              "target_observed:predecessor_runtime_and_profile_active"
              "target_observed:boot_candidate_profile_selected"
              "target_observed:mixed_or_unknown"
              "target_observed:unavailable"
            ];
            requiredVectorIds = [
              "valid-terminal-success"
              "ambiguous-manager-submission"
              "manager-start-before-barrier"
              "duplicate-manager-start"
              "release-before-durable-worker-identity"
              "foreign-transaction-event"
              "empty-expected-transaction"
              "whitespace-expected-attempt"
              "target-before-receipt-is-stale"
              "mixed-target-invalidates-prior-validation"
              "duplicate-process-receipt"
              "event-after-terminal-success"
              "repeated-failed-lifecycle-validation"
              "duplicate-successful-lifecycle-validation"
              "duplicate-payload-exit"
              "duplicate-authorization-verification"
              "worker-identity-persisted-before-observation"
              "foreign-attempt-event"
              "duplicate-attempt-preparation"
              "duplicate-write-ahead-barrier"
              "duplicate-worker-identity-observation"
              "duplicate-worker-identity-persistence"
              "duplicate-payload-release"
              "attempt-prepared-without-authorization"
              "barrier-without-prepared-attempt"
              "worker-identity-observed-before-start"
              "payload-released-without-authorization"
              "payload-released-before-start"
              "payload-exit-before-release"
              "receipt-before-payload-exit"
              "receipt-without-durable-worker-identity"
              "lifecycle-validation-before-exit"
              "terminal-success-without-process-receipt"
            ];
            requiredViolationNames = [
              "event_identity_binding_mismatch"
              "empty_expected_transaction_id"
              "empty_expected_attempt_id"
              "duplicate_authorization_verification"
              "duplicate_attempt_preparation"
              "duplicate_submission_barrier"
              "attempt_prepared_without_verified_authorization"
              "submission_barrier_without_prepared_attempt"
              "start_submission_without_write_ahead_barrier"
              "duplicate_manager_start_submission"
              "worker_identity_observed_before_start_submission"
              "duplicate_worker_identity_observation"
              "worker_identity_persisted_before_observation"
              "duplicate_worker_identity_persistence"
              "payload_released_without_authorization"
              "payload_released_before_start_submission"
              "payload_released_before_durable_worker_identity"
              "duplicate_payload_release"
              "payload_exit_before_payload_release"
              "duplicate_payload_exit"
              "receipt_before_payload_exit"
              "receipt_without_durable_worker_identity"
              "duplicate_process_receipt_publication"
              "lifecycle_validation_before_payload_exit"
              "lifecycle_validation_without_post_exit_target_observation"
              "lifecycle_validation_without_candidate_post_state"
              "duplicate_lifecycle_validation"
              "terminal_success_without_process_receipt"
              "terminal_success_without_candidate_post_state"
              "terminal_success_without_lifecycle_validation"
              "event_after_terminal_success"
            ];
            requiredDuplicateMilestones = [
              "duplicate_authorization_verification"
              "duplicate_attempt_preparation"
              "duplicate_submission_barrier"
              "duplicate_manager_start_submission"
              "duplicate_worker_identity_observation"
              "duplicate_worker_identity_persistence"
              "duplicate_payload_release"
              "duplicate_payload_exit"
              "duplicate_process_receipt_publication"
              "duplicate_lifecycle_validation"
            ];
            validEvent = event:
              builtins.isString event.transaction_id
              && builtins.isString event.attempt_id
              && builtins.isString event.kind
              && builtins.elem event.kind knownEventKinds;
            matchesReferenceModel = vector:
              let
                actual = referenceTraceCheck {
                  inherit (vector) expected_transaction_id expected_attempt_id events;
                };
              in
                actual.disposition == vector.expected_disposition
                && actual.terminal_success_claimed == vector.expected_terminal_success_claimed
                && actual.violations == pkgs.lib.sort builtins.lessThan vector.expected_violations;
            validVector = vector:
              builtins.isString vector.id
              && builtins.isString vector.purpose
              && builtins.isString vector.expected_transaction_id
              && builtins.isString vector.expected_attempt_id
              && builtins.elem vector.expected_disposition validDispositions
              && builtins.isBool vector.expected_terminal_success_claimed
              && builtins.isList vector.expected_violations
              && builtins.all builtins.isString vector.expected_violations
              && builtins.isList vector.events
              && builtins.all validEvent vector.events;
          in
            assert corpus.schema == "org.luminousdynamics.nixward.supervisor-temporal-trace-vectors";
            assert corpus.version == 1;
            # Version 1 is deliberately frozen at 33 unique cases; revise this
            # expectation explicitly when adding/removing normative vectors.
            assert builtins.length vectors == 33;
            assert builtins.length ids == builtins.length (pkgs.lib.unique ids);
            assert builtins.all (id: id != "") ids;
            assert builtins.all
              (id: builtins.elem id ids)
              requiredVectorIds;
            assert builtins.all
              (disposition: builtins.elem disposition (map (vector: vector.expected_disposition) vectors))
              validDispositions;
            assert builtins.all validVector vectors;
            # Differential semantic check: Nix reference model vs. Rust fixture expectations.
            assert builtins.all matchesReferenceModel vectors;
            assert builtins.all
              (name: builtins.elem name expectedViolations)
              requiredViolationNames;
            assert builtins.all
              (milestone: builtins.elem milestone expectedViolations)
              requiredDuplicateMilestones;
            pkgs.runCommand "nixward-supervisor-temporal-qualification-vectors" {} ''
              touch $out
            '';

        # Structural guard for the systemd transaction crash-cut campaign.
        # This validates the corpus declarations only; it does not run systemd,
        # a NixOS VM, storage faults, or establish durability semantics.
        checks.systemd-transaction-crash-cut-corpus =
          let
            corpus = builtins.fromJSON (builtins.readFile ./docs/fixtures/systemd-transaction-crash-cuts-v1.json);
            cuts = corpus.cuts;
            cutIds = map (cut: cut.id) cuts;
            controls = corpus.controls;
            controlIds = map (control: control.id) controls;
            dispositions = [
              "no_attempt"
              "incomplete"
              "indeterminate"
              "rejected"
              "validated_terminal_success"
            ];
            requiredCutIds = [
              "C001" "C002" "C003" "C004" "C005"
              "C006" "C007" "C008" "C009" "C010"
              "C011" "C012" "C013" "C014" "C015"
            ];
            requiredControls = [ "P001" "N001" "N002" "N003" "N004" ];
            validCut = cut:
              builtins.isString cut.id
              && builtins.isString cut.fault_class
              && builtins.isString cut.cut_after
              && builtins.isString cut.inject
              && builtins.isString cut.durable_prefix
              && builtins.isString cut.manager_state
              && builtins.elem cut.expected_disposition dispositions
              && builtins.isString cut.allowed_action
              && cut.same_attempt_replay == false
              && builtins.isBool cut.new_attempt_allowed
              && cut.new_attempt_allowed == (cut.id == "C001")
              && builtins.isList cut.required_evidence
              && builtins.length cut.required_evidence >= 2
              && builtins.all builtins.isString cut.required_evidence
              && builtins.isString cut.safety_invariant
              && builtins.stringLength cut.safety_invariant >= 20;
            validControl = control:
              builtins.isString control.id
              && builtins.elem control.kind [ "positive_control" "negative_control" ]
              && builtins.elem control.expected_disposition dispositions
              && builtins.isString control.requirement;
          in
            assert corpus.schema == "org.luminousdynamics.nixward.systemd-crash-cut-matrix";
            assert corpus.version == 1;
            assert corpus.status == "research_only_vm_qualification_plan";
            assert builtins.length cuts == 15;
            assert builtins.length cutIds == builtins.length (pkgs.lib.unique cutIds);
            assert builtins.all (id: builtins.elem id cutIds) requiredCutIds;
            assert builtins.all validCut cuts;
            assert builtins.length controls == 5;
            assert builtins.length controlIds == builtins.length (pkgs.lib.unique controlIds);
            assert builtins.all (id: builtins.elem id controlIds) requiredControls;
            assert builtins.all validControl controls;
            assert builtins.length corpus.result_dimensions >= 5;
            assert builtins.length corpus.promotion_gates >= 7;
            pkgs.runCommand "nixward-systemd-transaction-crash-cut-corpus" {} ''
              touch $out
            '';

        devShells.default = pkgs.mkShell {
          buildInputs = commonBuildInputs ++ [
            rustToolchain
            pkgs.cargo-watch
            pkgs.sbsigntool
          ];
          nativeBuildInputs = commonNativeBuildInputs;

          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";

          shellHook = ''
            echo "nixward standalone development shell"
            echo "  cargo check --all-targets"
            echo "  cargo test"
            echo "  nix flake check"
            echo "  sbsigntool: sbverify --cert <certificate> <efi-image>"
          '';
        };
      }
    ) // {
      inherit nixosModules;
    };
}
