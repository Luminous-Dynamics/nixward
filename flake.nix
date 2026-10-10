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
