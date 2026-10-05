# Nixward standalone flake.
#
# The executable source lives in this repository. Symthaea is consumed only as
# an exact git dependency so Cargo/Nix cannot silently fall back into the old
# monorepo checkout.
{
  description = "nixward: sovereign NixOS observation, reasoning, and bounded action";

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
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchainToml =
          builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
        rustChannel = rustToolchainToml.toolchain.channel;
        rustToolchain = pkgs.rust-bin.stable."\${rustChannel}".default;

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

        mkNixwardPackage =
          { name, features, binName ? name }:
          pkgs.rustPlatform.buildRustPackage {
            pname = name;
            version = "0.1.0";
            src = ./.;

            # Until the generated lockfile is committed, this fixed-output hash
            # deliberately fails closed and reports the exact vendor hash.
            cargoHash = pkgs.lib.fakeHash;

            buildInputs = commonBuildInputs;
            nativeBuildInputs = commonNativeBuildInputs;

            env.HOME = "$TMPDIR";
            env.RUSTC_WRAPPER = "";

            cargoBuildFlags = [
              "--bin" binName
              "--features" features
            ];

            doCheck = false;

            installPhase = ''
              mkdir -p $out/bin
              cp target/release/${binName} $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "Sovereign NixOS management tool (${name})";
              homepage = "https://luminousdynamics.org";
              license = licenses.agpl3Plus;
              platforms = platforms.linux;
            };
          };

      in {
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
          nixward = flake-utils.lib.mkApp {
            drv = self.packages.${system}.nixward;
          };
          nixward-tui = flake-utils.lib.mkApp {
            drv = self.packages.${system}.nixward-tui;
          };
          default = self.apps.${system}.nixward;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = commonBuildInputs ++ [ rustToolchain pkgs.cargo-watch ];
          nativeBuildInputs = commonNativeBuildInputs;

          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";

          shellHook = ''
            echo "nixward development shell"
            echo "  cargo build --features cli"
            echo "  cargo build --features tui"
            echo "  cargo test --features tui --lib"
          '';
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    ) // {
      inherit nixosModules;
    };
}
