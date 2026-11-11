{
  description = "Isolated Nix source-filter regression check";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      sourceFilter = root: import ../../nix/source-filter.nix {
        lib = pkgs.lib;
        inherit root;
      };
    in {
      checks.${system}.source-filter =
        import ./check.nix { inherit pkgs sourceFilter; };
    };
}
