{
  description = "Unity il2cpp reverse engineer";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: 
    let
      getPkgs = pkgs: rec {
        il2cppdumper = pkgs.callPackage ./default.nix { };
        default = il2cppdumper;
      };
    in
      flake-utils.lib.eachDefaultSystem (system: {
        packages = let
          pkgs = import nixpkgs { inherit system; };
        in
          getPkgs pkgs;
      }) // {
        overlays.default = final: prev:
          getPkgs prev;

        mkpkgs = (system: overlays: let
          pkgs = import nixpkgs { inherit system overlays; };
        in
          {
            packages = getPkgs pkgs;
          });
      };
}
