# The "flake" definition starts here. Flakes are an experimental (but already widely used) method of defining packages. They take some `inputs` (which are automatically pinned in `flake.lock`) and produce some `outputs` (which in theory should be deterministic)
{
  description = "Unity il2cpp reverse engineer";

  # The "inputs are defined here"
  inputs = {
    # The official nix package repository
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    # A widely used (https://wiki.nixos.org/wiki/Flake_Utils) module for automatically building packages for all available achitectures (among other things)
    flake-utils.url = "github:numtide/flake-utils";
  };

  # The package-build instructions start here. They use the previously defined inputs, as well as `self` (the current flake)
  outputs = { self, nixpkgs, flake-utils }:
    # Every constant defined after `let` will be available after `in`
    let
      # A function named `getPkgs` that takes a package repository and returns a set containing 2 packages
      # (The `rec` is so that I can use constants from the set in the set itself)
      getPkgs = pkgs: rec {
        # Defined the il2cppdumper package as "the package from `default.nix`"
        il2cppdumper = pkgs.callPackage ./default.nix { };
        # Copies `il2cppdumper` to `default`
        default = il2cppdumper;
      };
    # This is where `getPkgs` is used
    in
      # For each system that is "default" (an arbitrary category chosen by the flake-utils' developers), do the following
      flake-utils.lib.eachDefaultSystem (system: {
        # Define `packages` as "the result of running `getPkgs` on `pkgs`"
        packages = let
          # Define pkgs as "nixpkgs (from inputs) built for the system that is currently being evaluated (from flake-utils)"
          pkgs = import nixpkgs { inherit system; };
        in
          getPkgs pkgs;
      # We're still in `eachDefaultSystem` (EDIT: Actually, we are not). The `//` operator joins sets together
      # The following defines some utility functions for the users of this flake
      }) // {
        # Define a default "overlay" (a function that modifies a package repository). We don't use it, but users of the flake might
        # It takes `final` (the package repository after all the overlays, yes, that can cause an infinite recursion) and `prev` (the package repository just before this overlays)
        overlays.default = final: prev:
          # Add the il2cppdumper package by calling getPkgs with the package repository we got
          getPkgs prev;

        # Define a `mkpkgs` function that takes `system` and `overlays`, passes them into `nixpkgs` and returns a set containing the built `il2cppdumper`
        mkpkgs = (system: overlays: let
          pkgs = import nixpkgs { inherit system overlays; };
        in
          {
            packages = getPkgs pkgs;
          });
      };
}
