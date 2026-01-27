# The following is a package definition. It is used in `flake.nix`, but can also be called by the user directly if they don't wish to use flakes. Everything it takes as arguments it gets from `nixpkgs`, the official NixOS package repository (which doesn't only contain packages, but also helper functions for making new ones, it gets passed to it by `pkgs.callPackage` in the flake)
# It requests `buildDotnetModule` and `dotnetCorePackages`
{ buildDotnetModule, dotnetCorePackages }:

# This package is a .NET module...
buildDotnetModule rec {
  # ... with the name `Il2CppDumper` ...
  pname = "Il2CppDumper";
  # ... and version `6.7.46`
  version = "6.7.46";

  # The source code is located in the current directory (the GitHub repo)
  src = ./.;

  # Below are arguments that are specific to `buildDotnetModule`
  # The project file location
  projectFile = "Il2CppDumper/Il2CppDumper.csproj";

  # A lock-file for the dependencies (the one .NET creates is not specific enough)
  nugetDeps = ./deps.json;

  # The .NET sdk. The `with` means that everything after it has direct access to the properties of `dotnetCorePackages`
  # It uses `dotnetCorePackages.combinePackages`, and combines a single package: `dotnetCorePackages.sdk_8_0`
  dotnet-sdk = with dotnetCorePackages; combinePackages [
    sdk_8_0
  ];
  # And the same for the .NET runtime
  dotnet-runtime = with dotnetCorePackages; combinePackages [
    runtime_8_0
  ];
}
