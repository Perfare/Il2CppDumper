{ buildDotnetModule, dotnetCorePackages }:

buildDotnetModule rec {
  pname = "Il2CppDumper";
  version = "6.7.46";

  src = ./.;

  projectFile = "Il2CppDumper/Il2CppDumper.csproj";
  nugetDeps = ./deps.json;

  dotnet-sdk = with dotnetCorePackages; combinePackages [
    sdk_8_0
  ];
  dotnet-runtime = with dotnetCorePackages; combinePackages [
    runtime_8_0
  ];
}
