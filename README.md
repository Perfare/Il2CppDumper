# IL2CPPDumperBinja

Binary Ninja Plugin for IL2CPPDumper

# Instructions

1. Run `Il2CppDumper <GameAssembly.dll> <Global-Metadata.dat> <Output-Dir>`.
2. Add the Plugin to Binary Ninja's Plugin folder.
3. Run the Plugin _IL2CPPDumper Load_, selecting `script.json` and `il2cpp.h`.
4. For interesting functions or `XXX_Type` variables, run _IL2CPPDumper Annotate_, and the plugin will help add the typings.

# Acknowledgements

This code is based on https://github.com/Perfare/Il2CppDumper/tree/master/Il2CppDumper/Il2CppBinaryNinja , modified to work with Binary Ninja updates and my use-case.
