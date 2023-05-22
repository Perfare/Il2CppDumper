# IL2CPPDumperBinja
Binary Ninja Plugin for IL2CPPDumper

# Instructions

1. Run `Il2CppDumper <GameAssembly.dll> <Global-Metadata.dat> <Output-Dir>`.
2. Add the Plugin to Binary Ninja's Plugin folder.
3. Run `ConvertHeaders.jl` in the `Output-Dir`. 
4. Load `il2cpp-binja.h` into Binary Ninja via Analysis > Import Header file.
5. Run the Plugin, selecting `script.json`.
6. When analyzing the function, use 

   `current_function.type = current_function.get_function_tags(tag_type = "Signature")[0].data` 
   
   in the Python Console to add the type information. This is as adding the signatures directly will make the analysis too slow.

# Acknowledgements
  
This code is based on https://github.com/Perfare/Il2CppDumper/tree/master/Il2CppDumper/Il2CppBinaryNinja , modified to work with Binary Ninja updates and my use-case. 
