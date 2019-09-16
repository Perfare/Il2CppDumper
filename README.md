# Il2CppDumper

[![Build status](https://ci.appveyor.com/api/projects/status/anhqw33vcpmp8ofa?svg=true)](https://ci.appveyor.com/project/Perfare/il2cppdumper/branch/master/artifacts)

中文说明请戳[这里](README.zh-CN.md)

Extract .NET metadata from il2cpp binaries. (types, methods, fields, etc.)

Extraction code is based on [Il2CppDumper](https://github.com/Jumboperson/Il2CppDumper)  

## Features

* Supports il2cpp binaries in ELF, ELF64, Mach-O, PE and NSO format
* Supports global-metadata version 16 and 19-24
* Extracts .NET metadata including types, fields, properties, methods and attributes
* Supports automated IDA script generation
  * rename method
  * name and tag metadata
  * makefunction to improve ida analysis
* Generates dummy DLLs that can be viewed in .NET decompilers

## Usage

Run `Il2CppDumper.exe` and choose the main il2cpp executable (in ELF, Mach-O or PE format) and `global-metadata.dat` file, then select the extraction mode. The program will then generate all the output files in current working directory.

### Extraction Modes

#### Manual

The parameters (`CodeRegistration` and `MetadataRegistration`) that are passed to `il2cpp::vm::MetadataCache::Register()` needs to be manually reverse engineered and passed to the program.

#### Auto

Automatically finds the `il2cpp_codegen_register()` function by signature matching and read out the first (`CodeRegistration`) and second (`MetadataRegistration`) parameter passed to the `il2cpp::vm::MetadataCache::Register()` method that will be invoked in the registration function. May not work well due to compiler optimizations.

#### Auto(Plus) - **Recommended**

Matches possible pointers in the data section with some guidance from global-metadata.

Supports metadata version 20 and up

only `CodeRegistration` address can be found on metadata version 16

#### Auto(Symbol)

Uses symbols in the il2cpp binary to locate `CodeRegistration` and `MetadataRegistration`.

Only supports certain Android ELF files.

### Output files

#### dump.cs

C# pseudocode. Can be viewed in text editors (syntax highlighting recommended)

#### script.py

Requires IDA and IDAPython. Can be loaded in IDA via `File -> Script file`.

#### DummyDll

DLLs generated by Mono.Cecil which contain the .NET metadata extracted from the binary (no code included). Can be viewed in .NET decompilers.

### Configuration

All the configuration options are located in `config.json`
Available options:

* `DumpMethod`, `DumpField`, `DumpProperty`, `DumpAttribute`, `DumpFieldOffset`, `DumpMethodOffset`, `DumpTypeDefIndex`
  * Whether or not the program should extract these information

* `DummyDll`
  * Whether or not the program should generate dummy DLLs

* `ForceIl2CppVersion`, `ForceVersion`
  * If `ForceIl2CppVersion` is `true`, the program will use the version number specified in `ForceVersion` to choose parser for il2cpp binaries (does not affect the choice of metadata parser). This may be useful on some older il2cpp version (e.g. the program may need to use v16 parser on ilcpp v20 (Android) binaries in order to work properly)

## Common errors

#### `ERROR: Metadata file supplied is not valid metadata file.`  

The specified `global-metadata.dat` is invalid and the program cannot recognize it. Make sure you choose the correct file. Sometimes games may obfuscate this file for content protection purposes and so on. Deobfuscating of such files is beyond the scope of this program, so please **DO NOT** file an issue regarding to deobfuscating.

#### `ERROR: Can't use this mode to process file, try another mode.`

Try other extraction modes.

If all automated extraction modes failed with this error and you are sure that the files you supplied are not corrupted/obfuscated, please file an issue with the logs and sample files.

## Tutorial by Cesar
https://www.unknowncheats.me/forum/general-programming-and-reversing/355005-il2cppdumper-tutorial-finding-coderegistration-metadataregistration.html#post2573336

His git: https://github.com/morelli690/
