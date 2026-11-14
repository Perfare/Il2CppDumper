Run the binary format regression checks with .NET 8:

```powershell
dotnet run --project tests/Il2CppDumper.RegressionTests -c Release
```

The fixtures cover packed v108 RGCTX entries, 1/2/4-byte generic method and invoker indices (with and without adjustor thunks), invalid section boundaries/counts, v39 assembly records with optional module tokens, and version-dependent index decoding. They contain no game data and need no test-framework packages.

ELF64 fixtures also exercise Android APS2 RELA through the actual loader: ARM64 and x86-64, all supported grouping flags, signed deltas, addend carry/reset, ordinary and packed tables in one file, symbol resolution, unresolved imports, memory-dump reloads, and malformed streams/table ranges/targets. File offsets deliberately differ from virtual addresses. `JNI_OnLoad` alone must not produce a protection warning.

An optional path to the original v108 “百万金币” metadata enables sample-specific checks:

```powershell
dotnet run --project tests/Il2CppDumper.RegressionTests -c Release -- "path/to/global-metadata.dat"
```

Empty-header checks for other versions only exercise section handling; they do not establish full game compatibility for those versions.
