using System.IO;

namespace Il2CppDumper
{
    public static class DummyAssemblyExporter
    {
        public static void Export(Il2CppExecutor il2CppExecutor, string outputDir, Config config)
        {
            Directory.SetCurrentDirectory(outputDir);
            if (Directory.Exists("DummyDll"))
                Directory.Delete("DummyDll", true);
            Directory.CreateDirectory("DummyDll");
            Directory.SetCurrentDirectory("DummyDll");
            var dummy = new DummyAssemblyGenerator(il2CppExecutor, config);
            foreach (var assembly in dummy.Assemblies)
            {
                using var stream = new MemoryStream();
                assembly.Write(stream);
                File.WriteAllBytes(assembly.MainModule.Name, stream.ToArray());
            }
        }
    }
}
