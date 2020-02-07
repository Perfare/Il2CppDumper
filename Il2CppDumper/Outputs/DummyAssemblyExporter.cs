using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppDumper
{
    public static class DummyAssemblyExporter
    {
        public static void Export(Metadata metadata, Il2Cpp il2Cpp)
        {
            if (Directory.Exists("DummyDll"))
                Directory.Delete("DummyDll", true);
            Directory.CreateDirectory("DummyDll");
            Directory.SetCurrentDirectory("DummyDll");
            var dummy = new DummyAssemblyGenerator(metadata, il2Cpp);
            foreach (var assembly in dummy.Assemblies)
            {
                using (var stream = new MemoryStream())
                {
                    assembly.Write(stream);
                    File.WriteAllBytes(assembly.MainModule.Name, stream.ToArray());
                }
            }
        }
    }
}
