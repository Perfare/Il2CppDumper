using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
#if NETFRAMEWORK
using System.Windows.Forms;
#endif

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + @"config.json"));
            string il2cppPath = null;
            string metadataPath = null;
            string outputDir = null;

            if (args.Length == 1)
            {
                if (args[0] == "-h" || args[0] == "--help" || args[0] == "/?" || args[0] == "/h")
                {
                    ShowHelp();
                    return;
                }
            }
            if (args.Length > 3)
            {
                ShowHelp();
                return;
            }
            if (args.Length > 1)
            {
                foreach (var arg in args)
                {
                    if (File.Exists(arg))
                    {
                        var file = File.ReadAllBytes(arg);
                        if (BitConverter.ToUInt32(file, 0) == 0xFAB11BAF)
                        {
                            metadataPath = arg;
                        }
                        else
                        {
                            il2cppPath = arg;
                        }
                    }
                    else if (Directory.Exists(arg))
                    {
                        outputDir = Path.GetFullPath(arg) + Path.DirectorySeparatorChar;
                    }
                }
            }
            if (outputDir == null)
            {
                outputDir = AppDomain.CurrentDomain.BaseDirectory;
            }
#if NETFRAMEWORK
            if (il2cppPath == null)
            {
                var ofd = new OpenFileDialog();
                ofd.Filter = "Il2Cpp binary file|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    il2cppPath = ofd.FileName;
                    ofd.Filter = "global-metadata|global-metadata.dat";
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        metadataPath = ofd.FileName;
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    return;
                }
            }
#endif
            if (il2cppPath == null)
            {
                ShowHelp();
                return;
            }
            try
            {
                if (Init(il2cppPath, metadataPath, out var metadata, out var il2Cpp))
                {
                    Dump(metadata, il2Cpp, outputDir);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            if (config.RequireAnyKey)
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine($"usage: {AppDomain.CurrentDomain.FriendlyName} <executable-file> <global-metadata> <output-directory>");
        }

        private static bool Init(string il2cppPath, string metadataPath, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            Console.WriteLine("Initializing metadata...");
            var metadataBytes = File.ReadAllBytes(metadataPath);
            metadata = new Metadata(new MemoryStream(metadataBytes));
            Console.WriteLine($"Metadata Version: {metadata.Version}");

            Console.WriteLine("Initializing il2cpp file...");
            var il2cppBytes = File.ReadAllBytes(il2cppPath);
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var il2CppMemory = new MemoryStream(il2cppBytes);
            switch (il2cppMagic)
            {
                default:
                    throw new NotSupportedException("ERROR: il2cpp file not supported.");
                case 0x6D736100:
                    var web = new WebAssembly(il2CppMemory);
                    il2Cpp = web.CreateMemory();
                    break;
                case 0x304F534E:
                    var nso = new NSO(il2CppMemory);
                    il2Cpp = nso.UnCompress();
                    break;
                case 0x905A4D: //PE
                    il2Cpp = new PE(il2CppMemory);
                    break;
                case 0x464c457f: //ELF
                    if (il2cppBytes[4] == 2) //ELF64
                    {
                        il2Cpp = new Elf64(il2CppMemory);
                    }
                    else
                    {
                        il2Cpp = new Elf(il2CppMemory);
                    }
                    break;
                case 0xCAFEBABE: //FAT Mach-O
                case 0xBEBAFECA:
                    var machofat = new MachoFat(new MemoryStream(il2cppBytes));
                    Console.Write("Select Platform: ");
                    for (var i = 0; i < machofat.fats.Length; i++)
                    {
                        var fat = machofat.fats[i];
                        Console.Write(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                    }
                    Console.WriteLine();
                    var key = Console.ReadKey(true);
                    var index = int.Parse(key.KeyChar.ToString()) - 1;
                    var magic = machofat.fats[index % 2].magic;
                    il2cppBytes = machofat.GetMacho(index % 2);
                    il2CppMemory = new MemoryStream(il2cppBytes);
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    il2Cpp = new Macho64(il2CppMemory);
                    break;
                case 0xFEEDFACE: // 32bit Mach-O
                    il2Cpp = new Macho(il2CppMemory);
                    break;
            }
            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.Version;
            il2Cpp.SetProperties(version, metadata.maxMetadataUsages);
            Console.WriteLine($"Il2Cpp Version: {il2Cpp.Version}");
            if (il2Cpp.Version >= 27 && il2Cpp is ElfBase elf && elf.IsDumped)
            {
                Console.WriteLine("Input global-metadata.dat dump address:");
                metadata.Address = Convert.ToUInt64(Console.ReadLine(), 16);
            }


            Console.WriteLine("Searching...");
            try
            {
                var flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (!flag && il2Cpp is PE)
                    {
                        Console.WriteLine("Use custom PE loader");
                        il2Cpp = PELoader.Load(il2cppPath);
                        il2Cpp.SetProperties(version, metadata.maxMetadataUsages);
                        flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
                    }
                }
                if (!flag)
                {
                    flag = il2Cpp.Search();
                }
                if (!flag)
                {
                    flag = il2Cpp.SymbolSearch();
                }
                if (!flag)
                {
                    Console.WriteLine("ERROR: Can't use auto mode to process file, try manual mode.");
                    Console.Write("Input CodeRegistration: ");
                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    Console.Write("Input MetadataRegistration: ");
                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    il2Cpp.Init(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine("ERROR: An error occurred while processing.");
                return false;
            }
            return true;
        }

        private static void Dump(Metadata metadata, Il2Cpp il2Cpp, string outputDir)
        {
            Console.WriteLine("Dumping...");
            var executor = new Il2CppExecutor(metadata, il2Cpp);
            var decompiler = new Il2CppDecompiler(executor);
            decompiler.Decompile(config, outputDir);
            Console.WriteLine("Done!");
            if (config.GenerateScript)
            {
                Console.WriteLine("Generate script...");
                var scriptGenerator = new ScriptGenerator(executor);
                scriptGenerator.WriteScript(outputDir);
                Console.WriteLine("Done!");
            }
            if (config.GenerateDummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
                DummyAssemblyExporter.Export(executor, outputDir);
                Console.WriteLine("Done!");
            }
        }
    }
}
