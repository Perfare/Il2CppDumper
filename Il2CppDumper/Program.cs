using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading;
// Add WinForms reference for dialogs

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            // Ensure STAThread for WinForms dialogs
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
            {
                var thread = new Thread(() => Main(args));
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
                thread.Join();
                return;
            }

            config = JsonSerializer.Deserialize<Config>(
                File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json")));

            string il2cppPath = null;
            string metadataPath = null;
            string outputDir = null;

            // ─────────────── simple flag parser ───────────────
            var it = ((IEnumerable<string>)args).GetEnumerator();
            while (it.MoveNext())
            {
                var arg = it.Current;
                switch (arg)
                {
                    case "-h": case "--help": ShowHelp(); return;
                    case "-i":
                    case "--input":
                        if (!it.MoveNext()) { ShowHelp(); return; }
                        il2cppPath = it.Current; break;
                    case "-m":
                    case "--meta":
                        if (!it.MoveNext()) { ShowHelp(); return; }
                        metadataPath = it.Current; break;
                    case "-o":
                    case "--output":
                        if (!it.MoveNext()) { ShowHelp(); return; }
                        outputDir = it.Current; break;
                    default:
                        Console.WriteLine($"Unknown arg: {arg}"); ShowHelp(); return;
                }
            }
            // ─────────────────────────────────────────────────

            // GUI fall-backs
            if (il2cppPath == null)
            {
                var ofd = new OpenFileDialog { Filter = "Il2Cpp binary|*.*" };
                if (!ofd.ShowDialog()) return;
                il2cppPath = ofd.FileName;
            }
            if (metadataPath == null)
            {
                var ofd = new OpenFileDialog { Filter = "global-metadata.dat|global-metadata.dat" };
                if (!ofd.ShowDialog()) return;
                metadataPath = ofd.FileName;
            }
            if (outputDir == null)
            {
                var fbd = new FolderBrowserDialog { Description = "Select output folder" };
                if (!fbd.ShowDialog()) return;
                outputDir = fbd.SelectedPath + Path.DirectorySeparatorChar;
            }

            // ensure absolute + trailing slash
            outputDir = Path.GetFullPath(outputDir) + Path.DirectorySeparatorChar;

            try
            {
                if (Init(il2cppPath, metadataPath, out var metadata, out var il2Cpp))
                    Dump(metadata, il2Cpp, outputDir);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            if (config.RequireAnyKey)
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Il2CppDumper - Unity il2cpp reverse engineering tool\n");
            Console.WriteLine("Usage:");
            Console.WriteLine($"  {AppDomain.CurrentDomain.FriendlyName} -i <il2cpp-binary> -m <global-metadata> -o <output-directory>");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -h, --help           Show this help message and exit");
            Console.WriteLine("  -i, --input          Path to il2cpp binary file");
            Console.WriteLine("  -m, --meta           Path to global-metadata.dat file");
            Console.WriteLine("  -o, --output         Output directory");
            Console.WriteLine();
            Console.WriteLine("If no arguments are provided, GUI dialogs will be shown.");
            if (config.RequireAnyKey)
            {
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey(true);
            }
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
            il2Cpp.SetProperties(version, metadata.metadataUsagesCount);
            Console.WriteLine($"Il2Cpp Version: {il2Cpp.Version}");
            if (config.ForceDump || il2Cpp.CheckDump())
            {
                if (il2Cpp is ElfBase elf)
                {
                    Console.WriteLine("Detected this may be a dump file.");
                    Console.WriteLine("Input il2cpp dump address or input 0 to force continue:");
                    var DumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                    if (DumpAddr != 0)
                    {
                        il2Cpp.ImageBase = DumpAddr;
                        il2Cpp.IsDumped = true;
                        if (!config.NoRedirectedPointer)
                        {
                            elf.Reload();
                        }
                    }
                }
                else
                {
                    il2Cpp.IsDumped = true;
                }
            }

            Console.WriteLine("Searching...");
            try
            {
                var flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (!flag && il2Cpp is PE)
                    {
                        Console.WriteLine("Use custom PE loader");
                        il2Cpp = PELoader.Load(il2cppPath);
                        il2Cpp.SetProperties(version, metadata.metadataUsagesCount);
                        flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
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
                }
                if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
                {
                    var typeDef = metadata.typeDefs[0];
                    var il2CppType = il2Cpp.types[typeDef.byvalTypeIndex];
                    metadata.ImageBase = il2CppType.data.typeHandle - metadata.header.typeDefinitionsOffset;
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
            if (config.GenerateStruct)
            {
                Console.WriteLine("Generate struct...");
                var scriptGenerator = new StructGenerator(executor);
                scriptGenerator.WriteScript(outputDir);
                Console.WriteLine("Done!");
            }
            if (config.GenerateDummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
                DummyAssemblyExporter.Export(executor, outputDir, config.DummyDllAddToken);
                Console.WriteLine("Done!");
            }
        }
    }
}
