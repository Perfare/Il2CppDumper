using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Newtonsoft.Json;

namespace Il2CppDumper
{
    class Program
    {
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(Application.StartupPath + Path.DirectorySeparatorChar + @"config.json"));
            byte[] il2cppBytes = null;
            byte[] metadataBytes = null;
            string stringVersion = null;
            int mode = 0;

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
            if (args.Length > 2)
            {
                mode = int.Parse(args[2]);
            }
            if (args.Length > 1)
            {
                var file1 = File.ReadAllBytes(args[0]);
                var file2 = File.ReadAllBytes(args[1]);
                if (BitConverter.ToUInt32(file1, 0) == 0xFAB11BAF)
                {
                    il2cppBytes = file2;
                    metadataBytes = file1;
                }
                else if (BitConverter.ToUInt32(file2, 0) == 0xFAB11BAF)
                {
                    il2cppBytes = file1;
                    metadataBytes = file2;
                }
            }
            if (il2cppBytes == null)
            {
                var ofd = new OpenFileDialog();
                ofd.Filter = "Il2Cpp binary file|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    il2cppBytes = File.ReadAllBytes(ofd.FileName);
                    ofd.Filter = "global-metadata|global-metadata.dat";
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        metadataBytes = File.ReadAllBytes(ofd.FileName);
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
            try
            {
                if (Init(il2cppBytes, metadataBytes, stringVersion, mode, out var metadata, out var il2Cpp))
                {
                    Dump(metadata, il2Cpp);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey(true);
        }

        static void ShowHelp()
        {
            Console.WriteLine($"usage: {AppDomain.CurrentDomain.FriendlyName} <executable-file> <global-metadata> [mode]");
            Application.ExitThread();
        }

        private static bool Init(byte[] il2cppBytes, byte[] metadataBytes, string stringVersion, int mode, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            var sanity = BitConverter.ToUInt32(metadataBytes, 0);
            if (sanity != 0xFAB11BAF)
            {
                throw new InvalidDataException("ERROR: Metadata file supplied is not valid metadata file.");
            }
            Console.WriteLine("Initializing metadata...");
            metadata = new Metadata(new MemoryStream(metadataBytes));
            Console.WriteLine($"Metadata Version: {metadata.Version}");
            //判断il2cpp的magic
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var isElf = false;
            var isPE = false;
            var is64bit = false;
            var isNSO = false;
            switch (il2cppMagic)
            {
                default:
                    throw new NotSupportedException("ERROR: il2cpp file not supported.");
                case 0x304F534E:
                    isNSO = true;
                    is64bit = true;
                    break;
                case 0x905A4D: //PE
                    isPE = true;
                    break;
                case 0x464c457f: //ELF
                    isElf = true;
                    if (il2cppBytes[4] == 2) //ELF64
                    {
                        is64bit = true;
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
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    is64bit = true;
                    break;
                case 0xFEEDFACE: // 32bit Mach-O
                    break;
            }

            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.Version;
            Console.WriteLine("Initializing il2cpp file...");
            var il2CppMemory = new MemoryStream(il2cppBytes);
            if (isNSO)
            {
                var nso = new NSO(il2CppMemory, version, metadata.maxMetadataUsages);
                il2Cpp = nso.UnCompress();
            }
            else if (isPE)
            {
                il2Cpp = new PE(il2CppMemory, version, metadata.maxMetadataUsages);
            }
            else if (isElf)
            {
                if (is64bit)
                    il2Cpp = new Elf64(il2CppMemory, version, metadata.maxMetadataUsages);
                else
                    il2Cpp = new Elf(il2CppMemory, version, metadata.maxMetadataUsages);
            }
            else if (is64bit)
                il2Cpp = new Macho64(il2CppMemory, version, metadata.maxMetadataUsages);
            else
                il2Cpp = new Macho(il2CppMemory, version, metadata.maxMetadataUsages);

            if (mode == 0)
            {
                Console.WriteLine("Select Mode: 1.Manual 2.Auto");
                var modeKey = Console.ReadKey(true);
                mode = int.Parse(modeKey.KeyChar.ToString());
            }
            try
            {
                if (mode == 1)
                {
                    Console.Write("Input CodeRegistration: ");
                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    Console.Write("Input MetadataRegistration: ");
                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    il2Cpp.Init(codeRegistration, metadataRegistration);
                    return true;
                }
                else if (mode == 2)
                {
                    Console.WriteLine("Searching...");
                    var flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
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
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("ERROR: You have to choose a mode.");
                    return false;
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

        private static void Dump(Metadata metadata, Il2Cpp il2Cpp)
        {
            Console.WriteLine("Dumping...");
            var executor = new Il2CppExecutor(metadata, il2Cpp);
            var decompiler = new Il2CppDecompiler(executor);
            decompiler.Decompile(config);
            Console.WriteLine("Done!");
            Console.WriteLine("Generate script...");
            var scriptGenerator = new ScriptGenerator(executor);
            scriptGenerator.WriteScript(config);
            Console.WriteLine("Done!");
            if (config.DummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
                DummyAssemblyExporter.Export(metadata, il2Cpp);
                Console.WriteLine("Done!");
            }
        }
    }
}
