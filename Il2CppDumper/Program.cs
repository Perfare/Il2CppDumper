using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Newtonsoft.Json;
using static Il2CppDumper.DefineConstants;

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
            if (args.Length > 4)
            {
                ShowHelp();
                return;
            }
            if (args.Length > 3)
            {
                mode = int.Parse(args[3]);
            }
            if (args.Length > 2)
            {
                stringVersion = args[2];
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
            Console.WriteLine($"usage: {AppDomain.CurrentDomain.FriendlyName} <executable-file> <global-metadata> [unityVersion] [mode]");
            Application.ExitThread();
        }

        private static bool Init(byte[] il2cppBytes, byte[] metadataBytes, string stringVersion, int mode, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            var sanity = BitConverter.ToUInt32(metadataBytes, 0);
            if (sanity != 0xFAB11BAF)
            {
                throw new Exception("ERROR: Metadata file supplied is not valid metadata file.");
            }
            float fixedMetadataVersion;
            var metadataVersion = BitConverter.ToInt32(metadataBytes, 4);
            if (metadataVersion == 24)
            {
                if (stringVersion == null)
                {
                    Console.WriteLine("Input Unity version: ");
                    stringVersion = Console.ReadLine();
                }
                try
                {
                    var versionSplit = Array.ConvertAll(Regex.Replace(stringVersion, @"\D", ".").Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries), int.Parse);
                    var unityVersion = new Version(versionSplit[0], versionSplit[1]);
                    if (unityVersion >= Unity20191)
                    {
                        fixedMetadataVersion = 24.2f;
                    }
                    else if (unityVersion >= Unity20183)
                    {
                        fixedMetadataVersion = 24.1f;
                    }
                    else
                    {
                        fixedMetadataVersion = metadataVersion;
                    }
                }
                catch
                {
                    throw new Exception("You must enter the correct Unity version number");
                }
            }
            else
            {
                fixedMetadataVersion = metadataVersion;
            }
            Console.WriteLine("Initializing metadata...");
            metadata = new Metadata(new MemoryStream(metadataBytes), fixedMetadataVersion);
            //判断il2cpp的magic
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var isElf = false;
            var isPE = false;
            var is64bit = false;
            var isNSO = false;
            switch (il2cppMagic)
            {
                default:
                    throw new Exception("ERROR: il2cpp file not supported.");
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

            var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.version;
            Console.WriteLine("Initializing il2cpp file...");
            if (isNSO)
            {
                var nso = new NSO(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                il2Cpp = nso.UnCompress();
            }
            else if (isPE)
            {
                il2Cpp = new PE(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
            }
            else if (isElf)
            {
                if (is64bit)
                    il2Cpp = new Elf64(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
                else
                    il2Cpp = new Elf(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
            }
            else if (is64bit)
                il2Cpp = new Macho64(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);
            else
                il2Cpp = new Macho(new MemoryStream(il2cppBytes), version, metadata.maxMetadataUsages);

            if (mode == 0)
            {
                Console.WriteLine("Select Mode: 1.Manual 2.Auto 3.Auto(Plus) 4.Auto(Symbol)");
                var modeKey = Console.ReadKey(true);
                mode = int.Parse(modeKey.KeyChar.ToString());
            }
            if (mode != 1)
            {
                Console.WriteLine("Searching...");
            }
            try
            {
                bool flag;
                switch (mode)
                {
                    case 1: //Manual
                        Console.Write("Input CodeRegistration: ");
                        var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                        Console.Write("Input MetadataRegistration: ");
                        var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                        il2Cpp.Init(codeRegistration, metadataRegistration);
                        flag = true;
                        break;
                    case 2: //Auto
                        flag = il2Cpp.Search();
                        break;
                    case 3: //Auto(Plus)
                        flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
                        break;
                    case 4: //Auto(Symbol)
                        flag = il2Cpp.SymbolSearch();
                        break;
                    default:
                        Console.WriteLine("ERROR: You have to choose a mode.");
                        return false;
                }
                if (!flag)
                    throw new Exception();
            }
            catch
            {
                throw new Exception("ERROR: Can't use this mode to process file, try another mode.");
            }
            return true;
        }

        private static void Dump(Metadata metadata, Il2Cpp il2Cpp)
        {
            Console.WriteLine("Dumping...");
            var decompiler = new Il2CppDecompiler(metadata, il2Cpp);
            decompiler.Decompile(config);
            Console.WriteLine("Done!");
            Console.WriteLine("Generate script...");
            var scriptGenerator = new ScriptGenerator(metadata, il2Cpp);
            scriptGenerator.WriteScript(config);
            Console.WriteLine("Done!");
            if (config.DummyDll)
            {
                Console.WriteLine("Generate dummy dll...");
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
                Console.WriteLine("Done!");
            }
        }
    }
}
