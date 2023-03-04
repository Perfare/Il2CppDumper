using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmUtils;

namespace Il2CppDumper
{
    public sealed class Macho : Il2Cpp
    {
        private static readonly byte[] FeatureBytes1 = { 0x0, 0x22 };//MOVS R2, #0
        private static readonly byte[] FeatureBytes2 = { 0x78, 0x44, 0x79, 0x44 };//ADD R0, PC and ADD R1, PC
        private readonly List<MachoSection> sections = new();
        private readonly ulong vmaddr;

        public Macho(Stream stream) : base(stream)
        {
            Is32Bit = true;
            Position += 16; //skip magic, cputype, cpusubtype, filetype
            var ncmds = ReadUInt32();
            Position += 8; //skip sizeofcmds, flags
            for (var i = 0; i < ncmds; i++)
            {
                var pos = Position;
                var cmd = ReadUInt32();
                var cmdsize = ReadUInt32();
                switch (cmd)
                {
                    case 1: //LC_SEGMENT
                        var segname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                        if (segname == "__TEXT") //__PAGEZERO
                        {
                            vmaddr = ReadUInt32();
                        }
                        else
                        {
                            Position += 4;
                        }
                        Position += 20; //skip vmsize, fileoff, filesize, maxprot, initprot
                        var nsects = ReadUInt32();
                        Position += 4; //skip flags
                        for (var j = 0; j < nsects; j++)
                        {
                            var section = new MachoSection();
                            sections.Add(section);
                            section.sectname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                            Position += 16; //skip segname
                            section.addr = ReadUInt32();
                            section.size = ReadUInt32();
                            section.offset = ReadUInt32();
                            Position += 12; //skip align, reloff, nreloc
                            section.flags = ReadUInt32();
                            Position += 8; //skip reserved1, reserved2
                        }
                        break;
                    case 0x21: //LC_ENCRYPTION_INFO
                        Position += 8;
                        var cryptID = ReadUInt32();
                        if (cryptID != 0)
                        {
                            Console.WriteLine("ERROR: This Mach-O executable is encrypted and cannot be processed.");
                        }
                        break;
                }
                Position = pos + cmdsize;//next
            }
        }

        public override void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            base.Init(codeRegistration, metadataRegistration);
            methodPointers = methodPointers.Select(x => x - 1).ToArray();
            customAttributeGenerators = customAttributeGenerators.Select(x => x - 1).ToArray();
        }

        public override ulong MapVATR(ulong addr)
        {
            var section = sections.First(x => addr >= x.addr && addr <= x.addr + x.size);
            return addr - section.addr + section.offset;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var section = sections.FirstOrDefault(x => addr >= x.offset && addr <= x.offset + x.size);
            if (section == null)
            {
                return 0;
            }
            return addr - section.offset + section.addr;
        }

        public override bool Search()
        {
            if (Version < 21)
            {
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<uint>(__mod_init_func.offset, __mod_init_func.size / 4u);
                foreach (var a in addrs)
                {
                    if (a > 0)
                    {
                        var i = a - 1;
                        Position = MapVATR(i);
                        Position += 4;
                        var buff = ReadBytes(2);
                        if (FeatureBytes1.SequenceEqual(buff))
                        {
                            Position += 12;
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                Position = MapVATR(i) + 10;
                                var subaddr = DecodeMov(ReadBytes(8)) + i + 24u - 1u;
                                var rsubaddr = MapVATR(subaddr);
                                Position = rsubaddr;
                                var ptr = DecodeMov(ReadBytes(8)) + subaddr + 16u;
                                Position = MapVATR(ptr);
                                var metadataRegistration = ReadUInt32();
                                Position = rsubaddr + 8;
                                buff = ReadBytes(4);
                                Position = rsubaddr + 14;
                                buff = buff.Concat(ReadBytes(4)).ToArray();
                                var codeRegistration = DecodeMov(buff) + subaddr + 22u;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            else
            {
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<uint>(__mod_init_func.offset, __mod_init_func.size / 4u);
                foreach (var a in addrs)
                {
                    if (a > 0)
                    {
                        var i = a - 1;
                        Position = MapVATR(i);
                        Position += 4;
                        var buff = ReadBytes(2);
                        if (FeatureBytes1.SequenceEqual(buff))
                        {
                            Position += 12;
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                Position = MapVATR(i) + 10;
                                var subaddr = DecodeMov(ReadBytes(8)) + i + 24u - 1u;
                                var rsubaddr = MapVATR(subaddr);
                                Position = rsubaddr;
                                var ptr = DecodeMov(ReadBytes(8)) + subaddr + 16u;
                                Position = MapVATR(ptr);
                                var metadataRegistration = ReadUInt32();
                                Position = rsubaddr + 8;
                                buff = ReadBytes(4);
                                Position = rsubaddr + 14;
                                buff = buff.Concat(ReadBytes(4)).ToArray();
                                var codeRegistration = DecodeMov(buff) + subaddr + 26u;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var sectionHelper = GetSectionHelper(methodCount, typeDefinitionsCount, imageCount);
            var codeRegistration = sectionHelper.FindCodeRegistration();
            var metadataRegistration = sectionHelper.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            return pointer - vmaddr;
        }

        public override SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var data = sections.Where(x => x.sectname == "__const").ToArray();
            var code = sections.Where(x => x.flags == 0x80000400).ToArray();
            var bss = sections.Where(x => x.flags == 1u).ToArray();
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, code);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, bss);
            return sectionHelper;
        }

        public override bool CheckDump() => false;
    }
}
