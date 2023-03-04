using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmUtils;

namespace Il2CppDumper
{
    public sealed class Macho64 : Il2Cpp
    {
        private static readonly byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static readonly byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0
        private readonly List<MachoSection64Bit> sections = new();
        private readonly ulong vmaddr;

        public Macho64(Stream stream) : base(stream)
        {
            Position += 16; //skip magic, cputype, cpusubtype, filetype
            var ncmds = ReadUInt32();
            Position += 12; //skip sizeofcmds, flags, reserved
            for (var i = 0; i < ncmds; i++)
            {
                var pos = Position;
                var cmd = ReadUInt32();
                var cmdsize = ReadUInt32();
                switch (cmd)
                {
                    case 0x19: //LC_SEGMENT_64
                        var segname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                        if (segname == "__TEXT") //__PAGEZERO
                        {
                            vmaddr = ReadUInt64();
                        }
                        else
                        {
                            Position += 8;
                        }
                        Position += 32; //skip vmsize, fileoff, filesize, maxprot, initprot
                        var nsects = ReadUInt32();
                        Position += 4; //skip flags
                        for (var j = 0; j < nsects; j++)
                        {
                            var section = new MachoSection64Bit();
                            sections.Add(section);
                            section.sectname = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                            Position += 16; //skip segname
                            section.addr = ReadUInt64();
                            section.size = ReadUInt64();
                            section.offset = ReadUInt32();
                            Position += 12; //skip align, reloff, nreloc
                            section.flags = ReadUInt32();
                            Position += 12; //skip reserved1, reserved2, reserved3
                        }
                        break;
                    case 0x2C: //LC_ENCRYPTION_INFO_64
                        Position += 8;
                        var cryptID = ReadUInt32();
                        if (cryptID != 0)
                        {
                            Console.WriteLine("ERROR: This Mach-O executable is encrypted and cannot be processed.");
                        }
                        break;
                }
                Position = pos + cmdsize;//skip
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var section = sections.First(x => addr >= x.addr && addr <= x.addr + x.size);
            if (section.sectname == "__bss")
            {
                throw new Exception();
            }
            return addr - section.addr + section.offset;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var section = sections.FirstOrDefault(x => addr >= x.offset && addr <= x.offset + x.size);
            if (section == null)
            {
                return 0;
            }
            if (section.sectname == "__bss")
            {
                throw new Exception();
            }
            return addr - section.offset + section.addr;
        }

        public override bool Search()
        {
            var codeRegistration = 0ul;
            var metadataRegistration = 0ul;
            if (Version < 23)
            {
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, __mod_init_func.size / 8);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        var flag = false;
                        var subaddr = 0ul;
                        Position = MapVATR(i);
                        var buff = ReadBytes(4);
                        if (FeatureBytes1.SequenceEqual(buff))
                        {
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                Position += 8;
                                var inst = ReadBytes(4);
                                if (IsAdr(inst))
                                {
                                    subaddr = DecodeAdr(i + 16, inst);
                                    flag = true;
                                }
                            }
                        }
                        else
                        {
                            Position += 0xc;
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                buff = ReadBytes(4);
                                if (FeatureBytes1.SequenceEqual(buff))
                                {
                                    Position -= 0x10;
                                    var inst = ReadBytes(4);
                                    if (IsAdr(inst))
                                    {
                                        subaddr = DecodeAdr(i + 8, inst);
                                        flag = true;
                                    }
                                }
                            }
                        }
                        if (flag)
                        {
                            var rsubaddr = MapVATR(subaddr);
                            Position = rsubaddr;
                            codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                            codeRegistration += DecodeAdd(ReadBytes(4));
                            Position = rsubaddr + 8;
                            metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                            metadataRegistration += DecodeAdd(ReadBytes(4));
                        }
                    }
                }
            }
            if (Version == 23)
            {
                /* ADRP X0, unk
                 * ADD X0, X0, unk
                 * ADR X1, sub
                 * NOP
                 * MOV X2, #0
                 * MOV W3, #0
                 * B sub
                 */
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, __mod_init_func.size / 8);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        Position = MapVATR(i) + 16;
                        var buff = ReadBytes(4);
                        if (FeatureBytes1.SequenceEqual(buff))
                        {
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                Position -= 16;
                                var subaddr = DecodeAdr(i + 8, ReadBytes(4));
                                var rsubaddr = MapVATR(subaddr);
                                Position = rsubaddr;
                                codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                                codeRegistration += DecodeAdd(ReadBytes(4));
                                Position = rsubaddr + 8;
                                metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                                metadataRegistration += DecodeAdd(ReadBytes(4));
                            }
                        }
                    }
                }
            }
            if (Version >= 24)
            {
                /* ADRP X0, unk
                 * ADD X0, X0, unk
                 * ADR X1, sub
                 * NOP
                 * MOV W3, #0
                 * MOV X2, #0
                 * B sub
                 */
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, __mod_init_func.size / 8);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        Position = MapVATR(i) + 16;
                        var buff = ReadBytes(4);
                        if (FeatureBytes2.SequenceEqual(buff))
                        {
                            buff = ReadBytes(4);
                            if (FeatureBytes1.SequenceEqual(buff))
                            {
                                Position -= 16;
                                var subaddr = DecodeAdr(i + 8, ReadBytes(4));
                                var rsubaddr = MapVATR(subaddr);
                                Position = rsubaddr;
                                codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                                codeRegistration += DecodeAdd(ReadBytes(4));
                                Position = rsubaddr + 8;
                                metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                                metadataRegistration += DecodeAdd(ReadBytes(4));
                            }
                        }
                    }
                }
            }
            if (codeRegistration != 0 && metadataRegistration != 0)
            {
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
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
            var data = sections.Where(x => x.sectname == "__const" || x.sectname == "__cstring" || x.sectname == "__data").ToArray();
            var code = sections.Where(x => x.flags == 0x80000400).ToArray();
            var bss = sections.Where(x => x.flags == 1u).ToArray();
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, code);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, bss);
            return sectionHelper;
        }

        public override bool CheckDump() => false;

        public override ulong ReadUIntPtr()
        {
            var pointer = ReadUInt64();
            if (pointer > vmaddr + 0xFFFFFFFF)
            {
                var addr = Position;
                var section = sections.First(x => addr >= x.offset && addr <= x.offset + x.size);
                if (section.sectname == "__const" || section.sectname == "__data")
                {
                    var rva = pointer - vmaddr;
                    rva &= 0xFFFFFFFF;
                    pointer = rva + vmaddr;
                }
            }
            return pointer;
        }
    }
}
