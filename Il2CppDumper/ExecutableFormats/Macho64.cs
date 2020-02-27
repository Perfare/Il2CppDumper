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
        private List<MachoSection64Bit> sections = new List<MachoSection64Bit>();
        private static readonly byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static readonly byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0
        private ulong vmaddr;

        public Macho64(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            Position += 16; //skip magic, cputype, cpusubtype, filetype
            var ncmds = ReadUInt32();
            Position += 12; //skip sizeofcmds, flags, reserved
            for (var i = 0; i < ncmds; i++)
            {
                var pos = Position;
                var cmd = ReadUInt32();
                var cmdsize = ReadUInt32();
                if (cmd == 0x19) //LC_SEGMENT_64
                {
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
                        section.end = section.addr + section.size;
                        Position += 12; //skip reserved1, reserved2, reserved3
                    }
                }
                Position = pos + cmdsize;//skip
            }
        }

        public override ulong MapVATR(ulong uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.addr && uiAddr <= x.end);
            return uiAddr - (section.addr - section.offset);
        }

        public override bool Search()
        {
            if (Version < 23)
            {
                var __mod_init_func = sections.First(x => x.sectname == "__mod_init_func");
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, (long)__mod_init_func.size / 8);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        Position = MapVATR(i);
                        var buff = ReadBytes(4);
                        if (FeatureBytes1.SequenceEqual(buff))
                        {
                            buff = ReadBytes(4);
                            if (FeatureBytes2.SequenceEqual(buff))
                            {
                                Position += 8;
                                var subaddr = DecodeAdr(i + 16, ReadBytes(4));
                                var rsubaddr = MapVATR(subaddr);
                                Position = rsubaddr;
                                var codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                                codeRegistration += DecodeAdd(ReadBytes(4));
                                Position = rsubaddr + 8;
                                var metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                                metadataRegistration += DecodeAdd(ReadBytes(4));
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
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
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, (long)__mod_init_func.size / 8);
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
                                var codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                                codeRegistration += DecodeAdd(ReadBytes(4));
                                Position = rsubaddr + 8;
                                var metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                                metadataRegistration += DecodeAdd(ReadBytes(4));
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
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
                var addrs = ReadClassArray<ulong>(__mod_init_func.offset, (long)__mod_init_func.size / 8);
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
                                var codeRegistration = DecodeAdrp(subaddr, ReadBytes(4));
                                codeRegistration += DecodeAdd(ReadBytes(4));
                                Position = rsubaddr + 8;
                                var metadataRegistration = DecodeAdrp(subaddr + 8, ReadBytes(4));
                                metadataRegistration += DecodeAdd(ReadBytes(4));
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var data = sections.Where(x => x.sectname == "__const" || x.sectname == "__cstring" || x.sectname == "__data").ToArray();
            var code = sections.Where(x => x.flags == 0x80000400).ToArray();
            var bss = sections.Where(x => x.flags == 1u).ToArray();

            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            plusSearch.SetSection(SearchSectionType.Exec, code);
            plusSearch.SetSection(SearchSectionType.Data, data);
            plusSearch.SetSection(SearchSectionType.Bss, bss);
            var codeRegistration = plusSearch.FindCodeRegistration();
            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            return pointer - vmaddr;
        }
    }
}
