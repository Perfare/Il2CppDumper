using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmHelper;

namespace Il2CppDumper
{
    public sealed class Macho64 : Il2Cpp
    {
        private List<MachoSection64Bit> sections = new List<MachoSection64Bit>();
        private static readonly byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static readonly byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0


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
                    Position += 56; //skip segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot
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

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.addr && uiAddr <= x.end);
            return uiAddr - (section.addr - section.offset);
        }

        public override bool Search()
        {
            if (version < 23)
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
            if (version == 23)
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
            if (version >= 24)
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

        public override bool AdvancedSearch(int methodCount)
        {
            var __consts = sections.Where(x => x.sectname == "__const").ToArray();
            var __const = __consts[0];
            var __const2 = __consts[1];
            var __text = sections.First(x => x.sectname == "__text");
            var __common = sections.First(x => x.sectname == "__common");
            ulong codeRegistration = 0;
            ulong metadataRegistration = 0;
            var pmethodPointers = FindPointersAsc(methodCount, __const, __text);
            if (pmethodPointers == 0)
                pmethodPointers = FindPointersAsc(methodCount, __const2, __text);
            if (pmethodPointers != 0)
            {
                codeRegistration = FindReference(pmethodPointers, __const);
                if (codeRegistration == 0)
                    codeRegistration = FindReference(pmethodPointers, __const2);
                if (codeRegistration == 0)
                {
                    pmethodPointers = FindPointersDesc(methodCount, __const, __text);
                    if (pmethodPointers == 0)
                        pmethodPointers = FindPointersDesc(methodCount, __const2, __text);
                    if (pmethodPointers != 0)
                    {
                        codeRegistration = FindReference(pmethodPointers, __const);
                        if (codeRegistration == 0)
                            codeRegistration = FindReference(pmethodPointers, __const2);
                    }
                }
            }
            if (version == 16)
            {
                codeRegistration -= 16ul;
                Console.WriteLine("WARNING: Version 16 can only get CodeRegistration");
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                return false;
            }
            var pmetadataUsages = FindPointersAsc(maxMetadataUsages, __const, __common);
            if (pmetadataUsages == 0)
                pmetadataUsages = FindPointersAsc(maxMetadataUsages, __const2, __common);
            if (pmetadataUsages != 0)
            {
                metadataRegistration = FindReference(pmetadataUsages, __const);
                if (metadataRegistration == 0)
                    metadataRegistration = FindReference(pmetadataUsages, __const2);
                if (metadataRegistration == 0)
                {
                    pmetadataUsages = FindPointersDesc(maxMetadataUsages, __const, __common);
                    if (pmetadataUsages == 0)
                        pmetadataUsages = FindPointersDesc(maxMetadataUsages, __const2, __common);
                    if (pmetadataUsages != 0)
                    {
                        metadataRegistration = FindReference(pmetadataUsages, __const);
                        if (metadataRegistration == 0)
                            metadataRegistration = FindReference(pmetadataUsages, __const2);
                    }
                }
            }
            if (codeRegistration != 0 && metadataRegistration != 0)
            {
                codeRegistration -= 16ul;
                metadataRegistration -= 128ul;
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
        }

        private ulong FindPointersAsc(long readCount, MachoSection64Bit search, MachoSection64Bit range)
        {
            var add = 0ul;
            var searchend = search.offset + search.size;
            var rangeend = range.addr + range.size;
            while (search.offset + add < searchend)
            {
                var temp = ReadClassArray<ulong>(search.offset + add, readCount);
                var r = Array.FindLastIndex(temp, x => x < range.addr || x > rangeend);
                if (r != -1)
                {
                    add += (ulong)(++r * 8);
                }
                else
                {
                    return search.addr + add; //VirtualAddress
                }
            }
            return 0;
        }

        private ulong FindPointersDesc(long readCount, MachoSection64Bit search, MachoSection64Bit range)
        {
            var add = 0L;
            var searchend = search.offset + search.size;
            var rangeend = range.addr + range.size;
            while (searchend + (ulong)add > search.offset)
            {
                var temp = ReadClassArray<ulong>((long)searchend + add - 8 * readCount, readCount);
                var r = Array.FindIndex(temp, x => x < range.addr || x > rangeend);
                if (r != -1)
                {
                    add -= (readCount - r) * 8;
                }
                else
                {
                    return search.addr + search.size + (ulong)add - 8ul * (ulong)readCount; //VirtualAddress
                }
            }
            return 0;
        }

        private ulong FindReference(ulong pointer, MachoSection64Bit search)
        {
            var searchend = search.offset + search.size;
            Position = search.offset;
            while ((ulong)Position < searchend)
            {
                if (ReadUInt64() == pointer)
                {
                    return (ulong)Position - search.offset + search.addr; //VirtualAddress
                }
            }
            return 0;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var data = sections.Where(x => x.sectname == "__const").ToArray();
            var code = sections.Where(x => x.flags == 0x80000400).ToArray();
            var bss = sections.Where(x => x.flags == 1u).ToArray();

            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            plusSearch.SetSearch(data);
            plusSearch.SetPointerRangeFirst(data);
            plusSearch.SetPointerRangeSecond(code);
            var codeRegistration = plusSearch.FindCodeRegistration64Bit();
            plusSearch.SetPointerRangeSecond(bss);
            var metadataRegistration = plusSearch.FindMetadataRegistration64Bit();
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }
    }
}
