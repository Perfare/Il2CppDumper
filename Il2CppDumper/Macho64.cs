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
        private List<MachoSection64bit> sections = new List<MachoSection64bit>();
        private static byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0


        public Macho64(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            Position += 16;//skip
            var ncmds = ReadUInt32();
            Position += 12;//skip
            for (var i = 0; i < ncmds; i++)
            {
                var offset = Position;
                var loadCommandType = ReadUInt32();
                var command_size = ReadUInt32();
                if (loadCommandType == 0x19) //SEGMENT_64
                {
                    var segment_name = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                    if (segment_name == "__TEXT" || segment_name == "__DATA" || segment_name == "__RODATA")
                    {
                        Position += 40;//skip
                        var number_of_sections = ReadUInt32();
                        Position += 4;//skip
                        for (var j = 0; j < number_of_sections; j++)
                        {
                            var section_name = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                            Position += 16;//skip
                            var address = ReadUInt64();
                            var size = ReadUInt64();
                            var offset2 = (uint)ReadUInt64();
                            var end = address + size;
                            sections.Add(new MachoSection64bit { section_name = section_name, address = address, size = size, offset = offset2, end = end });
                            Position += 24;
                        }
                    }
                }
                Position = offset + command_size;//skip
            }
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.address && uiAddr <= x.end);
            return uiAddr - (section.address - section.offset);
        }

        public override bool Search()
        {
            if (version < 23)
            {
                var __mod_init_func = sections.First(x => x.section_name == "__mod_init_func");
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
                return false;
            }
            else
            {
                var __mod_init_func = sections.First(x => x.section_name == "__mod_init_func");
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
                return false;
            }
        }

        public override bool AdvancedSearch(int methodCount)
        {
            var __consts = sections.Where(x => x.section_name == "__const").ToArray();
            var __const = __consts[0];
            var __const2 = __consts[1];
            var __text = sections.First(x => x.section_name == "__text");
            var __common = sections.First(x => x.section_name == "__common");
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

        private ulong FindPointersAsc(long readCount, MachoSection64bit search, MachoSection64bit range)
        {
            var add = 0ul;
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            while (search.offset + add < searchend)
            {
                var temp = ReadClassArray<ulong>(search.offset + add, readCount);
                var r = Array.FindLastIndex(temp, x => x < range.address || x > rangeend);
                if (r != -1)
                {
                    add += (ulong)(++r * 8);
                }
                else
                {
                    return search.address + add; //VirtualAddress
                }
            }
            return 0;
        }

        private ulong FindPointersDesc(long readCount, MachoSection64bit search, MachoSection64bit range)
        {
            var add = 0L;
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            while (searchend + (ulong)add > search.offset)
            {
                var temp = ReadClassArray<ulong>((long)searchend + add - 8 * readCount, readCount);
                var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                if (r != -1)
                {
                    add -= (readCount - r) * 8;
                }
                else
                {
                    return search.address + search.size + (ulong)add - 8ul * (ulong)readCount; //VirtualAddress
                }
            }
            return 0;
        }

        private ulong FindReference(ulong pointer, MachoSection64bit search)
        {
            var searchend = search.offset + search.size;
            Position = search.offset;
            while ((ulong)Position < searchend)
            {
                if (ReadUInt64() == pointer)
                {
                    return (ulong)Position - search.offset + search.address; //VirtualAddress
                }
            }
            return 0;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var __consts = sections.Where(x => x.section_name == "__const").ToArray();
            var __const = __consts[0];
            var __const2 = __consts[1];
            var __text = sections.First(x => x.section_name == "__text");
            var __common = sections.First(x => x.section_name == "__common");
            var codeRegistration = FindCodeRegistration(methodCount, __const, __const2, __text);
            if (codeRegistration == 0)
            {
                codeRegistration = FindCodeRegistration(methodCount, __const2, __const2, __text);
            }
            if (version == 16)
            {
                Console.WriteLine("WARNING: Version 16 can only get CodeRegistration");
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                return false;
            }
            var metadataRegistration = FindMetadataRegistration(typeDefinitionsCount, __const, __const2, __common);
            if (metadataRegistration == 0)
            {
                metadataRegistration = FindMetadataRegistration(typeDefinitionsCount, __const2, __const2, __common);
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

        private ulong FindCodeRegistration(int count, MachoSection64bit search, MachoSection64bit search2, MachoSection64bit range)
        {
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            var search2end = search2 == null ? 0 : search2.offset + search2.size;
            Position = search.offset;
            while ((ulong)Position < searchend)
            {
                var add = Position;
                if (ReadUInt64() == (ulong)count)
                {
                    try
                    {
                        ulong pointers = MapVATR(ReadUInt64());
                        if (pointers >= search.offset && pointers <= searchend)
                        {
                            var np = Position;
                            var temp = ReadClassArray<ulong>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - search.offset + search.address; //VirtualAddress
                            }
                            Position = np;
                        }
                        else if (search2 != null && pointers >= search2.offset && pointers <= search2end)
                        {
                            var np = Position;
                            var temp = ReadClassArray<ulong>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - search.offset + search.address; //VirtualAddress
                            }
                            Position = np;
                        }
                    }
                    catch
                    {
                        // ignored
                    }
                }
            }
            return 0;
        }

        private ulong FindMetadataRegistration(int typeDefinitionsCount, MachoSection64bit search, MachoSection64bit search2, MachoSection64bit range)
        {
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            var search2end = search2 == null ? 0 : search2.offset + search2.size;
            Position = search.offset;
            while ((ulong)Position < searchend)
            {
                var add = Position;
                if (ReadUInt64() == (ulong)typeDefinitionsCount)
                {
                    try
                    {
                        var np = Position;
                        Position += 16;
                        ulong pointers = MapVATR(ReadUInt64());
                        if (pointers >= search.offset && pointers <= searchend)
                        {
                            var temp = ReadClassArray<ulong>(pointers, maxMetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - 96ul - search.offset + search.address; //VirtualAddress
                            }
                        }
                        else if (search2 != null && pointers >= search2.offset && pointers <= search2end)
                        {
                            var temp = ReadClassArray<ulong>(pointers, maxMetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - 96ul - search.offset + search.address; //VirtualAddress
                            }
                        }
                        Position = np;
                    }
                    catch
                    {
                        // ignored
                    }
                }
            }
            return 0;
        }

        public override bool SymbolSearch()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }
    }
}
