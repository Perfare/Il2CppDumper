using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmHelper;

namespace Il2CppDumper
{
    public sealed class Macho : Il2Cpp
    {
        private List<MachoSection> sections = new List<MachoSection>();
        private static byte[] FeatureBytes1 = { 0x0, 0x22 };//MOVS R2, #0
        private static byte[] FeatureBytes2 = { 0x78, 0x44, 0x79, 0x44 };//ADD R0, PC and ADD R1, PC


        public Macho(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            Position += 16;//skip
            var ncmds = ReadUInt32();
            Position += 8;//skip
            for (var i = 0; i < ncmds; i++)
            {
                var offset = Position;
                var loadCommandType = ReadUInt32();
                var command_size = ReadUInt32();
                if (loadCommandType == 1) //SEGMENT
                {
                    var segment_name = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                    if (segment_name == "__TEXT" || segment_name == "__DATA")
                    {
                        Position += 24;//skip
                        var number_of_sections = ReadUInt32();
                        Position += 4;//skip
                        for (var j = 0; j < number_of_sections; j++)
                        {
                            var section_name = Encoding.UTF8.GetString(ReadBytes(16)).TrimEnd('\0');
                            Position += 16;
                            var address = ReadUInt32();
                            var size = ReadUInt32();
                            var offset2 = ReadUInt32();
                            var end = address + size;
                            sections.Add(new MachoSection { section_name = section_name, address = address, size = size, offset = offset2, end = end });
                            Position += 24;
                        }
                    }
                }
                Position = offset + command_size;//skip
            }
        }

        public override void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            base.Init(codeRegistration, metadataRegistration);
            methodPointers = methodPointers.Select(x => x - 1).ToArray();
            customAttributeGenerators = customAttributeGenerators.Select(x => x - 1).ToArray();
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.address && uiAddr <= x.end);
            return uiAddr - (section.address - section.offset);
        }

        public override bool Search()
        {
            if (version < 21)
            {
                var __mod_init_func = sections.First(x => x.section_name == "__mod_init_func");
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
                var __mod_init_func = sections.First(x => x.section_name == "__mod_init_func");
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

        public override bool AdvancedSearch(int methodCount)
        {
            var __const = sections.First(x => x.section_name == "__const");
            var __const2 = sections.Last(x => x.section_name == "__const");
            var __text = sections.First(x => x.section_name == "__text");
            var __common = sections.First(x => x.section_name == "__common");
            uint codeRegistration = 0;
            uint metadataRegistration = 0;
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
                codeRegistration -= 8u;
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
                codeRegistration -= 8u;
                metadataRegistration -= 64u;
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
        }

        private uint FindPointersAsc(long readCount, MachoSection search, MachoSection range)
        {
            var add = 0;
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            while (search.offset + add < searchend)
            {
                var temp = ReadClassArray<int>(search.offset + add, readCount);
                var r = Array.FindLastIndex(temp, x => x < range.address || x > rangeend);
                if (r != -1)
                {
                    add += ++r * 4;
                }
                else
                {
                    return search.address + (uint)add; //VirtualAddress
                }
            }
            return 0;
        }

        private uint FindPointersDesc(long readCount, MachoSection search, MachoSection range)
        {
            var add = 0;
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            while (searchend + add > search.offset)
            {
                var temp = ReadClassArray<int>(searchend + add - 4 * readCount, readCount);
                var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                if (r != -1)
                {
                    add -= (int)((readCount - r) * 4);
                }
                else
                {
                    return (uint)(search.address + search.size + add - 4 * readCount); //VirtualAddress
                }
            }
            return 0;
        }

        private uint FindReference(uint pointer, MachoSection search)
        {
            var searchend = search.offset + search.size;
            Position = search.offset;
            while (Position < searchend)
            {
                if (ReadUInt32() == pointer)
                {
                    return (uint)Position - search.offset + search.address; //VirtualAddress
                }
            }
            return 0;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var __const = sections.First(x => x.section_name == "__const");
            var __const2 = sections.Last(x => x.section_name == "__const");
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

        private uint FindCodeRegistration(int count, MachoSection search, MachoSection search2, MachoSection range)
        {
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            var search2end = search2 == null ? 0 : search2.offset + search2.size;
            Position = search.offset;
            while (Position < searchend)
            {
                var add = Position;
                if (ReadUInt32() == count)
                {
                    try
                    {
                        uint pointers = MapVATR(ReadUInt32());
                        if (pointers >= search.offset && pointers <= searchend)
                        {
                            var np = Position;
                            var temp = ReadClassArray<uint>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - search.offset + search.address; //VirtualAddress
                            }
                            Position = np;
                        }
                        else if (search2 != null && pointers >= search2.offset && pointers <= search2end)
                        {
                            var np = Position;
                            var temp = ReadClassArray<uint>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - search.offset + search.address; //VirtualAddress
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

        private uint FindMetadataRegistration(int typeDefinitionsCount, MachoSection search, MachoSection search2, MachoSection range)
        {
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            var search2end = search2 == null ? 0 : search2.offset + search2.size;
            Position = search.offset;
            while (Position < searchend)
            {
                var add = Position;
                if (ReadUInt32() == typeDefinitionsCount)
                {
                    try
                    {
                        var np = Position;
                        Position += 8;
                        uint pointers = MapVATR(ReadUInt32());
                        if (pointers >= search.offset && pointers <= searchend)
                        {
                            var temp = ReadClassArray<uint>(pointers, maxMetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - 48u - search.offset + search.address; //VirtualAddress
                            }
                        }
                        else if (search2 != null && pointers >= search2.offset && pointers <= search2end)
                        {
                            var temp = ReadClassArray<uint>(pointers, maxMetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - 48u - search.offset + search.address; //VirtualAddress
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
