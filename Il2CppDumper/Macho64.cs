using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmHelper;

namespace Il2CppDumper
{
    class Macho64 : Il2CppGeneric
    {
        private List<MachoSection64bit> sections = new List<MachoSection64bit>();
        private static byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0


        public Macho64(Stream stream, int version, long maxmetadataUsages) : base(stream)
        {
            this.version = version;
            this.maxmetadataUsages = maxmetadataUsages;
            @namespace = "Il2CppDumper.v" + version + "._64bit.";
            if (version < 23)
                Search = Searchv16_22;
            else
                Search = Searchv23;
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
                    if (segment_name == "__TEXT" || segment_name == "__DATA")
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

        public Macho64(Stream stream, ulong codeRegistration, ulong metadataRegistration, int version, long maxmetadataUsages) : this(stream, version, maxmetadataUsages)
        {
            Init64(codeRegistration, metadataRegistration);
        }

        protected override dynamic MapVATR(dynamic uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.address && uiAddr <= x.end);
            return uiAddr - (section.address - section.offset);
        }

        public override long GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex)
        {
            if (isNew21)
            {
                var ptr = fieldOffsets[typeIndex];
                if (ptr >= 0)
                {
                    Position = MapVATR((ulong)ptr) + 4ul * (ulong)fieldIndexInType;
                    return ReadInt32();
                }
                return 0;
            }
            return fieldOffsets[fieldIndex];
        }

        public override ulong[] GetPointers(ulong pointer, long count)
        {
            var pointers = MapVATR<ulong>(pointer, count);
            return pointers;
        }

        private bool Searchv16_22()
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
                            var subaddr = decodeAdr(i + 16, ReadBytes(4));
                            var rsubaddr = MapVATR(subaddr);
                            Position = rsubaddr;
                            var codeRegistration = decodeAdrp(subaddr, ReadBytes(4));
                            codeRegistration += decodeAdd(ReadBytes(4));
                            Position = rsubaddr + 8;
                            var metadataRegistration = decodeAdrp(subaddr + 8, ReadBytes(4));
                            metadataRegistration += decodeAdd(ReadBytes(4));
                            Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                            Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                            Init64(codeRegistration, metadataRegistration);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private bool Searchv23()
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
                            var subaddr = decodeAdr(i + 8, ReadBytes(4));
                            var rsubaddr = MapVATR(subaddr);
                            Position = rsubaddr;
                            var codeRegistration = decodeAdrp(subaddr, ReadBytes(4));
                            codeRegistration += decodeAdd(ReadBytes(4));
                            Position = rsubaddr + 8;
                            var metadataRegistration = decodeAdrp(subaddr + 8, ReadBytes(4));
                            metadataRegistration += decodeAdd(ReadBytes(4));
                            Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                            Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                            Init64(codeRegistration, metadataRegistration);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public override bool AdvancedSearch(int methodCount)
        {
            var __const = sections.First(x => x.section_name == "__const");
            var __const2 = sections.Last(x => x.section_name == "__const");
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
            var pmetadataUsages = FindPointersAsc(maxmetadataUsages, __const, __common);
            if (pmetadataUsages == 0)
                pmetadataUsages = FindPointersAsc(maxmetadataUsages, __const2, __common);
            if (pmetadataUsages != 0)
            {
                metadataRegistration = FindReference(pmetadataUsages, __const);
                if (metadataRegistration == 0)
                    metadataRegistration = FindReference(pmetadataUsages, __const2);
                if (metadataRegistration == 0)
                {
                    pmetadataUsages = FindPointersDesc(maxmetadataUsages, __const, __common);
                    if (pmetadataUsages == 0)
                        pmetadataUsages = FindPointersDesc(maxmetadataUsages, __const2, __common);
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
                Init64(codeRegistration, metadataRegistration);
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
                    return search.address + add;//MapRATV
                }
            }
            return 0;
        }

        private ulong FindPointersDesc(long readCount, MachoSection64bit search, MachoSection64bit range)
        {
            var add = 0L;
            var searchend = search.offset + search.size;
            var rangeend = range.address + range.size;
            while ((ulong)((long)searchend + add) > search.offset)
            {
                var temp = ReadClassArray<ulong>((long)searchend + add - 8 * readCount, readCount);
                var r = Array.FindIndex(temp, x => x < range.address || x > rangeend);
                if (r != -1)
                {
                    add -= (readCount - r) * 8;
                }
                else
                {
                    return (ulong)((long)search.address + (long)search.size + add - 8L * readCount);//MapRATV
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
                    return (ulong)Position - search.offset + search.address;//MapRATV
                }
            }
            return 0;
        }
    }
}
