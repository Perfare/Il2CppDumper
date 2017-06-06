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
            Search = Searchv16_23;
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

        private bool Searchv16_23()
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
    }
}
