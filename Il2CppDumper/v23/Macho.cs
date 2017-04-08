using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.ArmHelper;

namespace Il2CppDumper.v23
{
    class Macho : Il2Cpp
    {
        private List<MachoSection> sections = new List<MachoSection>();
        private static byte[] FeatureBytes1 = { 0x0, 0x22 };//MOVS R2, #0
        private static byte[] FeatureBytes2 = { 0x78, 0x44, 0x79, 0x44 };//ADD R0, PC and ADD R1, PC


        public Macho(Stream stream) : base(stream)
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
                            sections.Add(new MachoSection() { section_name = section_name, address = address, size = size, offset = offset2, end = end });
                            Position += 24;
                        }
                    }
                }
                Position = offset + command_size;//skip
            }
        }

        public Macho(Stream stream, uint codeRegistration, uint metadataRegistration) : this(stream)
        {
            Init(codeRegistration, metadataRegistration);
        }

        public override uint MapVATR(uint uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.address && uiAddr <= x.end);
            return uiAddr - (section.address - section.offset);
        }

        public override bool Auto()
        {
            var __mod_init_func = sections.First(x => x.section_name == "__mod_init_func");
            var addrs = ReadClassArray<uint>(__mod_init_func.offset, (int)__mod_init_func.size / 4);
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
                            var subaddr = decodeMov(ReadBytes(8)) + i + 24u - 1u;
                            var rsubaddr = MapVATR(subaddr);
                            Position = rsubaddr;
                            var ptr = decodeMov(ReadBytes(8)) + subaddr + 16u;
                            Position = MapVATR(ptr);
                            var metadataRegistration = ReadUInt32();
                            Position = rsubaddr + 8;
                            buff = ReadBytes(4);
                            Position = rsubaddr + 14;
                            buff = buff.Concat(ReadBytes(4)).ToArray();
                            var codeRegistration = decodeMov(buff) + subaddr + 26u;
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
}
