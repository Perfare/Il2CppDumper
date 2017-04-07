using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper.v23._64bit
{
    class Macho : Il2Cpp
    {
        private List<MachoSection> sections = new List<MachoSection>();
        private static byte[] FeatureBytes1 = { 0x2, 0x0, 0x80, 0xD2 };//MOV X2, #0
        private static byte[] FeatureBytes2 = { 0x3, 0x0, 0x80, 0x52 };//MOV W3, #0


        public Macho(Stream stream) : base(stream)
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
                            sections.Add(new MachoSection() { section_name = section_name, address = address, size = size, offset = offset2, end = end });
                            Position += 24;
                        }
                    }
                }
                Position = offset + command_size;//skip
            }
        }

        public Macho(Stream stream, ulong codeRegistration, ulong metadataRegistration) : this(stream)
        {
            Init(codeRegistration, metadataRegistration);
        }

        public override ulong MapVATR(ulong uiAddr)
        {
            var section = sections.First(x => uiAddr >= x.address && uiAddr <= x.end);
            return uiAddr - (section.address - section.offset);
        }

        public override bool Auto()
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
                            Init(codeRegistration, metadataRegistration);
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private ulong decodeAdr(ulong pc, byte[] label)
        {
            var bin = "";
            foreach (var b in label)
            {
                var str = Convert.ToString(b, 2);
                if (str.Length < 8)
                {
                    str = new string(Enumerable.Repeat('0', 8 - str.Length).Concat(str.ToCharArray()).ToArray());
                }
                bin += str;
            }
            var uint64 = new string(Enumerable.Repeat(bin[16], 44).ToArray())
                         + bin.Substring(17, 7) + bin.Substring(8, 8) + bin.Substring(0, 3) + bin.Substring(25, 2);
            return pc + Convert.ToUInt64(uint64, 2);
        }

        private ulong decodeAdrp(ulong pc, byte[] label)
        {
            var pcbin = Convert.ToString((long)pc, 2);
            if (pcbin.Length < 64)
            {
                pcbin = new string(Enumerable.Repeat('0', 64 - pcbin.Length).Concat(pcbin.ToCharArray()).ToArray());
            }
            pcbin = pcbin.Substring(0, 52) + new string(Enumerable.Repeat('0', 12).ToArray());
            var bin = "";
            foreach (var b in label)
            {
                var str = Convert.ToString(b, 2);
                if (str.Length < 8)
                {
                    str = new string(Enumerable.Repeat('0', 8 - str.Length).Concat(str.ToCharArray()).ToArray());
                }
                bin += str;
            }
            var uint64 = new string(Enumerable.Repeat(bin[16], 32).ToArray())
                         + bin.Substring(17, 7) + bin.Substring(8, 8) + bin.Substring(0, 3) + bin.Substring(25, 2)
                         + new string(Enumerable.Repeat('0', 12).ToArray());
            return Convert.ToUInt64(pcbin, 2) + Convert.ToUInt64(uint64, 2);
        }

        private ulong decodeAdd(byte[] ins)
        {
            throw new NotSupportedException("尚未完工");
        }
    }
}
