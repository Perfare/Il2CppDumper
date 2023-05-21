using System;
using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssembly : BinaryStream
    {
        private readonly DataSection[] dataSections;
        private readonly uint[] funcRefs;

        public WebAssembly(Stream stream) : base(stream)
        {
            Is32Bit = true;
            var magic = ReadUInt32();
            var version = ReadInt32();
            while (Position < Length)
            {
                var id = ReadULeb128();
                var len = ReadULeb128();
                var nextSection = Position + len;

                if (id == 9) // element section
                {
                    // assume these is only one segment and is ref.func.
                    // probably we need to handle another type of segments in future.
                    var segmentCount = ReadULeb128();
                    if (segmentCount == 1)
                    {
                        var flags = ReadULeb128();
                        var opCode = ReadByte();
                        var value = ReadULeb128();
                        var endOpCode = ReadByte();
                        var elemCount = ReadULeb128();
                        if (flags == 0 || opCode == 0x41 || endOpCode == 0xB)
                        {
                            funcRefs = new uint[elemCount + 1];
                            for (int ei = 0; ei < elemCount; ++ei)
                            {
                                funcRefs[ei + 1] = ReadULeb128();
                            }
                        }
                    }
                }
                else if (id == 11) // data section
                {
                    var count = ReadULeb128();
                    dataSections = new DataSection[count];
                    for (int i = 0; i < count; i++)
                    {
                        var dataSection = new DataSection();
                        dataSections[i] = dataSection;
                        dataSection.Index = ReadULeb128();
                        var opCode = ReadByte();
                        if (opCode != 0x41) //i32.const
                        {
                            throw new InvalidOperationException();
                        }
                        dataSection.Offset = ReadULeb128();
                        opCode = ReadByte();
                        if (opCode != 0xB) //end
                        {
                            throw new InvalidOperationException();
                        }
                        dataSection.Data = ReadBytes((int)ReadULeb128());
                    }
                }

                Position = nextSection;
            }
        }

        public WebAssemblyMemory CreateMemory()
        {
            var last = dataSections[^1];
            var bssStart = last.Offset + (uint)last.Data.Length;
            var stream = new MemoryStream(new byte[Length]);
            foreach (var dataSection in dataSections)
            {
                stream.Position = dataSection.Offset;
                stream.Write(dataSection.Data, 0, dataSection.Data.Length);
            }
            return new WebAssemblyMemory(stream, bssStart, funcRefs);
        }
    }
}
