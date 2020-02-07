using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class MachoFat : BinaryStream
    {
        public Fat[] fats;

        public MachoFat(Stream stream) : base(stream)
        {
            //BigEndian
            Position += 4;
            var size = BitConverter.ToInt32(ReadBytes(4).Reverse().ToArray(), 0);
            fats = new Fat[size];
            for (var i = 0; i < size; i++)
            {
                Position += 8;
                fats[i] = new Fat();
                fats[i].offset = BitConverter.ToUInt32(ReadBytes(4).Reverse().ToArray(), 0);
                fats[i].size = BitConverter.ToUInt32(ReadBytes(4).Reverse().ToArray(), 0);
                Position += 4;
            }
            for (var i = 0; i < size; i++)
            {
                Position = fats[i].offset;
                fats[i].magic = ReadUInt32();
            }
        }

        public byte[] GetMacho(int index)
        {
            Position = fats[index].offset;
            return ReadBytes((int)fats[index].size);
        }
    }
}
