using System;
using System.IO;
using System.Text;

namespace Il2CppDumper
{
    public static class BinaryReaderExtensions
    {
        public static string ReadString(this BinaryReader reader, int numChars)
        {
            var start = reader.BaseStream.Position;
            // UTF8 takes up to 4 bytes per character
            var str = Encoding.UTF8.GetString(reader.ReadBytes(numChars * 4))[..numChars];
            // make our position what it would have been if we'd known the exact number of bytes needed.
            reader.BaseStream.Position = start;
            reader.ReadBytes(Encoding.UTF8.GetByteCount(str));
            return str;
        }

        public static uint ReadULeb128(this BinaryReader reader)
        {
            uint value = reader.ReadByte();
            if (value >= 0x80)
            {
                var bitshift = 0;
                value &= 0x7f;
                while (true)
                {
                    var b = reader.ReadByte();
                    bitshift += 7;
                    value |= (uint)((b & 0x7f) << bitshift);
                    if (b < 0x80)
                        break;
                }
            }
            return value;
        }

        public static uint ReadCompressedUInt32(this BinaryReader reader)
        {
            uint val;
            var read = reader.ReadByte();

            if ((read & 0x80) == 0)
            {
                // 1 byte written
                val = read;
            }
            else if ((read & 0xC0) == 0x80)
            {
                // 2 bytes written
                val = (read & ~0x80u) << 8;
                val |= reader.ReadByte();
            }
            else if ((read & 0xE0) == 0xC0)
            {
                // 4 bytes written
                val = (read & ~0xC0u) << 24;
                val |= ((uint)reader.ReadByte() << 16);
                val |= ((uint)reader.ReadByte() << 8);
                val |= reader.ReadByte();
            }
            else if (read == 0xF0)
            {
                // 5 bytes written, we had a really large int32!
                val = reader.ReadUInt32();
            }
            else if (read == 0xFE)
            {
                // Special encoding for Int32.MaxValue
                val = uint.MaxValue - 1;
            }
            else if (read == 0xFF)
            {
                // Yes we treat UInt32.MaxValue (and Int32.MinValue, see ReadCompressedInt32) specially
                val = uint.MaxValue;
            }
            else
            {
                throw new Exception("Invalid compressed integer format");
            }

            return val;
        }

        public static int ReadCompressedInt32(this BinaryReader reader)
        {
            var encoded = reader.ReadCompressedUInt32();

            // -UINT32_MAX can't be represted safely in an int32_t, so we treat it specially
            if (encoded == uint.MaxValue)
                return int.MinValue;

            bool isNegative = (encoded & 1) != 0;
            encoded >>= 1;
            if (isNegative)
                return -(int)(encoded + 1);
            return (int)encoded;
        }
    }
}
