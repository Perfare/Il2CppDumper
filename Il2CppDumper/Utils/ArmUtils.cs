using System;

namespace Il2CppDumper
{
    static class ArmUtils
    {
        public static uint DecodeMov(byte[] asm)
        {
            var low = (ushort)(asm[2] + ((asm[3] & 0x70) << 4) + ((asm[1] & 0x04) << 9) + ((asm[0] & 0x0f) << 12));
            var high = (ushort)(asm[6] + ((asm[7] & 0x70) << 4) + ((asm[5] & 0x04) << 9) + ((asm[4] & 0x0f) << 12));
            return (uint)((high << 16) + low);
        }

        public static ulong DecodeAdr(ulong pc, byte[] label)
        {
            var bin = label.HexToBin();
            var uint64 = new string(bin[16], 44) + bin.Substring(17, 7) + bin.Substring(8, 8) + bin.Substring(0, 3) + bin.Substring(25, 2);
            return pc + Convert.ToUInt64(uint64, 2);
        }

        public static ulong DecodeAdrp(ulong pc, byte[] label)
        {
            pc &= 0xFFFFFFFFFFFFF000;
            var bin = label.HexToBin();
            var uint64 = new string(bin[16], 32) + bin.Substring(17, 7) + bin.Substring(8, 8) + bin.Substring(0, 3) + bin.Substring(25, 2) + new string('0', 12);
            return pc + Convert.ToUInt64(uint64, 2);
        }

        public static ulong DecodeAdd(byte[] ins)
        {
            var bin = ins.HexToBin();
            var uint64 = Convert.ToUInt64(bin.Substring(18, 6) + bin.Substring(8, 6), 2);
            if (bin[17] == '1')
                uint64 <<= 12;
            return uint64;
        }
    }
}
