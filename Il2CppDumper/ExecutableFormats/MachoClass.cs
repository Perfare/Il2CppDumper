using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class MachoSection
    {
        public string sectname;
        public uint addr;
        public uint size;
        public uint offset;
        public uint flags;
    }

    public class MachoSection64Bit
    {
        public string sectname;
        public ulong addr;
        public ulong size;
        public ulong offset;
        public uint flags;
    }

    public class Fat
    {
        public uint offset;
        public uint size;
        public uint magic;
    }
}
