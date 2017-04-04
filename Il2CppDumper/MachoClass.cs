using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class MachoSection
    {
        public string section_name;
        public uint address;
        public uint size;
        public uint offset;
        public uint end;
    }

    class Fat
    {
        public uint file_offset;
        public uint size;
        public uint magic;
    }
}
