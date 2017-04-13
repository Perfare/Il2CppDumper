using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper._64bit
{
    public class MachoSection
    {
        public string section_name;
        public ulong address;
        public ulong size;
        public ulong offset;
        public ulong end;
    }

    public class Fat
    {
        public ulong file_offset;
        public ulong size;
        public ulong magic;
    }
}
