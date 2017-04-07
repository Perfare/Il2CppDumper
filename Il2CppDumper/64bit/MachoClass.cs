using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
#pragma warning disable CS0649
namespace Il2CppDumper._64bit
{
    class MachoSection
    {
        public string section_name;
        public ulong address;
        public ulong size;
        public ulong offset;
        public ulong end;
    }

    class Fat
    {
        public ulong file_offset;
        public ulong size;
        public ulong magic;
    }
}
