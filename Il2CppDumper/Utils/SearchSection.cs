using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public enum SearchSectionType
    {
        Exec,
        Data,
        Bss
    }

    public class SearchSection
    {
        public ulong offset;
        public ulong offsetEnd;
        public ulong address;
        public ulong addressEnd;
    }
}
