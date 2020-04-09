using System;
using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssemblyMemory : Il2Cpp
    {
        public WebAssemblyMemory(Stream stream, bool is32Bit) : base(stream)
        {
            Is32Bit = is32Bit;
        }

        public override ulong MapVATR(ulong addr)
        {
            return addr;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            return false;
        }

        public override bool Search()
        {
            return false;
        }

        public override bool SymbolSearch()
        {
            return false;
        }
    }
}
