using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Il2CppDumper
{
    public sealed class Raw : Il2Cpp
    {
        private ulong baseAddr;
        public Raw(Stream stream, ulong baseAddr, bool is64bit, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            Is32Bit = !is64bit;
            this.baseAddr = baseAddr;
        }
        public override ulong MapVATR(ulong absAddr)
        {
            return absAddr - baseAddr;
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            return false;
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            return pointer - baseAddr;
        }
    }
}
