using System.IO;

namespace Il2CppDumper
{
    public sealed class WebAssemblyMemory : Il2Cpp
    {
        private readonly uint bssStart;
        private readonly uint[] refTable;

        public WebAssemblyMemory(Stream stream, uint bssStart, uint[] funcRefs) : base(stream)
        {
            Is32Bit = true;
            this.bssStart = bssStart;
            this.refTable = funcRefs;
        }

        public override ulong MapVATR(ulong addr)
        {
            return addr;
        }

        public override ulong MapRTVA(ulong addr)
        {
            return addr;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var sectionHelper = GetSectionHelper(methodCount, typeDefinitionsCount, imageCount);
            var codeRegistration = sectionHelper.FindCodeRegistration();
            var metadataRegistration = sectionHelper.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
        }

        public override bool Search()
        {
            return false;
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var exec = new SearchSection
            {
                offset = 0,
                offsetEnd = (ulong)methodCount, //hack
                address = 0,
                addressEnd = (ulong)methodCount //hack
            };
            var data = new SearchSection
            {
                offset = 1024,
                offsetEnd = Length,
                address = 1024,
                addressEnd = Length
            };
            var bss = new SearchSection
            {
                offset = bssStart,
                offsetEnd = long.MaxValue, //hack
                address = bssStart,
                addressEnd = long.MaxValue //hack
            };
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, exec);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, bss);
            return sectionHelper;
        }

        public override bool CheckDump() => false;

        public override int GetFunctionIndex(ulong address)
        {
            // on wasm, address of function is actually index of reference table.
            // reference table points index of function at runtime.
            // (e.g. if a function has address 123 and refTable[123] is 456, it will be $func456)
            return refTable != null && address < (ulong)refTable.Length ? (int)refTable[address] : -1;
        }
    }
}
