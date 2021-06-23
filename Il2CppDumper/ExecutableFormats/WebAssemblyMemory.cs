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
                offset = Length,
                offsetEnd = long.MaxValue, //hack
                address = Length,
                addressEnd = long.MaxValue //hack
            };
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, maxMetadataUsages, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, exec);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, bss);
            return sectionHelper;
        }
    }
}
