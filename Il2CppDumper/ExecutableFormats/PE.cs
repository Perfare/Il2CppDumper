using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public sealed class PE : Il2Cpp
    {
        private readonly SectionHeader[] sections;

        public PE(Stream stream) : base(stream)
        {
            var dosHeader = ReadClass<DosHeader>();
            if (dosHeader.Magic != 0x5A4D)
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            Position = dosHeader.Lfanew;
            if (ReadUInt32() != 0x4550u) //Signature
            {
                throw new InvalidDataException("ERROR: Invalid PE file");
            }
            var fileHeader = ReadClass<FileHeader>();
            var pos = Position;
            var magic = ReadUInt16();
            Position -= 2;
            if (magic == 0x10b)
            {
                Is32Bit = true;
                var optionalHeader = ReadClass<OptionalHeader>();
                ImageBase = optionalHeader.ImageBase;
            }
            else if (magic == 0x20b)
            {
                var optionalHeader = ReadClass<OptionalHeader64>();
                ImageBase = optionalHeader.ImageBase;
            }
            else
            {
                throw new NotSupportedException($"Invalid Optional header magic {magic}");
            }
            Position = pos + fileHeader.SizeOfOptionalHeader;
            sections = ReadClassArray<SectionHeader>(fileHeader.NumberOfSections);
        }

        public void LoadFromMemory(ulong addr)
        {
            ImageBase = addr;
            foreach (var section in sections)
            {
                section.PointerToRawData = section.VirtualAddress;
                section.SizeOfRawData = section.VirtualSize;
            }
        }

        public override ulong MapVATR(ulong absAddr)
        {
            var addr = absAddr - ImageBase;
            var section = sections.FirstOrDefault(x => addr >= x.VirtualAddress && addr <= x.VirtualAddress + x.VirtualSize);
            if (section == null)
            {
                return 0ul;
            }
            return addr - section.VirtualAddress + section.PointerToRawData;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var section = sections.FirstOrDefault(x => addr >= x.PointerToRawData && addr <= x.PointerToRawData + x.SizeOfRawData);
            if (section == null)
            {
                return 0ul;
            }
            return addr - section.PointerToRawData + section.VirtualAddress + ImageBase;
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var sectionHelper = GetSectionHelper(methodCount, typeDefinitionsCount, imageCount);
            var codeRegistration = sectionHelper.FindCodeRegistration();
            var metadataRegistration = sectionHelper.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            return pointer - ImageBase;
        }

        public override SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var execList = new List<SectionHeader>();
            var dataList = new List<SectionHeader>();
            foreach (var section in sections)
            {
                switch (section.Characteristics)
                {
                    case 0x60000020:
                        execList.Add(section);
                        break;
                    case 0x40000040:
                    case 0xC0000040:
                        dataList.Add(section);
                        break;
                }
            }
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            var data = dataList.ToArray();
            var exec = execList.ToArray();
            sectionHelper.SetSection(SearchSectionType.Exec, ImageBase, exec);
            sectionHelper.SetSection(SearchSectionType.Data, ImageBase, data);
            sectionHelper.SetSection(SearchSectionType.Bss, ImageBase, data);
            return sectionHelper;
        }

        public override bool CheckDump()
        {
            if (Is32Bit)
            {
                return ImageBase != 0x10000000;
            }
            else
            {
                return ImageBase != 0x180000000;
            }
        }
    }
}
