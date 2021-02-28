using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class PE : Il2Cpp
    {
        private SectionHeader[] sections;
        private ulong imageBase;

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
                imageBase = optionalHeader.ImageBase;
            }
            else if (magic == 0x20b)
            {
                var optionalHeader = ReadClass<OptionalHeader64>();
                imageBase = optionalHeader.ImageBase;
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
            imageBase = addr;
            foreach (var section in sections)
            {
                section.PointerToRawData = section.VirtualAddress;
                section.SizeOfRawData = section.VirtualSize;
            }
        }

        public override ulong MapVATR(ulong absAddr)
        {
            var addr = absAddr - imageBase;
            var section = sections.FirstOrDefault(x => addr >= x.VirtualAddress && addr <= x.VirtualAddress + x.VirtualSize);
            if (section == null)
            {
                return 0ul;
            }
            return addr - (section.VirtualAddress - section.PointerToRawData);
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
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
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages, imageCount);
            var data = dataList.ToArray();
            var exec = execList.ToArray();
            plusSearch.SetSection(SearchSectionType.Exec, imageBase, exec);
            plusSearch.SetSection(SearchSectionType.Data, imageBase, data);
            plusSearch.SetSection(SearchSectionType.Bss, imageBase, data);
            var codeRegistration = plusSearch.FindCodeRegistration();
            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            return pointer - imageBase;
        }
    }
}
