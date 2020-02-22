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

        public PE(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
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
            if (fileHeader.Machine == 0x14c) //Intel 386
            {
                Is32Bit = true;
                var optionalHeader = ReadClass<OptionalHeader>();
                imageBase = optionalHeader.ImageBase;
            }
            else if (fileHeader.Machine == 0x8664) //AMD64
            {
                var optionalHeader = ReadClass<OptionalHeader64>();
                imageBase = optionalHeader.ImageBase;
            }
            else
            {
                throw new NotSupportedException("ERROR: Unsupported machine.");
            }
            Position = pos + fileHeader.SizeOfOptionalHeader;
            sections = ReadClassArray<SectionHeader>(fileHeader.NumberOfSections);
        }

        public override ulong MapVATR(ulong absAddr)
        {
            var addr = absAddr - imageBase;
            var section = sections.First(x => addr >= x.VirtualAddress && addr <= x.VirtualAddress + x.VirtualSize);
            return addr - (section.VirtualAddress - section.PointerToRawData);
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
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
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            var data = dataList.ToArray();
            var exec = execList.ToArray();
            plusSearch.SetSection(SearchSectionType.Exec, imageBase, exec);
            plusSearch.SetSection(SearchSectionType.Data, imageBase, data);
            plusSearch.SetSection(SearchSectionType.Bss, imageBase, data);
            var codeRegistration = plusSearch.FindCodeRegistration();
            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoInit(codeRegistration, metadataRegistration);
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
