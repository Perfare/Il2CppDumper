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
            if (ReadUInt16() != 0x5A4D)//e_magic
                throw new Exception("ERROR: Invalid PE file");
            Position = 0x3C;//e_lfanew
            Position = ReadUInt32();
            if (ReadUInt32() != 0x00004550)//Signature
                throw new Exception("ERROR: Invalid PE file");
            var fileHeader = ReadClass<FileHeader>();
            if (fileHeader.Machine == 0x014c)//Intel 386
            {
                is32Bit = true;
                var optionalHeader = ReadClass<OptionalHeader>();
                optionalHeader.DataDirectory = ReadClassArray<DataDirectory>(optionalHeader.NumberOfRvaAndSizes);
                imageBase = optionalHeader.ImageBase;
            }
            else if (fileHeader.Machine == 0x8664)//AMD64
            {
                var optionalHeader = ReadClass<OptionalHeader64>();
                optionalHeader.DataDirectory = ReadClassArray<DataDirectory>(optionalHeader.NumberOfRvaAndSizes);
                imageBase = optionalHeader.ImageBase;
            }
            else
            {
                throw new Exception("ERROR: Unsupported machine.");
            }
            sections = new SectionHeader[fileHeader.NumberOfSections];
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                sections[i] = new SectionHeader
                {
                    Name = Encoding.UTF8.GetString(ReadBytes(8)).Trim('\0'),
                    VirtualSize = ReadUInt32(),
                    VirtualAddress = ReadUInt32(),
                    SizeOfRawData = ReadUInt32(),
                    PointerToRawData = ReadUInt32(),
                    PointerToRelocations = ReadUInt32(),
                    PointerToLinenumbers = ReadUInt32(),
                    NumberOfRelocations = ReadUInt16(),
                    NumberOfLinenumbers = ReadUInt16(),
                    Characteristics = ReadUInt32()
                };
            }
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            uint addr = (uint)(uiAddr - imageBase);
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
            ulong codeRegistration;
            ulong metadataRegistration;
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            var data = dataList.ToArray();
            var exec = execList.ToArray();
            plusSearch.SetSearch(imageBase, data);
            plusSearch.SetPointerRangeFirst(imageBase, data);
            plusSearch.SetPointerRangeSecond(imageBase, exec);
            if (is32Bit)
            {
                codeRegistration = plusSearch.FindCodeRegistration();
                plusSearch.SetPointerRangeSecond(imageBase, data);
                metadataRegistration = plusSearch.FindMetadataRegistration();
            }
            else
            {
                codeRegistration = plusSearch.FindCodeRegistration64Bit();
                plusSearch.SetPointerRangeSecond(imageBase, data);
                metadataRegistration = plusSearch.FindMetadataRegistration64Bit();
            }
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }
    }
}
