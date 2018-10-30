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

        public PE(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
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
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        public override bool AdvancedSearch(int methodCount)
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            if (sections.Any(x => x.Name == ".text") && sections.Any(x => x.Name == ".data") && sections.Any(x => x.Name == ".rdata"))
            {
                var text = sections.First(x => x.Name == ".text");
                var data = sections.First(x => x.Name == ".data");
                var rdata = sections.First(x => x.Name == ".rdata");

                ulong codeRegistration;
                ulong metadataRegistration;
                var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
                plusSearch.SetSearch(imageBase, data, rdata);
                plusSearch.SetPointerRangeFirst(imageBase, data, rdata);
                plusSearch.SetPointerRangeSecond(imageBase, text);
                if (is32Bit)
                {
                    codeRegistration = plusSearch.FindCodeRegistration();
                    plusSearch.SetPointerRangeSecond(imageBase, data, rdata);
                    metadataRegistration = plusSearch.FindMetadataRegistration();
                }
                else
                {
                    codeRegistration = plusSearch.FindCodeRegistration64Bit();
                    plusSearch.SetPointerRangeSecond(imageBase, data, rdata);
                    metadataRegistration = plusSearch.FindMetadataRegistration64Bit();
                }
                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            else
            {
                Console.WriteLine("ERROR: The necessary section is missing.");
            }
            return false;
        }

        public override bool SymbolSearch()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }
    }
}
