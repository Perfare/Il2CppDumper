using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class PE : Il2Cpp
    {
        private FileHeader fileHeader;
        private OptionalHeader optionalHeader;
        private SectionHeader[] sections;
        private uint imageBase;

        public PE(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            if (ReadUInt16() != 0x5A4D)//e_magic
                throw new Exception("ERROR: Invalid PE file");
            Position = 0x3C;//e_lfanew
            Position = ReadUInt32();
            if (ReadUInt32() != 0x00004550)//Signature
                throw new Exception("ERROR: Invalid PE file");
            fileHeader = ReadClass<FileHeader>();
            optionalHeader = ReadClass<OptionalHeader>();
            optionalHeader.DataDirectory = ReadClassArray<DataDirectory>(optionalHeader.NumberOfRvaAndSizes);
            imageBase = optionalHeader.ImageBase;
            var IATVirtualAddress = optionalHeader.DataDirectory[12].VirtualAddress;
            var IATSize = optionalHeader.DataDirectory[12].Size;
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
            uint addr = (uint)uiAddr - imageBase;
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
                var codeRegistration = FindCodeRegistration(methodCount, rdata, text);
                var metadataRegistration = FindMetadataRegistration(typeDefinitionsCount, rdata, data);
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

        private uint FindCodeRegistration(int count, SectionHeader search, SectionHeader range)
        {
            var searchend = search.PointerToRawData + search.SizeOfRawData;
            var rangeend = range.VirtualAddress + range.VirtualSize;
            Position = search.PointerToRawData;
            while (Position < searchend)
            {
                var add = Position;
                if (ReadUInt32() == count)
                {
                    try
                    {
                        uint pointers = MapVATR(ReadUInt32());
                        if (pointers >= search.PointerToRawData && pointers <= searchend)
                        {
                            var np = Position;
                            var temp = ReadClassArray<uint>(pointers, count);
                            var r = Array.FindIndex(temp, x => x - imageBase < range.VirtualAddress || x - imageBase > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - search.PointerToRawData + search.VirtualAddress + imageBase; //VirtualAddress
                            }
                            Position = np;
                        }
                    }
                    catch
                    {
                        // ignored
                    }
                }
            }
            return 0;
        }

        private uint FindMetadataRegistration(int typeDefinitionsCount, SectionHeader search, SectionHeader range)
        {
            var searchend = search.PointerToRawData + search.SizeOfRawData;
            var rangeend = range.VirtualAddress + range.VirtualSize;
            Position = search.PointerToRawData;
            while (Position < searchend)
            {
                var add = Position;
                if (ReadUInt32() == typeDefinitionsCount)
                {
                    try
                    {
                        var np = Position;
                        Position += 8;
                        uint pointers = MapVATR(ReadUInt32());
                        if (pointers >= search.PointerToRawData && pointers <= searchend)
                        {
                            var temp = ReadClassArray<uint>(pointers, maxMetadataUsages);
                            var r = Array.FindIndex(temp, x => x - imageBase < range.VirtualAddress || x - imageBase > rangeend);
                            if (r == -1)
                            {
                                return (uint)add - 48u - search.PointerToRawData + search.VirtualAddress + imageBase; //VirtualAddress
                            }
                        }
                        Position = np;
                    }
                    catch
                    {
                        // ignored
                    }
                }
            }
            return 0;
        }

        public override bool SymbolSearch()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }
    }
}
