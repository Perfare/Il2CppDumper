using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class Elf64 : Il2Cpp
    {
        private Elf64_Ehdr elf_header;
        private Elf64_Phdr[] program_table_element;
        private Dictionary<string, Elf64_Shdr> sectionWithName = new Dictionary<string, Elf64_Shdr>();
        private ulong codeRegistration;
        private ulong metadataRegistration;

        public Elf64(Stream stream, int version, long maxmetadataUsages) : base(stream)
        {
            this.version = version;
            this.maxmetadataUsages = maxmetadataUsages;
            Search = SearchObsolete;
            elf_header = new Elf64_Ehdr();
            elf_header.ei_mag = ReadUInt32();
            elf_header.ei_class = ReadByte();
            elf_header.ei_data = ReadByte();
            elf_header.ei_version = ReadByte();
            elf_header.ei_osabi = ReadByte();
            elf_header.ei_abiversion = ReadByte();
            elf_header.ei_pad = ReadBytes(7);
            elf_header.e_type = ReadUInt16();
            elf_header.e_machine = ReadUInt16();
            elf_header.e_version = ReadUInt32();
            elf_header.e_entry = ReadUInt64();
            elf_header.e_phoff = ReadUInt64();
            elf_header.e_shoff = ReadUInt64();
            elf_header.e_flags = ReadUInt32();
            elf_header.e_ehsize = ReadUInt16();
            elf_header.e_phentsize = ReadUInt16();
            elf_header.e_phnum = ReadUInt16();
            elf_header.e_shentsize = ReadUInt16();
            elf_header.e_shnum = ReadUInt16();
            elf_header.e_shtrndx = ReadUInt16();
            program_table_element = ReadClassArray<Elf64_Phdr>(elf_header.e_phoff, elf_header.e_phnum);
            GetSectionWithName();
            RelocationProcessing();
        }

        private void GetSectionWithName()
        {
            try
            {
                var section_name_off = elf_header.e_shoff + (ulong)elf_header.e_shentsize * elf_header.e_shtrndx;
                Position = section_name_off + 2 * 4 + 8 + 8;//2 * sizeof(Elf64_Word) + sizeof(Elf64_Xword) + sizeof(Elf64_Addr)
                var section_name_block_off = ReadUInt32();
                for (int i = 0; i < elf_header.e_shnum; i++)
                {
                    var section = ReadClass<Elf64_Shdr>(elf_header.e_shoff + elf_header.e_shentsize * (ulong)i);
                    sectionWithName.Add(ReadStringToNull(section_name_block_off + section.sh_name), section);
                }
            }
            catch
            {
                Console.WriteLine("ERROR: Unable to get section.");
            }
        }

        private void RelocationProcessing()
        {
            //TODO
            /*if (sectionWithName.ContainsKey(".dynsym") && sectionWithName.ContainsKey(".dynstr") && sectionWithName.ContainsKey(".rela.dyn"))
            {
                Console.WriteLine("Applying relocations...");
                var dynsym = sectionWithName[".dynsym"];
                var symbol_name_block_off = sectionWithName[".dynstr"].sh_offset;
                var rela_dyn = sectionWithName[".rela.dyn"];
                var dynamic_symbol_table = ReadClassArray<Elf64_Sym>(dynsym.sh_offset, (long)dynsym.sh_size / 24);
                var rel_dynend = rela_dyn.sh_offset + rela_dyn.sh_size;
                Position = rela_dyn.sh_offset;
                var writer = new BinaryWriter(BaseStream);
                while ((ulong)Position < rel_dynend)
                {
                    //Elf64_Rela
                    var r_offset = ReadUInt64();
                    //r_info
                    var type = ReadUInt32();
                    var index = ReadUInt32();
                    var r_addend = ReadUInt64();
                    switch (type)
                    {
                        case 257: //R_AARCH64_ABS64
                        //case 1027: //R_AARCH64_RELATIVE
                            {
                                var position = Position;
                                var dynamic_symbol = dynamic_symbol_table[index];
                                writer.BaseStream.Position = (long)r_offset;
                                writer.Write(dynamic_symbol.st_value);
                                Position = position;
                                break;
                            }
                        case 1025: //R_AARCH64_GLOB_DAT
                            {
                                var position = Position;
                                var dynamic_symbol = dynamic_symbol_table[index];
                                var name = ReadStringToNull(symbol_name_block_off + dynamic_symbol.st_name);
                                switch (name)
                                {
                                    case "g_CodeRegistration":
                                        codeRegistration = dynamic_symbol.st_value;
                                        break;
                                    case "g_MetadataRegistration":
                                        metadataRegistration = dynamic_symbol.st_value;
                                        break;
                                }
                                Position = position;
                                break;
                            }
                    }
                }
            }*/
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= x.p_vaddr + x.p_memsz);
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        public override long GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex)
        {
            if (isNew21)
            {
                var ptr = fieldOffsets[typeIndex];
                if (ptr >= 0)
                {
                    Position = MapVATR((ulong)ptr) + 4ul * (ulong)fieldIndexInType;
                    return ReadInt32();
                }
                return 0;
            }
            return fieldOffsets[fieldIndex];
        }

        public override ulong[] GetPointers(ulong pointer, long count)
        {
            var pointers = MapVATR<ulong>(pointer, count);
            return pointers;
        }

        private bool SearchObsolete()
        {
            Console.WriteLine("ERROR: This mode not supported Elf64.");
            return false;
        }

        public override bool AdvancedSearch(int methodCount)
        {
            Console.WriteLine("ERROR: This mode not supported Elf64.");
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            if (sectionWithName.ContainsKey(".data") && sectionWithName.ContainsKey(".text") && sectionWithName.ContainsKey(".bss"))
            {
                var datarelro = sectionWithName[".data"];
                var text = sectionWithName[".text"];
                var bss = sectionWithName[".bss"];
                codeRegistration = FindCodeRegistration(methodCount, datarelro, null, text);
                metadataRegistration = FindMetadataRegistration(typeDefinitionsCount, datarelro, null, bss);
                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init64(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            else
            {
                Console.WriteLine("ERROR: The necessary section is missing.");
            }
            return false;
        }

        private ulong FindCodeRegistration(int count, Elf64_Shdr search, Elf64_Shdr search2, Elf64_Shdr range)
        {
            var searchend = search.sh_offset + search.sh_size;
            var rangeend = range.sh_addr + range.sh_size;
            var search2end = search2 == null ? 0 : search2.sh_offset + search2.sh_size;
            Position = search.sh_offset;
            while ((ulong)Position < searchend)
            {
                var add = Position;
                if (ReadUInt64() == (ulong)count)
                {
                    try
                    {
                        ulong pointers = MapVATR(ReadUInt64());
                        if (pointers >= search.sh_offset && pointers <= searchend)
                        {
                            var np = Position;
                            var temp = ReadClassArray<ulong>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.sh_addr || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - search.sh_offset + search.sh_addr;//MapRATV
                            }
                            Position = np;
                        }
                        else if (search2 != null && pointers >= search2.sh_offset && pointers <= search2end)
                        {
                            var np = Position;
                            var temp = ReadClassArray<ulong>(pointers, count);
                            var r = Array.FindIndex(temp, x => x < range.sh_addr || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - search.sh_offset + search.sh_addr;//MapRATV
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

        private ulong FindMetadataRegistration(int typeDefinitionsCount, Elf64_Shdr search, Elf64_Shdr search2, Elf64_Shdr range)
        {
            var searchend = search.sh_offset + search.sh_size;
            var rangeend = range.sh_addr + range.sh_size;
            var search2end = search2 == null ? 0 : search2.sh_offset + search2.sh_size;
            Position = search.sh_offset;
            while ((ulong)Position < searchend)
            {
                var add = Position;
                if (ReadUInt64() == (ulong)typeDefinitionsCount)
                {
                    try
                    {
                        var np = Position;
                        Position += 16;
                        ulong pointers = MapVATR(ReadUInt64());
                        if (pointers >= search.sh_offset && pointers <= searchend)
                        {
                            var temp = ReadClassArray<ulong>(pointers, maxmetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.sh_addr || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - 96ul - search.sh_offset + search.sh_addr;//MapRATV
                            }
                        }
                        else if (search2 != null && pointers >= search2.sh_offset && pointers <= search2end)
                        {
                            var temp = ReadClassArray<ulong>(pointers, maxmetadataUsages);
                            var r = Array.FindIndex(temp, x => x < range.sh_addr || x > rangeend);
                            if (r == -1)
                            {
                                return (ulong)add - 96ul - search.sh_offset + search.sh_addr;//MapRATV
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

        public bool DetectedSymbol()
        {
            Console.WriteLine("ERROR: This mode not supported Elf64.");
            return false;
        }
    }
}
