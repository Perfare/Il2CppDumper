using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class Elf : Il2Cpp
    {
        private Elf32_Ehdr elf_header;
        private Elf32_Phdr[] program_table_element;
        private static readonly byte[] ARMFeatureBytes = { 0x1c, 0x0, 0x9f, 0xe5, 0x1c, 0x10, 0x9f, 0xe5, 0x1c, 0x20, 0x9f, 0xe5 };
        private static readonly byte[] X86FeatureBytes1 = { 0x8D, 0x83 };//lea eax, X
        private static readonly byte[] X86FeatureBytes2 = { 0x89, 0x44, 0x24, 0x04, 0x8D, 0x83 };//mov [esp+4], eax and lea eax, X
        private Dictionary<string, Elf32_Shdr> sectionWithName = new Dictionary<string, Elf32_Shdr>();
        private ulong codeRegistration;
        private ulong metadataRegistration;

        public Elf(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            is32Bit = true;
            elf_header = new Elf32_Ehdr();
            elf_header.ei_mag = ReadUInt32();
            elf_header.ei_class = ReadByte();
            elf_header.ei_data = ReadByte();
            elf_header.ei_version = ReadByte();
            elf_header.ei_osabi = ReadByte();
            elf_header.ei_abiversion = ReadByte();
            elf_header.ei_pad = ReadBytes(7);
            elf_header.e_type = ReadUInt16();
            elf_header.e_machine = ReadUInt16();
            if (elf_header.e_machine != 0x28 && elf_header.e_machine != 0x3)
                throw new Exception("ERROR: Unsupported machines.");
            elf_header.e_version = ReadUInt32();
            elf_header.e_entry = ReadUInt32();
            elf_header.e_phoff = ReadUInt32();
            elf_header.e_shoff = ReadUInt32();
            elf_header.e_flags = ReadUInt32();
            elf_header.e_ehsize = ReadUInt16();
            elf_header.e_phentsize = ReadUInt16();
            elf_header.e_phnum = ReadUInt16();
            elf_header.e_shentsize = ReadUInt16();
            elf_header.e_shnum = ReadUInt16();
            elf_header.e_shtrndx = ReadUInt16();
            program_table_element = ReadClassArray<Elf32_Phdr>(elf_header.e_phoff, elf_header.e_phnum);
            GetSectionWithName();
            RelocationProcessing();
        }

        private void GetSectionWithName()
        {
            try
            {
                var section_name_off = (int)elf_header.e_shoff + (elf_header.e_shentsize * elf_header.e_shtrndx);
                Position = section_name_off + 2 * 4 + 4 + 4;//2 * sizeof(Elf32_Word) + sizeof(Elf32_Xword) + sizeof(Elf32_Addr)
                var section_name_block_off = ReadInt32();
                for (int i = 0; i < elf_header.e_shnum; i++)
                {
                    var section = ReadClass<Elf32_Shdr>((int)elf_header.e_shoff + (elf_header.e_shentsize * i));
                    sectionWithName.Add(ReadStringToNull(section_name_block_off + section.sh_name), section);
                }
            }
            catch
            {
                Console.WriteLine("WARNING: Unable to get section.");
            }
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= (x.p_vaddr + x.p_memsz));
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        public override bool Search()
        {
            if (version < 21)
            {
                Console.WriteLine("ERROR: Auto mode not support this version.");
                return false;
            }
            //取.dynamic
            var dynamic = new Elf32_Shdr();
            var PT_DYNAMIC = program_table_element.First(x => x.p_type == 2u);
            dynamic.sh_offset = PT_DYNAMIC.p_offset;
            dynamic.sh_size = PT_DYNAMIC.p_filesz;
            //从.dynamic获取_GLOBAL_OFFSET_TABLE_和.init_array
            uint _GLOBAL_OFFSET_TABLE_ = 0;
            var init_array = new Elf32_Shdr();
            Position = dynamic.sh_offset;
            var dynamicend = dynamic.sh_offset + dynamic.sh_size;
            while (Position < dynamicend)
            {
                var tag = ReadInt32();
                switch (tag)
                {
                    case 3:
                        _GLOBAL_OFFSET_TABLE_ = ReadUInt32();
                        break;
                    case 25:
                        init_array.sh_offset = MapVATR(ReadUInt32());
                        break;
                    case 27:
                        init_array.sh_size = ReadUInt32();
                        break;
                    default:
                        Position += 4;
                        break;
                }
            }
            if (_GLOBAL_OFFSET_TABLE_ != 0)
            {
                //从.init_array获取函数
                var addrs = ReadClassArray<uint>(init_array.sh_offset, init_array.sh_size / 4u);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        Position = i;
                        if (elf_header.e_machine == 0x28) //ARM
                        {
                            var buff = ReadBytes(12);
                            if (ARMFeatureBytes.SequenceEqual(buff))
                            {
                                Position = i + 0x2c;
                                var subaddr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = subaddr + 0x28;
                                codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Position = subaddr + 0x2C;
                                var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = MapVATR(ptr);
                                metadataRegistration = ReadUInt32();
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
                        }
                        else if (elf_header.e_machine == 0x3) //x86
                        {
                            Position = i + 22;
                            var buff = ReadBytes(2);
                            if (X86FeatureBytes1.SequenceEqual(buff))
                            {
                                Position = i + 28;
                                buff = ReadBytes(6);
                                if (X86FeatureBytes2.SequenceEqual(buff))
                                {
                                    Position = i + 0x18;
                                    var subaddr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                    Position = subaddr + 0x2C;
                                    codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                    Position = subaddr + 0x20;
                                    var temp = ReadUInt16();
                                    metadataRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                    if (temp == 0x838B)//mov
                                    {
                                        Position = MapVATR(metadataRegistration);
                                        metadataRegistration = ReadUInt32();
                                    }
                                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                    Init(codeRegistration, metadataRegistration);
                                    return true;
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("ERROR: Automatic processing does not support this ELF file.");
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("ERROR: Unable to get GOT form PT_DYNAMIC.");
            }
            return false;
        }

        public override bool AdvancedSearch(int methodCount)
        {
            if (sectionWithName.ContainsKey(".data.rel.ro") && sectionWithName.ContainsKey(".text") && sectionWithName.ContainsKey(".bss"))
            {
                var datarelro = sectionWithName[".data.rel.ro"];
                var text = sectionWithName[".text"];
                var bss = sectionWithName[".bss"];
                Elf32_Shdr datarelrolocal = null;
                if (sectionWithName.ContainsKey(".data.rel.ro.local"))
                    datarelrolocal = sectionWithName[".data.rel.ro.local"];
                var pmethodPointers = FindPointersAsc(methodCount, datarelro, text);
                if (pmethodPointers == 0 && datarelrolocal != null)
                    pmethodPointers = FindPointersAsc(methodCount, datarelrolocal, text);
                if (pmethodPointers != 0)
                {
                    codeRegistration = FindReference(pmethodPointers, datarelro);
                    if (codeRegistration == 0 && datarelrolocal != null)
                        codeRegistration = FindReference(pmethodPointers, datarelrolocal);
                    if (codeRegistration == 0)
                    {
                        pmethodPointers = FindPointersDesc(methodCount, datarelro, text);
                        if (pmethodPointers == 0 && datarelrolocal != null)
                            pmethodPointers = FindPointersDesc(methodCount, datarelrolocal, text);
                        if (pmethodPointers != 0)
                        {
                            codeRegistration = FindReference(pmethodPointers, datarelro);
                            if (codeRegistration == 0 && datarelrolocal != null)
                                codeRegistration = FindReference(pmethodPointers, datarelrolocal);
                        }
                    }
                }
                var pmetadataUsages = FindPointersAsc(maxMetadataUsages, datarelro, bss);
                if (pmetadataUsages == 0 && datarelrolocal != null)
                    pmetadataUsages = FindPointersAsc(maxMetadataUsages, datarelrolocal, bss);
                if (pmetadataUsages != 0)
                {
                    metadataRegistration = FindReference(pmetadataUsages, datarelro);
                    if (metadataRegistration == 0 && datarelrolocal != null)
                        metadataRegistration = FindReference(pmetadataUsages, datarelrolocal);
                    if (metadataRegistration == 0)
                    {
                        pmetadataUsages = FindPointersDesc(maxMetadataUsages, datarelro, bss);
                        if (pmetadataUsages == 0 && datarelrolocal != null)
                            pmetadataUsages = FindPointersDesc(maxMetadataUsages, datarelrolocal, bss);
                        if (pmetadataUsages != 0)
                        {
                            metadataRegistration = FindReference(pmetadataUsages, datarelro);
                            if (metadataRegistration == 0 && datarelrolocal != null)
                                metadataRegistration = FindReference(pmetadataUsages, datarelrolocal);
                        }
                    }
                }
                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    codeRegistration -= 8u;
                    metadataRegistration -= 64u;
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            else
            {
                Console.WriteLine("ERROR: This file has been protected.");
            }
            return false;
        }

        private uint FindPointersAsc(long readCount, Elf32_Shdr search, Elf32_Shdr range)
        {
            var add = 0;
            var searchend = search.sh_offset + search.sh_size;
            var rangeend = range.sh_addr + range.sh_size;
            while (search.sh_offset + add < searchend)
            {
                var temp = ReadClassArray<int>(search.sh_offset + add, readCount);
                var r = Array.FindLastIndex(temp, x => x < range.sh_addr || x > rangeend);
                if (r != -1)
                {
                    add += ++r * 4;
                }
                else
                {
                    return search.sh_addr + (uint)add; //VirtualAddress
                }
            }
            return 0;
        }

        private uint FindPointersDesc(long readCount, Elf32_Shdr search, Elf32_Shdr range)
        {
            var add = 0;
            var searchend = search.sh_offset + search.sh_size;
            var rangeend = range.sh_addr + range.sh_size;
            while (searchend + add > search.sh_offset)
            {
                var temp = ReadClassArray<int>(searchend + add - 4 * readCount, readCount);
                var r = Array.FindIndex(temp, x => x < range.sh_addr || x > rangeend);
                if (r != -1)
                {
                    add -= (int)((readCount - r) * 4);
                }
                else
                {
                    return (uint)(search.sh_addr + search.sh_size + add - 4 * readCount); //VirtualAddress
                }
            }
            return 0;
        }

        private uint FindReference(uint pointer, Elf32_Shdr search)
        {
            var searchend = search.sh_offset + search.sh_size;
            Position = search.sh_offset;
            while (Position < searchend)
            {
                if (ReadUInt32() == pointer)
                {
                    return (uint)Position - search.sh_offset + search.sh_addr; //VirtualAddress
                }
            }
            return 0;
        }

        private void RelocationProcessing()
        {
            if (sectionWithName.ContainsKey(".dynsym") && sectionWithName.ContainsKey(".dynstr") && sectionWithName.ContainsKey(".rel.dyn"))
            {
                Console.WriteLine("Applying relocations...");
                var dynsym = sectionWithName[".dynsym"];
                var symbol_name_block_off = sectionWithName[".dynstr"].sh_offset;
                var rel_dyn = sectionWithName[".rel.dyn"];
                var dynamic_symbol_table = ReadClassArray<Elf32_Sym>(dynsym.sh_offset, dynsym.sh_size / 16);
                var rel_dynend = rel_dyn.sh_offset + rel_dyn.sh_size;
                Position = rel_dyn.sh_offset;
                var writer = new BinaryWriter(BaseStream);
                var isx86 = elf_header.e_machine == 0x3;
                while (Position < rel_dynend)
                {
                    var offset = ReadUInt32();
                    var type = ReadByte();
                    var index = ReadByte() | (ReadByte() << 8) | (ReadByte() << 16);
                    switch (type)
                    {
                        case 1 when isx86: //R_386_32
                        case 2 when !isx86: //R_ARM_ABS32
                            {
                                var position = Position;
                                var dynamic_symbol = dynamic_symbol_table[index];
                                writer.BaseStream.Position = offset;
                                writer.Write(dynamic_symbol.st_value);
                                Position = position;
                                break;
                            }
                        case 6 when isx86: //R_386_GLOB_DAT
                        case 21 when !isx86: //R_ARM_GLOB_DAT
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
            }
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            if (sectionWithName.ContainsKey(".data.rel.ro") && sectionWithName.ContainsKey(".text") && sectionWithName.ContainsKey(".bss"))
            {
                var datarelro = sectionWithName[".data.rel.ro"];
                var text = sectionWithName[".text"];
                var bss = sectionWithName[".bss"];
                sectionWithName.TryGetValue(".data.rel.ro.local", out var datarelrolocal);

                var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
                plusSearch.SetSearch(datarelro, datarelrolocal);
                plusSearch.SetPointerRangeFirst(datarelro, datarelrolocal);
                plusSearch.SetPointerRangeSecond(text);
                codeRegistration = plusSearch.FindCodeRegistration();
                plusSearch.SetPointerRangeSecond(bss);
                metadataRegistration = plusSearch.FindMetadataRegistration();
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
                Console.WriteLine("WARNING: The necessary section is missing.");

                var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
                var dataList = new List<Elf32_Phdr>();
                var execList = new List<Elf32_Phdr>();
                foreach (var phdr in program_table_element)
                {
                    if (phdr.p_memsz != 0ul)
                    {
                        switch (phdr.p_flags)
                        {
                            case 1u: //PF_X
                            case 3u:
                            case 5u:
                            case 7u:
                                execList.Add(phdr);
                                break;
                            case 2u: //PF_W && PF_R
                            case 4u:
                            case 6u:
                                dataList.Add(phdr);
                                break;
                        }
                    }
                }
                var data = dataList.ToArray();
                var exec = execList.ToArray();
                plusSearch.SetSearch(data);
                plusSearch.SetPointerRangeFirst(data);
                plusSearch.SetPointerRangeSecond(exec);
                codeRegistration = plusSearch.FindCodeRegistration();
                plusSearch.SetPointerRangeSecond(data);
                metadataRegistration = plusSearch.FindMetadataRegistration();
                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            return false;
        }

        public override bool SymbolSearch()
        {
            if (codeRegistration > 0 && metadataRegistration > 0)
            {
                Console.WriteLine("Detected Symbol !");
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            Console.WriteLine("ERROR: No symbol is detected");
            return false;
        }
    }
}