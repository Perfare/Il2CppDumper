using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf : Il2Cpp
    {
        private Elf32_Ehdr elf_header;
        private Elf32_Phdr[] program_table;
        private Elf32_Dyn[] dynamic_table;
        private Elf32_Sym[] dynamic_symbol_table;
        private Dictionary<string, Elf32_Shdr> sectionWithName = new Dictionary<string, Elf32_Shdr>();
        private bool isDump;
        private uint dumpAddr;

        private static readonly byte[] ARMFeatureBytes = { 0x1c, 0x0, 0x9f, 0xe5, 0x1c, 0x10, 0x9f, 0xe5, 0x1c, 0x20, 0x9f, 0xe5 };
        private static readonly byte[] X86FeatureBytes1 = { 0x8D, 0x83 };//lea eax, X
        private static readonly byte[] X86FeatureBytes2 = { 0x89, 0x44, 0x24, 0x04, 0x8D, 0x83 };//mov [esp+4], eax and lea eax, X

        public Elf(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
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
            program_table = ReadClassArray<Elf32_Phdr>(elf_header.e_phoff, elf_header.e_phnum);
            if (!GetSectionWithName())
            {
                Console.WriteLine("Detected this may be a dump file. If not, it must be protected.");
                isDump = true;
                Console.WriteLine("Input dump address:");
                dumpAddr = Convert.ToUInt32(Console.ReadLine(), 16);
                foreach (var phdr in program_table)
                {
                    phdr.p_offset = phdr.p_vaddr;
                    phdr.p_filesz = phdr.p_memsz;
                }
                Console.WriteLine("Note that in this state, the Offset of the output is actually RVA.");
            }
            var pt_dynamic = program_table.First(x => x.p_type == 2u);
            dynamic_table = ReadClassArray<Elf32_Dyn>(pt_dynamic.p_offset, pt_dynamic.p_filesz / 8u);
            RelocationProcessing();
        }

        private bool GetSectionWithName()
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
                return false;
            }
            return true;
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            if (isDump && uiAddr > dumpAddr)
            {
                uiAddr -= dumpAddr;
                return uiAddr;
            }
            var program_header_table = program_table.First(x => uiAddr >= x.p_vaddr && uiAddr <= (x.p_vaddr + x.p_memsz));
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        public override bool Search()
        {
            var _GLOBAL_OFFSET_TABLE_ = dynamic_table.First(x => x.d_tag == DT_PLTGOT).d_un;
            uint initOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_INIT_ARRAY).d_un);
            var initSize = dynamic_table.First(x => x.d_tag == DT_INIT_ARRAYSZ).d_un;
            var addrs = ReadClassArray<uint>(initOffset, initSize / 4u);
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
                            var codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                            Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                            Position = subaddr + 0x2C;
                            var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                            Position = MapVATR(ptr);
                            var metadataRegistration = ReadUInt32();
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
                                var codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Position = subaddr + 0x20;
                                var temp = ReadUInt16();
                                var metadataRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
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
                }
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
                uint codeRegistration = 0;
                uint metadataRegistration = 0;
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
            else if (!isDump)
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
            Console.WriteLine("Applying relocations...");

            try
            {
                uint dynsymOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_SYMTAB).d_un);
                uint dynstrOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_STRTAB).d_un);
                var dynsymSize = dynstrOffset - dynsymOffset;
                uint reldynOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_REL).d_un);
                var reldynSize = dynamic_table.First(x => x.d_tag == DT_RELSZ).d_un;
                dynamic_symbol_table = ReadClassArray<Elf32_Sym>(dynsymOffset, dynsymSize / 16);
                var rel_table = ReadClassArray<Elf32_Rel>(reldynOffset, reldynSize / 8);
                var writer = new BinaryWriter(BaseStream);
                var isx86 = elf_header.e_machine == 0x3;
                foreach (var rel in rel_table)
                {
                    var type = rel.r_info & 0xff;
                    var sym = rel.r_info >> 8;
                    switch (type)
                    {
                        case R_386_32 when isx86:
                        case R_ARM_ABS32 when !isx86:
                            {
                                var dynamic_symbol = dynamic_symbol_table[sym];
                                Position = MapVATR(rel.r_offset);
                                writer.Write(dynamic_symbol.st_value);
                                break;
                            }
                    }
                }
                writer.Flush();
            }
            catch
            {
                // ignored
            }
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            if (!isDump && (!sectionWithName.ContainsKey(".data.rel.ro") || !sectionWithName.ContainsKey(".text") || !sectionWithName.ContainsKey(".bss")))
            {
                Console.WriteLine("ERROR: This file has been protected.");
            }
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            var dataList = new List<Elf32_Phdr>();
            var execList = new List<Elf32_Phdr>();
            foreach (var phdr in program_table.Where(x => x.p_type == 1u))
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
            if (isDump)
            {
                plusSearch.SetPointerRangeSecond(dumpAddr, exec);
            }
            else
            {
                plusSearch.SetPointerRangeSecond(exec);
            }
            var codeRegistration = plusSearch.FindCodeRegistration();
            if (isDump)
            {
                plusSearch.SetPointerRangeSecond(dumpAddr, data);
            }
            else
            {
                plusSearch.SetPointerRangeSecond(data);
            }

            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            uint codeRegistration = 0;
            uint metadataRegistration = 0;
            uint dynstrOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_STRTAB).d_un);
            foreach (var dynamic_symbol in dynamic_symbol_table)
            {
                var name = ReadStringToNull(dynstrOffset + dynamic_symbol.st_name);
                switch (name)
                {
                    case "g_CodeRegistration":
                        codeRegistration = dynamic_symbol.st_value;
                        break;
                    case "g_MetadataRegistration":
                        metadataRegistration = dynamic_symbol.st_value;
                        break;
                }
            }
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