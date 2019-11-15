using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf64 : Il2Cpp
    {
        private Elf64_Ehdr elf_header;
        private Elf64_Phdr[] program_table;
        private Elf64_Dyn[] dynamic_table;
        private Elf64_Sym[] dynamic_symbol_table;
        private Dictionary<string, Elf64_Shdr> sectionWithName = new Dictionary<string, Elf64_Shdr>();
        private bool isDumped;
        private ulong dumpAddr;

        public Elf64(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
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
            program_table = ReadClassArray<Elf64_Phdr>(elf_header.e_phoff, elf_header.e_phnum);
            if (!GetSectionWithName())
            {
                Console.WriteLine("Detected this may be a dump file. If not, it must be protected.");
                isDumped = true;
                Console.WriteLine("Input dump address:");
                dumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                foreach (var phdr in program_table)
                {
                    phdr.p_offset = phdr.p_vaddr;
                    phdr.p_filesz = phdr.p_memsz;
                    phdr.p_vaddr += dumpAddr;
                }
            }
            var pt_dynamic = program_table.First(x => x.p_type == 2u);
            dynamic_table = ReadClassArray<Elf64_Dyn>(pt_dynamic.p_offset, (long)pt_dynamic.p_filesz / 16L);
            if (!isDumped)
            {
                RelocationProcessing();
                if (CheckProtection())
                {
                    Console.WriteLine("ERROR: This file is protected.");
                }
            }
        }

        private bool GetSectionWithName()
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
                return false;
            }
            return true;
        }

        public override ulong MapVATR(ulong uiAddr)
        {
            var program_header_table = program_table.First(x => uiAddr >= x.p_vaddr && uiAddr <= x.p_vaddr + x.p_memsz);
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var dataList = new List<Elf64_Phdr>();
            var execList = new List<Elf64_Phdr>();
            foreach (var phdr in program_table)
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
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            plusSearch.SetSection(SearchSectionType.Exec, exec);
            plusSearch.SetSection(SearchSectionType.Data, data);
            plusSearch.SetSection(SearchSectionType.Bss, data);
            var codeRegistration = plusSearch.FindCodeRegistration();
            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            ulong codeRegistration = 0ul;
            ulong metadataRegistration = 0ul;
            ulong dynstrOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_STRTAB).d_un);
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

        private void RelocationProcessing()
        {
            Console.WriteLine("Applying relocations...");

            try
            {
                ulong dynsymOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_SYMTAB).d_un);
                ulong dynstrOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_STRTAB).d_un);
                var dynsymSize = dynstrOffset - dynsymOffset;
                ulong relaOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_RELA).d_un);
                var relaSize = dynamic_table.First(x => x.d_tag == DT_RELASZ).d_un;
                dynamic_symbol_table = ReadClassArray<Elf64_Sym>(dynsymOffset, (long)dynsymSize / 24L);
                var rela_table = ReadClassArray<Elf64_Rela>(relaOffset, (long)relaSize / 24L);
                var writer = new BinaryWriter(BaseStream);
                foreach (var rel in rela_table)
                {
                    var type = rel.r_info & 0xffffffff;
                    var sym = rel.r_info >> 32;
                    switch (type)
                    {
                        case R_AARCH64_ABS64:
                            {
                                var dynamic_symbol = dynamic_symbol_table[sym];
                                Position = MapVATR(rel.r_offset);
                                writer.Write(dynamic_symbol.st_value + (ulong)rel.r_addend);
                                break;
                            }
                        case R_AARCH64_RELATIVE:
                            {
                                Position = MapVATR(rel.r_offset);
                                writer.Write(rel.r_addend);
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

        private bool CheckProtection()
        {
            //简单的加壳检测，检测是否含有init function或者JNI_OnLoad
            //.init_proc
            if (dynamic_table.FirstOrDefault(x => x.d_tag == DT_INIT) != null)
            {
                Console.WriteLine("WARNING: find .init_proc");
                return true;
            }
            //JNI_OnLoad
            ulong dynstrOffset = MapVATR(dynamic_table.First(x => x.d_tag == DT_STRTAB).d_un);
            foreach (var dynamic_symbol in dynamic_symbol_table)
            {
                var name = ReadStringToNull(dynstrOffset + dynamic_symbol.st_name);
                switch (name)
                {
                    case "JNI_OnLoad":
                        Console.WriteLine("WARNING: find JNI_OnLoad");
                        return true;
                }
            }
            return false;
        }

        public override ulong FixPointer(ulong pointer)
        {
            if (isDumped)
            {
                return pointer - dumpAddr;
            }
            return pointer;
        }
    }
}
