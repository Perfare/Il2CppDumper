using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf64 : Il2Cpp
    {
        private Elf64_Ehdr elfHeader;
        private Elf64_Phdr[] programSegment;
        private Elf64_Dyn[] dynamicSection;
        private Elf64_Sym[] symbolTable;
        private Dictionary<string, Elf64_Shdr> sectionWithName = new Dictionary<string, Elf64_Shdr>();
        private bool isDumped;
        private ulong dumpAddr;

        public Elf64(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            elfHeader = new Elf64_Ehdr();
            elfHeader.ei_mag = ReadUInt32();
            elfHeader.ei_class = ReadByte();
            elfHeader.ei_data = ReadByte();
            elfHeader.ei_version = ReadByte();
            elfHeader.ei_osabi = ReadByte();
            elfHeader.ei_abiversion = ReadByte();
            elfHeader.ei_pad = ReadBytes(7);
            elfHeader.e_type = ReadUInt16();
            elfHeader.e_machine = ReadUInt16();
            elfHeader.e_version = ReadUInt32();
            elfHeader.e_entry = ReadUInt64();
            elfHeader.e_phoff = ReadUInt64();
            elfHeader.e_shoff = ReadUInt64();
            elfHeader.e_flags = ReadUInt32();
            elfHeader.e_ehsize = ReadUInt16();
            elfHeader.e_phentsize = ReadUInt16();
            elfHeader.e_phnum = ReadUInt16();
            elfHeader.e_shentsize = ReadUInt16();
            elfHeader.e_shnum = ReadUInt16();
            elfHeader.e_shtrndx = ReadUInt16();
            programSegment = ReadClassArray<Elf64_Phdr>(elfHeader.e_phoff, elfHeader.e_phnum);
            if (!GetSectionWithName())
            {
                Console.WriteLine("Detected this may be a dump file. If not, it must be protected.");
                isDumped = true;
                Console.WriteLine("Input dump address:");
                dumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                foreach (var phdr in programSegment)
                {
                    phdr.p_offset = phdr.p_vaddr;
                    phdr.p_filesz = phdr.p_memsz;
                    phdr.p_vaddr += dumpAddr;
                }
            }
            var pt_dynamic = programSegment.First(x => x.p_type == PT_DYNAMIC);
            dynamicSection = ReadClassArray<Elf64_Dyn>(pt_dynamic.p_offset, (long)pt_dynamic.p_filesz / 16L);
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
                var section_name_off = elfHeader.e_shoff + (ulong)elfHeader.e_shentsize * elfHeader.e_shtrndx;
                Position = section_name_off + 2 * 4 + 8 + 8;//2 * sizeof(Elf64_Word) + sizeof(Elf64_Xword) + sizeof(Elf64_Addr)
                var section_name_block_off = ReadUInt32();
                for (int i = 0; i < elfHeader.e_shnum; i++)
                {
                    var section = ReadClass<Elf64_Shdr>(elfHeader.e_shoff + elfHeader.e_shentsize * (ulong)i);
                    var key = ReadStringToNull(section_name_block_off + section.sh_name);
                    if (!sectionWithName.ContainsKey(key))
                    {
                        sectionWithName.Add(key, section);
                    }
                }
            }
            catch
            {
                return false;
            }
            return true;
        }

        public override ulong MapVATR(ulong addr)
        {
            var phdr = programSegment.First(x => addr >= x.p_vaddr && addr <= x.p_vaddr + x.p_memsz);
            return addr - (phdr.p_vaddr - phdr.p_offset);
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var dataList = new List<Elf64_Phdr>();
            var execList = new List<Elf64_Phdr>();
            foreach (var phdr in programSegment)
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
            ulong dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
            foreach (var symbol in symbolTable)
            {
                var name = ReadStringToNull(dynstrOffset + symbol.st_name);
                switch (name)
                {
                    case "g_CodeRegistration":
                        codeRegistration = symbol.st_value;
                        break;
                    case "g_MetadataRegistration":
                        metadataRegistration = symbol.st_value;
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
                ulong dynsymOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_SYMTAB).d_un);
                ulong dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
                var dynsymSize = dynstrOffset - dynsymOffset;
                ulong relaOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_RELA).d_un);
                var relaSize = dynamicSection.First(x => x.d_tag == DT_RELASZ).d_un;
                symbolTable = ReadClassArray<Elf64_Sym>(dynsymOffset, (long)dynsymSize / 24L);
                var relaTable = ReadClassArray<Elf64_Rela>(relaOffset, (long)relaSize / 24L);
                foreach (var rela in relaTable)
                {
                    var type = rela.r_info & 0xffffffff;
                    var sym = rela.r_info >> 32;
                    switch (type)
                    {
                        case R_AARCH64_ABS64:
                            {
                                var symbol = symbolTable[sym];
                                Position = MapVATR(rela.r_offset);
                                Write(symbol.st_value + (ulong)rela.r_addend);
                                break;
                            }
                        case R_AARCH64_RELATIVE:
                            {
                                Position = MapVATR(rela.r_offset);
                                Write(rela.r_addend);
                                break;
                            }
                    }
                }
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
            if (dynamicSection.FirstOrDefault(x => x.d_tag == DT_INIT) != null)
            {
                Console.WriteLine("WARNING: find .init_proc");
                return true;
            }
            //JNI_OnLoad
            ulong dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
            foreach (var symbol in symbolTable)
            {
                var name = ReadStringToNull(dynstrOffset + symbol.st_name);
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
