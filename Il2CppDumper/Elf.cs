using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf : Il2Cpp
    {
        private Elf32_Ehdr elfHeader;
        private Elf32_Phdr[] programSegment;
        private Elf32_Dyn[] dynamicSection;
        private Elf32_Sym[] symbolTable;
        private Elf32_Shdr[] sectionTable;
        private bool isDumped;
        private uint dumpAddr;

        /*
        * LDR R1, [X]
        * ADD R0, X, X
        * ADD R2, X, X
        */
        private static readonly string ARMFeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0";
        private static readonly string X86FeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0"; //TODO

        public Elf(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            is32Bit = true;
            elfHeader = new Elf32_Ehdr();
            elfHeader.ei_mag = ReadUInt32();
            elfHeader.ei_class = ReadByte();
            elfHeader.ei_data = ReadByte();
            elfHeader.ei_version = ReadByte();
            elfHeader.ei_osabi = ReadByte();
            elfHeader.ei_abiversion = ReadByte();
            elfHeader.ei_pad = ReadBytes(7);
            elfHeader.e_type = ReadUInt16();
            elfHeader.e_machine = ReadUInt16();
            if (elfHeader.e_machine != EM_ARM && elfHeader.e_machine != EM_386)
                throw new Exception("ERROR: Unsupported machines.");
            elfHeader.e_version = ReadUInt32();
            elfHeader.e_entry = ReadUInt32();
            elfHeader.e_phoff = ReadUInt32();
            elfHeader.e_shoff = ReadUInt32();
            elfHeader.e_flags = ReadUInt32();
            elfHeader.e_ehsize = ReadUInt16();
            elfHeader.e_phentsize = ReadUInt16();
            elfHeader.e_phnum = ReadUInt16();
            elfHeader.e_shentsize = ReadUInt16();
            elfHeader.e_shnum = ReadUInt16();
            elfHeader.e_shtrndx = ReadUInt16();
            programSegment = ReadClassArray<Elf32_Phdr>(elfHeader.e_phoff, elfHeader.e_phnum);
            try
            {
                sectionTable = ReadClassArray<Elf32_Shdr>(elfHeader.e_shoff, elfHeader.e_shnum);
            }
            catch
            {
                Console.WriteLine("Detected this may be a dump file. If not, it must be protected.");
                isDumped = true;
                Console.WriteLine("Input dump address:");
                dumpAddr = Convert.ToUInt32(Console.ReadLine(), 16);
                foreach (var phdr in programSegment)
                {
                    phdr.p_offset = phdr.p_vaddr;
                    phdr.p_filesz = phdr.p_memsz;
                    phdr.p_vaddr += dumpAddr;
                }
            }
            var pt_dynamic = programSegment.First(x => x.p_type == PT_DYNAMIC);
            dynamicSection = ReadClassArray<Elf32_Dyn>(pt_dynamic.p_offset, pt_dynamic.p_filesz / 8u);
            if (!isDumped)
            {
                RelocationProcessing();
                if (CheckProtection())
                {
                    Console.WriteLine("ERROR: This file is protected.");
                }
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var phdr = programSegment.First(x => addr >= x.p_vaddr && addr <= x.p_vaddr + x.p_memsz);
            return addr - (phdr.p_vaddr - phdr.p_offset);
        }

        public override bool Search()
        {
            var _GLOBAL_OFFSET_TABLE_ = dynamicSection.First(x => x.d_tag == DT_PLTGOT).d_un;
            var execs = programSegment.Where(x => x.p_type == PT_LOAD && (x.p_flags & PF_X) == 1).ToArray();
            var resultList = new List<int>();
            var featureBytes = elfHeader.e_machine == EM_ARM ? ARMFeatureBytes : X86FeatureBytes;
            foreach (var exec in execs)
            {
                Position = exec.p_offset;
                var buff = ReadBytes((int)exec.p_filesz);
                foreach (var temp in buff.Search(featureBytes))
                {
                    var bin = buff[temp + 2].HexToBin();
                    if (bin[3] == '1') //LDR
                    {
                        resultList.Add(temp);
                    }
                }
            }
            if (resultList.Count == 1)
            {
                uint codeRegistration = 0;
                uint metadataRegistration = 0;
                var result = (uint)resultList[0];
                if (version < 24f)
                {
                    if (elfHeader.e_machine == EM_ARM)
                    {
                        Position = result + 0x14;
                        codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                        Position = result + 0x18;
                        var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                        Position = MapVATR(ptr);
                        metadataRegistration = ReadUInt32();
                    }
                }
                else if (version >= 24f)
                {
                    if (elfHeader.e_machine == EM_ARM)
                    {
                        Position = result + 0x14;
                        codeRegistration = ReadUInt32() + result + 0xcu + dumpAddr;
                        Position = result + 0x10;
                        var ptr = ReadUInt32() + result + 0x8;
                        Position = MapVATR(ptr + dumpAddr);
                        metadataRegistration = ReadUInt32();
                    }
                }
                return AutoInit(codeRegistration, metadataRegistration);
            }
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var dataList = new List<Elf32_Phdr>();
            var execList = new List<Elf32_Phdr>();
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
            uint codeRegistration = 0;
            uint metadataRegistration = 0;
            var dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
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
                var dynsymOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_SYMTAB).d_un);
                var dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
                var dynsymSize = dynstrOffset - dynsymOffset;
                var reldynOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_REL).d_un);
                var reldynSize = dynamicSection.First(x => x.d_tag == DT_RELSZ).d_un;
                symbolTable = ReadClassArray<Elf32_Sym>(dynsymOffset, (long)dynsymSize / 16);
                var relTable = ReadClassArray<Elf32_Rel>(reldynOffset, reldynSize / 8);
                var isx86 = elfHeader.e_machine == 0x3;
                foreach (var rel in relTable)
                {
                    var type = rel.r_info & 0xff;
                    var sym = rel.r_info >> 8;
                    switch (type)
                    {
                        case R_386_32 when isx86:
                        case R_ARM_ABS32 when !isx86:
                            {
                                var symbol = symbolTable[sym];
                                Position = MapVATR(rel.r_offset);
                                Write(symbol.st_value);
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
            //.init_proc
            if (dynamicSection.FirstOrDefault(x => x.d_tag == DT_INIT) != null)
            {
                Console.WriteLine("WARNING: find .init_proc");
                return true;
            }
            //JNI_OnLoad
            var dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
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
            if (sectionTable.Any(x => x.sh_type == SHT_LOUSER))
            {
                Console.WriteLine("WARNING: find SHT_LOUSER section");
                return true;
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