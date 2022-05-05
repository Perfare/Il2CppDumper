using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf : ElfBase
    {
        private Elf32_Ehdr elfHeader;
        private Elf32_Phdr[] programSegment;
        private Elf32_Dyn[] dynamicSection;
        private Elf32_Sym[] symbolTable;
        private Elf32_Shdr[] sectionTable;
        private Elf32_Phdr pt_dynamic;

        /*
        * LDR R1, [X]
        * ADD R0, X, X
        * ADD R2, X, X
        */
        private static readonly string ARMFeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0";
        private static readonly string X86FeatureBytes = "? 0x10 ? 0xE7 ? 0x00 ? 0xE0 ? 0x20 ? 0xE0"; //TODO

        public Elf(Stream stream) : base(stream)
        {
            Is32Bit = true;
            Load();
        }

        protected override void Load()
        {
            elfHeader = ReadClass<Elf32_Ehdr>(0);
            programSegment = ReadClassArray<Elf32_Phdr>(elfHeader.e_phoff, elfHeader.e_phnum);
            if (IsDumped)
            {
                FixedProgramSegment();
            }
            pt_dynamic = programSegment.First(x => x.p_type == PT_DYNAMIC);
            dynamicSection = ReadClassArray<Elf32_Dyn>(pt_dynamic.p_offset, pt_dynamic.p_filesz / 8u);
            if (IsDumped)
            {
                FixedDynamicSection();
            }
            ReadSymbol();
            if (!IsDumped)
            {
                RelocationProcessing();
                if (CheckProtection())
                {
                    Console.WriteLine("ERROR: This file may be protected.");
                }
            }
        }

        protected override bool CheckSection()
        {
            try
            {
                var names = new List<string>();
                sectionTable = ReadClassArray<Elf32_Shdr>(elfHeader.e_shoff, elfHeader.e_shnum);
                var shstrndx = sectionTable[elfHeader.e_shstrndx].sh_offset;
                foreach (var section in sectionTable)
                {
                    names.Add(ReadStringToNull(shstrndx + section.sh_name));
                }
                if (!names.Contains(".text"))
                {
                    return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var phdr = programSegment.First(x => addr >= x.p_vaddr && addr <= x.p_vaddr + x.p_memsz);
            return addr - phdr.p_vaddr + phdr.p_offset;
        }

        public override ulong MapRTVA(ulong addr)
        {
            var phdr = programSegment.FirstOrDefault(x => addr >= x.p_offset && addr <= x.p_offset + x.p_filesz);
            if (phdr == null)
            {
                return 0;
            }
            return addr - phdr.p_offset + phdr.p_vaddr;
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
                if (Version < 24)
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
                else if (Version >= 24)
                {
                    if (elfHeader.e_machine == EM_ARM)
                    {
                        Position = result + 0x14;
                        codeRegistration = ReadUInt32() + result + 0xcu + (uint)ImageBase;
                        Position = result + 0x10;
                        var ptr = ReadUInt32() + result + 0x8;
                        Position = MapVATR(ptr + ImageBase);
                        metadataRegistration = ReadUInt32();
                    }
                }
                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount, int imageCount)
        {
            var sectionHelper = GetSectionHelper(methodCount, typeDefinitionsCount, imageCount);
            var codeRegistration = sectionHelper.FindCodeRegistration();
            var metadataRegistration = sectionHelper.FindMetadataRegistration();
            return AutoPlusInit(codeRegistration, metadataRegistration);
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

        private void ReadSymbol()
        {
            try
            {
                var symbolCount = 0u;
                var hash = dynamicSection.FirstOrDefault(x => x.d_tag == DT_HASH);
                if (hash != null)
                {
                    var addr = MapVATR(hash.d_un);
                    Position = addr;
                    var nbucket = ReadUInt32();
                    var nchain = ReadUInt32();
                    symbolCount = nchain;
                }
                else
                {
                    hash = dynamicSection.First(x => x.d_tag == DT_GNU_HASH);
                    var addr = MapVATR(hash.d_un);
                    Position = addr;
                    var nbuckets = ReadUInt32();
                    var symoffset = ReadUInt32();
                    var bloom_size = ReadUInt32();
                    var bloom_shift = ReadUInt32();
                    var buckets_address = addr + 16 + (4 * bloom_size);
                    var buckets = ReadClassArray<uint>(buckets_address, nbuckets);
                    var last_symbol = buckets.Max();
                    if (last_symbol < symoffset)
                    {
                        symbolCount = symoffset;
                    }
                    else
                    {
                        var chains_base_address = buckets_address + 4 * nbuckets;
                        Position = chains_base_address + (last_symbol - symoffset) * 4;
                        while (true)
                        {
                            var chain_entry = ReadUInt32();
                            ++last_symbol;
                            if ((chain_entry & 1) != 0)
                                break;
                        }
                        symbolCount = last_symbol;
                    }
                }
                var dynsymOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_SYMTAB).d_un);
                symbolTable = ReadClassArray<Elf32_Sym>(dynsymOffset, symbolCount);
            }
            catch
            {
                // ignored
            }
        }

        private void RelocationProcessing()
        {
            Console.WriteLine("Applying relocations...");
            try
            {
                var reldynOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_REL).d_un);
                var reldynSize = dynamicSection.First(x => x.d_tag == DT_RELSZ).d_un;
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
            try
            {
                //.init_proc
                if (dynamicSection.Any(x => x.d_tag == DT_INIT))
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
                if (sectionTable != null && sectionTable.Any(x => x.sh_type == SHT_LOUSER))
                {
                    Console.WriteLine("WARNING: find SHT_LOUSER section");
                    return true;
                }
            }
            catch
            {
                // ignored
            }
            return false;
        }

        public override ulong GetRVA(ulong pointer)
        {
            if (IsDumped)
            {
                return pointer - ImageBase;
            }
            return pointer;
        }

        private void FixedProgramSegment()
        {
            for (uint i = 0; i < programSegment.Length; i++)
            {
                Position = elfHeader.e_phoff + i * 32u + 4u;
                var phdr = programSegment[i];
                phdr.p_offset = phdr.p_vaddr;
                Write(phdr.p_offset);
                phdr.p_vaddr += (uint)ImageBase;
                Write(phdr.p_vaddr);
                Position += 4;
                phdr.p_filesz = phdr.p_memsz;
                Write(phdr.p_filesz);
            }
        }

        private void FixedDynamicSection()
        {
            for (uint i = 0; i < dynamicSection.Length; i++)
            {
                Position = pt_dynamic.p_offset + i * 8 + 4;
                var dyn = dynamicSection[i];
                switch (dyn.d_tag)
                {
                    case DT_PLTGOT:
                    case DT_HASH:
                    case DT_STRTAB:
                    case DT_SYMTAB:
                    case DT_RELA:
                    case DT_INIT:
                    case DT_FINI:
                    case DT_REL:
                    case DT_JMPREL:
                    case DT_INIT_ARRAY:
                    case DT_FINI_ARRAY:
                        dyn.d_un += (uint)ImageBase;
                        Write(dyn.d_un);
                        break;
                }
            }
        }

        public override SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount)
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
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, exec);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, data);
            return sectionHelper;
        }
    }
}