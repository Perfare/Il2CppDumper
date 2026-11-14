using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.ElfConstants;

namespace Il2CppDumper
{
    public sealed class Elf64 : ElfBase
    {
        private Elf64_Ehdr elfHeader;
        private Elf64_Phdr[] programSegment;
        private Elf64_Dyn[] dynamicSection;
        private Elf64_Sym[] symbolTable;
        private Elf64_Shdr[] sectionTable;
        private Elf64_Phdr pt_dynamic;

        public Elf64(Stream stream) : base(stream)
        {
            Load();
        }

        protected override void Load()
        {
            elfHeader = ReadClass<Elf64_Ehdr>(0);
            programSegment = ReadClassArray<Elf64_Phdr>(elfHeader.e_phoff, elfHeader.e_phnum);
            if (IsDumped)
            {
                FixedProgramSegment();
            }
            pt_dynamic = programSegment.First(x => x.p_type == PT_DYNAMIC);
            dynamicSection = ReadClassArray<Elf64_Dyn>(pt_dynamic.p_offset, pt_dynamic.p_filesz / 16L);
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
                    Console.WriteLine("WARNING: Nonstandard ELF sections detected; protection is not confirmed.");
                }
            }
        }

        protected override bool CheckSection()
        {
            try
            {
                var names = new List<string>();
                sectionTable = ReadClassArray<Elf64_Shdr>(elfHeader.e_shoff, elfHeader.e_shnum);
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
                    var buckets_address = addr + 16 + (8 * bloom_size);
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
                symbolTable = ReadClassArray<Elf64_Sym>(dynsymOffset, symbolCount);
            }
            catch
            {
                // ignored
            }
        }

        private void RelocationProcessing()
        {
            Console.WriteLine("Applying relocations...");
            var hasRela = ProcessRelocationTable(DT_RELA, DT_RELASZ, false);
            var hasAndroidRela = ProcessRelocationTable(DT_ANDROID_RELA, DT_ANDROID_RELASZ, true);
            if (!hasRela && !hasAndroidRela)
                Console.WriteLine("WARNING: No DT_RELA or DT_ANDROID_RELA relocation table found.");
        }

        private bool ProcessRelocationTable(long addressTag, long sizeTag, bool packed)
        {
            var address = dynamicSection.FirstOrDefault(x => x.d_tag == addressTag);
            var size = dynamicSection.FirstOrDefault(x => x.d_tag == sizeTag);
            var format = packed ? "Android APS2 RELA" : "ELF RELA";
            if (address == null && size == null)
                return false;
            if (address == null || size == null)
                throw new InvalidDataException($"Incomplete {format} dynamic tags: address and size are both required.");
            if (size.d_un == 0)
            {
                Console.WriteLine($"{format}: 0 relocations.");
                return true;
            }
            var offset = GetRelocationFileOffset(address.d_un, size.d_un, format);
            if (packed)
            {
                if (size.d_un > int.MaxValue)
                    throw new InvalidDataException($"{format} table is too large.");
                Position = offset;
                // Bound the expanded count by the number of pointer slots in the file.
                var relocations = AndroidPackedRelocations.Decode(ReadBytes((int)size.d_un), Length / sizeof(ulong));
                ApplyRelocations(relocations, format);
            }
            else
            {
                var entrySize = dynamicSection.FirstOrDefault(x => x.d_tag == DT_RELAENT);
                if (size.d_un % 24 != 0 || (entrySize != null && entrySize.d_un != 24))
                    throw new InvalidDataException($"Invalid {format} layout: expected 24-byte entries.");
                ApplyRelocations(ReadRelaTable(offset, size.d_un / 24), format);
            }
            return true;
        }

        private IEnumerable<Elf64_Rela> ReadRelaTable(ulong offset, ulong count)
        {
            for (ulong i = 0; i < count; i++)
            {
                Position = offset + i * 24;
                yield return new Elf64_Rela { r_offset = ReadUInt64(), r_info = ReadUInt64(), r_addend = ReadUInt64() };
            }
        }

        private void ApplyRelocations(IEnumerable<Elf64_Rela> relocations, string format)
        {
            long total = 0, applied = 0, unresolved = 0, unsupported = 0;
            foreach (var rela in relocations)
            {
                total++;
                var type = rela.r_info & 0xffffffff;
                var sym = rela.r_info >> 32;
                var relative = (elfHeader.e_machine == EM_AARCH64 && type == R_AARCH64_RELATIVE) ||
                    (elfHeader.e_machine == EM_X86_64 && type == R_X86_64_RELATIVE);
                var symbolic = (elfHeader.e_machine == EM_AARCH64 && (type == R_AARCH64_ABS64 || type == R_AARCH64_GLOB_DAT)) ||
                    (elfHeader.e_machine == EM_X86_64 && (type == R_X86_64_64 || type == R_X86_64_GLOB_DAT));
                if (!relative && !symbolic)
                {
                    if (type != 0) unsupported++;
                    continue;
                }
                // Only file-backed PT_LOAD bytes may be overwritten; never map BSS into another section.
                var target = GetRelocationFileOffset(rela.r_offset, sizeof(ulong), $"{format} relocation target");
                var value = rela.r_addend;
                if (symbolic)
                {
                    if (symbolTable == null)
                        throw new InvalidDataException($"{format} requires a readable dynamic symbol table.");
                    if (sym >= (ulong)symbolTable.Length)
                        throw new InvalidDataException($"{format} references invalid symbol index {sym}.");
                    if (symbolTable[sym].st_shndx == 0)
                    {
                        // Imported addresses need the runtime linker; do not substitute a bogus zero address.
                        unresolved++;
                        continue;
                    }
                    // x86-64 GLOB_DAT uses S; ARM64 GLOB_DAT and ABS64 use S + A.
                    value = elfHeader.e_machine == EM_X86_64 && type == R_X86_64_GLOB_DAT
                        ? symbolTable[sym].st_value
                        : unchecked(value + symbolTable[sym].st_value);
                }
                Position = target;
                Write(value); // Disk ELF addresses use a zero load bias. Memory dumps bypass this path.
                applied++;
            }
            Console.WriteLine($"{format}: {total} decoded, {applied} applied, {unresolved} unresolved imports, {unsupported} unsupported types.");
        }

        private ulong GetRelocationFileOffset(ulong address, ulong size, string context)
        {
            foreach (var segment in programSegment.Where(x => x.p_type == PT_LOAD))
            {
                if (address < segment.p_vaddr) continue;
                var delta = address - segment.p_vaddr;
                if (delta > segment.p_filesz || size > segment.p_filesz - delta) continue;
                if (segment.p_offset > Length || delta > Length - segment.p_offset) continue;
                var offset = segment.p_offset + delta;
                if (size <= Length - offset) return offset;
            }
            throw new InvalidDataException($"{context} at VA 0x{address:X} (size 0x{size:X}) is outside file-backed PT_LOAD data.");
        }

        private bool CheckProtection()
        {
            try
            {
                //.init_proc
                if (dynamicSection.Any(x => x.d_tag == DT_INIT))
                {
                    Console.WriteLine("INFO: ELF initializer found (DT_INIT).");
                }
                //JNI_OnLoad
                ulong dynstrOffset = MapVATR(dynamicSection.First(x => x.d_tag == DT_STRTAB).d_un);
                foreach (var symbol in symbolTable)
                {
                    var name = ReadStringToNull(dynstrOffset + symbol.st_name);
                    switch (name)
                    {
                        case "JNI_OnLoad":
                            Console.WriteLine("INFO: JNI_OnLoad export found.");
                            break;
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
                Position = elfHeader.e_phoff + i * 56u + 8u;
                var phdr = programSegment[i];
                phdr.p_offset = phdr.p_vaddr;
                Write(phdr.p_offset);
                phdr.p_vaddr += ImageBase;
                Write(phdr.p_vaddr);
                Position += 8;
                phdr.p_filesz = phdr.p_memsz;
                Write(phdr.p_filesz);
            }
        }

        private void FixedDynamicSection()
        {
            for (uint i = 0; i < dynamicSection.Length; i++)
            {
                Position = pt_dynamic.p_offset + i * 16 + 8;
                var dyn = dynamicSection[i];
                switch (dyn.d_tag)
                {
                    case DT_PLTGOT:
                    case DT_HASH:
                    case DT_STRTAB:
                    case DT_SYMTAB:
                    case DT_RELA:
                    case DT_ANDROID_RELA:
                    case DT_INIT:
                    case DT_FINI:
                    case DT_REL:
                    case DT_JMPREL:
                    case DT_INIT_ARRAY:
                    case DT_FINI_ARRAY:
                        dyn.d_un += ImageBase;
                        Write(dyn.d_un);
                        break;
                }
            }
        }

        public override SectionHelper GetSectionHelper(int methodCount, int typeDefinitionsCount, int imageCount)
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
            var sectionHelper = new SectionHelper(this, methodCount, typeDefinitionsCount, metadataUsagesCount, imageCount);
            sectionHelper.SetSection(SearchSectionType.Exec, exec);
            sectionHelper.SetSection(SearchSectionType.Data, data);
            sectionHelper.SetSection(SearchSectionType.Bss, data);
            return sectionHelper;
        }
    }
}
