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

        //默认编译器
        /*
         * LDR R1, [R1,R2]
         * ADD R0, R12, R2
         * ADD R2, R3, R2
         */
        private static readonly byte[] ARMFeatureBytesv21 = { 0x02, 0x10, 0x91, 0xE7, 0x02, 0x00, 0x8C, 0xE0, 0x02, 0x20, 0x83, 0xE0 };
        /*
         * LDR R1, [PC,R1]
         * ADD R0, PC, R0
         * ADD R2, PC, R2
         */
        private static readonly byte[] ARMFeatureBytesv24 = { 0x01, 0x10, 0x9F, 0xE7, 0x00, 0x00, 0x8F, 0xE0, 0x02, 0x20, 0x8F, 0xE0 };
        //TODO
        private static readonly byte[] X86FeatureBytesv21 = { 0x02, 0x10, 0x91, 0xE7, 0x02, 0x00, 0x8C, 0xE0, 0x02, 0x20, 0x83, 0xE0 };
        //TODO
        private static readonly byte[] X86FeatureBytesv24 = { 0x01, 0x10, 0x9F, 0xE7, 0x00, 0x00, 0x8F, 0xE0, 0x02, 0x20, 0x8F, 0xE0 };

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
            var execs = program_table.Where(x => x.p_type == 1u && (x.p_flags & 1) == 1).ToArray();
            var resultList = new List<int>();
            byte[] featureBytes = null;
            if (version < 24f)
            {
                featureBytes = elf_header.e_machine == 40 ? ARMFeatureBytesv21 : X86FeatureBytesv21;
            }
            else if (version >= 24f)
            {
                featureBytes = elf_header.e_machine == 40 ? ARMFeatureBytesv24 : X86FeatureBytesv24;
            }
            foreach (var exec in execs)
            {
                Position = exec.p_offset;
                var buff = ReadBytes((int)exec.p_filesz);
                resultList.AddRange(buff.IndicesOf(featureBytes));
            }
            if (resultList.Count == 1)
            {
                uint codeRegistration = 0;
                uint metadataRegistration = 0;
                if (version < 24f)
                {
                    if (elf_header.e_machine == 40)
                    {
                        var result = (uint)resultList[0];
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
                    if (elf_header.e_machine == 40)
                    {
                        var result = (uint)resultList[0];
                        Position = result + 0x14;
                        codeRegistration = ReadUInt32() + result + 0xcu;
                        Position = result + 0x10;
                        var ptr = ReadUInt32() + result + 0x8;
                        Position = MapVATR(ptr);
                        metadataRegistration = ReadUInt32();
                    }
                }
                return AutoInit(codeRegistration, metadataRegistration);
            }
            return false;
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
    }
}