using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class Elf : Il2Cpp
    {
        private elf_header elf_header;
        private program_header_table[] program_table_element;
        private static byte[] ARMFeatureBytes = { 0x1c, 0x0, 0x9f, 0xe5, 0x1c, 0x10, 0x9f, 0xe5, 0x1c, 0x20, 0x9f, 0xe5 };
        private static byte[] X86FeatureBytes1 = { 0x8D, 0x83 };//lea eax, X
        private static byte[] X86FeatureBytes2 = { 0x89, 0x44, 0x24, 0x04, 0x8D, 0x83 };//mov [esp+4], eax and lea eax, X
        public Dictionary<string, elf_32_shdr> sectionWithName;

        public Elf(Stream stream, int version, long maxmetadataUsages) : base(stream)
        {
            this.version = version;
            this.maxmetadataUsages = maxmetadataUsages;
            readas32bit = true;
            if (version < 21)
                Search = Searchv20;
            else
                Search = Searchv21;
            elf_header = new elf_header();
            elf_header.m_dwFormat = ReadUInt32();
            elf_header.m_arch = ReadByte();
            if (elf_header.m_arch == 2)//64
            {
                throw new Exception("ERROR: 64 bit not supported.");
            }
            elf_header.m_endian = ReadByte();
            elf_header.m_version = ReadByte();
            elf_header.m_osabi = ReadByte();
            elf_header.m_osabi_ver = ReadByte();
            elf_header.e_pad = ReadBytes(7);
            elf_header.e_type = ReadUInt16();
            elf_header.e_machine = ReadUInt16();
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
            program_table_element = ReadClassArray<program_header_table>(elf_header.e_phoff, elf_header.e_phnum);
            GetSectionWithName();
        }

        public Elf(Stream stream, ulong codeRegistration, ulong metadataRegistration, int version, long maxmetadataUsages) : this(stream, version, maxmetadataUsages)
        {
            Init(codeRegistration, metadataRegistration);
        }

        private void GetSectionWithName()
        {
            try
            {
                var section_name_block_off = (int)elf_header.e_shoff + (elf_header.e_shentsize * elf_header.e_shtrndx);
                Position = section_name_block_off + 2 * 4 + 4 + 4;
                section_name_block_off = ReadInt32();
                sectionWithName = new Dictionary<string, elf_32_shdr>();
                for (int i = 0; i < elf_header.e_shnum; i++)
                {
                    var section = ReadClass<elf_32_shdr>((int)elf_header.e_shoff + (elf_header.e_shentsize * i));
                    sectionWithName.Add(ReadStringToNull(section_name_block_off + section.sh_name), section);
                }
            }
            catch
            {
                Console.WriteLine("ERROR: Unable to get section.");
            }
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= (x.p_vaddr + x.p_memsz));
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        private bool Searchv20()
        {
            Console.WriteLine("ERROR: Auto mode not support this version.");
            return false;
        }

        private bool Searchv21()
        {
            //取.dynamic
            var dynamic = new elf_32_shdr();
            var PT_DYNAMIC = program_table_element.First(x => x.p_type == 2u);
            dynamic.sh_offset = PT_DYNAMIC.p_offset;
            dynamic.sh_size = PT_DYNAMIC.p_filesz;
            //从.dynamic获取_GLOBAL_OFFSET_TABLE_和.init_array
            uint _GLOBAL_OFFSET_TABLE_ = 0;
            var init_array = new elf_32_shdr();
            Position = dynamic.sh_offset;
            var dynamicend = dynamic.sh_offset + dynamic.sh_size;
            while (Position < dynamicend)
            {
                var tag = ReadInt32();
                if (tag == 3)//DT_PLTGOT
                {
                    _GLOBAL_OFFSET_TABLE_ = ReadUInt32();
                }
                else if (tag == 25)//DT_INIT_ARRAY
                {
                    init_array.sh_offset = MapVATR(ReadUInt32());
                }
                else if (tag == 27)//DT_INIT_ARRAYSZ
                {
                    init_array.sh_size = ReadUInt32();
                }
                else
                {
                    Position += 4;//skip
                }
            }
            if (_GLOBAL_OFFSET_TABLE_ != 0)
            {
                //从.init_array获取函数
                var addrs = ReadClassArray<uint>(init_array.sh_offset, (int)init_array.sh_size / 4);
                foreach (var i in addrs)
                {
                    if (i > 0)
                    {
                        Position = i;
                        if (elf_header.e_machine == 0x28)
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
                        else if (elf_header.e_machine == 0x3)
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
                                    uint metadataRegistration;
                                    if (temp == 0x838D)//lea
                                    {
                                        metadataRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                    }
                                    else//mov
                                    {
                                        var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                        Position = MapVATR(ptr);
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
            if (sectionWithName != null)
            {
                //处理重定向
                if (sectionWithName.ContainsKey(".dynsym") && sectionWithName.ContainsKey(".rel.dyn"))
                {
                    var dynsym = sectionWithName[".dynsym"];
                    var rel_dyn = sectionWithName[".rel.dyn"];
                    var dynamic_symbol_table = ReadClassArray<Elf32_Sym>(dynsym.sh_offset, dynsym.sh_size / 16);
                    var rel_dynend = rel_dyn.sh_offset + rel_dyn.sh_size;
                    Position = rel_dyn.sh_offset;
                    var writer = new BinaryWriter(BaseStream);
                    while (Position < rel_dynend)
                    {
                        var offset = ReadUInt32();
                        var type = ReadByte();
                        var index = ReadByte() | (ReadByte() << 8) | (ReadByte() << 16);
                        if (type == 2)
                        {
                            var dynamic_symbol = dynamic_symbol_table[index];
                            var position = Position;
                            writer.BaseStream.Position = offset;
                            writer.Write(dynamic_symbol.sym_value);
                            Position = position;
                        }
                    }
                }
                if (sectionWithName.ContainsKey(".data.rel.ro") && sectionWithName.ContainsKey(".text") && sectionWithName.ContainsKey(".bss"))
                {
                    var datarelro = sectionWithName[".data.rel.ro"];
                    var text = sectionWithName[".text"];
                    var bss = sectionWithName[".bss"];
                    elf_32_shdr datarelrolocal = null;
                    if (sectionWithName.ContainsKey(".data.rel.ro.local"))
                        datarelrolocal = sectionWithName[".data.rel.ro.local"];
                    uint codeRegistration = 0;
                    uint metadataRegistration = 0;
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
                    var pmetadataUsages = FindPointersAsc(maxmetadataUsages, datarelro, bss);
                    if (pmetadataUsages == 0 && datarelrolocal != null)
                        pmetadataUsages = FindPointersAsc(maxmetadataUsages, datarelrolocal, bss);
                    if (pmetadataUsages != 0)
                    {
                        metadataRegistration = FindReference(pmetadataUsages, datarelro);
                        if (metadataRegistration == 0 && datarelrolocal != null)
                            metadataRegistration = FindReference(pmetadataUsages, datarelrolocal);
                        if (metadataRegistration == 0)
                        {
                            pmetadataUsages = FindPointersDesc(maxmetadataUsages, datarelro, bss);
                            if (pmetadataUsages == 0 && datarelrolocal != null)
                                pmetadataUsages = FindPointersDesc(maxmetadataUsages, datarelrolocal, bss);
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
                    Console.WriteLine("ERROR: The necessary section is missing.");
                }
            }
            return false;
        }

        private uint FindPointersAsc(long readCount, elf_32_shdr search, elf_32_shdr range)
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
                    return search.sh_addr + (uint)add;//MapRATV
                }
            }
            return 0;
        }

        private uint FindPointersDesc(long readCount, elf_32_shdr search, elf_32_shdr range)
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
                    return (uint)(search.sh_addr + search.sh_size + add - 4 * readCount);//MapRATV
                }
            }
            return 0;
        }

        private uint FindReference(uint pointer, elf_32_shdr search)
        {
            var searchend = search.sh_offset + search.sh_size;
            Position = search.sh_offset;
            while (Position < searchend)
            {
                if (ReadUInt32() == pointer)
                {
                    return (uint)Position - search.sh_offset + search.sh_addr;//MapRATV
                }
            }
            return 0;
        }
    }
}