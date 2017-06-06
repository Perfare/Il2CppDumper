using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class Elf : Il2CppGeneric
    {
        private elf_header elf_header;
        private program_header_table[] program_table_element;
        private static byte[] ARMFeatureBytes = { 0x1c, 0x0, 0x9f, 0xe5, 0x1c, 0x10, 0x9f, 0xe5, 0x1c, 0x20, 0x9f, 0xe5 };
        private static byte[] X86FeatureBytes = { 0x55, 0x89, 0xE5, 0x53, 0x83, 0xE4, 0xF0, 0x83, 0xEC, 0x20, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B };


        public Elf(Stream stream, int version, long maxmetadataUsages) : base(stream)
        {
            this.version = version;
            this.maxmetadataUsages = maxmetadataUsages;
            @namespace = "Il2CppDumper.v" + version + ".";
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
        }

        public Elf(Stream stream, ulong codeRegistration, ulong metadataRegistration, int version, long maxmetadataUsages) : this(stream, version, maxmetadataUsages)
        {
            Init(codeRegistration, metadataRegistration);
        }

        protected override dynamic MapVATR(dynamic uiAddr)
        {
            var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= (x.p_vaddr + x.p_memsz));
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        private bool Searchv20()
        {
            throw new NotSupportedException("未完工");
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
                            var buff = ReadBytes(16);
                            if (X86FeatureBytes.SequenceEqual(buff))
                            {
                                Position = i + 0x18;
                                var subaddr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = subaddr + 0x2C;
                                var codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Position = subaddr + 0x22;
                                var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = MapVATR(ptr);
                                var metadataRegistration = ReadUInt32();
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
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
    }
}
