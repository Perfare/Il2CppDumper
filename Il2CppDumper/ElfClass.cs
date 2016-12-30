using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class elf_header
    {
        // 0x7f followed by ELF in ascii
        public uint m_dwFormat;

        // 1 - 32 bit
        // 2 - 64 bit
        public byte m_arch;

        // 1 - little endian
        // 2 - big endian
        public byte m_endian;

        // 1 is original elf format
        public byte m_version;

        // set based on OS, refer to OSABI enum
        public byte m_osabi;

        // refer to elf documentation
        public byte m_osabi_ver;

        // unused
        public byte[] e_pad;//byte[7]

        // 1 - relocatable
        // 2 - executable
        // 3 - shared
        // 4 - core
        public ushort e_type;

        // refer to isa enum
        public ushort e_machine;

        public uint e_version;

        //全部定义为64位
        public ulong e_entry;
        public ulong e_phoff;
        public ulong e_shoff;
        public uint e_flags;
        public ushort e_ehsize;
        public ushort e_phentsize;
        public ushort e_phnum;
        public ushort e_shentsize;
        public ushort e_shnum;
        public ushort e_shtrndx;
    }

    class elf_32_shdr
    {
        public uint sh_name;
        public uint sh_type;
        public uint sh_flags;
        public uint sh_addr;
        public uint sh_offset;
        public uint sh_size;
        public uint sh_link;
        public uint sh_info;
        public uint sh_addralign;
        public uint sh_entsize;
    }
}
