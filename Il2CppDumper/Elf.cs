using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class Elf : MyBinaryReader
    {
        public elf_header elf_header;
        public program_header_table[] program_table_element;

        public Elf(Stream stream) : base(stream)
        {
            elf_header = new elf_header();
            elf_header.m_dwFormat = ReadUInt32();
            if (elf_header.m_dwFormat != 0x464c457f)
            {
                throw new Exception("ERROR: il2cpp lib provided is not a valid ELF file.");
            }
            elf_header.m_arch = ReadByte();
            if (elf_header.m_arch == 2)//64
            {
                throw new Exception("ERROR: 64 bit so files are not supported.");
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

        public uint MapVATR(uint uiAddr)
        {
            var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= (x.p_vaddr + x.p_memsz));
            return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
        }

        public T MapVATR<T>(uint uiAddr) where T : new()
        {
            return ReadClass<T>(MapVATR(uiAddr));
        }

        public T[] MapVATR<T>(uint uiAddr, int count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(uiAddr), count);
        }
    }
}
