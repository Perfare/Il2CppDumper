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
        public Dictionary<string, elf_32_shdr> sectionWithName;
        List<elf_32_shdr> sections;

        public Elf(Stream stream) : base(stream)
        {
            elf_header = new elf_header();
            elf_header.m_dwFormat = ReadUInt32();
            if (elf_header.m_dwFormat != 0x464c457f)
            {
                throw new Exception("ERROR: il2cpp lib provided is not a valid ELF file.");
            }
            elf_header.m_arch = ReadByte();
            elf_header.m_endian = ReadByte();
            elf_header.m_version = ReadByte();
            elf_header.m_osabi = ReadByte();
            elf_header.m_osabi_ver = ReadByte();
            elf_header.e_pad = ReadBytes(7);
            elf_header.e_type = ReadUInt16();
            elf_header.e_machine = ReadUInt16();
            elf_header.e_version = ReadUInt32();
            if (elf_header.m_arch == 1)//32
            {
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
            }
            else//64
            {
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
            }
            GetSectionWithName();
        }

        private void GetSectionWithName()
        {
            try
            {
                var section_name_block_off = (int)elf_header.e_shoff + (elf_header.e_shentsize * elf_header.e_shtrndx);
                if (elf_header.m_arch == 1)//32
                {
                    Position = section_name_block_off + 2 * 4 + 4 + 4;
                    section_name_block_off = ReadInt32();
                }
                else//Hmm...
                {
                    Position = section_name_block_off + 2 * 4 + 8 + 8;
                    section_name_block_off = ReadInt32();
                }
                var sectionWithNametmp = new Dictionary<string, elf_32_shdr>();
                var sectionstmp = new List<elf_32_shdr>();
                for (int i = 0; i < elf_header.e_shnum; i++)
                {
                    var section = GetSection(i);
                    sectionWithNametmp.Add(ReadStringToNull(section_name_block_off + section.sh_name), section);
                    sectionstmp.Add(section);
                }
                sectionWithName = sectionWithNametmp;
                sections = sectionstmp;
            }
            catch
            {
                Console.WriteLine("ERROR: Unable to get section.");
            }
        }

        private elf_32_shdr GetSection(int iSection)
        {
            return ReadClass<elf_32_shdr>((int)elf_header.e_shoff + (elf_header.e_shentsize * iSection));
        }

        public uint MapVATR(uint uiAddr)
        {
            if (sections == null)
                return uiAddr;
            elf_32_shdr pFirstSec = sections[0];
            if (uiAddr < pFirstSec.sh_addr)
                return 0;
            for (int i = 1; i < elf_header.e_shnum; ++i)
            {
                elf_32_shdr pSection = sections[i];
                if (pSection.sh_addr > uiAddr)
                {
                    elf_32_shdr pRetSec = sections[i - 1];
                    uint uiResOffset = uiAddr - pRetSec.sh_addr;
                    return pRetSec.sh_offset + uiResOffset;
                }
            }
            elf_32_shdr pRetSec2 = sections[elf_header.e_shnum - 1];
            uint uiResOffset2 = uiAddr - pRetSec2.sh_addr;
            return pRetSec2.sh_offset + uiResOffset2;
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
