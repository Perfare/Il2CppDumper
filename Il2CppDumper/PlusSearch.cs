using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class PlusSearch
    {
        private class Section
        {
            public ulong start;
            public ulong end;
            public ulong address;
        }

        private Il2Cpp il2Cpp;
        private int methodCount;
        private int typeDefinitionsCount;
        private long maxMetadataUsages;
        private List<Section> search = new List<Section>();
        private List<Section> pointerRange1 = new List<Section>();
        private List<Section> pointerRange2 = new List<Section>();

        public PlusSearch(Il2Cpp il2Cpp, int methodCount, int typeDefinitionsCount, long maxMetadataUsages)
        {
            this.il2Cpp = il2Cpp;
            this.methodCount = methodCount;
            this.typeDefinitionsCount = typeDefinitionsCount;
            this.maxMetadataUsages = maxMetadataUsages;
        }

        public void SetSearch(params MachoSection64Bit[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.offset,
                        end = section.offset + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetSearch(params MachoSection[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.offset,
                        end = section.offset + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetSearch(params Elf32_Shdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.sh_offset,
                        end = section.sh_offset + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetSearch(params Elf64_Shdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.sh_offset,
                        end = section.sh_offset + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetSearch(params Elf32_Phdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.p_offset,
                        end = section.p_offset + section.p_filesz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetSearch(params Elf64_Phdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.p_offset,
                        end = section.p_offset + section.p_filesz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetSearch(ulong imageBase, params SectionHeader[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    search.Add(new Section
                    {
                        start = section.PointerToRawData,
                        end = section.PointerToRawData + section.SizeOfRawData,
                        address = section.VirtualAddress + imageBase
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params MachoSection64Bit[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.offset,
                        end = section.offset + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params MachoSection[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.offset,
                        end = section.offset + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params Elf32_Shdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.sh_offset,
                        end = section.sh_offset + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params Elf64_Shdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.sh_offset,
                        end = section.sh_offset + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params Elf32_Phdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.p_offset,
                        end = section.p_offset + section.p_filesz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetPointerRangeFirst(params Elf64_Phdr[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.p_offset,
                        end = section.p_offset + section.p_filesz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetPointerRangeFirst(ulong imageBase, params SectionHeader[] sections)
        {
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange1.Add(new Section
                    {
                        start = section.PointerToRawData,
                        end = section.PointerToRawData + section.SizeOfRawData,
                        address = section.VirtualAddress + imageBase
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params MachoSection64Bit[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.address,
                        end = section.address + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params MachoSection[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.address,
                        end = section.address + section.size,
                        address = section.address
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params Elf32_Shdr[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.sh_addr,
                        end = section.sh_addr + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params Elf64_Shdr[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.sh_addr,
                        end = section.sh_addr + section.sh_size,
                        address = section.sh_addr
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params Elf32_Phdr[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.p_vaddr,
                        end = section.p_vaddr + section.p_memsz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetPointerRangeSecond(uint dumpAddr, params Elf32_Phdr[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.p_vaddr + dumpAddr,
                        end = section.p_vaddr + dumpAddr + section.p_memsz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetPointerRangeSecond(params Elf64_Phdr[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.p_vaddr,
                        end = section.p_vaddr + section.p_memsz,
                        address = section.p_vaddr
                    });
                }
            }
        }

        public void SetPointerRangeSecond(ulong imageBase, params SectionHeader[] sections)
        {
            pointerRange2.Clear();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    pointerRange2.Add(new Section
                    {
                        start = section.VirtualAddress,
                        end = section.VirtualAddress + section.VirtualSize + imageBase,
                        address = section.VirtualAddress + imageBase
                    });
                }
            }
        }

        public ulong FindCodeRegistration()
        {
            foreach (var section in search)
            {
                il2Cpp.Position = section.start;
                while ((ulong)il2Cpp.Position < section.end)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadUInt32() == methodCount)
                    {
                        try
                        {
                            uint pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt32());
                            if (CheckPointerRangeFirst(pointer))
                            {
                                var sign = il2Cpp.Position;
                                var pointers = il2Cpp.ReadClassArray<uint>(pointer, methodCount);
                                if (CheckPointerRangeSecond(pointers))
                                {
                                    return (ulong)addr - section.start + section.address; //VirtualAddress
                                }
                                il2Cpp.Position = sign;
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                }
            }

            return 0ul;
        }

        public ulong FindCodeRegistration64Bit()
        {
            foreach (var section in search)
            {
                il2Cpp.Position = section.start;
                while ((ulong)il2Cpp.Position < section.end)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt64() == methodCount)
                    {
                        try
                        {
                            ulong pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt64());
                            if (CheckPointerRangeFirst(pointer))
                            {
                                var sign = il2Cpp.Position;
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, methodCount);
                                if (CheckPointerRangeSecond(pointers))
                                {
                                    return (ulong)addr - section.start + section.address; //VirtualAddress
                                }
                                il2Cpp.Position = sign;
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                }
            }

            return 0ul;
        }

        public ulong FindMetadataRegistration()
        {
            foreach (var section in search)
            {
                il2Cpp.Position = section.start;
                while ((ulong)il2Cpp.Position < section.end)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt32() == typeDefinitionsCount)
                    {
                        try
                        {
                            var sign = il2Cpp.Position;
                            il2Cpp.Position += 8;
                            uint pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt32());
                            if (CheckPointerRangeFirst(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<uint>(pointer, maxMetadataUsages);
                                if (CheckPointerRangeSecond(pointers))
                                {
                                    return (ulong)addr - 48ul - section.start + section.address; //VirtualAddress
                                }
                            }
                            il2Cpp.Position = sign;
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                }
            }

            return 0ul;
        }

        public ulong FindMetadataRegistration64Bit()
        {
            foreach (var section in search)
            {
                il2Cpp.Position = section.start;
                while ((ulong)il2Cpp.Position < section.end)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt64() == typeDefinitionsCount)
                    {
                        try
                        {
                            var sign = il2Cpp.Position;
                            il2Cpp.Position += 16;
                            ulong pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt64());
                            if (CheckPointerRangeFirst(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, maxMetadataUsages);
                                if (CheckPointerRangeSecond(pointers))
                                {
                                    return (ulong)addr - 96ul - section.start + section.address; //VirtualAddress
                                }
                            }
                            il2Cpp.Position = sign;
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                }
            }

            return 0ul;
        }

        private bool CheckPointerRangeFirst(ulong pointer)
        {
            return pointerRange1.Any(x => pointer >= x.start && pointer <= x.end);
        }

        private bool CheckPointerRangeSecond(ulong[] pointers)
        {
            return pointers.All(x => pointerRange2.Any(y => x >= y.start && x <= y.end));
        }

        private bool CheckPointerRangeSecond(uint[] pointers)
        {
            return pointers.All(x => pointerRange2.Any(y => x >= y.start && x <= y.end));
        }
    }
}
