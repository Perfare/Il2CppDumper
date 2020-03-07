using System;
using System.Collections.Generic;
using System.Linq;

namespace Il2CppDumper
{
    public class PlusSearch
    {
        private Il2Cpp il2Cpp;
        private int methodCount;
        private int typeDefinitionsCount;
        private long maxMetadataUsages;
        private List<SearchSection> exec;
        private List<SearchSection> data;
        private List<SearchSection> bss;

        public PlusSearch(Il2Cpp il2Cpp, int methodCount, int typeDefinitionsCount, long maxMetadataUsages)
        {
            this.il2Cpp = il2Cpp;
            this.methodCount = methodCount;
            this.typeDefinitionsCount = typeDefinitionsCount;
            this.maxMetadataUsages = maxMetadataUsages;
        }

        public void SetSection(SearchSectionType type, Elf32_Phdr[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.p_offset,
                        offsetEnd = section.p_offset + section.p_filesz,
                        address = section.p_vaddr,
                        addressEnd = section.p_vaddr + section.p_memsz
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, Elf64_Phdr[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.p_offset,
                        offsetEnd = section.p_offset + section.p_filesz,
                        address = section.p_vaddr,
                        addressEnd = section.p_vaddr + section.p_memsz
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, MachoSection[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.offset,
                        offsetEnd = section.offset + section.size,
                        address = section.addr,
                        addressEnd = section.addr + section.size
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, MachoSection64Bit[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.offset,
                        offsetEnd = section.offset + section.size,
                        address = section.addr,
                        addressEnd = section.addr + section.size
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, ulong imageBase, SectionHeader[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.PointerToRawData,
                        offsetEnd = section.PointerToRawData + section.SizeOfRawData,
                        address = section.VirtualAddress + imageBase,
                        addressEnd = section.VirtualAddress + section.VirtualSize + imageBase
                    });
                }
            }
            SetSection(type, secs);
        }

        public void SetSection(SearchSectionType type, params NSOSegmentHeader[] sections)
        {
            var secs = new List<SearchSection>();
            foreach (var section in sections)
            {
                if (section != null)
                {
                    secs.Add(new SearchSection
                    {
                        offset = section.FileOffset,
                        offsetEnd = section.FileOffset + section.DecompressedSize,
                        address = section.MemoryOffset,
                        addressEnd = section.MemoryOffset + section.DecompressedSize
                    });
                }
            }
            SetSection(type, secs);
        }

        private void SetSection(SearchSectionType type, List<SearchSection> secs)
        {
            switch (type)
            {
                case SearchSectionType.Exec:
                    exec = secs;
                    break;
                case SearchSectionType.Data:
                    data = secs;
                    break;
                case SearchSectionType.Bss:
                    bss = secs;
                    break;
            }
        }

        public ulong FindCodeRegistration()
        {
            if (il2Cpp.Is32Bit)
            {
                if (il2Cpp.Version >= 24.2)
                {
                    return FindCodeRegistration32Bit2019();
                }
                return FindCodeRegistration32Bit();
            }
            if (il2Cpp.Version >= 24.2)
            {
                return FindCodeRegistration64Bit2019();
            }
            return FindCodeRegistration64Bit();
        }

        public ulong FindMetadataRegistration()
        {
            if (il2Cpp.Is32Bit)
            {
                return FindMetadataRegistration32Bit();
            }
            return FindMetadataRegistration64Bit();
        }

        private ulong FindCodeRegistration32Bit()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadUInt32() == methodCount)
                    {
                        try
                        {
                            var pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt32());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<uint>(pointer, methodCount);
                                if (CheckPointerRangeExecVa(pointers))
                                {
                                    return addr - section.offset + section.address;
                                }
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                    il2Cpp.Position = addr + 4;
                }
            }

            return 0ul;
        }

        private ulong FindCodeRegistration64Bit()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt64() == methodCount)
                    {
                        try
                        {
                            ulong pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt64());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, methodCount);
                                if (CheckPointerRangeExecVa(pointers))
                                {
                                    return addr - section.offset + section.address;
                                }
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                    il2Cpp.Position = addr + 8;
                }
            }

            return 0ul;
        }

        private ulong FindMetadataRegistration32Bit()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt32() == typeDefinitionsCount)
                    {
                        try
                        {
                            il2Cpp.Position += 8;
                            var pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt32());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<uint>(pointer, maxMetadataUsages);
                                if (CheckPointerRangeBssVa(pointers))
                                {
                                    return addr - 48ul - section.offset + section.address;
                                }
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                    il2Cpp.Position = addr + 4;
                }
            }

            return 0ul;
        }

        private ulong FindMetadataRegistration64Bit()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadInt64() == typeDefinitionsCount)
                    {
                        try
                        {
                            il2Cpp.Position += 16;
                            ulong pointer = il2Cpp.MapVATR(il2Cpp.ReadUInt64());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, maxMetadataUsages);
                                if (CheckPointerRangeBssVa(pointers))
                                {
                                    return addr - 96ul - section.offset + section.address;
                                }
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                    il2Cpp.Position = addr + 8;
                }
            }

            return 0ul;
        }

        private bool CheckPointerRangeDataRa(ulong pointer)
        {
            return data.Any(x => pointer >= x.offset && pointer <= x.offsetEnd);
        }

        private bool CheckPointerRangeExecVa(ulong[] pointers)
        {
            return pointers.All(x => exec.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private bool CheckPointerRangeExecVa(uint[] pointers)
        {
            return pointers.All(x => exec.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private bool CheckPointerRangeBssVa(ulong[] pointers)
        {
            return pointers.All(x => bss.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private bool CheckPointerRangeBssVa(uint[] pointers)
        {
            return pointers.All(x => bss.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private static readonly byte[] featureBytes2019 = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x6C, 0x69, 0x62, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };

        private ulong FindCodeRegistration32Bit2019()
        {
            var secs = il2Cpp is Elf ? exec : data;
            foreach (var sec in secs)
            {
                il2Cpp.Position = sec.offset;
                var buff = il2Cpp.ReadBytes((int)(sec.offsetEnd - sec.offset));
                foreach (var index in buff.Search(featureBytes2019))
                {
                    var va = (ulong)index + sec.address;
                    foreach (var dataSec in data)
                    {
                        il2Cpp.Position = dataSec.offset;
                        while (il2Cpp.Position < dataSec.offsetEnd)
                        {
                            var offset = il2Cpp.Position;
                            if (il2Cpp.ReadUInt32() == va)
                            {
                                var va2 = offset - dataSec.offset + dataSec.address;
                                foreach (var dataSec2 in data)
                                {
                                    il2Cpp.Position = dataSec2.offset;
                                    while (il2Cpp.Position < dataSec2.offsetEnd)
                                    {
                                        var offset2 = il2Cpp.Position;
                                        if (il2Cpp.ReadUInt32() == va2)
                                        {
                                            var va3 = offset2 - dataSec2.offset + dataSec2.address;
                                            foreach (var dataSec3 in data)
                                            {
                                                il2Cpp.Position = dataSec3.offset;
                                                while (il2Cpp.Position < dataSec3.offsetEnd)
                                                {
                                                    var offset3 = il2Cpp.Position;
                                                    if (il2Cpp.ReadUInt32() == va3)
                                                    {
                                                        var offset4 = offset3 - dataSec3.offset + dataSec3.address;
                                                        if (il2Cpp.Version > 24.2f)
                                                        {
                                                            return offset4 - 60ul;
                                                        }
                                                        return offset4 - 52ul;
                                                    }
                                                }
                                            }

                                        }
                                        il2Cpp.Position = offset2 + 4;
                                    }
                                }
                            }
                            il2Cpp.Position = offset + 4;
                        }
                    }
                }
            }
            return 0ul;
        }

        private ulong FindCodeRegistration64Bit2019()
        {
            var secs = il2Cpp is Elf64 ? exec : data;
            foreach (var sec in secs)
            {
                il2Cpp.Position = sec.offset;
                var buff = il2Cpp.ReadBytes((int)(sec.offsetEnd - sec.offset));
                foreach (var index in buff.Search(featureBytes2019))
                {
                    var va = (ulong)index + sec.address;
                    foreach (var dataSec in data)
                    {
                        il2Cpp.Position = dataSec.offset;
                        while (il2Cpp.Position < dataSec.offsetEnd)
                        {
                            var offset = il2Cpp.Position;
                            if (il2Cpp.ReadUInt64() == va)
                            {
                                var va2 = offset - dataSec.offset + dataSec.address;
                                foreach (var dataSec2 in data)
                                {
                                    il2Cpp.Position = dataSec2.offset;
                                    while (il2Cpp.Position < dataSec2.offsetEnd)
                                    {
                                        var offset2 = il2Cpp.Position;
                                        if (il2Cpp.ReadUInt64() == va2)
                                        {
                                            var va3 = offset2 - dataSec2.offset + dataSec2.address;
                                            foreach (var dataSec3 in data)
                                            {
                                                il2Cpp.Position = dataSec3.offset;
                                                while (il2Cpp.Position < dataSec3.offsetEnd)
                                                {
                                                    var offset3 = il2Cpp.Position;
                                                    if (il2Cpp.ReadUInt64() == va3)
                                                    {
                                                        var offset4 = offset3 - dataSec3.offset + dataSec3.address;
                                                        if (il2Cpp.Version > 24.2f)
                                                        {
                                                            return offset4 - 120ul;
                                                        }
                                                        return offset4 - 104ul;
                                                    }
                                                }
                                            }

                                        }
                                        il2Cpp.Position = offset2 + 8;
                                    }
                                }
                            }
                            il2Cpp.Position = offset + 8;
                        }
                    }
                }
            }
            return 0ul;
        }
    }
}
