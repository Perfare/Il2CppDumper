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

        public void SetSection(SearchSectionType type, params SearchSection[] secs)
        {
            SetSection(type, secs.ToList());
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
            if (il2Cpp.Version >= 24.2)
            {
                return FindCodeRegistration2019();
            }
            return FindCodeRegistrationOld();
        }

        public ulong FindMetadataRegistration()
        {
            if (il2Cpp.Version < 19)
            {
                return 0;
            }
            if (il2Cpp.Version >= 27)
            {
                return FindMetadataRegistrationV21();
            }
            return FindMetadataRegistrationOld();
        }

        private ulong FindCodeRegistrationOld()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadIntPtr() == methodCount)
                    {
                        try
                        {
                            var pointer = il2Cpp.MapVATR(il2Cpp.ReadUIntPtr());
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
                    il2Cpp.Position = addr + il2Cpp.PointerSize;
                }
            }

            return 0ul;
        }

        private ulong FindMetadataRegistrationOld()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadIntPtr() == typeDefinitionsCount)
                    {
                        try
                        {
                            il2Cpp.Position += il2Cpp.PointerSize * 2;
                            var pointer = il2Cpp.MapVATR(il2Cpp.ReadUIntPtr());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, maxMetadataUsages);
                                if (CheckPointerRangeBssVa(pointers))
                                {
                                    return addr - il2Cpp.PointerSize * 12 - section.offset + section.address;
                                }
                            }
                        }
                        catch
                        {
                            // ignored
                        }
                    }
                    il2Cpp.Position = addr + il2Cpp.PointerSize;
                }
            }

            return 0ul;
        }

        private ulong FindMetadataRegistrationV21()
        {
            foreach (var section in data)
            {
                il2Cpp.Position = section.offset;
                while (il2Cpp.Position < section.offsetEnd)
                {
                    var addr = il2Cpp.Position;
                    if (il2Cpp.ReadIntPtr() == typeDefinitionsCount)
                    {
                        il2Cpp.Position += il2Cpp.PointerSize;
                        if (il2Cpp.ReadIntPtr() == typeDefinitionsCount)
                        {
                            var pointer = il2Cpp.MapVATR(il2Cpp.ReadUIntPtr());
                            if (CheckPointerRangeDataRa(pointer))
                            {
                                var pointers = il2Cpp.ReadClassArray<ulong>(pointer, typeDefinitionsCount);
                                if (il2Cpp is ElfBase)
                                {
                                    if (CheckPointerRangeExecVa(pointers))
                                    {
                                        return addr - il2Cpp.PointerSize * 10 - section.offset + section.address;
                                    }
                                }
                                else
                                {
                                    if (CheckPointerRangeDataVa(pointers))
                                    {
                                        return addr - il2Cpp.PointerSize * 10 - section.offset + section.address;
                                    }
                                }
                            }
                        }
                    }
                    il2Cpp.Position = addr + il2Cpp.PointerSize;
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

        private bool CheckPointerRangeDataVa(ulong[] pointers)
        {
            return pointers.All(x => data.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private bool CheckPointerRangeBssVa(ulong[] pointers)
        {
            return pointers.All(x => bss.Any(y => x >= y.address && x <= y.addressEnd));
        }

        private static readonly byte[] featureBytes2019 = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x6C, 0x69, 0x62, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
        private static readonly byte[] featureBytes2020dot2 = { 0x41, 0x73, 0x73, 0x65, 0x6D, 0x62, 0x6C, 0x79, 0x2D, 0x43, 0x53, 0x68, 0x61, 0x72, 0x70, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };

        private ulong FindCodeRegistration2019()
        {
            var featureBytes = il2Cpp.Version >= 27 ? featureBytes2020dot2 : featureBytes2019;
            var secs = data;
            if (il2Cpp is ElfBase)
            {
                secs = exec;
            }
            foreach (var sec in secs)
            {
                il2Cpp.Position = sec.offset;
                var buff = il2Cpp.ReadBytes((int)(sec.offsetEnd - sec.offset));
                foreach (var index in buff.Search(featureBytes))
                {
                    var va = (ulong)index + sec.address;
                    foreach (var dataSec in data)
                    {
                        il2Cpp.Position = dataSec.offset;
                        while (il2Cpp.Position < dataSec.offsetEnd)
                        {
                            var offset = il2Cpp.Position;
                            if (il2Cpp.ReadUIntPtr() == va)
                            {
                                var va2 = offset - dataSec.offset + dataSec.address;
                                foreach (var dataSec2 in data)
                                {
                                    il2Cpp.Position = dataSec2.offset;
                                    while (il2Cpp.Position < dataSec2.offsetEnd)
                                    {
                                        var offset2 = il2Cpp.Position;
                                        if (il2Cpp.ReadUIntPtr() == va2)
                                        {
                                            var va3 = offset2 - dataSec2.offset + dataSec2.address;
                                            foreach (var dataSec3 in data)
                                            {
                                                il2Cpp.Position = dataSec3.offset;
                                                while (il2Cpp.Position < dataSec3.offsetEnd)
                                                {
                                                    var offset3 = il2Cpp.Position;
                                                    if (il2Cpp.ReadUIntPtr() == va3)
                                                    {
                                                        var offset4 = offset3 - dataSec3.offset + dataSec3.address;
                                                        return offset4 - il2Cpp.PointerSize * 13;
                                                    }
                                                }
                                            }

                                        }
                                        il2Cpp.Position = offset2 + il2Cpp.PointerSize;
                                    }
                                }
                            }
                            il2Cpp.Position = offset + il2Cpp.PointerSize;
                        }
                    }
                }
            }
            return 0ul;
        }
    }
}
