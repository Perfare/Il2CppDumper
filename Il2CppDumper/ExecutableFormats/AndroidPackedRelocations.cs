using System;
using System.Collections.Generic;
using System.IO;

namespace Il2CppDumper
{
    // Android's APS2 RELA format, as consumed by bionic's linker_reloc_iterators.h.
    // Keep decoding separate from applying relocations: writes move BinaryStream.Position.
    internal sealed class AndroidPackedRelocations
    {
        private const int GroupedByInfo = 1;
        private const int GroupedByOffsetDelta = 2;
        private const int GroupedByAddend = 4;
        private const int HasAddend = 8;
        private readonly byte[] data;
        private int position;

        private AndroidPackedRelocations(byte[] data)
        {
            this.data = data;
        }

        public static IEnumerable<Elf64_Rela> Decode(byte[] data, ulong maxRelocations)
        {
            return new AndroidPackedRelocations(data).ReadRelocations(maxRelocations);
        }

        private IEnumerable<Elf64_Rela> ReadRelocations(ulong maxRelocations)
        {
            if (data.Length < 4 || data[0] != 'A' || data[1] != 'P' || data[2] != 'S' || data[3] != '2')
                throw Invalid("missing APS2 signature");
            position = 4;
            var count = ReadSleb128();
            if (count < 0 || (ulong)count > maxRelocations)
                throw Invalid($"invalid relocation count {count}");
            var offset = ReadSleb128();
            if (offset < 0)
                throw Invalid("negative initial relocation offset");
            long addend = 0;

            for (long index = 0; index < count;)
            {
                var groupSize = ReadSleb128();
                var flags = ReadSleb128();
                if (groupSize <= 0 || groupSize > count - index)
                    throw Invalid($"invalid group size {groupSize} at relocation {index}");
                if (flags < 0 || (flags & ~15L) != 0 ||
                    ((flags & GroupedByAddend) != 0 && (flags & HasAddend) == 0))
                    throw Invalid($"invalid group flags 0x{flags:X}");

                var offsetDelta = (flags & GroupedByOffsetDelta) != 0 ? ReadSleb128() : 0;
                var info = (flags & GroupedByInfo) != 0 ? ReadSleb128() : 0;
                if ((flags & HasAddend) == 0)
                    addend = 0;
                else if ((flags & GroupedByAddend) != 0)
                    // This delta is applied once per group, not once per relocation.
                    addend = Add(addend, ReadSleb128());

                for (long i = 0; i < groupSize; i++)
                {
                    offset = Add(offset, (flags & GroupedByOffsetDelta) != 0 ? offsetDelta : ReadSleb128());
                    if (offset < 0)
                        throw Invalid("negative relocation offset");
                    if ((flags & GroupedByInfo) == 0)
                        info = ReadSleb128();
                    if ((flags & (HasAddend | GroupedByAddend)) == HasAddend)
                        addend = Add(addend, ReadSleb128());
                    yield return new Elf64_Rela
                    {
                        r_offset = (ulong)offset,
                        r_info = unchecked((ulong)info),
                        r_addend = unchecked((ulong)addend)
                    };
                }
                index += groupSize;
            }
        }

        private long ReadSleb128()
        {
            ulong value = 0;
            for (var shift = 0; shift <= 63; shift += 7)
            {
                if (position >= data.Length)
                    throw Invalid("truncated SLEB128 value");
                var next = data[position++];
                if (shift == 63 && next != 0 && next != 0x7f)
                    throw Invalid("SLEB128 value exceeds 64 bits");
                value |= (ulong)(next & 0x7f) << shift;
                if ((next & 0x80) == 0)
                {
                    if (shift < 63 && (next & 0x40) != 0)
                        value |= ulong.MaxValue << (shift + 7);
                    return unchecked((long)value);
                }
            }
            throw Invalid("SLEB128 value exceeds 64 bits");
        }

        private long Add(long value, long delta)
        {
            try
            {
                return checked(value + delta);
            }
            catch (OverflowException)
            {
                throw Invalid("offset or addend overflow");
            }
        }

        private InvalidDataException Invalid(string message) =>
            new($"Invalid Android APS2 relocation data at byte 0x{position:X}: {message}.");
    }
}
