using System.Buffers.Binary;
using Il2CppDumper;
using static Il2CppDumper.ElfConstants;

static class ElfRelocationTests
{
    private const long Base = 0x10000;

    public static void Run(Action<string, Action> check)
    {
        foreach (var machine in new[] { EM_AARCH64, EM_X86_64 })
        foreach (var flags in new[] { 0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15 })
        {
            check($"APS2 ELF64 machine {machine}, group flags {flags}", () =>
            {
                var relativeType = machine == EM_AARCH64 ? R_AARCH64_RELATIVE : R_X86_64_RELATIVE;
                var values = new List<long> { 2, Base + 0x5f8, 2, flags };
                if ((flags & 2) != 0) values.Add(8);
                if ((flags & 1) != 0) values.Add(relativeType);
                if ((flags & 12) == 12) values.Add(0x1234);
                for (var i = 0; i < 2; i++)
                {
                    if ((flags & 2) == 0) values.Add(8);
                    if ((flags & 1) == 0) values.Add(relativeType);
                    if ((flags & 12) == 8) values.Add(i == 0 ? 0x1234 : -4);
                }
                var bytes = Elf(Packed(values.ToArray()), machine: machine);
                var log = Load(bytes, elf =>
                {
                    Expect(elf, 0x600, (flags & 8) == 0 ? 0UL : 0x1234UL);
                    Expect(elf, 0x608, (flags & 8) == 0 ? 0UL : (flags & 4) != 0 ? 0x1234UL : 0x1230UL);
                });
                Require(log.Contains("Android APS2 RELA: 2 decoded, 2 applied"), log);
            });
        }

        check("APS2 group transitions, negative offsets and addend reset", () =>
        {
            var data = Packed(5, Base + 0x600,
                2, 15, 8, R_AARCH64_RELATIVE, 100, // same addend for both entries
                1, 8, -16, R_AARCH64_RELATIVE, -20, // carry addend, move backwards
                1, 3, 24, R_AARCH64_RELATIVE, // no addend resets to zero
                1, 15, 8, R_AARCH64_RELATIVE, 7);
            Load(Elf(data), elf =>
            {
                Expect(elf, 0x600, 80);
                Expect(elf, 0x608, 100);
                Expect(elf, 0x610, 100);
                Expect(elf, 0x618, 0);
                Expect(elf, 0x620, 7);
            });
        });

        foreach (var machine in new[] { EM_AARCH64, EM_X86_64 })
        {
            check($"ordinary RELA and APS2 coexist, machine {machine}", () =>
            {
                var relative = machine == EM_AARCH64 ? R_AARCH64_RELATIVE : R_X86_64_RELATIVE;
                var absolute = machine == EM_AARCH64 ? R_AARCH64_ABS64 : R_X86_64_64;
                var globDat = machine == EM_AARCH64 ? R_AARCH64_GLOB_DAT : R_X86_64_GLOB_DAT;
                var data = Packed(3, Base + 0x5f8, 3, 10, 8,
                    (1L << 32) | (uint)absolute, -8,
                    (1L << 32) | (uint)globDat, 12,
                    (2L << 32) | (uint)absolute, -4);
                var log = Load(Elf(data, Rela(Base + 0x618, relative, 0x7654321), machine), elf =>
                {
                    Expect(elf, 0x600, Base + 0x700 - 8);
                    Expect(elf, 0x608, (ulong)(Base + 0x700 + (machine == EM_X86_64 ? 0 : 4)));
                    Expect(elf, 0x610, 0xcccccccccccccccc); // unresolved import is not overwritten
                    Expect(elf, 0x618, 0x7654321);
                });
                Require(log.Contains("ELF RELA: 1 decoded, 1 applied"), log);
                Require(log.Contains("Android APS2 RELA: 3 decoded, 2 applied, 1 unresolved imports"), log);
            });
        }

        check("ordinary RELA without APS2", () =>
        {
            Load(Elf(null, Rela(Base + 0x600, R_AARCH64_RELATIVE, 42)), elf => Expect(elf, 0x600, 42));
        });
        check("empty APS2 stream", () => Load(Elf(Packed(0, 0)), _ => { }));
        check("APS2 accepts signed 64-bit addend boundaries", () =>
        {
            Load(Elf(Packed(1, Base + 0x600, 1, 15, 0, R_AARCH64_RELATIVE, long.MinValue)),
                elf => Expect(elf, 0x600, 0x8000000000000000));
            Load(Elf(Packed(1, Base + 0x600, 1, 15, 0, R_AARCH64_RELATIVE, long.MaxValue)),
                elf => Expect(elf, 0x600, 0x7fffffffffffffff));
        });
        check("unknown relocation types are counted", () =>
        {
            var log = Load(Elf(Packed(1, Base + 0x600, 1, 3, 0, 12345)), elf => Expect(elf, 0x600, 0xcccccccccccccccc));
            Require(log.Contains("1 unsupported types"), log);
        });
        check("JNI_OnLoad does not imply protection", () =>
        {
            var bytes = Elf(Packed(0, 0));
            System.Text.Encoding.ASCII.GetBytes("JNI_OnLoad\0").CopyTo(bytes, 0x2e0);
            var log = Load(bytes, _ => { });
            Require(log.Contains("INFO: JNI_OnLoad"), log);
            Require(!log.Contains("protected") && !log.Contains("ERROR"), log);
        });
        check("memory dump reload skips disk relocations", () =>
        {
            Load(Elf(Packed(1, 0x600, 1, 15, 0, R_AARCH64_RELATIVE, 42), loadBase: 0), elf =>
            {
                Expect(elf, 0x600, 42);
                elf.Position = 0x300;
                elf.Write((byte)0); // invalid APS2 must not be decoded on Reload of a memory dump
                elf.IsDumped = true;
                elf.Reload();
                Expect(elf, 0x600, 42);
            });
        });

        var invalid = new (string Name, byte[] Data, string Error)[]
        {
            ("bad magic", new byte[] { 0, 0, 0, 0 }, "APS2 signature"),
            ("truncated SLEB128", new byte[] { 65, 80, 83, 50, 128 }, "truncated SLEB128"),
            ("64-bit SLEB128 overflow", new byte[] { 65, 80, 83, 50, 128, 128, 128, 128, 128, 128, 128, 128, 128, 1 }, "exceeds 64 bits"),
            ("negative count", Packed(-1, 0), "relocation count"),
            ("excessive expanded count", Packed(long.MaxValue, 0), "relocation count"),
            ("zero group", Packed(1, 0, 0, 0), "group size"),
            ("oversized group", Packed(1, 0, 2, 0), "group size"),
            ("unknown flags", Packed(1, 0, 1, 16), "group flags"),
            ("grouped addend without addend", Packed(1, 0, 1, 4), "group flags"),
            ("missing relocation", Packed(1, 0, 1, 0), "truncated SLEB128"),
            ("negative offset", Packed(1, 0, 1, 3, -8, R_AARCH64_RELATIVE), "negative relocation offset"),
            ("offset overflow", Packed(1, long.MaxValue, 1, 3, 1, R_AARCH64_RELATIVE), "overflow"),
            ("addend overflow", Packed(2, Base + 0x600, 2, 11, 8, R_AARCH64_RELATIVE, long.MaxValue, 1), "overflow"),
            ("invalid symbol", Packed(1, Base + 0x600, 1, 15, 0, (99L << 32) | R_AARCH64_ABS64, 1), "invalid symbol index"),
            ("BSS target", Packed(1, Base + 0x1000, 1, 15, 0, R_AARCH64_RELATIVE, 1), "outside file-backed"),
            ("target crosses file boundary", Packed(1, Base + 0xffc, 1, 15, 0, R_AARCH64_RELATIVE, 1), "outside file-backed")
        };
        foreach (var item in invalid)
            check($"reject APS2 {item.Name}", () => Reject(Elf(item.Data), item.Error));

        check("APS2 table range cannot exceed segment", () =>
        {
            var bytes = Elf(Packed(0, 0));
            // DT_ANDROID_RELASZ is the fifth dynamic entry.
            Put64(bytes, 0x180 + 4 * 16 + 8, 0x1000);
            Reject(bytes, "outside file-backed");
        });
        check("APS2 address without size fails explicitly", () =>
        {
            var bytes = Elf(Packed(0, 0));
            Put64(bytes, 0x180 + 4 * 16, 0);
            Reject(bytes, "Incomplete Android APS2 RELA");
        });
        check("partial ordinary RELA entry is rejected", () => Reject(Elf(null, new byte[23]), "24-byte entries"));
        check("invalid ordinary RELA entry size tag is rejected", () =>
        {
            var bytes = Elf(null, Rela(Base + 0x600, R_AARCH64_RELATIVE, 1));
            Put64(bytes, 0x180 + 5 * 16 + 8, 16);
            Reject(bytes, "24-byte entries");
        });
        check("invalid ordinary RELA target is rejected", () =>
            Reject(Elf(null, Rela(Base + 0x1000, R_AARCH64_RELATIVE, 1)), "outside file-backed"));
    }

    private static string Load(byte[] bytes, Action<Elf64> verify)
    {
        var original = Console.Out;
        using var log = new StringWriter();
        try
        {
            Console.SetOut(log);
            using var elf = new Elf64(new MemoryStream(bytes));
            verify(elf);
            return log.ToString();
        }
        finally { Console.SetOut(original); }
    }

    private static void Reject(byte[] bytes, string expected)
    {
        try { Load(bytes, _ => { }); }
        catch (InvalidDataException ex) when (ex.Message.Contains(expected)) { return; }
        throw new Exception($"Expected InvalidDataException containing '{expected}'.");
    }

    private static void Expect(Elf64 elf, ulong offset, ulong expected)
    {
        elf.Position = offset;
        var actual = elf.ReadUInt64();
        Require(actual == expected, $"At file offset 0x{offset:X}: expected 0x{expected:X}, got 0x{actual:X}.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static byte[] Packed(params long[] values)
    {
        var bytes = new List<byte> { 65, 80, 83, 50 };
        foreach (var initial in values)
        {
            var value = initial;
            while (true)
            {
                var next = (byte)(value & 127);
                value >>= 7;
                var last = (value == 0 && (next & 64) == 0) || (value == -1 && (next & 64) != 0);
                bytes.Add(last ? next : (byte)(next | 128));
                if (last) break;
            }
        }
        return bytes.ToArray();
    }

    private static byte[] Rela(long address, long info, long addend)
    {
        var bytes = new byte[24];
        Put64(bytes, 0, address); Put64(bytes, 8, info); Put64(bytes, 16, addend);
        return bytes;
    }

    private static byte[] Elf(byte[] packed, byte[] rela = null, int machine = EM_AARCH64, long loadBase = Base)
    {
        var bytes = new byte[0x1000];
        Array.Fill(bytes, (byte)0xcc, 0x600, 0x100);
        bytes[0] = 0x7f; bytes[1] = 69; bytes[2] = 76; bytes[3] = 70;
        bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
        Put16(bytes, 16, 3); Put16(bytes, 18, machine);
        Put32(bytes, 20, 1); Put64(bytes, 32, 64);
        Put16(bytes, 52, 64); Put16(bytes, 54, 56); Put16(bytes, 56, 2);
        var tags = new List<(long Tag, long Value)>
        {
            (DT_HASH, loadBase + 0x260), (DT_SYMTAB, loadBase + 0x280), (DT_STRTAB, loadBase + 0x2e0)
        };
        if (packed != null)
        {
            tags.Add((DT_ANDROID_RELA, loadBase + 0x300));
            tags.Add((DT_ANDROID_RELASZ, packed.Length));
            packed.CopyTo(bytes, 0x300);
        }
        if (rela != null)
        {
            tags.Add((DT_RELA, loadBase + 0x500)); tags.Add((DT_RELASZ, rela.Length)); tags.Add((DT_RELAENT, 24));
            rela.CopyTo(bytes, 0x500);
        }
        tags.Add((0, 0));
        Segment(bytes, 64, PT_LOAD, 0, loadBase, bytes.Length, bytes.Length + 0x100);
        Segment(bytes, 120, PT_DYNAMIC, 0x180, loadBase + 0x180, tags.Count * 16, tags.Count * 16);
        for (var i = 0; i < tags.Count; i++)
        {
            Put64(bytes, 0x180 + i * 16, tags[i].Tag);
            Put64(bytes, 0x188 + i * 16, tags[i].Value);
        }
        Put32(bytes, 0x260, 1); Put32(bytes, 0x264, 3); // hash: three dynamic symbols
        Put16(bytes, 0x280 + 24 + 6, 1); // symbol 1 defined, symbol 2 undefined
        Put64(bytes, 0x280 + 24 + 8, loadBase + 0x700);
        return bytes;
    }

    private static void Segment(byte[] bytes, int at, int type, long offset, long address, long fileSize, long memorySize)
    {
        Put32(bytes, at, type); Put32(bytes, at + 4, 6);
        Put64(bytes, at + 8, offset); Put64(bytes, at + 16, address); Put64(bytes, at + 24, address);
        Put64(bytes, at + 32, fileSize); Put64(bytes, at + 40, memorySize); Put64(bytes, at + 48, 8);
    }

    private static void Put16(byte[] bytes, int offset, int value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), (ushort)value);
    private static void Put32(byte[] bytes, int offset, int value) => BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), value);
    private static void Put64(byte[] bytes, int offset, long value) => BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(offset, 8), value);
}
