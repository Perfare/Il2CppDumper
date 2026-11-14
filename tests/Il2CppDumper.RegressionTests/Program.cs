using Il2CppDumper;

// Binary fixtures are written independently of Metadata.SizeOf and the production readers.
var passed = 0;
void Check(string name, Action test)
{
    test();
    Console.WriteLine($"PASS {name}");
    passed++;
}

foreach (var width in new[] { 1, 2, 4 })
foreach (var withAdjustor in new[] { false, true })
{
    Check($"v108 packed tables, width {width}, adjustor {withAdjustor}", () =>
    {
        using var metadata = Parse(PackedFixture(width, withAdjustor).Build());
        Equal(3, metadata.rgctxEntries.Length);
        Equal(2, (int)metadata.rgctxEntries[0].type);
        Equal(0x01020304UL, metadata.rgctxEntries[0]._data);
        Equal(6, (int)metadata.rgctxEntries[1].type);
        Equal(0x10203040UL, metadata.rgctxEntries[1]._data);
        Equal(8, (int)metadata.rgctxEntries[2].type);
        Equal(0xFFFFFFFFUL, metadata.rgctxEntries[2]._data);
        Equal(17, metadata.invokerIndices[0]);
        Equal(-1, metadata.invokerIndices[1]);
        for (var i = 0; i < 3; i++)
        {
            var method = metadata.genericMethodFunctionsDefinitions[i];
            Equal(i, method.genericMethodIndex);
            Equal(40 + i, method.indices.methodIndex);
            Equal(i == 2 ? -1 : 20 + i, method.indices.invokerIndex);
        }
        if (withAdjustor)
        {
            var method = metadata.genericMethodFunctionsDefinitionsWithAdjustor.Single();
            Equal(2, method.genericMethodIndex);
            Equal(42, method.methodIndex);
            Equal(-1, method.invokerIndex);
            Equal(0, method.adjustorThunkIndex);
        }
    });
}

Check("truncated RGCTX section is diagnosed before reading", () =>
{
    var bytes = PackedFixture(2, true).Build();
    Reject(bytes[..^1], "outside the file");
});

Check("inconsistent RGCTX count is rejected", () =>
{
    var fixture = PackedFixture(2, true);
    var bytes = fixture.Build();
    WriteInt(bytes, fixture.HeaderOffset("rgctxValues") + 8, 4);
    Reject(bytes, "unsupported layout");
});

Check("out of range section offset is rejected", () =>
{
    var fixture = PackedFixture(2, true);
    var bytes = fixture.Build();
    WriteInt(bytes, fixture.HeaderOffset("rgctxValues"), int.MaxValue);
    Reject(bytes, "outside the file");
});

Check("fractional generic table stride is rejected", () =>
{
    var fixture = PackedFixture(2, true);
    var bytes = fixture.Build();
    WriteInt(bytes, fixture.HeaderOffset("genericMethodFunctionsDefinitions") + 4, 14);
    Reject(bytes, "Invalid metadata section");
});

foreach (var withModuleToken in new[] { false, true })
{
    Check($"v39 assembly stride, module token {withModuleToken}", () =>
    {
        var fixture = new Fixture(39);
        fixture.Add("assemblies", 2, writer =>
        {
            for (var i = 0; i < 2; i++)
            {
                writer.Write(i); // image index
                writer.Write(0x20000001U + (uint)i);
                writer.Write(-1); // unused custom attribute index
                writer.Write(0); // referenced assembly start/count
                writer.Write(0);
                writer.Write((uint)(100 + i)); // assembly name index
                writer.Write(new byte[44]); // remaining name fields and public key token
                if (withModuleToken)
                    writer.Write(0x00000001U + (uint)i);
            }
        });
        using var metadata = Parse(fixture.Build());
        Equal(2, metadata.assemblyDefs.Length);
        Equal(1, metadata.assemblyDefs[1].imageIndex);
        Equal(101U, metadata.assemblyDefs[1].aname.nameIndex);
        Equal(withModuleToken ? 2U : 0U, metadata.assemblyDefs[1].moduleToken);
    });
}

foreach (var version in new[] { 38, 104, 105, 106, 107, 110 })
{
    Check($"empty v{version} sections", () =>
    {
        using var metadata = Parse(new Fixture(version).Build());
        Equal((double)version, metadata.Version);
        Equal(0, metadata.methodDefs.Length);
    });
}

Check("attribute constructor decoding follows metadata version", () =>
{
    using var oldMetadata = Parse(new Fixture(39).Build());
    using var newMetadata = Parse(new Fixture(108).Build());
    Equal(123U, oldMetadata.GetAttributeCtorMethodIndex(123));
    Equal(123U, newMetadata.GetAttributeCtorMethodIndex((2U << 29) | (123U << 1) | 1));
    Equal((uint)Il2CppMetadataUsage.kIl2CppMetadataUsageMethodRef,
        newMetadata.GetEncodedIndexTypeForVersion((5U << 29) | (123U << 1) | 1));
});

Check("new enum signatures use parentIndex", () =>
{
    using var metadata = Parse(new Fixture(108).Build());
    Equal(17, metadata.GetEnumElementTypeIndex(new Il2CppTypeDefinition { elementTypeIndex = 0, parentIndex = 17 }));
});

ElfRelocationTests.Run(Check);

if (args.Length > 0)
{
    Check("real v108 sample", () =>
    {
        using var metadata = Parse(File.ReadAllBytes(args[0]));
        Equal(108d, metadata.Version);
        Equal(88, metadata.imageDefs.Length);
        Equal(15412, metadata.typeDefs.Length);
        Equal(106326, metadata.methodDefs.Length);
        Equal(19350, metadata.rgctxEntries.Length);
        Equal(166787, metadata.genericMethodFunctionsDefinitions.Length);
        Equal(2, (int)metadata.rgctxEntries[0].type);
        Equal(0xCBB2UL, metadata.rgctxEntries[0]._data);
    });
}
Console.WriteLine($"{passed} regression checks passed.");

static Metadata Parse(byte[] bytes) => new(new MemoryStream(bytes));

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new Exception($"Expected {expected}, got {actual}.");
}

static void Reject(byte[] bytes, string message)
{
    try
    {
        using var metadata = Parse(bytes);
    }
    catch (InvalidDataException ex) when (ex.Message.Contains(message))
    {
        return;
    }
    throw new Exception($"Expected InvalidDataException containing '{message}'.");
}

static void WriteInt(byte[] bytes, int offset, int value) =>
    System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset, 4), value);

static void WriteIndex(BinaryWriter writer, int value, int width)
{
    if (width == 1) writer.Write(unchecked((byte)value));
    else if (width == 2) writer.Write(unchecked((ushort)value));
    else writer.Write(value);
}

static Fixture PackedFixture(int width, bool withAdjustor)
{
    var fixture = new Fixture(108);
    fixture.Add("methodSpecs", 3, writer =>
    {
        for (var i = 0; i < 3; i++)
        {
            writer.Write((byte)0); // one-byte method definition index
            writer.Write(-1); // no class or method instantiation
            writer.Write(-1);
        }
    });
    fixture.Add("genericMethodFunctionsDefinitions", 3, writer =>
    {
        for (var i = 0; i < 3; i++)
        {
            writer.Write((byte)i);
            WriteIndex(writer, 40 + i, width);
            WriteIndex(writer, i == 2 ? -1 : 20 + i, width);
        }
    });
    if (withAdjustor)
        fixture.Add("genericMethodFunctionsDefinitionsWithAdjustor", 1, writer =>
        {
            writer.Write((byte)2);
            WriteIndex(writer, 42, width);
            WriteIndex(writer, -1, width);
            writer.Write((byte)0);
        });
    fixture.Add("invokerIndices", 2, writer =>
    {
        WriteIndex(writer, 17, width);
        WriteIndex(writer, -1, width);
    });
    fixture.Add("rgctxValues", 3, writer =>
    {
        writer.Write((byte)2); writer.Write(0x01020304U);
        writer.Write((byte)6); writer.Write(0x10203040U);
        writer.Write((byte)8); writer.Write(uint.MaxValue);
    });
    return fixture;
}

sealed class Fixture
{
    private readonly int version;
    private readonly List<string> sections = new()
    {
        "stringLiterals", "stringLiteralData", "strings", "events", "properties", "methods",
        "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
        "fieldMarshaledSizes", "parameters", "fields", "genericParameters", "genericParameterConstraints",
        "genericContainers", "nestedTypes", "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions"
    };
    private readonly Dictionary<string, (int Count, byte[] Data)> data = new();

    public Fixture(int version)
    {
        this.version = version;
        if (version >= 104) sections.Add("typeInlineArrays");
        sections.AddRange(new[] { "images", "assemblies", "fieldRefs", "referencedAssemblies", "attributeData",
            "attributeDataRanges", "unresolvedIndirectCallParameterTypes", "unresolvedIndirectCallParameterRanges",
            "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions" });
        if (version >= 108) sections.AddRange(new[] { "methodSpecsOnGenericType", "genericMethodSpecsOnType",
            "methodSpecs", "genericMethodFunctionsDefinitions", "genericMethodFunctionsDefinitionsWithAdjustor",
            "invokerIndices", "rgctxRanges", "rgctxValues", "staticConstructorTypeIndices" });
        if (version >= 110) sections.AddRange(new[] { "generatedMethodTypeInfos", "generatedMethodTokens" });
    }

    public int HeaderOffset(string section) => 8 + sections.IndexOf(section) * 12;

    public void Add(string section, int count, Action<BinaryWriter> write)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        write(writer);
        data.Add(section, (count, stream.ToArray()));
    }

    public byte[] Build()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(0xFAB11BAFU);
        writer.Write(version);
        var offset = 8 + sections.Count * 12;
        foreach (var section in sections)
        {
            var entry = data.GetValueOrDefault(section, (0, Array.Empty<byte>()));
            writer.Write(offset);
            writer.Write(entry.Item2.Length);
            writer.Write(entry.Item1);
            offset += entry.Item2.Length;
        }
        foreach (var section in sections)
            if (data.TryGetValue(section, out var entry)) writer.Write(entry.Data);
        return stream.ToArray();
    }
}
