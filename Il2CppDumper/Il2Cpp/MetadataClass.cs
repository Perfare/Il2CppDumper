using System;

namespace Il2CppDumper
{
    public class Il2CppGlobalMetadataHeader
    {
        public uint sanity;
        public int version;
        public uint stringLiteralOffset; // string data for managed code
        public int stringLiteralSize;
        [Version(Min = 38)] public int stringLiteralCount;
        public uint stringLiteralDataOffset;
        public int stringLiteralDataSize;
        [Version(Min = 38)] public int stringLiteralDataCount;
        public uint stringOffset; // string data for metadata
        public int stringSize;
        [Version(Min = 38)] public int stringCount;
        public uint eventsOffset; // Il2CppEventDefinition
        public int eventsSize;
        [Version(Min = 38)] public int eventsCount;
        public uint propertiesOffset; // Il2CppPropertyDefinition
        public int propertiesSize;
        [Version(Min = 38)] public int propertiesCount;
        public uint methodsOffset; // Il2CppMethodDefinition
        public int methodsSize;
        [Version(Min = 38)] public int methodsCount;
        public uint parameterDefaultValuesOffset; // Il2CppParameterDefaultValue
        public int parameterDefaultValuesSize;
        [Version(Min = 38)] public int parameterDefaultValuesCount;
        public uint fieldDefaultValuesOffset; // Il2CppFieldDefaultValue
        public int fieldDefaultValuesSize;
        [Version(Min = 38)] public int fieldDefaultValuesCount;
        public uint fieldAndParameterDefaultValueDataOffset; // uint8_t
        public int fieldAndParameterDefaultValueDataSize;
        [Version(Min = 38)] public int fieldAndParameterDefaultValueDataCount;
        public int fieldMarshaledSizesOffset; // Il2CppFieldMarshaledSize
        public int fieldMarshaledSizesSize;
        [Version(Min = 38)] public int fieldMarshaledSizesCount;
        public uint parametersOffset; // Il2CppParameterDefinition
        public int parametersSize;
        [Version(Min = 38)] public int parametersCount;
        public uint fieldsOffset; // Il2CppFieldDefinition
        public int fieldsSize;
        [Version(Min = 38)] public int fieldsCount;
        public uint genericParametersOffset; // Il2CppGenericParameter
        public int genericParametersSize;
        [Version(Min = 38)] public int genericParametersCount;
        public uint genericParameterConstraintsOffset; // TypeIndex
        public int genericParameterConstraintsSize;
        [Version(Min = 38)] public int genericParameterConstraintsCount;
        public uint genericContainersOffset; // Il2CppGenericContainer
        public int genericContainersSize;
        [Version(Min = 38)] public int genericContainersCount;
        public uint nestedTypesOffset; // TypeDefinitionIndex
        public int nestedTypesSize;
        [Version(Min = 38)] public int nestedTypesCount;
        public uint interfacesOffset; // TypeIndex
        public int interfacesSize;
        [Version(Min = 38)] public int interfacesCount;
        public uint vtableMethodsOffset; // EncodedMethodIndex
        public int vtableMethodsSize;
        [Version(Min = 38)] public int vtableMethodsCount;
        public int interfaceOffsetsOffset; // Il2CppInterfaceOffsetPair
        public int interfaceOffsetsSize;
        [Version(Min = 38)] public int interfaceOffsetsCount;
        public uint typeDefinitionsOffset; // Il2CppTypeDefinition
        public int typeDefinitionsSize;
        [Version(Min = 38)] public int typeDefinitionsCount;
        [Version(Max = 24.1)]
        public uint rgctxEntriesOffset; // Il2CppRGCTXDefinition
        [Version(Max = 24.1)]
        public int rgctxEntriesCount;
        public uint imagesOffset; // Il2CppImageDefinition
        public int imagesSize;
        [Version(Min = 38)] public int imagesCount;
        public uint assembliesOffset; // Il2CppAssemblyDefinition
        public int assembliesSize;
        [Version(Min = 38)] public int assembliesCount;
        [Version(Min = 19, Max = 24.5)]
        public uint metadataUsageListsOffset; // Il2CppMetadataUsageList
        [Version(Min = 19, Max = 24.5)]
        public int metadataUsageListsCount;
        [Version(Min = 19, Max = 24.5)]
        public uint metadataUsagePairsOffset; // Il2CppMetadataUsagePair
        [Version(Min = 19, Max = 24.5)]
        public int metadataUsagePairsCount;
        [Version(Min = 19)]
        public uint fieldRefsOffset; // Il2CppFieldRef
        [Version(Min = 19)]
        public int fieldRefsSize;
        [Version(Min = 38)] public int fieldRefsCount;
        [Version(Min = 20)]
        public int referencedAssembliesOffset; // int32_t
        [Version(Min = 20)]
        public int referencedAssembliesSize;
        [Version(Min = 38)] public int referencedAssembliesCount;
        [Version(Min = 21, Max = 27.2)]
        public uint attributesInfoOffset; // Il2CppCustomAttributeTypeRange
        [Version(Min = 21, Max = 27.2)]
        public int attributesInfoCount;
        [Version(Min = 21, Max = 27.2)]
        public uint attributeTypesOffset; // TypeIndex
        [Version(Min = 21, Max = 27.2)]
        public int attributeTypesCount;
        [Version(Min = 29)]
        public uint attributeDataOffset;
        [Version(Min = 29)]
        public int attributeDataSize;
        [Version(Min = 38)] public int attributeDataCount;
        [Version(Min = 29)]
        public uint attributeDataRangeOffset;
        [Version(Min = 29)]
        public int attributeDataRangeSize;
        [Version(Min = 38)] public int attributeDataRangeCount;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesOffset; // TypeIndex
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesSize;
        [Version(Min = 38)] public int unresolvedVirtualCallParameterTypesCount;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesOffset; // Il2CppRange
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesSize;
        [Version(Min = 38)] public int unresolvedVirtualCallParameterRangesCount;
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesOffset; // Il2CppWindowsRuntimeTypeNamePair
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesSize;
        [Version(Min = 38)] public int windowsRuntimeTypeNamesCount;
        [Version(Min = 27)]
        public int windowsRuntimeStringsOffset; // const char*
        [Version(Min = 27)]
        public int windowsRuntimeStringsSize;
        [Version(Min = 38)] public int windowsRuntimeStringsCount;
        [Version(Min = 24)]
        public int exportedTypeDefinitionsOffset; // TypeDefinitionIndex
        [Version(Min = 24)]
        public int exportedTypeDefinitionsSize;
        [Version(Min = 38)] public int exportedTypeDefinitionsCount;
    }

    public class Il2CppAssemblyDefinition
    {
        public int imageIndex;
        [Version(Min = 24.1)]
        public uint token;
        [Version(Min = 38)]
        public uint moduleToken;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 20)]
        public int referencedAssemblyStart;
        [Version(Min = 20)]
        public int referencedAssemblyCount;
        public Il2CppAssemblyNameDefinition aname;
    }

    public class Il2CppAssemblyNameDefinition
    {
        public uint nameIndex;
        public uint cultureIndex;
        [Version(Max = 24.3)]
        public int hashValueIndex;
        public uint publicKeyIndex;
        public uint hash_alg;
        public int hash_len;
        public uint flags;
        public int major;
        public int minor;
        public int build;
        public int revision;
        [ArrayLength(Length = 8)]
        public byte[] public_key_token;
    }

    public class Il2CppImageDefinition
    {
        public uint nameIndex;
        public int assemblyIndex;

        [VariableIndex(VariableIndexKind.TypeDefinition)]
        public int typeStart;
        public uint typeCount;

        [Version(Min = 24)]
        [VariableIndex(VariableIndexKind.TypeDefinition)]
        public int exportedTypeStart;
        [Version(Min = 24)]
        public uint exportedTypeCount;

        public int entryPointIndex;
        [Version(Min = 19)]
        public uint token;

        [Version(Min = 24.1)]
        public int customAttributeStart;
        [Version(Min = 24.1)]
        public uint customAttributeCount;
    }

    public class Il2CppTypeDefinition
    {
        public uint nameIndex;
        public uint namespaceIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int byvalTypeIndex;
        [Version(Max = 24.5)]
        public int byrefTypeIndex;

        [VariableIndex(VariableIndexKind.Type)]
        public int declaringTypeIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int parentIndex;
        [Version(Max = 31)]
        public int elementTypeIndex; // we can probably remove this one. Only used for enums

        [Version(Max = 24.1)]
        public int rgctxStartIndex;
        [Version(Max = 24.1)]
        public int rgctxCount;

        [VariableIndex(VariableIndexKind.GenericContainer)]
        public int genericContainerIndex;

        [Version(Max = 22)]
        public int delegateWrapperFromManagedToNativeIndex;
        [Version(Max = 22)]
        public int marshalingFunctionsIndex;
        [Version(Min = 21, Max = 22)]
        public int ccwFunctionIndex;
        [Version(Min = 21, Max = 22)]
        public int guidIndex;

        public uint flags;

        public int fieldStart;
        public int methodStart;
        public int eventStart;
        public int propertyStart;
        public int nestedTypesStart;
        public int interfacesStart;
        public int vtableStart;
        public int interfaceOffsetsStart;

        public ushort method_count;
        public ushort property_count;
        public ushort field_count;
        public ushort event_count;
        public ushort nested_type_count;
        public ushort vtable_count;
        public ushort interfaces_count;
        public ushort interface_offsets_count;

        // bitfield to portably encode boolean values as single bits
        // 01 - valuetype;
        // 02 - enumtype;
        // 03 - has_finalize;
        // 04 - has_cctor;
        // 05 - is_blittable;
        // 06 - is_import_or_windows_runtime;
        // 07-10 - One of nine possible PackingSize values (0, 1, 2, 4, 8, 16, 32, 64, or 128)
        // 11 - PackingSize is default
        // 12 - ClassSize is default
        // 13-16 - One of nine possible PackingSize values (0, 1, 2, 4, 8, 16, 32, 64, or 128) - the specified packing size (even for explicit layouts)
        public uint bitfield;
        [Version(Min = 19)]
        public uint token;

        public bool IsValueType => (bitfield & 0x1) == 1;
        public bool IsEnum => ((bitfield >> 1) & 0x1) == 1;

        public int GetEnumElementTypeIndex(double version)
        {
            // Unity 6000.3/v35 removed elementTypeIndex and stores an enum's
            // underlying type in parentIndex instead.
            return version >= 35 ? parentIndex : elementTypeIndex;
        }
    }

    public class Il2CppMethodDefinition
    {
        public uint nameIndex;
        [VariableIndex(VariableIndexKind.TypeDefinition)]
        public int declaringType;
        [VariableIndex(VariableIndexKind.Type)]
        public int returnType;
        [Version(Min = 31)]
        public int returnParameterToken;
        [VariableIndex(VariableIndexKind.ParameterDefinition)]
        public int parameterStart;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [VariableIndex(VariableIndexKind.GenericContainer)]
        public int genericContainerIndex;
        [Version(Max = 24.1)]
        public int methodIndex;
        [Version(Max = 24.1)]
        public int invokerIndex;
        [Version(Max = 24.1)]
        public int delegateWrapperIndex;
        [Version(Max = 24.1)]
        public int rgctxStartIndex;
        [Version(Max = 24.1)]
        public int rgctxCount;
        public uint token;
        public ushort flags;
        public ushort iflags;
        public ushort slot;
        public ushort parameterCount;
    }

    public class Il2CppParameterDefinition
    {
        public uint nameIndex;
        public uint token;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
    }

    public class Il2CppFieldDefinition
    {
        public uint nameIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppFieldDefaultValue
    {
        public int fieldIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppPropertyDefinition
    {
        public uint nameIndex;
        public int get;
        public int set;
        public uint attrs;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppCustomAttributeTypeRange
    {
        [Version(Min = 24.1)]
        public uint token;
        public int start;
        public int count;
    }

    public class Il2CppMetadataUsageList
    {
        public uint start;
        public uint count;
    }

    public class Il2CppMetadataUsagePair
    {
        public uint destinationIndex;
        public uint encodedSourceIndex;
    }

    public class Il2CppStringLiteral
    {
        [Version(Max = 31)]
        public uint length;
        public int dataIndex;
    }

    public class Il2CppParameterDefaultValue
    {
        [VariableIndex(VariableIndexKind.ParameterDefinition)]
        public int parameterIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppEventDefinition
    {
        public uint nameIndex;
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
        public int add;
        public int remove;
        public int raise;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppGenericContainer
    {
        /* index of the generic type definition or the generic method definition corresponding to this container */
        public int ownerIndex; // either index into Il2CppClass metadata array or Il2CppMethodDefinition array
        public int type_argc;
        /* If true, we're a generic method, otherwise a generic type definition. */
        public int is_method;
        /* Our type parameters. */
        public int genericParameterStart;
    }

    public class Il2CppFieldRef
    {
        [VariableIndex(VariableIndexKind.Type)]
        public int typeIndex;
        public int fieldIndex; // local offset into type fields
    }

    public class Il2CppGenericParameter
    {
        [VariableIndex(VariableIndexKind.GenericContainer)]
        public int ownerIndex;  /* Type or method this parameter was defined in. */
        public uint nameIndex;
        public short constraintsStart;
        public short constraintsCount;
        public ushort num;
        public ushort flags;
    }

    public enum Il2CppRGCTXDataType
    {
        IL2CPP_RGCTX_DATA_INVALID,
        IL2CPP_RGCTX_DATA_TYPE,
        IL2CPP_RGCTX_DATA_CLASS,
        IL2CPP_RGCTX_DATA_METHOD,
        IL2CPP_RGCTX_DATA_ARRAY,
        IL2CPP_RGCTX_DATA_CONSTRAINED,
    }

    public class Il2CppRGCTXDefinitionData
    {
        public int rgctxDataDummy;
        public int methodIndex => rgctxDataDummy;
        public int typeIndex => rgctxDataDummy;
    }

    public class Il2CppRGCTXDefinition
    {
        public Il2CppRGCTXDataType type => type_post29 == 0 ? (Il2CppRGCTXDataType)type_pre29 : (Il2CppRGCTXDataType)type_post29;
        [Version(Max = 27.1)]
        public int type_pre29;
        [Version(Min = 29)]
        public ulong type_post29;
        [Version(Max = 27.1)]
        public Il2CppRGCTXDefinitionData data;
        [Version(Min = 27.2)]
        public ulong _data;
    }

    public enum Il2CppMetadataUsage
    {
        kIl2CppMetadataUsageInvalid,
        kIl2CppMetadataUsageTypeInfo,
        kIl2CppMetadataUsageIl2CppType,
        kIl2CppMetadataUsageMethodDef,
        kIl2CppMetadataUsageFieldInfo,
        kIl2CppMetadataUsageStringLiteral,
        kIl2CppMetadataUsageMethodRef,
    };

    public class Il2CppCustomAttributeDataRange
    {
        public uint token;
        public uint startOffset;
    }
}
