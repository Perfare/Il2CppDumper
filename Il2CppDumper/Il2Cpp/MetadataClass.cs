using System;

namespace Il2CppDumper
{
    public class Il2CppGlobalMetadataHeader
    {
        public uint sanity;
        public int version;
        public uint stringLiteralOffset; // string data for managed code
        public int stringLiteralSize;
        public uint stringLiteralDataOffset;
        public int stringLiteralDataSize;
        public uint stringOffset; // string data for metadata
        public int stringSize;
        public uint eventsOffset; // Il2CppEventDefinition
        public int eventsSize;
        public uint propertiesOffset; // Il2CppPropertyDefinition
        public int propertiesSize;
        public uint methodsOffset; // Il2CppMethodDefinition
        public int methodsSize;
        public uint parameterDefaultValuesOffset; // Il2CppParameterDefaultValue
        public int parameterDefaultValuesSize;
        public uint fieldDefaultValuesOffset; // Il2CppFieldDefaultValue
        public int fieldDefaultValuesSize;
        public uint fieldAndParameterDefaultValueDataOffset; // uint8_t
        public int fieldAndParameterDefaultValueDataSize;
        public int fieldMarshaledSizesOffset; // Il2CppFieldMarshaledSize
        public int fieldMarshaledSizesSize;
        public uint parametersOffset; // Il2CppParameterDefinition
        public int parametersSize;
        public uint fieldsOffset; // Il2CppFieldDefinition
        public int fieldsSize;
        public uint genericParametersOffset; // Il2CppGenericParameter
        public int genericParametersSize;
        public uint genericParameterConstraintsOffset; // TypeIndex
        public int genericParameterConstraintsSize;
        public uint genericContainersOffset; // Il2CppGenericContainer
        public int genericContainersSize;
        public uint nestedTypesOffset; // TypeDefinitionIndex
        public int nestedTypesSize;
        public uint interfacesOffset; // TypeIndex
        public int interfacesSize;
        public uint vtableMethodsOffset; // EncodedMethodIndex
        public int vtableMethodsSize;
        public int interfaceOffsetsOffset; // Il2CppInterfaceOffsetPair
        public int interfaceOffsetsSize;
        public uint typeDefinitionsOffset; // Il2CppTypeDefinition
        public int typeDefinitionsSize;
        [Version(Max = 24.1)]
        public uint rgctxEntriesOffset; // Il2CppRGCTXDefinition
        [Version(Max = 24.1)]
        public int rgctxEntriesCount;
        public uint imagesOffset; // Il2CppImageDefinition
        public int imagesSize;
        public uint assembliesOffset; // Il2CppAssemblyDefinition
        public int assembliesSize;
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
        [Version(Min = 20)]
        public int referencedAssembliesOffset; // int32_t
        [Version(Min = 20)]
        public int referencedAssembliesSize;
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
        [Version(Min = 29)]
        public uint attributeDataRangeOffset;
        [Version(Min = 29)]
        public int attributeDataRangeSize;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesOffset; // TypeIndex
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesSize;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesOffset; // Il2CppRange
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesSize;
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesOffset; // Il2CppWindowsRuntimeTypeNamePair
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesSize;
        [Version(Min = 27)]
        public int windowsRuntimeStringsOffset; // const char*
        [Version(Min = 27)]
        public int windowsRuntimeStringsSize;
        [Version(Min = 24)]
        public int exportedTypeDefinitionsOffset; // TypeDefinitionIndex
        [Version(Min = 24)]
        public int exportedTypeDefinitionsSize;

        // v38+ metadata sections
        [Version(Min = 38)]
        public Il2CppSectionMetadata stringLiterals; // Il2CppStringLiteral
        [Version(Min = 38)]
        public Il2CppSectionMetadata stringLiteralData; // uint8_t
        [Version(Min = 38)]
        public Il2CppSectionMetadata strings; // const char*
        [Version(Min = 38)]
        public Il2CppSectionMetadata events; // Il2CppEventDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata properties; // Il2CppPropertyDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata methods; // Il2CppMethodDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata parameterDefaultValues; // Il2CppParameterDefaultValue
        [Version(Min = 38)]
        public Il2CppSectionMetadata fieldDefaultValues; // Il2CppFieldDefaultValue
        [Version(Min = 38)]
        public Il2CppSectionMetadata fieldAndParameterDefaultValueData; // uint8_t
        [Version(Min = 38)]
        public Il2CppSectionMetadata fieldMarshaledSizes; // Il2CppFieldMarshaledSize
        [Version(Min = 38)]
        public Il2CppSectionMetadata parameters; // Il2CppParameterDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata fields; // Il2CppFieldDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata genericParameters; // Il2CppGenericParameter
        [Version(Min = 38)]
        public Il2CppSectionMetadata genericParameterConstraints; // TypeIndex
        [Version(Min = 38)]
        public Il2CppSectionMetadata genericContainers; // Il2_GENERICContainer
        [Version(Min = 38)]
        public Il2CppSectionMetadata nestedTypes; // TypeDefinitionIndex
        [Version(Min = 38)]
        public Il2CppSectionMetadata interfaces; // TypeIndex
        [Version(Min = 38)]
        public Il2CppSectionMetadata vtableMethods; // EncodedMethodIndex
        [Version(Min = 38)]
        public Il2CppSectionMetadata interfaceOffsets; // Il2CppInterfaceOffsetPair
        [Version(Min = 38)]
        public Il2CppSectionMetadata typeDefinitions; // Il2CppTypeDefinition
        [Version(Min = 104)]
        public Il2CppSectionMetadata typeInlineArrays;
        [Version(Min = 38)]
        public Il2CppSectionMetadata images; // Il2CppImageDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata assemblies; // Il2CppAssemblyDefinition
        [Version(Min = 38)]
        public Il2CppSectionMetadata fieldRefs; // Il2CppFieldRef
        [Version(Min = 38)]
        public Il2CppSectionMetadata referencedAssemblies; // int32_t
        [Version(Min = 38)]
        public Il2CppSectionMetadata attributeData; // uint8_t
        [Version(Min = 38)]
        public Il2CppSectionMetadata attributeDataRanges; // Il2CppCustomAttributeDataRange
        [Version(Min = 38)]
        public Il2CppSectionMetadata unresolvedIndirectCallParameterTypes; // TypeIndex
        [Version(Min = 38)]
        public Il2CppSectionMetadata unresolvedIndirectCallParameterRanges; // Il2CppRange
        [Version(Min = 38)]
        public Il2CppSectionMetadata windowsRuntimeTypeNames; // Il2CppWindowsRuntimeTypeNamePair
        [Version(Min = 38)]
        public Il2CppSectionMetadata windowsRuntimeStrings; // const char*
        [Version(Min = 38)]
        public Il2CppSectionMetadata exportedTypeDefinitions; // TypeDefinitionIndex
        [Version(Min = 108)]
        public Il2CppSectionMetadata methodSpecsOnGenericType; // Il2CppMethodSpecOnGenericType
        [Version(Min = 108)]
        public Il2CppSectionMetadata genericMethodSpecsOnType; // Il2CppGenericMethodSpecOnType
        [Version(Min = 108)]
        public Il2CppSectionMetadata methodSpecs; // Il2CppMethodSpec
        [Version(Min = 108)]
        public Il2CppSectionMetadata genericMethodFunctionsDefinitions; // Il2CppGenericMethodFunctionsDefinitions
        [Version(Min = 108)]
        public Il2CppSectionMetadata genericMethodFunctionsDefinitionsWithAdjustor; // Il2CppGenericMethodFunctionsDefinitionsWithAdjustor
        [Version(Min = 108)]
        public Il2CppSectionMetadata invokerIndices; // InvokerTableIndex
        [Version(Min = 108)]
        public Il2CppSectionMetadata rgctxRanges; // Il2CppTokenRangePair
        [Version(Min = 108)]
        public Il2CppSectionMetadata rgctxValues; // Il2CppRGCTXDataDefinition
        [Version(Min = 108)]
        public Il2CppSectionMetadata staticConstructorTypeIndices; // TypeDefinitionIndex
        [Version(Min = 110)]
        public Il2CppSectionMetadata generatedMethodTypeInfos; // Il2CppGeneratedMethodTypeInfo
        [Version(Min = 110)]
        public Il2CppSectionMetadata generatedMethodTokens; // Il2CppGeneratedMethodToken
    }

    public class Il2CppAssemblyDefinition
    {
        public int imageIndex;
        [Version(Min = 24.1)]
        public uint token;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 24.1)]
        public int unusedCustomAttributeIndex;
        [Version(Min = 20)]
        public int referencedAssemblyStart;
        [Version(Min = 20)]
        public int referencedAssemblyCount;
        public Il2CppAssemblyNameDefinition aname;
        [Version(Min = 38)]
        public uint moduleToken;
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

        public int typeStart;
        public uint typeCount;

        [Version(Min = 24)]
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
        [Version(Min = 108)]
        public int invokerIndicesStart;
        [Version(Min = 108)]
        public int rgctxRangesStart;
        [Version(Min = 108)]
        public int rgctxRangesCount;
        [Version(Min = 108)]
        public int staticConstructorStart;
        [Version(Min = 108)]
        public int staticConstructorCount;
        [Version(Min = 110)]
        public int fieldStart;
        [Version(Min = 110)]
        public int propertyStart;
        [Version(Min = 110)]
        public int eventStart;
        [Version(Min = 110)]
        public int methodStart;
    }

    public class Il2CppTypeDefinition
    {
        public uint nameIndex;
        public uint namespaceIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int byvalTypeIndex;
        [Version(Max = 24.5)]
        public int byrefTypeIndex;

        public int declaringTypeIndex;
        public int parentIndex;
        [Version(Max = 31)]
        public int elementTypeIndex; // we can probably remove this one. Only used for enums

        [Version(Max = 24.1)]
        public int rgctxStartIndex;
        [Version(Max = 24.1)]
        public int rgctxCount;

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
        [Version(Min = 19, Max = 109)]
        public uint token;

        public bool IsValueType => (bitfield & 0x1) == 1;
        public bool IsEnum => ((bitfield >> 1) & 0x1) == 1;
        public bool HasGeneratedMethods => ((bitfield >> 19) & 0x1) == 1;
    }

    public class Il2CppMethodDefinition
    {
        public uint nameIndex;
        public int declaringType;
        public int returnType;
        [Version(Min = 31)]
        public int returnParameterToken;
        public int parameterStart;
        [Version(Max = 24)]
        public int customAttributeIndex;
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
        [Version(Max = 109)]
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
        public int typeIndex;
    }

    public class Il2CppFieldDefinition
    {
        public uint nameIndex;
        public int typeIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19, Max = 109)]
        public uint token;
    }

    public class Il2CppFieldDefaultValue
    {
        public int fieldIndex;
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
        [Version(Min = 19, Max = 109)]
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
        public int parameterIndex;
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppEventDefinition
    {
        public uint nameIndex;
        public int typeIndex;
        public int add;
        public int remove;
        public int raise;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19, Max = 109)]
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
        public int typeIndex;
        public int fieldIndex; // local offset into type fields
    }

    public class Il2CppGenericParameter
    {
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

    public class Il2CppMethodSpecOnGenericType
    {
        public int methodDefinitionIndex;
        public int classIndexIndex;
    }

    public class Il2CppGenericMethodSpecOnType
    {
        public int methodDefinitionIndex;
        public int methodIndexIndex;
    }

    public class Il2CppGenericMethodFunctionsDefinitionsWithAdjustor
    {
        public int genericMethodIndex;
        public int methodIndex;
        public int invokerIndex;
        public int adjustorThunkIndex;
    }

    public class Il2CppGeneratedMethodTypeInfo
    {
        public int typeIndex;
        public int generatedMethodStart;
        public int generatedMethodCount;
    }

    public class Il2CppGeneratedMethodToken
    {
        public uint token;
    }

    // v38+ metadata section format
    public class Il2CppSectionMetadata
    {
        public int offset;
        public int sectionSize;
        public int count;
    }
}
