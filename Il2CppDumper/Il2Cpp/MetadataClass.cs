using System;

namespace Il2CppDumper
{
    public class Il2CppGlobalMetadataHeader
    {
        public uint sanity;
        public int version;
        public uint stringLiteralOffset; // string data for managed code
        public int stringLiteralCount;
        public uint stringLiteralDataOffset;
        public int stringLiteralDataCount;
        public uint stringOffset; // string data for metadata
        public int stringCount;
        public uint eventsOffset; // Il2CppEventDefinition
        public int eventsCount;
        public uint propertiesOffset; // Il2CppPropertyDefinition
        public int propertiesCount;
        public uint methodsOffset; // Il2CppMethodDefinition
        public int methodsCount;
        public uint parameterDefaultValuesOffset; // Il2CppParameterDefaultValue
        public int parameterDefaultValuesCount;
        public uint fieldDefaultValuesOffset; // Il2CppFieldDefaultValue
        public int fieldDefaultValuesCount;
        public uint fieldAndParameterDefaultValueDataOffset; // uint8_t
        public int fieldAndParameterDefaultValueDataCount;
        public int fieldMarshaledSizesOffset; // Il2CppFieldMarshaledSize
        public int fieldMarshaledSizesCount;
        public uint parametersOffset; // Il2CppParameterDefinition
        public int parametersCount;
        public uint fieldsOffset; // Il2CppFieldDefinition
        public int fieldsCount;
        public uint genericParametersOffset; // Il2CppGenericParameter
        public int genericParametersCount;
        public uint genericParameterConstraintsOffset; // TypeIndex
        public int genericParameterConstraintsCount;
        public uint genericContainersOffset; // Il2CppGenericContainer
        public int genericContainersCount;
        public uint nestedTypesOffset; // TypeDefinitionIndex
        public int nestedTypesCount;
        public uint interfacesOffset; // TypeIndex
        public int interfacesCount;
        public uint vtableMethodsOffset; // EncodedMethodIndex
        public int vtableMethodsCount;
        public int interfaceOffsetsOffset; // Il2CppInterfaceOffsetPair
        public int interfaceOffsetsCount;
        public uint typeDefinitionsOffset; // Il2CppTypeDefinition
        public int typeDefinitionsCount;
        [Version(Max = 24.1f)]
        public int rgctxEntriesOffset; // Il2CppRGCTXDefinition
        [Version(Max = 24.1f)]
        public int rgctxEntriesCount;
        public uint imagesOffset; // Il2CppImageDefinition
        public int imagesCount;
        public int assembliesOffset; // Il2CppAssemblyDefinition
        public int assembliesCount;
        [Version(Min = 19)]
        public uint metadataUsageListsOffset; // Il2CppMetadataUsageList
        [Version(Min = 19)]
        public int metadataUsageListsCount;
        [Version(Min = 19)]
        public uint metadataUsagePairsOffset; // Il2CppMetadataUsagePair
        [Version(Min = 19)]
        public int metadataUsagePairsCount;
        [Version(Min = 19)]
        public uint fieldRefsOffset; // Il2CppFieldRef
        [Version(Min = 19)]
        public int fieldRefsCount;
        [Version(Min = 19)]
        public int referencedAssembliesOffset; // int32_t
        [Version(Min = 19)]
        public int referencedAssembliesCount;
        [Version(Min = 21)]
        public uint attributesInfoOffset; // Il2CppCustomAttributeTypeRange
        [Version(Min = 21)]
        public int attributesInfoCount;
        [Version(Min = 21)]
        public uint attributeTypesOffset; // TypeIndex
        [Version(Min = 21)]
        public int attributeTypesCount;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesOffset; // TypeIndex
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterTypesCount;
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesOffset; // Il2CppRange
        [Version(Min = 22)]
        public int unresolvedVirtualCallParameterRangesCount;
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesOffset; // Il2CppWindowsRuntimeTypeNamePair
        [Version(Min = 23)]
        public int windowsRuntimeTypeNamesSize;
        [Version(Min = 24)]
        public int exportedTypeDefinitionsOffset; // TypeDefinitionIndex
        [Version(Min = 24)]
        public int exportedTypeDefinitionsCount;
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

        [Version(Min = 24.1f)]
        public int customAttributeStart;
        [Version(Min = 24.1f)]
        public uint customAttributeCount;
    }

    public class Il2CppTypeDefinition
    {
        public uint nameIndex;
        public uint namespaceIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int byvalTypeIndex;
        public int byrefTypeIndex;

        public int declaringTypeIndex;
        public int parentIndex;
        public int elementTypeIndex; // we can probably remove this one. Only used for enums

        [Version(Max = 24.1f)]
        public int rgctxStartIndex;
        [Version(Max = 24.1f)]
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
        public uint bitfield;
        [Version(Min = 19)]
        public uint token;

        public bool IsValueType => (bitfield & 0x1) == 1;
        public bool IsEnum => ((bitfield >> 1) & 0x1) == 1;
    }

    public class Il2CppMethodDefinition
    {
        public uint nameIndex;
        public int declaringType;
        public int returnType;
        public int parameterStart;
        [Version(Max = 24)]
        public int customAttributeIndex;
        public int genericContainerIndex;
        [Version(Max = 24.1f)]
        public int methodIndex;
        [Version(Max = 24.1f)]
        public int invokerIndex;
        [Version(Max = 24.1f)]
        public int delegateWrapperIndex;
        [Version(Max = 24.1f)]
        public int rgctxStartIndex;
        [Version(Max = 24.1f)]
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
        public int typeIndex;
    }

    public class Il2CppFieldDefinition
    {
        public uint nameIndex;
        public int typeIndex;
        [Version(Max = 24)]
        public int customAttributeIndex;
        [Version(Min = 19)]
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
        [Version(Min = 19)]
        public uint token;
    }

    public class Il2CppCustomAttributeTypeRange
    {
        [Version(Min = 24.1f)]
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
}
