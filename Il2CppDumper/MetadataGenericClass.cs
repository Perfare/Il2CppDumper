namespace Il2CppDumper
{
    public class Il2CppGlobalMetadataHeader
    {
        public int stringLiteralOffset; // string data for managed code
        public int stringLiteralCount;
        public int stringLiteralDataOffset;
        public int stringOffset; // string data for metadata
        public int propertiesOffset; // Il2CppPropertyDefinition
        public int propertiesCount;
        public int methodsOffset; // Il2CppMethodDefinition
        public int methodsCount;
        public int fieldDefaultValuesOffset; // Il2CppFieldDefaultValue
        public int fieldDefaultValuesCount;
        public int fieldAndParameterDefaultValueDataOffset; // uint8_t
        public int parametersOffset; // Il2CppParameterDefinition
        public int parametersCount;
        public int fieldsOffset; // Il2CppFieldDefinition
        public int fieldsCount;
        public int interfacesOffset; // TypeIndex
        public int interfacesCount;
        public int typeDefinitionsOffset; // Il2CppTypeDefinition
        public int typeDefinitionsCount;
        public int imagesOffset; // Il2CppImageDefinition
        public int imagesCount;
        public int metadataUsageListsOffset; // Il2CppMetadataUsageList
        public int metadataUsageListsCount;
        public int metadataUsagePairsOffset; // Il2CppMetadataUsagePair
        public int metadataUsagePairsCount;
        public int attributesInfoOffset; // Il2CppCustomAttributeTypeRange
        public int attributesInfoCount;
        public int attributeTypesOffset; // TypeIndex
        public int attributeTypesCount;
    }

    public class Il2CppImageDefinition
    {
        public int nameIndex;
        public int typeStart;
    }

    public class Il2CppTypeDefinition
    {
        public int nameIndex;
        public int namespaceIndex;
        public int customAttributeIndex;

        public int parentIndex;

        public uint flags;

        public int fieldStart;
        public int methodStart;
        public int propertyStart;
        public int interfacesStart;

        public ushort method_count;
        public ushort property_count;
        public ushort field_count;
        public ushort interfaces_count;
    }

    public class Il2CppMethodDefinition
    {
        public int nameIndex;
        public int returnType;
        public int parameterStart;
        public int customAttributeIndex;
        public int methodIndex;
        public ushort parameterCount;
        public ushort flags;
    }

    public class Il2CppParameterDefinition
    {
        public int nameIndex;
        public int typeIndex;
    }

    public class Il2CppFieldDefinition
    {
        public int nameIndex;
        public int typeIndex;
        public int customAttributeIndex;
    }

    public class Il2CppFieldDefaultValue
    {
        public int fieldIndex;
        public int typeIndex;
        public int dataIndex;
    }

    public class Il2CppPropertyDefinition
    {
        public int nameIndex;
        public int get;
        public int set;
        public int customAttributeIndex;
    }

    public class Il2CppCustomAttributeTypeRange
    {
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
}
