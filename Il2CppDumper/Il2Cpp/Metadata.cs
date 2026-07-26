using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Il2CppDumper
{
    public sealed class Metadata : BinaryStream
    {
        public Il2CppGlobalMetadataHeader header;
        public Il2CppImageDefinition[] imageDefs;
        public Il2CppAssemblyDefinition[] assemblyDefs;
        public Il2CppTypeDefinition[] typeDefs;
        public Il2CppMethodDefinition[] methodDefs;
        public Il2CppParameterDefinition[] parameterDefs;
        public Il2CppFieldDefinition[] fieldDefs;
        private readonly Dictionary<int, Il2CppFieldDefaultValue> fieldDefaultValuesDic;
        private readonly Dictionary<int, Il2CppParameterDefaultValue> parameterDefaultValuesDic;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributeTypeRanges;
        public Il2CppCustomAttributeDataRange[] attributeDataRanges;
        private readonly Dictionary<Il2CppImageDefinition, Dictionary<uint, int>> attributeTypeRangesDic;
        public Il2CppStringLiteral[] stringLiterals;
        private readonly Il2CppMetadataUsageList[] metadataUsageLists;
        private readonly Il2CppMetadataUsagePair[] metadataUsagePairs;
        public int[] attributeTypes;
        public int[] interfaceIndices;
        public Dictionary<Il2CppMetadataUsage, SortedDictionary<uint, uint>> metadataUsageDic;
        public long metadataUsagesCount;
        public int[] nestedTypeIndices;
        public Il2CppEventDefinition[] eventDefs;
        public Il2CppGenericContainer[] genericContainers;
        public Il2CppFieldRef[] fieldRefs;
        public Il2CppGenericParameter[] genericParameters;
        public int[] constraintIndices;
        public uint[] vtableMethods;
        public Il2CppRGCTXDefinition[] rgctxEntries;

        private readonly Dictionary<uint, string> stringCache = new();

        public Metadata(Stream stream) : base(stream)
        {
            var sanity = ReadUInt32();
            if (sanity != 0xFAB11BAF)
            {
                throw new InvalidDataException("ERROR: Metadata file supplied is not valid metadata file.");
            }
            var version = ReadInt32();
            if (version < 0 || version > 1000)
            {
                throw new InvalidDataException("ERROR: Metadata file supplied is not valid metadata file.");
            }
            // Unity 6000.3 introduced v35, v38, and v39 in quick succession.
            if (version < 16 || (version > 31 && version != 35 && version != 38 && version != 39))
            {
                throw new NotSupportedException($"ERROR: Metadata file supplied is not a supported version[{version}].");
            }
            Version = version;
            header = ReadClass<Il2CppGlobalMetadataHeader>(0);
            InitializeVariableIndexWidths();
            if (version == 24)
            {
                if (header.stringLiteralOffset == 264)
                {
                    Version = 24.2;
                    header = ReadClass<Il2CppGlobalMetadataHeader>(0);
                }
                else
                {
                    imageDefs = ReadMetadataClassArray<Il2CppImageDefinition>(header.imagesOffset, header.imagesSize, header.imagesCount);
                    if (imageDefs.Any(x => x.token != 1))
                    {
                        Version = 24.1;
                    }
                }
            }
            imageDefs = ReadMetadataClassArray<Il2CppImageDefinition>(header.imagesOffset, header.imagesSize, header.imagesCount);
            if (Version == 24.2 && header.assembliesSize / 68 < imageDefs.Length)
            {
                Version = 24.4;
            }
            var v241Plus = false;
            if (Version == 24.1 && header.assembliesSize / 64 == imageDefs.Length)
            {
                v241Plus = true;
            }
            if (v241Plus)
            {
                Version = 24.4;
            }
            assemblyDefs = ReadMetadataClassArray<Il2CppAssemblyDefinition>(header.assembliesOffset, header.assembliesSize, header.assembliesCount);
            if (v241Plus)
            {
                Version = 24.1;
            }
            typeDefs = ReadMetadataClassArray<Il2CppTypeDefinition>(header.typeDefinitionsOffset, header.typeDefinitionsSize, header.typeDefinitionsCount);
            methodDefs = ReadMetadataClassArray<Il2CppMethodDefinition>(header.methodsOffset, header.methodsSize, header.methodsCount);
            parameterDefs = ReadMetadataClassArray<Il2CppParameterDefinition>(header.parametersOffset, header.parametersSize, header.parametersCount);
            fieldDefs = ReadMetadataClassArray<Il2CppFieldDefinition>(header.fieldsOffset, header.fieldsSize, header.fieldsCount);
            var fieldDefaultValues = ReadMetadataClassArray<Il2CppFieldDefaultValue>(header.fieldDefaultValuesOffset, header.fieldDefaultValuesSize, header.fieldDefaultValuesCount);
            var parameterDefaultValues = ReadMetadataClassArray<Il2CppParameterDefaultValue>(header.parameterDefaultValuesOffset, header.parameterDefaultValuesSize, header.parameterDefaultValuesCount);
            fieldDefaultValuesDic = fieldDefaultValues.ToDictionary(x => x.fieldIndex);
            parameterDefaultValuesDic = parameterDefaultValues.ToDictionary(x => x.parameterIndex);
            propertyDefs = ReadMetadataClassArray<Il2CppPropertyDefinition>(header.propertiesOffset, header.propertiesSize, header.propertiesCount);
            interfaceIndices = ReadVariableIndexArray(header.interfacesOffset, header.interfacesSize, header.interfacesCount, VariableIndexKind.Type);
            nestedTypeIndices = ReadClassArray<int>(header.nestedTypesOffset, header.nestedTypesSize / 4);
            eventDefs = ReadMetadataClassArray<Il2CppEventDefinition>(header.eventsOffset, header.eventsSize, header.eventsCount);
            genericContainers = ReadMetadataClassArray<Il2CppGenericContainer>(header.genericContainersOffset, header.genericContainersSize, header.genericContainersCount);
            genericParameters = ReadMetadataClassArray<Il2CppGenericParameter>(header.genericParametersOffset, header.genericParametersSize, header.genericParametersCount);
            constraintIndices = ReadVariableIndexArray(header.genericParameterConstraintsOffset, header.genericParameterConstraintsSize, header.genericParameterConstraintsCount, VariableIndexKind.Type);
            vtableMethods = ReadClassArray<uint>(header.vtableMethodsOffset, header.vtableMethodsSize / 4);
            stringLiterals = ReadMetadataClassArray<Il2CppStringLiteral>(header.stringLiteralOffset, header.stringLiteralSize, header.stringLiteralCount);
            if (Version > 16)
            {
                fieldRefs = ReadMetadataClassArray<Il2CppFieldRef>(header.fieldRefsOffset, header.fieldRefsSize, header.fieldRefsCount);
                if (Version < 27)
                {
                    metadataUsageLists = ReadMetadataClassArray<Il2CppMetadataUsageList>(header.metadataUsageListsOffset, header.metadataUsageListsCount);
                    metadataUsagePairs = ReadMetadataClassArray<Il2CppMetadataUsagePair>(header.metadataUsagePairsOffset, header.metadataUsagePairsCount);

                    ProcessingMetadataUsage();
                }
            }
            if (Version > 20 && Version < 29)
            {
                attributeTypeRanges = ReadMetadataClassArray<Il2CppCustomAttributeTypeRange>(header.attributesInfoOffset, header.attributesInfoCount);
                attributeTypes = ReadClassArray<int>(header.attributeTypesOffset, header.attributeTypesCount / 4);
            }
            if (Version >= 29)
            {
                attributeDataRanges = ReadMetadataClassArray<Il2CppCustomAttributeDataRange>(header.attributeDataRangeOffset, header.attributeDataRangeSize, header.attributeDataRangeCount);
            }
            if (Version > 24)
            {
                attributeTypeRangesDic = new Dictionary<Il2CppImageDefinition, Dictionary<uint, int>>();
                foreach (var imageDef in imageDefs)
                {
                    var dic = new Dictionary<uint, int>();
                    attributeTypeRangesDic[imageDef] = dic;
                    var end = imageDef.customAttributeStart + imageDef.customAttributeCount;
                    for (int i = imageDef.customAttributeStart; i < end; i++)
                    {
                        if (Version >= 29)
                        {
                            dic.Add(attributeDataRanges[i].token, i);
                        }
                        else
                        {
                            dic.Add(attributeTypeRanges[i].token, i);
                        }
                    }
                }
            }
            if (Version <= 24.1)
            {
                rgctxEntries = ReadMetadataClassArray<Il2CppRGCTXDefinition>(header.rgctxEntriesOffset, header.rgctxEntriesCount);
            }
        }

        private void InitializeVariableIndexWidths()
        {
            if (Version < 38)
            {
                return;
            }

            SetVariableIndexWidth(VariableIndexKind.TypeDefinition, GetIndexWidth(header.typeDefinitionsCount));
            SetVariableIndexWidth(VariableIndexKind.GenericContainer, GetIndexWidth(header.genericContainersCount));
            SetVariableIndexWidth(
                VariableIndexKind.ParameterDefinition,
                Version >= 39 ? GetIndexWidth(header.parametersCount) : sizeof(int));

            int typeWidth;
            if (header.interfaceOffsetsCount > 0)
            {
                typeWidth = header.interfaceOffsetsSize / header.interfaceOffsetsCount - sizeof(int);
            }
            else if (header.fieldsCount > 0)
            {
                // Il2CppFieldDefinition is nameIndex + TypeIndex + token.
                typeWidth = header.fieldsSize / header.fieldsCount - sizeof(int) * 2;
            }
            else
            {
                typeWidth = sizeof(int);
            }
            SetVariableIndexWidth(VariableIndexKind.Type, typeWidth);
        }

        private static int GetIndexWidth(int elementCount)
        {
            if (elementCount < 0)
            {
                throw new InvalidDataException($"Invalid metadata element count: {elementCount}.");
            }
            if (elementCount <= byte.MaxValue)
            {
                return sizeof(byte);
            }
            if (elementCount <= ushort.MaxValue)
            {
                return sizeof(ushort);
            }
            return sizeof(int);
        }

        private int[] ReadVariableIndexArray(uint addr, int size, int count, VariableIndexKind kind)
        {
            var width = GetVariableIndexWidth(kind);
            var elementCount = Version >= 38 ? count : size / width;
            Position = addr;
            var values = new int[elementCount];
            for (var i = 0; i < values.Length; i++)
            {
                values[i] = ReadVariableIndex(kind);
            }
            return values;
        }

        private T[] ReadMetadataClassArray<T>(uint addr, int size, int count = 0) where T : new()
        {
            var elementCount = Version >= 38 ? count : size / SizeOf(typeof(T));
            return ReadClassArray<T>(addr, elementCount);
        }

        public bool GetFieldDefaultValueFromIndex(int index, out Il2CppFieldDefaultValue value)
        {
            return fieldDefaultValuesDic.TryGetValue(index, out value);
        }

        public bool GetParameterDefaultValueFromIndex(int index, out Il2CppParameterDefaultValue value)
        {
            return parameterDefaultValuesDic.TryGetValue(index, out value);
        }

        public uint GetDefaultValueFromIndex(int index)
        {
            return (uint)(header.fieldAndParameterDefaultValueDataOffset + index);
        }

        public string GetStringFromIndex(uint index)
        {
            if (!stringCache.TryGetValue(index, out var result))
            {
                result = ReadStringToNull(header.stringOffset + index);
                stringCache.Add(index, result);
            }
            return result;
        }

        public int GetCustomAttributeIndex(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token)
        {
            if (Version > 24)
            {
                if (attributeTypeRangesDic[imageDef].TryGetValue(token, out var index))
                {
                    return index;
                }
                else
                {
                    return -1;
                }
            }
            else
            {
                return customAttributeIndex;
            }
        }

        public string GetStringLiteralFromIndex(uint index)
        {
            var stringLiteral = stringLiterals[index];
            var start = (uint)(header.stringLiteralDataOffset + stringLiteral.dataIndex);
            Position = start;
            if (Version < 35)
            {
                return Encoding.UTF8.GetString(ReadBytes((int)stringLiteral.length));
            }

            var end = index + 1 < stringLiterals.Length
                ? (uint)(header.stringLiteralDataOffset + stringLiterals[index + 1].dataIndex)
                : (uint)(header.stringLiteralDataOffset + header.stringLiteralDataSize);
            return Encoding.UTF8.GetString(ReadBytes(checked((int)(end - start))));
        }

        private void ProcessingMetadataUsage()
        {
            metadataUsageDic = new Dictionary<Il2CppMetadataUsage, SortedDictionary<uint, uint>>();
            for (uint i = 1; i <= 6; i++)
            {
                metadataUsageDic[(Il2CppMetadataUsage)i] = new SortedDictionary<uint, uint>();
            }
            foreach (var metadataUsageList in metadataUsageLists)
            {
                for (int i = 0; i < metadataUsageList.count; i++)
                {
                    var offset = metadataUsageList.start + i;
                    if (offset >= metadataUsagePairs.Length)
                    {
                        continue;
                    }
                    var metadataUsagePair = metadataUsagePairs[offset];
                    var usage = GetEncodedIndexType(metadataUsagePair.encodedSourceIndex);
                    var decodedIndex = GetDecodedMethodIndex(metadataUsagePair.encodedSourceIndex);
                    metadataUsageDic[(Il2CppMetadataUsage)usage][metadataUsagePair.destinationIndex] = decodedIndex;
                }
            }
            //metadataUsagesCount = metadataUsagePairs.Max(x => x.destinationIndex) + 1;
            metadataUsagesCount = metadataUsageDic.Max(x => x.Value.Select(y => y.Key).DefaultIfEmpty().Max()) + 1;
        }

        public static uint GetEncodedIndexType(uint index)
        {
            return (index & 0xE0000000) >> 29;
        }

        public uint GetDecodedMethodIndex(uint index)
        {
            if (Version >= 27)
            {
                return (index & 0x1FFFFFFEU) >> 1;
            }
            return index & 0x1FFFFFFFU;
        }

        public int SizeOf(Type type)
        {
            var size = 0;
            foreach (var i in type.GetFields())
            {
                var versionAttributes = i.GetCustomAttributes<VersionAttribute>().ToArray();
                if (versionAttributes.Length > 0)
                {
                    if (!versionAttributes.Any(attr => Version >= attr.Min && Version <= attr.Max))
                        continue;
                }
                var fieldType = i.FieldType;
                var variableIndex = i.GetCustomAttribute<VariableIndexAttribute>();
                if (variableIndex != null)
                {
                    size += GetVariableIndexWidth(variableIndex.Kind);
                }
                else if (fieldType.IsPrimitive)
                {
                    size += GetPrimitiveTypeSize(fieldType.Name);
                }
                else if (fieldType.IsEnum)
                {
                    var e = fieldType.GetField("value__").FieldType;
                    size += GetPrimitiveTypeSize(e.Name);
                }
                else if (fieldType.IsArray)
                {
                    var arrayLengthAttribute = i.GetCustomAttribute<ArrayLengthAttribute>();
                    size += arrayLengthAttribute.Length;
                }
                else
                {
                    size += SizeOf(fieldType);
                }
            }
            return size;

            static int GetPrimitiveTypeSize(string name)
            {
                return name switch
                {
                    "Int32" or "UInt32" => 4,
                    "Int16" or "UInt16" => 2,
                    _ => 0,
                };
            }
        }
    }
}
