using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
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
        private readonly Dictionary<ParameterIndex, Il2CppParameterDefaultValue> parameterDefaultValuesDic;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributeTypeRanges;
        public Il2CppCustomAttributeDataRange[] attributeDataRanges;
        private readonly Dictionary<Il2CppImageDefinition, Dictionary<uint, int>> attributeTypeRangesDic;
        public Il2CppStringLiteral[] stringLiterals;
        private readonly Il2CppMetadataUsageList[] metadataUsageLists;
        private readonly Il2CppMetadataUsagePair[] metadataUsagePairs;
        public int[] attributeTypes;
        public readonly Il2CppInterfaceOffsetPair[] interfaceOffsetPairs;
        public Dictionary<Il2CppMetadataUsage, SortedDictionary<uint, uint>> metadataUsageDic;
        public long metadataUsagesCount;
        public int[] nestedTypeIndices;
        public Il2CppEventDefinition[] eventDefs;
        public Il2CppGenericContainer[] genericContainers;
        public Il2CppFieldRef[] fieldRefs;
        public Il2CppGenericParameter[] genericParameters;
        public Il2CppConstraintIndex[] constraintIndices;
        public uint[] vtableMethods;
        public Il2CppRGCTXDefinition[] rgctxEntries;

        private readonly Dictionary<uint, string> stringCache = new();

        // Types with custom sizes
        // Keep in sync with vm/MetadataDeserialization.h
        public static int typeIndexSize;
        public static int typeDefinitionIndexSize;
        public static int genericContainerIndexSize;
        public static int parameterIndexSize;

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
            if (version < 16 || version > 39)
            {
                throw new NotSupportedException($"ERROR: Metadata file supplied is not a supported version[{version}].");
            }
            Version = version;
            header = ReadClass<Il2CppGlobalMetadataHeader>(0);
            if (version == 24)
            {
                if (header.stringLiteralOffset == 264)
                {
                    Version = 24.2;
                    header = ReadClass<Il2CppGlobalMetadataHeader>(0);
                }
                else
                {
                    imageDefs = ReadMetadataClassArray<Il2CppImageDefinition>(header.imagesOffset, header.imagesSize);
                    if (imageDefs.Any(x => x.token != 1))
                    {
                        Version = 24.1;
                    }
                }
            }

            // Set custom sizes
            if (Version >= 38)
            {
                // Current definition of Il2CppParameterDefinition has size 8 (not counting typeIndex);
                //
                //  public class Il2CppParameterDefinition
                //  {
                //      public uint nameIndex;
                //      public uint token;
                //      [Version(Max = 24)]
                //      public int customAttributeIndex;
                //      public TypeIndex typeIndex;
                //  }
                //
                // By computing the size of this as reported by the header, we can infer TypeIndex size

                int sizeOfIl2CppParameterDefinition = (int)(header.parameters.size / header.parameters.count);
                typeIndexSize = sizeOfIl2CppParameterDefinition - 8;
                typeDefinitionIndexSize = GetIndexSize((int)header.typeDefinitions.count);
                genericContainerIndexSize = GetIndexSize((int)header.genericContainers.count);
                parameterIndexSize = GetIndexSize((int)header.parameters.count);
            }
            else
            {
                // Before version 38, these were always ints
                typeIndexSize = 4;
                typeDefinitionIndexSize = 4;
                genericContainerIndexSize = 4;
                parameterIndexSize = 4;
            }

            imageDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppImageDefinition>(header.imagesOffset, header.imagesSize)
                : ReadMetadataClassArray<Il2CppImageDefinition>(header.images.offset, (int)header.images.size);
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
            assemblyDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppAssemblyDefinition>(header.assembliesOffset, header.assembliesSize)
                : ReadMetadataClassArray<Il2CppAssemblyDefinition>(header.assemblies.offset, (int)header.assemblies.size);
            if (v241Plus)
            {
                Version = 24.1;
            }
            typeDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppTypeDefinition>(header.typeDefinitionsOffset, header.typeDefinitionsSize)
                : ReadMetadataClassArray<Il2CppTypeDefinition>(header.typeDefinitions.offset, (int)header.typeDefinitions.size);
            methodDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppMethodDefinition>(header.methodsOffset, header.methodsSize)
                : ReadMetadataClassArray<Il2CppMethodDefinition>(header.methods.offset, (int)header.methods.size);
            parameterDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppParameterDefinition>(header.parametersOffset, header.parametersSize)
                : ReadMetadataClassArray<Il2CppParameterDefinition>(header.parameters.offset, (int)header.parameters.size);
            fieldDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppFieldDefinition>(header.fieldsOffset, header.fieldsSize)
                : ReadMetadataClassArray<Il2CppFieldDefinition>(header.fields.offset, (int)header.fields.size);
            var fieldDefaultValues = Version < 38
                ? ReadMetadataClassArray<Il2CppFieldDefaultValue>(header.fieldDefaultValuesOffset, header.fieldDefaultValuesSize)
                : ReadMetadataClassArray<Il2CppFieldDefaultValue>(header.fieldDefaultValues.offset, (int)header.fieldDefaultValues.size);
            var parameterDefaultValues = Version < 38
                ? ReadMetadataClassArray<Il2CppParameterDefaultValue>(header.parameterDefaultValuesOffset, header.parameterDefaultValuesSize)
                : ReadMetadataClassArray<Il2CppParameterDefaultValue>(header.parameterDefaultValues.offset, (int)header.parameterDefaultValues.size);
            fieldDefaultValuesDic = fieldDefaultValues.ToDictionary(x => x.fieldIndex);
            parameterDefaultValuesDic = parameterDefaultValues.ToDictionary(x => x.parameterIndex);
            propertyDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppPropertyDefinition>(header.propertiesOffset, header.propertiesSize)
                : ReadMetadataClassArray<Il2CppPropertyDefinition>(header.properties.offset, (int)header.properties.size);
            interfaceOffsetPairs = Version < 38
                ? ReadMetadataClassArray<Il2CppInterfaceOffsetPair>(header.interfacesOffset, header.interfacesSize)
                : ReadMetadataClassArray<Il2CppInterfaceOffsetPair>(header.interfaces.offset, (int)header.interfaces.size);
            nestedTypeIndices = Version < 38
                ? ReadClassArray<int>(header.nestedTypesOffset, header.nestedTypesSize / 4)
                : ReadClassArray<int>(header.nestedTypes.offset, header.nestedTypes.size / 4);
            eventDefs = Version < 38
                ? ReadMetadataClassArray<Il2CppEventDefinition>(header.eventsOffset, header.eventsSize)
                : ReadMetadataClassArray<Il2CppEventDefinition>(header.events.offset, (int)header.events.size);
            genericContainers = Version < 38
                ? ReadMetadataClassArray<Il2CppGenericContainer>(header.genericContainersOffset, header.genericContainersSize)
                : ReadMetadataClassArray<Il2CppGenericContainer>(header.genericContainers.offset, (int)header.genericContainers.size);
            genericParameters = Version < 38
                ? ReadMetadataClassArray<Il2CppGenericParameter>(header.genericParametersOffset, header.genericParametersSize)
                : ReadMetadataClassArray<Il2CppGenericParameter>(header.genericParameters.offset, (int)header.genericParameters.size);
            constraintIndices = Version < 38
                ? ReadMetadataClassArray<Il2CppConstraintIndex>(header.genericParameterConstraintsOffset, header.genericParameterConstraintsSize)
                : ReadMetadataClassArray<Il2CppConstraintIndex>(header.genericParameterConstraints.offset, (int)header.genericParameterConstraints.size);
            vtableMethods = Version < 38
                ? ReadClassArray<uint>(header.vtableMethodsOffset, header.vtableMethodsSize / 4)
                : ReadClassArray<uint>(header.vtableMethods.offset, header.vtableMethods.size / 4);
            stringLiterals = Version < 38
                ? ReadMetadataClassArray<Il2CppStringLiteral>(header.stringLiteralOffset, header.stringLiteralSize)
                : ReadMetadataClassArray<Il2CppStringLiteral>(header.stringLiterals.offset, (int)header.stringLiterals.size);
            if (Version > 16)
            {
                fieldRefs = Version < 38
                    ? ReadMetadataClassArray<Il2CppFieldRef>(header.fieldRefsOffset, header.fieldRefsSize)
                    : ReadMetadataClassArray<Il2CppFieldRef>(header.fieldRefs.offset, (int)header.fieldRefs.size);
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
                attributeDataRanges = Version < 38
                    ? ReadMetadataClassArray<Il2CppCustomAttributeDataRange>(header.attributeDataRangeOffset, header.attributeDataRangeSize)
                    : ReadMetadataClassArray<Il2CppCustomAttributeDataRange>(header.attributeDataRanges.offset, (int)header.attributeDataRanges.size);
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

        public static int GetIndexSize(int count)
        {
            if (count <= 0xFF) return 1;
            if (count <= 0xFFFF) return 2;
            return 4;
        }

        private T[] ReadMetadataClassArray<T>(uint addr, int count) where T : new()
        {
            return ReadClassArray<T>(addr, count / SizeOf(typeof(T)));
        }

        public bool GetFieldDefaultValueFromIndex(int index, out Il2CppFieldDefaultValue value)
        {
            return fieldDefaultValuesDic.TryGetValue(index, out value);
        }

        public bool GetParameterDefaultValueFromIndex(int index, out Il2CppParameterDefaultValue value)
        {
            return parameterDefaultValuesDic.TryGetValue(new ParameterIndex(index), out value);
        }

        public uint GetDefaultValueFromIndex(int index)
        {
            return (uint)((Version < 38 ? header.fieldAndParameterDefaultValueDataOffset : header.fieldAndParameterDefaultValueData.offset) + index);
        }

        public string GetStringFromIndex(uint index)
        {
            if (!stringCache.TryGetValue(index, out var result))
            {
                result = ReadStringToNull((Version <= 35 ? header.stringOffset : header.strings.offset) + index);
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
            var currentLiteral = stringLiterals[index];
            int stringLength = 0;
            if (index < stringLiterals.Length - 1)
            {
                var nextLiteral = stringLiterals[index + 1];
                stringLength = nextLiteral.dataIndex - currentLiteral.dataIndex;
            }
            else
            {
                // Last string, read to end of section
                stringLength = (Version < 38 ? header.stringLiteralDataSize : (int)header.stringLiteralData.size) - currentLiteral.dataIndex;
            }

            Position = (uint)((Version < 38 ? header.stringLiteralDataOffset : header.stringLiteralData.offset) + currentLiteral.dataIndex);
            return Encoding.UTF8.GetString(ReadBytes(stringLength));
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
                var attr = (VersionAttribute)Attribute.GetCustomAttribute(i, typeof(VersionAttribute));
                if (attr != null)
                {
                    if (Version < attr.Min || Version > attr.Max)
                        continue;
                }
                var fieldType = i.FieldType;
                if (fieldType.IsPrimitive)
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
                else if (fieldType == typeof(TypeIndex))
                {
                    size += typeIndexSize;
                }
                else if (fieldType == typeof(TypeDefinitionIndex))
                {
                    size += typeDefinitionIndexSize;
                }
                else if (fieldType == typeof(GenericContainerIndex))
                {
                    size += genericContainerIndexSize;
                }
                else if (fieldType == typeof(ParameterIndex))
                {
                    size += parameterIndexSize;
                }
                else
                {
                    size += SizeOf(fieldType);
                }
            }
            return size;
        }

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
