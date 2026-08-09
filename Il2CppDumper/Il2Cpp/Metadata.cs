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
            // v32-v38 were never shipped publicly; v39 (Unity 6.x) is a distinct
            // format and is handled explicitly rather than by an open-ended range.
            if (version < 16 || (version > 31 && version != 39))
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
            imageDefs = ReadMetadataClassArray<Il2CppImageDefinition>(header.imagesOffset, header.imagesSize);
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
            assemblyDefs = ReadMetadataClassArray<Il2CppAssemblyDefinition>(header.assembliesOffset, header.assembliesSize);
            if (v241Plus)
            {
                Version = 24.1;
            }
            typeDefs = ReadMetadataClassArray<Il2CppTypeDefinition>(header.typeDefinitionsOffset, header.typeDefinitionsSize);
            methodDefs = ReadMetadataClassArray<Il2CppMethodDefinition>(header.methodsOffset, header.methodsSize);
            parameterDefs = ReadMetadataClassArray<Il2CppParameterDefinition>(header.parametersOffset, header.parametersSize);
            fieldDefs = ReadMetadataClassArray<Il2CppFieldDefinition>(header.fieldsOffset, header.fieldsSize);
            var fieldDefaultValues = ReadMetadataClassArray<Il2CppFieldDefaultValue>(header.fieldDefaultValuesOffset, header.fieldDefaultValuesSize);
            var parameterDefaultValues = ReadMetadataClassArray<Il2CppParameterDefaultValue>(header.parameterDefaultValuesOffset, header.parameterDefaultValuesSize);
            fieldDefaultValuesDic = fieldDefaultValues.ToDictionary(x => x.fieldIndex);
            parameterDefaultValuesDic = parameterDefaultValues.ToDictionary(x => x.parameterIndex);
            propertyDefs = ReadMetadataClassArray<Il2CppPropertyDefinition>(header.propertiesOffset, header.propertiesSize);
            // v39 narrowed the standalone TypeIndex arrays to uint16 as well.
            if (Version >= 39)
            {
                interfaceIndices = Array.ConvertAll(
                    ReadClassArray<ushort>(header.interfacesOffset, header.interfacesSize / 2), WidenIndexV39);
            }
            else
            {
                interfaceIndices = ReadClassArray<int>(header.interfacesOffset, header.interfacesSize / 4);
            }
            nestedTypeIndices = ReadClassArray<int>(header.nestedTypesOffset, header.nestedTypesSize / 4);
            eventDefs = ReadMetadataClassArray<Il2CppEventDefinition>(header.eventsOffset, header.eventsSize);
            genericContainers = ReadMetadataClassArray<Il2CppGenericContainer>(header.genericContainersOffset, header.genericContainersSize);
            genericParameters = ReadMetadataClassArray<Il2CppGenericParameter>(header.genericParametersOffset, header.genericParametersSize);
            if (Version >= 39)
            {
                constraintIndices = Array.ConvertAll(
                    ReadClassArray<ushort>(header.genericParameterConstraintsOffset, header.genericParameterConstraintsSize / 2), WidenIndexV39);
            }
            else
            {
                constraintIndices = ReadClassArray<int>(header.genericParameterConstraintsOffset, header.genericParameterConstraintsSize / 4);
            }
            vtableMethods = ReadClassArray<uint>(header.vtableMethodsOffset, header.vtableMethodsSize / 4);
            stringLiterals = ReadMetadataClassArray<Il2CppStringLiteral>(header.stringLiteralOffset, header.stringLiteralSize);
            if (Version > 16)
            {
                fieldRefs = ReadMetadataClassArray<Il2CppFieldRef>(header.fieldRefsOffset, header.fieldRefsSize);
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
                attributeDataRanges = ReadMetadataClassArray<Il2CppCustomAttributeDataRange>(header.attributeDataRangeOffset, header.attributeDataRangeSize);
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
            if (Version >= 39)
            {
                FixIndexesV39();
            }
        }

        /// <summary>
        /// Widens a v39 uint16 index into the int the rest of the dumper expects.
        /// 0xFFFF is the "no value" sentinel and becomes -1, which caps usable
        /// indexes at 65534 - well above anything Unity emits today.
        /// </summary>
        private static int WidenIndexV39(ushort value)
        {
            return value == ushort.MaxValue ? -1 : value;
        }

        /// <summary>
        /// v39 narrowed a set of index fields from int32 to uint16 and dropped
        /// Il2CppTypeDefinition.elementTypeIndex and Il2CppStringLiteral.length
        /// outright. Everything is normalised back into the pre-v39 fields here so
        /// no downstream consumer needs to know about the format change.
        /// </summary>
        private void FixIndexesV39()
        {
            foreach (var typeDef in typeDefs)
            {
                typeDef.byvalTypeIndex = WidenIndexV39(typeDef.byvalTypeIndexV39);
                typeDef.declaringTypeIndex = WidenIndexV39(typeDef.declaringTypeIndexV39);
                typeDef.parentIndex = WidenIndexV39(typeDef.parentIndexV39);
                typeDef.genericContainerIndex = WidenIndexV39(typeDef.genericContainerIndexV39);
            }
            foreach (var methodDef in methodDefs)
            {
                methodDef.declaringType = WidenIndexV39(methodDef.declaringTypeV39);
                methodDef.returnType = WidenIndexV39(methodDef.returnTypeV39);
                methodDef.genericContainerIndex = WidenIndexV39(methodDef.genericContainerIndexV39);
            }
            foreach (var parameterDef in parameterDefs)
            {
                parameterDef.typeIndex = WidenIndexV39(parameterDef.typeIndexV39);
            }
            foreach (var fieldDef in fieldDefs)
            {
                fieldDef.typeIndex = WidenIndexV39(fieldDef.typeIndexV39);
            }
            foreach (var eventDef in eventDefs)
            {
                eventDef.typeIndex = WidenIndexV39(eventDef.typeIndexV39);
            }
            foreach (var genericParameter in genericParameters)
            {
                genericParameter.ownerIndex = WidenIndexV39(genericParameter.ownerIndexV39);
            }
            foreach (var imageDef in imageDefs)
            {
                imageDef.typeStart = imageDef.typeStartV39;
                imageDef.typeCount = imageDef.typeCountV39;
            }
            foreach (var fieldDefaultValue in fieldDefaultValuesDic.Values)
            {
                fieldDefaultValue.typeIndex = WidenIndexV39(fieldDefaultValue.typeIndexV39);
            }
            foreach (var parameterDefaultValue in parameterDefaultValuesDic.Values)
            {
                parameterDefaultValue.typeIndex = WidenIndexV39(parameterDefaultValue.typeIndexV39);
            }
            if (fieldRefs != null)
            {
                foreach (var fieldRef in fieldRefs)
                {
                    fieldRef.typeIndex = WidenIndexV39(fieldRef.typeIndexV39);
                }
            }

            // v39 merged parentIndex and elementTypeIndex into a single slot. An
            // enum's parent is always System.Enum and therefore redundant, so for
            // enums the slot carries the underlying type instead; every other type
            // stores its parent there as before. Split them back apart, or the
            // generated enums end up deriving from their underlying type and every
            // enum-typed custom attribute argument becomes unserialisable.
            var systemEnumTypeIndex = -1;
            foreach (var typeDef in typeDefs)
            {
                if (GetStringFromIndex(typeDef.nameIndex) == "Enum"
                    && GetStringFromIndex(typeDef.namespaceIndex) == "System")
                {
                    systemEnumTypeIndex = typeDef.byvalTypeIndex;
                    break;
                }
            }
            if (systemEnumTypeIndex < 0)
            {
                Console.WriteLine("WARNING: System.Enum not found; enum base types will be wrong.");
            }
            foreach (var typeDef in typeDefs)
            {
                if (typeDef.IsEnum)
                {
                    typeDef.elementTypeIndex = typeDef.parentIndex;
                    if (systemEnumTypeIndex >= 0)
                    {
                        typeDef.parentIndex = systemEnumTypeIndex;
                    }
                }
                else
                {
                    typeDef.elementTypeIndex = -1;
                }
            }

            // The string literal table is now a sentinel-terminated list of offsets:
            // the final entry exists only to bound the one before it.
            if (stringLiterals.Length > 0)
            {
                for (var i = 0; i < stringLiterals.Length - 1; i++)
                {
                    stringLiterals[i].length = (uint)(stringLiterals[i + 1].dataIndex - stringLiterals[i].dataIndex);
                }
                Array.Resize(ref stringLiterals, stringLiterals.Length - 1);
            }
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
            Position = (uint)(header.stringLiteralDataOffset + stringLiteral.dataIndex);
            return Encoding.UTF8.GetString(ReadBytes((int)stringLiteral.length));
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
