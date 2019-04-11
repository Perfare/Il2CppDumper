using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class Metadata : MyBinaryReader
    {
        private Il2CppGlobalMetadataHeader metadataHeader;
        public Il2CppImageDefinition[] imageDefs;
        public Il2CppTypeDefinition[] typeDefs;
        public Il2CppMethodDefinition[] methodDefs;
        public Il2CppParameterDefinition[] parameterDefs;
        public Il2CppFieldDefinition[] fieldDefs;
        private Il2CppFieldDefaultValue[] fieldDefaultValues;
        private Il2CppParameterDefaultValue[] parameterDefaultValues;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributeTypeRanges;
        private Il2CppStringLiteral[] stringLiterals;
        private Il2CppMetadataUsageList[] metadataUsageLists;
        private Il2CppMetadataUsagePair[] metadataUsagePairs;
        public int[] attributeTypes;
        public int[] interfaceIndices;
        public Dictionary<uint, SortedDictionary<uint, uint>> metadataUsageDic;
        public long maxMetadataUsages;
        public int[] nestedTypeIndices;
        public Il2CppEventDefinition[] eventDefs;
        public Il2CppGenericContainer[] genericContainers;
        public Il2CppFieldRef[] fieldRefs;

        public Metadata(Stream stream, float version) : base(stream)
        {
            this.version = version;
            metadataHeader = ReadClass<Il2CppGlobalMetadataHeader>();
            if (metadataHeader.sanity != 0xFAB11BAF)
            {
                throw new Exception("ERROR: Metadata file supplied is not valid metadata file.");
            }
            switch (metadataHeader.version)
            {
                case 16:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                case 24:
                    break;
                default:
                    throw new Exception($"ERROR: Metadata file supplied is not a supported version[{version}].");
            }
            imageDefs = ReadMetadataClassArray<Il2CppImageDefinition>(metadataHeader.imagesOffset, metadataHeader.imagesCount);
            typeDefs = ReadMetadataClassArray<Il2CppTypeDefinition>(metadataHeader.typeDefinitionsOffset, metadataHeader.typeDefinitionsCount);
            methodDefs = ReadMetadataClassArray<Il2CppMethodDefinition>(metadataHeader.methodsOffset, metadataHeader.methodsCount);
            parameterDefs = ReadMetadataClassArray<Il2CppParameterDefinition>(metadataHeader.parametersOffset, metadataHeader.parametersCount);
            fieldDefs = ReadMetadataClassArray<Il2CppFieldDefinition>(metadataHeader.fieldsOffset, metadataHeader.fieldsCount);
            fieldDefaultValues = ReadMetadataClassArray<Il2CppFieldDefaultValue>(metadataHeader.fieldDefaultValuesOffset, metadataHeader.fieldDefaultValuesCount);
            parameterDefaultValues = ReadMetadataClassArray<Il2CppParameterDefaultValue>(metadataHeader.parameterDefaultValuesOffset, metadataHeader.parameterDefaultValuesCount);
            propertyDefs = ReadMetadataClassArray<Il2CppPropertyDefinition>(metadataHeader.propertiesOffset, metadataHeader.propertiesCount);
            interfaceIndices = ReadClassArray<int>(metadataHeader.interfacesOffset, metadataHeader.interfacesCount / 4);
            nestedTypeIndices = ReadClassArray<int>(metadataHeader.nestedTypesOffset, metadataHeader.nestedTypesCount / 4);
            eventDefs = ReadMetadataClassArray<Il2CppEventDefinition>(metadataHeader.eventsOffset, metadataHeader.eventsCount);
            genericContainers = ReadMetadataClassArray<Il2CppGenericContainer>(metadataHeader.genericContainersOffset, metadataHeader.genericContainersCount);
            if (version > 16)
            {
                stringLiterals = ReadMetadataClassArray<Il2CppStringLiteral>(metadataHeader.stringLiteralOffset, metadataHeader.stringLiteralCount);
                metadataUsageLists = ReadMetadataClassArray<Il2CppMetadataUsageList>(metadataHeader.metadataUsageListsOffset, metadataHeader.metadataUsageListsCount);
                metadataUsagePairs = ReadMetadataClassArray<Il2CppMetadataUsagePair>(metadataHeader.metadataUsagePairsOffset, metadataHeader.metadataUsagePairsCount);

                ProcessingMetadataUsage();

                fieldRefs = ReadMetadataClassArray<Il2CppFieldRef>(metadataHeader.fieldRefsOffset, metadataHeader.fieldRefsCount);
            }
            if (version > 20)
            {
                attributeTypeRanges = ReadMetadataClassArray<Il2CppCustomAttributeTypeRange>(metadataHeader.attributesInfoOffset, metadataHeader.attributesInfoCount);
                attributeTypes = ReadClassArray<int>(metadataHeader.attributeTypesOffset, metadataHeader.attributeTypesCount / 4);
            }
        }

        private T[] ReadMetadataClassArray<T>(int addr, int count) where T : new()
        {
            return ReadClassArray<T>(addr, count / MySizeOf(typeof(T)));
        }

        public Il2CppFieldDefaultValue GetFieldDefaultValueFromIndex(int index)
        {
            return fieldDefaultValues.FirstOrDefault(x => x.fieldIndex == index);
        }

        public Il2CppParameterDefaultValue GetParameterDefaultValueFromIndex(int index)
        {
            return parameterDefaultValues.FirstOrDefault(x => x.parameterIndex == index);
        }

        public int GetDefaultValueFromIndex(int index)
        {
            return metadataHeader.fieldAndParameterDefaultValueDataOffset + index;
        }

        public string GetStringFromIndex(int index)
        {
            return ReadStringToNull(metadataHeader.stringOffset + index);
        }

        public int GetCustomAttributeIndex(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token)
        {
            if (version > 24)
            {
                var end = imageDef.customAttributeStart + imageDef.customAttributeCount;
                for (int i = imageDef.customAttributeStart; i < end; i++)
                {
                    if (attributeTypeRanges[i].token == token)
                    {
                        return i;
                    }
                }
                return -1;
            }
            else
            {
                return customAttributeIndex;
            }
        }

        public string GetStringLiteralFromIndex(uint index)
        {
            var stringLiteral = stringLiterals[index];
            Position = metadataHeader.stringLiteralDataOffset + stringLiteral.dataIndex;
            return Encoding.UTF8.GetString(ReadBytes((int)stringLiteral.length));
        }

        private void ProcessingMetadataUsage()
        {
            metadataUsageDic = new Dictionary<uint, SortedDictionary<uint, uint>>();
            for (uint i = 1; i <= 6u; i++)
            {
                metadataUsageDic[i] = new SortedDictionary<uint, uint>();
            }
            foreach (var metadataUsageList in metadataUsageLists)
            {
                for (int i = 0; i < metadataUsageList.count; i++)
                {
                    var offset = metadataUsageList.start + i;
                    var metadataUsagePair = metadataUsagePairs[offset];
                    var usage = GetEncodedIndexType(metadataUsagePair.encodedSourceIndex);
                    var decodedIndex = GetDecodedMethodIndex(metadataUsagePair.encodedSourceIndex);
                    metadataUsageDic[usage][metadataUsagePair.destinationIndex] = decodedIndex;
                }
            }
            maxMetadataUsages = metadataUsageDic.Max(x => x.Value.Max(y => y.Key)) + 1;
        }

        private uint GetEncodedIndexType(uint index)
        {
            return (index & 0xE0000000) >> 29;
        }

        private uint GetDecodedMethodIndex(uint index)
        {
            return index & 0x1FFFFFFFU;
        }

        private int MySizeOf(Type type)
        {
            var size = 0;
            foreach (var i in type.GetFields())
            {
                var attr = (VersionAttribute)Attribute.GetCustomAttribute(i, typeof(VersionAttribute));
                if (attr != null)
                {
                    if (version < attr.Min || version > attr.Max)
                        continue;
                }
                switch (i.FieldType.Name)
                {
                    case "Int32":
                    case "UInt32":
                        size += 4;
                        break;
                    case "Int16":
                    case "UInt16":
                        size += 2;
                        break;
                }
            }
            return size;
        }
    }
}
