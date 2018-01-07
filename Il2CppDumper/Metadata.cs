using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class Metadata : MyBinaryReader
    {
        private Il2CppGlobalMetadataHeader pMetadataHdr;
        public int uiImageCount;
        public int uiNumTypes;
        public Il2CppImageDefinition[] imageDefs;
        public Il2CppTypeDefinition[] typeDefs;
        public Il2CppMethodDefinition[] methodDefs;
        public Il2CppParameterDefinition[] parameterDefs;
        public Il2CppFieldDefinition[] fieldDefs;
        private Il2CppFieldDefaultValue[] fieldDefaultValues;
        private Il2CppParameterDefaultValue[] parameterDefaultValues;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributesInfos;
        private Il2CppStringLiteral[] stringLiterals;
        private Il2CppMetadataUsageList[] metadataUsageLists;
        private Il2CppMetadataUsagePair[] metadataUsagePairs;
        public int[] attributeTypes;
        public int[] interfaceIndices;
        public SortedDictionary<uint, string> stringLiteralsdic;
        public long maxmetadataUsages;
        public int[] nestedTypeIndices;
        public Il2CppEventDefinition[] eventDefs;

        public Metadata(Stream stream) : base(stream)
        {
            var sanity = ReadUInt32();
            if (sanity != 0xFAB11BAF)
                throw new Exception("ERROR: Metadata file supplied is not valid metadata file.");
            version = ReadInt32();
            switch (version)
            {
                case 16:
                case 20:
                case 21:
                case 22:
                case 23:
                case 24:
                    break;
                default:
                    throw new Exception($"ERROR: Metadata file supplied is not a supported version[{version}].");
            }
            //pMetadataHdr
            pMetadataHdr = ReadClass<Il2CppGlobalMetadataHeader>(0);
            //ImageDefinition
            uiImageCount = pMetadataHdr.imagesCount / MySizeOf(typeof(Il2CppImageDefinition));
            uiNumTypes = pMetadataHdr.typeDefinitionsCount / MySizeOf(typeof(Il2CppTypeDefinition));
            imageDefs = ReadClassArray<Il2CppImageDefinition>(pMetadataHdr.imagesOffset, uiImageCount);
            //GetTypeDefinitionFromIndex
            typeDefs = ReadClassArray<Il2CppTypeDefinition>(pMetadataHdr.typeDefinitionsOffset, uiNumTypes);
            //GetMethodDefinitionFromIndex
            methodDefs = ReadClassArray<Il2CppMethodDefinition>(pMetadataHdr.methodsOffset, pMetadataHdr.methodsCount / MySizeOf(typeof(Il2CppMethodDefinition)));
            //GetParameterDefinitionFromIndex
            parameterDefs = ReadClassArray<Il2CppParameterDefinition>(pMetadataHdr.parametersOffset, pMetadataHdr.parametersCount / MySizeOf(typeof(Il2CppParameterDefinition)));
            //GetFieldDefinitionFromIndex
            fieldDefs = ReadClassArray<Il2CppFieldDefinition>(pMetadataHdr.fieldsOffset, pMetadataHdr.fieldsCount / MySizeOf(typeof(Il2CppFieldDefinition)));
            //FieldDefaultValue
            fieldDefaultValues = ReadClassArray<Il2CppFieldDefaultValue>(pMetadataHdr.fieldDefaultValuesOffset, pMetadataHdr.fieldDefaultValuesCount / MySizeOf(typeof(Il2CppFieldDefaultValue)));
            //ParameterDefaultValue
            parameterDefaultValues = ReadClassArray<Il2CppParameterDefaultValue>(pMetadataHdr.parameterDefaultValuesOffset, pMetadataHdr.parameterDefaultValuesCount / MySizeOf(typeof(Il2CppParameterDefaultValue)));
            //GetPropertyDefinitionFromIndex
            propertyDefs = ReadClassArray<Il2CppPropertyDefinition>(pMetadataHdr.propertiesOffset, pMetadataHdr.propertiesCount / MySizeOf(typeof(Il2CppPropertyDefinition)));
            //GetInterfaceFromIndex
            interfaceIndices = ReadClassArray<int>(pMetadataHdr.interfacesOffset, pMetadataHdr.interfacesCount / 4);
            //GetNestedTypeFromIndex
            nestedTypeIndices = ReadClassArray<int>(pMetadataHdr.nestedTypesOffset, pMetadataHdr.nestedTypesCount / 4);
            //GetEventDefinitionFromIndex
            eventDefs = ReadClassArray<Il2CppEventDefinition>(pMetadataHdr.eventsOffset, pMetadataHdr.eventsCount / MySizeOf(typeof(Il2CppEventDefinition)));
            if (version > 16)
            {
                //Il2CppStringLiteral
                stringLiterals = ReadClassArray<Il2CppStringLiteral>(pMetadataHdr.stringLiteralOffset, pMetadataHdr.stringLiteralCount / MySizeOf(typeof(Il2CppStringLiteral)));
                //Il2CppMetadataUsageList
                metadataUsageLists = ReadClassArray<Il2CppMetadataUsageList>(pMetadataHdr.metadataUsageListsOffset, pMetadataHdr.metadataUsageListsCount / MySizeOf(typeof(Il2CppMetadataUsageList)));
                //Il2CppMetadataUsagePair
                metadataUsagePairs = ReadClassArray<Il2CppMetadataUsagePair>(pMetadataHdr.metadataUsagePairsOffset, pMetadataHdr.metadataUsagePairsCount / MySizeOf(typeof(Il2CppMetadataUsagePair)));
                CreateStringLiteralDic();
            }
            if (version > 20)
            {
                //CustomAttributeTypeRange
                attributesInfos = ReadClassArray<Il2CppCustomAttributeTypeRange>(pMetadataHdr.attributesInfoOffset, pMetadataHdr.attributesInfoCount / MySizeOf(typeof(Il2CppCustomAttributeTypeRange)));
                //AttributeTypes
                attributeTypes = ReadClassArray<int>(pMetadataHdr.attributeTypesOffset, pMetadataHdr.attributeTypesCount / 4);
            }
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
            return pMetadataHdr.fieldAndParameterDefaultValueDataOffset + index;
        }

        public string GetStringFromIndex(int index)
        {
            return ReadStringToNull(pMetadataHdr.stringOffset + index);
        }

        private string GetStringLiteralFromIndex(uint index)
        {
            var stringLiteral = stringLiterals[index];
            Position = pMetadataHdr.stringLiteralDataOffset + stringLiteral.dataIndex;
            return Encoding.UTF8.GetString(ReadBytes((int)stringLiteral.length));
        }

        private void CreateStringLiteralDic()
        {
            stringLiteralsdic = new SortedDictionary<uint, string>();
            foreach (var metadataUsageList in metadataUsageLists)
            {
                for (int i = 0; i < metadataUsageList.count; i++)
                {
                    var offset = metadataUsageList.start + i;
                    var metadataUsagePair = metadataUsagePairs[offset];
                    var usage = GetEncodedIndexType(metadataUsagePair.encodedSourceIndex);
                    var decodedIndex = GetDecodedMethodIndex(metadataUsagePair.encodedSourceIndex);
                    if (usage == 5) //kIl2CppMetadataUsageStringLiteral
                    {
                        stringLiteralsdic[metadataUsagePair.destinationIndex] = GetStringLiteralFromIndex(decodedIndex);
                    }
                }
            }
            maxmetadataUsages = stringLiteralsdic.Last().Key + 1;
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
