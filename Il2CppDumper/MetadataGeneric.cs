using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.MyCopy;

namespace Il2CppDumper
{
    class MetadataGeneric : MyBinaryReader
    {
        public int version;
        private Il2CppGlobalMetadataHeader pMetadataHdr;
        public int uiImageCount;
        public int uiNumTypes;
        public Il2CppImageDefinition[] imageDefs;
        public Il2CppTypeDefinition[] typeDefs;
        public Il2CppMethodDefinition[] methodDefs;
        public Il2CppParameterDefinition[] parameterDefs;
        public Il2CppFieldDefinition[] fieldDefs;
        private Il2CppFieldDefaultValue[] fieldDefaultValues;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributesInfos;
        private Il2CppStringLiteral[] stringLiterals;
        public Il2CppMetadataUsageList[] metadataUsageLists;
        public Il2CppMetadataUsagePair[] metadataUsagePairs;
        public int[] attributeTypes;
        public int[] interfaceIndices;
        public SortedDictionary<uint, string> stringLiteralsdic;
        public long maxmetadataUsages;


        public MetadataGeneric(Stream stream) : base(stream)
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
            Position = 0;
            //pMetadataHdr
            var @namespace = "Il2CppDumper.v" + version + ".";
            var ReadClass = GetType().GetMethod("ReadClass", Type.EmptyTypes);
            var ReadClassArray = GetType().GetMethod("ReadClassArray");
            var m = ReadClass.MakeGenericMethod(Type.GetType(@namespace + "Il2CppGlobalMetadataHeader"));
            Copy(out pMetadataHdr, m.Invoke(this, null));
            //ImageDefinition
            var t = Type.GetType(@namespace + "Il2CppImageDefinition");
            uiImageCount = pMetadataHdr.imagesCount / MySizeOf(t);
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out imageDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.imagesOffset, uiImageCount }));
            //TypeDefinition
            t = Type.GetType(@namespace + "Il2CppTypeDefinition");
            uiNumTypes = pMetadataHdr.typeDefinitionsCount / MySizeOf(t);
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out typeDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.typeDefinitionsOffset, uiNumTypes }));
            //MethodDefinition
            t = Type.GetType(@namespace + "Il2CppMethodDefinition");
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out methodDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.methodsOffset, pMetadataHdr.methodsCount / MySizeOf(t) }));
            //ParameterDefinition
            t = Type.GetType(@namespace + "Il2CppParameterDefinition");
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out parameterDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.parametersOffset, pMetadataHdr.parametersCount / MySizeOf(t) }));
            //FieldDefinition
            t = Type.GetType(@namespace + "Il2CppFieldDefinition");
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out fieldDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.fieldsOffset, pMetadataHdr.fieldsCount / MySizeOf(t) }));
            //FieldDefaultValue
            t = Type.GetType(@namespace + "Il2CppFieldDefaultValue");
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out fieldDefaultValues, (IList)m.Invoke(this, new object[] { pMetadataHdr.fieldDefaultValuesOffset, pMetadataHdr.fieldDefaultValuesCount / MySizeOf(t) }));
            //PropertyDefinition
            t = Type.GetType(@namespace + "Il2CppPropertyDefinition");
            m = ReadClassArray.MakeGenericMethod(t);
            Copy(out propertyDefs, (IList)m.Invoke(this, new object[] { pMetadataHdr.propertiesOffset, pMetadataHdr.propertiesCount / MySizeOf(t) }));
            //GetInterfaceFromIndex
            interfaceIndices = ReadClassArray<int>(pMetadataHdr.interfacesOffset, pMetadataHdr.interfacesCount / 4);
            if (version > 16)
            {
                //Il2CppStringLiteral
                t = Type.GetType(@namespace + "Il2CppStringLiteral");
                m = ReadClassArray.MakeGenericMethod(t);
                Copy(out stringLiterals, (IList)m.Invoke(this, new object[] { pMetadataHdr.stringLiteralOffset, pMetadataHdr.stringLiteralCount / MySizeOf(t) }));
                //Il2CppMetadataUsageList
                t = Type.GetType(@namespace + "Il2CppMetadataUsageList");
                m = ReadClassArray.MakeGenericMethod(t);
                Copy(out metadataUsageLists, (IList)m.Invoke(this, new object[] { pMetadataHdr.metadataUsageListsOffset, pMetadataHdr.metadataUsageListsCount / MySizeOf(t) }));
                //Il2CppMetadataUsagePair
                t = Type.GetType(@namespace + "Il2CppMetadataUsagePair");
                m = ReadClassArray.MakeGenericMethod(t);
                Copy(out metadataUsagePairs, (IList)m.Invoke(this, new object[] { pMetadataHdr.metadataUsagePairsOffset, pMetadataHdr.metadataUsagePairsCount / MySizeOf(t) }));
                CreateStringLiteralDic();
            }
            if (version > 20)
            {
                //CustomAttributeTypeRange
                t = Type.GetType(@namespace + "Il2CppCustomAttributeTypeRange");
                m = ReadClassArray.MakeGenericMethod(t);
                Copy(out attributesInfos, (IList)m.Invoke(this, new object[] { pMetadataHdr.attributesInfoOffset, pMetadataHdr.attributesInfoCount / MySizeOf(t) }));
                //AttributeTypes
                attributeTypes = ReadClassArray<int>(pMetadataHdr.attributeTypesOffset, pMetadataHdr.attributeTypesCount / 4);
            }
        }

        public Il2CppFieldDefaultValue GetFieldDefaultFromIndex(int idx)
        {
            return fieldDefaultValues.FirstOrDefault(x => x.fieldIndex == idx);
        }

        public int GetDefaultValueFromIndex(int idx)
        {
            return pMetadataHdr.fieldAndParameterDefaultValueDataOffset + idx;
        }

        public string GetString(int idx)
        {
            return ReadStringToNull(pMetadataHdr.stringOffset + idx);
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

        private static int MySizeOf(Type type)
        {
            var size = 0;
            foreach (var i in type.GetFields())
            {
                if (i.FieldType == typeof(int))
                {
                    size += 4;
                }
                else if (i.FieldType == typeof(uint))
                {
                    size += 4;
                }
                else if (i.FieldType == typeof(short))
                {
                    size += 2;
                }
                else if (i.FieldType == typeof(ushort))
                {
                    size += 2;
                }
            }
            return size;
        }
    }
}
