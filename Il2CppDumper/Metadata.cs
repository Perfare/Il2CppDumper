using System;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    class Metadata : MyBinaryReader
    {
        private Il2CppGlobalMetadataHeader pMetadataHdr;
        public int uiImageCount;
        public int uiNumTypes;
        public Il2CppImageDefinition[] imageDefs;
        public Il2CppTypeDefinition[] typeDefs;
        public Il2CppMethodDefinition[] methodDefs;
        public Il2CppParameterDefinition[] parameterDefs;
        public Il2CppFieldDefinition[] fieldDefs;
        public Il2CppFieldDefaultValue[] fieldDefaultValues;
        public Il2CppPropertyDefinition[] propertyDefs;
        public Il2CppCustomAttributeTypeRange[] attributesInfos;
        public int[] attributeTypes;

        public Metadata(Stream stream) : base(stream)
        {
            pMetadataHdr = ReadClass<Il2CppGlobalMetadataHeader>();
            if (pMetadataHdr.sanity != 0xFAB11BAF)
            {
                throw new Exception("ERROR: Metadata file supplied is not valid metadata file.");
            }
            if (pMetadataHdr.version != 21 && pMetadataHdr.version != 22)
            {
                throw new Exception($"ERROR: Metadata file supplied is not a supported version[{pMetadataHdr.version}].");
            }
            uiImageCount = pMetadataHdr.imagesCount / MySizeOf(typeof(Il2CppImageDefinition));
            uiNumTypes = pMetadataHdr.typeDefinitionsCount / MySizeOf(typeof(Il2CppTypeDefinition));
            imageDefs = ReadClassArray<Il2CppImageDefinition>(pMetadataHdr.imagesOffset, uiImageCount);
            //GetTypeDefFromIndex
            typeDefs = ReadClassArray<Il2CppTypeDefinition>(pMetadataHdr.typeDefinitionsOffset, uiNumTypes);
            //GetMethodDefinition
            methodDefs = ReadClassArray<Il2CppMethodDefinition>(pMetadataHdr.methodsOffset, pMetadataHdr.methodsCount / MySizeOf(typeof(Il2CppMethodDefinition)));
            //GetParameterFromIndex
            parameterDefs = ReadClassArray<Il2CppParameterDefinition>(pMetadataHdr.parametersOffset, pMetadataHdr.parametersCount / MySizeOf(typeof(Il2CppParameterDefinition)));
            //GetFieldDefFromIndex
            fieldDefs = ReadClassArray<Il2CppFieldDefinition>(pMetadataHdr.fieldsOffset, pMetadataHdr.fieldsCount / MySizeOf(typeof(Il2CppFieldDefinition)));
            //GetFieldDefaultValuesFromIndex
            fieldDefaultValues = ReadClassArray<Il2CppFieldDefaultValue>(pMetadataHdr.fieldDefaultValuesOffset, pMetadataHdr.fieldDefaultValuesCount / MySizeOf(typeof(Il2CppFieldDefaultValue)));
            //GetPropertyDefinitionFromIndex
            propertyDefs = ReadClassArray<Il2CppPropertyDefinition>(pMetadataHdr.propertiesOffset, pMetadataHdr.propertiesCount / MySizeOf(typeof(Il2CppPropertyDefinition)));
            //GetAttributesInfoFromIndex
            attributesInfos = ReadClassArray<Il2CppCustomAttributeTypeRange>(pMetadataHdr.attributesInfoOffset, pMetadataHdr.attributesInfoCount / MySizeOf(typeof(Il2CppCustomAttributeTypeRange)));
            //GetAttributeTypesFromIndex
            attributeTypes = ReadClassArray<int>(pMetadataHdr.attributeTypesOffset, pMetadataHdr.attributeTypesCount / 4);
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

        private int MySizeOf(Type type)
        {
            int size = 0;
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
