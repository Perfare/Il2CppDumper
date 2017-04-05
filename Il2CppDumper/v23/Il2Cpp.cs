using System.IO;

namespace Il2CppDumper.v23
{
    abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public uint[] methodPointers;
        public uint[] customAttributeGenerators;
        private int[] fieldOffsets;
        public Il2CppType[] types;

        public abstract bool Auto();
        protected abstract uint MapVATR(uint uiAddr);

        protected Il2Cpp(Stream stream) : base(stream) { }

        protected void Init(uint codeRegistration, uint metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            methodPointers = MapVATR<uint>(pCodeRegistration.methodPointers, (int)pCodeRegistration.methodPointersCount);
            customAttributeGenerators = MapVATR<uint>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            fieldOffsets = MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            var ptypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                types[i] = MapVATR<Il2CppType>(ptypes[i]);
                types[i].Init();
            }
        }

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType)
        {
            var ptr = fieldOffsets[typeIndex];
            if (ptr >= 0)
            {
                Position = MapVATR((uint)ptr) + 4 * fieldIndexInType;
                return ReadInt32();
            }
            return 0;
        }

        public T MapVATR<T>(uint uiAddr) where T : new()
        {
            return ReadClass<T>(MapVATR(uiAddr));
        }

        public T[] MapVATR<T>(uint uiAddr, int count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(uiAddr), count);
        }
    }
}
