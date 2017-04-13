using System.IO;

namespace Il2CppDumper.v16
{
    abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public uint[] methodPointers;
        private int[] fieldOffsets;
        public Il2CppType[] types;

        public abstract bool Auto();
        public abstract uint MapVATR(uint uiAddr);

        protected Il2Cpp(Stream stream) : base(stream) { }

        protected void Init(uint codeRegistration, uint metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            methodPointers = MapVATR<uint>(pCodeRegistration.methodPointers, (int)pCodeRegistration.methodPointersCount);
            fieldOffsets = MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            var ptypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                types[i] = MapVATR<Il2CppType>(ptypes[i]);
                types[i].Init();
            }
        }

        public int GetFieldOffsetFromIndex(int fieldIndex)
        {
            return fieldOffsets[fieldIndex];
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
