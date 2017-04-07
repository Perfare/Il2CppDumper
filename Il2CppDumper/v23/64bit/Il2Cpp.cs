using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper.v23._64bit
{
    abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public ulong[] methodPointers;
        public ulong[] customAttributeGenerators;
        private long[] fieldOffsets;
        public Il2CppType[] types;

        public abstract bool Auto();
        public abstract ulong MapVATR(ulong uiAddr);

        protected Il2Cpp(Stream stream) : base(stream) { }

        protected void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, (long)pCodeRegistration.methodPointersCount);
            customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            fieldOffsets = MapVATR<long>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            var ptypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
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
                Position = MapVATR((ulong)ptr) + 8u * (ulong)fieldIndexInType;
                return ReadInt32();
            }
            return 0;
        }

        public T MapVATR<T>(ulong uiAddr) where T : new()
        {
            return ReadClass<T>(MapVATR(uiAddr));
        }

        public T[] MapVATR<T>(ulong uiAddr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(uiAddr), count);
        }
    }
}
