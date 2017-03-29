using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        public Il2CppCodeRegistration pCodeRegistration;

        public abstract bool Auto();
        protected abstract uint MapVATR(uint uiAddr);


        protected Il2Cpp(Stream stream) : base(stream) { }

        protected void Init(uint codeRegistration, uint metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            pCodeRegistration.methodPointers = MapVATR<uint>(pCodeRegistration.pmethodPointers, (int)pCodeRegistration.methodPointersCount);
            pCodeRegistration.customAttributeGenerators = MapVATR<uint>(pCodeRegistration.pcustomAttributeGenerators, pCodeRegistration.customAttributeCount);
            pMetadataRegistration.fieldOffsets = MapVATR<int>(pMetadataRegistration.pfieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            var types = MapVATR<uint>(pMetadataRegistration.ptypes, pMetadataRegistration.typesCount);
            pMetadataRegistration.types = new Il2CppType[pMetadataRegistration.typesCount];
            for (int i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                pMetadataRegistration.types[i] = MapVATR<Il2CppType>(types[i]);
                pMetadataRegistration.types[i].Init();
            }
        }

        public Il2CppType GetTypeFromTypeIndex(int idx)
        {
            return pMetadataRegistration.types[idx];
        }

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType)
        {
            var ptr = pMetadataRegistration.fieldOffsets[typeIndex];
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
