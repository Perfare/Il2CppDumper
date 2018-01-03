using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public ulong[] methodPointers;
        public ulong[] genericMethodPointers;
        public ulong[] invokerPointers;
        public ulong[] customAttributeGenerators;
        protected long[] fieldOffsets;
        public Il2CppType[] types;
        private Dictionary<ulong, Il2CppType> typesdic = new Dictionary<ulong, Il2CppType>();
        public ulong[] metadataUsages;
        protected bool isNew21;
        protected long maxmetadataUsages;

        public Func<bool> Search;
        public abstract bool AdvancedSearch(int methodCount);
        public abstract bool PlusSearch(int methodCount, int typeDefinitionsCount);

        public abstract dynamic MapVATR(dynamic uiAddr);

        protected Il2Cpp(Stream stream) : base(stream) { }

        protected virtual void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            methodPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.methodPointers, (long)pCodeRegistration.methodPointersCount), x => (ulong)x);
            genericMethodPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.genericMethodPointers, (long)pCodeRegistration.genericMethodPointersCount), x => (ulong)x);
            invokerPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.invokerPointers, (long)pCodeRegistration.invokerPointersCount), x => (ulong)x);
            customAttributeGenerators = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount), x => (ulong)x);
            fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
            //TODO 在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
            isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
            var ptypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                types[i] = MapVATR<Il2CppType>(ptypes[i]);
                types[i].Init();
                typesdic.Add(ptypes[i], types[i]);
            }
            if (version > 16)
                metadataUsages = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.metadataUsages, maxmetadataUsages), x => (ulong)x);
        }

        protected void Init64(ulong codeRegistration, ulong metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, (long)pCodeRegistration.methodPointersCount);
            genericMethodPointers = MapVATR<ulong>(pCodeRegistration.genericMethodPointers, (long)pCodeRegistration.genericMethodPointersCount);
            invokerPointers = MapVATR<ulong>(pCodeRegistration.invokerPointers, (long)pCodeRegistration.invokerPointersCount);
            customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            fieldOffsets = MapVATR<long>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            //TODO 在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
            isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
            if (!isNew21)
                fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
            var ptypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                types[i] = MapVATR<Il2CppType>(ptypes[i]);
                types[i].Init();
                typesdic.Add(ptypes[i], types[i]);
            }
            if (version > 16)
                metadataUsages = MapVATR<ulong>(pMetadataRegistration.metadataUsages, maxmetadataUsages);
        }

        public virtual long GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex)
        {
            if (isNew21)
            {
                var ptr = fieldOffsets[typeIndex];
                if (ptr >= 0)
                {
                    Position = MapVATR((uint)ptr) + 4 * fieldIndexInType;
                    return ReadInt32();
                }
                return 0;
            }
            return fieldOffsets[fieldIndex];
        }

        public T[] MapVATR<T>(dynamic uiAddr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(uiAddr), count);
        }

        public T MapVATR<T>(dynamic uiAddr) where T : new()
        {
            return ReadClass<T>(MapVATR(uiAddr));
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            return typesdic[pointer];
        }

        public virtual ulong[] GetPointers(ulong pointer, long count)
        {
            var pointers = Array.ConvertAll(MapVATR<uint>(pointer, count), x => (ulong)x);
            return pointers;
        }
    }
}
