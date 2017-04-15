using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static Il2CppDumper.MyCopy;

namespace Il2CppDumper
{
    abstract class Il2CppGeneric : MyBinaryReader
    {
        protected int version;
        protected string @namespace;
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public ulong[] methodPointers;
        public ulong[] customAttributeGenerators;
        protected long[] fieldOffsets;
        public Il2CppType[] types;
        private Dictionary<ulong, Il2CppType> typesdic = new Dictionary<ulong, Il2CppType>();
        public ulong[] metadataUsages;
        protected bool isNew21;

        public Func<bool> Search;

        protected abstract dynamic MapVATR(dynamic uiAddr);

        protected Il2CppGeneric(Stream stream) : base(stream) { }

        protected void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            //pCodeRegistration
            var t = Type.GetType(@namespace + "Il2CppCodeRegistration");
            var m = MapVATR.MakeGenericMethod(t);
            Copy(out pCodeRegistration, m.Invoke(this, new object[] { codeRegistration }));
            //pMetadataRegistration
            t = Type.GetType(@namespace + "Il2CppMetadataRegistration");
            m = MapVATR.MakeGenericMethod(t);
            Copy(out pMetadataRegistration, m.Invoke(this, new object[] { metadataRegistration }));
            methodPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.methodPointers, (int)pCodeRegistration.methodPointersCount), x => (ulong)x);
            customAttributeGenerators = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount), x => (ulong)x);
            fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
            //TODO 在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
            isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
            var ptypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            t = Type.GetType(@namespace + "Il2CppType");
            m = MapVATR.MakeGenericMethod(t);
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                Copy(out types[i], m.Invoke(this, new object[] { ptypes[i] }));
                types[i].Init();
                typesdic.Add(ptypes[i], types[i]);
            }
            if (version > 16)
                metadataUsages = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.metadataUsages, (long)pMetadataRegistration.metadataUsagesCount), x => (ulong)x);
        }

        protected void Init64(ulong codeRegistration, ulong metadataRegistration)
        {
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            //pCodeRegistration
            var t = Type.GetType(@namespace + "Il2CppCodeRegistration");
            var m = MapVATR.MakeGenericMethod(t);
            Copy(out pCodeRegistration, m.Invoke(this, new object[] { codeRegistration }));
            //pMetadataRegistration
            t = Type.GetType(@namespace + "Il2CppMetadataRegistration");
            m = MapVATR.MakeGenericMethod(t);
            Copy(out pMetadataRegistration, m.Invoke(this, new object[] { metadataRegistration }));
            methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, (int)pCodeRegistration.methodPointersCount);
            customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            fieldOffsets = MapVATR<long>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            //TODO 在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
            isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
            if (!isNew21)
                fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
            var ptypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            t = Type.GetType(@namespace + "Il2CppType");
            m = MapVATR.MakeGenericMethod(t);
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                Copy(out types[i], m.Invoke(this, new object[] { ptypes[i] }));
                types[i].Init();
                typesdic.Add(ptypes[i], types[i]);
            }
            if (version > 16)
                metadataUsages = MapVATR<ulong>(pMetadataRegistration.metadataUsages, (long)pMetadataRegistration.metadataUsagesCount);
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

        protected T[] MapVATR<T>(dynamic uiAddr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(uiAddr), count);
        }

        public T MapVATRGeneric<T>(dynamic uiAddr) where T : new()
        {
            return ReadClass<T>(MapVATR(uiAddr));
        }

        public Il2CppGenericClass GetIl2CppGenericClass(ulong pointer)
        {
            Il2CppGenericClass re;
            var t = Type.GetType(@namespace + "Il2CppGenericClass");
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            var m = MapVATR.MakeGenericMethod(t);
            dynamic o = m.Invoke(this, new object[] { pointer });
            Copy(out re, o);
            re.context = new Il2CppGenericContext { class_inst = o.context.class_inst };
            return re;
        }

        public Il2CppGenericInst GetIl2CppGenericInst(ulong pointer)
        {
            Il2CppGenericInst re;
            var t = Type.GetType(@namespace + "Il2CppGenericInst");
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            var m = MapVATR.MakeGenericMethod(t);
            Copy(out re, m.Invoke(this, new object[] { pointer }));
            return re;
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            return typesdic[pointer];
            /*Il2CppType re;
            var t = Type.GetType(@namespace + "Il2CppType");
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            var m = MapVATR.MakeGenericMethod(t);
            Copy(out re, m.Invoke(this, new object[] { pointer }));
            return re;*/
        }

        public virtual ulong[] GetPointers(ulong pointer, long count)
        {
            var pointers = Array.ConvertAll(MapVATR<uint>(pointer, count), x => (ulong)x);
            return pointers;
        }

        public Il2CppArrayType GetIl2CppArrayType(ulong pointer)
        {
            Il2CppArrayType re;
            var t = Type.GetType(@namespace + "Il2CppArrayType");
            var MapVATR = GetType().GetMethod("MapVATRGeneric");
            var m = MapVATR.MakeGenericMethod(t);
            Copy(out re, m.Invoke(this, new object[] { pointer }));
            return re;
        }
    }
}
