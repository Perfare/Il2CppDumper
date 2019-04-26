using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public abstract class Il2Cpp : MyBinaryReader
    {
        private Il2CppMetadataRegistration pMetadataRegistration;
        private Il2CppCodeRegistration pCodeRegistration;
        public ulong[] methodPointers;
        public ulong[] genericMethodPointers;
        public ulong[] invokerPointers;
        public ulong[] customAttributeGenerators;
        private long[] fieldOffsets;
        public Il2CppType[] types;
        private Dictionary<ulong, Il2CppType> typesdic = new Dictionary<ulong, Il2CppType>();
        public ulong[] metadataUsages;
        private Il2CppGenericMethodFunctionsDefinitions[] genericMethodTable;
        public Il2CppMethodSpec[] methodSpecs;
        private Dictionary<int, ulong> genericMethoddDictionary;
        private bool isNew21;
        protected long maxMetadataUsages;
        private Il2CppCodeGenModule[] codeGenModules;
        public ulong[][] codeGenModuleMethodPointers;

        public abstract dynamic MapVATR(dynamic uiAddr);

        public abstract bool Search();
        public abstract bool PlusSearch(int methodCount, int typeDefinitionsCount);
        public abstract bool SymbolSearch();

        protected Il2Cpp(Stream stream, float version, long maxMetadataUsages) : base(stream)
        {
            this.version = version;
            this.maxMetadataUsages = maxMetadataUsages;
        }

        protected bool AutoInit(ulong codeRegistration, ulong metadataRegistration)
        {
            Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
            Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
            if (codeRegistration != 0 && metadataRegistration != 0)
            {
                Init(codeRegistration, metadataRegistration);
                return true;
            }
            return false;
        }

        public virtual void Init(ulong codeRegistration, ulong metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            if (is32Bit)
            {
                genericMethodPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.genericMethodPointers, (long)pCodeRegistration.genericMethodPointersCount), x => (ulong)x);
                invokerPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.invokerPointers, (long)pCodeRegistration.invokerPointersCount), x => (ulong)x);
                customAttributeGenerators = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount), x => (ulong)x);
                fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
                //在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
                isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
                var pTypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
                types = new Il2CppType[pMetadataRegistration.typesCount];
                for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
                {
                    types[i] = MapVATR<Il2CppType>(pTypes[i]);
                    types[i].Init();
                    typesdic.Add(pTypes[i], types[i]);
                }
                if (version > 16)
                {
                    metadataUsages = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.metadataUsages, maxMetadataUsages), x => (ulong)x);
                }
                if (version >= 24.2f)
                {
                    var pCodeGenModules = MapVATR<uint>(pCodeRegistration.codeGenModules, (long)pCodeRegistration.codeGenModulesCount);
                    codeGenModules = new Il2CppCodeGenModule[pCodeGenModules.Length];
                    codeGenModuleMethodPointers = new ulong[pCodeGenModules.Length][];
                    for (int i = 0; i < pCodeGenModules.Length; i++)
                    {
                        var codeGenModule = MapVATR<Il2CppCodeGenModule>(pCodeGenModules[i]);
                        codeGenModules[i] = codeGenModule;
                        try
                        {
                            var ptrs = Array.ConvertAll(MapVATR<uint>(codeGenModule.methodPointers, (long)codeGenModule.methodPointerCount), x => (ulong)x);
                            codeGenModuleMethodPointers[i] = ptrs;
                        }
                        catch
                        {
                            //当整个DLL只有泛型函数时就会出现这种情况
                            Console.WriteLine($"WARNING: Unable to get function pointers for {ReadStringToNull(MapVATR(codeGenModule.moduleName))}");
                            codeGenModuleMethodPointers[i] = new ulong[codeGenModule.methodPointerCount];
                        }
                    }

                }
                else
                {
                    methodPointers = Array.ConvertAll(MapVATR<uint>(pCodeRegistration.methodPointers, (long)pCodeRegistration.methodPointersCount), x => (ulong)x);
                }
            }
            else
            {
                genericMethodPointers = MapVATR<ulong>(pCodeRegistration.genericMethodPointers, (long)pCodeRegistration.genericMethodPointersCount);
                invokerPointers = MapVATR<ulong>(pCodeRegistration.invokerPointers, (long)pCodeRegistration.invokerPointersCount);
                customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
                fieldOffsets = MapVATR<long>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
                //在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
                isNew21 = version > 21 || (version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5);
                if (!isNew21)
                    fieldOffsets = Array.ConvertAll(MapVATR<int>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (long)x);
                var pTypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
                types = new Il2CppType[pMetadataRegistration.typesCount];
                for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
                {
                    types[i] = MapVATR<Il2CppType>(pTypes[i]);
                    types[i].Init();
                    typesdic.Add(pTypes[i], types[i]);
                }
                if (version > 16)
                {
                    metadataUsages = MapVATR<ulong>(pMetadataRegistration.metadataUsages, maxMetadataUsages);
                }
                if (version >= 24.2f)
                {
                    var pCodeGenModules = MapVATR<ulong>(pCodeRegistration.codeGenModules, (long)pCodeRegistration.codeGenModulesCount);
                    codeGenModules = new Il2CppCodeGenModule[pCodeGenModules.Length];
                    codeGenModuleMethodPointers = new ulong[pCodeGenModules.Length][];
                    for (int i = 0; i < pCodeGenModules.Length; i++)
                    {
                        var codeGenModule = MapVATR<Il2CppCodeGenModule>(pCodeGenModules[i]);
                        codeGenModules[i] = codeGenModule;
                        try
                        {
                            var ptrs = MapVATR<ulong>(codeGenModule.methodPointers, (long)codeGenModule.methodPointerCount);
                            codeGenModuleMethodPointers[i] = ptrs;
                        }
                        catch
                        {
                            //当整个DLL只有泛型函数时就会出现这种情况
                            Console.WriteLine($"WARNING: Unable to get function pointers for {ReadStringToNull(MapVATR(codeGenModule.moduleName))}");
                            codeGenModuleMethodPointers[i] = new ulong[codeGenModule.methodPointerCount];
                        }
                    }
                }
                else
                {
                    methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, (long)pCodeRegistration.methodPointersCount);
                }
            }
            //处理泛型
            genericMethodTable = MapVATR<Il2CppGenericMethodFunctionsDefinitions>(pMetadataRegistration.genericMethodTable, pMetadataRegistration.genericMethodTableCount);
            methodSpecs = MapVATR<Il2CppMethodSpec>(pMetadataRegistration.methodSpecs, pMetadataRegistration.methodSpecsCount);
            genericMethoddDictionary = new Dictionary<int, ulong>(genericMethodTable.Length);
            foreach (var table in genericMethodTable)
            {
                var index = methodSpecs[table.genericMethodIndex].methodDefinitionIndex;
                if (!genericMethoddDictionary.ContainsKey(index))
                {
                    genericMethoddDictionary.Add(index, genericMethodPointers[table.indices.methodIndex]);
                }
            }
        }

        public long GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex)
        {
            if (isNew21)
            {
                var ptr = fieldOffsets[typeIndex];
                if (ptr >= 0)
                {
                    dynamic pos;
                    if (is32Bit)
                        pos = MapVATR((uint)ptr) + 4 * fieldIndexInType;
                    else
                        pos = MapVATR((ulong)ptr) + 4ul * (ulong)fieldIndexInType;
                    if ((long)pos <= BaseStream.Length - 4)
                    {
                        Position = pos;
                        return ReadInt32();
                    }
                    return -1;
                }
                return 0;
            }
            return fieldOffsets[fieldIndex];
        }

        public T[] MapVATR<T>(dynamic addr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(addr), count);
        }

        public T MapVATR<T>(dynamic addr) where T : new()
        {
            return ReadClass<T>(MapVATR(addr));
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            return typesdic[pointer];
        }

        public ulong[] GetPointers(ulong pointer, long count)
        {
            if (is32Bit)
                return Array.ConvertAll(MapVATR<uint>(pointer, count), x => (ulong)x);
            return MapVATR<ulong>(pointer, count);
        }

        public ulong GetMethodPointer(int methodIndex, int methodDefinitionIndex, int imageIndex, uint methodToken)
        {
            if (version >= 24.2f)
            {
                if (genericMethoddDictionary.TryGetValue(methodDefinitionIndex, out var methodPointer))
                {
                    return methodPointer;
                }
                else
                {
                    var ptrs = codeGenModuleMethodPointers[imageIndex];
                    var methodPointerIndex = methodToken & 0x00FFFFFFu;
                    return ptrs[methodPointerIndex - 1];
                }
            }
            else
            {
                if (methodIndex >= 0)
                {
                    return methodPointers[methodIndex];
                }
                genericMethoddDictionary.TryGetValue(methodDefinitionIndex, out var methodPointer);
                return methodPointer;
            }
        }
    }
}
