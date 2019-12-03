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
        public ulong[] reversePInvokeWrappers;
        public ulong[] unresolvedVirtualCallPointers;
        private ulong[] fieldOffsets;
        public Il2CppType[] types;
        private Dictionary<ulong, Il2CppType> typesdic = new Dictionary<ulong, Il2CppType>();
        public ulong[] metadataUsages;
        private Il2CppGenericMethodFunctionsDefinitions[] genericMethodTable;
        public Il2CppGenericInst[] genericInsts;
        public Il2CppMethodSpec[] methodSpecs;
        private Dictionary<int, ulong> genericMethoddDictionary;
        private bool isNew21;
        protected long maxMetadataUsages;
        private Il2CppCodeGenModule[] codeGenModules;
        public ulong[][] codeGenModuleMethodPointers;

        public abstract ulong MapVATR(ulong uiAddr);
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
            genericMethodPointers = ReadPointers(pCodeRegistration.genericMethodPointers, pCodeRegistration.genericMethodPointersCount);
            invokerPointers = ReadPointers(pCodeRegistration.invokerPointers, pCodeRegistration.invokerPointersCount);
            customAttributeGenerators = ReadPointers(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            if (version > 16)
            {
                metadataUsages = ReadPointers(pMetadataRegistration.metadataUsages, maxMetadataUsages);
            }
            if (version >= 22)
            {
                reversePInvokeWrappers = ReadPointers(pCodeRegistration.reversePInvokeWrappers, pCodeRegistration.reversePInvokeWrapperCount);
                unresolvedVirtualCallPointers = ReadPointers(pCodeRegistration.unresolvedVirtualCallPointers, pCodeRegistration.unresolvedVirtualCallCount);
            }
            if (is32Bit)
            {
                genericInsts = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.genericInsts, pMetadataRegistration.genericInstsCount), x => MapVATR<Il2CppGenericInst>(x));
                fieldOffsets = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (ulong)x);
                //在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
                isNew21 = version > 21 || version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5;
                var pTypes = MapVATR<uint>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
                types = new Il2CppType[pMetadataRegistration.typesCount];
                for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
                {
                    types[i] = MapVATR<Il2CppType>(pTypes[i]);
                    types[i].Init();
                    typesdic.Add(pTypes[i], types[i]);
                }
                if (version >= 24.2f)
                {
                    var pCodeGenModules = MapVATR<uint>(pCodeRegistration.codeGenModules, pCodeRegistration.codeGenModulesCount);
                    codeGenModules = new Il2CppCodeGenModule[pCodeGenModules.Length];
                    codeGenModuleMethodPointers = new ulong[pCodeGenModules.Length][];
                    for (int i = 0; i < pCodeGenModules.Length; i++)
                    {
                        var codeGenModule = MapVATR<Il2CppCodeGenModule>(pCodeGenModules[i]);
                        codeGenModules[i] = codeGenModule;
                        try
                        {
                            codeGenModuleMethodPointers[i] = ReadPointers(codeGenModule.methodPointers, codeGenModule.methodPointerCount);
                        }
                        catch
                        {
                            //当整个DLL只有泛型函数时就会出现这种情况
                            //Console.WriteLine($"WARNING: Unable to get function pointers for {ReadStringToNull(MapVATR(codeGenModule.moduleName))}");
                            codeGenModuleMethodPointers[i] = new ulong[codeGenModule.methodPointerCount];
                        }
                    }
                }
                else
                {
                    methodPointers = ReadPointers(pCodeRegistration.methodPointers, pCodeRegistration.methodPointersCount);
                }
            }
            else
            {
                genericInsts = Array.ConvertAll(MapVATR<ulong>(pMetadataRegistration.genericInsts, pMetadataRegistration.genericInstsCount), x => MapVATR<Il2CppGenericInst>(x));
                fieldOffsets = MapVATR<ulong>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
                //在21版本中存在两种FieldOffset，通过判断前5个数值是否为0确认是指针还是int
                isNew21 = version > 21 || version == 21 && fieldOffsets.ToList().FindIndex(x => x > 0) == 5;
                if (!isNew21)
                    fieldOffsets = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (ulong)x);
                var pTypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
                types = new Il2CppType[pMetadataRegistration.typesCount];
                for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
                {
                    types[i] = MapVATR<Il2CppType>(pTypes[i]);
                    types[i].Init();
                    typesdic.Add(pTypes[i], types[i]);
                }
                if (version >= 24.2f)
                {
                    var pCodeGenModules = MapVATR<ulong>(pCodeRegistration.codeGenModules, pCodeRegistration.codeGenModulesCount);
                    codeGenModules = new Il2CppCodeGenModule[pCodeGenModules.Length];
                    codeGenModuleMethodPointers = new ulong[pCodeGenModules.Length][];
                    for (int i = 0; i < pCodeGenModules.Length; i++)
                    {
                        var codeGenModule = MapVATR<Il2CppCodeGenModule>(pCodeGenModules[i]);
                        codeGenModules[i] = codeGenModule;
                        try
                        {
                            codeGenModuleMethodPointers[i] = MapVATR<ulong>(codeGenModule.methodPointers, codeGenModule.methodPointerCount);
                        }
                        catch
                        {
                            //当整个DLL只有泛型函数时就会出现这种情况
                            //Console.WriteLine($"WARNING: Unable to get function pointers for {ReadStringToNull(MapVATR(codeGenModule.moduleName))}");
                            codeGenModuleMethodPointers[i] = new ulong[codeGenModule.methodPointerCount];
                        }
                    }
                }
                else
                {
                    methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, pCodeRegistration.methodPointersCount);
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

        public ulong[] ReadPointers(ulong addr, long count)
        {
            if (addr == 0 || count == 0)
            {
                return new ulong[0];
            }
            if (is32Bit)
            {
                return Array.ConvertAll(MapVATR<uint>(addr, count), x => (ulong)x);
            }
            return MapVATR<ulong>(addr, count);
        }

        public T[] MapVATR<T>(ulong addr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(addr), count);
        }

        public T MapVATR<T>(ulong addr) where T : new()
        {
            return ReadClass<T>(MapVATR(addr));
        }

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex)
        {
            try
            {
                if (isNew21)
                {
                    var ptr = fieldOffsets[typeIndex];
                    if (ptr > 0)
                    {
                        Position = MapVATR(ptr) + 4ul * (ulong)fieldIndexInType;
                        return ReadInt32();
                    }
                    else
                    {
                        return -1;
                    }
                }
                else
                {
                    return (int)fieldOffsets[fieldIndex];
                }
            }
            catch
            {
                return -1;
            }
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            return typesdic[pointer];
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

        public virtual ulong FixPointer(ulong pointer)
        {
            return pointer;
        }
    }
}
