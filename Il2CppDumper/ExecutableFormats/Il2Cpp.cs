using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Il2CppDumper
{
    public abstract class Il2Cpp : BinaryStream
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
        private Dictionary<ulong, Il2CppType> typeDic = new Dictionary<ulong, Il2CppType>();
        public ulong[] metadataUsages;
        private Il2CppGenericMethodFunctionsDefinitions[] genericMethodTable;
        public Il2CppGenericInst[] genericInsts;
        public Il2CppMethodSpec[] methodSpecs;
        private Dictionary<int, ulong> genericMethoddDictionary;
        private bool fieldOffsetsArePointers;
        protected long maxMetadataUsages;
        private Il2CppCodeGenModule[] codeGenModules;
        public ulong[][] codeGenModuleMethodPointers;

        public abstract ulong MapVATR(ulong uiAddr);
        public abstract bool Search();
        public abstract bool PlusSearch(int methodCount, int typeDefinitionsCount);
        public abstract bool SymbolSearch();

        protected Il2Cpp(Stream stream, float version, long maxMetadataUsages) : base(stream)
        {
            Version = version;
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
            genericMethodPointers = MapVATR<ulong>(pCodeRegistration.genericMethodPointers, pCodeRegistration.genericMethodPointersCount);
            invokerPointers = MapVATR<ulong>(pCodeRegistration.invokerPointers, pCodeRegistration.invokerPointersCount);
            customAttributeGenerators = MapVATR<ulong>(pCodeRegistration.customAttributeGenerators, pCodeRegistration.customAttributeCount);
            if (Version > 16)
            {
                metadataUsages = MapVATR<ulong>(pMetadataRegistration.metadataUsages, maxMetadataUsages);
            }
            if (Version >= 22)
            {
                reversePInvokeWrappers = MapVATR<ulong>(pCodeRegistration.reversePInvokeWrappers, pCodeRegistration.reversePInvokeWrapperCount);
                unresolvedVirtualCallPointers = MapVATR<ulong>(pCodeRegistration.unresolvedVirtualCallPointers, pCodeRegistration.unresolvedVirtualCallCount);
            }
            genericInsts = Array.ConvertAll(MapVATR<ulong>(pMetadataRegistration.genericInsts, pMetadataRegistration.genericInstsCount), x => MapVATR<Il2CppGenericInst>(x));
            fieldOffsetsArePointers = Version > 21;
            if (Version == 21)
            {
                var fieldTest = MapVATR<uint>(pMetadataRegistration.fieldOffsets, 6);
                fieldOffsetsArePointers = fieldTest[0] == 0 && fieldTest[1] == 0 && fieldTest[2] == 0 && fieldTest[3] == 0 && fieldTest[4] == 0 && fieldTest[5] > 0;
            }
            if (fieldOffsetsArePointers)
            {
                fieldOffsets = MapVATR<ulong>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            }
            else
            {
                fieldOffsets = Array.ConvertAll(MapVATR<uint>(pMetadataRegistration.fieldOffsets, pMetadataRegistration.fieldOffsetsCount), x => (ulong)x);
            }
            var pTypes = MapVATR<ulong>(pMetadataRegistration.types, pMetadataRegistration.typesCount);
            types = new Il2CppType[pMetadataRegistration.typesCount];
            for (var i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                types[i] = MapVATR<Il2CppType>(pTypes[i]);
                types[i].Init();
                typeDic.Add(pTypes[i], types[i]);
            }
            if (Version >= 24.2f)
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
                        var name = ReadStringToNull(MapVATR(codeGenModule.moduleName));
                        codeGenModuleMethodPointers[i] = MapVATR<ulong>(codeGenModule.methodPointers, codeGenModule.methodPointerCount);
                    }
                    catch
                    {
                        codeGenModuleMethodPointers[i] = new ulong[codeGenModule.methodPointerCount];
                    }
                }
            }
            else
            {
                methodPointers = MapVATR<ulong>(pCodeRegistration.methodPointers, pCodeRegistration.methodPointersCount);
            }
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

        public T MapVATR<T>(ulong addr) where T : new()
        {
            if (!ReadClassCache<T>.TryGetValue(addr, out var value))
            {
                value = ReadClass<T>(MapVATR(addr));
                ReadClassCache<T>.Add(addr, value);
            }
            return value;
        }

        public T[] MapVATR<T>(ulong addr, long count) where T : new()
        {
            return ReadClassArray<T>(MapVATR(addr), count);
        }

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType, int fieldIndex, bool isValueType, bool isStatic)
        {
            //TODO 计算泛型类的偏移
            try
            {
                var offset = -1;
                if (fieldOffsetsArePointers)
                {
                    var ptr = fieldOffsets[typeIndex];
                    if (ptr > 0)
                    {
                        Position = MapVATR(ptr) + 4ul * (ulong)fieldIndexInType;
                        offset = ReadInt32();
                    }
                }
                else
                {
                    offset = (int)fieldOffsets[fieldIndex];
                }
                if (offset > 0)
                {
                    if (isValueType && !isStatic)
                    {
                        if (Is32Bit)
                        {
                            offset -= 8;
                        }
                        else
                        {
                            offset -= 16;
                        }
                    }
                }
                return offset;
            }
            catch
            {
                return -1;
            }
        }

        public Il2CppType GetIl2CppType(ulong pointer)
        {
            return typeDic[pointer];
        }

        public ulong GetMethodPointer(int methodIndex, int methodDefinitionIndex, int imageIndex, uint methodToken)
        {
            if (Version >= 24.2f)
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

        public virtual ulong GetRVA(ulong pointer)
        {
            return pointer;
        }
    }
}
