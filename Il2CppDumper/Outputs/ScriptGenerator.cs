using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class ScriptGenerator
    {
        private Il2CppExecutor executor;
        private Metadata metadata;
        private Il2Cpp il2Cpp;
        private Dictionary<Il2CppTypeDefinition, int> typeDefImageIndices = new Dictionary<Il2CppTypeDefinition, int>();

        public ScriptGenerator(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
        }

        public void WriteScript(Config config)
        {
            var writer = new StreamWriter(new FileStream("ida.py", FileMode.Create), new UTF8Encoding(false));
            writer.WriteLine("# -*- coding: utf-8 -*-");
            writer.WriteLine("import idaapi");
            writer.WriteLine();
            writer.WriteLine("def SetString(addr, comm):");
            writer.WriteLine("\tglobal index");
            writer.WriteLine("\tname = \"StringLiteral_\" + str(index)");
            writer.WriteLine("\tret = idc.set_name(addr, name, SN_NOWARN)");
            writer.WriteLine("\tidc.set_cmt(addr, comm, 1)");
            writer.WriteLine("\tindex += 1");
            writer.WriteLine();
            writer.WriteLine("def SetName(addr, name):");
            writer.WriteLine("\tret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)");
            writer.WriteLine("\tif ret == 0:");
            writer.WriteLine("\t\tnew_name = name + '_' + str(addr)");
            writer.WriteLine("\t\tret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)");
            writer.WriteLine();
            writer.WriteLine("def MakeFunction(start, end):");
            writer.WriteLine("\tnext_func = idc.get_next_func(start)");
            writer.WriteLine("\tif next_func < end:");
            writer.WriteLine("\t\tend = next_func");
            writer.WriteLine("\tif idc.get_func_attr(start, FUNCATTR_START) == start:");
            writer.WriteLine("\t\tida_funcs.del_func(start)");
            writer.WriteLine("\tida_funcs.add_func(start, end)");
            writer.WriteLine();
            writer.WriteLine("index = 1");
            writer.WriteLine("print('Making method name...')");
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    var typeDef = metadata.typeDefs[typeIndex];
                    var typeName = executor.GetTypeDefName(typeDef, false, true);
                    typeDefImageIndices.Add(typeDef, imageIndex);
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        var methodDef = metadata.methodDefs[i];
                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                        var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                        if (methodPointer > 0)
                        {
                            var fixedMethodPointer = il2Cpp.FixPointer(methodPointer);
                            if (il2Cpp is PE)
                            {
                                writer.WriteLine($"SetName(0x{methodPointer:X}, '{typeName + "$$" + methodName}')");
                            }
                            else
                            {
                                writer.WriteLine($"SetName(0x{fixedMethodPointer:X}, '{typeName + "$$" + methodName}')");
                            }
                        }
                    }
                }
            }
            writer.WriteLine("print('Make method name done')");
            if (il2Cpp.version > 16)
            {
                writer.WriteLine("print('Setting MetadataUsage...')");
                foreach (var i in metadata.metadataUsageDic[1]) //kIl2CppMetadataUsageTypeInfo
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, true);
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in metadata.metadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, true);
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in metadata.metadataUsageDic[3]) //kIl2CppMetadataUsageMethodDef
                {
                    var methodDef = metadata.methodDefs[i.Value];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = executor.GetTypeDefName(typeDef, true, true);
                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Method$" + methodName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Method$" + methodName}', 1)");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, (int)i.Value, imageIndex, methodDef.token);
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, '0x{methodPointer:X}', 0)");
                }
                foreach (var i in metadata.metadataUsageDic[4]) //kIl2CppMetadataUsageFieldInfo
                {
                    var fieldRef = metadata.fieldRefs[i.Value];
                    var type = il2Cpp.types[fieldRef.typeIndex];
                    var typeDef = metadata.typeDefs[type.data.klassIndex];
                    var fieldDef = metadata.fieldDefs[typeDef.fieldStart + fieldRef.fieldIndex];
                    var fieldName = executor.GetTypeName(type, true, true) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Field$" + fieldName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, r'{fieldName}', 1)");
                }
                var stringLiterals = metadata.metadataUsageDic[5].Select(x => new //kIl2CppMetadataUsageStringLiteral
                {
                    value = metadata.GetStringLiteralFromIndex(x.Value),
                    address = $"0x{il2Cpp.metadataUsages[x.Key]:X}"
                }).ToArray();
                File.WriteAllText("stringliteral.json", JsonConvert.SerializeObject(stringLiterals, Formatting.Indented), new UTF8Encoding(false)); //TODO
                foreach (var stringLiteral in stringLiterals)
                {
                    writer.WriteLine($"SetString({stringLiteral.address}, r'{stringLiteral.value.ToEscapedString()}')");
                }
                foreach (var i in metadata.metadataUsageDic[6]) //kIl2CppMetadataUsageMethodRef
                {
                    var methodSpec = il2Cpp.methodSpecs[i.Value];
                    var methodDef = metadata.methodDefs[methodSpec.methodDefinitionIndex];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = executor.GetTypeDefName(typeDef, true, false);
                    if (methodSpec.classIndexIndex != -1)
                    {
                        var classInst = il2Cpp.genericInsts[methodSpec.classIndexIndex];
                        typeName += executor.GetGenericInstParams(classInst);
                    }
                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex);
                    if (methodSpec.methodIndexIndex != -1)
                    {
                        var methodInst = il2Cpp.genericInsts[methodSpec.methodIndexIndex];
                        methodName += executor.GetGenericInstParams(methodInst);
                    }
                    methodName += "()";
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Method$" + methodName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Method$" + methodName}', 1)");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, methodSpec.methodDefinitionIndex, imageIndex, methodDef.token);
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, '0x{methodPointer:X}', 0)");
                }
                writer.WriteLine("print('Set MetadataUsage done')");
            }
            if (config.MakeFunction)
            {
                List<ulong> orderedPointers;
                if (il2Cpp.version >= 24.2f)
                {
                    orderedPointers = new List<ulong>();
                    foreach (var methodPointers in il2Cpp.codeGenModuleMethodPointers)
                    {
                        orderedPointers.AddRange(methodPointers);
                    }
                }
                else
                {
                    orderedPointers = il2Cpp.methodPointers.ToList();
                }
                orderedPointers.AddRange(il2Cpp.genericMethodPointers);
                orderedPointers.AddRange(il2Cpp.invokerPointers);
                orderedPointers.AddRange(il2Cpp.customAttributeGenerators);
                if (il2Cpp.version >= 22)
                {
                    orderedPointers.AddRange(il2Cpp.reversePInvokeWrappers);
                    orderedPointers.AddRange(il2Cpp.unresolvedVirtualCallPointers);
                }
                //TODO interopData内也包含函数
                orderedPointers = orderedPointers.Distinct().OrderBy(x => x).ToList();
                orderedPointers.Remove(0);
                writer.WriteLine("print('Making function...')");
                for (int i = 0; i < orderedPointers.Count - 1; i++)
                {
                    writer.WriteLine($"MakeFunction(0x{orderedPointers[i]:X}, 0x{orderedPointers[i + 1]:X})");
                }
                writer.WriteLine("print('Make function done, please wait for IDA to complete the analysis')");
            }
            writer.WriteLine("print('Script finished!')");
            writer.Close();
        }

        private string GetNameSpace(Il2CppType il2CppType)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                    var ret = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                    if (ret != string.Empty)
                    {
                        ret += ".";
                    }
                    return ret;
                default:
                    return string.Empty;
            }
        }
    }
}
