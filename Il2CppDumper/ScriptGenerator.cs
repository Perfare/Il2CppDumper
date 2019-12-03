using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    public class ScriptGenerator
    {
        private Metadata metadata;
        private Il2Cpp il2Cpp;
        private Dictionary<Il2CppTypeDefinition, int> typeDefImageIndices = new Dictionary<Il2CppTypeDefinition, int>();

        public ScriptGenerator(Metadata metadata, Il2Cpp il2Cpp)
        {
            this.metadata = metadata;
            this.il2Cpp = il2Cpp;
        }

        public void WriteScript(StreamWriter writer, Config config)
        {
            writer.WriteLine("#encoding: utf-8");
            writer.WriteLine("import idaapi");
            writer.WriteLine();
            writer.WriteLine("def SetString(addr, comm):");
            writer.WriteLine("\tglobal index");
            writer.WriteLine("\tname = \"StringLiteral_\" + str(index);");
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
                    var typeName = GetTypeName(typeDef);
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
                    var typeName = GetTypeName(type, true);
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in metadata.metadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = GetTypeName(type, true);
                    writer.WriteLine($"SetName(0x{il2Cpp.metadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{il2Cpp.metadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in metadata.metadataUsageDic[3]) //kIl2CppMetadataUsageMethodDef
                {
                    var methodDef = metadata.methodDefs[i.Value];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = GetTypeName(typeDef);
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
                    var fieldName = GetTypeName(type, true) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
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
                    var typeName = GetTypeName(typeDef);
                    if (methodSpec.classIndexIndex != -1)
                    {
                        var classInst = il2Cpp.genericInsts[methodSpec.classIndexIndex];
                        typeName += GetGenericTypeParams(classInst);
                    }
                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
                    if (methodSpec.methodIndexIndex != -1)
                    {
                        var methodInst = il2Cpp.genericInsts[methodSpec.methodIndexIndex];
                        methodName += GetGenericTypeParams(methodInst);
                    }
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

        public string GetTypeName(Il2CppType type, bool fullName = false)
        {
            string ret;
            switch (type.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = metadata.typeDefs[type.data.klassIndex];
                        ret = string.Empty;
                        if (fullName)
                        {
                            ret = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                            if (ret != string.Empty)
                            {
                                ret += ".";
                            }
                        }
                        ret += GetTypeName(typeDef);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(type.data.generic_class);
                        var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                        ret = metadata.GetStringFromIndex(typeDef.nameIndex);
                        var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(genericClass.context.class_inst);
                        ret = ret.Replace($"`{genericInst.type_argc}", "");
                        ret += GetGenericTypeParams(genericInst);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        var param = metadata.genericParameters[type.data.genericParameterIndex];
                        ret = metadata.GetStringFromIndex(param.nameIndex);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(type.data.array);
                        var oriType = il2Cpp.GetIl2CppType(arrayType.etype);
                        ret = $"{GetTypeName(oriType)}[{new string(',', arrayType.rank - 1)}]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var oriType = il2Cpp.GetIl2CppType(type.data.type);
                        ret = $"{GetTypeName(oriType)}[]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.GetIl2CppType(type.data.type);
                        ret = $"{GetTypeName(oriType)}*";
                        break;
                    }
                default:
                    ret = TypeString[(int)type.type];
                    break;
            }

            return ret;
        }

        public string GetTypeName(Il2CppTypeDefinition typeDef)
        {
            var ret = string.Empty;
            if (typeDef.declaringTypeIndex != -1)
            {
                ret += GetTypeName(il2Cpp.types[typeDef.declaringTypeIndex]) + ".";
            }
            ret += metadata.GetStringFromIndex(typeDef.nameIndex);
            var names = new List<string>();
            if (typeDef.genericContainerIndex >= 0)
            {
                var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                for (int i = 0; i < genericContainer.type_argc; i++)
                {
                    var genericParameterIndex = genericContainer.genericParameterStart + i;
                    var param = metadata.genericParameters[genericParameterIndex];
                    names.Add(metadata.GetStringFromIndex(param.nameIndex));
                }
                ret = ret.Replace($"`{genericContainer.type_argc}", "");
                ret += $"<{string.Join(", ", names)}>";
            }
            return ret;
        }

        public string GetGenericTypeParams(Il2CppGenericInst genericInst)
        {
            var typeNames = new List<string>();
            var pointers = il2Cpp.ReadPointers(genericInst.type_argv, genericInst.type_argc);
            for (uint i = 0; i < genericInst.type_argc; ++i)
            {
                var oriType = il2Cpp.GetIl2CppType(pointers[i]);
                typeNames.Add(GetTypeName(oriType));
            }
            return $"<{string.Join(", ", typeNames)}>";
        }
    }
}
