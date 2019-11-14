using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class ScriptGenerator
    {
        private Il2CppDecompiler decompiler;
        private Dictionary<Il2CppTypeDefinition, int> typeDefImageIndices = new Dictionary<Il2CppTypeDefinition, int>();

        public ScriptGenerator(Il2CppDecompiler decompiler)
        {
            this.decompiler = decompiler;
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
            for (var imageIndex = 0; imageIndex < decompiler.Images.Length; imageIndex++)
            {
                var imageDef = decompiler.Images[imageIndex];
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    var typeDef = decompiler.Types[typeIndex];
                    var typeName = decompiler.GetTypeName(typeDef);
                    typeDefImageIndices.Add(typeDef, imageIndex);
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        var methodDef = decompiler.Methods[i];
                        var methodName = decompiler.GetStringFromIndex(methodDef.nameIndex);
                        var methodPointer = decompiler.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                        if (methodPointer > 0)
                        {
                            var fixedMethodPointer = decompiler.FixPointer(methodPointer);
                            if (decompiler.IsPE)
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
            if (decompiler.Version > 16)
            {
                writer.WriteLine("print('Setting MetadataUsage...')");
                foreach (var i in decompiler.MetadataUsageDic[1]) //kIl2CppMetadataUsageTypeInfo
                {
                    var type = decompiler.il2CppTypes[i.Value];
                    var typeName = decompiler.GetTypeName(type, true);
                    writer.WriteLine($"SetName(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in decompiler.MetadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = decompiler.il2CppTypes[i.Value];
                    var typeName = decompiler.GetTypeName(type, true);
                    writer.WriteLine($"SetName(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Class$" + typeName}')");
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, r'{typeName}', 1)");
                }
                foreach (var i in decompiler.MetadataUsageDic[3]) //kIl2CppMetadataUsageMethodDef
                {
                    var methodDef = decompiler.Methods[i.Value];
                    var typeDef = decompiler.Types[methodDef.declaringType];
                    var typeName = decompiler.GetTypeName(typeDef);
                    var methodName = typeName + "." + decompiler.GetStringFromIndex(methodDef.nameIndex) + "()";
                    writer.WriteLine($"SetName(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Method$" + methodName}')");
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Method$" + methodName}', 1)");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = decompiler.GetMethodPointer(methodDef.methodIndex, (int)i.Value, imageIndex, methodDef.token);
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, '0x{methodPointer:X}', 0)");
                }
                foreach (var i in decompiler.MetadataUsageDic[4]) //kIl2CppMetadataUsageFieldInfo
                {
                    var fieldRef = decompiler.FieldRefs[i.Value];
                    var type = decompiler.il2CppTypes[fieldRef.typeIndex];
                    var typeDef = decompiler.Types[type.data.klassIndex];
                    var fieldDef = decompiler.Fields[typeDef.fieldStart + fieldRef.fieldIndex];
                    var fieldName = decompiler.GetTypeName(type, true) + "." + decompiler.GetStringFromIndex(fieldDef.nameIndex);
                    writer.WriteLine($"SetName(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Field$" + fieldName}')");
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, r'{fieldName}', 1)");
                }
                var stringLiterals = decompiler.MetadataUsageDic[5].Select(x => new //kIl2CppMetadataUsageStringLiteral
                {
                    value = decompiler.GetStringLiteralFromIndex(x.Value),
                    address = $"0x{decompiler.MetadataUsages[x.Key]:X}"
                }).ToArray();
                File.WriteAllText("stringliteral.json", JsonConvert.SerializeObject(stringLiterals, Formatting.Indented), new UTF8Encoding(false)); //TODO
                foreach (var stringLiteral in stringLiterals)
                {
                    writer.WriteLine($"SetString({stringLiteral.address}, r'{decompiler.ToEscapedString(stringLiteral.value)}')");
                }
                foreach (var i in decompiler.MetadataUsageDic[6]) //kIl2CppMetadataUsageMethodRef
                {
                    var methodSpec = decompiler.MethodSpecs[i.Value];
                    var methodDef = decompiler.Methods[methodSpec.methodDefinitionIndex];
                    var typeDef = decompiler.Types[methodDef.declaringType];
                    var typeName = decompiler.GetTypeName(typeDef);
                    if (methodSpec.classIndexIndex != -1)
                    {
                        var classInst = decompiler.GenericInsts[methodSpec.classIndexIndex];
                        typeName += decompiler.GetGenericTypeParams(classInst);
                    }
                    var methodName = typeName + "." + decompiler.GetStringFromIndex(methodDef.nameIndex) + "()";
                    if (methodSpec.methodIndexIndex != -1)
                    {
                        var methodInst = decompiler.GenericInsts[methodSpec.methodIndexIndex];
                        methodName += decompiler.GetGenericTypeParams(methodInst);
                    }
                    writer.WriteLine($"SetName(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Method$" + methodName}')");
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, '{"Method$" + methodName}', 1)");
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = decompiler.GetMethodPointer(methodDef.methodIndex, methodSpec.methodDefinitionIndex, imageIndex, methodDef.token);
                    writer.WriteLine($"idc.set_cmt(0x{decompiler.MetadataUsages[i.Key]:X}, '0x{methodPointer:X}', 0)");
                }
                writer.WriteLine("print('Set MetadataUsage done')");
            }
            if (config.MakeFunction)
            {
                var orderedPointers = decompiler.GenerateOrderedPointers();
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
    }
}
