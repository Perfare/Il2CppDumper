using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class ScriptGenerator
    {
        private Il2CppExecutor executor;
        private Metadata metadata;
        private Il2Cpp il2Cpp;
        private Dictionary<Il2CppTypeDefinition, int> typeDefImageIndices = new Dictionary<Il2CppTypeDefinition, int>();
        private HashSet<string> structNameHashSet = new HashSet<string>(StringComparer.Ordinal);
        private List<StructInfo> structInfoList = new List<StructInfo>();
        private Dictionary<string, StructInfo> structInfoWithStructName = new Dictionary<string, StructInfo>();
        private HashSet<StructInfo> structCache = new HashSet<StructInfo>();
        private Dictionary<Il2CppTypeDefinition, string> structNameDic = new Dictionary<Il2CppTypeDefinition, string>();
        private Dictionary<ulong, string> genericClassStructNameDic = new Dictionary<ulong, string>();
        private List<ulong> genericClassList = new List<ulong>();
        private StringBuilder arrayClassPreHeader = new StringBuilder();
        private StringBuilder arrayClassHeader = new StringBuilder();
        private static HashSet<string> keyword = new HashSet<string>(StringComparer.Ordinal) { "klass", "monitor", "register", "_cs", "auto", "friend", "template" };

        public ScriptGenerator(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
        }

        public void WriteScript(Config config)
        {
            var json = new ScriptJson();
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    var typeDef = metadata.typeDefs[typeIndex];
                    CreateStructNameDic(typeDef);
                }
            }
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int typeIndex = imageDef.typeStart; typeIndex < typeEnd; typeIndex++)
                {
                    var typeDef = metadata.typeDefs[typeIndex];
                    AddStruct(typeDef);
                    var typeName = executor.GetTypeDefName(typeDef, true, true);
                    typeDefImageIndices.Add(typeDef, imageIndex);
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        var methodDef = metadata.methodDefs[i];
                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                        var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                        if (methodPointer > 0)
                        {
                            var scriptMethod = new ScriptMethod();
                            json.ScriptMethod.Add(scriptMethod);
                            scriptMethod.Address = il2Cpp.GetRVA(methodPointer);
                            var methodFullName = typeName + "$$" + methodName;
                            scriptMethod.Name = methodFullName;

                            var methodReturnType = il2Cpp.types[methodDef.returnType];
                            var returnType = ParseType(methodReturnType);
                            var signature = $"{returnType} {FixName(methodFullName)} (";
                            var parameterStrs = new List<string>();
                            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) == 0)
                            {
                                var thisType = ParseType(il2Cpp.types[typeDef.byrefTypeIndex]);
                                parameterStrs.Add($"{thisType} this");
                            }
                            for (var j = 0; j < methodDef.parameterCount; j++)
                            {
                                var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                var parameterType = il2Cpp.types[parameterDef.typeIndex];
                                parameterStrs.Add($"{ParseType(parameterType)} {FixName(parameterName)}");
                            }
                            signature += string.Join(", ", parameterStrs);
                            signature += ");";
                            scriptMethod.Signature = signature;
                        }
                    }
                }
            }
            if (il2Cpp.Version > 16)
            {
                foreach (var i in metadata.metadataUsageDic[1]) //kIl2CppMetadataUsageTypeInfo
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, false);
                    var scriptMetadata = new ScriptMetadata();
                    json.ScriptMetadata.Add(scriptMetadata);
                    scriptMetadata.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadata.Name = "Class$" + typeName;
                    var signature = GetIl2CppStructName(type);
                    if (signature.EndsWith("_array"))
                    {
                        scriptMetadata.Signature = signature + "*";
                    }
                    else
                    {
                        scriptMetadata.Signature = FixName(signature) + "_c*";
                    }
                }
                foreach (var i in metadata.metadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, false);
                    var scriptMetadata = new ScriptMetadata();
                    json.ScriptMetadata.Add(scriptMetadata);
                    scriptMetadata.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadata.Name = "Object$" + typeName;
                    var signature = GetIl2CppStructName(type);
                    if (signature.EndsWith("_array"))
                    {
                        scriptMetadata.Signature = signature + "*";
                    }
                    else
                    {
                        scriptMetadata.Signature = FixName(signature) + "_o*";
                    }
                }
                foreach (var i in metadata.metadataUsageDic[3]) //kIl2CppMetadataUsageMethodDef
                {
                    var methodDef = metadata.methodDefs[i.Value];
                    var typeDef = metadata.typeDefs[methodDef.declaringType];
                    var typeName = executor.GetTypeDefName(typeDef, true, true);
                    var methodName = typeName + "." + metadata.GetStringFromIndex(methodDef.nameIndex) + "()";
                    var scriptMetadataMethod = new ScriptMetadataMethod();
                    json.ScriptMetadataMethod.Add(scriptMetadataMethod);
                    scriptMetadataMethod.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadataMethod.Name = "Method$" + methodName;
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, (int)i.Value, imageIndex, methodDef.token);
                    if (methodPointer > 0)
                    {
                        scriptMetadataMethod.MethodAddress = il2Cpp.GetRVA(methodPointer);
                    }
                }
                foreach (var i in metadata.metadataUsageDic[4]) //kIl2CppMetadataUsageFieldInfo
                {
                    var fieldRef = metadata.fieldRefs[i.Value];
                    var type = il2Cpp.types[fieldRef.typeIndex];
                    var typeDef = metadata.typeDefs[type.data.klassIndex];
                    var fieldDef = metadata.fieldDefs[typeDef.fieldStart + fieldRef.fieldIndex];
                    var fieldName = executor.GetTypeName(type, true, false) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
                    var scriptMetadata = new ScriptMetadata();
                    json.ScriptMetadata.Add(scriptMetadata);
                    scriptMetadata.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadata.Name = "Field$" + fieldName;
                }
                foreach (var i in metadata.metadataUsageDic[5]) //kIl2CppMetadataUsageStringLiteral
                {
                    var scriptString = new ScriptString();
                    json.ScriptString.Add(scriptString);
                    scriptString.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptString.Value = metadata.GetStringLiteralFromIndex(i.Value);
                }
                var stringLiterals = json.ScriptString.Select(x => new
                {
                    value = x.Value,
                    address = $"0x{x.Address:X}"
                }).ToArray();
                File.WriteAllText("stringliteral.json", JsonConvert.SerializeObject(stringLiterals, Formatting.Indented), new UTF8Encoding(false));
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
                    var scriptMetadataMethod = new ScriptMetadataMethod();
                    json.ScriptMetadataMethod.Add(scriptMetadataMethod);
                    scriptMetadataMethod.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadataMethod.Name = "Method$" + methodName;
                    var imageIndex = typeDefImageIndices[typeDef];
                    var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, methodSpec.methodDefinitionIndex, imageIndex, methodDef.token);
                    if (methodPointer > 0)
                    {
                        scriptMetadataMethod.MethodAddress = il2Cpp.GetRVA(methodPointer);
                    }
                }
            }
            if (config.MakeFunction)
            {
                List<ulong> orderedPointers;
                if (il2Cpp.Version >= 24.2f)
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
                if (il2Cpp.Version >= 22)
                {
                    orderedPointers.AddRange(il2Cpp.reversePInvokeWrappers);
                    orderedPointers.AddRange(il2Cpp.unresolvedVirtualCallPointers);
                }
                //TODO interopData内也包含函数
                orderedPointers = orderedPointers.Distinct().OrderBy(x => x).ToList();
                orderedPointers.Remove(0);
                for (int i = 0; i < orderedPointers.Count; i++)
                {
                    orderedPointers[i] = il2Cpp.GetRVA(orderedPointers[i]);
                }
                json.Addresses = orderedPointers;
            }
            File.WriteAllText("script.json", JsonConvert.SerializeObject(json, Formatting.Indented));
            //il2cpp.h
            for (int i = 0; i < genericClassList.Count; i++)
            {
                var pointer = genericClassList[i];
                AddGenericClassStruct(pointer);
            }
            var preHeader = new StringBuilder();
            var headerStruct = new StringBuilder();
            var headerClass = new StringBuilder();
            foreach (var info in structInfoList)
            {
                structInfoWithStructName.Add(info.TypeName + "_o", info);
            }
            foreach (var info in structInfoList)
            {
                preHeader.Append($"struct {info.TypeName}_o;\n");

                if (info.IsValueType)
                {
                    headerStruct.Append(RecursionStructInfo(info));
                }
                else
                {
                    headerClass.Append($"struct {info.TypeName}_StaticFields {{\n");
                    foreach (var field in info.StaticFields)
                    {
                        headerClass.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
                    }
                    headerClass.Append("};\n");

                    headerClass.Append($"struct {info.TypeName}_VTable {{\n");
                    foreach (var method in info.VTableMethod)
                    {
                        headerClass.Append($"\tVirtualInvokeData {method.MethodName};\n");
                    }
                    headerClass.Append("};\n");

                    headerClass.Append($"struct {info.TypeName}_c {{\n" +
                        $"\tIl2CppClass_1 _1;\n" +
                        $"\t{info.TypeName}_StaticFields* static_fields;\n" +
                        $"\tIl2CppClass_2 _2;\n" +
                        $"\t{info.TypeName}_VTable vtable;\n" +
                        $"}};\n");
                    headerClass.Append($"struct {info.TypeName}_o {{\n" +
                        $"\t{info.TypeName}_c *klass;\n" +
                        $"\tvoid *monitor;\n");

                    foreach (var field in info.Fields)
                    {
                        headerClass.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
                    }
                    headerClass.Append("};\n");
                }
            }
            var sb = new StringBuilder();
            if (il2Cpp is PE)
            {
                sb.Append(HeaderConstants.TypedefHeader);
            }
            sb.Append(HeaderConstants.GenericHeader);
            switch (il2Cpp.Version)
            {
                case 22f:
                    sb.Append(HeaderConstants.HeaderV22);
                    break;
                case 23f:
                    sb.Append(HeaderConstants.HeaderV240);
                    break;
                case 24f:
                    sb.Append(HeaderConstants.HeaderV240);
                    break;
                case 24.1f:
                    sb.Append(HeaderConstants.HeaderV241);
                    break;
                case 24.2f:
                    sb.Append(HeaderConstants.HeaderV242);
                    break;
                //TODO
                default:
                    Console.WriteLine($"WARNING: This il2cpp version [{il2Cpp.Version}] does not support generating .h files");
                    return;
            }
            sb.Append(preHeader);
            sb.Append(arrayClassPreHeader);
            sb.Append(headerStruct);
            sb.Append(headerClass);
            sb.Append(arrayClassHeader);
            File.WriteAllText("il2cpp.h", sb.ToString());
        }

        private static string FixName(string str)
        {
            if (keyword.Contains(str))
            {
                str = "_" + str;
            }
            if (Regex.IsMatch(str, "^[0-9]"))
            {
                return "_" + str;
            }
            else
            {
                return Regex.Replace(str, "[^a-zA-Z0-9_]", "_");
            }
        }

        private string ParseType(Il2CppType il2CppType, Il2CppGenericContext context = null)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                    return "void";
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    return "bool";
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    return "uint16_t"; //Il2CppChar
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    return "int8_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    return "uint8_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    return "int16_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    return "uint16_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    return "int32_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    return "uint32_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    return "int64_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    return "uint64_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    return "float";
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    return "double";
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return "System_String_o*";
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        return ParseType(oriType) + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                        if (typeDef.IsEnum)
                        {
                            return ParseType(il2Cpp.types[typeDef.elementTypeIndex]);
                        }
                        return structNameDic[typeDef] + "_o";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                    {
                        var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                        return structNameDic[typeDef] + "_o*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return ParseType(type);
                        }
                        return "Il2CppObject*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var elementType = il2Cpp.GetIl2CppType(arrayType.etype);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                        var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                        if (!genericClassStructNameDic.TryGetValue(il2CppType.data.generic_class, out var typeStructName))
                        {
                            var typeOriName = structNameDic[typeDef];
                            var typeToReplaceName = FixName(executor.GetTypeDefName(typeDef, true, true));
                            var typeReplaceName = FixName(executor.GetTypeName(il2CppType, true, false));
                            typeStructName = typeOriName.Replace(typeToReplaceName, typeReplaceName);
                            genericClassStructNameDic.Add(il2CppType.data.generic_class, typeStructName);
                            if (structNameHashSet.Add(typeStructName))
                            {
                                genericClassList.Add(il2CppType.data.generic_class);
                            }
                        }
                        if (typeDef.IsValueType)
                        {
                            return typeStructName + "_o";
                        }
                        return typeStructName + "_o*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                    return "Il2CppObject*";
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                    return "intptr_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                    return "uintptr_t";
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return "Il2CppObject*";
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var elementType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName + "*";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return ParseType(type);
                        }
                        return "Il2CppObject*";
                    }
                default:
                    throw new NotSupportedException();
            }
        }

        private void AddStruct(Il2CppTypeDefinition typeDef)
        {
            var structInfo = new StructInfo();
            structInfoList.Add(structInfo);
            structInfo.TypeName = structNameDic[typeDef];
            structInfo.IsValueType = typeDef.IsValueType;
            AddFields(typeDef, structInfo.Fields, structInfo.StaticFields, null, false);
            AddVTableMethod(structInfo, typeDef);
        }

        private void AddGenericClassStruct(ulong pointer)
        {
            var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(pointer);
            var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
            var structInfo = new StructInfo();
            structInfoList.Add(structInfo);
            structInfo.TypeName = genericClassStructNameDic[pointer];
            structInfo.IsValueType = typeDef.IsValueType;
            AddFields(typeDef, structInfo.Fields, structInfo.StaticFields, genericClass.context, false);
            AddVTableMethod(structInfo, typeDef);
        }

        private void AddFields(Il2CppTypeDefinition typeDef, List<StructFieldInfo> fields, List<StructFieldInfo> staticFields, Il2CppGenericContext context, bool isParent)
        {
            if (!typeDef.IsValueType && !typeDef.IsEnum)
            {
                if (typeDef.parentIndex >= 0)
                {
                    var parent = il2Cpp.types[typeDef.parentIndex];
                    ParseParent(parent, out var parentDef, out var parentContext);
                    if (parentDef != null)
                    {
                        AddFields(parentDef, fields, staticFields, parentContext, true);
                    }
                }
            }
            if (typeDef.field_count > 0)
            {
                var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                {
                    var fieldDef = metadata.fieldDefs[i];
                    var fieldType = il2Cpp.types[fieldDef.typeIndex];
                    if ((fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) != 0)
                    {
                        continue;
                    }
                    var structFieldInfo = new StructFieldInfo();
                    structFieldInfo.FieldTypeName = ParseType(fieldType, context);
                    var fieldName = FixName(metadata.GetStringFromIndex(fieldDef.nameIndex));
                    structFieldInfo.FieldName = fieldName;
                    structFieldInfo.IsValueType = IsValueType(fieldType, context);
                    if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                    {
                        if (!isParent)
                        {
                            staticFields.Add(structFieldInfo);
                        }
                    }
                    else
                    {
                        if (isParent)
                        {
                            var access = fieldType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
                            if (access == FIELD_ATTRIBUTE_PRIVATE)
                            {
                                structFieldInfo.FieldName = $"{FixName(metadata.GetStringFromIndex(typeDef.nameIndex))}_{fieldName}";
                            }
                        }
                        if (fields.Any(x => x.FieldName == structFieldInfo.FieldName))
                        {
                            structFieldInfo.FieldName = "new_" + structFieldInfo.FieldName;
                        }
                        fields.Add(structFieldInfo);
                    }
                }
            }
        }

        private void AddVTableMethod(StructInfo structInfo, Il2CppTypeDefinition typeDef)
        {
            var dic = new SortedDictionary<int, Il2CppMethodDefinition>();
            for (int i = 0; i < typeDef.vtable_count; i++)
            {
                var vTableIndex = typeDef.vtableStart + i;
                var encodedMethodIndex = metadata.vtableMethods[vTableIndex];
                var usage = metadata.GetEncodedIndexType(encodedMethodIndex);
                var index = metadata.GetDecodedMethodIndex(encodedMethodIndex);
                Il2CppMethodDefinition methodDef;
                if (usage == 6) //kIl2CppMetadataUsageMethodRef
                {
                    var methodSpec = il2Cpp.methodSpecs[index];
                    methodDef = metadata.methodDefs[methodSpec.methodDefinitionIndex];
                }
                else
                {
                    methodDef = metadata.methodDefs[index];
                }
                dic[methodDef.slot] = methodDef;
            }
            foreach (var i in dic)
            {
                var methodInfo = new StructVTableMethodInfo();
                structInfo.VTableMethod.Add(methodInfo);
                var methodDef = i.Value;
                methodInfo.MethodName = $"_{methodDef.slot}_{FixName(metadata.GetStringFromIndex(methodDef.nameIndex))}";
            }
        }

        private void ParseArrayClassStruct(Il2CppType il2CppType, Il2CppGenericContext context)
        {
            var structName = GetIl2CppStructName(il2CppType, context);
            arrayClassPreHeader.Append($"struct {structName}_array;\n");
            arrayClassHeader.Append($"struct {structName}_array {{\n" +
                $"\tIl2CppObject obj;\n" +
                $"\tIl2CppArrayBounds *bounds;\n" +
                $"\tuintptr_t max_length;\n" +
                $"\t{ParseType(il2CppType, context)} m_Items[65535];\n" +
                $"}};\n");
        }

        private void ParseParent(Il2CppType il2CppType, out Il2CppTypeDefinition typeDef, out Il2CppGenericContext context)
        {
            context = null;
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                    break;
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                    context = genericClass.context;
                    typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                    break;
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    typeDef = null;
                    break;
                default:
                    throw new NotSupportedException();
            }
        }

        private void CreateStructNameDic(Il2CppTypeDefinition typeDef)
        {
            var typeName = executor.GetTypeDefName(typeDef, true, true);
            var typeStructName = FixName(typeName);
            var uniqueName = GetUniqueName(typeStructName);
            structNameDic.Add(typeDef, uniqueName);
        }

        private string GetUniqueName(string name)
        {
            var fixName = name;
            int i = 1;
            while (!structNameHashSet.Add(fixName))
            {
                fixName = $"{name}_{i++}";
            }
            return fixName;
        }

        private string RecursionStructInfo(StructInfo info)
        {
            if (!structCache.Add(info))
            {
                return string.Empty;
            }

            var sb = new StringBuilder();
            var pre = new StringBuilder();

            sb.Append($"struct {info.TypeName}_o {{\n");
            foreach (var field in info.Fields)
            {
                if (field.IsValueType)
                {
                    var fieldInfo = structInfoWithStructName[field.FieldTypeName];
                    pre.Append(RecursionStructInfo(fieldInfo));
                }
                sb.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
            }
            sb.Append("};\n");

            sb.Append($"struct {info.TypeName}_StaticFields {{\n");
            foreach (var field in info.StaticFields)
            {
                if (field.IsValueType)
                {
                    var fieldInfo = structInfoWithStructName[field.FieldTypeName];
                    pre.Append(RecursionStructInfo(fieldInfo));
                }
                sb.Append($"\t{field.FieldTypeName} {field.FieldName};\n");
            }
            sb.Append("};\n");

            sb.Append($"struct {info.TypeName}_VTable {{\n");
            foreach (var method in info.VTableMethod)
            {
                sb.Append($"\tVirtualInvokeData {method.MethodName};\n");
            }
            sb.Append("};\n");

            sb.Append($"struct {info.TypeName}_c {{\n" +
                $"\tIl2CppClass_1 _1;\n" +
                $"\t{info.TypeName}_StaticFields* static_fields;\n" +
                $"\tIl2CppClass_2 _2;\n" +
                $"\t{info.TypeName}_VTable vtable;\n" +
                $"}};\n");

            return pre.Append(sb).ToString();
        }

        private string GetIl2CppStructName(Il2CppType il2CppType, Il2CppGenericContext context = null)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    {
                        var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                        return structNameDic[typeDef];
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        return GetIl2CppStructName(oriType);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var elementType = il2Cpp.GetIl2CppType(arrayType.etype);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var elementType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        var elementStructName = GetIl2CppStructName(elementType, context);
                        var typeStructName = elementStructName + "_array";
                        if (structNameHashSet.Add(typeStructName))
                        {
                            ParseArrayClassStruct(elementType, context);
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        if (!genericClassStructNameDic.TryGetValue(il2CppType.data.generic_class, out var typeStructName))
                        {
                            var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                            var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                            var typeOriName = structNameDic[typeDef];
                            var typeToReplaceName = FixName(executor.GetTypeDefName(typeDef, true, true));
                            var typeReplaceName = FixName(executor.GetTypeName(il2CppType, true, false));
                            typeStructName = typeOriName.Replace(typeToReplaceName, typeReplaceName);
                            genericClassStructNameDic.Add(il2CppType.data.generic_class, typeStructName);
                            if (structNameHashSet.Add(typeStructName))
                            {
                                genericClassList.Add(il2CppType.data.generic_class);
                            }
                        }
                        return typeStructName;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return GetIl2CppStructName(type);
                        }
                        return "System_Object";
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return GetIl2CppStructName(type);
                        }
                        return "System_Object";
                    }
                default:
                    throw new NotSupportedException();
            }
        }

        private bool IsValueType(Il2CppType il2CppType, Il2CppGenericContext context)
        {
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                        if (!typeDef.IsEnum)
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                        var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                        return typeDef.IsValueType;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.class_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return IsValueType(type, null);
                        }
                        return false;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (context != null)
                        {
                            var genericParameter = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                            var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(context.method_inst);
                            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                            var pointer = pointers[genericParameter.num];
                            var type = il2Cpp.GetIl2CppType(pointer);
                            return IsValueType(type, null);
                        }
                        return false;
                    }
                default:
                    return false;
            }
        }
    }
}
