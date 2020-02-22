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
            var json = new ScriptJson();
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
                            var scriptMethod = new ScriptMethod();
                            json.ScriptMethod.Add(scriptMethod);
                            scriptMethod.Address = il2Cpp.GetRVA(methodPointer);
                            scriptMethod.Name = typeName + "$$" + methodName;
                        }
                    }
                }
            }
            if (il2Cpp.Version > 16)
            {
                foreach (var i in metadata.metadataUsageDic[1]) //kIl2CppMetadataUsageTypeInfo
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, true);
                    var scriptMetadata = new ScriptMetadata();
                    json.ScriptMetadata.Add(scriptMetadata);
                    scriptMetadata.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadata.Name = "Class$" + typeName;
                }
                foreach (var i in metadata.metadataUsageDic[2]) //kIl2CppMetadataUsageIl2CppType
                {
                    var type = il2Cpp.types[i.Value];
                    var typeName = executor.GetTypeName(type, true, true);
                    var scriptMetadata = new ScriptMetadata();
                    json.ScriptMetadata.Add(scriptMetadata);
                    scriptMetadata.Address = il2Cpp.GetRVA(il2Cpp.metadataUsages[i.Key]);
                    scriptMetadata.Name = "Class$" + typeName;
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
                    if (methodPointer == 0)
                    {
                        scriptMetadataMethod.MethodAddress = 0;
                    }
                    else
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
                    var fieldName = executor.GetTypeName(type, true, true) + "." + metadata.GetStringFromIndex(fieldDef.nameIndex);
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
                    if (methodPointer == 0)
                    {
                        scriptMetadataMethod.MethodAddress = 0;
                    }
                    else
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
