using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Il2CppDumper
{
    static class DummyDllCreator
    {
        static Metadata metadata = Program.metadata;
        static Il2Cpp il2cpp = Program.il2cpp;
        static List<AssemblyDefinition> assemblyDefinitions = new List<AssemblyDefinition>();
        static Dictionary<long, TypeDefinition> typeDefinitionDic = new Dictionary<long, TypeDefinition>();
        static Dictionary<int, MethodDefinition> methodDefinitionDic = new Dictionary<int, MethodDefinition>();


        //TODO 泛型类，泛型方法，泛型参数等等关于泛型的东西。。。
        public static void AssemblyCreat()
        {
            Directory.CreateDirectory("DummyDll");
            //var Il2CppDummyDll = AssemblyDefinition.ReadAssembly("Il2CppDummyDll.dll");
            //var AddressAttribute = Il2CppDummyDll.MainModule.Types.First(x => x.Name == "AddressAttribute").Methods.First();
            //var FieldOffsetAttribute = Il2CppDummyDll.MainModule.Types.First(x => x.Name == "FieldOffsetAttribute").Methods.First();
            //创建程序集，同时遍历所有类
            foreach (var imageDef in metadata.imageDefs)
            {
                var assemblyName = new AssemblyNameDefinition(metadata.GetString(imageDef.nameIndex).Replace(".dll", ""), new Version("3.7.1.6"));
                var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyName, metadata.GetString(imageDef.nameIndex), ModuleKind.Dll);
                assemblyDefinitions.Add(assemblyDefinition);
                var moduleDefinition = assemblyDefinition.MainModule;
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var idx = imageDef.typeStart; idx < typeEnd; ++idx)
                {
                    var typeDef = metadata.typeDefs[idx];
                    var namespaceName = metadata.GetString(typeDef.namespaceIndex);
                    var typeName = metadata.GetString(typeDef.nameIndex);
                    if (typeName == "<Module>")
                    {
                        typeDefinitionDic.Add(idx, null);
                        continue;
                    }
                    TypeDefinition typeDefinition = null;
                    if (typeDef.declaringTypeIndex != -1)//nested types
                    {
                        typeDefinition = typeDefinitionDic[idx];
                    }
                    else
                    {
                        typeDefinition = new TypeDefinition(namespaceName, typeName, (TypeAttributes)typeDef.flags);
                        moduleDefinition.Types.Add(typeDefinition);
                        typeDefinitionDic.Add(idx, typeDefinition);
                    }
                    //nestedtype
                    for (int i = 0; i < typeDef.nested_type_count; i++)
                    {
                        var nestedIndex = metadata.GetNestedTypeFromIndex(typeDef.nestedTypesStart + i);
                        var nestedTypeDef = metadata.typeDefs[nestedIndex];
                        var nestedTypeDefinition = new TypeDefinition(metadata.GetString(nestedTypeDef.namespaceIndex), metadata.GetString(nestedTypeDef.nameIndex), (TypeAttributes)nestedTypeDef.flags);
                        typeDefinition.NestedTypes.Add(nestedTypeDefinition);
                        typeDefinitionDic.Add(nestedIndex, nestedTypeDefinition);
                    }
                }
            }
            for (var idx = 0; idx < metadata.uiNumTypes; ++idx)
            {
                var typeDef = metadata.typeDefs[idx];
                var typeDefinition = typeDefinitionDic[idx];
                //parent
                if (typeDef.parentIndex >= 0)
                {
                    var parentType = il2cpp.types[typeDef.parentIndex];
                    var parentTypeRef = typeDefinition.Module.GetTypeReference(parentType);
                    typeDefinition.BaseType = parentTypeRef;
                }
                //interfaces
                for (int i = 0; i < typeDef.interfaces_count; i++)
                {
                    var interfaceType = il2cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                    var interfaceTypeRef = typeDefinition.Module.GetTypeReference(interfaceType);
                    typeDefinition.Interfaces.Add(interfaceTypeRef);
                }
            }
            //处理field, method, property等等
            for (var imageIndex = 0; imageIndex < metadata.uiImageCount; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var assemblyDefinition = assemblyDefinitions[imageIndex];
                var moduleDefinition = assemblyDefinition.MainModule;
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var idx = imageDef.typeStart; idx < typeEnd; ++idx)
                {
                    var typeDef = metadata.typeDefs[idx];
                    var typeDefinition = typeDefinitionDic[idx];

                    //field
                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                    for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                    {
                        var fieldDef = metadata.fieldDefs[i];
                        var fieldType = il2cpp.types[fieldDef.typeIndex];
                        var fieldName = metadata.GetString(fieldDef.nameIndex);
                        var fieldTypeRef = moduleDefinition.GetTypeReference(fieldType);
                        var fieldDefinition = new FieldDefinition(fieldName, (FieldAttributes)fieldType.attrs, fieldTypeRef);
                        typeDefinition.Fields.Add(fieldDefinition);
                        /*//fieldOffset
                        var fieldOffset = il2cpp.GetFieldOffsetFromIndex(idx, i - typeDef.fieldStart, i);
                        if (fieldOffset > 0)
                        {
                            var customAttribute = new CustomAttribute(moduleDefinition.Import(FieldOffsetAttribute));
                            var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(Il2CppDummyDll.MainModule.TypeSystem.Int64, fieldOffset));
                            customAttribute.Fields.Add(offset);
                            fieldDefinition.CustomAttributes.Add(customAttribute);
                        }*/
                    }

                    //method
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        var methodDef = metadata.methodDefs[i];
                        var methodReturnType = il2cpp.types[methodDef.returnType];
                        var methodReturnTypeRef = moduleDefinition.GetTypeReference(methodReturnType);
                        var methodName = metadata.GetString(methodDef.nameIndex);
                        var methodDefinition = new MethodDefinition(methodName, (MethodAttributes)methodDef.flags, methodReturnTypeRef);
                        if (methodDefinition.HasBody)
                        {
                            var ilprocessor = methodDefinition.Body.GetILProcessor();
                            ilprocessor.Append(ilprocessor.Create(OpCodes.Nop));
                        }
                        typeDefinition.Methods.Add(methodDefinition);
                        methodDefinitionDic.Add(i, methodDefinition);
                        //method parameter
                        for (var j = 0; j < methodDef.parameterCount; ++j)
                        {
                            var pParam = metadata.parameterDefs[methodDef.parameterStart + j];
                            var parameterName = metadata.GetString(pParam.nameIndex);
                            var parameterType = il2cpp.types[pParam.typeIndex];
                            var parameterTypeRef = moduleDefinition.GetTypeReference(parameterType);
                            var parameterDefinition = new ParameterDefinition(parameterName, (ParameterAttributes)parameterType.attrs, parameterTypeRef);
                            methodDefinition.Parameters.Add(parameterDefinition);
                        }
                        /*//address
                        if (methodDef.methodIndex >= 0)
                        {
                            var customAttribute = new CustomAttribute(moduleDefinition.Import(AddressAttribute));
                            var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(Il2CppDummyDll.MainModule.TypeSystem.UInt64, il2cpp.methodPointers[methodDef.methodIndex]));
                            var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(Il2CppDummyDll.MainModule.TypeSystem.UInt64, il2cpp.MapVATR(il2cpp.methodPointers[methodDef.methodIndex])));
                            customAttribute.Fields.Add(rva);
                            customAttribute.Fields.Add(offset);
                            methodDefinition.CustomAttributes.Add(customAttribute);
                        }*/
                    }

                    //property
                    var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                    for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                    {
                        var propertyDef = metadata.propertyDefs[i];
                        var propertyName = metadata.GetString(propertyDef.nameIndex);
                        TypeReference propertyType;
                        MethodDefinition GetMethod = null;
                        MethodDefinition SetMethod = null;
                        if (propertyDef.get >= 0)
                        {
                            GetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.get];
                            propertyType = GetMethod.ReturnType;
                        }
                        else
                        {
                            SetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.set];
                            propertyType = SetMethod.Parameters[0].ParameterType;
                        }
                        var propertyDefinition = new PropertyDefinition(propertyName, (PropertyAttributes)propertyDef.attrs, propertyType);
                        propertyDefinition.GetMethod = GetMethod;
                        propertyDefinition.SetMethod = SetMethod;
                        typeDefinition.Properties.Add(propertyDefinition);
                    }
                }
                var file = File.Create("./DummyDll/" + metadata.GetString(imageDef.nameIndex));
                assemblyDefinition.Write(file);
                file.Close();
            }
        }

        private static TypeReference GetTypeReference(this ModuleDefinition moduleDefinition, Il2CppType pType)
        {
            switch (pType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDefinition = typeDefinitionDic[pType.data.klassIndex];
                        return moduleDefinition.Import(typeDefinition);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2cpp.MapVATR<Il2CppArrayType>(pType.data.array);
                        var type = il2cpp.GetIl2CppType(arrayType.etype);
                        var array = new ArrayType(moduleDefinition.GetTypeReference(type), arrayType.rank);
                        return moduleDefinition.Import(array);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var generic_class = il2cpp.MapVATR<Il2CppGenericClass>(pType.data.generic_class);
                        var typeDefinition = typeDefinitionDic[generic_class.typeDefinitionIndex];
                        var genericInstanceType = new GenericInstanceType(typeDefinition);
                        var pInst = il2cpp.MapVATR<Il2CppGenericInst>(generic_class.context.class_inst);
                        var pointers = il2cpp.GetPointers(pInst.type_argv, (long)pInst.type_argc);
                        foreach (var pointer in pointers)
                        {
                            var pOriType = il2cpp.GetIl2CppType(pointer);
                            genericInstanceType.GenericArguments.Add(moduleDefinition.GetTypeReference(pOriType));
                        }
                        return moduleDefinition.Import(genericInstanceType);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var type = il2cpp.GetIl2CppType(pType.data.type);
                        var array = new ArrayType(moduleDefinition.GetTypeReference(type));
                        return moduleDefinition.Import(array);
                    }
                default:
                    {
                        if (FullNameTypeString.TryGetValue((int)pType.type, out var fullName))
                        {
                            foreach (var assemblyDefinition in assemblyDefinitions)
                            {
                                var typeReference = assemblyDefinition.MainModule.GetType(fullName);
                                if (typeReference != null)
                                    return moduleDefinition.Import(typeReference);
                            }
                        }
                        else
                        {
                            foreach (var assemblyDefinition in assemblyDefinitions)
                            {
                                var typeReference = assemblyDefinition.MainModule.GetType("System.Int32");
                                if (typeReference != null)
                                    return moduleDefinition.Import(typeReference);
                            }
                        }
                        return null;
                    }
            }
        }

        public static Dictionary<int, string> FullNameTypeString = new Dictionary<int, string>
        {
            {1,"System.Void"},
            {2,"System.Boolean"},
            {3,"System.Char"},
            {4,"System.SByte"},
            {5,"System.Byte"},
            {6,"System.Int16"},
            {7,"System.UInt16"},
            {8,"System.Int32"},
            {9,"System.UInt32"},
            {10,"System.Int64"},
            {11,"System.UInt64"},
            {12,"System.Single"},
            {13,"System.Double"},
            {14,"System.String"},
            {24,"System.IntPtr"},
            {25,"System.UIntPtr"},
            {27,"System.Delegate"},
            {28,"System.Object"},
        };
    }
}
