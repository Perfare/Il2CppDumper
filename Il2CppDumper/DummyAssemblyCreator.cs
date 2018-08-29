using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Il2CppDumper
{
    public class DummyAssemblyCreator
    {
        private Metadata metadata;
        private Il2Cpp il2cpp;
        public List<AssemblyDefinition> Assemblies = new List<AssemblyDefinition>();
        private Dictionary<long, TypeDefinition> typeDefinitionDic = new Dictionary<long, TypeDefinition>();
        private Dictionary<int, MethodDefinition> methodDefinitionDic = new Dictionary<int, MethodDefinition>();
        private Dictionary<Il2CppType, GenericParameter> genericParameterDic = new Dictionary<Il2CppType, GenericParameter>();


        public DummyAssemblyCreator(Metadata metadata, Il2Cpp il2cpp)
        {
            this.metadata = metadata;
            this.il2cpp = il2cpp;
            //Il2CppDummyDll
            var il2CppDummyDll = AssemblyDefinition.ReadAssembly(new MemoryStream(Resource1.Il2CppDummyDll));
            var addressAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "AddressAttribute").Methods.First();
            var fieldOffsetAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "FieldOffsetAttribute").Methods.First();
            var stringType = il2CppDummyDll.MainModule.TypeSystem.String;
            //创建程序集，同时创建所有类
            foreach (var imageDef in metadata.imageDefs)
            {
                var assemblyName = new AssemblyNameDefinition(metadata.GetStringFromIndex(imageDef.nameIndex).Replace(".dll", ""), new Version("3.7.1.6"));
                var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyName, metadata.GetStringFromIndex(imageDef.nameIndex), ModuleKind.Dll);
                Assemblies.Add(assemblyDefinition);
                var moduleDefinition = assemblyDefinition.MainModule;
                moduleDefinition.Types.Clear();//清除自动创建的<Module>类
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (var index = imageDef.typeStart; index < typeEnd; ++index)
                {
                    var typeDef = metadata.typeDefs[index];
                    var namespaceName = metadata.GetStringFromIndex(typeDef.namespaceIndex);
                    var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);
                    TypeDefinition typeDefinition;
                    if (typeDef.declaringTypeIndex != -1)//nested types
                    {
                        typeDefinition = typeDefinitionDic[index];
                    }
                    else
                    {
                        typeDefinition = new TypeDefinition(namespaceName, typeName, (TypeAttributes)typeDef.flags);
                        moduleDefinition.Types.Add(typeDefinition);
                        typeDefinitionDic.Add(index, typeDefinition);
                    }
                    //nestedtype
                    for (int i = 0; i < typeDef.nested_type_count; i++)
                    {
                        var nestedIndex = metadata.nestedTypeIndices[typeDef.nestedTypesStart + i];
                        var nestedTypeDef = metadata.typeDefs[nestedIndex];
                        var nestedTypeDefinition = new TypeDefinition(metadata.GetStringFromIndex(nestedTypeDef.namespaceIndex), metadata.GetStringFromIndex(nestedTypeDef.nameIndex), (TypeAttributes)nestedTypeDef.flags);
                        typeDefinition.NestedTypes.Add(nestedTypeDefinition);
                        typeDefinitionDic.Add(nestedIndex, nestedTypeDefinition);
                    }
                }
            }
            //先单独处理，因为不知道会不会有问题
            for (var index = 0; index < metadata.uiNumTypes; ++index)
            {
                var typeDef = metadata.typeDefs[index];
                var typeDefinition = typeDefinitionDic[index];
                //parent
                if (typeDef.parentIndex >= 0)
                {
                    var parentType = il2cpp.types[typeDef.parentIndex];
                    var parentTypeRef = GetTypeReference(typeDefinition, parentType);
                    typeDefinition.BaseType = parentTypeRef;
                }
                //interfaces
                for (int i = 0; i < typeDef.interfaces_count; i++)
                {
                    var interfaceType = il2cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                    var interfaceTypeRef = GetTypeReference(typeDefinition, interfaceType);
                    typeDefinition.Interfaces.Add(interfaceTypeRef);
                }
            }
            //处理field, method, property等等
            for (var index = 0; index < metadata.uiNumTypes; ++index)
            {
                var typeDef = metadata.typeDefs[index];
                var typeDefinition = typeDefinitionDic[index];
                //field
                var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                {
                    var fieldDef = metadata.fieldDefs[i];
                    var fieldType = il2cpp.types[fieldDef.typeIndex];
                    var fieldName = metadata.GetStringFromIndex(fieldDef.nameIndex);
                    var fieldTypeRef = GetTypeReference(typeDefinition, fieldType);
                    var fieldDefinition = new FieldDefinition(fieldName, (FieldAttributes)fieldType.attrs, fieldTypeRef);
                    typeDefinition.Fields.Add(fieldDefinition);
                    //fieldDefault
                    if (fieldDefinition.HasDefault)
                    {
                        var fieldDefault = metadata.GetFieldDefaultValueFromIndex(i);
                        if (fieldDefault != null && fieldDefault.dataIndex != -1)
                        {
                            fieldDefinition.Constant = GetDefaultValue(fieldDefault.dataIndex, fieldDefault.typeIndex);
                        }
                    }
                    //fieldOffset
                    var fieldOffset = il2cpp.GetFieldOffsetFromIndex(index, i - typeDef.fieldStart, i);
                    if (fieldOffset > 0)
                    {
                        var customAttribute = new CustomAttribute(typeDefinition.Module.Import(fieldOffsetAttribute));
                        var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{fieldOffset:X}"));
                        customAttribute.Fields.Add(offset);
                        fieldDefinition.CustomAttributes.Add(customAttribute);
                    }
                }
                //method
                var methodEnd = typeDef.methodStart + typeDef.method_count;
                for (var i = typeDef.methodStart; i < methodEnd; ++i)
                {
                    var methodDef = metadata.methodDefs[i];
                    var methodReturnType = il2cpp.types[methodDef.returnType];
                    var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                    var methodDefinition = new MethodDefinition(methodName, (MethodAttributes)methodDef.flags, typeDefinition.Module.Import(typeof(void)));
                    typeDefinition.Methods.Add(methodDefinition);
                    methodDefinition.ReturnType = GetTypeReference(methodDefinition, methodReturnType);
                    if (methodDefinition.HasBody && typeDefinition.BaseType?.FullName != "System.MulticastDelegate")
                    {
                        var ilprocessor = methodDefinition.Body.GetILProcessor();
                        ilprocessor.Append(ilprocessor.Create(OpCodes.Nop));
                    }
                    methodDefinitionDic.Add(i, methodDefinition);
                    //method parameter
                    for (var j = 0; j < methodDef.parameterCount; ++j)
                    {
                        var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                        var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                        var parameterType = il2cpp.types[parameterDef.typeIndex];
                        var parameterTypeRef = GetTypeReference(methodDefinition, parameterType);
                        var parameterDefinition = new ParameterDefinition(parameterName, (ParameterAttributes)parameterType.attrs, parameterTypeRef);
                        methodDefinition.Parameters.Add(parameterDefinition);
                        //ParameterDefault
                        if (parameterDefinition.HasDefault)
                        {
                            var parameterDefault = metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j);
                            if (parameterDefault != null && parameterDefault.dataIndex != -1)
                            {
                                parameterDefinition.Constant = GetDefaultValue(parameterDefault.dataIndex, parameterDefault.typeIndex);
                            }
                        }
                    }
                    //补充泛型参数
                    if (methodDef.genericContainerIndex >= 0)
                    {
                        var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                        if (genericContainer.type_argc > methodDefinition.GenericParameters.Count)
                        {
                            for (int j = methodDefinition.GenericParameters.Count + 1; j <= genericContainer.type_argc; j++)
                            {
                                var genericParameter = new GenericParameter("T" + j, methodDefinition);
                                methodDefinition.GenericParameters.Add(genericParameter);
                            }
                        }
                    }
                    //address
                    ulong methodPointer;
                    if (methodDef.methodIndex >= 0)
                    {
                        methodPointer = il2cpp.methodPointers[methodDef.methodIndex];
                    }
                    else
                    {
                        il2cpp.genericMethoddDictionary.TryGetValue(i, out methodPointer);
                    }
                    if (methodPointer > 0)
                    {
                        var customAttribute = new CustomAttribute(typeDefinition.Module.Import(addressAttribute));
                        var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{methodPointer:X}"));
                        var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2cpp.MapVATR(methodPointer):X}"));
                        customAttribute.Fields.Add(rva);
                        customAttribute.Fields.Add(offset);
                        methodDefinition.CustomAttributes.Add(customAttribute);
                    }
                }
                //property
                var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                {
                    var propertyDef = metadata.propertyDefs[i];
                    var propertyName = metadata.GetStringFromIndex(propertyDef.nameIndex);
                    TypeReference propertyType = null;
                    MethodDefinition GetMethod = null;
                    MethodDefinition SetMethod = null;
                    if (propertyDef.get >= 0)
                    {
                        GetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.get];
                        propertyType = GetMethod.ReturnType;
                    }
                    if (propertyDef.set >= 0)
                    {
                        SetMethod = methodDefinitionDic[typeDef.methodStart + propertyDef.set];
                        if (propertyType == null)
                            propertyType = SetMethod.Parameters[0].ParameterType;
                    }
                    var propertyDefinition = new PropertyDefinition(propertyName, (PropertyAttributes)propertyDef.attrs, propertyType)
                    {
                        GetMethod = GetMethod,
                        SetMethod = SetMethod
                    };
                    typeDefinition.Properties.Add(propertyDefinition);
                }
                //event
                var eventEnd = typeDef.eventStart + typeDef.event_count;
                for (var i = typeDef.eventStart; i < eventEnd; ++i)
                {
                    var eventDef = metadata.eventDefs[i];
                    var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                    var eventType = il2cpp.types[eventDef.typeIndex];
                    var eventTypeRef = GetTypeReference(typeDefinition, eventType);
                    var eventDefinition = new EventDefinition(eventName, (EventAttributes)eventType.attrs, eventTypeRef);
                    if (eventDef.add >= 0)
                        eventDefinition.AddMethod = methodDefinitionDic[typeDef.methodStart + eventDef.add];
                    if (eventDef.remove >= 0)
                        eventDefinition.RemoveMethod = methodDefinitionDic[typeDef.methodStart + eventDef.remove];
                    if (eventDef.raise >= 0)
                        eventDefinition.InvokeMethod = methodDefinitionDic[typeDef.methodStart + eventDef.raise];
                    typeDefinition.Events.Add(eventDefinition);

                }
                //补充泛型参数
                if (typeDef.genericContainerIndex >= 0)
                {
                    var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                    if (genericContainer.type_argc > typeDefinition.GenericParameters.Count)
                    {
                        for (int j = typeDefinition.GenericParameters.Count + 1; j <= genericContainer.type_argc; j++)
                        {
                            var genericParameter = new GenericParameter("T" + j, typeDefinition);
                            typeDefinition.GenericParameters.Add(genericParameter);
                        }
                    }
                }
            }
        }

        private TypeReference GetTypeReference(MemberReference memberReference, Il2CppType pType)
        {
            var moduleDefinition = memberReference.Module;
            switch (pType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return moduleDefinition.Import(typeof(Object));
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                    return moduleDefinition.Import(typeof(void));
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    return moduleDefinition.Import(typeof(Boolean));
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    return moduleDefinition.Import(typeof(Char));
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    return moduleDefinition.Import(typeof(SByte));
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    return moduleDefinition.Import(typeof(Byte));
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    return moduleDefinition.Import(typeof(Int16));
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    return moduleDefinition.Import(typeof(UInt16));
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    return moduleDefinition.Import(typeof(Int32));
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    return moduleDefinition.Import(typeof(UInt32));
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                    return moduleDefinition.Import(typeof(IntPtr));
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                    return moduleDefinition.Import(typeof(UIntPtr));
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    return moduleDefinition.Import(typeof(Int64));
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    return moduleDefinition.Import(typeof(UInt64));
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    return moduleDefinition.Import(typeof(Single));
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    return moduleDefinition.Import(typeof(Double));
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return moduleDefinition.Import(typeof(String));
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                    return moduleDefinition.Import(typeof(TypedReference));
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
                        return new ArrayType(GetTypeReference(memberReference, type), arrayType.rank);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var generic_class = il2cpp.MapVATR<Il2CppGenericClass>(pType.data.generic_class);
                        var typeDefinition = typeDefinitionDic[generic_class.typeDefinitionIndex];
                        var genericInstanceType = new GenericInstanceType(moduleDefinition.Import(typeDefinition));
                        var pInst = il2cpp.MapVATR<Il2CppGenericInst>(generic_class.context.class_inst);
                        var pointers = il2cpp.GetPointers(pInst.type_argv, (long)pInst.type_argc);
                        foreach (var pointer in pointers)
                        {
                            var pOriType = il2cpp.GetIl2CppType(pointer);
                            genericInstanceType.GenericArguments.Add(GetTypeReference(memberReference, pOriType));
                        }
                        return genericInstanceType;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var type = il2cpp.GetIl2CppType(pType.data.type);
                        return new ArrayType(GetTypeReference(memberReference, type));
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (genericParameterDic.TryGetValue(pType, out var genericParameter))
                        {
                            return genericParameter;
                        }
                        if (memberReference is MethodDefinition methodDefinition)
                        {
                            var genericName = "T" + (methodDefinition.DeclaringType.GenericParameters.Count + 1);
                            genericParameter = new GenericParameter(genericName, methodDefinition.DeclaringType);
                            methodDefinition.DeclaringType.GenericParameters.Add(genericParameter);
                            genericParameterDic.Add(pType, genericParameter);
                            return genericParameter;
                        }
                        var typeDefinition = (TypeDefinition)memberReference;
                        var genericName2 = "T" + (typeDefinition.GenericParameters.Count + 1);
                        genericParameter = new GenericParameter(genericName2, typeDefinition);
                        typeDefinition.GenericParameters.Add(genericParameter);
                        genericParameterDic.Add(pType, genericParameter);
                        return genericParameter;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (genericParameterDic.TryGetValue(pType, out var genericParameter))
                        {
                            return genericParameter;
                        }
                        var methodDefinition = (MethodDefinition)memberReference;
                        var genericName = "T" + (methodDefinition.GenericParameters.Count + 1);
                        genericParameter = new GenericParameter(genericName, methodDefinition);
                        methodDefinition.GenericParameters.Add(genericParameter);
                        genericParameterDic.Add(pType, genericParameter);
                        return genericParameter;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var type = il2cpp.GetIl2CppType(pType.data.type);
                        return new PointerType(GetTypeReference(memberReference, type));
                    }
                default:
                    return moduleDefinition.Import(typeof(Object));
            }
        }

        private object GetDefaultValue(int dataIndex, int typeIndex)
        {
            var pointer = metadata.GetDefaultValueFromIndex(dataIndex);
            if (pointer > 0)
            {
                var pTypeToUse = il2cpp.types[typeIndex];
                metadata.Position = pointer;
                switch (pTypeToUse.type)
                {
                    case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                        return metadata.ReadBoolean();
                    case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                        return metadata.ReadByte();
                    case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                        return metadata.ReadSByte();
                    case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                        return BitConverter.ToChar(metadata.ReadBytes(2), 0);
                    case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                        return metadata.ReadUInt16();
                    case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                        return metadata.ReadInt16();
                    case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                        return metadata.ReadUInt32();
                    case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                        return metadata.ReadInt32();
                    case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                        return metadata.ReadUInt64();
                    case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                        return metadata.ReadInt64();
                    case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                        return metadata.ReadSingle();
                    case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                        return metadata.ReadDouble();
                    case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                        var uiLen = metadata.ReadInt32();
                        return Encoding.UTF8.GetString(metadata.ReadBytes(uiLen));
                }
            }
            return null;
        }
    }
}
