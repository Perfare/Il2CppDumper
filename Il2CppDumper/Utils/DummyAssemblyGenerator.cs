using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Collections.Generic;

namespace Il2CppDumper
{
    public class DummyAssemblyGenerator
    {
        public List<AssemblyDefinition> Assemblies = new List<AssemblyDefinition>();

        private Metadata metadata;
        private Il2Cpp il2Cpp;
        private Dictionary<long, TypeDefinition> typeDefinitionDic = new Dictionary<long, TypeDefinition>();
        private Dictionary<long, GenericParameter> genericParameterDic = new Dictionary<long, GenericParameter>();
        private MethodDefinition attributeAttribute;
        private TypeReference stringType;
        private Dictionary<string, MethodDefinition> knownAttributes = new Dictionary<string, MethodDefinition>();

        public DummyAssemblyGenerator(Metadata metadata, Il2Cpp il2Cpp)
        {
            this.metadata = metadata;
            this.il2Cpp = il2Cpp;

            //Il2CppDummyDll
            var il2CppDummyDll = Il2CppDummyDll.Create();
            Assemblies.Add(il2CppDummyDll);
            var addressAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "AddressAttribute").Methods[0];
            var fieldOffsetAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "FieldOffsetAttribute").Methods[0];
            attributeAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "AttributeAttribute").Methods[0];
            var metadataOffsetAttribute = il2CppDummyDll.MainModule.Types.First(x => x.Name == "MetadataOffsetAttribute").Methods[0];
            stringType = il2CppDummyDll.MainModule.TypeSystem.String;

            var resolver = new MyAssemblyResolver();
            var moduleParameters = new ModuleParameters
            {
                Kind = ModuleKind.Dll,
                AssemblyResolver = resolver
            };
            resolver.Register(il2CppDummyDll);

            var fieldDefinitionDic = new Dictionary<int, FieldDefinition>();
            var methodDefinitionDic = new Dictionary<int, MethodDefinition>();
            var parameterDefinitionDic = new Dictionary<int, ParameterDefinition>();
            var propertyDefinitionDic = new Dictionary<int, PropertyDefinition>();
            var eventDefinitionDic = new Dictionary<int, EventDefinition>();

            //创建程序集，同时创建所有类
            foreach (var imageDef in metadata.imageDefs)
            {
                var imageName = metadata.GetStringFromIndex(imageDef.nameIndex);
                var assemblyName = new AssemblyNameDefinition(imageName.Replace(".dll", ""), new Version("3.7.1.6"));
                var assemblyDefinition = AssemblyDefinition.CreateAssembly(assemblyName, imageName, moduleParameters);
                resolver.Register(assemblyDefinition);
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
            for (var index = 0; index < metadata.typeDefs.Length; ++index)
            {
                var typeDef = metadata.typeDefs[index];
                var typeDefinition = typeDefinitionDic[index];
                //parent
                if (typeDef.parentIndex >= 0)
                {
                    var parentType = il2Cpp.types[typeDef.parentIndex];
                    var parentTypeRef = GetTypeReference(typeDefinition, parentType);
                    typeDefinition.BaseType = parentTypeRef;
                }
                //interfaces
                for (int i = 0; i < typeDef.interfaces_count; i++)
                {
                    var interfaceType = il2Cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                    var interfaceTypeRef = GetTypeReference(typeDefinition, interfaceType);
                    typeDefinition.Interfaces.Add(new InterfaceImplementation(interfaceTypeRef));
                }
            }
            //处理field, method, property等等
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                var typeEnd = imageDef.typeStart + imageDef.typeCount;
                for (int index = imageDef.typeStart; index < typeEnd; index++)
                {
                    var typeDef = metadata.typeDefs[index];
                    var typeDefinition = typeDefinitionDic[index];

                    //field
                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                    for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                    {
                        var fieldDef = metadata.fieldDefs[i];
                        var fieldType = il2Cpp.types[fieldDef.typeIndex];
                        var fieldName = metadata.GetStringFromIndex(fieldDef.nameIndex);
                        var fieldTypeRef = GetTypeReference(typeDefinition, fieldType);
                        var fieldDefinition = new FieldDefinition(fieldName, (FieldAttributes)fieldType.attrs, fieldTypeRef);
                        typeDefinition.Fields.Add(fieldDefinition);
                        fieldDefinitionDic.Add(i, fieldDefinition);
                        //fieldDefault
                        if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefault) && fieldDefault.dataIndex != -1)
                        {
                            if (TryGetDefaultValue(fieldDefault.typeIndex, fieldDefault.dataIndex, out var value))
                            {
                                fieldDefinition.Constant = value;
                            }
                            else
                            {
                                var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                customAttribute.Fields.Add(offset);
                                fieldDefinition.CustomAttributes.Add(customAttribute);
                            }
                        }
                        //fieldOffset
                        var fieldOffset = il2Cpp.GetFieldOffsetFromIndex(index, i - typeDef.fieldStart, i, typeDefinition.IsValueType, fieldDefinition.IsStatic);
                        if (fieldOffset >= 0)
                        {
                            var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(fieldOffsetAttribute));
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
                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                        var methodDefinition = new MethodDefinition(methodName, (MethodAttributes)methodDef.flags, typeDefinition.Module.ImportReference(typeof(void)));
                        methodDefinition.ImplAttributes = (MethodImplAttributes)methodDef.iflags;
                        typeDefinition.Methods.Add(methodDefinition);
                        var methodReturnType = il2Cpp.types[methodDef.returnType];
                        var returnType = GetTypeReferenceWithByRef(methodDefinition, methodReturnType);
                        methodDefinition.ReturnType = returnType;
                        if (methodDefinition.HasBody && typeDefinition.BaseType?.FullName != "System.MulticastDelegate")
                        {
                            var ilprocessor = methodDefinition.Body.GetILProcessor();
                            if (returnType.FullName == "System.Void")
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else if (returnType.IsValueType)
                            {
                                var variable = new VariableDefinition(returnType);
                                methodDefinition.Body.Variables.Add(variable);
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloca_S, variable));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Initobj, returnType));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldloc_0));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                            else
                            {
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ldnull));
                                ilprocessor.Append(ilprocessor.Create(OpCodes.Ret));
                            }
                        }
                        methodDefinitionDic.Add(i, methodDefinition);
                        //method parameter
                        for (var j = 0; j < methodDef.parameterCount; ++j)
                        {
                            var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                            var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                            var parameterType = il2Cpp.types[parameterDef.typeIndex];
                            var parameterTypeRef = GetTypeReferenceWithByRef(methodDefinition, parameterType);
                            var parameterDefinition = new ParameterDefinition(parameterName, (ParameterAttributes)parameterType.attrs, parameterTypeRef);
                            methodDefinition.Parameters.Add(parameterDefinition);
                            parameterDefinitionDic.Add(methodDef.parameterStart + j, parameterDefinition);
                            //ParameterDefault
                            if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault) && parameterDefault.dataIndex != -1)
                            {
                                if (TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                {
                                    parameterDefinition.Constant = value;
                                }
                                else
                                {
                                    var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(metadataOffsetAttribute));
                                    var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{value:X}"));
                                    customAttribute.Fields.Add(offset);
                                    parameterDefinition.CustomAttributes.Add(customAttribute);
                                }
                            }
                        }
                        //补充泛型参数
                        if (methodDef.genericContainerIndex >= 0)
                        {
                            var genericContainer = metadata.genericContainers[methodDef.genericContainerIndex];
                            if (genericContainer.type_argc > methodDefinition.GenericParameters.Count)
                            {
                                for (int j = 0; j < genericContainer.type_argc; j++)
                                {
                                    var genericParameterIndex = genericContainer.genericParameterStart + j;
                                    if (!genericParameterDic.TryGetValue(genericParameterIndex, out var genericParameter))
                                    {
                                        CreateGenericParameter(genericParameterIndex, methodDefinition);
                                    }
                                    else
                                    {
                                        if (!methodDefinition.GenericParameters.Contains(genericParameter))
                                        {
                                            methodDefinition.GenericParameters.Add(genericParameter);
                                        }
                                    }
                                }
                            }
                        }
                        //methodAddress
                        var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                        if (methodPointer > 0)
                        {
                            var customAttribute = new CustomAttribute(typeDefinition.Module.ImportReference(addressAttribute));
                            var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                            var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{fixedMethodPointer:X}"));
                            var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2Cpp.MapVATR(methodPointer):X}"));
                            var va = new CustomAttributeNamedArgument("VA", new CustomAttributeArgument(stringType, $"0x{methodPointer:X}"));
                            customAttribute.Fields.Add(rva);
                            customAttribute.Fields.Add(offset);
                            customAttribute.Fields.Add(va);
                            if (methodDef.slot != ushort.MaxValue)
                            {
                                var slot = new CustomAttributeNamedArgument("Slot", new CustomAttributeArgument(stringType, methodDef.slot.ToString()));
                                customAttribute.Fields.Add(slot);
                            }
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
                        propertyDefinitionDic.Add(i, propertyDefinition);
                    }
                    //event
                    var eventEnd = typeDef.eventStart + typeDef.event_count;
                    for (var i = typeDef.eventStart; i < eventEnd; ++i)
                    {
                        var eventDef = metadata.eventDefs[i];
                        var eventName = metadata.GetStringFromIndex(eventDef.nameIndex);
                        var eventType = il2Cpp.types[eventDef.typeIndex];
                        var eventTypeRef = GetTypeReference(typeDefinition, eventType);
                        var eventDefinition = new EventDefinition(eventName, (EventAttributes)eventType.attrs, eventTypeRef);
                        if (eventDef.add >= 0)
                            eventDefinition.AddMethod = methodDefinitionDic[typeDef.methodStart + eventDef.add];
                        if (eventDef.remove >= 0)
                            eventDefinition.RemoveMethod = methodDefinitionDic[typeDef.methodStart + eventDef.remove];
                        if (eventDef.raise >= 0)
                            eventDefinition.InvokeMethod = methodDefinitionDic[typeDef.methodStart + eventDef.raise];
                        typeDefinition.Events.Add(eventDefinition);
                        eventDefinitionDic.Add(i, eventDefinition);
                    }
                    //补充泛型参数
                    if (typeDef.genericContainerIndex >= 0)
                    {
                        var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                        if (genericContainer.type_argc > typeDefinition.GenericParameters.Count)
                        {
                            for (int i = 0; i < genericContainer.type_argc; i++)
                            {
                                var genericParameterIndex = genericContainer.genericParameterStart + i;
                                if (!genericParameterDic.TryGetValue(genericParameterIndex, out var genericParameter))
                                {
                                    CreateGenericParameter(genericParameterIndex, typeDefinition);
                                }
                                else
                                {
                                    if (!typeDefinition.GenericParameters.Contains(genericParameter))
                                    {
                                        typeDefinition.GenericParameters.Add(genericParameter);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            //第三遍，添加CustomAttribute
            if (il2Cpp.Version > 20)
            {
                PrepareCustomAttribute();
                foreach (var imageDef in metadata.imageDefs)
                {
                    var typeEnd = imageDef.typeStart + imageDef.typeCount;
                    for (int index = imageDef.typeStart; index < typeEnd; index++)
                    {
                        var typeDef = metadata.typeDefs[index];
                        var typeDefinition = typeDefinitionDic[index];
                        //typeAttribute
                        CreateCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token, typeDefinition.Module, typeDefinition.CustomAttributes);

                        //field
                        var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                        for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                        {
                            var fieldDef = metadata.fieldDefs[i];
                            var fieldDefinition = fieldDefinitionDic[i];
                            //fieldAttribute
                            CreateCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, typeDefinition.Module, fieldDefinition.CustomAttributes);
                        }

                        //method
                        var methodEnd = typeDef.methodStart + typeDef.method_count;
                        for (var i = typeDef.methodStart; i < methodEnd; ++i)
                        {
                            var methodDef = metadata.methodDefs[i];
                            var methodDefinition = methodDefinitionDic[i];
                            //methodAttribute
                            CreateCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, typeDefinition.Module, methodDefinition.CustomAttributes);

                            //method parameter
                            for (var j = 0; j < methodDef.parameterCount; ++j)
                            {
                                var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                var parameterDefinition = parameterDefinitionDic[methodDef.parameterStart + j];
                                //parameterAttribute
                                CreateCustomAttribute(imageDef, parameterDef.customAttributeIndex, parameterDef.token, typeDefinition.Module, parameterDefinition.CustomAttributes);
                            }
                        }

                        //property
                        var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                        for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                        {
                            var propertyDef = metadata.propertyDefs[i];
                            var propertyDefinition = propertyDefinitionDic[i];
                            //propertyAttribute
                            CreateCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, typeDefinition.Module, propertyDefinition.CustomAttributes);
                        }

                        //event
                        var eventEnd = typeDef.eventStart + typeDef.event_count;
                        for (var i = typeDef.eventStart; i < eventEnd; ++i)
                        {
                            var eventDef = metadata.eventDefs[i];
                            var eventDefinition = eventDefinitionDic[i];
                            //eventAttribute
                            CreateCustomAttribute(imageDef, eventDef.customAttributeIndex, eventDef.token, typeDefinition.Module, eventDefinition.CustomAttributes);
                        }
                    }
                }
            }
        }

        private TypeReference GetTypeReferenceWithByRef(MemberReference memberReference, Il2CppType il2CppType)
        {
            var typeReference = GetTypeReference(memberReference, il2CppType);
            if (il2CppType.byref == 1)
            {
                return new ByReferenceType(typeReference);
            }
            else
            {
                return typeReference;
            }
        }

        private TypeReference GetTypeReference(MemberReference memberReference, Il2CppType il2CppType)
        {
            var moduleDefinition = memberReference.Module;
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_OBJECT:
                    return moduleDefinition.ImportReference(typeof(object));
                case Il2CppTypeEnum.IL2CPP_TYPE_VOID:
                    return moduleDefinition.ImportReference(typeof(void));
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    return moduleDefinition.ImportReference(typeof(bool));
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    return moduleDefinition.ImportReference(typeof(char));
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    return moduleDefinition.ImportReference(typeof(sbyte));
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    return moduleDefinition.ImportReference(typeof(byte));
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    return moduleDefinition.ImportReference(typeof(short));
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    return moduleDefinition.ImportReference(typeof(ushort));
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    return moduleDefinition.ImportReference(typeof(int));
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    return moduleDefinition.ImportReference(typeof(uint));
                case Il2CppTypeEnum.IL2CPP_TYPE_I:
                    return moduleDefinition.ImportReference(typeof(IntPtr));
                case Il2CppTypeEnum.IL2CPP_TYPE_U:
                    return moduleDefinition.ImportReference(typeof(UIntPtr));
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    return moduleDefinition.ImportReference(typeof(long));
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    return moduleDefinition.ImportReference(typeof(ulong));
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    return moduleDefinition.ImportReference(typeof(float));
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    return moduleDefinition.ImportReference(typeof(double));
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    return moduleDefinition.ImportReference(typeof(string));
                case Il2CppTypeEnum.IL2CPP_TYPE_TYPEDBYREF:
                    return moduleDefinition.ImportReference(typeof(TypedReference));
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDefinition = typeDefinitionDic[il2CppType.data.klassIndex];
                        return moduleDefinition.ImportReference(typeDefinition);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var oriType = il2Cpp.GetIl2CppType(arrayType.etype);
                        return new ArrayType(GetTypeReference(memberReference, oriType), arrayType.rank);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                        var typeDefinition = typeDefinitionDic[genericClass.typeDefinitionIndex];
                        var genericInstanceType = new GenericInstanceType(moduleDefinition.ImportReference(typeDefinition));
                        var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(genericClass.context.class_inst);
                        var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
                        foreach (var pointer in pointers)
                        {
                            var oriType = il2Cpp.GetIl2CppType(pointer);
                            genericInstanceType.GenericArguments.Add(GetTypeReference(memberReference, oriType));
                        }
                        return genericInstanceType;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        return new ArrayType(GetTypeReference(memberReference, oriType));
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                    {
                        if (genericParameterDic.TryGetValue(il2CppType.data.genericParameterIndex, out var genericParameter))
                        {
                            return genericParameter;
                        }
                        if (memberReference is MethodDefinition methodDefinition)
                        {
                            return CreateGenericParameter(il2CppType.data.genericParameterIndex, methodDefinition.DeclaringType);
                        }
                        var typeDefinition = (TypeDefinition)memberReference;
                        return CreateGenericParameter(il2CppType.data.genericParameterIndex, typeDefinition);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        if (genericParameterDic.TryGetValue(il2CppType.data.genericParameterIndex, out var genericParameter))
                        {
                            return genericParameter;
                        }
                        var methodDefinition = (MethodDefinition)memberReference;
                        return CreateGenericParameter(il2CppType.data.genericParameterIndex, methodDefinition);
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        return new PointerType(GetTypeReference(memberReference, oriType));
                    }
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private bool TryGetDefaultValue(int typeIndex, int dataIndex, out object value)
        {
            var pointer = metadata.GetDefaultValueFromIndex(dataIndex);
            var defaultValueType = il2Cpp.types[typeIndex];
            metadata.Position = pointer;
            switch (defaultValueType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                    value = metadata.ReadBoolean();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                    value = metadata.ReadByte();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                    value = metadata.ReadSByte();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                    value = BitConverter.ToChar(metadata.ReadBytes(2), 0);
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                    value = metadata.ReadUInt16();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                    value = metadata.ReadInt16();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                    value = metadata.ReadUInt32();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                    value = metadata.ReadInt32();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                    value = metadata.ReadUInt64();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                    value = metadata.ReadInt64();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                    value = metadata.ReadSingle();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                    value = metadata.ReadDouble();
                    return true;
                case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                    var len = metadata.ReadInt32();
                    value = Encoding.UTF8.GetString(metadata.ReadBytes(len));
                    return true;
                default:
                    value = pointer;
                    return false;
            }
        }

        private void PrepareCustomAttribute()
        {
            foreach (var attributeName in knownAttributeNames)
            {
                foreach (var assemblyDefinition in Assemblies)
                {
                    var attributeType = assemblyDefinition.MainModule.GetType(attributeName);
                    if (attributeType != null)
                    {
                        knownAttributes.Add(attributeName, attributeType.Methods.First(x => x.Name == ".ctor"));
                        break;
                    }
                }
            }
        }

        private void CreateCustomAttribute(Il2CppImageDefinition imageDef, int customAttributeIndex, uint token, ModuleDefinition moduleDefinition, Collection<CustomAttribute> customAttributes)
        {
            var attributeIndex = metadata.GetCustomAttributeIndex(imageDef, customAttributeIndex, token);
            if (attributeIndex >= 0)
            {
                var attributeTypeRange = metadata.attributeTypeRanges[attributeIndex];
                for (int i = 0; i < attributeTypeRange.count; i++)
                {
                    var attributeTypeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                    var attributeType = il2Cpp.types[attributeTypeIndex];
                    var typeDefinition = typeDefinitionDic[attributeType.data.klassIndex];
                    if (knownAttributes.TryGetValue(typeDefinition.FullName, out var methodDefinition))
                    {
                        var customAttribute = new CustomAttribute(moduleDefinition.ImportReference(methodDefinition));
                        customAttributes.Add(customAttribute);
                    }
                    else
                    {
                        var methodPointer = il2Cpp.customAttributeGenerators[attributeIndex];
                        var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                        var customAttribute = new CustomAttribute(moduleDefinition.ImportReference(attributeAttribute));
                        var name = new CustomAttributeNamedArgument("Name", new CustomAttributeArgument(stringType, typeDefinition.Name));
                        var rva = new CustomAttributeNamedArgument("RVA", new CustomAttributeArgument(stringType, $"0x{fixedMethodPointer:X}"));
                        var offset = new CustomAttributeNamedArgument("Offset", new CustomAttributeArgument(stringType, $"0x{il2Cpp.MapVATR(methodPointer):X}"));
                        customAttribute.Fields.Add(name);
                        customAttribute.Fields.Add(rva);
                        customAttribute.Fields.Add(offset);
                        customAttributes.Add(customAttribute);
                    }
                }
            }
        }

        private GenericParameter CreateGenericParameter(long genericParameterIndex, IGenericParameterProvider iGenericParameterProvider)
        {
            var param = metadata.genericParameters[genericParameterIndex];
            var genericName = metadata.GetStringFromIndex(param.nameIndex);
            var genericParameter = new GenericParameter(genericName, iGenericParameterProvider);
            genericParameter.Attributes = (GenericParameterAttributes)param.flags;
            iGenericParameterProvider.GenericParameters.Add(genericParameter);
            genericParameterDic.Add(genericParameterIndex, genericParameter);
            for (int i = 0; i < param.constraintsCount; ++i)
            {
                var il2CppType = il2Cpp.types[metadata.constraintIndices[param.constraintsStart + i]];
                genericParameter.Constraints.Add(new GenericParameterConstraint(GetTypeReference((MemberReference)iGenericParameterProvider, il2CppType)));
            }
            return genericParameter;
        }

        private static readonly string[] knownAttributeNames = new[]
        {
            //"System.Runtime.CompilerServices.CompilerGeneratedAttribute",
            "System.Runtime.CompilerServices.ExtensionAttribute",
            "System.Runtime.CompilerServices.NullableAttribute",
            "System.Runtime.CompilerServices.NullableContextAttribute",
            "System.Runtime.CompilerServices.IsReadOnlyAttribute", //in关键字
            "System.Diagnostics.DebuggerHiddenAttribute",
            "System.Diagnostics.DebuggerStepThroughAttribute",
            // Type attributes:
            "System.FlagsAttribute",
            "System.Runtime.CompilerServices.IsByRefLikeAttribute",
            // Field attributes:
            "System.NonSerializedAttribute",
            // Method attributes:
            "System.Runtime.InteropServices.PreserveSigAttribute",
            // Parameter attributes:
            "System.ParamArrayAttribute",
            "System.Runtime.CompilerServices.CallerMemberNameAttribute",
            "System.Runtime.CompilerServices.CallerFilePathAttribute",
            "System.Runtime.CompilerServices.CallerLineNumberAttribute",
            // Type parameter attributes:
            "System.Runtime.CompilerServices.IsUnmanagedAttribute",
            // Unity
            "UnityEngine.SerializeField" //MonoBehaviour的反序列化
        };
    }
}
