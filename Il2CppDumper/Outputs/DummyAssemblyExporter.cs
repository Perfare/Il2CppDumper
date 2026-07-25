using System.IO;

using Mono.Cecil;
using System.Collections.Generic;

namespace Il2CppDumper
{
    public static class DummyAssemblyExporter
    {
        public static void Export(Il2CppExecutor il2CppExecutor, string outputDir, bool addToken)
        {
            Directory.SetCurrentDirectory(outputDir);
            if (Directory.Exists("DummyDll"))
                Directory.Delete("DummyDll", true);
            Directory.CreateDirectory("DummyDll");
            Directory.SetCurrentDirectory("DummyDll");
            var dummy = new DummyAssemblyGenerator(il2CppExecutor, addToken);
            foreach (var assembly in dummy.Assemblies)
            {
                SanitizeConstants(assembly);
                SanitizeMemberReferences(assembly);
                SanitizeCustomAttributes(assembly);
                File.WriteAllBytes(assembly.MainModule.Name, WriteAssembly(assembly));
            }
        }

        private static byte[] WriteAssembly(AssemblyDefinition assembly)
        {
            try
            {
                return WriteAssemblyToBytes(assembly);
            }
            catch (System.Exception ex) when (IsCustomAttributeWriteException(ex))
            {
                StripRestoredCustomAttributes(assembly);
                return WriteAssemblyToBytes(assembly);
            }
        }

        private static byte[] WriteAssemblyToBytes(AssemblyDefinition assembly)
        {
            using var stream = new MemoryStream();
            assembly.Write(stream);
            return stream.ToArray();
        }

        private static bool IsCustomAttributeWriteException(System.Exception ex)
        {
            return ex.StackTrace?.Contains("WriteCustomAttribute") == true
                || ex.StackTrace?.Contains("GetCustomAttributeSignature") == true
                || ex.StackTrace?.Contains("AddCustomAttributes") == true;
        }

        private static void StripRestoredCustomAttributes(AssemblyDefinition assembly)
        {
            var module = assembly.MainModule;
            StripCustomAttributes(assembly.CustomAttributes);
            StripCustomAttributes(module.CustomAttributes);
            foreach (var type in GetAllTypes(module.Types))
            {
                StripCustomAttributes(type.CustomAttributes);
                foreach (var genericParameter in type.GenericParameters)
                {
                    StripCustomAttributes(genericParameter.CustomAttributes);
                    foreach (var constraint in genericParameter.Constraints)
                    {
                        StripCustomAttributes(constraint.CustomAttributes);
                    }
                }
                foreach (var field in type.Fields)
                {
                    StripCustomAttributes(field.CustomAttributes);
                }
                foreach (var method in type.Methods)
                {
                    StripCustomAttributes(method.CustomAttributes);
                    StripCustomAttributes(method.MethodReturnType.CustomAttributes);
                    foreach (var genericParameter in method.GenericParameters)
                    {
                        StripCustomAttributes(genericParameter.CustomAttributes);
                        foreach (var constraint in genericParameter.Constraints)
                        {
                            StripCustomAttributes(constraint.CustomAttributes);
                        }
                    }
                    foreach (var parameter in method.Parameters)
                    {
                        StripCustomAttributes(parameter.CustomAttributes);
                    }
                }
                foreach (var property in type.Properties)
                {
                    StripCustomAttributes(property.CustomAttributes);
                }
                foreach (var @event in type.Events)
                {
                    StripCustomAttributes(@event.CustomAttributes);
                }
            }
        }

        private static void StripCustomAttributes(Mono.Collections.Generic.Collection<CustomAttribute> customAttributes)
        {
            for (var i = customAttributes.Count - 1; i >= 0; i--)
            {
                if (!IsIl2CppDumperAttribute(customAttributes[i]))
                {
                    customAttributes.RemoveAt(i);
                }
            }
        }

        private static bool IsIl2CppDumperAttribute(CustomAttribute customAttribute)
        {
            var declaringType = customAttribute.Constructor?.DeclaringType;
            return declaringType?.Namespace == "Il2CppDummyDll"
                || declaringType?.Scope?.Name == "Il2CppDummyDll.dll";
        }

        private static void SanitizeMemberReferences(AssemblyDefinition assembly)
        {
            var module = assembly.MainModule;
            foreach (var type in GetAllTypes(module.Types))
            {
                type.BaseType = ImportTypeReference(module, type.BaseType);
                SanitizeGenericParameters(module, type.GenericParameters);
                foreach (var @interface in type.Interfaces)
                {
                    @interface.InterfaceType = ImportTypeReference(module, @interface.InterfaceType);
                }
                foreach (var field in type.Fields)
                {
                    field.FieldType = ImportTypeReference(module, field.FieldType);
                }
                foreach (var method in type.Methods)
                {
                    method.ReturnType = ImportTypeReference(module, method.ReturnType);
                    SanitizeGenericParameters(module, method.GenericParameters);
                    for (var i = 0; i < method.Overrides.Count; i++)
                    {
                        method.Overrides[i] = ImportMethodReference(module, method.Overrides[i]);
                    }
                    foreach (var parameter in method.Parameters)
                    {
                        parameter.ParameterType = ImportTypeReference(module, parameter.ParameterType);
                    }
                    if (method.HasBody)
                    {
                        foreach (var variable in method.Body.Variables)
                        {
                            variable.VariableType = ImportTypeReference(module, variable.VariableType);
                        }
                        foreach (var instruction in method.Body.Instructions)
                        {
                            switch (instruction.Operand)
                            {
                                case TypeReference typeReference:
                                    instruction.Operand = ImportTypeReference(module, typeReference);
                                    break;
                                case MethodReference methodReference:
                                    instruction.Operand = ImportMethodReference(module, methodReference);
                                    break;
                                case FieldReference fieldReference:
                                    instruction.Operand = ImportFieldReference(module, fieldReference);
                                    break;
                                case CallSite callSite:
                                    SanitizeCallSite(module, callSite);
                                    break;
                            }
                        }
                    }
                }
                foreach (var property in type.Properties)
                {
                    property.PropertyType = ImportTypeReference(module, property.PropertyType);
                    foreach (var parameter in property.Parameters)
                    {
                        parameter.ParameterType = ImportTypeReference(module, parameter.ParameterType);
                    }
                }
                foreach (var @event in type.Events)
                {
                    @event.EventType = ImportTypeReference(module, @event.EventType);
                }
            }
        }

        private static void SanitizeGenericParameters(ModuleDefinition module, Mono.Collections.Generic.Collection<GenericParameter> genericParameters)
        {
            foreach (var genericParameter in genericParameters)
            {
                ImportCustomAttributes(module, genericParameter.CustomAttributes);
                foreach (var constraint in genericParameter.Constraints)
                {
                    constraint.ConstraintType = ImportTypeReference(module, constraint.ConstraintType);
                    ImportCustomAttributes(module, constraint.CustomAttributes);
                }
            }
        }

        private static void SanitizeCallSite(ModuleDefinition module, CallSite callSite)
        {
            callSite.ReturnType = ImportTypeReference(module, callSite.ReturnType);
            foreach (var parameter in callSite.Parameters)
            {
                parameter.ParameterType = ImportTypeReference(module, parameter.ParameterType);
            }
        }

        private static void SanitizeCustomAttributes(AssemblyDefinition assembly)
        {
            var module = assembly.MainModule;
            ImportCustomAttributes(module, assembly.CustomAttributes);
            ImportCustomAttributes(module, module.CustomAttributes);
            foreach (var type in GetAllTypes(module.Types))
            {
                ImportCustomAttributes(module, type.CustomAttributes);
                SanitizeGenericParameters(module, type.GenericParameters);
                foreach (var field in type.Fields)
                {
                    ImportCustomAttributes(module, field.CustomAttributes);
                }
                foreach (var method in type.Methods)
                {
                    ImportCustomAttributes(module, method.CustomAttributes);
                    ImportCustomAttributes(module, method.MethodReturnType.CustomAttributes);
                    SanitizeGenericParameters(module, method.GenericParameters);
                    foreach (var parameter in method.Parameters)
                    {
                        ImportCustomAttributes(module, parameter.CustomAttributes);
                    }
                }
                foreach (var property in type.Properties)
                {
                    ImportCustomAttributes(module, property.CustomAttributes);
                }
                foreach (var @event in type.Events)
                {
                    ImportCustomAttributes(module, @event.CustomAttributes);
                }
            }
        }

        private static void ImportCustomAttributes(ModuleDefinition module, Mono.Collections.Generic.Collection<CustomAttribute> customAttributes)
        {
            if (module == null)
            {
                return;
            }
            for (var attributeIndex = customAttributes.Count - 1; attributeIndex >= 0; attributeIndex--)
            {
                var customAttribute = customAttributes[attributeIndex];
                try
                {
                    if (customAttribute.Constructor != null)
                    {
                        customAttribute.Constructor = ImportMethodReference(module, customAttribute.Constructor);
                    }
                    for (var i = 0; i < customAttribute.ConstructorArguments.Count; i++)
                    {
                        customAttribute.ConstructorArguments[i] = ImportCustomAttributeArgument(module, customAttribute.ConstructorArguments[i]);
                    }
                    for (var i = 0; i < customAttribute.Fields.Count; i++)
                    {
                        var field = customAttribute.Fields[i];
                        customAttribute.Fields[i] = new CustomAttributeNamedArgument(field.Name, ImportCustomAttributeArgument(module, field.Argument));
                    }
                    for (var i = 0; i < customAttribute.Properties.Count; i++)
                    {
                        var property = customAttribute.Properties[i];
                        customAttribute.Properties[i] = new CustomAttributeNamedArgument(property.Name, ImportCustomAttributeArgument(module, property.Argument));
                    }
                }
                catch
                {
                    customAttributes.RemoveAt(attributeIndex);
                }
            }
        }

        private static CustomAttributeArgument ImportCustomAttributeArgument(ModuleDefinition module, CustomAttributeArgument argument)
        {
            var type = ImportTypeReference(module, argument.Type);
            var value = argument.Value;
            switch (value)
            {
                case TypeReference typeReference:
                    value = ImportTypeReference(module, typeReference);
                    break;
                case CustomAttributeArgument customAttributeArgument:
                    value = ImportCustomAttributeArgument(module, customAttributeArgument);
                    break;
                case CustomAttributeArgument[] customAttributeArguments:
                    var importedArguments = new CustomAttributeArgument[customAttributeArguments.Length];
                    for (var i = 0; i < customAttributeArguments.Length; i++)
                    {
                        importedArguments[i] = ImportCustomAttributeArgument(module, customAttributeArguments[i]);
                    }
                    value = importedArguments;
                    break;
            }
            value = NormalizeCustomAttributeValue(type, value);
            return new CustomAttributeArgument(type, value);
        }

        private static object NormalizeCustomAttributeValue(TypeReference type, object value)
        {
            if (TryGetEnumUnderlyingType(type, out var underlyingType))
            {
                return ConvertEnumValue(underlyingType, value);
            }
            return value;
        }

        private static bool TryGetEnumUnderlyingType(TypeReference type, out TypeReference underlyingType)
        {
            underlyingType = null;
            if (type == null)
            {
                return false;
            }
            TypeDefinition typeDefinition;
            try
            {
                typeDefinition = type as TypeDefinition ?? type.Resolve();
            }
            catch
            {
                return false;
            }
            if (typeDefinition == null || !typeDefinition.IsEnum)
            {
                return false;
            }
            foreach (var field in typeDefinition.Fields)
            {
                if (field.Name == "value__")
                {
                    underlyingType = field.FieldType;
                    return underlyingType != null;
                }
            }
            return false;
        }

        private static object ConvertEnumValue(TypeReference underlyingType, object value)
        {
            if (value == null)
            {
                throw new System.InvalidOperationException("Enum custom attribute value cannot be null.");
            }
            return underlyingType.MetadataType switch
            {
                MetadataType.SByte => System.Convert.ToSByte(value),
                MetadataType.Byte => System.Convert.ToByte(value),
                MetadataType.Int16 => System.Convert.ToInt16(value),
                MetadataType.UInt16 => System.Convert.ToUInt16(value),
                MetadataType.Int32 => System.Convert.ToInt32(value),
                MetadataType.UInt32 => System.Convert.ToUInt32(value),
                MetadataType.Int64 => System.Convert.ToInt64(value),
                MetadataType.UInt64 => System.Convert.ToUInt64(value),
                _ => throw new System.InvalidOperationException($"Unsupported enum underlying type: {underlyingType.FullName}")
            };
        }

        private static TypeReference ImportTypeReference(ModuleDefinition module, TypeReference typeReference)
        {
            if (typeReference == null || typeReference.IsGenericParameter)
            {
                return typeReference;
            }
            switch (typeReference)
            {
                case GenericInstanceType genericInstanceType:
                    var importedGenericInstanceType = new GenericInstanceType(ImportTypeReference(module, genericInstanceType.ElementType));
                    CopyIsValueType(importedGenericInstanceType, genericInstanceType);
                    foreach (var genericArgument in genericInstanceType.GenericArguments)
                    {
                        importedGenericInstanceType.GenericArguments.Add(ImportTypeReference(module, genericArgument));
                    }
                    return importedGenericInstanceType;
                case ArrayType arrayType:
                    var importedArrayType = new ArrayType(ImportTypeReference(module, arrayType.ElementType), arrayType.Rank);
                    CopyIsValueType(importedArrayType, arrayType);
                    importedArrayType.Dimensions.Clear();
                    foreach (var dimension in arrayType.Dimensions)
                    {
                        importedArrayType.Dimensions.Add(new ArrayDimension(dimension.LowerBound, dimension.UpperBound));
                    }
                    return importedArrayType;
                case ByReferenceType byReferenceType:
                    var importedByReferenceType = new ByReferenceType(ImportTypeReference(module, byReferenceType.ElementType));
                    CopyIsValueType(importedByReferenceType, byReferenceType);
                    return importedByReferenceType;
                case PointerType pointerType:
                    var importedPointerType = new PointerType(ImportTypeReference(module, pointerType.ElementType));
                    CopyIsValueType(importedPointerType, pointerType);
                    return importedPointerType;
                case PinnedType pinnedType:
                    var importedPinnedType = new PinnedType(ImportTypeReference(module, pinnedType.ElementType));
                    CopyIsValueType(importedPinnedType, pinnedType);
                    return importedPinnedType;
                case OptionalModifierType optionalModifierType:
                    var importedOptionalModifierType = new OptionalModifierType(
                        ImportTypeReference(module, optionalModifierType.ModifierType),
                        ImportTypeReference(module, optionalModifierType.ElementType));
                    CopyIsValueType(importedOptionalModifierType, optionalModifierType);
                    return importedOptionalModifierType;
                case RequiredModifierType requiredModifierType:
                    var importedRequiredModifierType = new RequiredModifierType(
                        ImportTypeReference(module, requiredModifierType.ModifierType),
                        ImportTypeReference(module, requiredModifierType.ElementType));
                    CopyIsValueType(importedRequiredModifierType, requiredModifierType);
                    return importedRequiredModifierType;
                case SentinelType sentinelType:
                    var importedSentinelType = new SentinelType(ImportTypeReference(module, sentinelType.ElementType));
                    CopyIsValueType(importedSentinelType, sentinelType);
                    return importedSentinelType;
                case FunctionPointerType functionPointerType:
                    var importedFunctionPointerType = new FunctionPointerType
                    {
                        HasThis = functionPointerType.HasThis,
                        ExplicitThis = functionPointerType.ExplicitThis,
                        CallingConvention = functionPointerType.CallingConvention,
                        ReturnType = ImportTypeReference(module, functionPointerType.ReturnType)
                    };
                    CopyIsValueType(importedFunctionPointerType, functionPointerType);
                    foreach (var parameter in functionPointerType.Parameters)
                    {
                        importedFunctionPointerType.Parameters.Add(new ParameterDefinition(
                            parameter.Name,
                            parameter.Attributes,
                            ImportTypeReference(module, parameter.ParameterType)));
                    }
                    return importedFunctionPointerType;
            }
            return typeReference.Module == module ? typeReference : module.ImportReference(typeReference);
        }

        private static void CopyIsValueType(TypeReference target, TypeReference source)
        {
            try
            {
                target.IsValueType = source.IsValueType;
            }
            catch (System.InvalidOperationException)
            {
            }
            catch (System.NotSupportedException)
            {
            }
        }

        private static MethodReference ImportMethodReference(ModuleDefinition module, MethodReference methodReference)
        {
            if (methodReference == null)
            {
                return null;
            }
            return methodReference.Module == module && (methodReference.DeclaringType == null || methodReference.DeclaringType.Module == module)
                ? methodReference
                : module.ImportReference(methodReference);
        }

        private static FieldReference ImportFieldReference(ModuleDefinition module, FieldReference fieldReference)
        {
            if (fieldReference == null)
            {
                return null;
            }
            return fieldReference.Module == module && (fieldReference.DeclaringType == null || fieldReference.DeclaringType.Module == module)
                ? fieldReference
                : module.ImportReference(fieldReference);
        }

        private static void SanitizeConstants(AssemblyDefinition assembly)
        {
            foreach (var type in GetAllTypes(assembly.MainModule.Types))
            {
                foreach (var field in type.Fields)
                {
                    if (field.HasConstant && !CanWriteConstant(field.FieldType))
                    {
                        field.HasConstant = false;
                        field.Constant = null;
                    }
                }
                foreach (var method in type.Methods)
                {
                    foreach (var parameter in method.Parameters)
                    {
                        if (parameter.HasConstant && !CanWriteConstant(parameter.ParameterType))
                        {
                            parameter.HasConstant = false;
                            parameter.Constant = null;
                        }
                    }
                }
            }
        }

        private static IEnumerable<TypeDefinition> GetAllTypes(IEnumerable<TypeDefinition> types)
        {
            foreach (var type in types)
            {
                yield return type;
                foreach (var nestedType in GetAllTypes(type.NestedTypes))
                {
                    yield return nestedType;
                }
            }
        }

        private static bool CanWriteConstant(TypeReference typeReference)
        {
            return typeReference?.FullName is "System.Boolean"
                or "System.Char"
                or "System.SByte"
                or "System.Byte"
                or "System.Int16"
                or "System.UInt16"
                or "System.Int32"
                or "System.UInt32"
                or "System.Int64"
                or "System.UInt64"
                or "System.Single"
                or "System.Double"
                or "System.String";
        }
    }
}
