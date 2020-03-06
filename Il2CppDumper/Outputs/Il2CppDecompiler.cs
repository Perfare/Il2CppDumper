using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using static Il2CppDumper.Il2CppConstants;

namespace Il2CppDumper
{
    public class Il2CppDecompiler
    {
        private Il2CppExecutor executor;
        private Metadata metadata;
        private Il2Cpp il2Cpp;
        private Dictionary<Il2CppMethodDefinition, string> methodModifiers = new Dictionary<Il2CppMethodDefinition, string>();

        public Il2CppDecompiler(Il2CppExecutor il2CppExecutor)
        {
            executor = il2CppExecutor;
            metadata = il2CppExecutor.metadata;
            il2Cpp = il2CppExecutor.il2Cpp;
        }

        public void Decompile(Config config)
        {
            var writer = new StreamWriter(new FileStream("dump.cs", FileMode.Create), new UTF8Encoding(false));
            //dump image
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                var imageDef = metadata.imageDefs[imageIndex];
                writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)} - {imageDef.typeStart}\n");
            }
            //dump type
            for (var imageIndex = 0; imageIndex < metadata.imageDefs.Length; imageIndex++)
            {
                try
                {
                    var imageDef = metadata.imageDefs[imageIndex];
                    var typeEnd = imageDef.typeStart + imageDef.typeCount;
                    for (int typeDefIndex = imageDef.typeStart; typeDefIndex < typeEnd; typeDefIndex++)
                    {
                        var typeDef = metadata.typeDefs[typeDefIndex];
                        var extends = new List<string>();
                        if (typeDef.parentIndex >= 0)
                        {
                            var parent = il2Cpp.types[typeDef.parentIndex];
                            var parentName = executor.GetTypeName(parent, false, false);
                            if (!typeDef.IsValueType && !typeDef.IsEnum && parentName != "object")
                            {
                                extends.Add(parentName);
                            }
                        }
                        if (typeDef.interfaces_count > 0)
                        {
                            for (int i = 0; i < typeDef.interfaces_count; i++)
                            {
                                var @interface = il2Cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                                extends.Add(executor.GetTypeName(@interface, false, false));
                            }
                        }
                        writer.Write($"\n// Namespace: {metadata.GetStringFromIndex(typeDef.namespaceIndex)}\n");
                        if (config.DumpAttribute)
                        {
                            writer.Write(GetCustomAttribute(imageDef, typeDef.customAttributeIndex, typeDef.token));
                        }
                        if (config.DumpAttribute && (typeDef.flags & TYPE_ATTRIBUTE_SERIALIZABLE) != 0)
                            writer.Write("[Serializable]\n");
                        var visibility = typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
                        switch (visibility)
                        {
                            case TYPE_ATTRIBUTE_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_PUBLIC:
                                writer.Write("public ");
                                break;
                            case TYPE_ATTRIBUTE_NOT_PUBLIC:
                            case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
                            case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
                                writer.Write("internal ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_PRIVATE:
                                writer.Write("private ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAMILY:
                                writer.Write("protected ");
                                break;
                            case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
                                writer.Write("protected internal ");
                                break;
                        }
                        if ((typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0 && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("static ");
                        else if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) == 0 && (typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0)
                            writer.Write("abstract ");
                        else if (!typeDef.IsValueType && !typeDef.IsEnum && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                            writer.Write("sealed ");
                        if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0)
                            writer.Write("interface ");
                        else if (typeDef.IsEnum)
                            writer.Write("enum ");
                        else if (typeDef.IsValueType)
                            writer.Write("struct ");
                        else
                            writer.Write("class ");
                        var typeName = executor.GetTypeDefName(typeDef, false, true);
                        writer.Write($"{typeName}");
                        if (extends.Count > 0)
                            writer.Write($" : {string.Join(", ", extends)}");
                        if (config.DumpTypeDefIndex)
                            writer.Write($" // TypeDefIndex: {typeDefIndex}\n{{");
                        else
                            writer.Write("\n{");
                        //dump field
                        if (config.DumpField && typeDef.field_count > 0)
                        {
                            writer.Write("\n\t// Fields\n");
                            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                            for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                            {
                                var fieldDef = metadata.fieldDefs[i];
                                var fieldType = il2Cpp.types[fieldDef.typeIndex];
                                var isStatic = false;
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, fieldDef.customAttributeIndex, fieldDef.token, "\t"));
                                }
                                writer.Write("\t");
                                var access = fieldType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
                                switch (access)
                                {
                                    case FIELD_ATTRIBUTE_PRIVATE:
                                        writer.Write("private ");
                                        break;
                                    case FIELD_ATTRIBUTE_PUBLIC:
                                        writer.Write("public ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAMILY:
                                        writer.Write("protected ");
                                        break;
                                    case FIELD_ATTRIBUTE_ASSEMBLY:
                                    case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                                        writer.Write("internal ");
                                        break;
                                    case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                                        writer.Write("protected internal ");
                                        break;
                                }
                                if ((fieldType.attrs & FIELD_ATTRIBUTE_LITERAL) != 0)
                                {
                                    writer.Write("const ");
                                }
                                else
                                {
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                    {
                                        isStatic = true;
                                        writer.Write("static ");
                                    }
                                    if ((fieldType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                    {
                                        writer.Write("readonly ");
                                    }
                                }
                                writer.Write($"{executor.GetTypeName(fieldType, false, false)} {metadata.GetStringFromIndex(fieldDef.nameIndex)}");
                                if (metadata.GetFieldDefaultValueFromIndex(i, out var fieldDefaultValue) && fieldDefaultValue.dataIndex != -1)
                                {
                                    if (TryGetDefaultValue(fieldDefaultValue.typeIndex, fieldDefaultValue.dataIndex, out var value))
                                    {
                                        writer.Write($" = ");
                                        if (value is string str)
                                        {
                                            writer.Write($"\"{str.ToEscapedString()}\"");
                                        }
                                        else if (value is char c)
                                        {
                                            var v = (int)c;
                                            writer.Write($"'\\x{v:x}'");
                                        }
                                        else if (value != null)
                                        {
                                            writer.Write($"{value}");
                                        }
                                    }
                                    else
                                    {
                                        writer.Write($" /*Metadata offset 0x{value:X}*/");
                                    }
                                }
                                if (config.DumpFieldOffset)
                                    writer.Write("; // 0x{0:X}\n", il2Cpp.GetFieldOffsetFromIndex(typeDefIndex, i - typeDef.fieldStart, i, typeDef.IsValueType, isStatic));
                                else
                                    writer.Write(";\n");
                            }
                        }
                        //dump property
                        if (config.DumpProperty && typeDef.property_count > 0)
                        {
                            writer.Write("\n\t// Properties\n");
                            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                            for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                            {
                                var propertyDef = metadata.propertyDefs[i];
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, propertyDef.customAttributeIndex, propertyDef.token, "\t"));
                                }
                                writer.Write("\t");
                                if (propertyDef.get >= 0)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.get];
                                    writer.Write(GetModifiers(methodDef));
                                    var propertyType = il2Cpp.types[methodDef.returnType];
                                    writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }
                                else if (propertyDef.set > 0)
                                {
                                    var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.set];
                                    writer.Write(GetModifiers(methodDef));
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart];
                                    var propertyType = il2Cpp.types[parameterDef.typeIndex];
                                    writer.Write($"{executor.GetTypeName(propertyType, false, false)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                }
                                if (propertyDef.get >= 0)
                                    writer.Write("get; ");
                                if (propertyDef.set >= 0)
                                    writer.Write("set; ");
                                writer.Write("}");
                                writer.Write("\n");
                            }
                        }
                        //dump method
                        if (config.DumpMethod && typeDef.method_count > 0)
                        {
                            writer.Write("\n\t// Methods\n");
                            var methodEnd = typeDef.methodStart + typeDef.method_count;
                            for (var i = typeDef.methodStart; i < methodEnd; ++i)
                            {
                                var methodDef = metadata.methodDefs[i];
                                if (config.DumpAttribute)
                                {
                                    writer.Write(GetCustomAttribute(imageDef, methodDef.customAttributeIndex, methodDef.token, "\t"));
                                }
                                if (config.DumpMethodOffset)
                                {
                                    var methodPointer = il2Cpp.GetMethodPointer(methodDef.methodIndex, i, imageIndex, methodDef.token);
                                    if (methodPointer > 0)
                                    {
                                        var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                                        writer.Write("\t// RVA: 0x{0:X} Offset: 0x{1:X} VA: 0x{2:X}", fixedMethodPointer, il2Cpp.MapVATR(methodPointer), methodPointer);
                                    }
                                    else
                                    {
                                        writer.Write("\t// RVA: -1 Offset: -1");
                                    }
                                    if (methodDef.slot != ushort.MaxValue)
                                    {
                                        writer.Write(" Slot: {0}", methodDef.slot);
                                    }
                                    writer.Write("\n");
                                }
                                writer.Write("\t");
                                writer.Write(GetModifiers(methodDef));
                                var methodReturnType = il2Cpp.types[methodDef.returnType];
                                var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                                if (methodReturnType.byref == 1)
                                {
                                    writer.Write("ref ");
                                }
                                writer.Write($"{executor.GetTypeName(methodReturnType, false, false)} {methodName}(");
                                var parameterStrs = new List<string>();
                                for (var j = 0; j < methodDef.parameterCount; ++j)
                                {
                                    var parameterStr = "";
                                    var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                    var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                    var parameterType = il2Cpp.types[parameterDef.typeIndex];
                                    var parameterTypeName = executor.GetTypeName(parameterType, false, false);
                                    if (parameterType.byref == 1)
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) == 0)
                                        {
                                            parameterStr += "out ";
                                        }
                                        else if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) == 0 && (parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "in ";
                                        }
                                        else
                                        {
                                            parameterStr += "ref ";
                                        }
                                    }
                                    else
                                    {
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_IN) != 0)
                                        {
                                            parameterStr += "[In] ";
                                        }
                                        if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                        {
                                            parameterStr += "[Out] ";
                                        }
                                    }
                                    parameterStr += $"{parameterTypeName} {parameterName}";
                                    if (metadata.GetParameterDefaultValueFromIndex(methodDef.parameterStart + j, out var parameterDefault) && parameterDefault.dataIndex != -1)
                                    {
                                        if (TryGetDefaultValue(parameterDefault.typeIndex, parameterDefault.dataIndex, out var value))
                                        {
                                            parameterStr += " = ";
                                            if (value is string str)
                                            {
                                                parameterStr += $"\"{str.ToEscapedString()}\"";
                                            }
                                            else if (value is char c)
                                            {
                                                var v = (int)c;
                                                parameterStr += $"'\\x{v:x}'";
                                            }
                                            else if (value != null)
                                            {
                                                parameterStr += $"{value}";
                                            }
                                        }
                                        else
                                        {
                                            parameterStr += $" /*Metadata offset 0x{value:X}*/";
                                        }
                                    }
                                    parameterStrs.Add(parameterStr);
                                }
                                writer.Write(string.Join(", ", parameterStrs));
                                writer.Write(") { }\n");
                            }
                        }
                        writer.Write("}\n");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: Some errors in dumping");
                    writer.Write("/*");
                    writer.Write(e);
                    writer.Write("*/\n}\n");
                }
            }
            writer.Close();
        }

        public string GetCustomAttribute(Il2CppImageDefinition image, int customAttributeIndex, uint token, string padding = "")
        {
            if (il2Cpp.Version < 21)
                return string.Empty;
            var attributeIndex = metadata.GetCustomAttributeIndex(image, customAttributeIndex, token);
            if (attributeIndex >= 0)
            {
                var attributeTypeRange = metadata.attributeTypeRanges[attributeIndex];
                var sb = new StringBuilder();
                for (var i = 0; i < attributeTypeRange.count; i++)
                {
                    var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                    var methodPointer = il2Cpp.customAttributeGenerators[attributeIndex];
                    var fixedMethodPointer = il2Cpp.GetRVA(methodPointer);
                    sb.AppendFormat("{0}[{1}] // RVA: 0x{2:X} Offset: 0x{3:X} VA: 0x{4:X}\n",
                        padding,
                        executor.GetTypeName(il2Cpp.types[typeIndex], false, false),
                        fixedMethodPointer,
                        il2Cpp.MapVATR(methodPointer),
                        methodPointer);
                }
                return sb.ToString();
            }
            else
            {
                return string.Empty;
            }
        }

        public string GetModifiers(Il2CppMethodDefinition methodDef)
        {
            if (methodModifiers.TryGetValue(methodDef, out string str))
                return str;
            var access = methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
            switch (access)
            {
                case METHOD_ATTRIBUTE_PRIVATE:
                    str += "private ";
                    break;
                case METHOD_ATTRIBUTE_PUBLIC:
                    str += "public ";
                    break;
                case METHOD_ATTRIBUTE_FAMILY:
                    str += "protected ";
                    break;
                case METHOD_ATTRIBUTE_ASSEM:
                case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
                    str += "internal ";
                    break;
                case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
                    str += "protected internal ";
                    break;
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                str += "static ";
            if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
            {
                str += "abstract ";
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_FINAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
                    str += "sealed override ";
            }
            else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
            {
                if ((methodDef.flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
                    str += "virtual ";
                else
                    str += "override ";
            }
            if ((methodDef.flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) != 0)
                str += "extern ";
            methodModifiers.Add(methodDef, str);
            return str;
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
    }
}
