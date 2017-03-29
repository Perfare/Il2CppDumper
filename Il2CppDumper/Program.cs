using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows.Forms;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    class Program
    {
        static Metadata metadata;
        static Il2Cpp il2cpp;

        [STAThread]
        static void Main(string[] args)
        {
            var ofd = new OpenFileDialog();
            ofd.Filter = "ELF file or Mach-O file|*.*";
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                var il2cppfile = File.ReadAllBytes(ofd.FileName);
                ofd.Filter = "global-metadata|global-metadata.dat";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        //判断magic
                        var macig = BitConverter.ToUInt32(il2cppfile, 0);
                        var isElf = false;
                        if (macig == 0x464c457f) //Elf
                        {
                            isElf = true;
                        }
                        else if (macig != 0xFEEDFACE) //32-bit mach object file
                        {
                            throw new Exception("ERROR: il2cpp file not supported.");
                        }
                        Console.WriteLine("Select Mode: 1. Manual 2.Auto");
                        var key = Console.ReadKey(true);
                        if (key.KeyChar == '2')
                        {
                            metadata = new Metadata(new MemoryStream(File.ReadAllBytes(ofd.FileName)));
                            if (isElf)
                                il2cpp = new Elf(new MemoryStream(il2cppfile));
                            else
                                il2cpp = new Macho(new MemoryStream(il2cppfile));
                            if (!il2cpp.Auto())
                            {
                                throw new Exception("ERROR: Unable to process file automatically, try to use manual mode.");
                            }
                        }
                        else if (key.KeyChar == '1')
                        {
                            Console.Write("Input CodeRegistration(R0): ");
                            var codeRegistration = Convert.ToUInt32(Console.ReadLine(), 16);
                            Console.Write("Input MetadataRegistration(R1): ");
                            var metadataRegistration = Convert.ToUInt32(Console.ReadLine(), 16);
                            metadata = new Metadata(new MemoryStream(File.ReadAllBytes(ofd.FileName)));
                            if (isElf)
                                il2cpp = new Elf(new MemoryStream(il2cppfile), codeRegistration, metadataRegistration);
                            else
                                il2cpp = new Macho(new MemoryStream(il2cppfile), codeRegistration, metadataRegistration);
                        }
                        else
                        {
                            return;
                        }
                        var writer = new StreamWriter(new FileStream("dump.cs", FileMode.Create));
                        Console.WriteLine("Dumping...");
                        //dump_image();
                        for (int imageIndex = 0; imageIndex < metadata.uiImageCount; imageIndex++)
                        {
                            var imageDef = metadata.imageDefs[imageIndex];
                            writer.Write($"// Image {imageIndex}: {metadata.GetString(imageDef.nameIndex)} - {imageDef.typeStart}\n");
                        }
                        for (int idx = 0; idx < metadata.uiNumTypes; ++idx)
                        {
                            try
                            {
                                //dump_class(i);
                                var typeDef = metadata.typeDefs[idx];
                                writer.Write($"\n// Namespace: {metadata.GetString(typeDef.namespaceIndex)}\n");
                                writer.Write(GetCustomAttribute(typeDef.customAttributeIndex));
                                if ((typeDef.flags & TYPE_ATTRIBUTE_SERIALIZABLE) != 0)
                                    writer.Write("[Serializable]\n");
                                if ((typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK) == TYPE_ATTRIBUTE_PUBLIC)
                                    writer.Write("public ");
                                else if ((typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK) == TYPE_ATTRIBUTE_NOT_PUBLIC)
                                    writer.Write("internal ");
                                if ((typeDef.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0)
                                    writer.Write("abstract ");
                                if ((typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                                    writer.Write("sealed ");
                                if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0)
                                    writer.Write("interface ");
                                else
                                    writer.Write("class ");
                                writer.Write($"{metadata.GetString(typeDef.nameIndex)}");
                                if (typeDef.parentIndex >= 0)
                                {
                                    var parent = il2cpp.GetTypeFromTypeIndex(typeDef.parentIndex);
                                    var parentname = get_type_name(parent);
                                    if (parentname != "object")
                                        writer.Write($" : {parentname}");
                                }
                                writer.Write($" // TypeDefIndex: {idx}\n{{\n");
                                if (typeDef.field_count > 0)
                                {
                                    writer.Write("\t// Fields\n");
                                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                                    for (int i = typeDef.fieldStart; i < fieldEnd; ++i)
                                    {
                                        //dump_field(i, idx, i - typeDef.fieldStart);
                                        var pField = metadata.fieldDefs[i];
                                        var pType = il2cpp.GetTypeFromTypeIndex(pField.typeIndex);
                                        var pDefault = metadata.GetFieldDefaultFromIndex(i);
                                        writer.Write(GetCustomAttribute(pField.customAttributeIndex, "\t"));
                                        writer.Write("\t");
                                        if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) == FIELD_ATTRIBUTE_PRIVATE)
                                            writer.Write("private ");
                                        else if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) == FIELD_ATTRIBUTE_PUBLIC)
                                            writer.Write("public ");
                                        else if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) == FIELD_ATTRIBUTE_FAMILY)
                                            writer.Write("protected ");
                                        if ((pType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                            writer.Write("static ");
                                        if ((pType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                            writer.Write("readonly ");
                                        writer.Write($"{get_type_name(pType)} {metadata.GetString(pField.nameIndex)}");
                                        if (pDefault != null && pDefault.dataIndex != -1)
                                        {
                                            var pointer = metadata.GetDefaultValueFromIndex(pDefault.dataIndex);
                                            Il2CppType pTypeToUse = il2cpp.GetTypeFromTypeIndex(pDefault.typeIndex);
                                            if (pointer > 0)
                                            {
                                                metadata.Position = pointer;
                                                object multi = null;
                                                switch (pTypeToUse.type)
                                                {
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_BOOLEAN:
                                                        multi = metadata.ReadBoolean();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_U1:
                                                        multi = metadata.ReadByte();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                                                        multi = metadata.ReadSByte();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_CHAR:
                                                        multi = metadata.ReadChar();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_U2:
                                                        multi = metadata.ReadUInt16();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_I2:
                                                        multi = metadata.ReadInt16();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_U4:
                                                        multi = metadata.ReadUInt32();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_I4:
                                                        multi = metadata.ReadInt32();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_U8:
                                                        multi = metadata.ReadUInt64();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_I8:
                                                        multi = metadata.ReadInt64();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_R4:
                                                        multi = metadata.ReadSingle();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_R8:
                                                        multi = metadata.ReadDouble();
                                                        break;
                                                    case Il2CppTypeEnum.IL2CPP_TYPE_STRING:
                                                        var uiLen = metadata.ReadInt32();
                                                        multi = Encoding.UTF8.GetString(metadata.ReadBytes(uiLen));
                                                        break;
                                                }
                                                if (multi is string)
                                                    writer.Write($" = \"{multi}\"");
                                                else if (multi != null)
                                                    writer.Write($" = {multi}");
                                            }
                                        }
                                        writer.Write("; // 0x{0:x}\n", il2cpp.GetFieldOffsetFromIndex(idx, i - typeDef.fieldStart));
                                    }
                                    writer.Write("\n");
                                }
                                if (typeDef.property_count > 0)
                                {
                                    //dump_property(i);
                                    writer.Write("\t// Properties\n");
                                    var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                                    for (int i = typeDef.propertyStart; i < propertyEnd; ++i)
                                    {
                                        var propertydef = metadata.propertyDefs[i];
                                        writer.Write(GetCustomAttribute(propertydef.customAttributeIndex, "\t"));
                                        writer.Write("\t");
                                        var tmp = propertydef.get >= 0 ? propertydef.get : propertydef.set;
                                        if (tmp >= 0)
                                        {
                                            var methodDef = metadata.methodDefs[typeDef.methodStart + propertydef.get];
                                            var pReturnType = il2cpp.GetTypeFromTypeIndex(methodDef.returnType);
                                            if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_PRIVATE)
                                                writer.Write("private ");
                                            else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_PUBLIC)
                                                writer.Write("public ");
                                            else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_FAMILY)
                                                writer.Write("protected ");
                                            if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
                                                writer.Write("abstract ");
                                            else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                                                writer.Write("virtual ");
                                            if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                                                writer.Write("static ");
                                            writer.Write($"{get_type_name(pReturnType)} {metadata.GetString(propertydef.nameIndex)} {{ ");
                                            if (propertydef.get >= 0)
                                                writer.Write("get; ");
                                            if (propertydef.set >= 0)
                                                writer.Write("set; ");
                                            writer.Write("}");
                                        }
                                        writer.Write("\n");
                                    }
                                    writer.Write("\n");
                                }
                                if (typeDef.method_count > 0)
                                {
                                    writer.Write("\t// Methods\n");
                                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                                    for (int i = typeDef.methodStart; i < methodEnd; ++i)
                                    {
                                        //dump_method(i);
                                        var methodDef = metadata.methodDefs[i];
                                        writer.Write(GetCustomAttribute(methodDef.customAttributeIndex, "\t"));
                                        writer.Write("\t");
                                        Il2CppType pReturnType = il2cpp.GetTypeFromTypeIndex(methodDef.returnType);
                                        if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_PRIVATE)
                                            writer.Write("private ");
                                        else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_PUBLIC)
                                            writer.Write("public ");
                                        else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == METHOD_ATTRIBUTE_FAMILY)
                                            writer.Write("protected ");
                                        if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
                                            writer.Write("abstract ");
                                        else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                                            writer.Write("virtual ");
                                        if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                                            writer.Write("static ");
                                        writer.Write($"{get_type_name(pReturnType)} {metadata.GetString(methodDef.nameIndex)}(");
                                        for (int j = 0; j < methodDef.parameterCount; ++j)
                                        {
                                            Il2CppParameterDefinition pParam =
                                                metadata.parameterDefs[methodDef.parameterStart + j];
                                            string szParamName = metadata.GetString(pParam.nameIndex);
                                            Il2CppType pType = il2cpp.GetTypeFromTypeIndex(pParam.typeIndex);
                                            string szTypeName = get_type_name(pType);
                                            if ((pType.attrs & PARAM_ATTRIBUTE_OPTIONAL) != 0)
                                                writer.Write("optional ");
                                            if ((pType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                                writer.Write("out ");
                                            if (j != methodDef.parameterCount - 1)
                                            {
                                                writer.Write($"{szTypeName} {szParamName}, ");
                                            }
                                            else
                                            {
                                                writer.Write($"{szTypeName} {szParamName}");
                                            }
                                        }
                                        if (methodDef.methodIndex >= 0)
                                            writer.Write("); // {0:x}\n", il2cpp.pCodeRegistration.methodPointers[methodDef.methodIndex]);
                                        else
                                            writer.Write("); // 0\n");
                                    }
                                }
                                writer.Write("}\n");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("ERROR: Some errors in dumping");
                                writer.Write("/*");
                                writer.Write($"{e.Message}\r\n{e.StackTrace}\r\n");
                                writer.Write("*/\n}\n");
                            }
                        }
                        writer.Close();
                        Console.WriteLine("Done !");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey(true);
                }
            }
        }

        private static string get_type_name(Il2CppType pType)
        {
            string ret;
            if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_CLASS || pType.type == Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE)
            {
                Il2CppTypeDefinition klass = metadata.typeDefs[pType.data.klassIndex];
                ret = metadata.GetString(klass.nameIndex);
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST)
            {
                Il2CppGenericClass generic_class = il2cpp.MapVATR<Il2CppGenericClass>(pType.data.generic_class);
                Il2CppTypeDefinition pMainDef = metadata.typeDefs[generic_class.typeDefinitionIndex];
                ret = metadata.GetString(pMainDef.nameIndex);
                var typeNames = new List<string>();
                Il2CppGenericInst pInst = il2cpp.MapVATR<Il2CppGenericInst>(generic_class.context.class_inst);
                var pointers = il2cpp.MapVATR<uint>(pInst.type_argv, (int)pInst.type_argc);
                for (int i = 0; i < pInst.type_argc; ++i)
                {
                    var pOriType = il2cpp.MapVATR<Il2CppType>(pointers[i]);
                    pOriType.Init();
                    typeNames.Add(get_type_name(pOriType));
                }
                ret += $"<{string.Join(", ", typeNames)}>";
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_ARRAY)
            {
                Il2CppArrayType arrayType = il2cpp.MapVATR<Il2CppArrayType>(pType.data.array);
                var type = il2cpp.MapVATR<Il2CppType>(arrayType.etype);
                type.Init();
                ret = $"{get_type_name(type)}[]";
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY)
            {
                var type = il2cpp.MapVATR<Il2CppType>(pType.data.type);
                type.Init();
                ret = $"{get_type_name(type)}[]";
            }
            else
            {
                if ((int)pType.type >= szTypeString.Length)
                    ret = "unknow";
                else
                    ret = szTypeString[(int)pType.type];
            }
            return ret;
        }

        private static string GetCustomAttribute(int index, string padding = "")
        {
            var attributeTypeRange = metadata.attributesInfos[index];
            var sb = new StringBuilder();
            for (int i = 0; i < attributeTypeRange.count; i++)
            {
                var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                sb.AppendFormat("{0}[{1}] // {2:x}\n", padding, get_type_name(il2cpp.GetTypeFromTypeIndex(typeIndex)), il2cpp.pCodeRegistration.customAttributeGenerators[index]);
            }
            return sb.ToString();
        }

        static string[] szTypeString =
        {
            "END",
            "void",
            "bool",
            "char",
            "sbyte",
            "byte",
            "short",
            "ushort",
            "int",
            "uint",
            "long",
            "ulong",
            "float",
            "double",
            "string",
            "PTR",//eg. void*
            "BYREF",
            "VALUETYPE",
            "CLASS",
            "T",
            "ARRAY",
            "GENERICINST",
            "TYPEDBYREF",
            "None",
            "IntPtr",
            "UIntPtr",
            "None",
            "FNPTR",
            "object",
            "SZARRAY",
            "T",
            "CMOD_REQD",
            "CMOD_OPT",
            "INTERNAL",
        };
    }
}
