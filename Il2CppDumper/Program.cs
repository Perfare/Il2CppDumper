using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class Program
    {
        static Metadata metadata;
        static Il2Cpp il2cpp;

        static void Main(string[] args)
        {
            Console.WriteLine("Select Mode: 1. Manual 2.Auto");
            var key = Console.ReadKey(true);
            try
            {
                if (key.KeyChar == '2')
                {
                    metadata = new Metadata(new MemoryStream(File.ReadAllBytes("global-metadata.dat")));
                    il2cpp = new Il2Cpp(new MemoryStream(File.ReadAllBytes("libil2cpp.so")));
                }
                else if (key.KeyChar == '1')
                {
                    Console.Write("Input CodeRegistration(R0): ");
                    var codeRegistration = Convert.ToUInt32(Console.ReadLine(), 16);
                    Console.Write("Input MetadataRegistration(R1): ");
                    var metadataRegistration = Convert.ToUInt32(Console.ReadLine(), 16);
                    metadata = new Metadata(new MemoryStream(File.ReadAllBytes("global-metadata.dat")));
                    il2cpp = new Il2Cpp(new MemoryStream(File.ReadAllBytes("libil2cpp.so")), codeRegistration, metadataRegistration);
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
                    //dump_class(i);
                    var typeDef = metadata.typeDefs[idx];
                    writer.Write($"// Namespace: {metadata.GetString(typeDef.namespaceIndex)}\n");
                    if ((typeDef.flags & DefineConstants.TYPE_ATTRIBUTE_SERIALIZABLE) != 0)
                        writer.Write("[Serializable]\n");
                    if ((typeDef.flags & DefineConstants.TYPE_ATTRIBUTE_VISIBILITY_MASK) == DefineConstants.TYPE_ATTRIBUTE_PUBLIC)
                        writer.Write("public ");
                    if ((typeDef.flags & DefineConstants.TYPE_ATTRIBUTE_ABSTRACT) != 0)
                        writer.Write("abstract ");
                    if ((typeDef.flags & DefineConstants.TYPE_ATTRIBUTE_SEALED) != 0)
                        writer.Write("sealed ");
                    if ((typeDef.flags & DefineConstants.TYPE_ATTRIBUTE_INTERFACE) != 0)
                        writer.Write("interface ");
                    else
                        writer.Write("class ");
                    writer.Write($"{metadata.GetString(typeDef.nameIndex)} // TypeDefIndex: {idx}\n{{\n");
                    writer.Write("\t// Fields\n");
                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                    for (int i = typeDef.fieldStart; i < fieldEnd; ++i)
                    {
                        //dump_field(i, idx, i - typeDef.fieldStart);
                        var pField = metadata.fieldDefs[i];
                        var pType = il2cpp.GetTypeFromTypeIndex(pField.typeIndex);
                        var pDefault = metadata.GetFieldDefaultFromIndex(i);
                        writer.Write("\t");
                        if ((pType.attrs & DefineConstants.FIELD_ATTRIBUTE_PRIVATE) == DefineConstants.FIELD_ATTRIBUTE_PRIVATE)
                            writer.Write("private ");
                        if ((pType.attrs & DefineConstants.FIELD_ATTRIBUTE_PUBLIC) == DefineConstants.FIELD_ATTRIBUTE_PUBLIC)
                            writer.Write("public ");
                        if ((pType.attrs & DefineConstants.FIELD_ATTRIBUTE_STATIC) != 0)
                            writer.Write("static ");
                        if ((pType.attrs & DefineConstants.FIELD_ATTRIBUTE_INIT_ONLY) != 0)
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
                                    case Il2CppTypeEnum.IL2CPP_TYPE_I1:
                                        multi = metadata.ReadByte();
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
                    writer.Write("\t// Methods\n");
                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                    for (int i = typeDef.methodStart; i < methodEnd; ++i)
                    {
                        //dump_method(i);
                        var methodDef = metadata.methodDefs[i];
                        writer.Write("\t");
                        Il2CppType pReturnType = il2cpp.GetTypeFromTypeIndex(methodDef.returnType);
                        if ((methodDef.flags & DefineConstants.METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == DefineConstants.METHOD_ATTRIBUTE_PRIVATE)
                            writer.Write("private ");
                        if ((methodDef.flags & DefineConstants.METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == DefineConstants.METHOD_ATTRIBUTE_PUBLIC)
                            writer.Write("public ");
                        if ((methodDef.flags & DefineConstants.METHOD_ATTRIBUTE_VIRTUAL) != 0)
                            writer.Write("virtual ");
                        if ((methodDef.flags & DefineConstants.METHOD_ATTRIBUTE_STATIC) != 0)
                            writer.Write("static ");

                        writer.Write($"{get_type_name(pReturnType)} {metadata.GetString(methodDef.nameIndex)}(");
                        for (int j = 0; j < methodDef.parameterCount; ++j)
                        {
                            Il2CppParameterDefinition pParam = metadata.parameterDefs[methodDef.parameterStart + j];
                            string szParamName = metadata.GetString(pParam.nameIndex);
                            Il2CppType pType = il2cpp.GetTypeFromTypeIndex(pParam.typeIndex);
                            string szTypeName = get_type_name(pType);
                            if ((pType.attrs & DefineConstants.PARAM_ATTRIBUTE_OPTIONAL) != 0)
                                writer.Write("optional ");
                            if ((pType.attrs & DefineConstants.PARAM_ATTRIBUTE_OUT) != 0)
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
                            writer.Write("); // {0:x} - {1}\n", il2cpp.pCodeRegistration.methodPointers[methodDef.methodIndex], methodDef.methodIndex);
                        else
                            writer.Write("); // 0 - -1\n");
                    }
                    writer.Write("}\n");
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
