using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    class Program
    {
        static MetadataGeneric metadata;
        static Il2CppGeneric il2cpp;
        private static Config config;

        [STAThread]
        static void Main(string[] args)
        {
            config = File.Exists("config.json") ? new JavaScriptSerializer().Deserialize<Config>(File.ReadAllText("config.json")) : new Config();
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
                        metadata = new MetadataGeneric(new MemoryStream(File.ReadAllBytes(ofd.FileName)));
                        //判断il2cpp的magic
                        var il2cppmagic = BitConverter.ToUInt32(il2cppfile, 0);
                        var isElf = false;
                        var is64bit = false;
                        switch (il2cppmagic)
                        {
                            default:
                                throw new Exception("ERROR: il2cpp file not supported.");
                            case 0x464c457f://ELF
                                isElf = true;
                                goto case 0xFEEDFACE;
                            case 0xCAFEBABE://FAT header
                            case 0xBEBAFECA:
                                Console.WriteLine("WARNING: fat macho will only dump the first object file.");
                                var fat = new MachoFat(new MemoryStream(il2cppfile));
                                il2cppfile = fat.GetFirstMacho();
                                var magic = fat.GetFirstMachoMagic();
                                if (magic == 0xFEEDFACF)// 64-bit mach object file
                                    goto case 0xFEEDFACF;
                                else
                                    goto case 0xFEEDFACE;
                            case 0xFEEDFACF:// 64-bit mach object file
                                is64bit = true;
                                goto case 0xFEEDFACE;
                            case 0xFEEDFACE:// 32-bit mach object file
                                Console.WriteLine("Select Mode: 1. Manual 2.Auto");
                                var key = Console.ReadKey(true);
                                if (key.KeyChar == '2')
                                {
                                    if (isElf)
                                        il2cpp = new Elf(new MemoryStream(il2cppfile), metadata.version, metadata.maxmetadataUsages);
                                    else if (is64bit)
                                        il2cpp = new Macho64(new MemoryStream(il2cppfile), metadata.version, metadata.maxmetadataUsages);
                                    else
                                        il2cpp = new Macho(new MemoryStream(il2cppfile), metadata.version, metadata.maxmetadataUsages);
                                    try
                                    {
                                        if (!il2cpp.Search())
                                        {
                                            throw new Exception();
                                        }
                                    }
                                    catch
                                    {
                                        throw new Exception("ERROR: Unable to process file automatically, try to use manual mode.");
                                    }
                                }
                                else if (key.KeyChar == '1')
                                {
                                    Console.Write("Input CodeRegistration(R0): ");
                                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                                    Console.Write("Input MetadataRegistration(R1): ");
                                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                                    if (isElf)
                                        il2cpp = new Elf(new MemoryStream(il2cppfile), codeRegistration, metadataRegistration, metadata.version, metadata.maxmetadataUsages);
                                    else if (is64bit)
                                        il2cpp = new Macho64(new MemoryStream(il2cppfile), codeRegistration, metadataRegistration, metadata.version, metadata.maxmetadataUsages);
                                    else
                                        il2cpp = new Macho(new MemoryStream(il2cppfile), codeRegistration, metadataRegistration, metadata.version, metadata.maxmetadataUsages);
                                }
                                else
                                {
                                    return;
                                }
                                var writer = new StreamWriter(new FileStream("dump.cs", FileMode.Create));
                                Console.WriteLine("Dumping...");
                                //Script
                                var scriptwriter = new StreamWriter(new FileStream("script.py", FileMode.Create));
                                scriptwriter.WriteLine(File.ReadAllText("ida"));
                                //
                                //dump_image();
                                for (var imageIndex = 0; imageIndex < metadata.uiImageCount; imageIndex++)
                                {
                                    var imageDef = metadata.imageDefs[imageIndex];
                                    writer.Write(
                                        $"// Image {imageIndex}: {metadata.GetString(imageDef.nameIndex)} - {imageDef.typeStart}\n");
                                }
                                for (var idx = 0; idx < metadata.uiNumTypes; ++idx)
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
                                        else if ((typeDef.flags & TYPE_ATTRIBUTE_VISIBILITY_MASK) ==
                                                 TYPE_ATTRIBUTE_NOT_PUBLIC)
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
                                            var parent = il2cpp.types[typeDef.parentIndex];
                                            var parentname = get_type_name(parent);
                                            if (parentname != "object")
                                                writer.Write($" : {parentname}");
                                        }
                                        writer.Write($" // TypeDefIndex: {idx}\n{{\n");
                                        if (config.dumpfield && typeDef.field_count > 0)
                                        {
                                            writer.Write("\t// Fields\n");
                                            var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                                            for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                                            {
                                                //dump_field(i, idx, i - typeDef.fieldStart);
                                                var pField = metadata.fieldDefs[i];
                                                var pType = il2cpp.types[pField.typeIndex];
                                                var pDefault = metadata.GetFieldDefaultFromIndex(i);
                                                writer.Write(GetCustomAttribute(pField.customAttributeIndex, "\t"));
                                                writer.Write("\t");
                                                if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) ==
                                                    FIELD_ATTRIBUTE_PRIVATE)
                                                    writer.Write("private ");
                                                else if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) ==
                                                         FIELD_ATTRIBUTE_PUBLIC)
                                                    writer.Write("public ");
                                                else if ((pType.attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK) ==
                                                         FIELD_ATTRIBUTE_FAMILY)
                                                    writer.Write("protected ");
                                                if ((pType.attrs & FIELD_ATTRIBUTE_STATIC) != 0)
                                                    writer.Write("static ");
                                                if ((pType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                                    writer.Write("readonly ");
                                                writer.Write(
                                                    $"{get_type_name(pType)} {metadata.GetString(pField.nameIndex)}");
                                                if (pDefault != null && pDefault.dataIndex != -1)
                                                {
                                                    var pointer = metadata.GetDefaultValueFromIndex(pDefault.dataIndex);
                                                    if (pointer > 0)
                                                    {
                                                        var pTypeToUse = il2cpp.types[pDefault.typeIndex];
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
                                                                //multi = metadata.ReadChar();
                                                                multi = BitConverter.ToChar(metadata.ReadBytes(2), 0);
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
                                                writer.Write("; // 0x{0:x}\n",
                                                    il2cpp.GetFieldOffsetFromIndex(idx, i - typeDef.fieldStart, i));
                                            }
                                            writer.Write("\n");
                                        }
                                        if (config.dumpproperty && typeDef.property_count > 0)
                                        {
                                            //dump_property(i);
                                            writer.Write("\t// Properties\n");
                                            var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                                            for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                                            {
                                                var propertydef = metadata.propertyDefs[i];
                                                writer.Write(GetCustomAttribute(propertydef.customAttributeIndex, "\t"));
                                                writer.Write("\t");
                                                if (propertydef.get >= 0)
                                                {
                                                    var methodDef =
                                                        metadata.methodDefs[typeDef.methodStart + propertydef.get];
                                                    var pReturnType = il2cpp.types[methodDef.returnType];
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                        METHOD_ATTRIBUTE_PRIVATE)
                                                        writer.Write("private ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                             METHOD_ATTRIBUTE_PUBLIC)
                                                        writer.Write("public ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                             METHOD_ATTRIBUTE_FAMILY)
                                                        writer.Write("protected ");
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
                                                        writer.Write("abstract ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                                                        writer.Write("virtual ");
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                                                        writer.Write("static ");
                                                    writer.Write(
                                                        $"{get_type_name(pReturnType)} {metadata.GetString(propertydef.nameIndex)} {{ ");
                                                }
                                                else if (propertydef.set > 0)
                                                {
                                                    var methodDef =
                                                        metadata.methodDefs[typeDef.methodStart + propertydef.set];
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                        METHOD_ATTRIBUTE_PRIVATE)
                                                        writer.Write("private ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                             METHOD_ATTRIBUTE_PUBLIC)
                                                        writer.Write("public ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                             METHOD_ATTRIBUTE_FAMILY)
                                                        writer.Write("protected ");
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
                                                        writer.Write("abstract ");
                                                    else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                                                        writer.Write("virtual ");
                                                    if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                                                        writer.Write("static ");
                                                    var pParam = metadata.parameterDefs[methodDef.parameterStart];
                                                    var pType = il2cpp.types[pParam.typeIndex];
                                                    writer.Write(
                                                        $"{get_type_name(pType)} {metadata.GetString(propertydef.nameIndex)} {{ ");
                                                }
                                                if (propertydef.get >= 0)
                                                    writer.Write("get; ");
                                                if (propertydef.set >= 0)
                                                    writer.Write("set; ");
                                                writer.Write("}");
                                                writer.Write("\n");
                                            }
                                            writer.Write("\n");
                                        }
                                        if (config.dumpmethod && typeDef.method_count > 0)
                                        {
                                            writer.Write("\t// Methods\n");
                                            var methodEnd = typeDef.methodStart + typeDef.method_count;
                                            for (var i = typeDef.methodStart; i < methodEnd; ++i)
                                            {
                                                //dump_method(i);
                                                var methodDef = metadata.methodDefs[i];
                                                writer.Write(GetCustomAttribute(methodDef.customAttributeIndex, "\t"));
                                                writer.Write("\t");
                                                var pReturnType = il2cpp.types[methodDef.returnType];
                                                if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                    METHOD_ATTRIBUTE_PRIVATE)
                                                    writer.Write("private ");
                                                else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                         METHOD_ATTRIBUTE_PUBLIC)
                                                    writer.Write("public ");
                                                else if ((methodDef.flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) ==
                                                         METHOD_ATTRIBUTE_FAMILY)
                                                    writer.Write("protected ");
                                                if ((methodDef.flags & METHOD_ATTRIBUTE_ABSTRACT) != 0)
                                                    writer.Write("abstract ");
                                                else if ((methodDef.flags & METHOD_ATTRIBUTE_VIRTUAL) != 0)
                                                    writer.Write("virtual ");
                                                if ((methodDef.flags & METHOD_ATTRIBUTE_STATIC) != 0)
                                                    writer.Write("static ");
                                                writer.Write(
                                                    $"{get_type_name(pReturnType)} {metadata.GetString(methodDef.nameIndex)}(");
                                                for (var j = 0; j < methodDef.parameterCount; ++j)
                                                {
                                                    var pParam = metadata.parameterDefs[methodDef.parameterStart + j];
                                                    var szParamName = metadata.GetString(pParam.nameIndex);
                                                    var pType = il2cpp.types[pParam.typeIndex];
                                                    var szTypeName = get_type_name(pType);
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
                                                {
                                                    writer.Write("); // {0:x}\n", il2cpp.methodPointers[methodDef.methodIndex]);
                                                    //Script
                                                    var name = ToUnicodeString(metadata.GetString(typeDef.nameIndex) + "$$" + metadata.GetString(methodDef.nameIndex));
                                                    scriptwriter.WriteLine($"SetMethod(0x{il2cpp.methodPointers[methodDef.methodIndex]:x}, '{name}')");
                                                    //
                                                }
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
                                        writer.Write($"{e.Message}\n{e.StackTrace}\n");
                                        writer.Write("*/\n}\n");
                                    }
                                }
                                //Script
                                if (metadata.version > 16)
                                {
                                    foreach (var i in metadata.stringLiteralsdic)
                                    {
                                        scriptwriter.WriteLine($"SetString(0x{il2cpp.metadataUsages[i.Key]:x}, '{ToUnicodeString(i.Value)}')");
                                    }
                                }
                                //
                                writer.Close();
                                scriptwriter.Close();
                                Console.WriteLine("Done !");
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"{e.Message}\r\n{e.StackTrace}");
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
                var klass = metadata.typeDefs[pType.data.klassIndex];
                ret = metadata.GetString(klass.nameIndex);
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST)
            {
                var generic_class = il2cpp.GetIl2CppGenericClass(pType.data.generic_class);
                var pMainDef = metadata.typeDefs[generic_class.typeDefinitionIndex];
                ret = metadata.GetString(pMainDef.nameIndex);
                var typeNames = new List<string>();
                var pInst = il2cpp.GetIl2CppGenericInst(generic_class.context.class_inst);
                var pointers = il2cpp.GetPointers(pInst.type_argv, (long)pInst.type_argc);
                for (uint i = 0; i < pInst.type_argc; ++i)
                {
                    var pOriType = il2cpp.GetIl2CppType(pointers[i]);
                    typeNames.Add(get_type_name(pOriType));
                }
                ret += $"<{string.Join(", ", typeNames)}>";
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_ARRAY)
            {
                var arrayType = il2cpp.GetIl2CppArrayType(pType.data.array);
                var type = il2cpp.GetIl2CppType(arrayType.etype);
                ret = $"{get_type_name(type)}[]";
            }
            else if (pType.type == Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY)
            {
                var type = il2cpp.GetIl2CppType(pType.data.type);
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
            if (!config.dumpattribute || metadata.version < 21)
                return "";
            var attributeTypeRange = metadata.attributesInfos[index];
            var sb = new StringBuilder();
            for (var i = 0; i < attributeTypeRange.count; i++)
            {
                var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                sb.AppendFormat("{0}[{1}] // {2:x}\n", padding, get_type_name(il2cpp.types[typeIndex]), il2cpp.customAttributeGenerators[index]);
            }
            return sb.ToString();
        }

        private static string ToUnicodeString(string str)
        {
            StringBuilder strResult = new StringBuilder();
            if (!string.IsNullOrEmpty(str))
            {
                for (int i = 0; i < str.Length; i++)
                {
                    strResult.Append("\\u");
                    var c = ((int)str[i]).ToString("x4");
                    c = c.Replace("000a", @"005c\u0072").Replace("000d", @"005c\u006e");
                    strResult.Append(c);
                }
            }
            return strResult.ToString();
        }
    }
}
