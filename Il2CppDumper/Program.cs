﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using static Il2CppDumper.DefineConstants;

namespace Il2CppDumper
{
    class Program
    {
        private static Metadata metadata;
        private static Il2Cpp il2cpp;
        private static Config config;
        private static Dictionary<Il2CppMethodDefinition, string> methodModifiers = new Dictionary<Il2CppMethodDefinition, string>();

        [STAThread]
        static void Main(string[] args)
        {
            config = File.Exists("config.json") ? new JavaScriptSerializer().Deserialize<Config>(File.ReadAllText("config.json")) : new Config();
            var ofd = new OpenFileDialog();
            ofd.Filter = "Il2Cpp binary file|*.*";
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                var il2cppfile = File.ReadAllBytes(ofd.FileName);
                ofd.Filter = "global-metadata|global-metadata.dat";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        Console.WriteLine("Initializing metadata...");
                        metadata = new Metadata(new MemoryStream(File.ReadAllBytes(ofd.FileName)));
                        Console.Clear();
                        //判断il2cpp的magic
                        var il2cppMagic = BitConverter.ToUInt32(il2cppfile, 0);
                        var isElf = false;
                        var isPE = false;
                        var is64bit = false;
                        switch (il2cppMagic)
                        {
                            default:
                                throw new Exception("ERROR: il2cpp file not supported.");
                            case 0x905A4D: //PE
                                isPE = true;
                                break;
                            case 0x464c457f: //ELF
                                isElf = true;
                                if (il2cppfile[4] == 2)
                                {
                                    goto case 0xFEEDFACF; //ELF64
                                }
                                break;
                            case 0xCAFEBABE: //FAT header
                            case 0xBEBAFECA:
                                var machofat = new MachoFat(new MemoryStream(il2cppfile));
                                Console.Write("Select Platform: ");
                                for (var i = 0; i < machofat.fats.Length; i++)
                                {
                                    var fat = machofat.fats[i];
                                    Console.Write(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                                }
                                Console.WriteLine();
                                var key = Console.ReadKey(true);
                                var index = int.Parse(key.KeyChar.ToString()) - 1;
                                var magic = machofat.fats[index % 2].magic;
                                il2cppfile = machofat.GetMacho(index % 2);
                                if (magic == 0xFEEDFACF) // 64-bit mach object file
                                    goto case 0xFEEDFACF;
                                else
                                    goto case 0xFEEDFACE;
                            case 0xFEEDFACF: // 64-bit mach object file
                                is64bit = true;
                                break;
                            case 0xFEEDFACE: // 32-bit mach object file
                                break;
                        }

                        Console.WriteLine("Select Mode: 1.Manual 2.Auto 3.Auto(Advanced) 4.Auto(Plus) 5.Auto(Symbol)");
                        var modeKey = Console.ReadKey(true);
                        var version = config.ForceIl2CppVersion ? config.ForceVersion : metadata.version;
                        Console.WriteLine("Initializing il2cpp file...");
                        if (isPE)
                        {
                            il2cpp = new PE(new MemoryStream(il2cppfile), version, metadata.maxMetadataUsages);
                        }
                        else if (isElf)
                        {
                            if (is64bit)
                                il2cpp = new Elf64(new MemoryStream(il2cppfile), version, metadata.maxMetadataUsages);
                            else
                                il2cpp = new Elf(new MemoryStream(il2cppfile), version, metadata.maxMetadataUsages);
                        }
                        else if (is64bit)
                            il2cpp = new Macho64(new MemoryStream(il2cppfile), version, metadata.maxMetadataUsages);
                        else
                            il2cpp = new Macho(new MemoryStream(il2cppfile), version, metadata.maxMetadataUsages);

                        try
                        {
                            bool flag;
                            switch (modeKey.KeyChar)
                            {
                                case '1': //Manual
                                    Console.Write("Input CodeRegistration: ");
                                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                                    Console.Write("Input MetadataRegistration: ");
                                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                                    il2cpp.Init(codeRegistration, metadataRegistration);
                                    flag = true;
                                    break;
                                case '2': //Auto
                                    flag = il2cpp.Search();
                                    break;
                                case '3': //Auto(Advanced)
                                    flag = il2cpp.AdvancedSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0));
                                    break;
                                case '4': //Auto(Plus)
                                    flag = il2cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length);
                                    break;
                                case '5': //Auto(Symbol)
                                    flag = il2cpp.SymbolSearch();
                                    break;
                                default:
                                    return;
                            }
                            if (!flag)
                                throw new Exception();
                        }
                        catch
                        {
                            throw new Exception("ERROR: Can't use this mode to process file, try another mode.");
                        }
                        var writer = new StreamWriter(new FileStream("dump.cs", FileMode.Create), new UTF8Encoding(false));
                        Console.WriteLine("Dumping...");
                        //Script
                        var scriptwriter = new StreamWriter(new FileStream("script.py", FileMode.Create), new UTF8Encoding(false));
                        scriptwriter.WriteLine(Resource1.ida);
                        //dump image;
                        for (var imageIndex = 0; imageIndex < metadata.uiImageCount; imageIndex++)
                        {
                            var imageDef = metadata.imageDefs[imageIndex];
                            writer.Write($"// Image {imageIndex}: {metadata.GetStringFromIndex(imageDef.nameIndex)} - {imageDef.typeStart}\n");
                        }
                        //dump type;
                        for (var idx = 0; idx < metadata.uiNumTypes; ++idx)
                        {
                            try
                            {
                                var typeDef = metadata.typeDefs[idx];
                                var isStruct = false;
                                var isEnum = false;
                                var extends = new List<string>();
                                if (typeDef.parentIndex >= 0)
                                {
                                    var parent = il2cpp.types[typeDef.parentIndex];
                                    var parentName = GetTypeName(parent);
                                    if (parentName == "ValueType")
                                        isStruct = true;
                                    else if (parentName == "Enum")
                                        isEnum = true;
                                    else if (parentName != "object")
                                        extends.Add(parentName);
                                }
                                //implementedInterfaces
                                if (typeDef.interfaces_count > 0)
                                {
                                    for (int i = 0; i < typeDef.interfaces_count; i++)
                                    {
                                        var @interface = il2cpp.types[metadata.interfaceIndices[typeDef.interfacesStart + i]];
                                        extends.Add(GetTypeName(@interface));
                                    }
                                }
                                writer.Write($"\n// Namespace: {metadata.GetStringFromIndex(typeDef.namespaceIndex)}\n");
                                writer.Write(GetCustomAttribute(typeDef.customAttributeIndex));
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
                                else if (!isStruct && !isEnum && (typeDef.flags & TYPE_ATTRIBUTE_SEALED) != 0)
                                    writer.Write("sealed ");
                                if ((typeDef.flags & TYPE_ATTRIBUTE_INTERFACE) != 0)
                                    writer.Write("interface ");
                                else if (isStruct)
                                    writer.Write("struct ");
                                else if (isEnum)
                                    writer.Write("enum ");
                                else
                                    writer.Write("class ");
                                var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);
                                writer.Write($"{typeName}");
                                if (extends.Count > 0)
                                    writer.Write($" : {string.Join(", ", extends)}");
                                if (config.DumpTypeDefIndex)
                                    writer.Write($" // TypeDefIndex: {idx}\n{{\n");
                                else
                                    writer.Write("\n{\n");
                                //dump field
                                if (config.DumpField && typeDef.field_count > 0)
                                {
                                    writer.Write("\t// Fields\n");
                                    var fieldEnd = typeDef.fieldStart + typeDef.field_count;
                                    for (var i = typeDef.fieldStart; i < fieldEnd; ++i)
                                    {
                                        //dump_field(i, idx, i - typeDef.fieldStart);
                                        var fieldDef = metadata.fieldDefs[i];
                                        var fieldType = il2cpp.types[fieldDef.typeIndex];
                                        var fieldDefault = metadata.GetFieldDefaultValueFromIndex(i);
                                        writer.Write(GetCustomAttribute(fieldDef.customAttributeIndex, "\t"));
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
                                                writer.Write("static ");
                                            if ((fieldType.attrs & FIELD_ATTRIBUTE_INIT_ONLY) != 0)
                                                writer.Write("readonly ");
                                        }
                                        writer.Write($"{GetTypeName(fieldType)} {metadata.GetStringFromIndex(fieldDef.nameIndex)}");
                                        if (fieldDefault != null && fieldDefault.dataIndex != -1)
                                        {
                                            var pointer = metadata.GetDefaultValueFromIndex(fieldDefault.dataIndex);
                                            if (pointer > 0)
                                            {
                                                var pTypeToUse = il2cpp.types[fieldDefault.typeIndex];
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
                                                if (multi is string str)
                                                    writer.Write($" = \"{ToEscapedString(str)}\"");
                                                else if (multi is char c)
                                                {
                                                    var v = (int)c;
                                                    writer.Write($" = '\\x{v:x}'");
                                                }
                                                else if (multi != null)
                                                    writer.Write($" = {multi}");
                                            }
                                        }
                                        if (config.DumpFieldOffset)
                                            writer.Write("; // 0x{0:X}\n", il2cpp.GetFieldOffsetFromIndex(idx, i - typeDef.fieldStart, i));
                                        else
                                            writer.Write(";\n");
                                    }
                                    writer.Write("\n");
                                }
                                //dump property
                                if (config.DumpProperty && typeDef.property_count > 0)
                                {
                                    writer.Write("\t// Properties\n");
                                    var propertyEnd = typeDef.propertyStart + typeDef.property_count;
                                    for (var i = typeDef.propertyStart; i < propertyEnd; ++i)
                                    {
                                        var propertyDef = metadata.propertyDefs[i];
                                        writer.Write(GetCustomAttribute(propertyDef.customAttributeIndex, "\t"));
                                        writer.Write("\t");
                                        if (propertyDef.get >= 0)
                                        {
                                            var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.get];
                                            writer.Write(GetModifiers(methodDef));
                                            var propertyType = il2cpp.types[methodDef.returnType];
                                            writer.Write($"{GetTypeName(propertyType)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                        }
                                        else if (propertyDef.set > 0)
                                        {
                                            var methodDef = metadata.methodDefs[typeDef.methodStart + propertyDef.set];
                                            writer.Write(GetModifiers(methodDef));
                                            var parameterDef = metadata.parameterDefs[methodDef.parameterStart];
                                            var propertyType = il2cpp.types[parameterDef.typeIndex];
                                            writer.Write($"{GetTypeName(propertyType)} {metadata.GetStringFromIndex(propertyDef.nameIndex)} {{ ");
                                        }
                                        if (propertyDef.get >= 0)
                                            writer.Write("get; ");
                                        if (propertyDef.set >= 0)
                                            writer.Write("set; ");
                                        writer.Write("}");
                                        writer.Write("\n");
                                    }
                                    writer.Write("\n");
                                }
                                //dump method
                                if (config.DumpMethod && typeDef.method_count > 0)
                                {
                                    writer.Write("\t// Methods\n");
                                    var methodEnd = typeDef.methodStart + typeDef.method_count;
                                    for (var i = typeDef.methodStart; i < methodEnd; ++i)
                                    {
                                        var methodDef = metadata.methodDefs[i];
                                        writer.Write(GetCustomAttribute(methodDef.customAttributeIndex, "\t"));
                                        writer.Write("\t");
                                        writer.Write(GetModifiers(methodDef));
                                        var methodReturnType = il2cpp.types[methodDef.returnType];
                                        var methodName = metadata.GetStringFromIndex(methodDef.nameIndex);
                                        writer.Write($"{GetTypeName(methodReturnType)} {methodName}(");
                                        var parameterStrs = new List<string>();
                                        for (var j = 0; j < methodDef.parameterCount; ++j)
                                        {
                                            var parameterStr = "";
                                            var parameterDef = metadata.parameterDefs[methodDef.parameterStart + j];
                                            var parameterName = metadata.GetStringFromIndex(parameterDef.nameIndex);
                                            var parameterType = il2cpp.types[parameterDef.typeIndex];
                                            var parameterTypeName = GetTypeName(parameterType);
                                            if ((parameterType.attrs & PARAM_ATTRIBUTE_OPTIONAL) != 0)
                                                parameterStr += "optional ";
                                            if ((parameterType.attrs & PARAM_ATTRIBUTE_OUT) != 0)
                                                parameterStr += "out ";
                                            parameterStr += $"{parameterTypeName} {parameterName}";
                                            parameterStrs.Add(parameterStr);
                                        }
                                        writer.Write(string.Join(", ", parameterStrs));
                                        if (config.DumpMethodOffset)
                                        {
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
                                                writer.Write("); // 0x{0:X}\n", methodPointer);
                                                //Script - method
                                                var name = ToEscapedString(Regex.Replace(typeName, @"`\d", "") + "$$" + methodName);
                                                scriptwriter.WriteLine($"SetMethod(0x{methodPointer:X}, '{name}')");
                                            }
                                            else
                                            {
                                                writer.Write("); // -1\n");
                                            }
                                        }
                                        else
                                        {
                                            writer.Write("); \n");
                                        }
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
                        //Script - stringLiteral
                        scriptwriter.WriteLine("print('Make method name done')");
                        scriptwriter.WriteLine("print('Setting String...')");
                        if (il2cpp.version > 16)
                        {
                            foreach (var i in metadata.stringLiteralsdic)
                            {
                                scriptwriter.WriteLine($"SetString(0x{il2cpp.metadataUsages[i.Key]:X}, r'{ToEscapedString(i.Value)}')");
                            }
                        }
                        scriptwriter.WriteLine("print('Set string done')");
                        //Script - MakeFunction
                        if (config.MakeFunction)
                        {
                            var orderedPointers = il2cpp.methodPointers.ToList();
                            orderedPointers.AddRange(il2cpp.genericMethodPointers.Where(x => x > 0));
                            orderedPointers.AddRange(il2cpp.invokerPointers);
                            orderedPointers.AddRange(il2cpp.customAttributeGenerators);
                            orderedPointers = orderedPointers.OrderBy(x => x).ToList();
                            scriptwriter.WriteLine("print('Making function...')");
                            for (int i = 0; i < orderedPointers.Count - 1; i++)
                            {
                                scriptwriter.WriteLine($"MakeFunction(0x{orderedPointers[i]:X}, 0x{orderedPointers[i + 1]:X})");
                            }
                            scriptwriter.WriteLine("print('Make function done, please wait for IDA to complete the analysis')");
                        }
                        scriptwriter.WriteLine("print('Script finish !')");
                        //writer close
                        writer.Close();
                        scriptwriter.Close();
                        Console.WriteLine("Done !");
                        //DummyDll
                        if (config.DummyDll)
                        {
                            Console.WriteLine("Create DummyDll...");
                            if (Directory.Exists("DummyDll"))
                                Directory.Delete("DummyDll", true);
                            Directory.CreateDirectory("DummyDll");
                            Directory.SetCurrentDirectory("DummyDll");
                            File.WriteAllBytes("Il2CppDummyDll.dll", Resource1.Il2CppDummyDll);
                            var dummy = new DummyAssemblyCreator(metadata, il2cpp);
                            foreach (var assembly in dummy.Assemblies)
                            {
                                var stream = new MemoryStream();
                                assembly.Write(stream);
                                File.WriteAllBytes(assembly.MainModule.Name, stream.ToArray());
                            }
                            Console.WriteLine("Done !");
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey(true);
                }
            }
        }

        private static string GetTypeName(Il2CppType pType)
        {
            string ret;
            switch (pType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var klass = metadata.typeDefs[pType.data.klassIndex];
                        ret = metadata.GetStringFromIndex(klass.nameIndex);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var generic_class = il2cpp.MapVATR<Il2CppGenericClass>(pType.data.generic_class);
                        var pMainDef = metadata.typeDefs[generic_class.typeDefinitionIndex];
                        ret = metadata.GetStringFromIndex(pMainDef.nameIndex);
                        var typeNames = new List<string>();
                        var pInst = il2cpp.MapVATR<Il2CppGenericInst>(generic_class.context.class_inst);
                        var pointers = il2cpp.GetPointers(pInst.type_argv, (long)pInst.type_argc);
                        for (uint i = 0; i < pInst.type_argc; ++i)
                        {
                            var pOriType = il2cpp.GetIl2CppType(pointers[i]);
                            typeNames.Add(GetTypeName(pOriType));
                        }
                        ret += $"<{string.Join(", ", typeNames)}>";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2cpp.MapVATR<Il2CppArrayType>(pType.data.array);
                        var type = il2cpp.GetIl2CppType(arrayType.etype);
                        ret = $"{GetTypeName(type)}[{new string(',', arrayType.rank - 1)}]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var type = il2cpp.GetIl2CppType(pType.data.type);
                        ret = $"{GetTypeName(type)}[]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var type = il2cpp.GetIl2CppType(pType.data.type);
                        ret = $"{GetTypeName(type)}*";
                        break;
                    }
                default:
                    ret = TypeString[(int)pType.type];
                    break;
            }

            return ret;
        }

        private static string GetCustomAttribute(int index, string padding = "")
        {
            if (!config.DumpAttribute || il2cpp.version < 21)
                return "";
            var attributeTypeRange = metadata.attributeTypeRanges[index];
            var sb = new StringBuilder();
            for (var i = 0; i < attributeTypeRange.count; i++)
            {
                var typeIndex = metadata.attributeTypes[attributeTypeRange.start + i];
                sb.AppendFormat("{0}[{1}] // 0x{2:X}\n", padding, GetTypeName(il2cpp.types[typeIndex]), il2cpp.customAttributeGenerators[index]);
            }
            return sb.ToString();
        }

        private static string GetModifiers(Il2CppMethodDefinition methodDef)
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

        private static string ToEscapedString(string s)
        {
            var re = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '\'':
                        re.Append(@"\'");
                        break;
                    case '"':
                        re.Append(@"\""");
                        break;
                    case '\t':
                        re.Append(@"\t");
                        break;
                    case '\n':
                        re.Append(@"\n");
                        break;
                    case '\r':
                        re.Append(@"\r");
                        break;
                    case '\f':
                        re.Append(@"\f");
                        break;
                    case '\b':
                        re.Append(@"\b");
                        break;
                    case '\\':
                        re.Append(@"\\");
                        break;
                    case '\0':
                        re.Append(@"\0");
                        break;
                    case '\u0085':
                        re.Append(@"\u0085");
                        break;
                    case '\u2028':
                        re.Append(@"\u2028");
                        break;
                    case '\u2029':
                        re.Append(@"\u2029");
                        break;
                    default:
                        re.Append(c);
                        break;
                }
            }
            return re.ToString();
        }
    }
}
