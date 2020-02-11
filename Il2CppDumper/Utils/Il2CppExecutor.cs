using System.Collections.Generic;

namespace Il2CppDumper
{
    public class Il2CppExecutor
    {
        public Metadata metadata;
        public Il2Cpp il2Cpp;
        private static readonly Dictionary<int, string> TypeString = new Dictionary<int, string>
        {
            {1,"void"},
            {2,"bool"},
            {3,"char"},
            {4,"sbyte"},
            {5,"byte"},
            {6,"short"},
            {7,"ushort"},
            {8,"int"},
            {9,"uint"},
            {10,"long"},
            {11,"ulong"},
            {12,"float"},
            {13,"double"},
            {14,"string"},
            {22,"TypedReference"},
            {24,"IntPtr"},
            {25,"UIntPtr"},
            {28,"object"},
        };

        public Il2CppExecutor(Metadata metadata, Il2Cpp il2Cpp)
        {
            this.metadata = metadata;
            this.il2Cpp = il2Cpp;
        }

        public string GetTypeName(Il2CppType il2CppType, bool fullName, bool genericParameter)
        {
            string ret;
            switch (il2CppType.type)
            {
                case Il2CppTypeEnum.IL2CPP_TYPE_CLASS:
                case Il2CppTypeEnum.IL2CPP_TYPE_VALUETYPE:
                    {
                        var typeDef = metadata.typeDefs[il2CppType.data.klassIndex];
                        ret = GetTypeDefName(typeDef, fullName, genericParameter);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_GENERICINST:
                    {
                        var genericClass = il2Cpp.MapVATR<Il2CppGenericClass>(il2CppType.data.generic_class);
                        var typeDef = metadata.typeDefs[genericClass.typeDefinitionIndex];
                        ret = GetTypeDefName(typeDef, fullName, false);
                        var genericInst = il2Cpp.MapVATR<Il2CppGenericInst>(genericClass.context.class_inst);
                        ret = ret.Replace($"`{genericInst.type_argc}", "");
                        ret += GetGenericInstParams(genericInst);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_VAR:
                case Il2CppTypeEnum.IL2CPP_TYPE_MVAR:
                    {
                        var param = metadata.genericParameters[il2CppType.data.genericParameterIndex];
                        ret = metadata.GetStringFromIndex(param.nameIndex);
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_ARRAY:
                    {
                        var arrayType = il2Cpp.MapVATR<Il2CppArrayType>(il2CppType.data.array);
                        var oriType = il2Cpp.GetIl2CppType(arrayType.etype);
                        ret = $"{GetTypeName(oriType, fullName, genericParameter)}[{new string(',', arrayType.rank - 1)}]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_SZARRAY:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        ret = $"{GetTypeName(oriType, fullName, genericParameter)}[]";
                        break;
                    }
                case Il2CppTypeEnum.IL2CPP_TYPE_PTR:
                    {
                        var oriType = il2Cpp.GetIl2CppType(il2CppType.data.type);
                        ret = $"{GetTypeName(oriType, fullName, genericParameter)}*";
                        break;
                    }
                default:
                    ret = TypeString[(int)il2CppType.type];
                    break;
            }
            return ret;
        }

        public string GetTypeDefName(Il2CppTypeDefinition typeDef, bool fullName, bool genericParameter)
        {
            var prefix = string.Empty;
            if (typeDef.declaringTypeIndex != -1)
            {
                prefix = GetTypeName(il2Cpp.types[typeDef.declaringTypeIndex], fullName, genericParameter) + ".";
            }
            else if (fullName)
            {
                prefix = metadata.GetStringFromIndex(typeDef.namespaceIndex) + ".";
            }
            var typeName = metadata.GetStringFromIndex(typeDef.nameIndex);
            if (typeDef.genericContainerIndex >= 0)
            {
                var genericContainer = metadata.genericContainers[typeDef.genericContainerIndex];
                typeName = typeName.Replace($"`{genericContainer.type_argc}", "");
                if (genericParameter)
                {
                    var genericParameterNames = new List<string>();
                    for (int i = 0; i < genericContainer.type_argc; i++)
                    {
                        var genericParameterIndex = genericContainer.genericParameterStart + i;
                        var param = metadata.genericParameters[genericParameterIndex];
                        genericParameterNames.Add(metadata.GetStringFromIndex(param.nameIndex));
                    }
                    typeName += $"<{string.Join(", ", genericParameterNames)}>";
                }
            }
            return prefix + typeName;
        }

        public string GetGenericInstParams(Il2CppGenericInst genericInst)
        {
            var typeNames = new List<string>();
            var pointers = il2Cpp.MapVATR<ulong>(genericInst.type_argv, genericInst.type_argc);
            for (uint i = 0; i < genericInst.type_argc; ++i)
            {
                var oriType = il2Cpp.GetIl2CppType(pointers[i]);
                typeNames.Add(GetTypeName(oriType, false, true));
            }
            return $"<{string.Join(", ", typeNames)}>";
        }
    }
}
