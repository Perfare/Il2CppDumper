using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    public class StructInfo
    {
        public string TypeName;
        public bool IsValueType;
        public bool IsExplicitLayout;
        public int NativeSize;
        public string Parent;
        public List<StructFieldInfo> Fields = new();
        public List<StructFieldInfo> StaticFields = new();
        public StructVTableMethodInfo[] VTableMethod = Array.Empty<StructVTableMethodInfo>();
        public List<StructRGCTXInfo> RGCTXs = new();
    }

    public class StructFieldInfo
    {
        public string FieldTypeName;
        public string FieldName;
        public bool IsValueType;
        public bool IsCustomType;
        public int Offset = -1;
    }

    public class StructVTableMethodInfo
    {
        public string MethodName;
    }

    public class StructRGCTXInfo
    {
        public Il2CppRGCTXDataType Type;
        public string TypeName;
        public string ClassName;
        public string MethodName;
    }
}
