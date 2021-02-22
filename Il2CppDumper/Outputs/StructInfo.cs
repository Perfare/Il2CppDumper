using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    public class StructInfo
    {
        public string TypeName;
        public bool IsValueType;
        public string Parent;
        public List<StructFieldInfo> Fields = new List<StructFieldInfo>();
        public List<StructFieldInfo> StaticFields = new List<StructFieldInfo>();
        public StructVTableMethodInfo[] VTableMethod = Array.Empty<StructVTableMethodInfo>();
        public List<StructRGCTXInfo> RGCTXs = new List<StructRGCTXInfo>();
    }

    public class StructFieldInfo
    {
        public string FieldTypeName;
        public string FieldName;
        public bool IsValueType;
        public bool IsCustomType;
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
