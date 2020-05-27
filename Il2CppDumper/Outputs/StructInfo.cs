﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppDumper
{
    public class StructInfo
    {
        public string TypeName;
        public bool IsValueType;
        public List<StructFieldInfo> Fields = new List<StructFieldInfo>();
        public List<StructFieldInfo> StaticFields = new List<StructFieldInfo>();
        public List<StructVTableMethodInfo> VTableMethod = new List<StructVTableMethodInfo>();

        public List<StructMethodInfo> Methods = new List<StructMethodInfo>();
    }

    public class StructFieldInfo
    {
        public string FieldTypeName;
        public string FieldName;
        public bool IsValueType;
    }

    public class StructVTableMethodInfo
    {
        public string MethodName;
    }

    public class StructMethodInfo : IEquatable<StructMethodInfo> {
        public ulong Address;

        public string FnFormat;
        public string Signature;

        public bool Equals(StructMethodInfo other) {
            return this.Address == other.Address;
        }
    }
}
