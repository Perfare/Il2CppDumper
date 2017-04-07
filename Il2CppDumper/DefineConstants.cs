namespace Il2CppDumper
{
    internal static class DefineConstants
    {
        public const int FIELD_ATTRIBUTE_FIELD_ACCESS_MASK = 0x0007;
        public const int FIELD_ATTRIBUTE_PRIVATE = 0x0001;
        public const int FIELD_ATTRIBUTE_FAMILY = 0x0004;
        public const int FIELD_ATTRIBUTE_PUBLIC = 0x0006;
        public const int FIELD_ATTRIBUTE_STATIC = 0x0010;
        public const int FIELD_ATTRIBUTE_INIT_ONLY = 0x0020;
        public const int METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK = 0x0007;
        public const int METHOD_ATTRIBUTE_PRIVATE = 0x0001;
        public const int METHOD_ATTRIBUTE_FAMILY = 0x0004;
        public const int METHOD_ATTRIBUTE_PUBLIC = 0x0006;
        public const int METHOD_ATTRIBUTE_STATIC = 0x0010;
        public const int METHOD_ATTRIBUTE_VIRTUAL = 0x0040;
        public const int METHOD_ATTRIBUTE_ABSTRACT = 0x0400;
        public const int TYPE_ATTRIBUTE_VISIBILITY_MASK = 0x00000007;
        public const int TYPE_ATTRIBUTE_NOT_PUBLIC = 0x00000000;
        public const int TYPE_ATTRIBUTE_PUBLIC = 0x00000001;
        public const int TYPE_ATTRIBUTE_INTERFACE = 0x00000020;
        public const int TYPE_ATTRIBUTE_ABSTRACT = 0x00000080;
        public const int TYPE_ATTRIBUTE_SEALED = 0x00000100;
        public const int TYPE_ATTRIBUTE_SERIALIZABLE = 0x00002000;
        public const int PARAM_ATTRIBUTE_OUT = 0x0002;
        public const int PARAM_ATTRIBUTE_OPTIONAL = 0x0010;


        public static string[] szTypeString =
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
            "PTR", //eg. void*
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