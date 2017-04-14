using System;
using System.Linq;

namespace Il2CppDumper.v16._64bit
{
    public class Il2CppCodeRegistration
    {
        public ulong methodPointersCount;
        public ulong methodPointers;
        public ulong delegateWrappersFromNativeToManagedCount;
        public ulong delegateWrappersFromNativeToManaged; // note the double indirection to handle different calling conventions
        public ulong delegateWrappersFromManagedToNativeCount;
        public ulong delegateWrappersFromManagedToNative;
        public ulong marshalingFunctionsCount;
        public ulong marshalingFunctions;
        public ulong genericMethodPointersCount;
        public ulong genericMethodPointers;
        public ulong invokerPointersCount;
        public ulong invokerPointers;
        public long customAttributeCount;
        public ulong customAttributeGenerators;
    }

    public class Il2CppMetadataRegistration
    {
        public long genericClassesCount;
        public ulong genericClasses;
        public long genericInstsCount;
        public ulong genericInsts;
        public long genericMethodTableCount;
        public ulong genericMethodTable;
        public long typesCount;
        public ulong types;
        public long methodSpecsCount;
        public ulong methodSpecs;
        public long methodReferencesCount;
        public ulong methodReferences;

        public long fieldOffsetsCount;
        public ulong fieldOffsets;

        public long typeDefinitionsSizesCount;
        public ulong typeDefinitionsSizes;
    }

    public enum Il2CppTypeEnum
    {
        IL2CPP_TYPE_END = 0x00,       /* End of List */
        IL2CPP_TYPE_VOID = 0x01,
        IL2CPP_TYPE_BOOLEAN = 0x02,
        IL2CPP_TYPE_CHAR = 0x03,
        IL2CPP_TYPE_I1 = 0x04,
        IL2CPP_TYPE_U1 = 0x05,
        IL2CPP_TYPE_I2 = 0x06,
        IL2CPP_TYPE_U2 = 0x07,
        IL2CPP_TYPE_I4 = 0x08,
        IL2CPP_TYPE_U4 = 0x09,
        IL2CPP_TYPE_I8 = 0x0a,
        IL2CPP_TYPE_U8 = 0x0b,
        IL2CPP_TYPE_R4 = 0x0c,
        IL2CPP_TYPE_R8 = 0x0d,
        IL2CPP_TYPE_STRING = 0x0e,
        IL2CPP_TYPE_PTR = 0x0f,       /* arg: <type> token */
        IL2CPP_TYPE_BYREF = 0x10,       /* arg: <type> token */
        IL2CPP_TYPE_VALUETYPE = 0x11,       /* arg: <type> token */
        IL2CPP_TYPE_CLASS = 0x12,       /* arg: <type> token */
        IL2CPP_TYPE_VAR = 0x13,       /* Generic parameter in a generic type definition, represented as number (compressed unsigned integer) number */
        IL2CPP_TYPE_ARRAY = 0x14,       /* type, rank, boundsCount, bound1, loCount, lo1 */
        IL2CPP_TYPE_GENERICINST = 0x15,    /* <type> <type-arg-count> <type-1> \x{2026} <type-n> */
        IL2CPP_TYPE_TYPEDBYREF = 0x16,
        IL2CPP_TYPE_I = 0x18,
        IL2CPP_TYPE_U = 0x19,
        IL2CPP_TYPE_FNPTR = 0x1b,         /* arg: full method signature */
        IL2CPP_TYPE_OBJECT = 0x1c,
        IL2CPP_TYPE_SZARRAY = 0x1d,       /* 0-based one-dim-array */
        IL2CPP_TYPE_MVAR = 0x1e,       /* Generic parameter in a generic method definition, represented as number (compressed unsigned integer)  */
        IL2CPP_TYPE_CMOD_REQD = 0x1f,       /* arg: typedef or typeref token */
        IL2CPP_TYPE_CMOD_OPT = 0x20,       /* optional arg: typedef or typref token */
        IL2CPP_TYPE_INTERNAL = 0x21,       /* CLR internal type */

        IL2CPP_TYPE_MODIFIER = 0x40,       /* Or with the following types */
        IL2CPP_TYPE_SENTINEL = 0x41,       /* Sentinel for varargs method signature */
        IL2CPP_TYPE_PINNED = 0x45,       /* Local var that points to pinned object */

        IL2CPP_TYPE_ENUM = 0x55        /* an enumeration */
    }

    public class Il2CppType
    {
        public ulong datapoint;
        public Union data { get; set; }
        public uint bits;
        public uint attrs { get; set; }
        public Il2CppTypeEnum type { get; set; }
        public uint num_mods { get; set; }
        public uint byref { get; set; }
        public uint pinned { get; set; }

        public void Init()
        {
            var str = Convert.ToString(bits, 2);
            if (str.Length != 32)
            {
                str = new string(Enumerable.Repeat('0', 32 - str.Length).Concat(str.ToCharArray()).ToArray());
            }
            attrs = Convert.ToUInt32(str.Substring(16, 16), 2);
            type = (Il2CppTypeEnum)Convert.ToInt32(str.Substring(8, 8), 2);
            num_mods = Convert.ToUInt32(str.Substring(2, 6), 2);
            byref = Convert.ToUInt32(str.Substring(1, 1), 2);
            pinned = Convert.ToUInt32(str.Substring(0, 1), 2);
            data = new Union { dummy = datapoint };
        }

        public class Union
        {
            public ulong dummy;
            public long klassIndex => (long)dummy;
            public ulong type => dummy;
            public ulong array => dummy;
            public long genericParameterIndex => (long)dummy;
            public ulong generic_class => dummy;
        }
    }

    public class Il2CppGenericClass
    {
        public long typeDefinitionIndex;    /* the generic type definition */
        public Il2CppGenericContext context;   /* a context that contains the type instantiation doesn't contain any method instantiation */
        public ulong cached_class; /* if present, the Il2CppClass corresponding to the instantiation.  */
    }

    public class Il2CppGenericContext
    {
        /* The instantiation corresponding to the class generic parameters */
        public ulong class_inst;
        /* The instantiation corresponding to the method generic parameters */
        public ulong method_inst;
    }

    public class Il2CppGenericInst
    {
        public ulong type_argc;
        public ulong type_argv;
    }

    public class Il2CppArrayType
    {
        public ulong etype;
        public byte rank;
        public byte numsizes;
        public byte numlobounds;
        public ulong sizes;
        public ulong lobounds;
    }
}
