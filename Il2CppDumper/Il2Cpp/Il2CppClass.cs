using System;

namespace Il2CppDumper
{
    public class Il2CppCodeRegistration
    {
        [Version(Max = 24.1)]
        public ulong methodPointersCount;
        [Version(Max = 24.1)]
        public ulong methodPointers;
        [Version(Max = 21)]
        public ulong delegateWrappersFromNativeToManagedCount;
        [Version(Max = 21)]
        public ulong delegateWrappersFromNativeToManaged; // note the double indirection to handle different calling conventions
        [Version(Min = 22)]
        public ulong reversePInvokeWrapperCount;
        [Version(Min = 22)]
        public ulong reversePInvokeWrappers;
        [Version(Max = 22)]
        public ulong delegateWrappersFromManagedToNativeCount;
        [Version(Max = 22)]
        public ulong delegateWrappersFromManagedToNative;
        [Version(Max = 22)]
        public ulong marshalingFunctionsCount;
        [Version(Max = 22)]
        public ulong marshalingFunctions;
        [Version(Min = 21, Max = 22)]
        public ulong ccwMarshalingFunctionsCount;
        [Version(Min = 21, Max = 22)]
        public ulong ccwMarshalingFunctions;
        public ulong genericMethodPointersCount;
        public ulong genericMethodPointers;
        [Version(Min = 24.5, Max = 24.5)]
        [Version(Min = 27.1)]
        public ulong genericAdjustorThunks;
        public ulong invokerPointersCount;
        public ulong invokerPointers;
        [Version(Max = 24.5)]
        public ulong customAttributeCount;
        [Version(Max = 24.5)]
        public ulong customAttributeGenerators;
        [Version(Min = 21, Max = 22)]
        public ulong guidCount;
        [Version(Min = 21, Max = 22)]
        public ulong guids; // Il2CppGuid
        [Version(Min = 22)]
        public ulong unresolvedVirtualCallCount; //29.1 unresolvedIndirectCallCount;
        [Version(Min = 22)]
        public ulong unresolvedVirtualCallPointers;
        [Version(Min = 29.1)]
        public ulong unresolvedInstanceCallPointers;
        [Version(Min = 29.1)]
        public ulong unresolvedStaticCallPointers;
        [Version(Min = 23)]
        public ulong interopDataCount;
        [Version(Min = 23)]
        public ulong interopData;
        [Version(Min = 24.3)]
        public ulong windowsRuntimeFactoryCount;
        [Version(Min = 24.3)]
        public ulong windowsRuntimeFactoryTable;
        [Version(Min = 24.2)]
        public ulong codeGenModulesCount;
        [Version(Min = 24.2)]
        public ulong codeGenModules;
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
        [Version(Max = 16)]
        public long methodReferencesCount;
        [Version(Max = 16)]
        public ulong methodReferences;

        public long fieldOffsetsCount;
        public ulong fieldOffsets;

        public long typeDefinitionsSizesCount;
        public ulong typeDefinitionsSizes;
        [Version(Min = 19)]
        public ulong metadataUsagesCount;
        [Version(Min = 19)]
        public ulong metadataUsages;
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
        IL2CPP_TYPE_GENERICINST = 0x15,     /* <type> <type-arg-count> <type-1> \x{2026} <type-n> */
        IL2CPP_TYPE_TYPEDBYREF = 0x16,
        IL2CPP_TYPE_I = 0x18,
        IL2CPP_TYPE_U = 0x19,
        IL2CPP_TYPE_FNPTR = 0x1b,        /* arg: full method signature */
        IL2CPP_TYPE_OBJECT = 0x1c,
        IL2CPP_TYPE_SZARRAY = 0x1d,       /* 0-based one-dim-array */
        IL2CPP_TYPE_MVAR = 0x1e,       /* Generic parameter in a generic method definition, represented as number (compressed unsigned integer)  */
        IL2CPP_TYPE_CMOD_REQD = 0x1f,       /* arg: typedef or typeref token */
        IL2CPP_TYPE_CMOD_OPT = 0x20,       /* optional arg: typedef or typref token */
        IL2CPP_TYPE_INTERNAL = 0x21,       /* CLR internal type */

        IL2CPP_TYPE_MODIFIER = 0x40,       /* Or with the following types */
        IL2CPP_TYPE_SENTINEL = 0x41,       /* Sentinel for varargs method signature */
        IL2CPP_TYPE_PINNED = 0x45,       /* Local var that points to pinned object */

        IL2CPP_TYPE_ENUM = 0x55,        /* an enumeration */
        IL2CPP_TYPE_IL2CPP_TYPE_INDEX = 0xff        /* an index into IL2CPP type metadata table */
    }

    public class Il2CppType
    {
        public ulong datapoint;
        public uint bits;
        public Union data { get; set; }
        public uint attrs { get; set; }
        public Il2CppTypeEnum type { get; set; }
        public uint num_mods { get; set; }
        public uint byref { get; set; }
        public uint pinned { get; set; }
        public uint valuetype { get; set; }

        public void Init(double version)
        {
            attrs = bits & 0xffff;
            type = (Il2CppTypeEnum)((bits >> 16) & 0xff);
            if (version >= 27.2)
            {
                num_mods = (bits >> 24) & 0x1f;
                byref = (bits >> 29) & 1;
                pinned = (bits >> 30) & 1;
                valuetype = bits >> 31;
            }
            else
            {
                num_mods = (bits >> 24) & 0x3f;
                byref = (bits >> 30) & 1;
                pinned = bits >> 31;
            }
            data = new Union { dummy = datapoint };
        }

        public class Union
        {
            public ulong dummy;
            /// <summary>
            /// for VALUETYPE and CLASS
            /// </summary>
            public long klassIndex => (long)dummy;
            /// <summary>
            /// for VALUETYPE and CLASS at runtime
            /// </summary>
            public ulong typeHandle => dummy;
            /// <summary>
            /// for PTR and SZARRAY
            /// </summary>
            public ulong type => dummy;
            /// <summary>
            /// for ARRAY
            /// </summary>
            public ulong array => dummy;
            /// <summary>
            /// for VAR and MVAR
            /// </summary>
            public long genericParameterIndex => (long)dummy;
            /// <summary>
            /// for VAR and MVAR at runtime
            /// </summary>
            public ulong genericParameterHandle => dummy;
            /// <summary>
            /// for GENERICINST
            /// </summary>
            public ulong generic_class => dummy;
        }
    }

    public class Il2CppGenericClass
    {
        [Version(Max = 24.5)]
        public long typeDefinitionIndex;    /* the generic type definition */
        [Version(Min = 27)]
        public ulong type;        /* the generic type definition */
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
        public long type_argc;
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

    public class Il2CppGenericMethodFunctionsDefinitions
    {
        public int genericMethodIndex;
        public Il2CppGenericMethodIndices indices;
    }

    public class Il2CppGenericMethodIndices
    {
        public int methodIndex;
        public int invokerIndex;
        [Version(Min = 24.5, Max = 24.5)]
        [Version(Min = 27.1)]
        public int adjustorThunk;
    };

    public class Il2CppMethodSpec
    {
        public int methodDefinitionIndex;
        public int classIndexIndex;
        public int methodIndexIndex;
    };

    public class Il2CppCodeGenModule
    {
        public ulong moduleName;
        public long methodPointerCount;
        public ulong methodPointers;
        [Version(Min = 24.5, Max = 24.5)]
        [Version(Min = 27.1)]
        public long adjustorThunkCount;
        [Version(Min = 24.5, Max = 24.5)]
        [Version(Min = 27.1)]
        public ulong adjustorThunks;
        public ulong invokerIndices;
        public ulong reversePInvokeWrapperCount;
        public ulong reversePInvokeWrapperIndices;
        public long rgctxRangesCount;
        public ulong rgctxRanges;
        public long rgctxsCount;
        public ulong rgctxs;
        public ulong debuggerMetadata;
        [Version(Min = 27, Max = 27.2)]
        public ulong customAttributeCacheGenerator;
        [Version(Min = 27)]
        public ulong moduleInitializer;
        [Version(Min = 27)]
        public ulong staticConstructorTypeIndices;
        [Version(Min = 27)]
        public ulong metadataRegistration; // Per-assembly mode only
        [Version(Min = 27)]
        public ulong codeRegistaration; // Per-assembly mode only
    }

    public class Il2CppRange
    {
        public int start;
        public int length;
    }

    public class Il2CppTokenRangePair
    {
        public uint token;
        public Il2CppRange range;
    }
}
