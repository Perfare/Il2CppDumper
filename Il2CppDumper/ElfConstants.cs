namespace Il2CppDumper
{
    static class ElfConstants
    {
        public const int EM_386 = 3;
        public const int EM_ARM = 40;

        public const int PT_LOAD = 1;
        public const int PT_DYNAMIC = 2;

        public const int PF_X = 1;

        public const int DT_PLTGOT = 3;
        public const int DT_HASH = 4;
        public const int DT_STRTAB = 5;
        public const int DT_SYMTAB = 6;
        public const int DT_RELA = 7;
        public const int DT_RELASZ = 8;
        public const int DT_RELAENT = 9;
        public const int DT_SYMENT = 11;
        public const int DT_INIT = 12;
        public const int DT_REL = 17;
        public const int DT_RELSZ = 18;
        public const int DT_JMPREL = 23;
        public const int DT_INIT_ARRAY = 25;
        public const int DT_FINI_ARRAY = 26;
        public const int DT_INIT_ARRAYSZ = 27;

        public const int R_ARM_ABS32 = 2;

        public const int R_386_32 = 1;

        public const int R_AARCH64_ABS64 = 257;
        public const int R_AARCH64_RELATIVE = 1027;
    }
}