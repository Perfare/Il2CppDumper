namespace Il2CppDumper
{
    public class Config
    {
        public bool DumpMethod = true;
        public bool DumpField = true;
        public bool DumpProperty = false;
        public bool DumpAttribute = false;
        public bool DumpFieldOffset = true;
        public bool DumpMethodOffset = true;
        public bool DumpTypeDefIndex = true;
        public bool GenerateDummyDll = true;
        public bool GenerateStruct = true;
        public bool DummyDllAddToken = true;
        public bool RequireAnyKey = true;
        public bool ForceIl2CppVersion = false;
        public double ForceVersion = 24.3;
        public bool ForceDump = false;
        public bool NoRedirectedPointer = false;
    }
}
