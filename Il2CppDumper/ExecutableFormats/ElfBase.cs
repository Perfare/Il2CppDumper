using System;
using System.IO;

namespace Il2CppDumper
{
    public abstract class ElfBase : Il2Cpp
    {
        public bool IsDumped;
        public ulong DumpAddr;

        protected ElfBase(Stream stream) : base(stream) { }

        public void GetDumpAddress()
        {
            Console.WriteLine("Detected this may be a dump file.");
            Console.WriteLine("Input il2cpp dump address or input 0 to force continue:");
            DumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
            if (DumpAddr != 0)
            {
                IsDumped = true;
            }
        }
    }
}
