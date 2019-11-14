using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
        public bool DummyDll = true;
        public bool MakeFunction = false;
        public bool ForceIl2CppVersion = false;
        public int ForceVersion = 16;
    }
}
