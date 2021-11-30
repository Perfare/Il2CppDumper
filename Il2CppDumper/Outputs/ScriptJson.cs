using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Il2CppDumper
{
    public class ScriptJson
    {
        public List<ScriptMethod> ScriptMethod = new List<ScriptMethod>();
        public List<ScriptString> ScriptString = new List<ScriptString>();
        public List<ScriptMetadata> ScriptMetadata = new List<ScriptMetadata>();
        public List<ScriptMetadataMethod> ScriptMetadataMethod = new List<ScriptMetadataMethod>();
        public ulong[] Addresses;
    }

    public class ScriptMethod
    {
        public ulong Address;
        public string Name;
        public string Signature;
        public string TypeSignature;
    }

    public class ScriptString
    {
        public ulong Address;
        public string Value;
    }

    public class ScriptMetadata
    {
        public ulong Address;
        public string Name;
        public string Signature;
    }

    public class ScriptMetadataMethod
    {
        public ulong Address;
        public string Name;
        public ulong MethodAddress;
    }
}
