using System;

namespace Il2CppDumper
{
    [AttributeUsage(AttributeTargets.Field)]
    class VersionAttribute : Attribute
    {
        public int Min { get; set; } = 0;
        public int Max { get; set; } = 99;
    }
}
