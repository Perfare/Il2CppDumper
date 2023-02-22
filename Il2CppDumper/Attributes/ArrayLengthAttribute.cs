using System;

namespace Il2CppDumper
{
    [AttributeUsage(AttributeTargets.Field)]
    class ArrayLengthAttribute : Attribute
    {
        public int Length { get; set; }
    }
}
