using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace Il2CppDumper
{
    public class MyBinaryReader : BinaryReader
    {
        public float version;
        protected bool is32Bit;
        private MethodInfo readClass;


        public MyBinaryReader(Stream stream) : base(stream)
        {
            readClass = GetType().GetMethod("ReadClass", Type.EmptyTypes);
        }

        private object ReadPrimitive(Type type)
        {
            var typename = type.Name;
            switch (typename)
            {
                case "Int32":
                    return ReadInt32();
                case "UInt32":
                    return ReadUInt32();
                case "Int16":
                    return ReadInt16();
                case "UInt16":
                    return ReadUInt16();
                case "Byte":
                    return ReadByte();
                case "Int64" when is32Bit:
                    return ReadInt32();
                case "Int64":
                    return ReadInt64();
                case "UInt64" when is32Bit:
                    return ReadUInt32();
                case "UInt64":
                    return ReadUInt64();
                default:
                    return null;
            }
        }

        public dynamic Position
        {
            get => BaseStream.Position;
            set => BaseStream.Position = (long)value;
        }

        public T ReadClass<T>(dynamic addr) where T : new()
        {
            Position = addr;
            return ReadClass<T>();
        }

        public T ReadClass<T>() where T : new()
        {
            var type = typeof(T);
            if (type.IsPrimitive)
            {
                return (T)ReadPrimitive(type);
            }
            else
            {
                var t = new T();
                foreach (var i in t.GetType().GetFields())
                {
                    var attr = (VersionAttribute)Attribute.GetCustomAttribute(i, typeof(VersionAttribute));
                    if (attr != null)
                    {
                        if (version < attr.Min || version > attr.Max)
                            continue;
                    }
                    if (i.FieldType.IsPrimitive)
                    {
                        i.SetValue(t, ReadPrimitive(i.FieldType));
                    }
                    else
                    {
                        var gm = readClass.MakeGenericMethod(i.FieldType);
                        var o = gm.Invoke(this, null);
                        i.SetValue(t, o);
                        break;
                    }
                }
                return t;
            }
        }

        public T[] ReadClassArray<T>(long count) where T : new()
        {
            var t = new T[count];
            for (var i = 0; i < count; i++)
            {
                t[i] = ReadClass<T>();
            }
            return t;
        }

        public T[] ReadClassArray<T>(dynamic addr, long count) where T : new()
        {
            Position = addr;
            return ReadClassArray<T>(count);
        }

        public string ReadStringToNull(dynamic addr)
        {
            Position = addr;
            var bytes = new List<byte>();
            byte b;
            while ((b = ReadByte()) != 0)
                bytes.Add(b);
            return Encoding.UTF8.GetString(bytes.ToArray());
        }
    }
}
