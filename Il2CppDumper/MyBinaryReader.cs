using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Il2CppDumper
{
    class MyBinaryReader : BinaryReader
    {
        public MyBinaryReader(Stream stream) : base(stream) { }

        public int version;

        protected bool readas32bit;

        private Dictionary<string, string> _64bitTo32bit = new Dictionary<string, string>()
        {
            {"Int64", "Int32"},
            {"UInt64", "UInt32"}
        };

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
                var typename = type.Name;
                if (readas32bit && _64bitTo32bit.ContainsKey(typename))
                    typename = _64bitTo32bit[typename];
                switch (typename)
                {
                    case "Int32":
                        return (T)(object)ReadInt32();
                    case "UInt32":
                        return (T)(object)ReadUInt32();
                    case "Int16":
                        return (T)(object)ReadInt16();
                    case "UInt16":
                        return (T)(object)ReadUInt16();
                    case "Byte":
                        return (T)(object)ReadByte();
                    case "Int64":
                        return (T)(object)ReadInt64();
                    case "UInt64":
                        return (T)(object)ReadUInt64();
                    default:
                        return default(T);
                }
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
                    var typename = i.FieldType.Name;
                    if (readas32bit && _64bitTo32bit.ContainsKey(typename))
                        typename = _64bitTo32bit[typename];
                    switch (typename)
                    {
                        case "Int32":
                            i.SetValue(t, ReadInt32());
                            break;
                        case "UInt32":
                            i.SetValue(t, ReadUInt32());
                            break;
                        case "Int16":
                            i.SetValue(t, ReadInt16());
                            break;
                        case "UInt16":
                            i.SetValue(t, ReadUInt16());
                            break;
                        case "Byte":
                            i.SetValue(t, ReadByte());
                            break;
                        case "Int64":
                            i.SetValue(t, ReadInt64());
                            break;
                        case "UInt64":
                            i.SetValue(t, ReadUInt64());
                            break;
                        default:
                            var mi = GetType().GetMethod("ReadClass", Type.EmptyTypes);
                            var mi2 = mi.MakeGenericMethod(i.FieldType);
                            var o = mi2.Invoke(this, null);
                            i.SetValue(t, o);
                            break;
                    }
                }
                return t;
            }
        }

        public T[] ReadClassArray<T>(dynamic addr, long count) where T : new()
        {
            Position = addr;
            var t = new T[count];
            for (var i = 0; i < count; i++)
            {
                t[i] = ReadClass<T>();
            }
            return t;
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
