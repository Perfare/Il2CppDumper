using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Il2CppDumper
{
    class MyBinaryReader : BinaryReader
    {
        public MyBinaryReader(Stream stream) : base(stream) { }

        public dynamic Position
        {
            get
            {
                return BaseStream.Position;
            }
            set
            {
                BaseStream.Position = (long)value;
            }
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
                if (type == typeof(int))
                {
                    return (T)(object)ReadInt32();
                }
                else if (type == typeof(uint))
                {
                    return (T)(object)ReadUInt32();
                }
                else if (type == typeof(long))
                {
                    return (T)(object)ReadInt64();
                }
                else if (type == typeof(ulong))
                {
                    return (T)(object)ReadUInt64();
                }
                else
                {
                    return default(T);
                }
            }
            else
            {
                var t = new T();
                foreach (var i in t.GetType().GetFields())
                {
                    if (i.FieldType == typeof(int))
                    {
                        i.SetValue(t, ReadInt32());
                    }
                    else if (i.FieldType == typeof(uint))
                    {
                        i.SetValue(t, ReadUInt32());
                    }
                    else if (i.FieldType == typeof(short))
                    {
                        i.SetValue(t, ReadInt16());
                    }
                    else if (i.FieldType == typeof(ushort))
                    {
                        i.SetValue(t, ReadUInt16());
                    }
                    else if (i.FieldType == typeof(byte))
                    {
                        i.SetValue(t, ReadByte());
                    }
                    else if (i.FieldType == typeof(long))
                    {
                        i.SetValue(t, ReadInt64());
                    }
                    else if (i.FieldType == typeof(ulong))
                    {
                        i.SetValue(t, ReadUInt64());
                    }
                    else
                    {
                        var mi = GetType().GetMethod("ReadClass", Type.EmptyTypes);
                        var mi2 = mi.MakeGenericMethod(i.FieldType);
                        var o = mi2.Invoke(this, null);
                        i.SetValue(t, o);
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
