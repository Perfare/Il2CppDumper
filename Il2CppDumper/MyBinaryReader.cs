using System;
using System.IO;

namespace Il2CppDumper
{
    class MyBinaryReader : BinaryReader
    {
        public MyBinaryReader(Stream stream) : base(stream) { }

        public long Position
        {
            get
            {
                return BaseStream.Position;
            }
            set
            {
                BaseStream.Position = value;
            }
        }

        public T ReadClass<T>(long addr) where T : new()
        {
            BaseStream.Position = addr;
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
                else
                {
                    return default(T);
                }
            }
            else
            {
                T t = new T();
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

        public T[] ReadClassArray<T>(long addr, int count) where T : new()
        {
            BaseStream.Position = addr;
            var type = typeof(T);
            if (type.IsPrimitive)
            {
                if (type == typeof(int))
                {
                    int[] t = new int[count];
                    for (int i = 0; i < count; i++)
                    {
                        t[i] = ReadInt32();
                    }
                    return t as T[];
                }
                else if (type == typeof(uint))
                {
                    uint[] t = new uint[count];
                    for (int i = 0; i < count; i++)
                    {
                        t[i] = ReadUInt32();
                    }
                    return t as T[];
                }
                else
                {
                    return null;
                }
            }
            else
            {
                T[] t = new T[count];
                for (int i = 0; i < count; i++)
                {
                    t[i] = ReadClass<T>();
                }
                return t;
            }
        }

        public string ReadStringToNull(long addr)
        {
            BaseStream.Position = addr;
            string result = "";
            char c;
            for (int i = 0; i < base.BaseStream.Length; i++)
            {
                if ((c = (char)base.ReadByte()) == 0)
                {
                    break;
                }
                result += c.ToString();
            }
            return result;
        }
    }
}
