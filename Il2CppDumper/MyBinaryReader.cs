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
        public bool is32Bit;

        private MethodInfo readClass;
        private Dictionary<Type, MethodInfo> readClassCache = new Dictionary<Type, MethodInfo>();
        private Dictionary<FieldInfo, VersionAttribute> attributeCache = new Dictionary<FieldInfo, VersionAttribute>();

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

        public ulong Position
        {
            get => (ulong)BaseStream.Position;
            set => BaseStream.Position = (long)value;
        }

        public T ReadClass<T>(ulong addr) where T : new()
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
                    if (!attributeCache.TryGetValue(i, out var versionAttribute))
                    {
                        if (Attribute.IsDefined(i, typeof(VersionAttribute)))
                        {
                            versionAttribute = (VersionAttribute)Attribute.GetCustomAttribute(i, typeof(VersionAttribute));
                            attributeCache.Add(i, versionAttribute);
                        }
                    }
                    if (versionAttribute != null)
                    {
                        if (version < versionAttribute.Min || version > versionAttribute.Max)
                            continue;
                    }
                    if (i.FieldType.IsPrimitive)
                    {
                        i.SetValue(t, ReadPrimitive(i.FieldType));
                    }
                    else
                    {
                        if (!readClassCache.TryGetValue(i.FieldType, out var methodInfo))
                        {
                            methodInfo = readClass.MakeGenericMethod(i.FieldType);
                            readClassCache.Add(i.FieldType, methodInfo);
                        }
                        var value = methodInfo.Invoke(this, null);
                        i.SetValue(t, value);
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

        public T[] ReadClassArray<T>(ulong addr, long count) where T : new()
        {
            Position = addr;
            return ReadClassArray<T>(count);
        }

        public string ReadStringToNull(ulong addr)
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
