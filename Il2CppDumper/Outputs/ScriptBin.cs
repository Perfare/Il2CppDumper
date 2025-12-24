using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public class CBinaryWriter : BinaryWriter
    {
        public CBinaryWriter(Stream stream, Encoding encoding) : base(stream, encoding)
        {
        }

        public void WriteString0(string str)
        {
            if (str == null)
            {
                Write(0);
                return;
            }
            if (str.Any(x => x > byte.MaxValue || x == 0))
            {
                var lastIndex = 0;
                var builder = new StringBuilder();
                for (var index = 0; index < str.Length; index++)
                {
                    var ch = str[index];
                    if (ch == 0)
                    {
                        lastIndex = index + 1;
                    }
                    else if (ch > byte.MaxValue)
                    {
                        var len = index - lastIndex;
                        if (len > 0)
                        {
                            builder.Append(str.Substring(lastIndex, len));
                        }
                        builder.AppendFormat("\\u{0:X}", (int)ch);
                        lastIndex = index + 1;
                    }
                }
                str = builder.ToString();
            }
            if (str.Length == 0)
            {
                Write(0);
                return;
            }
            var buffer = Encoding.ASCII.GetBytes(str);
            if (buffer.Any(v => v == 0))
            {
                Console.WriteLine($"bad string: {str}");
                Write(0);
                return;
            }
            Write(buffer.Length);
            Write(buffer);
        }

        public void Write<T>(IList<T> list, Action<CBinaryWriter, T> write)
        {
            Write(list.Count);
            foreach (var item in list)
            {
                write(this, item);
                Write(BaseStream.Position);
            }
        }
    }

    public class CBinaryReader : BinaryReader
    {
        public CBinaryReader(Stream stream, Encoding encoding) : base(stream, encoding)
        {
        }

        public string ReadString0()
        {
            var buffer = new List<byte>();
            while (true)
            {
                var data = ReadByte();
                if (data == 0) break;
                buffer.Add(data);
            }
            return Encoding.ASCII.GetString(buffer.ToArray());
        }

        public List<T> Read<T>(Func<CBinaryReader, T> reader)
        {
            var count = ReadInt32();
            var list = new List<T>(count);
            for (var i = 0; i < count; i++)
            {
                var item = reader(this);
                list.Add(item);
            }
            return list;
        }
    }

    public static class ScriptBin
    {
        public static void WriteFile(string filename, ScriptJson json)
        {
            using var file = File.Create(filename);
            var binary = new CBinaryWriter(file, Encoding.ASCII);
            binary.Write(json.ScriptMethod, Write);
            binary.Write(json.ScriptString, Write);
            binary.Write(json.ScriptMetadata, Write);
            binary.Write(json.ScriptMetadataMethod, Write);
            binary.Write(json.Addresses, Write);
            file.Close();
        }

        public static void ReadFile(string filename)
        {
            using var file = File.OpenRead(filename);
            var binary = new CBinaryReader(file, Encoding.ASCII);
            var json = new ScriptJson();
            json.ScriptMethod = binary.Read(ReadScriptMethod);
            json.ScriptString = binary.Read(ReadScriptString);
            json.ScriptMetadata = binary.Read(ReadReadScriptMetadata);
            json.ScriptMetadataMethod = binary.Read(ReadScriptMetadataMethod);
            file.Close();
        }

        private static ScriptMethod ReadScriptMethod(CBinaryReader reader)
        {
            var o = new ScriptMethod();
            o.Address = reader.ReadUInt64();
            o.Name = reader.ReadString0();
            o.Signature = reader.ReadString0();
            o.TypeSignature = reader.ReadString0();
            return o;
        }

        private static ScriptString ReadScriptString(CBinaryReader reader)
        {
            var o = new ScriptString();
            o.Address = reader.ReadUInt64();
            o.Value = reader.ReadString0();
            return o;
        }

        private static ScriptMetadata ReadReadScriptMetadata(CBinaryReader reader)
        {
            var o = new ScriptMetadata();
            o.Address = reader.ReadUInt64();
            o.Name = reader.ReadString0();
            o.Signature = reader.ReadString0();
            return o;
        }

        private static ScriptMetadataMethod ReadScriptMetadataMethod(CBinaryReader reader)
        {
            var o = new ScriptMetadataMethod();
            o.Address = reader.ReadUInt64();
            o.Name = reader.ReadString0();
            o.MethodAddress = reader.ReadUInt64();
            return o;
        }

        private static void Write(CBinaryWriter writer, ScriptMethod o)
        {
            writer.Write(o.Address);
            writer.WriteString0(o.Name);
            writer.WriteString0(o.Signature);
            writer.WriteString0(o.TypeSignature);
        }

        private static void Write(CBinaryWriter writer, ScriptString o)
        {
            writer.Write(o.Address);
            writer.WriteString0(o.Value);
        }

        private static void Write(CBinaryWriter writer, ScriptMetadata o)
        {
            writer.Write(o.Address);
            writer.WriteString0(o.Name);
            writer.WriteString0(o.Signature);
        }

        private static void Write(CBinaryWriter writer, ScriptMetadataMethod o)
        {
            writer.Write(o.Address);
            writer.WriteString0(o.Name);
            writer.Write(o.MethodAddress);
        }

        private static void Write(CBinaryWriter writer, ulong o)
        {
            writer.Write(o);
        }
    }
}