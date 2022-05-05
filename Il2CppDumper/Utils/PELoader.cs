﻿using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Il2CppDumper
{
    public class PELoader
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private extern static IntPtr LoadLibrary(string path);

        public static PE Load(string fileName)
        {
            var buff = File.ReadAllBytes(fileName);
            using (var reader = new BinaryStream(new MemoryStream(buff)))
            {
                var dosHeader = reader.ReadClass<DosHeader>();
                if (dosHeader.Magic != 0x5A4D)
                {
                    throw new InvalidDataException("ERROR: Invalid PE file");
                }
                reader.Position = dosHeader.Lfanew;
                if (reader.ReadUInt32() != 0x4550u) //Signature
                {
                    throw new InvalidDataException("ERROR: Invalid PE file");
                }
                var fileHeader = reader.ReadClass<FileHeader>();
                if ((fileHeader.Machine == 0x14c && Environment.Is64BitProcess) //64bit process can't load 32bit dll
                    || (fileHeader.Machine == 0x8664 && !Environment.Is64BitProcess)) //32bit process can't load 64bit dll
                {
                    return new PE(new MemoryStream(buff));
                }
                var pos = reader.Position;
                reader.Position = pos + fileHeader.SizeOfOptionalHeader;
                var sections = reader.ReadClassArray<SectionHeader>(fileHeader.NumberOfSections);
                var last = sections.Last();
                var size = last.VirtualAddress + last.VirtualSize;
                var peBuff = new byte[size];
                var handle = LoadLibrary(fileName);
                if (handle == IntPtr.Zero)
                {
                    //Missing dependent DLL
                    //throw new Win32Exception();
                    return new PE(new MemoryStream(buff));
                }
                foreach (var section in sections)
                {
                    switch (section.Characteristics)
                    {
                        case 0x60000020:
                        case 0x40000040:
                        case 0xC0000040:
                            Marshal.Copy(new IntPtr(handle.ToInt64() + section.VirtualAddress), peBuff, (int)section.VirtualAddress, (int)section.VirtualSize);
                            break;
                    }
                }
                var peMemory = new MemoryStream(peBuff);
                var writer = new BinaryWriter(peMemory, Encoding.UTF8, true);
                var headerSize = reader.Position;
                reader.Position = 0;
                var buff2 = reader.ReadBytes((int)headerSize);
                writer.Write(buff2);
                writer.Flush();
                writer.Close();
                peMemory.Position = 0;
                var pe = new PE(peMemory);
                pe.LoadFromMemory((ulong)handle.ToInt64());
                return pe;
            }
        }
    }
}
