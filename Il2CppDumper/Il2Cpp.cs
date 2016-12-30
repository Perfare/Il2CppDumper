using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    class Il2Cpp : Elf
    {
        Il2CppMetadataRegistration pMetadataRegistration;
        public Il2CppCodeRegistration pCodeRegistration;

        public Il2Cpp(Stream stream) : base(stream)
        {
            if (!Auto())
            {
                throw new Exception("ERROR: Unable to process file automatically, try to use manual mode.");
            }
        }

        public Il2Cpp(Stream stream, uint codeRegistration, uint metadataRegistration) : base(stream)
        {
            Init(codeRegistration, metadataRegistration);
        }

        private void Init(uint codeRegistration, uint metadataRegistration)
        {
            pCodeRegistration = MapVATR<Il2CppCodeRegistration>(codeRegistration);
            pMetadataRegistration = MapVATR<Il2CppMetadataRegistration>(metadataRegistration);
            pCodeRegistration.methodPointers = MapVATR<uint>(pCodeRegistration.pmethodPointers, (int)pCodeRegistration.methodPointersCount);
            pMetadataRegistration.fieldOffsets = MapVATR<int>(pMetadataRegistration.pfieldOffsets, pMetadataRegistration.fieldOffsetsCount);
            var types = MapVATR<uint>(pMetadataRegistration.ptypes, pMetadataRegistration.typesCount);
            pMetadataRegistration.types = new Il2CppType[pMetadataRegistration.typesCount];
            for (int i = 0; i < pMetadataRegistration.typesCount; ++i)
            {
                pMetadataRegistration.types[i] = MapVATR<Il2CppType>(types[i]);
                pMetadataRegistration.types[i].Init();
            }
        }

        public Il2CppType GetTypeFromTypeIndex(int idx)
        {
            return pMetadataRegistration.types[idx];
        }

        public int GetFieldOffsetFromIndex(int typeIndex, int fieldIndexInType)
        {
            var ptr = pMetadataRegistration.fieldOffsets[typeIndex];
            Position = ptr + 4 * fieldIndexInType;
            return ReadInt32();
        }

        public bool Auto()
        {
            if (sectionWithName != null)
            {
                var bytes = new byte[] { 0x1c, 0x0, 0x9f, 0xe5, 0x1c, 0x10, 0x9f, 0xe5, 0x1c, 0x20, 0x9f, 0xe5 };
                //判断必要的section是否都在
                if (sectionWithName.ContainsKey(".got") && sectionWithName.ContainsKey(".init_array") && sectionWithName.ContainsKey(".dynamic"))
                {
                    var dynamic = sectionWithName[".dynamic"];
                    var got = sectionWithName[".got"];
                    //从.dynamic获取_GLOBAL_OFFSET_TABLE_
                    uint _GLOBAL_OFFSET_TABLE_ = 0;
                    Position = dynamic.sh_offset;
                    var dynamicend = dynamic.sh_offset + dynamic.sh_size;
                    var gotend = got.sh_offset + got.sh_size;
                    while (Position < dynamicend)
                    {
                        var tag = ReadInt32();
                        if (tag == 3)
                        {
                            var tmp = ReadUInt32();
                            if (tmp >= got.sh_offset && tmp <= gotend)
                            {
                                _GLOBAL_OFFSET_TABLE_ = tmp;
                                break;
                            }
                        }
                        Position += 4;
                    }
                    //从.init_array获取函数
                    var init_array = sectionWithName[".init_array"];
                    var addrs = ReadClassArray<uint>(init_array.sh_offset, (int)init_array.sh_size / 4);
                    foreach (var i in addrs)
                    {
                        if (i != 0)
                        {
                            Position = i;
                            var buff = ReadBytes(12);
                            if (bytes.SequenceEqual(buff))
                            {
                                Position = i + 0x2c;
                                var subaddr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = subaddr + 0x28;
                                var codeRegistration = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                                Position = subaddr + 0x2C;
                                var ptr = ReadUInt32() + _GLOBAL_OFFSET_TABLE_;
                                Position = MapVATR(ptr);
                                var metadataRegistration = ReadUInt32();
                                Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                                Init(codeRegistration, metadataRegistration);
                                return true;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("ERROR: The necessary section is missing.");
                }
            }
            return false;
        }
    }
}
