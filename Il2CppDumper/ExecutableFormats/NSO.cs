using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    public sealed class NSO : Il2Cpp
    {
        private NSOHeader header;
        private bool isTextCompressed;
        private bool isRoDataCompressed;
        private bool isDataCompressed;
        private List<NSOSegmentHeader> segments = new List<NSOSegmentHeader>();
        private bool isCompressed => isTextCompressed || isRoDataCompressed || isDataCompressed;


        public NSO(Stream stream, float version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {
            header = new NSOHeader();
            header.Magic = ReadUInt32();
            header.Version = ReadUInt32();
            header.Reserved = ReadUInt32();
            header.Flags = ReadUInt32();
            isTextCompressed = (header.Flags & 1) != 0;
            isRoDataCompressed = (header.Flags & 2) != 0;
            isDataCompressed = (header.Flags & 4) != 0;
            header.TextSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.TextSegment);
            header.ModuleOffset = ReadUInt32();
            header.RoDataSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.RoDataSegment);
            header.ModuleFileSize = ReadUInt32();
            header.DataSegment = new NSOSegmentHeader
            {
                FileOffset = ReadUInt32(),
                MemoryOffset = ReadUInt32(),
                DecompressedSize = ReadUInt32()
            };
            segments.Add(header.DataSegment);
            header.BssSize = ReadUInt32();
            header.DigestBuildID = ReadBytes(0x20);
            header.TextCompressedSize = ReadUInt32();
            header.RoDataCompressedSize = ReadUInt32();
            header.DataCompressedSize = ReadUInt32();
            header.Padding = ReadBytes(0x1C);
            header.APIInfo = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.DynStr = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.DynSym = new NSORelativeExtent
            {
                RegionRoDataOffset = ReadUInt32(),
                RegionSize = ReadUInt32()
            };
            header.TextHash = ReadBytes(0x20);
            header.RoDataHash = ReadBytes(0x20);
            header.DataHash = ReadBytes(0x20);

            if (!isCompressed)
            {
                Position = header.TextSegment.FileOffset + 4;
                var modOffset = ReadUInt32();
                Position = header.TextSegment.FileOffset + modOffset + 8;
                var bssStart = ReadUInt32();
                var bssEnd = ReadUInt32();
                header.BssSegment = new NSOSegmentHeader
                {
                    FileOffset = bssStart,
                    MemoryOffset = bssStart,
                    DecompressedSize = bssEnd - bssStart
                };
            }
        }

        public override ulong MapVATR(ulong addr)
        {
            var segment = segments.First(x => addr >= x.MemoryOffset && addr <= x.MemoryOffset + x.DecompressedSize);
            return addr - segment.MemoryOffset + segment.FileOffset;
        }

        public override bool Search()
        {
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
            plusSearch.SetSection(SearchSectionType.Exec, header.TextSegment);
            plusSearch.SetSection(SearchSectionType.Data, header.DataSegment);
            plusSearch.SetSection(SearchSectionType.Bss, header.BssSegment);
            var codeRegistration = plusSearch.FindCodeRegistration();
            var metadataRegistration = plusSearch.FindMetadataRegistration();
            return AutoInit(codeRegistration, metadataRegistration);
        }

        public override bool SymbolSearch()
        {
            return false;
        }

        public NSO UnCompress()
        {
            if (isTextCompressed || isRoDataCompressed || isDataCompressed)
            {
                var unCompressedStream = new MemoryStream();
                var writer = new BinaryWriter(unCompressedStream);
                writer.Write(header.Magic);
                writer.Write(header.Version);
                writer.Write(header.Reserved);
                writer.Write(0); //Flags
                writer.Write(header.TextSegment.FileOffset);
                writer.Write(header.TextSegment.MemoryOffset);
                writer.Write(header.TextSegment.DecompressedSize);
                writer.Write(header.ModuleOffset);
                var roOffset = header.TextSegment.FileOffset + header.TextSegment.DecompressedSize;
                writer.Write(roOffset); //header.RoDataSegment.FileOffset
                writer.Write(header.RoDataSegment.MemoryOffset);
                writer.Write(header.RoDataSegment.DecompressedSize);
                writer.Write(header.ModuleFileSize);
                writer.Write(roOffset + header.RoDataSegment.DecompressedSize); //header.DataSegment.FileOffset
                writer.Write(header.DataSegment.MemoryOffset);
                writer.Write(header.DataSegment.DecompressedSize);
                writer.Write(header.BssSize);
                writer.Write(header.DigestBuildID);
                writer.Write(header.TextCompressedSize);
                writer.Write(header.RoDataCompressedSize);
                writer.Write(header.DataCompressedSize);
                writer.Write(header.Padding);
                writer.Write(header.APIInfo.RegionRoDataOffset);
                writer.Write(header.APIInfo.RegionSize);
                writer.Write(header.DynStr.RegionRoDataOffset);
                writer.Write(header.DynStr.RegionSize);
                writer.Write(header.DynSym.RegionRoDataOffset);
                writer.Write(header.DynSym.RegionSize);
                writer.Write(header.TextHash);
                writer.Write(header.RoDataHash);
                writer.Write(header.DataHash);
                writer.BaseStream.Position = header.TextSegment.FileOffset;
                Position = header.TextSegment.FileOffset;
                var textBytes = ReadBytes((int)header.TextCompressedSize);
                if (isTextCompressed)
                {
                    var unCompressedData = new byte[header.TextSegment.DecompressedSize];
                    using (var decoder = new Lz4DecoderStream(new MemoryStream(textBytes)))
                    {
                        decoder.Read(unCompressedData, 0, unCompressedData.Length);
                    }
                    writer.Write(unCompressedData);
                }
                else
                {
                    writer.Write(textBytes);
                }
                var roDataBytes = ReadBytes((int)header.RoDataCompressedSize);
                if (isRoDataCompressed)
                {
                    var unCompressedData = new byte[header.RoDataSegment.DecompressedSize];
                    using (var decoder = new Lz4DecoderStream(new MemoryStream(roDataBytes)))
                    {
                        decoder.Read(unCompressedData, 0, unCompressedData.Length);
                    }
                    writer.Write(unCompressedData);
                }
                else
                {
                    writer.Write(roDataBytes);
                }
                var dataBytes = ReadBytes((int)header.DataCompressedSize);
                if (isDataCompressed)
                {
                    var unCompressedData = new byte[header.DataSegment.DecompressedSize];
                    using (var decoder = new Lz4DecoderStream(new MemoryStream(dataBytes)))
                    {
                        decoder.Read(unCompressedData, 0, unCompressedData.Length);
                    }
                    writer.Write(unCompressedData);
                }
                else
                {
                    writer.Write(dataBytes);
                }
                writer.Flush();
                unCompressedStream.Position = 0;
                return new NSO(unCompressedStream, Version, maxMetadataUsages);
            }
            return this;
        }
    }
}
