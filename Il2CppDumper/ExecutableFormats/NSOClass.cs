namespace Il2CppDumper
{
    public class NSOHeader
    {
        public uint Magic;
        public uint Version;
        public uint Reserved;
        public uint Flags;
        public NSOSegmentHeader TextSegment;
        public uint ModuleOffset;
        public NSOSegmentHeader RoDataSegment;
        public uint ModuleFileSize;
        public NSOSegmentHeader DataSegment;
        public uint BssSize;
        public byte[] DigestBuildID;
        public uint TextCompressedSize;
        public uint RoDataCompressedSize;
        public uint DataCompressedSize;
        public byte[] Padding;
        public NSORelativeExtent APIInfo;
        public NSORelativeExtent DynStr;
        public NSORelativeExtent DynSym;
        public byte[] TextHash;
        public byte[] RoDataHash;
        public byte[] DataHash;

        public NSOSegmentHeader BssSegment;
    }

    public class NSOSegmentHeader
    {
        public uint FileOffset;
        public uint MemoryOffset;
        public uint DecompressedSize;
    }

    public class NSORelativeExtent
    {
        public uint RegionRoDataOffset;
        public uint RegionSize;
    }
}
