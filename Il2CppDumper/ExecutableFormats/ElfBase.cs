using System.IO;

namespace Il2CppDumper
{
    public abstract class ElfBase : Il2Cpp
    {
        protected ElfBase(Stream stream) : base(stream) { }
        protected abstract void Load();
        protected abstract bool CheckSection();

        public override bool CheckDump() => !CheckSection();

        public void Reload() => Load();
    }
}
