using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppDumper
{
    internal static class ReadClassCache<T>
    {
        private static Dictionary<ulong, T> CacheInstance;

        public static void Add(ulong key, T value)
        {
            if (CacheInstance == null)
            {
                CacheInstance = new Dictionary<ulong, T>();
            }
            CacheInstance.Add(key, value);
        }

        public static bool TryGetValue(ulong key, out T value)
        {
            if (CacheInstance == null)
            {
                CacheInstance = new Dictionary<ulong, T>();
            }
            return CacheInstance.TryGetValue(key, out value);
        }
    }
}
