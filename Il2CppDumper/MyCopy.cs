using System.Collections;

namespace Il2CppDumper
{
    static class MyCopy
    {
        public static void Copy<T1, T2>(out T1 o1, T2 o2) where T1 : new()
        {
            o1 = new T1();
            var t2 = o2.GetType();
            foreach (var field in o1.GetType().GetFields())
            {
                if (field.FieldType.IsPrimitive)
                    field.SetValue(o1, t2.GetField(field.Name)?.GetValue(o2));
            }
        }

        public static void Copy<T1>(out T1[] o1, IList o2) where T1 : new()
        {
            o1 = new T1[o2.Count];
            for (int i = 0; i < o1.Length; i++)
            {
                Copy(out o1[i], o2[i]);
            }
        }
    }
}
