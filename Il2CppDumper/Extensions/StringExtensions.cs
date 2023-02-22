using System.Text;

namespace Il2CppDumper
{
    public static class StringExtensions
    {
        public static string ToEscapedString(this string s)
        {
            var re = new StringBuilder(s.Length);
            foreach (var c in s)
            {
                switch (c)
                {
                    case '\'':
                        re.Append(@"\'");
                        break;
                    case '"':
                        re.Append(@"\""");
                        break;
                    case '\\':
                        re.Append(@"\\");
                        break;
                    case '\0':
                        re.Append(@"\0");
                        break;
                    case '\a':
                        re.Append(@"\a");
                        break;
                    case '\b':
                        re.Append(@"\b");
                        break;
                    case '\f':
                        re.Append(@"\f");
                        break;
                    case '\n':
                        re.Append(@"\n");
                        break;
                    case '\r':
                        re.Append(@"\r");
                        break;
                    case '\t':
                        re.Append(@"\t");
                        break;
                    case '\v':
                        re.Append(@"\v");
                        break;
                    case '\u0085':
                        re.Append(@"\u0085");
                        break;
                    case '\u2028':
                        re.Append(@"\u2028");
                        break;
                    case '\u2029':
                        re.Append(@"\u2029");
                        break;
                    default:
                        re.Append(c);
                        break;
                }
            }
            return re.ToString();
        }
    }
}
