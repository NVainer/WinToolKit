// Minimal JSON writer and reader.
//
// The in-box C# compiler has no package manager behind it, so this is
// hand-rolled rather than pulled from NuGet.  It covers exactly what the API
// needs: writing dictionaries/lists of primitives, and reading the small flat
// objects the page POSTs back.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace DeviceControlConsole
{
    public static class Json
    {
        // U+2028 / U+2029 are valid inside JSON but terminate a JavaScript
        // string literal, so they get escaped.  Written as numbers to keep
        // this source file pure ASCII.
        private const int LineSeparator = 0x2028;
        private const int ParagraphSeparator = 0x2029;

        // ---------------------------------------------------------- write
        public static string Write(object value)
        {
            StringBuilder sb = new StringBuilder(1 << 16);
            WriteValue(sb, value);
            return sb.ToString();
        }

        private static void WriteValue(StringBuilder sb, object value)
        {
            if (value == null) { sb.Append("null"); return; }

            string s = value as string;
            if (s != null) { WriteString(sb, s); return; }

            if (value is bool) { sb.Append(((bool)value) ? "true" : "false"); return; }

            if (value is int || value is long || value is short || value is uint
                || value is ulong || value is ushort || value is byte)
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }

            if (value is double || value is float || value is decimal)
            {
                double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) { sb.Append("null"); return; }
                sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }

            if (value is DateTime)
            {
                WriteString(sb, ((DateTime)value).ToString("o", CultureInfo.InvariantCulture));
                return;
            }

            IDictionary<string, object> map = value as IDictionary<string, object>;
            if (map != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (KeyValuePair<string, object> kv in map)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, kv.Key);
                    sb.Append(':');
                    WriteValue(sb, kv.Value);
                }
                sb.Append('}');
                return;
            }

            IEnumerable list = value as IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool firstItem = true;
                foreach (object item in list)
                {
                    if (!firstItem) sb.Append(',');
                    firstItem = false;
                    WriteValue(sb, item);
                }
                sb.Append(']');
                return;
            }

            WriteString(sb, value.ToString());
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20 || c == LineSeparator || c == ParagraphSeparator)
                        {
                            sb.Append("\\u");
                            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        // ----------------------------------------------------------- read
        public static object Read(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            int pos = 0;
            object value = ReadValue(text, ref pos);
            SkipWhite(text, ref pos);
            return value;
        }

        /// <summary>Reads a JSON object, returning an empty map on anything else.</summary>
        public static Dictionary<string, object> ReadObject(string text)
        {
            try
            {
                Dictionary<string, object> map = Read(text) as Dictionary<string, object>;
                if (map == null) return new Dictionary<string, object>();
                return map;
            }
            catch (FormatException)
            {
                return new Dictionary<string, object>();
            }
        }

        private static void SkipWhite(string s, ref int i)
        {
            while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
        }

        private static object ReadValue(string s, ref int i)
        {
            SkipWhite(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end of JSON");
            char c = s[i];
            if (c == '{') return ReadMap(s, ref i);
            if (c == '[') return ReadList(s, ref i);
            if (c == '"') return ReadString(s, ref i);
            if (Match(s, ref i, "true")) return true;
            if (Match(s, ref i, "false")) return false;
            if (Match(s, ref i, "null")) return null;
            return ReadNumber(s, ref i);
        }

        private static bool Match(string s, ref int i, string word)
        {
            if (i + word.Length > s.Length) return false;
            if (string.CompareOrdinal(s, i, word, 0, word.Length) != 0) return false;
            i += word.Length;
            return true;
        }

        private static Dictionary<string, object> ReadMap(string s, ref int i)
        {
            Dictionary<string, object> map = new Dictionary<string, object>();
            i++; // opening brace
            SkipWhite(s, ref i);
            if (i < s.Length && s[i] == '}') { i++; return map; }
            while (true)
            {
                SkipWhite(s, ref i);
                if (i >= s.Length || s[i] != '"') throw new FormatException("expected a key");
                string key = ReadString(s, ref i);
                SkipWhite(s, ref i);
                if (i >= s.Length || s[i] != ':') throw new FormatException("expected a colon");
                i++;
                map[key] = ReadValue(s, ref i);
                SkipWhite(s, ref i);
                if (i >= s.Length) throw new FormatException("unterminated object");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == '}') { i++; return map; }
                throw new FormatException("expected a comma or closing brace");
            }
        }

        private static List<object> ReadList(string s, ref int i)
        {
            List<object> list = new List<object>();
            i++; // opening bracket
            SkipWhite(s, ref i);
            if (i < s.Length && s[i] == ']') { i++; return list; }
            while (true)
            {
                list.Add(ReadValue(s, ref i));
                SkipWhite(s, ref i);
                if (i >= s.Length) throw new FormatException("unterminated array");
                if (s[i] == ',') { i++; continue; }
                if (s[i] == ']') { i++; return list; }
                throw new FormatException("expected a comma or closing bracket");
            }
        }

        private static string ReadString(string s, ref int i)
        {
            StringBuilder sb = new StringBuilder();
            i++; // opening quote
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new FormatException("bad unicode escape");
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber,
                            CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("bad escape character");
                }
            }
            throw new FormatException("unterminated string");
        }

        private static object ReadNumber(string s, ref int i)
        {
            int start = i;
            while (i < s.Length && ("+-.eE0123456789".IndexOf(s[i]) >= 0)) i++;
            string raw = s.Substring(start, i - start);
            if (raw.Length == 0) throw new FormatException("expected a number");
            long l;
            if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out l)) return l;
            double d;
            if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d;
            throw new FormatException("bad number");
        }

        // ------------------------------------------------------- helpers
        public static Dictionary<string, object> Obj()
        {
            return new Dictionary<string, object>();
        }

        public static bool Flag(Dictionary<string, object> map, string key)
        {
            object v;
            if (map == null || !map.TryGetValue(key, out v) || v == null) return false;
            if (v is bool) return (bool)v;
            string s = v.ToString();
            return s == "true" || s == "1" || s == "on";
        }

        public static string Str(Dictionary<string, object> map, string key)
        {
            object v;
            if (map == null || !map.TryGetValue(key, out v) || v == null) return "";
            return v.ToString();
        }
    }
}
