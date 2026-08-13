// .NET runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
// case matches iff parse_ok == expect_parse_ok and, when ok, canonical bytes are
// equal.
//
// No canonical RFC 8941 library ships for .NET, so this is a compact hand-rolled
// RFC 8941 parser + canonical serializer, ported from the reference
// tools/oracle_sfv.py. JSON via System.Text.Json (built in). Independence for the
// profile comes from the five native-library runners (typescript/go/rust/ruby/php)
// and the http_sfv KAT gate.
//
// Corpus path: argv[0], else ../../corpus/sfv_v0/sfv_v0.json relative to the
// project. Exit 0 iff every case matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Text.Json;

static class VerifySfv
{
    const string DefaultPath = "../../corpus/sfv_v0/sfv_v0.json";
    static readonly string[] Sections = {
        "sfv_item", "sfv_list", "sfv_dictionary",
        "sfv_parameters", "sfv_canonical", "sfv_reject"
    };

    const long IntMin = -999_999_999_999_999L;
    const long IntMax = 999_999_999_999_999L;

    const string Digits = "0123456789";
    const string Lcalpha = "abcdefghijklmnopqrstuvwxyz";
    const string Ucalpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string TokenTail = Lcalpha + Ucalpha + Digits + "!#$%&'*+-.^_`|~:/";
    const string KeyTail = Lcalpha + Digits + "_-.*";
    const string B64Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    sealed class SFVError : Exception { public SFVError(string m) : base(m) { } }

    sealed class Bare
    {
        public string Kind;   // integer|decimal|string|token|bytes|boolean
        public long I;
        public string Dec;
        public string S;
        public byte[] By;
        public bool B;
    }

    sealed class Param
    {
        public string Key;
        public Bare Val;
        public Param(string key, Bare val) { Key = key; Val = val; }
    }

    sealed class Member
    {
        public Bare Bare;
        public List<Param> Params;
        public Member(Bare bare, List<Param> ps) { Bare = bare; Params = ps; }
    }

    sealed class Node
    {
        public bool InnerList;
        public Bare Bare;
        public List<Param> Params;
        public List<Member> Members;
    }

    sealed class Entry
    {
        public string Key;
        public Node Node;
        public Entry(string key, Node node) { Key = key; Node = node; }
    }

    // ================= Parser =================
    sealed class Parser
    {
        readonly string s;
        public int I;

        public Parser(string text)
        {
            foreach (char c in text)
                if (c > 0x7F) throw new SFVError("non-ASCII in field value");
            s = text;
            I = 0;
        }

        public bool Eof() => I >= s.Length;
        char? Peek() => Eof() ? (char?)null : s[I];

        public void DiscardSp() { while (!Eof() && s[I] == ' ') I++; }
        void DiscardOws() { while (!Eof() && (s[I] == ' ' || s[I] == '\t')) I++; }

        static bool IsAlpha(char c) => Lcalpha.IndexOf(c) >= 0 || Ucalpha.IndexOf(c) >= 0;

        Bare BareItem()
        {
            char? c = Peek();
            if (c == null) throw new SFVError("empty bare item");
            char ch = c.Value;
            if (ch == '-' || Digits.IndexOf(ch) >= 0) return Number();
            if (ch == '"') return new Bare { Kind = "string", S = ParseString() };
            if (ch == ':') return new Bare { Kind = "bytes", By = Byteseq() };
            if (ch == '?') return new Bare { Kind = "boolean", B = Bool() };
            if (ch == '*' || IsAlpha(ch)) return new Bare { Kind = "token", S = Token() };
            throw new SFVError("unexpected char starting a bare item");
        }

        Bare Number()
        {
            bool isDecimal = false;
            int sign = 1;
            var num = new StringBuilder();
            if (Peek() == '-') { I++; sign = -1; }
            if (Eof() || Digits.IndexOf(s[I]) < 0) throw new SFVError("number with no digits");
            while (!Eof())
            {
                char c = s[I];
                if (Digits.IndexOf(c) >= 0) { num.Append(c); I++; }
                else if (!isDecimal && c == '.')
                {
                    if (num.Length > 12) throw new SFVError("too many integer digits before decimal");
                    num.Append('.'); isDecimal = true; I++;
                }
                else break;
                if (!isDecimal && num.Length > 15) throw new SFVError("integer too long");
                if (isDecimal && num.Length > 16) throw new SFVError("decimal too long");
            }
            if (!isDecimal)
            {
                long val = sign * long.Parse(num.ToString());
                if (val < IntMin || val > IntMax) throw new SFVError("integer out of range");
                return new Bare { Kind = "integer", I = val };
            }
            string text = num.ToString();
            if (text.EndsWith(".")) throw new SFVError("decimal ends with a dot");
            int dot = text.IndexOf('.');
            if (text.Length - dot - 1 > 3) throw new SFVError("too many fractional digits");
            return new Bare { Kind = "decimal", Dec = SerDecimal(sign, text.Substring(0, dot), text.Substring(dot + 1)) };
        }

        string ParseString()
        {
            I++;
            var outp = new StringBuilder();
            while (!Eof())
            {
                char c = s[I]; I++;
                if (c == '\\')
                {
                    if (Eof()) throw new SFVError("trailing backslash in string");
                    char nxt = s[I]; I++;
                    if (nxt != '"' && nxt != '\\') throw new SFVError("bad string escape");
                    outp.Append(nxt);
                }
                else if (c == '"') return outp.ToString();
                else if (c < 0x20 || c > 0x7E) throw new SFVError("control char in string");
                else outp.Append(c);
            }
            throw new SFVError("unterminated string");
        }

        string Token()
        {
            int start = I; I++;
            while (!Eof() && TokenTail.IndexOf(s[I]) >= 0) I++;
            return s.Substring(start, I - start);
        }

        byte[] Byteseq()
        {
            I++;
            int start = I;
            while (!Eof() && s[I] != ':')
            {
                if (B64Alphabet.IndexOf(s[I]) < 0) throw new SFVError("non-base64 char");
                I++;
            }
            if (Eof()) throw new SFVError("unterminated byte sequence");
            string content = s.Substring(start, I - start);
            I++;
            return StrictB64Decode(content);
        }

        bool Bool()
        {
            I++;
            char? c = Peek();
            if (c == '1') { I++; return true; }
            if (c == '0') { I++; return false; }
            throw new SFVError("boolean must be ?0 or ?1");
        }

        string Key()
        {
            char? c = Peek();
            if (c == null || (Lcalpha.IndexOf(c.Value) < 0 && c.Value != '*'))
                throw new SFVError("key must start with lcalpha or *");
            int start = I; I++;
            while (!Eof() && KeyTail.IndexOf(s[I]) >= 0) I++;
            return s.Substring(start, I - start);
        }

        List<Param> Parameters()
        {
            var ps = new List<Param>();
            while (Peek() == ';')
            {
                I++;
                DiscardSp();
                string k = Key();
                Bare val;
                if (Peek() == '=') { I++; val = BareItem(); }
                else val = new Bare { Kind = "boolean", B = true };
                // duplicate key: overwrite value in place, keeping original position.
                int existing = ps.FindIndex(p => p.Key == k);
                if (existing >= 0) ps[existing] = new Param(k, val);
                else ps.Add(new Param(k, val));
            }
            return ps;
        }

        Node Item()
        {
            return new Node { InnerList = false, Bare = BareItem(), Params = Parameters() };
        }

        Node InnerList()
        {
            I++;
            var members = new List<Member>();
            while (true)
            {
                DiscardSp();
                if (Peek() == ')')
                {
                    I++;
                    return new Node { InnerList = true, Members = members, Params = Parameters() };
                }
                if (Eof()) throw new SFVError("unterminated inner list");
                Bare bare = BareItem();
                var ps = Parameters();
                members.Add(new Member(bare, ps));
                char? c = Peek();
                if (c == null || (c.Value != ' ' && c.Value != ')'))
                    throw new SFVError("inner-list items must be space separated");
            }
        }

        Node ItemOrInnerList() => Peek() == '(' ? InnerList() : Item();

        public List<Node> ParseList()
        {
            var members = new List<Node>();
            DiscardSp();
            if (Eof()) return members;
            while (true)
            {
                members.Add(ItemOrInnerList());
                DiscardOws();
                if (Eof()) return members;
                if (Peek() != ',') throw new SFVError("list members must be comma separated");
                I++;
                DiscardOws();
                if (Eof()) throw new SFVError("trailing comma in list");
            }
        }

        public List<Entry> ParseDictionary()
        {
            var members = new List<Entry>();
            DiscardSp();
            if (Eof()) return members;
            while (true)
            {
                string k = Key();
                Node value;
                if (Peek() == '=') { I++; value = ItemOrInnerList(); }
                else
                {
                    var ps = Parameters();
                    value = new Node { InnerList = false, Bare = new Bare { Kind = "boolean", B = true }, Params = ps };
                }
                // duplicate key: overwrite value in place, keeping original position.
                int existing = members.FindIndex(e => e.Key == k);
                if (existing >= 0) members[existing] = new Entry(k, value);
                else members.Add(new Entry(k, value));
                DiscardOws();
                if (Eof()) return members;
                if (Peek() != ',') throw new SFVError("dictionary members must be comma separated");
                I++;
                DiscardOws();
                if (Eof()) throw new SFVError("trailing comma in dictionary");
            }
        }

        public Node Item0() { DiscardSp(); return Item(); }
    }

    static byte[] StrictB64Decode(string content)
    {
        if (content.Length % 4 != 0) throw new SFVError("bad base64 length");
        int pad = 0;
        for (int k = 0; k < content.Length; k++)
        {
            char c = content[k];
            if (c == '=')
            {
                pad++;
                if (k < content.Length - 2) throw new SFVError("misplaced padding");
            }
            else
            {
                if (pad > 0) throw new SFVError("data after padding");
                if (B64Alphabet.IndexOf(c) < 0 || c == '=') throw new SFVError("non-base64 char");
            }
        }
        try { return Convert.FromBase64String(content); }
        catch (FormatException) { throw new SFVError("invalid base64"); }
    }

    // ================= Serialization =================
    static string SerDecimal(int sign, string intpart, string frac)
    {
        string frac3 = (frac + "000").Substring(0, 3);
        string stripped = frac3.TrimEnd('0');
        if (stripped.Length == 0) stripped = "0";
        BigInteger whole = BigInteger.Parse(intpart.Length == 0 ? "0" : intpart);
        if (whole >= BigInteger.Pow(10, 12)) throw new SFVError("decimal integer part too large");
        bool isZero = whole.IsZero && stripped == "0";
        string neg = (sign < 0 && !isZero) ? "-" : "";
        return neg + whole.ToString() + "." + stripped;
    }

    static string SerBare(Bare b)
    {
        switch (b.Kind)
        {
            case "integer":
                if (b.I < IntMin || b.I > IntMax) throw new SFVError("integer out of range");
                return b.I.ToString();
            case "decimal":
                return b.Dec;
            case "string":
            {
                var outp = new StringBuilder("\"");
                foreach (char c in b.S)
                {
                    if (c < 0x20 || c > 0x7E) throw new SFVError("control char in string");
                    if (c == '"' || c == '\\') outp.Append('\\');
                    outp.Append(c);
                }
                outp.Append('"');
                return outp.ToString();
            }
            case "token":
                return b.S;
            case "bytes":
                return ":" + Convert.ToBase64String(b.By) + ":";
            case "boolean":
                return b.B ? "?1" : "?0";
            default:
                throw new SFVError("unknown bare kind");
        }
    }

    static bool IsBoolTrue(Bare b) => b.Kind == "boolean" && b.B;

    static string SerParams(List<Param> ps)
    {
        var outp = new StringBuilder();
        foreach (var p in ps)
        {
            if (IsBoolTrue(p.Val)) outp.Append(";").Append(p.Key);
            else outp.Append(";").Append(p.Key).Append("=").Append(SerBare(p.Val));
        }
        return outp.ToString();
    }

    static string SerMember(Node node)
    {
        if (node.InnerList)
        {
            var inner = new StringBuilder();
            for (int k = 0; k < node.Members.Count; k++)
            {
                if (k > 0) inner.Append(" ");
                var m = node.Members[k];
                inner.Append(SerBare(m.Bare)).Append(SerParams(m.Params));
            }
            return "(" + inner + ")" + SerParams(node.Params);
        }
        return SerBare(node.Bare) + SerParams(node.Params);
    }

    static string SerializeList(List<Node> members)
    {
        var outp = new StringBuilder();
        for (int k = 0; k < members.Count; k++)
        {
            if (k > 0) outp.Append(", ");
            outp.Append(SerMember(members[k]));
        }
        return outp.ToString();
    }

    static string SerializeDict(List<Entry> members)
    {
        var outp = new StringBuilder();
        for (int k = 0; k < members.Count; k++)
        {
            if (k > 0) outp.Append(", ");
            var e = members[k];
            if (!e.Node.InnerList && IsBoolTrue(e.Node.Bare))
                outp.Append(e.Key).Append(SerParams(e.Node.Params));
            else
                outp.Append(e.Key).Append("=").Append(SerMember(e.Node));
        }
        return outp.ToString();
    }

    // ================= verdict =================
    static (bool ok, string canon) Verdict(string fieldType, string text)
    {
        object value;
        try
        {
            var p = new Parser(text);
            if (fieldType == "item") value = p.Item0();
            else if (fieldType == "list") value = p.ParseList();
            else if (fieldType == "dictionary") value = p.ParseDictionary();
            else return (false, null);
            p.DiscardSp();
            if (!p.Eof()) throw new SFVError("trailing characters after value");
        }
        catch (SFVError) { return (false, null); }
        try
        {
            string canon = fieldType switch
            {
                "item" => SerMember((Node)value),
                "list" => SerializeList((List<Node>)value),
                "dictionary" => SerializeDict((List<Entry>)value),
                _ => throw new SFVError("unknown field type"),
            };
            return (true, canon);
        }
        catch (SFVError) { return (false, null); }
    }

    static int Main(string[] args)
    {
        string path = args.Length > 0 ? args[0] : DefaultPath;
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement corpus = doc.RootElement;

        int total = 0, matched = 0;
        var fails = new List<string>();
        foreach (string sec in Sections)
        {
            if (!corpus.TryGetProperty(sec, out var cases) || cases.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var c in cases.EnumerateArray())
            {
                string ft = c.GetProperty("field_type").GetString();
                string input = c.GetProperty("input").GetString();
                var (ok, canon) = Verdict(ft, input);
                bool expect = c.GetProperty("expect_parse_ok").GetBoolean();
                string wantCanon = c.TryGetProperty("canonical", out var cc) ? cc.GetString() : null;
                bool match = (ok == expect) && (!ok || canon == wantCanon);
                total++;
                if (match) matched++;
                else fails.Add("[" + sec + "] " + (c.TryGetProperty("note", out var n) ? n.GetString() : ""));
            }
        }
        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (sfv): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
