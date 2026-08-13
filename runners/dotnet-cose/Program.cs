// .NET runner for the COSE_Sign1 corpus (cose_v0).
//
// Independent C# port of the Python reference runner (runners/python/verify_cose.py)
// and its decision surface (tools/oracle_cose.py). Parses each COSE_Sign1 (CBOR array
// of 4, tagged 18 or untagged), applies the COSE security gates in order (protected
// header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in
// the protected header, an unknown crit (label 2) label rejected, alg/key-type match),
// builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
// CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
// section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is NOT
// enforced (a COSE base rule, not a FAPI rule).
//
// The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
// canonical encoder) so the deterministic judgement and the Sig_structure bytes are
// byte-identical to the frozen corpus, independent of System.Formats.Cbor's Canonical
// mode (which uses length-first CTAP2 ordering, not the RFC 8949 Section 4.2 bytewise
// ordering the corpus uses).
//
// JSON via System.Text.Json; ES256 (ECDSA P-256, ECParameters.Validate() enforces
// on-curve) and PS256 (RSA-PSS SHA-256, salt 32) via System.Security.Cryptography;
// EdDSA (Ed25519) via Bouncy Castle. Keys from the hex COSE material.
//
// Corpus path: argv[0], else ../../corpus/cose_v0/cose_v0.json. Exit 0 iff every case
// matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static class VerifyCose
{
    const string DefaultPath = "../../corpus/cose_v0/cose_v0.json";

    static readonly string[] Sections = {
        "cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
        "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"
    };

    const long CoseSign1Tag = 18;

    static string AlgKty(long alg) => alg switch { -7 => "EC2", -8 => "OKP", -37 => "RSA", _ => null };
    static bool KnownLabel(long l) => l >= 1 && l <= 5;

    // -----------------------------------------------------------------------
    // Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
    // -----------------------------------------------------------------------
    sealed class CborException : Exception { public CborException(string m) : base(m) { } }

    const int T_INT = 0, T_BYTES = 1, T_TEXT = 2, T_ARRAY = 3, T_MAP = 4, T_NULL = 5, T_TAG = 6, T_BOOL = 7;

    sealed class Cval
    {
        public int T;
        public long I;
        public byte[] B;
        public string S;
        public List<Cval> Arr;
        public List<Cval[]> Map;  // each entry {key, value}
        public long Tag;
        public Cval(int t) { T = t; }
    }

    static (Cval, int) Decode(byte[] buf, int pos)
    {
        if (pos >= buf.Length) throw new CborException("truncated");
        int ib = buf[pos++];
        int major = ib >> 5;
        int ai = ib & 0x1f;
        long arg;
        if (ai < 24) arg = ai;
        else if (ai == 24) { if (pos + 1 > buf.Length) throw new CborException("t"); arg = buf[pos]; pos += 1; }
        else if (ai == 25) { if (pos + 2 > buf.Length) throw new CborException("t"); arg = ((long)buf[pos] << 8) | buf[pos + 1]; pos += 2; }
        else if (ai == 26) { if (pos + 4 > buf.Length) throw new CborException("t"); arg = 0; for (int i = 0; i < 4; i++) arg = (arg << 8) | buf[pos + i]; pos += 4; }
        else if (ai == 27) { if (pos + 8 > buf.Length) throw new CborException("t"); arg = 0; for (int i = 0; i < 8; i++) arg = (arg << 8) | buf[pos + i]; pos += 8; }
        else if (ai == 31) { if (major < 2 || major > 5) throw new CborException("indef"); return DecodeIndefinite(buf, pos, major); }
        else throw new CborException("reserved");

        switch (major)
        {
            case 0: return (new Cval(T_INT) { I = arg }, pos);
            case 1: return (new Cval(T_INT) { I = -1 - arg }, pos);
            case 2:
            {
                if (pos + arg > buf.Length) throw new CborException("t");
                var v = new Cval(T_BYTES) { B = new byte[arg] };
                Array.Copy(buf, pos, v.B, 0, (int)arg);
                return (v, pos + (int)arg);
            }
            case 3:
            {
                if (pos + arg > buf.Length) throw new CborException("t");
                var v = new Cval(T_TEXT) { S = Encoding.UTF8.GetString(buf, pos, (int)arg) };
                return (v, pos + (int)arg);
            }
            case 4:
            {
                var v = new Cval(T_ARRAY) { Arr = new List<Cval>() };
                for (long i = 0; i < arg; i++) { var (e, np) = Decode(buf, pos); v.Arr.Add(e); pos = np; }
                return (v, pos);
            }
            case 5:
            {
                var v = new Cval(T_MAP) { Map = new List<Cval[]>() };
                for (long i = 0; i < arg; i++)
                {
                    var (k, p1) = Decode(buf, pos);
                    var (val, p2) = Decode(buf, p1);
                    v.Map.Add(new[] { k, val });
                    pos = p2;
                }
                return (v, pos);
            }
            case 6:
            {
                var (inner, np) = Decode(buf, pos);
                return (new Cval(T_TAG) { Tag = arg, Arr = new List<Cval> { inner } }, np);
            }
            case 7:
                if (ai == 22) return (new Cval(T_NULL), pos);
                if (ai == 20) return (new Cval(T_BOOL) { I = 0 }, pos);
                if (ai == 21) return (new Cval(T_BOOL) { I = 1 }, pos);
                throw new CborException("simple/float");
        }
        throw new CborException("major");
    }

    static (Cval, int) DecodeIndefinite(byte[] buf, int pos, int major)
    {
        if (major == 2 || major == 3)
        {
            using var acc = new MemoryStream();
            while (true)
            {
                if (pos >= buf.Length) throw new CborException("t");
                if (buf[pos] == 0xff) { pos++; break; }
                var (chunk, np) = Decode(buf, pos);
                if (chunk.T != (major == 2 ? T_BYTES : T_TEXT)) throw new CborException("chunk");
                byte[] cb = major == 2 ? chunk.B : Encoding.UTF8.GetBytes(chunk.S);
                acc.Write(cb, 0, cb.Length);
                pos = np;
            }
            var v = new Cval(major == 2 ? T_BYTES : T_TEXT);
            if (major == 2) v.B = acc.ToArray(); else v.S = Encoding.UTF8.GetString(acc.ToArray());
            return (v, pos);
        }
        if (major == 4)
        {
            var v = new Cval(T_ARRAY) { Arr = new List<Cval>() };
            while (true)
            {
                if (pos >= buf.Length) throw new CborException("t");
                if (buf[pos] == 0xff) { pos++; break; }
                var (e, np) = Decode(buf, pos); v.Arr.Add(e); pos = np;
            }
            return (v, pos);
        }
        var m = new Cval(T_MAP) { Map = new List<Cval[]>() };
        while (true)
        {
            if (pos >= buf.Length) throw new CborException("t");
            if (buf[pos] == 0xff) { pos++; break; }
            var (k, p1) = Decode(buf, pos);
            var (val, p2) = Decode(buf, p1);
            m.Map.Add(new[] { k, val }); pos = p2;
        }
        return (m, pos);
    }

    static byte[] Head(int major, long n)
    {
        int b = major << 5;
        if (n < 24) return new[] { (byte)(b | (int)n) };
        if (n < 0x100L) return new[] { (byte)(b | 24), (byte)n };
        if (n < 0x10000L) return new[] { (byte)(b | 25), (byte)(n >> 8), (byte)n };
        if (n < 0x100000000L) return new[] { (byte)(b | 26), (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
        var outb = new byte[9]; outb[0] = (byte)(b | 27);
        for (int i = 0; i < 8; i++) outb[8 - i] = (byte)(n >> (8 * i));
        return outb;
    }

    static void EncodeInto(Cval v, MemoryStream outS)
    {
        switch (v.T)
        {
            case T_INT: { var h = v.I >= 0 ? Head(0, v.I) : Head(1, -1 - v.I); outS.Write(h, 0, h.Length); break; }
            case T_BYTES: { var h = Head(2, v.B.Length); outS.Write(h, 0, h.Length); outS.Write(v.B, 0, v.B.Length); break; }
            case T_TEXT:
            {
                var sb = Encoding.UTF8.GetBytes(v.S); var h = Head(3, sb.Length);
                outS.Write(h, 0, h.Length); outS.Write(sb, 0, sb.Length); break;
            }
            case T_ARRAY:
            {
                var h = Head(4, v.Arr.Count); outS.Write(h, 0, h.Length);
                foreach (var it in v.Arr) EncodeInto(it, outS);
                break;
            }
            case T_MAP:
            {
                var enc = new List<byte[][]>();
                foreach (var p in v.Map) enc.Add(new[] { Encode(p[0]), Encode(p[1]) });
                enc.Sort((a, b) => CompareUnsigned(a[0], b[0]));
                var h = Head(5, enc.Count); outS.Write(h, 0, h.Length);
                foreach (var p in enc) { outS.Write(p[0], 0, p[0].Length); outS.Write(p[1], 0, p[1].Length); }
                break;
            }
            case T_NULL: outS.WriteByte(0xf6); break;
            default: throw new CborException("encode");
        }
    }

    static byte[] Encode(Cval v)
    {
        using var s = new MemoryStream();
        EncodeInto(v, s);
        return s.ToArray();
    }

    static int CompareUnsigned(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++) { int d = a[i] - b[i]; if (d != 0) return d; }
        return a.Length - b.Length;
    }

    static bool IsDeterministic(byte[] buf)
    {
        Cval v; int np;
        try { (v, np) = Decode(buf, 0); } catch (Exception) { return false; }
        if (np != buf.Length) return false;
        if (v.T == T_TAG) return false;
        try { return ByteEq(Encode(v), buf); } catch (Exception) { return false; }
    }

    static bool ByteEq(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    static Cval MapGet(Cval m, long key)
    {
        foreach (var p in m.Map) if (p[0].T == T_INT && p[0].I == key) return p[1];
        return null;
    }

    // -----------------------------------------------------------------------
    // COSE_Sign1 parse + gates
    // -----------------------------------------------------------------------
    sealed class Sign1 { public byte[] Protected; public Cval Phdr; public byte[] Payload; public byte[] Sig; }

    static Sign1 ParseSign1(byte[] buf)
    {
        Cval top;
        try { (top, _) = Decode(buf, 0); } catch (Exception) { return null; }
        var arr = top;
        if (top.T == T_TAG)
        {
            if (top.Tag != CoseSign1Tag) return null;
            arr = top.Arr[0];
        }
        if (arr.T != T_ARRAY || arr.Arr.Count != 4) return null;
        Cval prot = arr.Arr[0], uhdr = arr.Arr[1], payload = arr.Arr[2], sig = arr.Arr[3];
        if (prot.T != T_BYTES || uhdr.T != T_MAP || sig.T != T_BYTES) return null;
        if (payload.T != T_BYTES && payload.T != T_NULL) return null;
        Cval phdr;
        if (prot.B.Length == 0)
        {
            phdr = new Cval(T_MAP) { Map = new List<Cval[]>() };
        }
        else
        {
            if (!IsDeterministic(prot.B)) return null;
            Cval dec;
            try { (dec, _) = Decode(prot.B, 0); } catch (Exception) { return null; }
            if (dec.T != T_MAP) return null;
            phdr = dec;
        }
        return new Sign1
        {
            Protected = prot.B,
            Phdr = phdr,
            Payload = payload.T == T_BYTES ? payload.B : Array.Empty<byte>(),
            Sig = sig.B
        };
    }

    static byte[] SigStructure(byte[] prot, byte[] payload)
    {
        var a = new Cval(T_ARRAY) { Arr = new List<Cval>() };
        a.Arr.Add(new Cval(T_TEXT) { S = "Signature1" });
        a.Arr.Add(new Cval(T_BYTES) { B = prot });
        a.Arr.Add(new Cval(T_BYTES) { B = Array.Empty<byte>() });
        a.Arr.Add(new Cval(T_BYTES) { B = payload });
        return Encode(a);
    }

    // -----------------------------------------------------------------------
    // Signature verification per algorithm
    // -----------------------------------------------------------------------
    static string GetStr(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    static bool Es256(JsonElement key, byte[] preimage, byte[] sig)
    {
        try
        {
            if (sig.Length != 64) return false;
            byte[] x = Convert.FromHexString(GetStr(key, "x"));
            byte[] y = Convert.FromHexString(GetStr(key, "y"));
            if (x.Length != 32 || y.Length != 32) return false;
            var ecp = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
            ecp.Validate(); // throws for an off-curve point
            using var ecdsa = ECDsa.Create(ecp);
            return ecdsa.VerifyData(preimage, sig, HashAlgorithmName.SHA256,
                                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch { return false; }
    }

    static bool Eddsa(JsonElement key, byte[] preimage, byte[] sig)
    {
        try
        {
            byte[] pk = Convert.FromHexString(GetStr(key, "x"));
            if (pk.Length != 32 || sig.Length != 64) return false;
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(pk, 0));
            signer.BlockUpdate(preimage, 0, preimage.Length);
            return signer.VerifySignature(sig);
        }
        catch { return false; }
    }

    static bool Ps256(JsonElement key, byte[] preimage, byte[] sig)
    {
        try
        {
            byte[] n = Convert.FromHexString(GetStr(key, "n"));
            byte[] e = Convert.FromHexString(GetStr(key, "e"));
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
            return rsa.VerifyData(preimage, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch { return false; }
    }

    static bool Verdict(byte[] buf, JsonElement key)
    {
        var p = ParseSign1(buf);
        if (p == null) return false;
        var alg = MapGet(p.Phdr, 1);
        if (alg == null || alg.T != T_INT) return false;
        var crit = MapGet(p.Phdr, 2);
        if (crit != null)
        {
            if (crit.T != T_ARRAY || crit.Arr.Count == 0) return false;
            foreach (var l in crit.Arr) if (l.T != T_INT || !KnownLabel(l.I)) return false;
        }
        string wantKty = AlgKty(alg.I);
        if (wantKty == null) return false;
        if (GetStr(key, "kty") != wantKty) return false;
        byte[] preimage = SigStructure(p.Protected, p.Payload);
        return alg.I switch
        {
            -7 => Es256(key, preimage, p.Sig),
            -8 => Eddsa(key, preimage, p.Sig),
            -37 => Ps256(key, preimage, p.Sig),
            _ => false
        };
    }

    static int Main(string[] args)
    {
        string path = args.Length > 0 ? args[0] : DefaultPath;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(File.ReadAllText(path)); }
        catch (Exception e)
        {
            Console.Error.WriteLine("cannot read corpus " + path + ": " + e.Message);
            return 1;
        }
        var corpus = doc.RootElement;
        var keys = corpus.GetProperty("keys");

        int total = 0, matched = 0;
        var fails = new List<string>();
        foreach (var sec in Sections)
        {
            if (!corpus.TryGetProperty(sec, out var arr)) continue;
            foreach (var c in arr.EnumerateArray())
            {
                bool accept;
                if (sec == "cose_deterministic_cbor")
                    accept = IsDeterministic(Convert.FromHexString(c.GetProperty("cbor_hex").GetString()));
                else
                    accept = Verdict(Convert.FromHexString(c.GetProperty("cose_hex").GetString()),
                                     keys.GetProperty(c.GetProperty("key").GetString()));
                total++;
                bool expect = c.GetProperty("expect_valid").ValueKind == JsonValueKind.True;
                if (accept == expect) matched++;
                else fails.Add("[" + sec + "] " + GetStr(c, "note"));
            }
        }
        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (cose): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
