// .NET runner for the rfc9421_negative_v1 CORE cross-language battery.
//
// Independent C# port of the verdict surface (signing_base.py, parse.py,
// keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
// (no .NET RFC 9421 verifier exists); must produce byte-identical verdicts to
// every other runner. Ed25519 verify + canonical-S via Bouncy Castle; the
// small-order / non-canonical key gate is ported with System.Numerics.BigInteger;
// ECDSA P-256/P-384 uses System.Security.Cryptography over a raw r||s signature
// (IEEE P1363 format) with explicit range / width / strict-low-s checks.
//
// Corpus path: argv[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static class NegativeV1
{
    const string DefaultPath = "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json";

    class SigningBaseError : Exception { public SigningBaseError(string m) : base(m) { } }
    class ParseErr : Exception { public ParseErr(string m) : base(m) { } }
    class WeakKeyError : Exception { public WeakKeyError(string m) : base(m) { } }

    // curve subgroup orders (public curve parameters)
    static readonly BigInteger N_P256 = BigInteger.Parse(
        "0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        System.Globalization.NumberStyles.HexNumber);
    static readonly BigInteger N_P384 = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        System.Globalization.NumberStyles.HexNumber);

    // ================= signing base (port of signing_base.py) =================
    static string BuildSigningBase(JsonElement input, string mode, string sigParamsRaw)
    {
        if (mode != "algovoi-v0" && mode != "rfc9421")
            throw new SigningBaseError("mode must be 'algovoi-v0' or 'rfc9421', got " + mode);
        if (mode == "rfc9421" && sigParamsRaw == null)
            throw new SigningBaseError("rfc9421 mode requires signature_params_raw");

        var headers = new Dictionary<string, string>();
        if (input.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
            foreach (var p in h.EnumerateObject())
                headers[p.Name.ToLowerInvariant()] = p.Value.GetString();

        input.TryGetProperty("parameters", out var parameters);

        string StrOrThrow(string field, string msg)
        {
            if (!input.TryGetProperty(field, out var n) || n.ValueKind == JsonValueKind.Null)
                throw new SigningBaseError(msg);
            return n.GetString();
        }
        string ParamStrOrThrow(string key, string msg)
        {
            if (parameters.ValueKind != JsonValueKind.Object || !parameters.TryGetProperty(key, out var v))
                throw new SigningBaseError(msg);
            return v.ValueKind == JsonValueKind.Number ? v.GetRawText() : v.GetString();
        }

        var lines = new List<string>();
        foreach (var compNode in input.GetProperty("covered_components").EnumerateArray())
        {
            string component = compNode.GetString();
            string c = component.ToLowerInvariant();
            string value;
            switch (c)
            {
                case "@method":
                    value = StrOrThrow("method", "@method covered but method not supplied");
                    if (mode != "rfc9421") value = value.ToLowerInvariant();
                    break;
                case "@authority":
                    value = StrOrThrow("authority", "@authority covered but authority not supplied").ToLowerInvariant();
                    break;
                case "@path":
                    value = StrOrThrow("path", "@path covered but path not supplied");
                    break;
                case "@target-uri":
                    value = StrOrThrow("target_uri", "@target-uri covered but target_uri not supplied");
                    break;
                case "@scheme":
                    value = StrOrThrow("scheme", "@scheme covered but scheme not supplied").ToLowerInvariant();
                    break;
                case "@status":
                    if (!input.TryGetProperty("status", out var st) || st.ValueKind == JsonValueKind.Null)
                        throw new SigningBaseError("@status covered but status not supplied");
                    value = st.GetRawText();
                    break;
                case "created":
                    value = ParamStrOrThrow("created", "'created' covered but no 'created' parameter in Signature-Input");
                    break;
                case "expires":
                    value = ParamStrOrThrow("expires", "'expires' covered but no 'expires' parameter in Signature-Input");
                    break;
                default:
                    if (c.StartsWith("@")) throw new SigningBaseError("unsupported derived component: " + component);
                    if (!headers.TryGetValue(c, out value))
                        throw new SigningBaseError("covered header " + component + " not present in supplied headers");
                    break;
            }
            lines.Add("\"" + c + "\": " + value);
        }
        if (mode == "rfc9421") lines.Add("\"@signature-params\": " + sigParamsRaw);
        return string.Join("\n", lines);
    }

    // ================= structured-field parse (port of parse.py) =================
    static readonly System.Text.RegularExpressions.Regex LabelRe =
        new(@"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*");
    static readonly System.Text.RegularExpressions.Regex CoveredRe =
        new(@"^\(\s*(?:""[^""]*""\s*)*\)");

    static void ParseSignatureInput(string header)
    {
        if (header == null) throw new ParseErr("header must be str");
        string hv = header.Trim();
        if (hv.Length == 0) throw new ParseErr("empty header value");
        var lm = LabelRe.Match(hv);
        string rest;
        if (lm.Success) rest = hv.Substring(lm.Length);
        else if (hv.StartsWith("(")) rest = hv;
        else throw new ParseErr("no label or covered-components list found at start");
        if (!CoveredRe.IsMatch(rest)) throw new ParseErr("no covered-components list found");
    }

    static void ParseSignatureValue(string header)
    {
        if (header == null) throw new ParseErr("header must be str");
        string hv = header.Trim();
        if (hv.Length == 0) throw new ParseErr("empty Signature header value");
        var lm = LabelRe.Match(hv);
        string rest;
        if (lm.Success) rest = hv.Substring(lm.Length).Trim();
        else if (hv.StartsWith(":")) rest = hv;
        else throw new ParseErr("no label or signature-value prefix found at start");
        if (!rest.StartsWith(":") || !rest.EndsWith(":") || rest.Length < 2)
            throw new ParseErr("signature value must be wrapped in colons");
        string sigB64 = rest.Substring(1, rest.Length - 2);
        byte[] decoded;
        try { decoded = Convert.FromBase64String(sigB64); }
        catch (FormatException) { throw new ParseErr("signature value is not valid base64"); }
        if (Convert.ToBase64String(decoded) != sigB64)
            throw new ParseErr("signature value is not canonical base64 (non-zero pad bits)");
    }

    // ================= Ed25519 key gate (port of keycheck.py) =================
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    static BigInteger Mod(BigInteger a) { BigInteger r = a % P; return r.Sign < 0 ? r + P : r; }
    static BigInteger Inv(BigInteger a) => BigInteger.ModPow(Mod(a), P - 2, P);
    static readonly BigInteger D = Mod(new BigInteger(-121665) * Inv(121666));
    static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    static bool IsOdd(BigInteger x) => !x.IsEven;

    static BigInteger[] RecoverX(BigInteger y, int sign)
    {
        if (y >= P) return null;
        BigInteger y2 = Mod(y * y);
        BigInteger x2 = Mod(Mod(y2 - 1) * Inv(Mod(D * y2 + 1)));
        if (x2.IsZero) return sign == 1 ? null : new[] { BigInteger.Zero };
        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (!Mod(x * x - x2).IsZero) x = Mod(x * SqrtM1);
        if (!Mod(x * x - x2).IsZero) return null;
        if (IsOdd(x) ? sign == 0 : sign == 1) x = P - x;
        return new[] { x };
    }

    static BigInteger[] DecodePoint(byte[] pk)
    {
        if (pk.Length != 32) return null;
        var le = (byte[])pk.Clone();
        BigInteger y = new BigInteger(le, isUnsigned: true, isBigEndian: false);
        int sign = (pk[31] >> 7) & 1;
        y &= (BigInteger.One << 255) - 1;
        var xr = RecoverX(y, sign);
        if (xr == null) return null;
        BigInteger x = xr[0];
        return new[] { x, y, BigInteger.One, Mod(x * y) };
    }

    static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
    {
        BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
        BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
        BigInteger c = Mod(2 * p[3] * q[3] * D);
        BigInteger dd = Mod(2 * p[2] * q[2]);
        BigInteger e = b - a, f = dd - c, g = dd + c, h = b + a;
        return new[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
    }

    static BigInteger[] Mul8(BigInteger[] p)
    {
        var p2 = Add(p, p); var p4 = Add(p2, p2); return Add(p4, p4);
    }

    static bool IsIdentity(BigInteger[] p) => Mod(p[0]).IsZero && Mod(p[1] - p[2]).IsZero;

    static bool IsSmallOrder(byte[] pk)
    {
        var p = DecodePoint(pk);
        return p != null && IsIdentity(Mul8(p));
    }

    static void CheckEd25519PublicKey(byte[] pk)
    {
        var p = DecodePoint(pk);
        if (p == null) throw new WeakKeyError("public key is not a canonical on-curve Ed25519 point");
        if (IsIdentity(Mul8(p))) throw new WeakKeyError("public key is a small-order Ed25519 point");
    }

    // ================= Ed25519 verify (port of verify.py) =================
    static bool Ed25519Verify(byte[] msg, byte[] sig, byte[] pk)
    {
        if (sig.Length != 64) return false;
        if (pk.Length != 32) return false;
        try { CheckEd25519PublicKey(pk); } catch (WeakKeyError) { return false; }
        var signer = new Ed25519Signer();
        signer.Init(false, new Ed25519PublicKeyParameters(pk, 0));
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.VerifySignature(sig);
    }

    // ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
    static BigInteger FromBE(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);

    static bool EcdsaVerify(string curve, byte[] msg, byte[] sigRaw, byte[] pub, bool strictLowS)
    {
        try
        {
            int fieldSize = curve == "p256" ? 32 : 48;
            var named = curve == "p256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384;
            var hashAlg = curve == "p256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            BigInteger n = curve == "p256" ? N_P256 : N_P384;
            if (sigRaw.Length != 2 * fieldSize) return false;

            BigInteger r = FromBE(sigRaw[0..fieldSize]);
            BigInteger s = FromBE(sigRaw[fieldSize..(2 * fieldSize)]);
            if (r.Sign <= 0 || r >= n || s.Sign <= 0 || s >= n) return false;
            if (strictLowS && s > n / 2) return false;

            if (pub.Length != 1 + 2 * fieldSize || pub[0] != 0x04) return false;
            var ecParams = new ECParameters
            {
                Curve = named,
                Q = new ECPoint
                {
                    X = pub[1..(1 + fieldSize)],
                    Y = pub[(1 + fieldSize)..(1 + 2 * fieldSize)]
                }
            };
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(ecParams);   // validates the point is on the curve
            return ecdsa.VerifyData(msg, sigRaw, hashAlg, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception)
        {
            return false;
        }
    }

    static byte[] Hex(string s)
    {
        var o = new byte[s.Length / 2];
        for (int i = 0; i < s.Length; i += 2) o[i / 2] = Convert.ToByte(s.Substring(i, 2), 16);
        return o;
    }

    static int Main(string[] args)
    {
        string path = args.Length > 0 ? args[0]
            : Environment.GetEnvironmentVariable("ALGOVOI_NEGATIVE_V1") ?? DefaultPath;
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        int total = 0, matched = 0;
        var fails = new List<string>();

        void Record(bool ok, string section, JsonElement c)
        {
            total++;
            if (ok) matched++;
            else fails.Add("[" + section + "] " +
                (c.TryGetProperty("note", out var nn) && nn.ValueKind == JsonValueKind.String ? nn.GetString() : ""));
        }

        foreach (var c in root.GetProperty("signing_base").EnumerateArray())
        {
            string want = Encoding.UTF8.GetString(Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString()));
            string spr = c.TryGetProperty("signature_params_raw", out var sprE) && sprE.ValueKind == JsonValueKind.String
                ? sprE.GetString() : null;
            bool ok;
            try { ok = c.GetProperty("ok").GetBoolean() && BuildSigningBase(c.GetProperty("in"), c.GetProperty("mode").GetString(), spr) == want; }
            catch (Exception) { ok = !c.GetProperty("ok").GetBoolean(); }
            Record(ok, "signing_base", c);
        }
        foreach (var c in root.GetProperty("signature_input_parse").EnumerateArray())
        {
            bool parsedOk; try { ParseSignatureInput(c.GetProperty("header").GetString()); parsedOk = true; }
            catch (ParseErr) { parsedOk = false; }
            Record(parsedOk == c.GetProperty("ok").GetBoolean(), "sig_input_parse", c);
        }
        foreach (var c in root.GetProperty("signature_value_parse").EnumerateArray())
        {
            bool parsedOk; try { ParseSignatureValue(c.GetProperty("header").GetString()); parsedOk = true; }
            catch (ParseErr) { parsedOk = false; }
            Record(parsedOk == c.GetProperty("ok").GetBoolean(), "sig_value_parse", c);
        }
        foreach (var c in root.GetProperty("keygate").EnumerateArray())
        {
            byte[] raw = Hex(c.GetProperty("pk_hex").GetString());
            string rejected; try { CheckEd25519PublicKey(raw); rejected = null; } catch (WeakKeyError) { rejected = "WeakKeyError"; }
            string want = c.TryGetProperty("rejected", out var rj) && rj.ValueKind == JsonValueKind.String ? rj.GetString() : null;
            Record(rejected == want && IsSmallOrder(raw) == c.GetProperty("small_order").GetBoolean(), "keygate", c);
        }
        foreach (var c in root.GetProperty("ed25519_verify").EnumerateArray())
        {
            byte[] baseBytes = Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString());
            bool valid = Ed25519Verify(baseBytes, Hex(c.GetProperty("sig_hex").GetString()), Hex(c.GetProperty("pk_hex").GetString()));
            Record(valid == c.GetProperty("expect_valid").GetBoolean(), "ed25519_verify", c);
        }
        foreach (var c in root.GetProperty("ecdsa_verify").EnumerateArray())
        {
            bool strict = c.TryGetProperty("strict_low_s", out var sl) && sl.ValueKind == JsonValueKind.True;
            bool valid = EcdsaVerify(c.GetProperty("curve").GetString(), Hex(c.GetProperty("msg_hex").GetString()),
                Hex(c.GetProperty("sig_raw_hex").GetString()), Hex(c.GetProperty("pub_uncompressed_hex").GetString()), strict);
            Record(valid == c.GetProperty("expect_valid").GetBoolean(), "ecdsa_verify", c);
        }

        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet: " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
