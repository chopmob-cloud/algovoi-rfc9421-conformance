// .NET runner for the JSON Web Signature corpus (jws_v0).
//
// Independent C# port of the Python reference runner (runners/python/verify_jws.py)
// and its decision surface (tools/oracle_jws.py). Parses each compact JWS, applies
// the JOSE security gates in order (reject alg:none, reject any crit, reject
// alg/key-type mismatch such as HS256 keyed with an RSA public key, select the key
// by kid when required), then verifies the RS256 / ES256 / EdDSA signature over
// ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
// high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule). JSON via
// System.Text.Json; RS256 (RSASSA-PKCS1v15) and ES256 (ECDSA P-256, ECParameters
// .Validate() enforces on-curve) via System.Security.Cryptography; EdDSA (Ed25519)
// via Bouncy Castle (same PackageReference as the sibling dotnet-wba runner).
//
// Corpus path: argv[0], else ../../corpus/jws_v0/jws_v0.json. Exit 0 iff every
// case matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static class VerifyJws
{
    const string DefaultPath = "../../corpus/jws_v0/jws_v0.json";

    static readonly string[] Sections = {
        "jws_compact_parse", "jws_alg_none", "jws_alg_confusion", "jws_rs256_verify",
        "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"
    };

    static string AlgKty(string alg) => alg switch
    {
        "RS256" => "RSA", "ES256" => "EC", "EdDSA" => "OKP", "HS256" => "oct", _ => null
    };

    static string StrOrNull(JsonElement e)
        => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    static string GetStr(JsonElement obj, string name)
        => obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v)
            ? StrOrNull(v) : null;

    // Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
    static byte[] B64Url(string seg)
    {
        foreach (char ch in seg)
        {
            bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            if (!ok) return null;
        }
        if (seg.Length % 4 == 1) return null;
        string s = seg.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        try { return Convert.FromBase64String(s); }
        catch { return null; }
    }

    // (header, sig, signingInput) or null on any structural fault.
    static (JsonElement header, byte[] sig, byte[] si)? ParseCompact(string token)
    {
        string[] parts = token.Split('.');
        if (parts.Length != 3) return null;
        byte[] headerBytes = B64Url(parts[0]);
        if (headerBytes == null) return null;
        JsonElement header;
        try
        {
            using var doc = JsonDocument.Parse(headerBytes);
            header = doc.RootElement.Clone();
        }
        catch { return null; }
        if (header.ValueKind != JsonValueKind.Object) return null;
        if (!header.TryGetProperty("alg", out _)) return null;
        if (B64Url(parts[1]) == null) return null;
        byte[] sig = B64Url(parts[2]);
        if (sig == null) return null;
        byte[] si = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        return (header, sig, si);
    }

    static JsonElement? SelectKey(JsonElement header, JsonElement keysObj, JsonElement keyNames, bool byKid)
    {
        if (byKid)
        {
            if (!header.TryGetProperty("kid", out var kidE) || kidE.ValueKind != JsonValueKind.String)
                return null;
            string kid = kidE.GetString();
            foreach (var nameE in keyNames.EnumerateArray())
            {
                var jwk = keysObj.GetProperty(nameE.GetString());
                if (GetStr(jwk, "kid") == kid) return jwk;
            }
            return null;
        }
        return keysObj.GetProperty(keyNames[0].GetString());
    }

    static bool Rs256(JsonElement jwk, byte[] si, byte[] sig)
    {
        try
        {
            byte[] n = B64Url(GetStr(jwk, "n"));
            byte[] e = B64Url(GetStr(jwk, "e"));
            if (n == null || e == null) return false;
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
            return rsa.VerifyData(si, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch { return false; }
    }

    static bool Es256(JsonElement jwk, byte[] si, byte[] sig)
    {
        try
        {
            if (sig.Length != 64) return false;
            byte[] x = B64Url(GetStr(jwk, "x"));
            byte[] y = B64Url(GetStr(jwk, "y"));
            if (x == null || y == null || x.Length != 32 || y.Length != 32) return false;
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            };
            ecParams.Validate(); // throws for an off-curve point
            using var ecdsa = ECDsa.Create(ecParams);
            return ecdsa.VerifyData(si, sig, HashAlgorithmName.SHA256,
                                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch { return false; }
    }

    static bool Eddsa(JsonElement jwk, byte[] si, byte[] sig)
    {
        try
        {
            byte[] pk = B64Url(GetStr(jwk, "x"));
            if (pk == null || pk.Length != 32 || sig.Length != 64) return false;
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(pk, 0));
            signer.BlockUpdate(si, 0, si.Length);
            return signer.VerifySignature(sig);
        }
        catch { return false; }
    }

    static bool Verdict(string token, JsonElement keysObj, JsonElement keyNames, bool byKid)
    {
        var parsed = ParseCompact(token);
        if (parsed == null) return false;
        var (header, sig, si) = parsed.Value;
        string alg = GetStr(header, "alg");
        if (alg == null || alg == "none") return false;
        if (header.TryGetProperty("crit", out _)) return false;
        string wantKty = AlgKty(alg);
        if (wantKty == null) return false;
        var jwkOpt = SelectKey(header, keysObj, keyNames, byKid);
        if (jwkOpt == null) return false;
        var jwk = jwkOpt.Value;
        if (GetStr(jwk, "kty") != wantKty) return false;
        return alg switch
        {
            "RS256" => Rs256(jwk, si, sig),
            "ES256" => Es256(jwk, si, sig),
            "EdDSA" => Eddsa(jwk, si, sig),
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
        var keysObj = corpus.GetProperty("keys");

        int total = 0, matched = 0;
        var fails = new List<string>();
        foreach (var sec in Sections)
        {
            if (!corpus.TryGetProperty(sec, out var arr)) continue;
            foreach (var c in arr.EnumerateArray())
            {
                var verify = c.GetProperty("verify");
                bool accept = Verdict(c.GetProperty("jws").GetString(), keysObj,
                    verify.GetProperty("key_names"),
                    verify.GetProperty("select_by_kid").ValueKind == JsonValueKind.True);
                total++;
                bool expect = c.GetProperty("expect_valid").ValueKind == JsonValueKind.True;
                if (accept == expect) matched++;
                else fails.Add("[" + sec + "] " + GetStr(c, "note"));
            }
        }
        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (jws): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
