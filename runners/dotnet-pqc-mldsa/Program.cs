// .NET runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independent C# port of the Python reference runner (runners/python/verify_pqc_mldsa.py)
// and its decision surface (tools/oracle_pqc_mldsa.py): decode the hex public key,
// message and signature, reject a wrong-length public key (must be 1952) or
// signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
// signature over the exact message bytes with the EMPTY context string.
//
// JSON via System.Text.Json; crypto via Bouncy Castle (BouncyCastle.Cryptography
// 2.6.1, which carries FIPS-204 ML-DSA). MLDsaSigner over an
// MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, ...) verifies
// the pure ML-DSA variant (empty context) via Init/BlockUpdate/VerifySignature.
// BC's round-3 Dilithium classes are deliberately NOT used; a Dilithium verifier
// would fail the valid controls.
//
// Corpus path: argv[0], else $ALGOVOI_PQC_MLDSA, else ../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json.
// Exit 0 iff every case matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static class VerifyPqcMldsa
{
    const string DefaultPath = "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json";

    static readonly string[] Sections = { "mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat" };
    const int PkLen = 1952;
    const int SigLen = 3309;

    static int HexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static byte[] Hex(string s)
    {
        if (s == null || (s.Length & 1) != 0) return null;
        var o = new byte[s.Length / 2];
        for (int i = 0; i < o.Length; i++)
        {
            int hi = HexVal(s[2 * i]);
            int lo = HexVal(s[2 * i + 1]);
            if (hi < 0 || lo < 0) return null;
            o[i] = (byte)((hi << 4) | lo);
        }
        return o;
    }

    static bool Verdict(string pkHex, string msgHex, string sigHex)
    {
        byte[] pk = Hex(pkHex), msg = Hex(msgHex), sig = Hex(sigHex);
        if (pk == null || msg == null || sig == null) return false;
        if (pk.Length != PkLen || sig.Length != SigLen) return false;
        try
        {
            var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, pk);
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, false);
            signer.Init(false, pub);
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.VerifySignature(sig);
        }
        catch { return false; }
    }

    static string GetStr(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    static int Main(string[] args)
    {
        string env = Environment.GetEnvironmentVariable("ALGOVOI_PQC_MLDSA");
        string path = args.Length > 0 ? args[0] : (env ?? DefaultPath);
        JsonDocument doc;
        try { doc = JsonDocument.Parse(File.ReadAllText(path)); }
        catch (Exception e)
        {
            Console.Error.WriteLine("cannot read corpus " + path + ": " + e.Message);
            return 1;
        }
        var corpus = doc.RootElement;

        int total = 0, matched = 0;
        var fails = new List<string>();
        foreach (var sec in Sections)
        {
            if (!corpus.TryGetProperty(sec, out var arr)) continue;
            foreach (var c in arr.EnumerateArray())
            {
                bool accept = Verdict(GetStr(c, "public_key"), GetStr(c, "message"), GetStr(c, "signature"));
                total++;
                bool expect = c.GetProperty("expect_valid").ValueKind == JsonValueKind.True;
                if (accept == expect) matched++;
                else fails.Add("[" + sec + "] " + GetStr(c, "note"));
            }
        }
        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (pqc_mldsa): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
