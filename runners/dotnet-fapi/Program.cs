// .NET runner for the FAPI 2.0 Message Signing profile corpus (fapi_messagesigning_v0).
//
// Independent C# port of the Python reference runner (runners/python/verify_fapi.py,
// the authority). Every PROFILE rule (RFC 9421 Section 2.5 signing base, mandated
// covered-component completeness, Content-Digest (RFC 9530) body binding, PS256/ES256
// algorithm restriction) and the PS256 (RSA-PSS-SHA256) / ES256 (ECDSA-P256, low-s
// enforced) crypto are re-implemented here directly from the corpus `policy` block
// read at RUNTIME, NOT imported from a shared oracle, so a runner passing is genuine
// agreement rather than an echo. Mirrors the python/rust-fapi runners case for case.
// JSON via System.Text.Json; crypto via System.Security.Cryptography built-ins.
//
// Corpus path: argv[0], else ../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json
// relative to the project. Exit 0 iff every case matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static class VerifyFapi
{
    const string DefaultPath = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json";

    // ---- generic JSON helpers ----

    static string StrOrNull(JsonElement e)
        => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    static string GetStr(JsonElement obj, string name)
        => obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v)
            ? StrOrNull(v) : null;

    static bool GetBool(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    static List<string> StrList(JsonElement e)
    {
        var outp = new List<string>();
        if (e.ValueKind == JsonValueKind.Array)
            foreach (var x in e.EnumerateArray())
                if (x.ValueKind == JsonValueKind.String) outp.Add(x.GetString());
        return outp;
    }

    static byte[] Hex(string s)
    {
        var o = new byte[s.Length / 2];
        for (int i = 0; i < s.Length; i += 2) o[i / 2] = Convert.ToByte(s.Substring(i, 2), 16);
        return o;
    }

    // ---- profile rules (re-derived from policy) ----

    // 1. Hand-build the RFC 9421 Section 2.5 signing base by direct concatenation.
    // Returns null when a covered component's value is missing (build impossible).
    static string BuildSigningBase(JsonElement input, string paramsRaw)
    {
        JsonElement headers = default;
        bool hasHeaders = input.ValueKind == JsonValueKind.Object
            && input.TryGetProperty("headers", out headers)
            && headers.ValueKind == JsonValueKind.Object;

        if (input.ValueKind != JsonValueKind.Object
            || !input.TryGetProperty("covered_components", out var covered)
            || covered.ValueKind != JsonValueKind.Array)
            return null;

        var lines = new List<string>();
        foreach (var compE in covered.EnumerateArray())
        {
            string comp = StrOrNull(compE);
            if (comp == null) return null;
            string name = comp.ToLowerInvariant();
            string val;
            switch (name)
            {
                case "@method": val = GetStr(input, "method"); break;
                case "@target-uri": val = GetStr(input, "target_uri"); break;
                case "@authority": val = GetStr(input, "authority"); break;
                case "@path": val = GetStr(input, "path"); break;
                case "@status":
                    // status rendered as string (str(status) in the authority).
                    if (input.TryGetProperty("status", out var s))
                    {
                        if (s.ValueKind == JsonValueKind.Number) val = s.GetRawText();
                        else if (s.ValueKind == JsonValueKind.String) val = s.GetString();
                        else val = null;
                    }
                    else val = null;
                    break;
                default:
                    val = hasHeaders && headers.TryGetProperty(name, out var hv)
                        ? StrOrNull(hv) : null;
                    break;
            }
            if (val == null) return null;
            lines.Add("\"" + name + "\": " + val);
        }
        lines.Add("\"@signature-params\": " + paramsRaw);
        return string.Join("\n", lines);
    }

    // 2. Required coverage: every mandated component (by message_type) present,
    // case-insensitively.
    static bool CoverageOk(string messageType, List<string> covered, JsonElement policy)
    {
        string key = messageType == "request"
            ? "required_covered_request" : "required_covered_response";
        var have = new HashSet<string>();
        foreach (var c in covered) have.Add(c.ToLowerInvariant());
        foreach (var r in StrList(policy.GetProperty(key)))
            if (!have.Contains(r.ToLowerInvariant())) return false;
        return true;
    }

    // 3. Content-Digest body binding: header must be covered, use an allowed
    // algorithm, and match the recomputed digest of the base64-decoded body.
    static bool ContentDigestOk(string bodyB64, string headerValue, List<string> covered, JsonElement policy)
    {
        bool isCovered = false;
        foreach (var c in covered)
            if (c.ToLowerInvariant() == "content-digest") { isCovered = true; break; }
        if (!isCovered) return false;

        int eq = headerValue.IndexOf('=');
        if (eq < 0) return false;
        string algorithm = headerValue.Substring(0, eq).Trim().ToLowerInvariant();

        var allowed = new HashSet<string>(StrList(policy.GetProperty("content_digest_algorithms")));
        if (!allowed.Contains(algorithm)) return false;

        byte[] body = Convert.FromBase64String(bodyB64);
        byte[] digest = algorithm == "sha-256"
            ? SHA256.HashData(body) : SHA512.HashData(body);
        string expect = algorithm + "=:" + Convert.ToBase64String(digest) + ":";
        return headerValue.Trim() == expect;
    }

    // 5. PS256: RSA-PSS SHA-256 (salt length = hash length 32, .NET Pss default)
    // over the raw signing-base bytes under an RSA public key from SPKI DER.
    static bool Ps256Ok(byte[] baseBytes, byte[] sig, byte[] spkiDer)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
            return rsa.VerifyData(baseBytes, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (Exception) { return false; }
    }

    // 6. ES256: ECDSA P-256 SHA-256 over the raw signing-base bytes, with the raw
    // 64-byte r||s signature. Under require_low_s, reject s > n/2 (malleable twin).
    static bool Es256Ok(byte[] baseBytes, byte[] sigRaw, byte[] pubUncompressed,
                        bool requireLowS, JsonElement policy)
    {
        if (sigRaw.Length != 64) return false;

        if (requireLowS)
        {
            byte[] sBytes = new byte[32];
            Array.Copy(sigRaw, 32, sBytes, 0, 32);
            BigInteger s = new BigInteger(sBytes, isUnsigned: true, isBigEndian: true);
            BigInteger n = BigInteger.Parse(policy.GetProperty("p256_n").GetString());
            if (s > n / 2) return false;
        }

        try
        {
            // Uncompressed point: 0x04 || X(32) || Y(32).
            if (pubUncompressed.Length != 65 || pubUncompressed[0] != 0x04) return false;
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            Array.Copy(pubUncompressed, 1, x, 0, 32);
            Array.Copy(pubUncompressed, 33, y, 0, 32);
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            };
            ecParams.Validate();
            using var ecdsa = ECDsa.Create(ecParams);
            return ecdsa.VerifyData(baseBytes, sigRaw, HashAlgorithmName.SHA256,
                                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception) { return false; }
    }

    // ---- driver ----

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
        var policy = corpus.GetProperty("policy");
        var allowedAlgs = new HashSet<string>(StrList(policy.GetProperty("allowed_algs")));

        int total = 0, matched = 0;
        var fails = new List<string>();
        void Record(string section, string note, bool ok)
        {
            total++;
            if (ok) matched++;
            else fails.Add("[" + section + "] " + note);
        }

        // 1. fapi_signing_base
        foreach (var c in corpus.GetProperty("fapi_signing_base").EnumerateArray())
        {
            string note = GetStr(c, "note");
            bool okFlag = GetBool(c, "ok");
            string want = Encoding.UTF8.GetString(
                Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString()));
            string paramsRaw = GetStr(c, "signature_params_raw");
            // Build FIRST; `okFlag && Build(...)` would short-circuit negative
            // cases and never exercise the build-failure path.
            string built = BuildSigningBase(c.GetProperty("in"), paramsRaw);
            bool ok = built == null ? !okFlag : (okFlag && built == want);
            Record("fapi_signing_base", note, ok);
        }

        // 2. fapi_required_coverage
        foreach (var c in corpus.GetProperty("fapi_required_coverage").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = CoverageOk(GetStr(c, "message_type"),
                                  StrList(c.GetProperty("covered_components")), policy);
            Record("fapi_required_coverage", GetStr(c, "note"), got == expect);
        }

        // 3. fapi_content_digest
        foreach (var c in corpus.GetProperty("fapi_content_digest").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = ContentDigestOk(GetStr(c, "body_b64"), GetStr(c, "content_digest"),
                                       StrList(c.GetProperty("covered_components")), policy);
            Record("fapi_content_digest", GetStr(c, "note"), got == expect);
        }

        // 4. fapi_alg
        foreach (var c in corpus.GetProperty("fapi_alg").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = allowedAlgs.Contains(GetStr(c, "alg").ToLowerInvariant());
            Record("fapi_alg", GetStr(c, "note"), got == expect);
        }

        // 5. fapi_ps256_verify
        foreach (var c in corpus.GetProperty("fapi_ps256_verify").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_valid");
            byte[] baseBytes = Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString());
            bool valid = Ps256Ok(baseBytes, Hex(GetStr(c, "sig_hex")), Hex(GetStr(c, "pub_spki_hex")));
            Record("fapi_ps256_verify", GetStr(c, "note"), valid == expect);
        }

        // 6. fapi_es256_verify
        foreach (var c in corpus.GetProperty("fapi_es256_verify").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_valid");
            byte[] baseBytes = Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString());
            bool requireLowS = GetBool(c, "require_low_s");
            bool valid = Es256Ok(baseBytes, Hex(GetStr(c, "sig_raw_hex")),
                                 Hex(GetStr(c, "pub_uncompressed_hex")), requireLowS, policy);
            Record("fapi_es256_verify", GetStr(c, "note"), valid == expect);
        }

        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (fapi): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
