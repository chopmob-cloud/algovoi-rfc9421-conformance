// .NET runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Independent C# port of the Python reference runner (runners/python/verify_wba.py,
// the authority) and its independent KAT gate (tools/check_kat_wba.py). Every
// PROFILE rule (signing base, coverage completeness, freshness window, directory
// keyid resolution, Signature-Agent SSRF, Ed25519 verification) is re-implemented
// here directly from the corpus `policy` block read at RUNTIME, NOT imported from
// a shared oracle, so a runner passing is genuine agreement rather than an echo.
// Mirrors the go/typescript runners case for case. JSON via System.Text.Json;
// Ed25519 via Bouncy Castle (same PackageReference as the sibling runners/dotnet);
// CIDR membership via System.Net.IPNetwork (IPv4 AND IPv6).
//
// Corpus path: argv[0], else ../../corpus/webbotauth_v0/webbotauth_v0.json
// relative to the project. Exit 0 iff every case matches, else 1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

static class VerifyWba
{
    const string DefaultPath = "../../corpus/webbotauth_v0/webbotauth_v0.json";

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

    // Integer per Python's isinstance(x, int): rejects floats (e.g. 15.0) and
    // non-numbers.
    static bool TryInt(JsonElement obj, string name, out long val)
    {
        val = 0;
        if (!obj.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Number)
            return false;
        string raw = v.GetRawText();
        if (raw.IndexOf('.') >= 0 || raw.IndexOf('e') >= 0 || raw.IndexOf('E') >= 0)
            return false;
        return v.TryGetInt64(out val);
    }

    static byte[] Hex(string s)
    {
        var o = new byte[s.Length / 2];
        for (int i = 0; i < s.Length; i += 2) o[i / 2] = Convert.ToByte(s.Substring(i, 2), 16);
        return o;
    }

    // ---- profile rules (re-derived from policy, per RULES 1-6) ----

    // 1. Hand-build the RFC 9421 Section 2.5 signing base by direct concatenation.
    // Returns null when a covered component's value is missing (build impossible).
    static string BuildSigningBase(JsonElement input, string paramsRaw)
    {
        var lines = new List<string>();
        JsonElement headers = default;
        bool hasHeaders = input.ValueKind == JsonValueKind.Object
            && input.TryGetProperty("headers", out headers)
            && headers.ValueKind == JsonValueKind.Object;

        if (!input.TryGetProperty("covered_components", out var covered)
            || covered.ValueKind != JsonValueKind.Array)
            return null;

        foreach (var compE in covered.EnumerateArray())
        {
            string comp = StrOrNull(compE);
            if (comp == null) return null;
            string name = comp.ToLowerInvariant();
            string val;
            switch (name)
            {
                case "@authority": val = GetStr(input, "authority"); break;
                case "@method": val = GetStr(input, "method"); break;
                case "@path": val = GetStr(input, "path"); break;
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

    // 2. Coverage completeness: every required component present (lowercased).
    static bool CoverageOk(List<string> covered, List<string> required)
    {
        var have = new HashSet<string>();
        foreach (var c in covered) have.Add(c.ToLowerInvariant());
        foreach (var r in required)
            if (!have.Contains(r.ToLowerInvariant())) return false;
        return true;
    }

    // 3. Freshness window: integers, expires > created, (created - skew) <= now < expires.
    static bool FreshnessOk(JsonElement c, long skew)
    {
        if (!TryInt(c, "created", out long created)) return false;
        if (!TryInt(c, "expires", out long expires)) return false;
        if (!TryInt(c, "now", out long now)) return false;
        if (expires <= created) return false;
        return (created - skew) <= now && now < expires;
    }

    // 4. Directory keyid resolution to a usable Ed25519 JWK.
    static bool DirectoryOk(JsonElement directory, string keyid)
    {
        if (directory.ValueKind != JsonValueKind.Array) return false;
        foreach (var jwk in directory.EnumerateArray())
        {
            if (GetStr(jwk, "kid") == keyid)
            {
                string x = GetStr(jwk, "x");
                return GetStr(jwk, "kty") == "OKP"
                    && GetStr(jwk, "crv") == "Ed25519"
                    && !string.IsNullOrEmpty(x);
            }
        }
        return false;
    }

    // 5. Signature-Agent SSRF guard (IPv4 AND IPv6 CIDR membership).
    static bool SsrfOk(string rawUrl, string resolvedIp, JsonElement ssrf)
    {
        Uri u;
        try { u = new Uri(rawUrl, UriKind.Absolute); }
        catch { return false; }

        // require_https defaults to true (present-and-false disables it).
        bool requireHttps = !ssrf.TryGetProperty("require_https", out var rh)
            || rh.ValueKind != JsonValueKind.False;
        if (requireHttps && u.Scheme != "https") return false;

        if (!string.IsNullOrEmpty(u.UserInfo)) return false; // userinfo -> reject

        string host = u.DnsSafeHost; // strips [] from IPv6 literals
        if (string.IsNullOrEmpty(host)) return false;

        IPAddress addr;
        if (!IPAddress.TryParse(host, out addr))
        {
            // Not an IP literal: fall back to the resolved address.
            if (string.IsNullOrEmpty(resolvedIp)) return false;
            if (!IPAddress.TryParse(resolvedIp, out addr)) return false;
        }

        if (ssrf.TryGetProperty("denied_cidrs", out var cidrs)
            && cidrs.ValueKind == JsonValueKind.Array)
        {
            foreach (var cidrE in cidrs.EnumerateArray())
            {
                string cidr = StrOrNull(cidrE);
                if (cidr == null) continue;
                if (!IPNetwork.TryParse(cidr, out var net)) continue;
                // IPNetwork.Contains is family-aware: it returns false for a
                // different IP version, mirroring the Python reference.
                if (net.Contains(addr)) return false;
            }
        }
        return true;
    }

    // 6. Ed25519 verify of the raw signing-base bytes under a raw 32-byte key.
    static bool Ed25519Verify(byte[] msg, string sigHex, string pkHex)
    {
        try
        {
            byte[] pk = Hex(pkHex);
            if (pk.Length != 32) return false;
            byte[] sig = Hex(sigHex);
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(pk, 0));
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.VerifySignature(sig);
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
        var required = StrList(policy.GetProperty("required_covered_components"));
        long skew = 0;
        if (policy.TryGetProperty("clock_skew_seconds", out var skewE))
            skewE.TryGetInt64(out skew);
        var ssrf = policy.GetProperty("ssrf");

        int total = 0, matched = 0;
        var fails = new List<string>();
        void Record(string section, string note, bool ok)
        {
            total++;
            if (ok) matched++;
            else fails.Add("[" + section + "] " + note);
        }

        // 1. wba_signing_base
        foreach (var c in corpus.GetProperty("wba_signing_base").EnumerateArray())
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
            Record("wba_signing_base", note, ok);
        }

        // 2. wba_coverage
        foreach (var c in corpus.GetProperty("wba_coverage").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = CoverageOk(StrList(c.GetProperty("covered_components")), required);
            Record("wba_coverage", GetStr(c, "note"), got == expect);
        }

        // 3. wba_freshness
        foreach (var c in corpus.GetProperty("wba_freshness").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = FreshnessOk(c, skew);
            Record("wba_freshness", GetStr(c, "note"), got == expect);
        }

        // 4. wba_directory
        foreach (var c in corpus.GetProperty("wba_directory").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_accept");
            bool got = DirectoryOk(c.GetProperty("directory"), GetStr(c, "keyid"));
            Record("wba_directory", GetStr(c, "note"), got == expect);
        }

        // 5. wba_directory_ssrf
        foreach (var c in corpus.GetProperty("wba_directory_ssrf").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_fetch_allowed");
            string resolvedIp = GetStr(c, "resolved_ip");
            bool got = SsrfOk(GetStr(c, "signature_agent_url"), resolvedIp, ssrf);
            Record("wba_directory_ssrf", GetStr(c, "note"), got == expect);
        }

        // 6. wba_ed25519_verify
        foreach (var c in corpus.GetProperty("wba_ed25519_verify").EnumerateArray())
        {
            bool expect = GetBool(c, "expect_valid");
            byte[] baseBytes = Convert.FromBase64String(c.GetProperty("signing_base_b64").GetString());
            bool valid = Ed25519Verify(baseBytes, GetStr(c, "sig_hex"), GetStr(c, "pk_hex"));
            Record("wba_ed25519_verify", GetStr(c, "note"), valid == expect);
        }

        foreach (var f in fails) Console.WriteLine("FAIL  " + f);
        Console.WriteLine("\ndotnet (wba): " + matched + "/" + total + " cases matched");
        return matched == total ? 0 : 1;
    }
}
