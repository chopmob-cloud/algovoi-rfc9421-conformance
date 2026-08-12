// Java runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Independently reproduces every verdict in the frozen corpus. The PROFILE rules
// (signing base, coverage completeness, freshness window, directory keyid
// resolution, Signature-Agent SSRF, Ed25519 verification) are re-implemented here
// from the corpus `policy` block read at RUNTIME, NOT imported from the
// generator's oracle, so a runner passing is genuine agreement rather than an
// echo. This mirrors the Python reference runner (runners/python/verify_wba.py),
// the Go runner (runners/go/verify_wba_go.go), the TypeScript runner
// (runners/typescript/verify_wba.mjs), and the independent KAT gate
// (tools/check_kat_wba.py) case for case.
//
// Dependencies (same JSON library as the sibling java runner path): org.json for
// JSON parsing; Ed25519 is verified with the JDK's built-in EdDSA provider
// (Java 15+) over the raw 32-byte key wrapped in an Ed25519 SPKI DER, matching
// the TypeScript runner's approach. IPv4 and IPv6 CIDR membership is implemented
// inline with java.math.BigInteger (no java.net address resolution, no DNS).
//
// Corpus path: args[0], else the repo corpus relative to the runner directory
// (runners/java), i.e. ../../corpus/webbotauth_v0/webbotauth_v0.json.
//
// Exit 0 iff every case matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class VerifyWba {

    static final String DEFAULT_PATH =
        "../../corpus/webbotauth_v0/webbotauth_v0.json";

    // ---- errors that mirror the reference's fail-closed exceptions ----
    static final class SigningBaseError extends RuntimeException {
        SigningBaseError(String m) { super(m); }
    }

    // ================= Rule 1: signing base (RFC 9421 Section 2.5) =================
    // Hand-built by direct concatenation, mirroring the TS/Go WBA runners and the
    // KAT gate: for each covered component (lowercased name) emit `"name": value`,
    // then append `"@signature-params": <signature_params_raw>`, joined by "\n".
    static String buildSigningBase(JSONObject in, String paramsRaw) {
        List<String> lines = new ArrayList<>();
        JSONArray covered = in.getJSONArray("covered_components");
        for (int i = 0; i < covered.length(); i++) {
            String name = covered.getString(i).toLowerCase();
            String val;
            switch (name) {
                case "@authority":
                    val = strOrThrow(in, "authority");
                    break;
                case "@method":
                    val = strOrThrow(in, "method");
                    break;
                case "@path":
                    val = strOrThrow(in, "path");
                    break;
                default:
                    if (!in.has("headers") || in.isNull("headers"))
                        throw new SigningBaseError("headers not supplied for covered component " + name);
                    JSONObject headers = in.getJSONObject("headers");
                    if (!headers.has(name) || headers.isNull(name))
                        throw new SigningBaseError("covered header " + name + " not present in supplied headers");
                    val = headers.getString(name);
            }
            lines.add("\"" + name + "\": " + val);
        }
        lines.add("\"@signature-params\": " + paramsRaw);
        return String.join("\n", lines);
    }

    static String strOrThrow(JSONObject o, String field) {
        if (!o.has(field) || o.isNull(field))
            throw new SigningBaseError(field + " covered but not supplied");
        return o.getString(field);
    }

    // ================= Rule 2: coverage completeness =================
    static boolean coverageOk(List<String> covered, List<String> required) {
        List<String> have = new ArrayList<>();
        for (String c : covered) have.add(c.toLowerCase());
        for (String r : required) {
            if (!have.contains(r.toLowerCase())) return false;
        }
        return true;
    }

    // ================= Rule 3: freshness window =================
    // All three must be JSON integers (floats/non-numbers rejected, mirroring
    // Python isinstance(x, int)), expires > created, (created - skew) <= now < expires.
    static boolean isInt(Object v) {
        return v instanceof Integer || v instanceof Long || v instanceof BigInteger;
    }

    static boolean freshnessOk(Object created, Object expires, Object now, long skew) {
        if (!isInt(created) || !isInt(expires) || !isInt(now)) return false;
        long c = ((Number) created).longValue();
        long e = ((Number) expires).longValue();
        long n = ((Number) now).longValue();
        if (e <= c) return false;
        return (c - skew) <= n && n < e;
    }

    // ================= Rule 4: directory keyid resolution =================
    static boolean directoryOk(JSONArray directory, String keyid) {
        for (int i = 0; i < directory.length(); i++) {
            JSONObject jwk = directory.getJSONObject(i);
            if (keyid.equals(jwk.opt("kid"))) {
                return "OKP".equals(jwk.opt("kty"))
                    && "Ed25519".equals(jwk.opt("crv"))
                    && !jwk.optString("x", "").isEmpty();
            }
        }
        return false;
    }

    // ================= Rule 5: Signature-Agent SSRF guard =================
    static boolean ssrfOk(String url, String resolvedIp, boolean requireHttps, JSONArray deniedCidrs) {
        URI u;
        try {
            u = new URI(url);
        } catch (Exception e) {
            return false;
        }
        String scheme = u.getScheme();
        if (requireHttps && !"https".equals(scheme)) return false;
        // userinfo present ("user@host") -> reject (mirrors Python '@' in netloc)
        String authority = u.getRawAuthority();
        if (authority != null && authority.indexOf('@') >= 0) return false;
        String host = u.getHost();
        if (host == null || host.isEmpty()) return false;
        // strip [] from IPv6 literals
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        Addr addr = parseAddr(host);
        if (addr == null) {
            // not an IP literal -> rely on the resolved address
            if (resolvedIp == null || resolvedIp.isEmpty()) return false;
            addr = parseAddr(resolvedIp);
            if (addr == null) return false;
        }
        for (int i = 0; i < deniedCidrs.length(); i++) {
            Cidr net = parseCidr(deniedCidrs.getString(i));
            if (net == null) continue;
            // same IP version only, mirroring the Python reference
            if (net.version == addr.version && inNet(addr, net)) return false;
        }
        return true;
    }

    static final class Addr {
        final int version;      // 4 or 6
        final BigInteger value;
        final int bits;         // 32 or 128
        Addr(int version, BigInteger value, int bits) {
            this.version = version; this.value = value; this.bits = bits;
        }
    }

    static final class Cidr {
        final int version;
        final BigInteger value;
        final int prefix;
        final int bits;
        Cidr(int version, BigInteger value, int prefix, int bits) {
            this.version = version; this.value = value; this.prefix = prefix; this.bits = bits;
        }
    }

    static BigInteger parseIPv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) return null;
        BigInteger v = BigInteger.ZERO;
        for (String p : parts) {
            if (p.isEmpty() || !p.chars().allMatch(Character::isDigit)) return null;
            if (p.length() > 1 && p.charAt(0) == '0') return null; // reject leading zeros (py3.9+ strict)
            int n;
            try {
                n = Integer.parseInt(p);
            } catch (NumberFormatException e) {
                return null;
            }
            if (n > 255) return null;
            v = v.shiftLeft(8).or(BigInteger.valueOf(n));
        }
        return v;
    }

    // returns list of 16-bit groups, or null on malformed segment
    static int[] groupsOf(String part) {
        if (part.isEmpty()) return new int[0];
        String[] segs = part.split(":", -1);
        List<Integer> out = new ArrayList<>();
        for (int k = 0; k < segs.length; k++) {
            String seg = segs[k];
            if (seg.indexOf('.') >= 0) {
                if (k != segs.length - 1) return null; // embedded IPv4 must be last
                BigInteger v4 = parseIPv4(seg);
                if (v4 == null) return null;
                int val = v4.intValue();
                out.add((val >> 16) & 0xffff);
                out.add(val & 0xffff);
            } else {
                if (seg.isEmpty() || seg.length() > 4) return null;
                for (int j = 0; j < seg.length(); j++) {
                    char ch = seg.charAt(j);
                    boolean hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
                    if (!hex) return null;
                }
                out.add(Integer.parseInt(seg, 16));
            }
        }
        int[] arr = new int[out.size()];
        for (int i = 0; i < arr.length; i++) arr[i] = out.get(i);
        return arr;
    }

    static BigInteger parseIPv6(String s) {
        if (s == null || s.isEmpty()) return null;
        // at most one "::"
        int dc = 0;
        for (int i = 0; i + 1 < s.length(); i++) {
            if (s.charAt(i) == ':' && s.charAt(i + 1) == ':') dc++;
        }
        if (dc > 1) return null;

        int[] value;
        int idx = s.indexOf("::");
        if (idx >= 0) {
            int[] head = groupsOf(s.substring(0, idx));
            int[] tail = groupsOf(s.substring(idx + 2));
            if (head == null || tail == null) return null;
            int missing = 8 - head.length - tail.length;
            if (missing < 1) return null; // "::" must stand for at least one group
            value = new int[8];
            int p = 0;
            for (int g : head) value[p++] = g;
            for (int i = 0; i < missing; i++) value[p++] = 0;
            for (int g : tail) value[p++] = g;
        } else {
            int[] groups = groupsOf(s);
            if (groups == null || groups.length != 8) return null;
            value = groups;
        }
        if (value.length != 8) return null;

        BigInteger big = BigInteger.ZERO;
        for (int g : value) {
            if (g < 0 || g > 0xffff) return null;
            big = big.shiftLeft(16).or(BigInteger.valueOf(g));
        }
        return big;
    }

    static Addr parseAddr(String s) {
        BigInteger v4 = parseIPv4(s);
        if (v4 != null) return new Addr(4, v4, 32);
        BigInteger v6 = parseIPv6(s);
        if (v6 != null) return new Addr(6, v6, 128);
        return null;
    }

    static Cidr parseCidr(String cidr) {
        int slash = cidr.lastIndexOf('/');
        if (slash < 0) return null;
        Addr addr = parseAddr(cidr.substring(0, slash));
        if (addr == null) return null;
        int prefix;
        try {
            prefix = Integer.parseInt(cidr.substring(slash + 1));
        } catch (NumberFormatException e) {
            return null;
        }
        if (prefix < 0 || prefix > addr.bits) return null;
        return new Cidr(addr.version, addr.value, prefix, addr.bits);
    }

    static boolean inNet(Addr addr, Cidr net) {
        if (addr.version != net.version) return false;
        BigInteger full = BigInteger.ONE.shiftLeft(net.bits).subtract(BigInteger.ONE);
        int hostBits = net.bits - net.prefix;
        BigInteger mask = full.xor(BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE));
        return addr.value.and(mask).equals(net.value.and(mask));
    }

    // ================= Rule 6: Ed25519 verify (JDK EdDSA) =================
    // Raw 32-byte public key wrapped in an Ed25519 SubjectPublicKeyInfo DER,
    // matching the TypeScript runner. Any failure -> invalid (fail-closed).
    static final byte[] ED_SPKI_PREFIX = hex("302a300506032b6570032100");

    static boolean ed25519Verify(byte[] msg, byte[] sig, byte[] pk) {
        try {
            if (pk.length != 32) return false;
            byte[] der = new byte[ED_SPKI_PREFIX.length + 32];
            System.arraycopy(ED_SPKI_PREFIX, 0, der, 0, ED_SPKI_PREFIX.length);
            System.arraycopy(pk, 0, der, ED_SPKI_PREFIX.length, 32);
            PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(key);
            v.update(msg);
            return v.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    // ================= helpers =================
    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    static List<String> strList(JSONArray a) {
        List<String> out = new ArrayList<>();
        if (a == null) return out;
        for (int i = 0; i < a.length(); i++) out.add(a.getString(i));
        return out;
    }

    // ================= driver =================
    static final class Result {
        final String section; final String note; final boolean matched;
        Result(String section, String note, boolean matched) {
            this.section = section; this.note = note; this.matched = matched;
        }
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : DEFAULT_PATH;
        String content = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        JSONObject corpus = new JSONObject(content);

        JSONObject policy = corpus.getJSONObject("policy");
        List<String> required = strList(policy.getJSONArray("required_covered_components"));
        long skew = policy.optLong("clock_skew_seconds", 0);
        JSONObject ssrf = policy.getJSONObject("ssrf");
        boolean requireHttps = ssrf.optBoolean("require_https", true);
        JSONArray deniedCidrs = ssrf.getJSONArray("denied_cidrs");

        List<Result> results = new ArrayList<>();

        // 1. wba_signing_base
        JSONArray sb = corpus.getJSONArray("wba_signing_base");
        for (int i = 0; i < sb.length(); i++) {
            JSONObject c = sb.getJSONObject(i);
            String note = c.optString("note", "");
            boolean okFlag = c.getBoolean("ok");
            String want = new String(Base64.getDecoder().decode(c.getString("signing_base_b64")), StandardCharsets.UTF_8);
            String paramsRaw = c.isNull("signature_params_raw") ? null : c.optString("signature_params_raw", null);
            boolean matched;
            try {
                // build FIRST; `okFlag && build(...)` would short-circuit negative
                // cases and never verify that the build actually fails.
                String built = buildSigningBase(c.getJSONObject("in"), paramsRaw);
                matched = okFlag && built.equals(want);
            } catch (RuntimeException e) {
                matched = !okFlag;
            }
            results.add(new Result("wba_signing_base", note, matched));
        }

        // 2. wba_coverage
        JSONArray cov = corpus.getJSONArray("wba_coverage");
        for (int i = 0; i < cov.length(); i++) {
            JSONObject c = cov.getJSONObject(i);
            boolean got = coverageOk(strList(c.getJSONArray("covered_components")), required);
            results.add(new Result("wba_coverage", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 3. wba_freshness
        JSONArray fr = corpus.getJSONArray("wba_freshness");
        for (int i = 0; i < fr.length(); i++) {
            JSONObject c = fr.getJSONObject(i);
            boolean got = freshnessOk(c.get("created"), c.get("expires"), c.get("now"), skew);
            results.add(new Result("wba_freshness", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 4. wba_directory
        JSONArray dir = corpus.getJSONArray("wba_directory");
        for (int i = 0; i < dir.length(); i++) {
            JSONObject c = dir.getJSONObject(i);
            boolean got = directoryOk(c.getJSONArray("directory"), c.getString("keyid"));
            results.add(new Result("wba_directory", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 5. wba_directory_ssrf
        JSONArray ss = corpus.getJSONArray("wba_directory_ssrf");
        for (int i = 0; i < ss.length(); i++) {
            JSONObject c = ss.getJSONObject(i);
            String resolvedIp = c.isNull("resolved_ip") ? null : c.optString("resolved_ip", null);
            boolean got = ssrfOk(c.getString("signature_agent_url"), resolvedIp, requireHttps, deniedCidrs);
            results.add(new Result("wba_directory_ssrf", c.optString("note", ""), got == c.getBoolean("expect_fetch_allowed")));
        }

        // 6. wba_ed25519_verify
        JSONArray ev = corpus.getJSONArray("wba_ed25519_verify");
        for (int i = 0; i < ev.length(); i++) {
            JSONObject c = ev.getJSONObject(i);
            byte[] base = Base64.getDecoder().decode(c.getString("signing_base_b64"));
            boolean valid = ed25519Verify(base, hex(c.getString("sig_hex")), hex(c.getString("pk_hex")));
            results.add(new Result("wba_ed25519_verify", c.optString("note", ""), valid == c.getBoolean("expect_valid")));
        }

        int matched = 0;
        for (Result r : results) {
            if (r.matched) {
                matched++;
            } else {
                System.out.println("FAIL  [" + r.section + "] " + r.note);
            }
        }
        int total = results.size();
        System.out.println("\njava (wba): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
