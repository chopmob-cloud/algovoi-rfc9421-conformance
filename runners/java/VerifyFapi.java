// Java runner for the FAPI 2.0 Message Signing profile corpus (fapi_messagesigning_v0).
//
// Independently reproduces every verdict in the frozen corpus. The PROFILE rules
// (signing base, mandated covered-component completeness, Content-Digest body
// binding, PS256/ES256 algorithm restriction) are re-implemented here from the
// corpus `policy` block read at RUNTIME, NOT imported from the generator's
// oracle, so a runner passing is genuine agreement rather than an echo. This
// mirrors the Python reference runner (runners/python/verify_fapi.py) case for
// case, and follows the sibling java runners' conventions (org.json for JSON as
// in VerifyWba.java; RSA-PSS + ECDSA over the JDK provider as in NegativeV1.java).
//
// Dependencies: org.json for JSON parsing (one jar in runners/java/libs). Crypto
// is JDK built-in: RSASSA-PSS via Signature.getInstance("RSASSA-PSS") with a
// PSSParameterSpec(SHA-256, MGF1/SHA-256, saltLen 32, trailer 1); ECDSA P-256 via
// Signature.getInstance("SHA256withECDSAinP1363Format"), which accepts the raw
// 64-byte r||s signature directly. Public keys are rebuilt with KeyFactory (an
// X.509 SPKI DER for RSA; the SEC1 uncompressed EC point for ECDSA).
//
// Corpus path: args[0], else the repo corpus relative to the runner directory
// (runners/java), i.e. ../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json.
//
// Exit 0 iff every case matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class VerifyFapi {

    static final String DEFAULT_PATH =
        "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json";

    // ---- error that mirrors the reference's fail-closed exceptions ----
    static final class SigningBaseError extends RuntimeException {
        SigningBaseError(String m) { super(m); }
    }

    // ================= Section 1: signing base (RFC 9421 Section 2.5) =================
    // Hand-built by direct concatenation, mirroring the sibling WBA runner: for
    // each covered component (lowercased name) emit `"name": value`, then append
    // `"@signature-params": <signature_params_raw>`, joined by "\n". Derived
    // components map @method->method, @target-uri->target_uri, @status->str(status),
    // @authority->authority, @path->path; anything else is a header lookup.
    static String buildSigningBase(JSONObject in, String paramsRaw) {
        List<String> lines = new ArrayList<>();
        JSONArray covered = in.getJSONArray("covered_components");
        for (int i = 0; i < covered.length(); i++) {
            String name = covered.getString(i).toLowerCase();
            String val;
            switch (name) {
                case "@method":
                    val = strOrThrow(in, "method");
                    break;
                case "@target-uri":
                    val = strOrThrow(in, "target_uri");
                    break;
                case "@status":
                    if (!in.has("status") || in.isNull("status"))
                        throw new SigningBaseError("@status covered but status not supplied");
                    val = String.valueOf(in.getInt("status"));
                    break;
                case "@authority":
                    val = strOrThrow(in, "authority");
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

    // ================= Section 2: required coverage completeness =================
    // required = policy.required_covered_request / _response by message_type; every
    // required component (lowercased) must be in the covered set (lowercased).
    static boolean coverageOk(String messageType, List<String> covered, JSONObject policy) {
        String key = "request".equals(messageType)
            ? "required_covered_request" : "required_covered_response";
        List<String> required = strList(policy.getJSONArray(key));
        List<String> have = new ArrayList<>();
        for (String c : covered) have.add(c.toLowerCase());
        for (String r : required) {
            if (!have.contains(r.toLowerCase())) return false;
        }
        return true;
    }

    // ================= Section 3: Content-Digest body binding =================
    // "content-digest" must be covered; the header algorithm (first "=" split,
    // lowercased) must be in policy.content_digest_algorithms; the digest of the
    // base64-decoded body must equal the header value exactly (`<alg>=:<b64>:`).
    static boolean contentDigestOk(String bodyB64, String headerValue, List<String> covered, JSONObject policy) {
        List<String> haveCov = new ArrayList<>();
        for (String c : covered) haveCov.add(c.toLowerCase());
        if (!haveCov.contains("content-digest")) return false;

        int eq = headerValue.indexOf('=');
        if (eq < 0) return false;
        String algorithm = headerValue.substring(0, eq).trim().toLowerCase();

        List<String> algs = strList(policy.getJSONArray("content_digest_algorithms"));
        if (!algs.contains(algorithm)) return false;

        byte[] body = Base64.getDecoder().decode(bodyB64);
        byte[] digest;
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.equals("sha-256") ? "SHA-256" : "SHA-512");
            digest = md.digest(body);
        } catch (Exception e) {
            return false;
        }
        String expect = algorithm + "=:" + Base64.getEncoder().encodeToString(digest) + ":";
        return headerValue.trim().equals(expect);
    }

    // ================= Section 5: PS256 verify (RSA-PSS SHA-256, salt 32) =================
    static boolean ps256Ok(byte[] base, byte[] sig, byte[] spkiDer) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spkiDer));
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initVerify(key);
            s.update(base);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    // ================= Section 6: ES256 verify (ECDSA P-256 SHA-256, low-s) =================
    // Raw 64-byte r||s: r = first 32 bytes, s = last 32 bytes (unsigned). Under
    // require_low_s a signature with s > n/2 is rejected before verification;
    // otherwise the raw signature is verified directly with the P1363-format
    // ECDSA verifier over the SEC1 uncompressed public point.
    static boolean es256Ok(byte[] base, byte[] sigRaw, byte[] pubUncompressed, boolean requireLowS, JSONObject policy) {
        try {
            if (sigRaw.length != 64) return false;
            BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sigRaw, 0, 32));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sigRaw, 32, 64));

            if (requireLowS) {
                BigInteger n = new BigInteger(policy.getString("p256_n"));
                if (s.compareTo(n.divide(BigInteger.TWO)) > 0) return false;
            }

            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);

            if (pubUncompressed.length != 65 || pubUncompressed[0] != 0x04) return false;
            BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(pubUncompressed, 1, 33));
            BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(pubUncompressed, 33, 65));
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(new ECPoint(x, y), spec);
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(pubSpec);

            // P1363 format accepts the raw fixed-width r||s concatenation directly.
            Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(key);
            verifier.update(base);
            return verifier.verify(sigRaw);
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

        List<Result> results = new ArrayList<>();

        // 1. fapi_signing_base
        JSONArray sb = corpus.getJSONArray("fapi_signing_base");
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
            results.add(new Result("fapi_signing_base", note, matched));
        }

        // 2. fapi_required_coverage
        JSONArray cov = corpus.getJSONArray("fapi_required_coverage");
        for (int i = 0; i < cov.length(); i++) {
            JSONObject c = cov.getJSONObject(i);
            boolean got = coverageOk(c.getString("message_type"), strList(c.getJSONArray("covered_components")), policy);
            results.add(new Result("fapi_required_coverage", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 3. fapi_content_digest
        JSONArray cd = corpus.getJSONArray("fapi_content_digest");
        for (int i = 0; i < cd.length(); i++) {
            JSONObject c = cd.getJSONObject(i);
            boolean got = contentDigestOk(c.getString("body_b64"), c.getString("content_digest"),
                strList(c.getJSONArray("covered_components")), policy);
            results.add(new Result("fapi_content_digest", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 4. fapi_alg
        JSONArray al = corpus.getJSONArray("fapi_alg");
        List<String> allowed = strList(policy.getJSONArray("allowed_algs"));
        for (int i = 0; i < al.length(); i++) {
            JSONObject c = al.getJSONObject(i);
            boolean got = allowed.contains(c.getString("alg").toLowerCase());
            results.add(new Result("fapi_alg", c.optString("note", ""), got == c.getBoolean("expect_accept")));
        }

        // 5. fapi_ps256_verify
        JSONArray ps = corpus.getJSONArray("fapi_ps256_verify");
        for (int i = 0; i < ps.length(); i++) {
            JSONObject c = ps.getJSONObject(i);
            byte[] base = Base64.getDecoder().decode(c.getString("signing_base_b64"));
            boolean valid = ps256Ok(base, hex(c.getString("sig_hex")), hex(c.getString("pub_spki_hex")));
            results.add(new Result("fapi_ps256_verify", c.optString("note", ""), valid == c.getBoolean("expect_valid")));
        }

        // 6. fapi_es256_verify
        JSONArray es = corpus.getJSONArray("fapi_es256_verify");
        for (int i = 0; i < es.length(); i++) {
            JSONObject c = es.getJSONObject(i);
            byte[] base = Base64.getDecoder().decode(c.getString("signing_base_b64"));
            boolean requireLowS = c.optBoolean("require_low_s", false);
            boolean valid = es256Ok(base, hex(c.getString("sig_raw_hex")), hex(c.getString("pub_uncompressed_hex")), requireLowS, policy);
            results.add(new Result("fapi_es256_verify", c.optString("note", ""), valid == c.getBoolean("expect_valid")));
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
        System.out.println("\njava (fapi): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
