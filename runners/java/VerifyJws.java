// Java runner for the JSON Web Signature corpus (jws_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_jws.py) and its decision surface
// (tools/oracle_jws.py) case for case. Parses each compact JWS, applies the JOSE
// security gates in order (reject alg:none, reject any crit, reject alg/key-type
// mismatch such as HS256 keyed with an RSA public key, select the key by kid when
// required), then verifies the RS256 / ES256 / EdDSA signature over
// ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
// high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule).
//
// Dependencies: org.json for JSON parsing (one jar in runners/java/libs). Crypto is
// JDK built-in: RS256 via Signature.getInstance("SHA256withRSA") over an RSA public
// key rebuilt from (n, e); ES256 via "SHA256withECDSAinP1363Format" over the raw
// 64-byte r||s, with an explicit secp256r1 on-curve check; EdDSA via the JDK EdDSA
// provider over the raw 32-byte key wrapped in an Ed25519 SPKI DER.
//
// Corpus path: args[0], else ../../corpus/jws_v0/jws_v0.json. Exit 0 iff every
// case matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class VerifyJws {

    static final String DEFAULT_PATH = "../../corpus/jws_v0/jws_v0.json";

    static final String[] SECTIONS = {
        "jws_compact_parse", "jws_alg_none", "jws_alg_confusion", "jws_rs256_verify",
        "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"
    };

    // secp256r1 parameters for the explicit on-curve check.
    static final BigInteger P256_P = new BigInteger(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    static final BigInteger P256_A = new BigInteger(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    static final BigInteger P256_B = new BigInteger(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

    static final byte[] ED_SPKI_PREFIX = hex("302a300506032b6570032100");

    static String algKty(String alg) {
        if ("RS256".equals(alg)) return "RSA";
        if ("ES256".equals(alg)) return "EC";
        if ("EdDSA".equals(alg)) return "OKP";
        if ("HS256".equals(alg)) return "oct";
        return null;
    }

    // Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
    static byte[] b64url(String seg) {
        for (int i = 0; i < seg.length(); i++) {
            char ch = seg.charAt(i);
            boolean ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            if (!ok) return null;
        }
        if (seg.length() % 4 == 1) return null;
        try {
            return Base64.getUrlDecoder().decode(seg);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static BigInteger b64uInt(String seg) {
        byte[] b = b64url(seg);
        if (b == null) return null;
        return new BigInteger(1, b);
    }

    // (header, sig, signingInput) or null on any structural fault.
    static Object[] parseCompact(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) return null;
        byte[] headerBytes = b64url(parts[0]);
        if (headerBytes == null) return null;
        JSONObject header;
        try {
            header = new JSONObject(new String(headerBytes, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return null;
        }
        if (!header.has("alg")) return null;
        if (b64url(parts[1]) == null) return null;
        byte[] sig = b64url(parts[2]);
        if (sig == null) return null;
        byte[] si = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        return new Object[]{header, sig, si};
    }

    static JSONObject selectKey(JSONObject header, JSONObject keysObj, JSONArray keyNames, boolean byKid) {
        if (byKid) {
            if (!header.has("kid") || header.isNull("kid")) return null;
            String kid = header.getString("kid");
            for (int i = 0; i < keyNames.length(); i++) {
                JSONObject jwk = keysObj.getJSONObject(keyNames.getString(i));
                if (kid.equals(jwk.optString("kid", null))) return jwk;
            }
            return null;
        }
        return keysObj.getJSONObject(keyNames.getString(0));
    }

    static boolean rs256(JSONObject jwk, byte[] si, byte[] sig) {
        try {
            BigInteger n = b64uInt(jwk.getString("n"));
            BigInteger e = b64uInt(jwk.getString("e"));
            if (n == null || e == null) return false;
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            Signature v = Signature.getInstance("SHA256withRSA");
            v.initVerify(key);
            v.update(si);
            return v.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    static boolean onCurve(BigInteger x, BigInteger y) {
        BigInteger lhs = y.multiply(y).mod(P256_P);
        BigInteger rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P);
        return lhs.equals(rhs);
    }

    static boolean es256(JSONObject jwk, byte[] si, byte[] sig) {
        try {
            if (sig.length != 64) return false;
            BigInteger x = b64uInt(jwk.getString("x"));
            BigInteger y = b64uInt(jwk.getString("y"));
            if (x == null || y == null || !onCurve(x, y)) return false;
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
            PublicKey key = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
            Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
            v.initVerify(key);
            v.update(si);
            return v.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    static boolean eddsa(JSONObject jwk, byte[] si, byte[] sig) {
        try {
            byte[] pk = b64url(jwk.getString("x"));
            if (pk == null || pk.length != 32) return false;
            byte[] der = new byte[ED_SPKI_PREFIX.length + 32];
            System.arraycopy(ED_SPKI_PREFIX, 0, der, 0, ED_SPKI_PREFIX.length);
            System.arraycopy(pk, 0, der, ED_SPKI_PREFIX.length, 32);
            PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(key);
            v.update(si);
            return v.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    static boolean verdict(String token, JSONObject keysObj, JSONArray keyNames, boolean byKid) {
        Object[] parsed = parseCompact(token);
        if (parsed == null) return false;
        JSONObject header = (JSONObject) parsed[0];
        byte[] sig = (byte[]) parsed[1];
        byte[] si = (byte[]) parsed[2];
        String alg = header.optString("alg", null);
        if (alg == null || alg.equals("none")) return false;
        if (header.has("crit")) return false;
        String wantKty = algKty(alg);
        if (wantKty == null) return false;
        JSONObject jwk = selectKey(header, keysObj, keyNames, byKid);
        if (jwk == null) return false;
        if (!wantKty.equals(jwk.optString("kty", null))) return false;
        switch (alg) {
            case "RS256": return rs256(jwk, si, sig);
            case "ES256": return es256(jwk, si, sig);
            case "EdDSA": return eddsa(jwk, si, sig);
            default: return false;
        }
    }

    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : DEFAULT_PATH;
        String content = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        JSONObject corpus = new JSONObject(content);
        JSONObject keysObj = corpus.getJSONObject("keys");

        int total = 0, matched = 0;
        List<String> fails = new ArrayList<>();
        for (String sec : SECTIONS) {
            JSONArray arr = corpus.optJSONArray(sec);
            if (arr == null) continue;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject c = arr.getJSONObject(i);
                JSONObject verify = c.getJSONObject("verify");
                boolean accept = verdict(c.getString("jws"), keysObj,
                    verify.getJSONArray("key_names"), verify.getBoolean("select_by_kid"));
                total++;
                if (accept == c.getBoolean("expect_valid")) matched++;
                else fails.add("[" + sec + "] " + c.optString("note", ""));
            }
        }
        for (String f : fails) System.out.println("FAIL  " + f);
        System.out.println("\njava (jws): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
