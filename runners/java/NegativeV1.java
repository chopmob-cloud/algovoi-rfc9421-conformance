// Java runner for the rfc9421_negative_v1 CORE cross-language battery.
//
// Self-contained probe: unlike the python/typescript/go/rust runners (which import
// the published AlgoVoi verifier for their language), no Java RFC 9421 verifier
// exists yet, so this runner re-implements the exact verdict surface inline,
// ported from the reference modules (signing_base.py, parse.py, keycheck.py,
// verify.py) and the algovoi-rfc9421-ecdsa provider. It must produce byte-identical
// verdicts to the other runners on every case: reject every negative, accept every
// positive control.
//
// Crypto: Ed25519 verify + canonical-S enforcement via Bouncy Castle
// (Ed25519Signer rejects non-canonical S and wrong-length signatures); the
// small-order / non-canonical public-key gate is ported from keycheck.py with
// java.math.BigInteger (RFC 8032 Appendix A arithmetic), applied fail-closed
// BEFORE verification. ECDSA P-256/P-384 uses the JDK provider over a raw r||s
// signature with explicit [1,n-1] range, fixed-width, on-curve and strict-low-s
// checks.
//
// Corpus path: argv[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NegativeV1 {

    static final String DEFAULT_PATH =
        "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json";

    // ---- errors that mirror the reference's fail-closed exceptions ----
    static final class SigningBaseError extends RuntimeException {
        SigningBaseError(String m) { super(m); }
    }
    static final class ParseError extends RuntimeException {
        ParseError(String m) { super(m); }
    }
    static final class WeakKeyError extends RuntimeException {
        WeakKeyError(String m) { super(m); }
    }

    // ================= signing base (port of signing_base.py) =================
    static String buildSigningBase(JsonNode in, String mode, String signatureParamsRaw) {
        if (!mode.equals("algovoi-v0") && !mode.equals("rfc9421")) {
            throw new SigningBaseError("mode must be 'algovoi-v0' or 'rfc9421', got " + mode);
        }
        if (mode.equals("rfc9421") && signatureParamsRaw == null) {
            throw new SigningBaseError("rfc9421 mode requires signature_params_raw");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        JsonNode h = in.get("headers");
        if (h != null && h.isObject()) {
            for (Iterator<String> it = h.fieldNames(); it.hasNext(); ) {
                String k = it.next();
                headers.put(k.toLowerCase(), h.get(k).asText());
            }
        }
        JsonNode params = in.get("parameters");

        List<String> lines = new ArrayList<>();
        JsonNode covered = in.get("covered_components");
        for (JsonNode compNode : covered) {
            String component = compNode.asText();
            String c = component.toLowerCase();
            String value;
            switch (c) {
                case "@method":
                    value = strOrThrow(in, "method", "@method covered but method not supplied");
                    if (!mode.equals("rfc9421")) value = value.toLowerCase();
                    break;
                case "@authority":
                    value = strOrThrow(in, "authority", "@authority covered but authority not supplied").toLowerCase();
                    break;
                case "@path":
                    value = strOrThrow(in, "path", "@path covered but path not supplied");
                    break;
                case "@target-uri":
                    value = strOrThrow(in, "target_uri", "@target-uri covered but target_uri not supplied");
                    break;
                case "@scheme":
                    value = strOrThrow(in, "scheme", "@scheme covered but scheme not supplied").toLowerCase();
                    break;
                case "@status":
                    if (in.get("status") == null || in.get("status").isNull())
                        throw new SigningBaseError("@status covered but status not supplied");
                    value = in.get("status").bigIntegerValue().toString();
                    break;
                case "created":
                    value = paramStrOrThrow(params, "created",
                        "'created' covered but no 'created' parameter in Signature-Input");
                    break;
                case "expires":
                    value = paramStrOrThrow(params, "expires",
                        "'expires' covered but no 'expires' parameter in Signature-Input");
                    break;
                default:
                    if (c.startsWith("@"))
                        throw new SigningBaseError("unsupported derived component: " + component);
                    if (!headers.containsKey(c))
                        throw new SigningBaseError("covered header " + component + " not present in supplied headers");
                    value = headers.get(c);
            }
            lines.add("\"" + c + "\": " + value);
        }
        if (mode.equals("rfc9421")) {
            lines.add("\"@signature-params\": " + signatureParamsRaw);
        }
        return String.join("\n", lines);
    }

    static String strOrThrow(JsonNode in, String field, String msg) {
        JsonNode n = in.get(field);
        if (n == null || n.isNull()) throw new SigningBaseError(msg);
        return n.asText();
    }

    static String paramStrOrThrow(JsonNode params, String key, String msg) {
        if (params == null || !params.has(key)) throw new SigningBaseError(msg);
        JsonNode v = params.get(key);
        return v.isIntegralNumber() ? v.bigIntegerValue().toString() : v.asText();
    }

    // ================= structured-field parse (port of parse.py) =================
    static void parseSignatureInput(String header) {
        if (header == null) throw new ParseError("header must be str");
        String hv = header.strip();
        if (hv.isEmpty()) throw new ParseError("empty header value");
        String rest;
        java.util.regex.Matcher lm =
            java.util.regex.Pattern.compile("^\\s*([A-Za-z][A-Za-z0-9_-]*)\\s*=\\s*").matcher(hv);
        if (lm.find()) {
            rest = hv.substring(lm.end());
        } else if (hv.startsWith("(")) {
            rest = hv;
        } else {
            throw new ParseError("no label or covered-components list found at start");
        }
        java.util.regex.Matcher cm =
            java.util.regex.Pattern.compile("\\(\\s*(?:\"[^\"]*\"\\s*)*\\)").matcher(rest);
        if (!cm.lookingAt()) throw new ParseError("no covered-components list found");
        // parameters after the covered list are optional and, per parse.py, are
        // tolerantly scanned; only the structural pieces above can reject.
    }

    static void parseSignatureValue(String header) {
        if (header == null) throw new ParseError("header must be str");
        String hv = header.strip();
        if (hv.isEmpty()) throw new ParseError("empty Signature header value");
        String rest;
        java.util.regex.Matcher lm =
            java.util.regex.Pattern.compile("^\\s*([A-Za-z][A-Za-z0-9_-]*)\\s*=\\s*").matcher(hv);
        if (lm.find()) {
            rest = hv.substring(lm.end()).strip();
        } else if (hv.startsWith(":")) {
            rest = hv;
        } else {
            throw new ParseError("no label or signature-value prefix found at start");
        }
        if (!rest.startsWith(":") || !rest.endsWith(":") || rest.length() < 2) {
            throw new ParseError("signature value must be wrapped in colons");
        }
        String sigB64 = rest.substring(1, rest.length() - 1);
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(sigB64);
        } catch (IllegalArgumentException e) {
            throw new ParseError("signature value is not valid base64");
        }
        // Reject NON-CANONICAL base64 (non-zero pad bits): require exact round-trip.
        if (!Base64.getEncoder().encodeToString(decoded).equals(sigB64)) {
            throw new ParseError("signature value is not canonical base64 (non-zero pad bits)");
        }
    }

    // ================= Ed25519 key gate (port of keycheck.py) =================
    static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    static final BigInteger D = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    static final BigInteger SQRT_M1 =
        BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

    static BigInteger recoverX(BigInteger y, int sign) {
        if (y.compareTo(P) >= 0) return null;
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger num = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger den = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = num.multiply(den.modInverse(P)).mod(P);
        if (x2.signum() == 0) return (sign == 1) ? null : BigInteger.ZERO;
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P);
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null;
        if (x.testBit(0) ? sign == 0 : sign == 1) x = P.subtract(x);
        return x;
    }

    // extended coords (X, Y, Z, T)
    static BigInteger[] decodePoint(byte[] pk) {
        if (pk.length != 32) return null;
        byte[] le = new byte[32];
        for (int i = 0; i < 32; i++) le[i] = pk[31 - i];
        BigInteger y = new BigInteger(1, le);
        int sign = y.testBit(255) ? 1 : 0;
        y = y.clearBit(255);
        BigInteger x = recoverX(y, sign);
        if (x == null) return null;
        return new BigInteger[]{x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    }

    static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = BigInteger.TWO.multiply(p[3]).multiply(q[3]).multiply(D).mod(P);
        BigInteger dd = BigInteger.TWO.multiply(p[2]).multiply(q[2]).mod(P);
        BigInteger e = b.subtract(a), f = dd.subtract(c), g = dd.add(c), hh = b.add(a);
        return new BigInteger[]{e.multiply(f).mod(P), g.multiply(hh).mod(P),
                                f.multiply(g).mod(P), e.multiply(hh).mod(P)};
    }

    static BigInteger[] mul8(BigInteger[] p) {
        BigInteger[] p2 = add(p, p);
        BigInteger[] p4 = add(p2, p2);
        return add(p4, p4);
    }

    static boolean isIdentity(BigInteger[] p) {
        return p[0].mod(P).signum() == 0 && p[1].subtract(p[2]).mod(P).signum() == 0;
    }

    static boolean isSmallOrder(byte[] pk) {
        BigInteger[] p = decodePoint(pk);
        if (p == null) return false;
        return isIdentity(mul8(p));
    }

    static void checkEd25519PublicKey(byte[] pk) {
        BigInteger[] p = decodePoint(pk);
        if (p == null) throw new WeakKeyError("public key is not a canonical on-curve Ed25519 point");
        if (isIdentity(mul8(p))) throw new WeakKeyError("public key is a small-order Ed25519 point");
    }

    // ================= Ed25519 verify (port of verify.py) =================
    static boolean ed25519Verify(byte[] msg, byte[] sig, byte[] pk) {
        if (sig.length != 64) return false;      // reference: wrong length -> invalid
        if (pk.length != 32) return false;
        try {
            checkEd25519PublicKey(pk);            // fail-closed key gate before verify
        } catch (WeakKeyError e) {
            return false;
        }
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(pk, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, pub);
        signer.update(msg, 0, msg.length);
        return signer.verifySignature(sig);       // BC rejects non-canonical S
    }

    // ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
    static boolean ecdsaVerify(String curve, byte[] msg, byte[] sigRaw, byte[] pub, boolean strictLowS) {
        try {
            int fieldSize = curve.equals("p256") ? 32 : 48;
            String stdName = curve.equals("p256") ? "secp256r1" : "secp384r1";
            String sigAlg = curve.equals("p256") ? "SHA256withECDSA" : "SHA384withECDSA";
            if (sigRaw.length != 2 * fieldSize) return false;   // wrong width

            BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sigRaw, 0, fieldSize));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sigRaw, fieldSize, 2 * fieldSize));

            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(stdName));
            ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
            BigInteger n = spec.getOrder();

            // r, s in [1, n-1]
            if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0)
                return false;
            if (strictLowS && s.compareTo(n.shiftRight(1)) > 0) return false;

            // decode SEC1 uncompressed public point and validate on-curve
            if (pub.length != 1 + 2 * fieldSize || pub[0] != 0x04) return false;
            BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(pub, 1, 1 + fieldSize));
            BigInteger yc = new BigInteger(1, java.util.Arrays.copyOfRange(pub, 1 + fieldSize, 1 + 2 * fieldSize));
            BigInteger pMod = ((java.security.spec.ECFieldFp) spec.getCurve().getField()).getP();
            BigInteger aa = spec.getCurve().getA(), bb = spec.getCurve().getB();
            BigInteger lhs = yc.multiply(yc).mod(pMod);
            BigInteger rhs = x.multiply(x).multiply(x).add(aa.multiply(x)).add(bb).mod(pMod);
            if (!lhs.equals(rhs)) return false;      // off-curve public key

            ECPublicKeySpec pubSpec = new ECPublicKeySpec(new ECPoint(x, yc), spec);
            java.security.PublicKey key = KeyFactory.getInstance("EC").generatePublic(pubSpec);

            // DER-encode r||s for the JDK verifier
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            byte[] der = new DERSequence(v).getEncoded("DER");

            Signature verifier = Signature.getInstance(sigAlg);
            verifier.initVerify(key);
            verifier.update(msg);
            return verifier.verify(der);
        } catch (Exception e) {
            return false;   // any setup failure -> invalid, matching the reference
        }
    }

    // ================= driver =================
    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0]
            : System.getenv().getOrDefault("ALGOVOI_NEGATIVE_V1", DEFAULT_PATH);
        JsonNode corpus = new ObjectMapper().readTree(new File(path));

        int total = 0, matched = 0;
        List<String> fails = new ArrayList<>();

        for (JsonNode c : corpus.get("signing_base")) {
            total++;
            boolean ok;
            String want = new String(Base64.getDecoder().decode(c.get("signing_base_b64").asText()), StandardCharsets.UTF_8);
            String spr = c.hasNonNull("signature_params_raw") ? c.get("signature_params_raw").asText() : null;
            try {
                // build FIRST; `ok && build(...)` would short-circuit for negative
                // cases and never verify that the build actually fails.
                String built = buildSigningBase(c.get("in"), c.get("mode").asText(), spr);
                ok = c.get("ok").asBoolean() && built.equals(want);
            } catch (RuntimeException e) {
                ok = !c.get("ok").asBoolean();
            }
            record(ok, "signing_base", c, fails); if (ok) matched++;
        }
        for (JsonNode c : corpus.get("signature_input_parse")) {
            total++;
            boolean parsedOk;
            try { parseSignatureInput(c.get("header").asText()); parsedOk = true; }
            catch (ParseError e) { parsedOk = false; }
            boolean ok = parsedOk == c.get("ok").asBoolean();
            record(ok, "sig_input_parse", c, fails); if (ok) matched++;
        }
        for (JsonNode c : corpus.get("signature_value_parse")) {
            total++;
            boolean parsedOk;
            try { parseSignatureValue(c.get("header").asText()); parsedOk = true; }
            catch (ParseError e) { parsedOk = false; }
            boolean ok = parsedOk == c.get("ok").asBoolean();
            record(ok, "sig_value_parse", c, fails); if (ok) matched++;
        }
        for (JsonNode c : corpus.get("keygate")) {
            total++;
            byte[] raw = hex(c.get("pk_hex").asText());
            String rejected;
            try { checkEd25519PublicKey(raw); rejected = null; }
            catch (WeakKeyError e) { rejected = "WeakKeyError"; }
            String want = c.hasNonNull("rejected") ? c.get("rejected").asText() : null;
            boolean ok = java.util.Objects.equals(rejected, want)
                && isSmallOrder(raw) == c.get("small_order").asBoolean();
            record(ok, "keygate", c, fails); if (ok) matched++;
        }
        for (JsonNode c : corpus.get("ed25519_verify")) {
            total++;
            byte[] base = Base64.getDecoder().decode(c.get("signing_base_b64").asText());
            boolean valid = ed25519Verify(base, hex(c.get("sig_hex").asText()), hex(c.get("pk_hex").asText()));
            boolean ok = valid == c.get("expect_valid").asBoolean();
            record(ok, "ed25519_verify", c, fails); if (ok) matched++;
        }
        for (JsonNode c : corpus.get("ecdsa_verify")) {
            total++;
            byte[] msg = hex(c.get("msg_hex").asText());
            boolean strict = c.hasNonNull("strict_low_s") && c.get("strict_low_s").asBoolean();
            boolean valid = ecdsaVerify(c.get("curve").asText(), msg,
                hex(c.get("sig_raw_hex").asText()), hex(c.get("pub_uncompressed_hex").asText()), strict);
            boolean ok = valid == c.get("expect_valid").asBoolean();
            record(ok, "ecdsa_verify", c, fails); if (ok) matched++;
        }

        for (String f : fails) System.out.println("FAIL  " + f);
        System.out.println("\njava: " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }

    static void record(boolean ok, String section, JsonNode c, List<String> fails) {
        if (!ok) {
            String note = c.hasNonNull("note") ? c.get("note").asText() : "";
            fails.add("[" + section + "] " + note);
        }
    }
}
