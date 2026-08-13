// Java runner for the COSE_Sign1 corpus (cose_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the Python
// reference runner (runners/python/verify_cose.py) and its decision surface
// (tools/oracle_cose.py) case for case. Parses each COSE_Sign1 (CBOR array of 4,
// tagged 18 or untagged), applies the COSE security gates in order (protected header
// deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in the
// protected header, an unknown crit (label 2) label rejected, alg/key-type match),
// builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
// CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
// section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is NOT
// enforced (a COSE base rule, not a FAPI rule).
//
// The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
// canonical encoder) so the deterministic judgement and the Sig_structure bytes are
// byte-identical to the frozen corpus, independent of any CBOR library's default
// map-key ordering (bytewise-lexicographic, not length-first).
//
// Dependencies: org.json (one jar in runners/java/libs). Crypto is JDK built-in:
// ES256 via "SHA256withECDSAinP1363Format" over the raw 64-byte r||s (explicit
// on-curve check); EdDSA via the JDK Ed25519 provider; PS256 via "RSASSA-PSS" with a
// PSSParameterSpec(SHA-256, MGF1/SHA-256, salt 32). Keys from the hex COSE material.
//
// Corpus path: args[0], else ../../corpus/cose_v0/cose_v0.json. Exit 0 iff every case
// matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VerifyCose {

    static final String DEFAULT_PATH = "../../corpus/cose_v0/cose_v0.json";

    static final String[] SECTIONS = {
        "cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
        "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"
    };

    static final int COSE_SIGN1_TAG = 18;

    static final BigInteger P256_P = new BigInteger(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    static final BigInteger P256_A = new BigInteger(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    static final BigInteger P256_B = new BigInteger(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    static final byte[] ED_SPKI_PREFIX = hex("302a300506032b6570032100");

    static String algKty(long alg) {
        if (alg == -7) return "EC2";
        if (alg == -8) return "OKP";
        if (alg == -37) return "RSA";
        return null;
    }

    static boolean knownLabel(long l) { return l >= 1 && l <= 5; }

    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    // -----------------------------------------------------------------------
    // Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
    // -----------------------------------------------------------------------
    static final class CborException extends RuntimeException { CborException(String m) { super(m); } }

    static final int T_INT = 0, T_BYTES = 1, T_TEXT = 2, T_ARRAY = 3, T_MAP = 4, T_NULL = 5, T_TAG = 6, T_BOOL = 7;

    static final class Cval {
        int t;
        long i;
        byte[] b;
        String s;
        List<Cval> arr;
        List<Cval[]> map;  // each entry is {key, value}
        long tag;
        Cval(int t) { this.t = t; }
    }

    static final class Dec { Cval v; int pos; Dec(Cval v, int pos) { this.v = v; this.pos = pos; } }

    static Dec decode(byte[] buf, int pos) {
        if (pos >= buf.length) throw new CborException("truncated");
        int ib = buf[pos++] & 0xff;
        int major = ib >> 5;
        int ai = ib & 0x1f;
        long arg;
        if (ai < 24) {
            arg = ai;
        } else if (ai == 24) {
            if (pos + 1 > buf.length) throw new CborException("t");
            arg = buf[pos] & 0xffL; pos += 1;
        } else if (ai == 25) {
            if (pos + 2 > buf.length) throw new CborException("t");
            arg = ((buf[pos] & 0xffL) << 8) | (buf[pos + 1] & 0xffL); pos += 2;
        } else if (ai == 26) {
            if (pos + 4 > buf.length) throw new CborException("t");
            arg = 0; for (int i = 0; i < 4; i++) arg = (arg << 8) | (buf[pos + i] & 0xffL); pos += 4;
        } else if (ai == 27) {
            if (pos + 8 > buf.length) throw new CborException("t");
            arg = 0; for (int i = 0; i < 8; i++) arg = (arg << 8) | (buf[pos + i] & 0xffL); pos += 8;
        } else if (ai == 31) {
            if (major < 2 || major > 5) throw new CborException("indef");
            return decodeIndefinite(buf, pos, major);
        } else {
            throw new CborException("reserved");
        }

        switch (major) {
            case 0: { Cval v = new Cval(T_INT); v.i = arg; return new Dec(v, pos); }
            case 1: { Cval v = new Cval(T_INT); v.i = -1 - arg; return new Dec(v, pos); }
            case 2: {
                if (pos + arg > buf.length) throw new CborException("t");
                Cval v = new Cval(T_BYTES); v.b = Arrays.copyOfRange(buf, pos, pos + (int) arg);
                return new Dec(v, pos + (int) arg);
            }
            case 3: {
                if (pos + arg > buf.length) throw new CborException("t");
                Cval v = new Cval(T_TEXT);
                v.s = new String(buf, pos, (int) arg, StandardCharsets.UTF_8);
                return new Dec(v, pos + (int) arg);
            }
            case 4: {
                Cval v = new Cval(T_ARRAY); v.arr = new ArrayList<>();
                for (long i = 0; i < arg; i++) { Dec d = decode(buf, pos); v.arr.add(d.v); pos = d.pos; }
                return new Dec(v, pos);
            }
            case 5: {
                Cval v = new Cval(T_MAP); v.map = new ArrayList<>();
                for (long i = 0; i < arg; i++) {
                    Dec dk = decode(buf, pos); Dec dv = decode(buf, dk.pos);
                    v.map.add(new Cval[]{dk.v, dv.v}); pos = dv.pos;
                }
                return new Dec(v, pos);
            }
            case 6: {
                Dec inner = decode(buf, pos);
                Cval v = new Cval(T_TAG); v.tag = arg; v.arr = new ArrayList<>(); v.arr.add(inner.v);
                return new Dec(v, inner.pos);
            }
            case 7: {
                if (ai == 22) return new Dec(new Cval(T_NULL), pos);
                if (ai == 20) { Cval v = new Cval(T_BOOL); v.i = 0; return new Dec(v, pos); }
                if (ai == 21) { Cval v = new Cval(T_BOOL); v.i = 1; return new Dec(v, pos); }
                throw new CborException("simple/float");
            }
        }
        throw new CborException("major");
    }

    static Dec decodeIndefinite(byte[] buf, int pos, int major) {
        if (major == 2 || major == 3) {
            ByteArrayOutputStream acc = new ByteArrayOutputStream();
            while (true) {
                if (pos >= buf.length) throw new CborException("t");
                if ((buf[pos] & 0xff) == 0xff) { pos++; break; }
                Dec d = decode(buf, pos);
                if (d.v.t != (major == 2 ? T_BYTES : T_TEXT)) throw new CborException("chunk");
                byte[] cb = major == 2 ? d.v.b : d.v.s.getBytes(StandardCharsets.UTF_8);
                acc.write(cb, 0, cb.length); pos = d.pos;
            }
            Cval v = new Cval(major == 2 ? T_BYTES : T_TEXT);
            if (major == 2) v.b = acc.toByteArray(); else v.s = new String(acc.toByteArray(), StandardCharsets.UTF_8);
            return new Dec(v, pos);
        }
        if (major == 4) {
            Cval v = new Cval(T_ARRAY); v.arr = new ArrayList<>();
            while (true) {
                if (pos >= buf.length) throw new CborException("t");
                if ((buf[pos] & 0xff) == 0xff) { pos++; break; }
                Dec d = decode(buf, pos); v.arr.add(d.v); pos = d.pos;
            }
            return new Dec(v, pos);
        }
        Cval v = new Cval(T_MAP); v.map = new ArrayList<>();
        while (true) {
            if (pos >= buf.length) throw new CborException("t");
            if ((buf[pos] & 0xff) == 0xff) { pos++; break; }
            Dec dk = decode(buf, pos); Dec dv = decode(buf, dk.pos);
            v.map.add(new Cval[]{dk.v, dv.v}); pos = dv.pos;
        }
        return new Dec(v, pos);
    }

    static byte[] head(int major, long n) {
        int base = major << 5;
        if (n < 24) return new byte[]{(byte) (base | (int) n)};
        if (n < 0x100L) return new byte[]{(byte) (base | 24), (byte) n};
        if (n < 0x10000L) return new byte[]{(byte) (base | 25), (byte) (n >> 8), (byte) n};
        if (n < 0x100000000L)
            return new byte[]{(byte) (base | 26), (byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8), (byte) n};
        byte[] out = new byte[9]; out[0] = (byte) (base | 27);
        for (int i = 0; i < 8; i++) out[8 - i] = (byte) (n >> (8 * i));
        return out;
    }

    static byte[] encode(Cval v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encodeInto(v, out);
        return out.toByteArray();
    }

    static void encodeInto(Cval v, ByteArrayOutputStream out) {
        try {
            switch (v.t) {
                case T_INT: {
                    byte[] h = v.i >= 0 ? head(0, v.i) : head(1, -1 - v.i);
                    out.write(h); break;
                }
                case T_BYTES: out.write(head(2, v.b.length)); out.write(v.b); break;
                case T_TEXT: {
                    byte[] sb = v.s.getBytes(StandardCharsets.UTF_8);
                    out.write(head(3, sb.length)); out.write(sb); break;
                }
                case T_ARRAY:
                    out.write(head(4, v.arr.size()));
                    for (Cval it : v.arr) encodeInto(it, out);
                    break;
                case T_MAP: {
                    List<byte[][]> enc = new ArrayList<>();
                    for (Cval[] p : v.map) enc.add(new byte[][]{encode(p[0]), encode(p[1])});
                    enc.sort((a, b) -> Arrays.compareUnsigned(a[0], b[0]));
                    out.write(head(5, enc.size()));
                    for (byte[][] p : enc) { out.write(p[0]); out.write(p[1]); }
                    break;
                }
                case T_NULL: out.write(0xf6); break;
                default: throw new CborException("encode");
            }
        } catch (java.io.IOException e) {
            throw new CborException("io");
        }
    }

    static boolean isDeterministic(byte[] buf) {
        Dec d;
        try { d = decode(buf, 0); } catch (RuntimeException e) { return false; }
        if (d.pos != buf.length) return false;
        if (d.v.t == T_TAG) return false;
        try { return Arrays.equals(encode(d.v), buf); } catch (RuntimeException e) { return false; }
    }

    static Cval mapGet(Cval m, long key) {
        for (Cval[] p : m.map) if (p[0].t == T_INT && p[0].i == key) return p[1];
        return null;
    }

    // -----------------------------------------------------------------------
    // COSE_Sign1 parse + gates
    // -----------------------------------------------------------------------
    static final class Sign1 { byte[] protectedBytes; Cval phdr; byte[] payload; byte[] sig; }

    static Sign1 parseSign1(byte[] buf) {
        Cval top;
        try { top = decode(buf, 0).v; } catch (RuntimeException e) { return null; }
        Cval arr = top;
        if (top.t == T_TAG) {
            if (top.tag != COSE_SIGN1_TAG) return null;
            arr = top.arr.get(0);
        }
        if (arr.t != T_ARRAY || arr.arr.size() != 4) return null;
        Cval protectedV = arr.arr.get(0), uhdr = arr.arr.get(1), payload = arr.arr.get(2), sig = arr.arr.get(3);
        if (protectedV.t != T_BYTES || uhdr.t != T_MAP || sig.t != T_BYTES) return null;
        if (payload.t != T_BYTES && payload.t != T_NULL) return null;
        Cval phdr;
        if (protectedV.b.length == 0) {
            phdr = new Cval(T_MAP); phdr.map = new ArrayList<>();
        } else {
            if (!isDeterministic(protectedV.b)) return null;
            Cval dec;
            try { dec = decode(protectedV.b, 0).v; } catch (RuntimeException e) { return null; }
            if (dec.t != T_MAP) return null;
            phdr = dec;
        }
        Sign1 s = new Sign1();
        s.protectedBytes = protectedV.b;
        s.phdr = phdr;
        s.payload = payload.t == T_BYTES ? payload.b : new byte[0];
        s.sig = sig.b;
        return s;
    }

    static byte[] sigStructure(byte[] protectedBytes, byte[] payload) {
        Cval a = new Cval(T_ARRAY); a.arr = new ArrayList<>();
        Cval s1 = new Cval(T_TEXT); s1.s = "Signature1"; a.arr.add(s1);
        Cval p = new Cval(T_BYTES); p.b = protectedBytes; a.arr.add(p);
        Cval aad = new Cval(T_BYTES); aad.b = new byte[0]; a.arr.add(aad);
        Cval pl = new Cval(T_BYTES); pl.b = payload; a.arr.add(pl);
        return encode(a);
    }

    // -----------------------------------------------------------------------
    // Signature verification per algorithm
    // -----------------------------------------------------------------------
    static boolean onCurve(BigInteger x, BigInteger y) {
        BigInteger lhs = y.multiply(y).mod(P256_P);
        BigInteger rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P);
        return lhs.equals(rhs);
    }

    static boolean es256(JSONObject key, byte[] preimage, byte[] sig) {
        try {
            if (sig.length != 64) return false;
            BigInteger x = new BigInteger(1, hex(key.getString("x")));
            BigInteger y = new BigInteger(1, hex(key.getString("y")));
            if (!onCurve(x, y)) return false;
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
            PublicKey pub = KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
            Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
            v.initVerify(pub); v.update(preimage); return v.verify(sig);
        } catch (Exception e) { return false; }
    }

    static boolean eddsa(JSONObject key, byte[] preimage, byte[] sig) {
        try {
            byte[] pk = hex(key.getString("x"));
            if (pk.length != 32) return false;
            byte[] der = new byte[ED_SPKI_PREFIX.length + 32];
            System.arraycopy(ED_SPKI_PREFIX, 0, der, 0, ED_SPKI_PREFIX.length);
            System.arraycopy(pk, 0, der, ED_SPKI_PREFIX.length, 32);
            PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(pub); v.update(preimage); return v.verify(sig);
        } catch (Exception e) { return false; }
    }

    static boolean ps256(JSONObject key, byte[] preimage, byte[] sig) {
        try {
            BigInteger n = new BigInteger(1, hex(key.getString("n")));
            BigInteger e = new BigInteger(1, hex(key.getString("e")));
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            Signature v = Signature.getInstance("RSASSA-PSS");
            v.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            v.initVerify(pub); v.update(preimage); return v.verify(sig);
        } catch (Exception e) { return false; }
    }

    static boolean verdict(byte[] buf, JSONObject key) {
        Sign1 p = parseSign1(buf);
        if (p == null) return false;
        Cval alg = mapGet(p.phdr, 1);
        if (alg == null || alg.t != T_INT) return false;
        Cval crit = mapGet(p.phdr, 2);
        if (crit != null) {
            if (crit.t != T_ARRAY || crit.arr.isEmpty()) return false;
            for (Cval l : crit.arr) if (l.t != T_INT || !knownLabel(l.i)) return false;
        }
        String wantKty = algKty(alg.i);
        if (wantKty == null) return false;
        if (!wantKty.equals(key.optString("kty", null))) return false;
        byte[] preimage = sigStructure(p.protectedBytes, p.payload);
        if (alg.i == -7) return es256(key, preimage, p.sig);
        if (alg.i == -8) return eddsa(key, preimage, p.sig);
        if (alg.i == -37) return ps256(key, preimage, p.sig);
        return false;
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : DEFAULT_PATH;
        String content = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        JSONObject corpus = new JSONObject(content);
        JSONObject keys = corpus.getJSONObject("keys");

        int total = 0, matched = 0;
        List<String> fails = new ArrayList<>();
        for (String sec : SECTIONS) {
            JSONArray arr = corpus.optJSONArray(sec);
            if (arr == null) continue;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject c = arr.getJSONObject(i);
                boolean accept;
                if (sec.equals("cose_deterministic_cbor")) {
                    accept = isDeterministic(hex(c.getString("cbor_hex")));
                } else {
                    accept = verdict(hex(c.getString("cose_hex")), keys.getJSONObject(c.getString("key")));
                }
                total++;
                if (accept == c.getBoolean("expect_valid")) matched++;
                else fails.add("[" + sec + "] " + c.optString("note", ""));
            }
        }
        for (String f : fails) System.out.println("FAIL  " + f);
        System.out.println("\njava (cose): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
