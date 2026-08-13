// Java runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_pqc_mldsa.py) and its decision
// surface (tools/oracle_pqc_mldsa.py) case for case: decode the hex public key,
// message and signature, reject a wrong-length public key (must be 1952) or
// signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
// signature over the exact message bytes with the EMPTY context string.
//
// Dependencies: org.json for JSON parsing and Bouncy Castle (bcprov-jdk18on 1.81+,
// the first BC line with FIPS-204 ML-DSA) for the crypto. MLDSASigner over an
// MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, ...) verifies the pure
// ML-DSA variant (empty context) via init/update/verifySignature. BC's separate
// round-3 Dilithium classes are deliberately NOT used; a Dilithium verifier would
// fail the valid controls.
//
// Corpus path: args[0], else $ALGOVOI_PQC_MLDSA, else ../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json.
// Exit 0 iff every case matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class VerifyPqcMldsa {

    static final String DEFAULT_PATH = "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json";
    static final String[] SECTIONS = {"mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"};
    static final int PK_LEN = 1952;
    static final int SIG_LEN = 3309;

    static byte[] hex(String s) {
        if (s == null || (s.length() & 1) != 0) return null;
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            o[i] = (byte) ((hi << 4) | lo);
        }
        return o;
    }

    static boolean verdict(String pkHex, String msgHex, String sigHex) {
        byte[] pk = hex(pkHex);
        byte[] msg = hex(msgHex);
        byte[] sig = hex(sigHex);
        if (pk == null || msg == null || sig == null) return false;
        if (pk.length != PK_LEN || sig.length != SIG_LEN) return false;
        try {
            MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk);
            MLDSASigner s = new MLDSASigner();
            s.init(false, pub);
            s.update(msg, 0, msg.length);
            return s.verifySignature(sig);
        } catch (Throwable e) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        String env = System.getenv("ALGOVOI_PQC_MLDSA");
        String path = args.length > 0 ? args[0] : (env != null ? env : DEFAULT_PATH);
        String content = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        JSONObject corpus = new JSONObject(content);

        int total = 0, matched = 0;
        List<String> fails = new ArrayList<>();
        for (String sec : SECTIONS) {
            JSONArray arr = corpus.optJSONArray(sec);
            if (arr == null) continue;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject c = arr.getJSONObject(i);
                boolean accept = verdict(c.getString("public_key"), c.getString("message"),
                    c.getString("signature"));
                total++;
                if (accept == c.getBoolean("expect_valid")) matched++;
                else fails.add("[" + sec + "] " + c.optString("note", ""));
            }
        }
        for (String f : fails) System.out.println("FAIL  " + f);
        System.out.println("\njava (pqc_mldsa): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
