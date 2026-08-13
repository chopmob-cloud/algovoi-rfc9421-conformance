// Kotlin runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_pqc_mldsa.py) and its decision
// surface (tools/oracle_pqc_mldsa.py) case for case: decode the hex public key,
// message and signature, reject a wrong-length public key (must be 1952) or
// signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
// signature over the exact message bytes with the EMPTY context string.
//
// JSON via Jackson; crypto via Bouncy Castle (bcprov-jdk18on 1.81+, the first BC
// line with FIPS-204 ML-DSA). MLDSASigner over an MLDSAPublicKeyParameters
// (MLDSAParameters.ml_dsa_65, ...) verifies the pure ML-DSA variant (empty
// context). BC's round-3 Dilithium classes are deliberately NOT used.
//     kotlinc VerifyPqcMldsa.kt -cp "$JARS" -include-runtime -d vpm.jar
//     java -cp "vpm.jar:$JARS" VerifyPqcMldsaKt <corpus.json>
//
// Corpus path: argv[0], else $ALGOVOI_PQC_MLDSA, else the sibling repo default.
// Exit 0 iff every case matches.

import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import java.io.File
import kotlin.system.exitProcess

private val MAPPER = ObjectMapper()
private const val DEFAULT_PATH = "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json"
private val SECTIONS = listOf("mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat")
private const val PK_LEN = 1952
private const val SIG_LEN = 3309

private fun hex(s: String?): ByteArray? {
    if (s == null || s.length % 2 != 0) return null
    val o = ByteArray(s.length / 2)
    for (i in o.indices) {
        val hi = Character.digit(s[2 * i], 16)
        val lo = Character.digit(s[2 * i + 1], 16)
        if (hi < 0 || lo < 0) return null
        o[i] = ((hi shl 4) or lo).toByte()
    }
    return o
}

private fun verdict(pkHex: String?, msgHex: String?, sigHex: String?): Boolean {
    val pk = hex(pkHex) ?: return false
    val msg = hex(msgHex) ?: return false
    val sig = hex(sigHex) ?: return false
    if (pk.size != PK_LEN || sig.size != SIG_LEN) return false
    return try {
        val pub = MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk)
        val s = MLDSASigner()
        s.init(false, pub)
        s.update(msg, 0, msg.size)
        s.verifySignature(sig)
    } catch (e: Throwable) {
        false
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else (System.getenv("ALGOVOI_PQC_MLDSA") ?: DEFAULT_PATH)
    val corpus = MAPPER.readTree(File(path))

    var total = 0
    var matched = 0
    val fails = ArrayList<String>()
    for (sec in SECTIONS) {
        val arr = corpus.get(sec) ?: continue
        for (c in arr) {
            val accept = verdict(
                c.get("public_key").asText(),
                c.get("message").asText(),
                c.get("signature").asText()
            )
            total++
            if (accept == c.get("expect_valid").asBoolean()) matched++
            else fails.add("[$sec] ${if (c.hasNonNull("note")) c.get("note").asText() else ""}")
        }
    }
    fails.forEach { println("FAIL  $it") }
    println("\nkotlin (pqc_mldsa): $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
