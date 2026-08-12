// Kotlin runner for the JSON Web Signature corpus (jws_v0).
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
// Self-contained, mirroring the sibling kotlin runners: JSON via Jackson and JDK
// built-in crypto (RS256 = "SHA256withRSA"; ES256 = "SHA256withECDSAinP1363Format"
// over raw r||s with an explicit on-curve check; EdDSA via the JDK EdDSA provider).
//     kotlinc VerifyJws.kt -cp "$JAR" -include-runtime -d verifyjws.jar
//     java -cp "verifyjws.jar:$JAR" VerifyJwsKt <corpus.json>
//
// Corpus path: argv[0], else the sibling repo default. Exit 0 iff every case matches.

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.system.exitProcess

private val MAPPER = ObjectMapper()
private const val DEFAULT_PATH = "../../corpus/jws_v0/jws_v0.json"

private val SECTIONS = listOf(
    "jws_compact_parse", "jws_alg_none", "jws_alg_confusion", "jws_rs256_verify",
    "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"
)

private val P256_P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
private val P256_A = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
private val P256_B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

private val ED_SPKI_PREFIX = hex("302a300506032b6570032100")

private fun algKty(alg: String?): String? = when (alg) {
    "RS256" -> "RSA"; "ES256" -> "EC"; "EdDSA" -> "OKP"; "HS256" -> "oct"; else -> null
}

private fun hex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in s.indices step 2) out[i / 2] = s.substring(i, i + 2).toInt(16).toByte()
    return out
}

// Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
private fun b64url(seg: String): ByteArray? {
    for (ch in seg) {
        val ok = ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '_'
        if (!ok) return null
    }
    if (seg.length % 4 == 1) return null
    return try { Base64.getUrlDecoder().decode(seg) } catch (e: IllegalArgumentException) { null }
}

private fun b64uInt(seg: String): BigInteger? {
    val b = b64url(seg) ?: return null
    return BigInteger(1, b)
}

private class Parsed(val header: JsonNode, val sig: ByteArray, val si: ByteArray)

private fun parseCompact(token: String): Parsed? {
    val parts = token.split(".")
    if (parts.size != 3) return null
    val headerBytes = b64url(parts[0]) ?: return null
    val header: JsonNode = try {
        MAPPER.readTree(String(headerBytes, Charsets.UTF_8))
    } catch (e: Exception) {
        return null
    } ?: return null
    if (!header.isObject) return null
    if (!header.has("alg")) return null
    if (b64url(parts[1]) == null) return null
    val sig = b64url(parts[2]) ?: return null
    val si = (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)
    return Parsed(header, sig, si)
}

private fun selectKey(header: JsonNode, keysObj: JsonNode, keyNames: JsonNode, byKid: Boolean): JsonNode? {
    if (byKid) {
        if (!header.hasNonNull("kid")) return null
        val kid = header.get("kid").asText()
        for (nameNode in keyNames) {
            val jwk = keysObj.get(nameNode.asText())
            if (jwk != null && jwk.hasNonNull("kid") && jwk.get("kid").asText() == kid) return jwk
        }
        return null
    }
    return keysObj.get(keyNames.get(0).asText())
}

private fun rs256(jwk: JsonNode, si: ByteArray, sig: ByteArray): Boolean {
    return try {
        val n = b64uInt(jwk.get("n").asText()) ?: return false
        val e = b64uInt(jwk.get("e").asText()) ?: return false
        val key = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))
        val v = Signature.getInstance("SHA256withRSA")
        v.initVerify(key); v.update(si); v.verify(sig)
    } catch (e: Exception) {
        false
    }
}

private fun onCurve(x: BigInteger, y: BigInteger): Boolean {
    val lhs = y.multiply(y).mod(P256_P)
    val rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P)
    return lhs == rhs
}

private fun es256(jwk: JsonNode, si: ByteArray, sig: ByteArray): Boolean {
    return try {
        if (sig.size != 64) return false
        val x = b64uInt(jwk.get("x").asText()) ?: return false
        val y = b64uInt(jwk.get("y").asText()) ?: return false
        if (!onCurve(x, y)) return false
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
        val v = Signature.getInstance("SHA256withECDSAinP1363Format")
        v.initVerify(key); v.update(si); v.verify(sig)
    } catch (e: Exception) {
        false
    }
}

private fun eddsa(jwk: JsonNode, si: ByteArray, sig: ByteArray): Boolean {
    return try {
        val pk = b64url(jwk.get("x").asText()) ?: return false
        if (pk.size != 32) return false
        val der = ED_SPKI_PREFIX + pk
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
        val v = Signature.getInstance("Ed25519")
        v.initVerify(key); v.update(si); v.verify(sig)
    } catch (e: Exception) {
        false
    }
}

private fun verdict(token: String, keysObj: JsonNode, keyNames: JsonNode, byKid: Boolean): Boolean {
    val parsed = parseCompact(token) ?: return false
    val alg = if (parsed.header.hasNonNull("alg")) parsed.header.get("alg").asText() else null
    if (alg == null || alg == "none") return false
    if (parsed.header.has("crit")) return false
    val wantKty = algKty(alg) ?: return false
    val jwk = selectKey(parsed.header, keysObj, keyNames, byKid) ?: return false
    val kty = if (jwk.hasNonNull("kty")) jwk.get("kty").asText() else null
    if (kty != wantKty) return false
    return when (alg) {
        "RS256" -> rs256(jwk, parsed.si, parsed.sig)
        "ES256" -> es256(jwk, parsed.si, parsed.sig)
        "EdDSA" -> eddsa(jwk, parsed.si, parsed.sig)
        else -> false
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else DEFAULT_PATH
    val corpus = MAPPER.readTree(File(path))
    val keysObj = corpus.get("keys")

    var total = 0; var matched = 0
    val fails = ArrayList<String>()
    for (sec in SECTIONS) {
        val arr = corpus.get(sec) ?: continue
        for (c in arr) {
            val verify = c.get("verify")
            val accept = verdict(c.get("jws").asText(), keysObj,
                verify.get("key_names"), verify.get("select_by_kid").asBoolean())
            total++
            if (accept == c.get("expect_valid").asBoolean()) matched++
            else fails.add("[$sec] ${if (c.hasNonNull("note")) c.get("note").asText() else ""}")
        }
    }
    fails.forEach { println("FAIL  $it") }
    println("\nkotlin (jws): $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
