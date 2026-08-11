// Kotlin runner for the rfc9421_negative_v1 CORE cross-language battery.
//
// Independent Kotlin/JVM port of the verdict surface (signing_base.py, parse.py,
// keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Like the Java
// runner it is self-contained (no Kotlin RFC 9421 verifier exists) and must
// produce byte-identical verdicts to every other runner. Ed25519 verify +
// canonical-S via Bouncy Castle; the small-order / non-canonical key gate is
// ported with java.math.BigInteger; ECDSA P-256/P-384 via the JDK provider with
// explicit range / width / on-curve / strict-low-s checks.
//
// Corpus path: argv[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import kotlin.system.exitProcess

private const val DEFAULT_PATH = "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json"

private class SigningBaseError(m: String) : RuntimeException(m)
private class ParseError(m: String) : RuntimeException(m)
private class WeakKeyError(m: String) : RuntimeException(m)

// ================= signing base (port of signing_base.py) =================
private fun buildSigningBase(input: JsonNode, mode: String, sigParamsRaw: String?): String {
    if (mode != "algovoi-v0" && mode != "rfc9421")
        throw SigningBaseError("mode must be 'algovoi-v0' or 'rfc9421', got $mode")
    if (mode == "rfc9421" && sigParamsRaw == null)
        throw SigningBaseError("rfc9421 mode requires signature_params_raw")

    val headers = LinkedHashMap<String, String>()
    input.get("headers")?.takeIf { it.isObject }?.let { h ->
        h.fieldNames().forEach { k -> headers[k.lowercase()] = h.get(k).asText() }
    }
    val params = input.get("parameters")

    fun strOrThrow(field: String, msg: String): String {
        val n = input.get(field)
        if (n == null || n.isNull) throw SigningBaseError(msg)
        return n.asText()
    }
    fun paramStrOrThrow(key: String, msg: String): String {
        if (params == null || !params.has(key)) throw SigningBaseError(msg)
        val v = params.get(key)
        return if (v.isIntegralNumber) v.bigIntegerValue().toString() else v.asText()
    }

    val lines = ArrayList<String>()
    for (compNode in input.get("covered_components")) {
        val component = compNode.asText()
        val c = component.lowercase()
        val value: String = when (c) {
            "@method" -> strOrThrow("method", "@method covered but method not supplied")
                .let { if (mode == "rfc9421") it else it.lowercase() }
            "@authority" -> strOrThrow("authority", "@authority covered but authority not supplied").lowercase()
            "@path" -> strOrThrow("path", "@path covered but path not supplied")
            "@target-uri" -> strOrThrow("target_uri", "@target-uri covered but target_uri not supplied")
            "@scheme" -> strOrThrow("scheme", "@scheme covered but scheme not supplied").lowercase()
            "@status" -> {
                val n = input.get("status")
                if (n == null || n.isNull) throw SigningBaseError("@status covered but status not supplied")
                n.bigIntegerValue().toString()
            }
            "created" -> paramStrOrThrow("created", "'created' covered but no 'created' parameter in Signature-Input")
            "expires" -> paramStrOrThrow("expires", "'expires' covered but no 'expires' parameter in Signature-Input")
            else -> {
                if (c.startsWith("@")) throw SigningBaseError("unsupported derived component: $component")
                headers[c] ?: throw SigningBaseError("covered header $component not present in supplied headers")
            }
        }
        lines.add("\"$c\": $value")
    }
    if (mode == "rfc9421") lines.add("\"@signature-params\": $sigParamsRaw")
    return lines.joinToString("\n")
}

// ================= structured-field parse (port of parse.py) =================
private val LABEL_RE = Regex("^\\s*([A-Za-z][A-Za-z0-9_-]*)\\s*=\\s*")
private val COVERED_RE = Regex("\\(\\s*(?:\"[^\"]*\"\\s*)*\\)")

private fun parseSignatureInput(header: String?) {
    if (header == null) throw ParseError("header must be str")
    val hv = header.trim()
    if (hv.isEmpty()) throw ParseError("empty header value")
    val lm = LABEL_RE.find(hv)
    val rest = when {
        lm != null -> hv.substring(lm.range.last + 1)
        hv.startsWith("(") -> hv
        else -> throw ParseError("no label or covered-components list found at start")
    }
    val cm = COVERED_RE.find(rest)
    if (cm == null || cm.range.first != 0) throw ParseError("no covered-components list found")
}

private fun parseSignatureValue(header: String?) {
    if (header == null) throw ParseError("header must be str")
    val hv = header.trim()
    if (hv.isEmpty()) throw ParseError("empty Signature header value")
    val lm = LABEL_RE.find(hv)
    val rest = when {
        lm != null -> hv.substring(lm.range.last + 1).trim()
        hv.startsWith(":") -> hv
        else -> throw ParseError("no label or signature-value prefix found at start")
    }
    if (!rest.startsWith(":") || !rest.endsWith(":") || rest.length < 2)
        throw ParseError("signature value must be wrapped in colons")
    val sigB64 = rest.substring(1, rest.length - 1)
    val decoded = try { Base64.getDecoder().decode(sigB64) }
        catch (e: IllegalArgumentException) { throw ParseError("signature value is not valid base64") }
    if (Base64.getEncoder().encodeToString(decoded) != sigB64)
        throw ParseError("signature value is not canonical base64 (non-zero pad bits)")
}

// ================= Ed25519 key gate (port of keycheck.py) =================
private val P: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
private val D: BigInteger = BigInteger.valueOf(-121665)
    .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
private val SQRT_M1: BigInteger = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)

private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
    if (y >= P) return null
    val y2 = y.multiply(y).mod(P)
    val x2 = y2.subtract(BigInteger.ONE).mod(P)
        .multiply(D.multiply(y2).add(BigInteger.ONE).mod(P).modInverse(P)).mod(P)
    if (x2.signum() == 0) return if (sign == 1) null else BigInteger.ZERO
    var x = x2.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P)
    if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P)
    if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null
    if (if (x.testBit(0)) sign == 0 else sign == 1) x = P.subtract(x)
    return x
}

private fun decodePoint(pk: ByteArray): Array<BigInteger>? {
    if (pk.size != 32) return null
    val le = ByteArray(32) { pk[31 - it] }
    var y = BigInteger(1, le)
    val sign = if (y.testBit(255)) 1 else 0
    y = y.clearBit(255)
    val x = recoverX(y, sign) ?: return null
    return arrayOf(x, y, BigInteger.ONE, x.multiply(y).mod(P))
}

private fun add(p: Array<BigInteger>, q: Array<BigInteger>): Array<BigInteger> {
    val a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P)
    val b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P)
    val c = BigInteger.TWO.multiply(p[3]).multiply(q[3]).multiply(D).mod(P)
    val dd = BigInteger.TWO.multiply(p[2]).multiply(q[2]).mod(P)
    val e = b.subtract(a); val f = dd.subtract(c); val g = dd.add(c); val h = b.add(a)
    return arrayOf(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
}

private fun mul8(p: Array<BigInteger>): Array<BigInteger> {
    val p2 = add(p, p); val p4 = add(p2, p2); return add(p4, p4)
}

private fun isIdentity(p: Array<BigInteger>) =
    p[0].mod(P).signum() == 0 && p[1].subtract(p[2]).mod(P).signum() == 0

private fun isSmallOrder(pk: ByteArray): Boolean {
    val p = decodePoint(pk) ?: return false
    return isIdentity(mul8(p))
}

private fun checkEd25519PublicKey(pk: ByteArray) {
    val p = decodePoint(pk) ?: throw WeakKeyError("public key is not a canonical on-curve Ed25519 point")
    if (isIdentity(mul8(p))) throw WeakKeyError("public key is a small-order Ed25519 point")
}

// ================= Ed25519 verify (port of verify.py) =================
private fun ed25519Verify(msg: ByteArray, sig: ByteArray, pk: ByteArray): Boolean {
    if (sig.size != 64) return false
    if (pk.size != 32) return false
    try { checkEd25519PublicKey(pk) } catch (e: WeakKeyError) { return false }
    val signer = Ed25519Signer()
    signer.init(false, Ed25519PublicKeyParameters(pk, 0))
    signer.update(msg, 0, msg.size)
    return signer.verifySignature(sig)
}

// ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
private fun ecdsaVerify(curve: String, msg: ByteArray, sigRaw: ByteArray, pub: ByteArray, strictLowS: Boolean): Boolean {
    return try {
        val fieldSize = if (curve == "p256") 32 else 48
        val stdName = if (curve == "p256") "secp256r1" else "secp384r1"
        val sigAlg = if (curve == "p256") "SHA256withECDSA" else "SHA384withECDSA"
        if (sigRaw.size != 2 * fieldSize) return false

        val r = BigInteger(1, sigRaw.copyOfRange(0, fieldSize))
        val s = BigInteger(1, sigRaw.copyOfRange(fieldSize, 2 * fieldSize))

        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec(stdName))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val n = spec.order
        if (r.signum() <= 0 || r >= n || s.signum() <= 0 || s >= n) return false
        if (strictLowS && s > n.shiftRight(1)) return false

        if (pub.size != 1 + 2 * fieldSize || pub[0].toInt() != 0x04) return false
        val x = BigInteger(1, pub.copyOfRange(1, 1 + fieldSize))
        val yc = BigInteger(1, pub.copyOfRange(1 + fieldSize, 1 + 2 * fieldSize))
        val pMod = (spec.curve.field as ECFieldFp).p
        val lhs = yc.multiply(yc).mod(pMod)
        val rhs = x.multiply(x).multiply(x).add(spec.curve.a.multiply(x)).add(spec.curve.b).mod(pMod)
        if (lhs != rhs) return false

        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, yc), spec))
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(r)); v.add(ASN1Integer(s))
        val der = DERSequence(v).getEncoded("DER")

        val verifier = Signature.getInstance(sigAlg)
        verifier.initVerify(key)
        verifier.update(msg)
        verifier.verify(der)
    } catch (e: Exception) {
        false
    }
}

private fun hex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in s.indices step 2) out[i / 2] = s.substring(i, i + 2).toInt(16).toByte()
    return out
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0]
        else System.getenv("ALGOVOI_NEGATIVE_V1") ?: DEFAULT_PATH
    val corpus = ObjectMapper().readTree(File(path))
    var total = 0; var matched = 0
    val fails = ArrayList<String>()

    fun record(ok: Boolean, section: String, c: JsonNode) {
        total++
        if (ok) matched++ else fails.add("[$section] " + (if (c.hasNonNull("note")) c.get("note").asText() else ""))
    }

    for (c in corpus.get("signing_base")) {
        val want = String(Base64.getDecoder().decode(c.get("signing_base_b64").asText()), Charsets.UTF_8)
        val spr = if (c.hasNonNull("signature_params_raw")) c.get("signature_params_raw").asText() else null
        val ok = try {
            c.get("ok").asBoolean() && buildSigningBase(c.get("in"), c.get("mode").asText(), spr) == want
        } catch (e: RuntimeException) { !c.get("ok").asBoolean() }
        record(ok, "signing_base", c)
    }
    for (c in corpus.get("signature_input_parse")) {
        val parsedOk = try { parseSignatureInput(c.get("header").asText()); true } catch (e: ParseError) { false }
        record(parsedOk == c.get("ok").asBoolean(), "sig_input_parse", c)
    }
    for (c in corpus.get("signature_value_parse")) {
        val parsedOk = try { parseSignatureValue(c.get("header").asText()); true } catch (e: ParseError) { false }
        record(parsedOk == c.get("ok").asBoolean(), "sig_value_parse", c)
    }
    for (c in corpus.get("keygate")) {
        val raw = hex(c.get("pk_hex").asText())
        val rejected = try { checkEd25519PublicKey(raw); null } catch (e: WeakKeyError) { "WeakKeyError" }
        val want = if (c.hasNonNull("rejected")) c.get("rejected").asText() else null
        record(rejected == want && isSmallOrder(raw) == c.get("small_order").asBoolean(), "keygate", c)
    }
    for (c in corpus.get("ed25519_verify")) {
        val base = Base64.getDecoder().decode(c.get("signing_base_b64").asText())
        val valid = ed25519Verify(base, hex(c.get("sig_hex").asText()), hex(c.get("pk_hex").asText()))
        record(valid == c.get("expect_valid").asBoolean(), "ed25519_verify", c)
    }
    for (c in corpus.get("ecdsa_verify")) {
        val strict = c.hasNonNull("strict_low_s") && c.get("strict_low_s").asBoolean()
        val valid = ecdsaVerify(c.get("curve").asText(), hex(c.get("msg_hex").asText()),
            hex(c.get("sig_raw_hex").asText()), hex(c.get("pub_uncompressed_hex").asText()), strict)
        record(valid == c.get("expect_valid").asBoolean(), "ecdsa_verify", c)
    }

    fails.forEach { println("FAIL  $it") }
    println("\nkotlin: $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
