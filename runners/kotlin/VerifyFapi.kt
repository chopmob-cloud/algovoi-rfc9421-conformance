// Kotlin runner for the FAPI 2.0 Message Signing profile corpus (fapi_messagesigning_v0).
//
// Independently reproduces every verdict in the frozen corpus. The signing base
// (RFC 9421 Section 2.5), the PROFILE rules (mandated coverage, Content-Digest
// body binding, algorithm restriction) and the PS256/ES256 crypto are
// re-implemented here from the corpus `policy` block, NOT imported from the
// generator's oracle, so a runner passing is genuine agreement rather than an
// echo. This mirrors the Python reference runner (runners/python/verify_fapi.py)
// and the go/typescript runners case for case.
//
// Self-contained, mirroring the sibling runners/kotlin/NegativeV1.kt and
// runners/kotlin/VerifyWba.kt: JSON via Jackson (com.fasterxml.jackson.databind)
// and JDK built-in crypto (RSASSA-PSS + ECDSA P-256), the exact jars
// tools/run_consensus_fapi.sh puts on the classpath (runners/kotlin/libs/*.jar).
// It is compiled and run identically to the siblings:
//     kotlinc VerifyFapi.kt -cp "$JAR" -include-runtime -d verifyfapi.jar
//     java -cp "verifyfapi.jar:$JAR" VerifyFapiKt <corpus.json>
//
// Corpus path: argv[0], else the sibling repo default. Exit 0 iff every case matches.

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.system.exitProcess

private const val DEFAULT_PATH = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json"

private class SigningBaseError(m: String) : RuntimeException(m)

// ---- generic helpers -------------------------------------------------------

private fun hex(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in s.indices step 2) out[i / 2] = s.substring(i, i + 2).toInt(16).toByte()
    return out
}

private fun noteOf(c: JsonNode): String = if (c.hasNonNull("note")) c.get("note").asText() else ""

// Lowercased set of the string elements of a JSON array (null-safe).
private fun lowerSet(arr: JsonNode?): HashSet<String> {
    val out = HashSet<String>()
    arr?.forEach { out.add(it.asText().lowercase()) }
    return out
}

// ---- Rule 1: RFC 9421 Section 2.5 signing base, hand-built ------------------
// Derived components @method/@target-uri/@status/@authority/@path map to the
// matching top-level `in` field; any other component is a header looked up
// (lowercased) in `in.headers`. A missing covered value makes the base
// unbuildable (throws), which the driver maps to a negative verdict. mode is
// always "rfc9421" in this corpus, so "@signature-params" is always appended.
// Values are used verbatim (no case-folding), mirroring the go/ts fapi runners.
private fun strField(input: JsonNode, field: String, comp: String): String {
    val n = input.get(field)
    if (n == null || n.isNull) throw SigningBaseError("$comp covered but $field not supplied")
    return n.asText()
}

private fun buildSigningBase(input: JsonNode, paramsRaw: String?): String {
    val headers = input.get("headers")
    val lines = ArrayList<String>()
    for (compNode in input.get("covered_components")) {
        val name = compNode.asText().lowercase()
        val value: String = when (name) {
            "@method" -> strField(input, "method", "@method")
            "@target-uri" -> strField(input, "target_uri", "@target-uri")
            "@authority" -> strField(input, "authority", "@authority")
            "@path" -> strField(input, "path", "@path")
            "@status" -> {
                val n = input.get("status")
                if (n == null || n.isNull || !n.isIntegralNumber)
                    throw SigningBaseError("@status covered but status not supplied")
                n.bigIntegerValue().toString()
            }
            else -> {
                val hv = if (headers != null && headers.isObject) headers.get(name) else null
                if (hv == null || hv.isNull) throw SigningBaseError("covered header $name not present")
                hv.asText()
            }
        }
        lines.add("\"$name\": $value")
    }
    lines.add("\"@signature-params\": ${paramsRaw ?: ""}")
    return lines.joinToString("\n")
}

// ---- Rule 2: mandated coverage (required lowercased subset of covered) ------
private fun coverageOk(messageType: String, covered: JsonNode?, policy: JsonNode): Boolean {
    val key = if (messageType == "request") "required_covered_request" else "required_covered_response"
    val have = lowerSet(covered)
    val required = policy.get(key) ?: return false
    return required.all { have.contains(it.asText().lowercase()) }
}

// ---- Rule 3: Content-Digest body binding -----------------------------------
// Reject if content-digest is not covered; the header algorithm (before the
// first "=") must be an allowed digest algorithm; and the header must equal
// <alg>=:<base64(digest of body)>:.
private fun contentDigestOk(bodyB64: String, header: String, covered: JsonNode?, policy: JsonNode): Boolean {
    if (!lowerSet(covered).contains("content-digest")) return false
    val idx = header.indexOf('=')
    if (idx < 0) return false
    val algorithm = header.substring(0, idx).trim().lowercase()
    if (!lowerSet(policy.get("content_digest_algorithms")).contains(algorithm)) return false
    val body = try { Base64.getDecoder().decode(bodyB64) } catch (e: IllegalArgumentException) { return false }
    val digest = when (algorithm) {
        "sha-256" -> MessageDigest.getInstance("SHA-256").digest(body)
        "sha-512" -> MessageDigest.getInstance("SHA-512").digest(body)
        else -> return false
    }
    val expect = "$algorithm=:${Base64.getEncoder().encodeToString(digest)}:"
    return header.trim() == expect
}

// ---- Rule 5: PS256 (RSASSA-PSS/SHA-256, salt 32) over the signing base ------
private fun ps256Ok(base: ByteArray, sig: ByteArray, spkiDer: ByteArray): Boolean {
    return try {
        val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spkiDer))
        val v = Signature.getInstance("RSASSA-PSS")
        v.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
        v.initVerify(key)
        v.update(base)
        v.verify(sig)
    } catch (e: Exception) {
        false
    }
}

// ---- Rule 6: ES256 (ECDSA/P-256/SHA-256) over the signing base -------------
// sig is a raw 64-byte r||s. Under require_low_s a signature with s > n/2
// (n from policy.p256_n) is rejected for malleability. Otherwise verify with
// the uncompressed public point using the P1363 (raw r||s) signature format.
private fun es256Ok(base: ByteArray, sigRaw: ByteArray, pubUncompressed: ByteArray,
                    requireLowS: Boolean, policy: JsonNode): Boolean {
    if (sigRaw.size != 64) return false
    val s = BigInteger(1, sigRaw.copyOfRange(32, 64))
    if (requireLowS) {
        val n = BigInteger(policy.get("p256_n").asText().trim())
        if (s > n.shiftRight(1)) return false
    }
    return try {
        if (pubUncompressed.size != 65 || pubUncompressed[0].toInt() != 0x04) return false
        val x = BigInteger(1, pubUncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, pubUncompressed.copyOfRange(33, 65))
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
        val v = Signature.getInstance("SHA256withECDSAinP1363Format")
        v.initVerify(key)
        v.update(base)
        v.verify(sigRaw)
    } catch (e: Exception) {
        false
    }
}

// ---- driver ----------------------------------------------------------------
fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else DEFAULT_PATH
    val corpus = ObjectMapper().readTree(File(path))
    val policy = corpus.get("policy")

    var total = 0
    var matched = 0
    val fails = ArrayList<String>()
    fun record(ok: Boolean, section: String, note: String) {
        total++
        if (ok) matched++ else fails.add("[$section] $note")
    }

    // 1. fapi_signing_base
    for (c in corpus.get("fapi_signing_base")) {
        val want = String(Base64.getDecoder().decode(c.get("signing_base_b64").asText()), Charsets.UTF_8)
        val spr = if (c.hasNonNull("signature_params_raw")) c.get("signature_params_raw").asText() else null
        val okFlag = c.get("ok").asBoolean()
        // Build FIRST; `okFlag && build(...)` would short-circuit for negative
        // cases and never exercise the build-failure path.
        val ok = try {
            val built = buildSigningBase(c.get("in"), spr)
            okFlag && built == want
        } catch (e: SigningBaseError) {
            !okFlag
        }
        record(ok, "fapi_signing_base", noteOf(c))
    }

    // 2. fapi_required_coverage
    for (c in corpus.get("fapi_required_coverage")) {
        val got = coverageOk(c.get("message_type").asText(), c.get("covered_components"), policy)
        record(got == c.get("expect_accept").asBoolean(), "fapi_required_coverage", noteOf(c))
    }

    // 3. fapi_content_digest
    for (c in corpus.get("fapi_content_digest")) {
        val got = contentDigestOk(c.get("body_b64").asText(), c.get("content_digest").asText(),
            c.get("covered_components"), policy)
        record(got == c.get("expect_accept").asBoolean(), "fapi_content_digest", noteOf(c))
    }

    // 4. fapi_alg
    val allowed = lowerSet(policy.get("allowed_algs"))
    for (c in corpus.get("fapi_alg")) {
        val got = allowed.contains(c.get("alg").asText().lowercase())
        record(got == c.get("expect_accept").asBoolean(), "fapi_alg", noteOf(c))
    }

    // 5. fapi_ps256_verify
    for (c in corpus.get("fapi_ps256_verify")) {
        val base = Base64.getDecoder().decode(c.get("signing_base_b64").asText())
        val valid = ps256Ok(base, hex(c.get("sig_hex").asText()), hex(c.get("pub_spki_hex").asText()))
        record(valid == c.get("expect_valid").asBoolean(), "fapi_ps256_verify", noteOf(c))
    }

    // 6. fapi_es256_verify
    for (c in corpus.get("fapi_es256_verify")) {
        val base = Base64.getDecoder().decode(c.get("signing_base_b64").asText())
        val requireLowS = c.hasNonNull("require_low_s") && c.get("require_low_s").asBoolean()
        val valid = es256Ok(base, hex(c.get("sig_raw_hex").asText()),
            hex(c.get("pub_uncompressed_hex").asText()), requireLowS, policy)
        record(valid == c.get("expect_valid").asBoolean(), "fapi_es256_verify", noteOf(c))
    }

    fails.forEach { println("FAIL  $it") }
    println("\nkotlin (fapi): $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
