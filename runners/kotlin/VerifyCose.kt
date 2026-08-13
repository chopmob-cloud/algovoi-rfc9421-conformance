// Kotlin runner for the COSE_Sign1 corpus (cose_v0).
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
// JSON via Jackson; JDK built-in crypto: ES256 ("SHA256withECDSAinP1363Format" over
// raw r||s with an explicit on-curve check), EdDSA (JDK Ed25519), PS256 ("RSASSA-PSS",
// SHA-256, MGF1/SHA-256, salt 32). Keys from the hex COSE material.
//
// Corpus path: argv[0], else the sibling repo default. Exit 0 iff every case matches.

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.system.exitProcess

private val MAPPER = ObjectMapper()
private const val DEFAULT_PATH = "../../corpus/cose_v0/cose_v0.json"

private val SECTIONS = listOf(
    "cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
    "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"
)

private const val COSE_SIGN1_TAG = 18L

private val P256_P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
private val P256_A = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
private val P256_B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
private val ED_SPKI_PREFIX = hexb("302a300506032b6570032100")

private fun algKty(alg: Long): String? = when (alg) {
    -7L -> "EC2"; -8L -> "OKP"; -37L -> "RSA"; else -> null
}

private fun knownLabel(l: Long): Boolean = l in 1..5

private fun hexb(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in s.indices step 2) out[i / 2] = s.substring(i, i + 2).toInt(16).toByte()
    return out
}

// ---------------------------------------------------------------------------
// Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
// ---------------------------------------------------------------------------
private class CborException(m: String) : RuntimeException(m)

private const val T_INT = 0; private const val T_BYTES = 1; private const val T_TEXT = 2
private const val T_ARRAY = 3; private const val T_MAP = 4; private const val T_NULL = 5
private const val T_TAG = 6; private const val T_BOOL = 7

private class Cval(val t: Int) {
    var i: Long = 0
    var b: ByteArray = ByteArray(0)
    var s: String = ""
    var arr: MutableList<Cval> = mutableListOf()
    var map: MutableList<Array<Cval>> = mutableListOf()
    var tag: Long = 0
}

private class Dec(val v: Cval, val pos: Int)

private fun decode(buf: ByteArray, start: Int): Dec {
    if (start >= buf.size) throw CborException("truncated")
    var pos = start
    val ib = buf[pos++].toInt() and 0xff
    val major = ib shr 5
    val ai = ib and 0x1f
    val arg: Long
    when {
        ai < 24 -> arg = ai.toLong()
        ai == 24 -> { if (pos + 1 > buf.size) throw CborException("t"); arg = (buf[pos].toLong() and 0xff); pos += 1 }
        ai == 25 -> { if (pos + 2 > buf.size) throw CborException("t"); arg = ((buf[pos].toLong() and 0xff) shl 8) or (buf[pos + 1].toLong() and 0xff); pos += 2 }
        ai == 26 -> { if (pos + 4 > buf.size) throw CborException("t"); var a = 0L; for (j in 0 until 4) a = (a shl 8) or (buf[pos + j].toLong() and 0xff); arg = a; pos += 4 }
        ai == 27 -> { if (pos + 8 > buf.size) throw CborException("t"); var a = 0L; for (j in 0 until 8) a = (a shl 8) or (buf[pos + j].toLong() and 0xff); arg = a; pos += 8 }
        ai == 31 -> { if (major < 2 || major > 5) throw CborException("indef"); return decodeIndefinite(buf, pos, major) }
        else -> throw CborException("reserved")
    }

    when (major) {
        0 -> { val v = Cval(T_INT); v.i = arg; return Dec(v, pos) }
        1 -> { val v = Cval(T_INT); v.i = -1 - arg; return Dec(v, pos) }
        2 -> {
            if (pos + arg > buf.size) throw CborException("t")
            val v = Cval(T_BYTES); v.b = buf.copyOfRange(pos, pos + arg.toInt()); return Dec(v, pos + arg.toInt())
        }
        3 -> {
            if (pos + arg > buf.size) throw CborException("t")
            val v = Cval(T_TEXT); v.s = String(buf, pos, arg.toInt(), Charsets.UTF_8); return Dec(v, pos + arg.toInt())
        }
        4 -> {
            val v = Cval(T_ARRAY)
            for (j in 0 until arg) { val d = decode(buf, pos); v.arr.add(d.v); pos = d.pos }
            return Dec(v, pos)
        }
        5 -> {
            val v = Cval(T_MAP)
            for (j in 0 until arg) { val dk = decode(buf, pos); val dv = decode(buf, dk.pos); v.map.add(arrayOf(dk.v, dv.v)); pos = dv.pos }
            return Dec(v, pos)
        }
        6 -> { val inner = decode(buf, pos); val v = Cval(T_TAG); v.tag = arg; v.arr.add(inner.v); return Dec(v, inner.pos) }
        7 -> {
            if (ai == 22) return Dec(Cval(T_NULL), pos)
            if (ai == 20) { val v = Cval(T_BOOL); v.i = 0; return Dec(v, pos) }
            if (ai == 21) { val v = Cval(T_BOOL); v.i = 1; return Dec(v, pos) }
            throw CborException("simple/float")
        }
    }
    throw CborException("major")
}

private fun decodeIndefinite(buf: ByteArray, start: Int, major: Int): Dec {
    var pos = start
    if (major == 2 || major == 3) {
        val acc = ByteArrayOutputStream()
        while (true) {
            if (pos >= buf.size) throw CborException("t")
            if ((buf[pos].toInt() and 0xff) == 0xff) { pos++; break }
            val d = decode(buf, pos)
            if (d.v.t != (if (major == 2) T_BYTES else T_TEXT)) throw CborException("chunk")
            val cb = if (major == 2) d.v.b else d.v.s.toByteArray(Charsets.UTF_8)
            acc.write(cb); pos = d.pos
        }
        val v = Cval(if (major == 2) T_BYTES else T_TEXT)
        if (major == 2) v.b = acc.toByteArray() else v.s = String(acc.toByteArray(), Charsets.UTF_8)
        return Dec(v, pos)
    }
    if (major == 4) {
        val v = Cval(T_ARRAY)
        while (true) {
            if (pos >= buf.size) throw CborException("t")
            if ((buf[pos].toInt() and 0xff) == 0xff) { pos++; break }
            val d = decode(buf, pos); v.arr.add(d.v); pos = d.pos
        }
        return Dec(v, pos)
    }
    val v = Cval(T_MAP)
    while (true) {
        if (pos >= buf.size) throw CborException("t")
        if ((buf[pos].toInt() and 0xff) == 0xff) { pos++; break }
        val dk = decode(buf, pos); val dv = decode(buf, dk.pos); v.map.add(arrayOf(dk.v, dv.v)); pos = dv.pos
    }
    return Dec(v, pos)
}

private fun head(major: Int, n: Long): ByteArray {
    val base = major shl 5
    return when {
        n < 24 -> byteArrayOf((base or n.toInt()).toByte())
        n < 0x100L -> byteArrayOf((base or 24).toByte(), n.toByte())
        n < 0x10000L -> byteArrayOf((base or 25).toByte(), (n shr 8).toByte(), n.toByte())
        n < 0x100000000L -> byteArrayOf((base or 26).toByte(), (n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        else -> {
            val out = ByteArray(9); out[0] = (base or 27).toByte()
            for (i in 0 until 8) out[8 - i] = (n shr (8 * i)).toByte()
            out
        }
    }
}

private fun encode(v: Cval): ByteArray {
    val out = ByteArrayOutputStream()
    encodeInto(v, out)
    return out.toByteArray()
}

private fun encodeInto(v: Cval, out: ByteArrayOutputStream) {
    when (v.t) {
        T_INT -> out.write(if (v.i >= 0) head(0, v.i) else head(1, -1 - v.i))
        T_BYTES -> { out.write(head(2, v.b.size.toLong())); out.write(v.b) }
        T_TEXT -> { val sb = v.s.toByteArray(Charsets.UTF_8); out.write(head(3, sb.size.toLong())); out.write(sb) }
        T_ARRAY -> { out.write(head(4, v.arr.size.toLong())); for (it in v.arr) encodeInto(it, out) }
        T_MAP -> {
            val enc = v.map.map { Pair(encode(it[0]), encode(it[1])) }
                .sortedWith(Comparator { a, b -> compareUnsigned(a.first, b.first) })
            out.write(head(5, enc.size.toLong()))
            for (p in enc) { out.write(p.first); out.write(p.second) }
        }
        T_NULL -> out.write(0xf6)
        else -> throw CborException("encode")
    }
}

private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
    val n = minOf(a.size, b.size)
    for (i in 0 until n) {
        val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (d != 0) return d
    }
    return a.size - b.size
}

private fun isDeterministic(buf: ByteArray): Boolean {
    val d = try { decode(buf, 0) } catch (e: RuntimeException) { return false }
    if (d.pos != buf.size) return false
    if (d.v.t == T_TAG) return false
    return try { encode(d.v).contentEquals(buf) } catch (e: RuntimeException) { false }
}

private fun mapGet(m: Cval, key: Long): Cval? {
    for (p in m.map) if (p[0].t == T_INT && p[0].i == key) return p[1]
    return null
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parse + gates
// ---------------------------------------------------------------------------
private class Sign1(val protectedBytes: ByteArray, val phdr: Cval, val payload: ByteArray, val sig: ByteArray)

private fun parseSign1(buf: ByteArray): Sign1? {
    val top = try { decode(buf, 0).v } catch (e: RuntimeException) { return null }
    var arr = top
    if (top.t == T_TAG) {
        if (top.tag != COSE_SIGN1_TAG) return null
        arr = top.arr[0]
    }
    if (arr.t != T_ARRAY || arr.arr.size != 4) return null
    val protectedV = arr.arr[0]; val uhdr = arr.arr[1]; val payload = arr.arr[2]; val sig = arr.arr[3]
    if (protectedV.t != T_BYTES || uhdr.t != T_MAP || sig.t != T_BYTES) return null
    if (payload.t != T_BYTES && payload.t != T_NULL) return null
    val phdr: Cval
    if (protectedV.b.isEmpty()) {
        phdr = Cval(T_MAP)
    } else {
        if (!isDeterministic(protectedV.b)) return null
        val dec = try { decode(protectedV.b, 0).v } catch (e: RuntimeException) { return null }
        if (dec.t != T_MAP) return null
        phdr = dec
    }
    val pl = if (payload.t == T_BYTES) payload.b else ByteArray(0)
    return Sign1(protectedV.b, phdr, pl, sig.b)
}

private fun sigStructure(protectedBytes: ByteArray, payload: ByteArray): ByteArray {
    val a = Cval(T_ARRAY)
    val s1 = Cval(T_TEXT); s1.s = "Signature1"; a.arr.add(s1)
    val p = Cval(T_BYTES); p.b = protectedBytes; a.arr.add(p)
    val aad = Cval(T_BYTES); aad.b = ByteArray(0); a.arr.add(aad)
    val pl = Cval(T_BYTES); pl.b = payload; a.arr.add(pl)
    return encode(a)
}

// ---------------------------------------------------------------------------
// Signature verification per algorithm
// ---------------------------------------------------------------------------
private fun onCurve(x: BigInteger, y: BigInteger): Boolean {
    val lhs = y.multiply(y).mod(P256_P)
    val rhs = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P)
    return lhs == rhs
}

private fun es256(key: JsonNode, preimage: ByteArray, sig: ByteArray): Boolean {
    return try {
        if (sig.size != 64) return false
        val x = BigInteger(1, hexb(key.get("x").asText()))
        val y = BigInteger(1, hexb(key.get("y").asText()))
        if (!onCurve(x, y)) return false
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
        val v = Signature.getInstance("SHA256withECDSAinP1363Format")
        v.initVerify(pub); v.update(preimage); v.verify(sig)
    } catch (e: Exception) { false }
}

private fun eddsa(key: JsonNode, preimage: ByteArray, sig: ByteArray): Boolean {
    return try {
        val pk = hexb(key.get("x").asText())
        if (pk.size != 32) return false
        val der = ED_SPKI_PREFIX + pk
        val pub = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
        val v = Signature.getInstance("Ed25519")
        v.initVerify(pub); v.update(preimage); v.verify(sig)
    } catch (e: Exception) { false }
}

private fun ps256(key: JsonNode, preimage: ByteArray, sig: ByteArray): Boolean {
    return try {
        val n = BigInteger(1, hexb(key.get("n").asText()))
        val e = BigInteger(1, hexb(key.get("e").asText()))
        val pub = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))
        val v = Signature.getInstance("RSASSA-PSS")
        v.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
        v.initVerify(pub); v.update(preimage); v.verify(sig)
    } catch (e: Exception) { false }
}

private fun verdict(buf: ByteArray, key: JsonNode): Boolean {
    val p = parseSign1(buf) ?: return false
    val alg = mapGet(p.phdr, 1) ?: return false
    if (alg.t != T_INT) return false
    val crit = mapGet(p.phdr, 2)
    if (crit != null) {
        if (crit.t != T_ARRAY || crit.arr.isEmpty()) return false
        for (l in crit.arr) if (l.t != T_INT || !knownLabel(l.i)) return false
    }
    val wantKty = algKty(alg.i) ?: return false
    val kty = if (key.hasNonNull("kty")) key.get("kty").asText() else null
    if (kty != wantKty) return false
    val preimage = sigStructure(p.protectedBytes, p.payload)
    return when (alg.i) {
        -7L -> es256(key, preimage, p.sig)
        -8L -> eddsa(key, preimage, p.sig)
        -37L -> ps256(key, preimage, p.sig)
        else -> false
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else DEFAULT_PATH
    val corpus = MAPPER.readTree(File(path))
    val keys = corpus.get("keys")

    var total = 0; var matched = 0
    val fails = ArrayList<String>()
    for (sec in SECTIONS) {
        val arr = corpus.get(sec) ?: continue
        for (c in arr) {
            val accept = if (sec == "cose_deterministic_cbor") {
                isDeterministic(hexb(c.get("cbor_hex").asText()))
            } else {
                verdict(hexb(c.get("cose_hex").asText()), keys.get(c.get("key").asText()))
            }
            total++
            if (accept == c.get("expect_valid").asBoolean()) matched++
            else fails.add("[$sec] ${if (c.hasNonNull("note")) c.get("note").asText() else ""}")
        }
    }
    fails.forEach { println("FAIL  $it") }
    println("\nkotlin (cose): $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
