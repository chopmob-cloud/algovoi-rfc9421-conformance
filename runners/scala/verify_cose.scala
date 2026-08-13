// Scala/JVM runner for the COSE_Sign1 corpus (cose_v0).
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
// JSON via Jackson; ES256 ("SHA256withECDSAinP1363Format" over raw r||s with an
// explicit on-curve check) and PS256 ("RSASSA-PSS", SHA-256, MGF1/SHA-256, salt 32)
// via the JDK provider; EdDSA (Ed25519) via Bouncy Castle. Keys from the hex COSE
// material. Same `using` deps as the sibling runners.
//
// Run:  scala-cli run --server=false verify_cose.scala -- <corpus path>
// Corpus path: argv[0], else the sibling repo default. Exit 0 iff every case matches.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.78.1"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

import java.io.{ByteArrayOutputStream, File}
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{AlgorithmParameters, KeyFactory, Signature}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPoint, ECPublicKeySpec}
import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec, RSAPublicKeySpec}
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

object VerifyCose:
  val DefaultPath = "../../corpus/cose_v0/cose_v0.json"
  val Mapper = ObjectMapper()

  val Sections = Seq("cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
    "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit")

  val CoseSign1Tag = 18L

  val P256P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
  val P256A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
  val P256B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

  def hexb(s: String): Array[Byte] =
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < s.length do
      out(i / 2) = Integer.parseInt(s.substring(i, i + 2), 16).toByte
      i += 2
    out

  val EdSpkiPrefix = hexb("302a300506032b6570032100")

  def algKty(alg: Long): String = alg match
    case -7L => "EC2"; case -8L => "OKP"; case -37L => "RSA"; case _ => null

  def knownLabel(l: Long): Boolean = l >= 1 && l <= 5

  // -------------------------------------------------------------------------
  // Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
  // -------------------------------------------------------------------------
  class CborException(m: String) extends RuntimeException(m)

  val TInt = 0; val TBytes = 1; val TText = 2; val TArray = 3; val TMap = 4
  val TNull = 5; val TTag = 6; val TBool = 7

  class Cval(val t: Int):
    var i: Long = 0
    var b: Array[Byte] = Array.empty
    var s: String = ""
    var arr: ArrayBuffer[Cval] = ArrayBuffer.empty
    var map: ArrayBuffer[(Cval, Cval)] = ArrayBuffer.empty
    var tag: Long = 0

  class Dec(val v: Cval, val pos: Int)

  def decode(buf: Array[Byte], start: Int): Dec =
    if start >= buf.length then throw new CborException("truncated")
    var pos = start
    val ib = buf(pos) & 0xff
    pos += 1
    val major = ib >> 5
    val ai = ib & 0x1f
    var arg = 0L
    if ai < 24 then arg = ai.toLong
    else if ai == 24 then
      if pos + 1 > buf.length then throw new CborException("t")
      arg = (buf(pos) & 0xffL); pos += 1
    else if ai == 25 then
      if pos + 2 > buf.length then throw new CborException("t")
      arg = ((buf(pos) & 0xffL) << 8) | (buf(pos + 1) & 0xffL); pos += 2
    else if ai == 26 then
      if pos + 4 > buf.length then throw new CborException("t")
      var a = 0L; var j = 0; while j < 4 do { a = (a << 8) | (buf(pos + j) & 0xffL); j += 1 }; arg = a; pos += 4
    else if ai == 27 then
      if pos + 8 > buf.length then throw new CborException("t")
      var a = 0L; var j = 0; while j < 8 do { a = (a << 8) | (buf(pos + j) & 0xffL); j += 1 }; arg = a; pos += 8
    else if ai == 31 then
      if major < 2 || major > 5 then throw new CborException("indef")
      return decodeIndefinite(buf, pos, major)
    else throw new CborException("reserved")

    major match
      case 0 => val v = Cval(TInt); v.i = arg; new Dec(v, pos)
      case 1 => val v = Cval(TInt); v.i = -1 - arg; new Dec(v, pos)
      case 2 =>
        if pos + arg > buf.length then throw new CborException("t")
        val v = Cval(TBytes); v.b = buf.slice(pos, pos + arg.toInt); new Dec(v, pos + arg.toInt)
      case 3 =>
        if pos + arg > buf.length then throw new CborException("t")
        val v = Cval(TText); v.s = new String(buf, pos, arg.toInt, StandardCharsets.UTF_8); new Dec(v, pos + arg.toInt)
      case 4 =>
        val v = Cval(TArray)
        var j = 0L
        while j < arg do { val d = decode(buf, pos); v.arr += d.v; pos = d.pos; j += 1 }
        new Dec(v, pos)
      case 5 =>
        val v = Cval(TMap)
        var j = 0L
        while j < arg do { val dk = decode(buf, pos); val dv = decode(buf, dk.pos); v.map += ((dk.v, dv.v)); pos = dv.pos; j += 1 }
        new Dec(v, pos)
      case 6 =>
        val inner = decode(buf, pos); val v = Cval(TTag); v.tag = arg; v.arr += inner.v; new Dec(v, inner.pos)
      case 7 =>
        if ai == 22 then new Dec(Cval(TNull), pos)
        else if ai == 20 then { val v = Cval(TBool); v.i = 0; new Dec(v, pos) }
        else if ai == 21 then { val v = Cval(TBool); v.i = 1; new Dec(v, pos) }
        else throw new CborException("simple/float")
      case _ => throw new CborException("major")

  def decodeIndefinite(buf: Array[Byte], start: Int, major: Int): Dec =
    var pos = start
    if major == 2 || major == 3 then
      val acc = new ByteArrayOutputStream()
      var done = false
      while !done do
        if pos >= buf.length then throw new CborException("t")
        if (buf(pos) & 0xff) == 0xff then { pos += 1; done = true }
        else
          val d = decode(buf, pos)
          if d.v.t != (if major == 2 then TBytes else TText) then throw new CborException("chunk")
          val cb = if major == 2 then d.v.b else d.v.s.getBytes(StandardCharsets.UTF_8)
          acc.write(cb); pos = d.pos
      val v = Cval(if major == 2 then TBytes else TText)
      if major == 2 then v.b = acc.toByteArray else v.s = new String(acc.toByteArray, StandardCharsets.UTF_8)
      new Dec(v, pos)
    else if major == 4 then
      val v = Cval(TArray)
      var done = false
      while !done do
        if pos >= buf.length then throw new CborException("t")
        if (buf(pos) & 0xff) == 0xff then { pos += 1; done = true }
        else { val d = decode(buf, pos); v.arr += d.v; pos = d.pos }
      new Dec(v, pos)
    else
      val v = Cval(TMap)
      var done = false
      while !done do
        if pos >= buf.length then throw new CborException("t")
        if (buf(pos) & 0xff) == 0xff then { pos += 1; done = true }
        else { val dk = decode(buf, pos); val dv = decode(buf, dk.pos); v.map += ((dk.v, dv.v)); pos = dv.pos }
      new Dec(v, pos)

  def head(major: Int, n: Long): Array[Byte] =
    val base = major << 5
    if n < 24 then Array((base | n.toInt).toByte)
    else if n < 0x100L then Array((base | 24).toByte, n.toByte)
    else if n < 0x10000L then Array((base | 25).toByte, (n >> 8).toByte, n.toByte)
    else if n < 0x100000000L then Array((base | 26).toByte, (n >> 24).toByte, (n >> 16).toByte, (n >> 8).toByte, n.toByte)
    else
      val out = new Array[Byte](9); out(0) = (base | 27).toByte
      var i = 0; while i < 8 do { out(8 - i) = (n >> (8 * i)).toByte; i += 1 }
      out

  def encode(v: Cval): Array[Byte] =
    val out = new ByteArrayOutputStream()
    encodeInto(v, out)
    out.toByteArray

  def encodeInto(v: Cval, out: ByteArrayOutputStream): Unit =
    v.t match
      case TInt => out.write(if v.i >= 0 then head(0, v.i) else head(1, -1 - v.i))
      case TBytes => out.write(head(2, v.b.length)); out.write(v.b)
      case TText =>
        val sb = v.s.getBytes(StandardCharsets.UTF_8); out.write(head(3, sb.length)); out.write(sb)
      case TArray =>
        out.write(head(4, v.arr.size)); v.arr.foreach(encodeInto(_, out))
      case TMap =>
        val enc = v.map.map((k, vv) => (encode(k), encode(vv)))
          .sortWith((a, b) => compareUnsigned(a._1, b._1) < 0)
        out.write(head(5, enc.size))
        enc.foreach((k, vv) => { out.write(k); out.write(vv) })
      case TNull => out.write(0xf6)
      case _ => throw new CborException("encode")

  def compareUnsigned(a: Array[Byte], b: Array[Byte]): Int =
    val n = math.min(a.length, b.length)
    var i = 0
    while i < n do
      val d = (a(i) & 0xff) - (b(i) & 0xff)
      if d != 0 then return d
      i += 1
    a.length - b.length

  def isDeterministic(buf: Array[Byte]): Boolean =
    try
      val d = decode(buf, 0)
      if d.pos != buf.length then false
      else if d.v.t == TTag then false
      else java.util.Arrays.equals(encode(d.v), buf)
    catch case _: RuntimeException => false

  def mapGet(m: Cval, key: Long): Cval =
    m.map.foreach((k, v) => if k.t == TInt && k.i == key then return v)
    null

  // -------------------------------------------------------------------------
  // COSE_Sign1 parse + gates
  // -------------------------------------------------------------------------
  class Sign1(val protectedBytes: Array[Byte], val phdr: Cval, val payload: Array[Byte], val sig: Array[Byte])

  def parseSign1(buf: Array[Byte]): Sign1 =
    val top =
      try decode(buf, 0).v
      catch case _: RuntimeException => return null
    var arr = top
    if top.t == TTag then
      if top.tag != CoseSign1Tag then return null
      arr = top.arr(0)
    if arr.t != TArray || arr.arr.size != 4 then return null
    val protectedV = arr.arr(0); val uhdr = arr.arr(1); val payload = arr.arr(2); val sig = arr.arr(3)
    if protectedV.t != TBytes || uhdr.t != TMap || sig.t != TBytes then return null
    if payload.t != TBytes && payload.t != TNull then return null
    val phdr =
      if protectedV.b.isEmpty then Cval(TMap)
      else
        if !isDeterministic(protectedV.b) then return null
        val dec =
          try decode(protectedV.b, 0).v
          catch case _: RuntimeException => return null
        if dec.t != TMap then return null
        dec
    val pl = if payload.t == TBytes then payload.b else Array.empty[Byte]
    new Sign1(protectedV.b, phdr, pl, sig.b)

  def sigStructure(protectedBytes: Array[Byte], payload: Array[Byte]): Array[Byte] =
    val a = Cval(TArray)
    val s1 = Cval(TText); s1.s = "Signature1"; a.arr += s1
    val p = Cval(TBytes); p.b = protectedBytes; a.arr += p
    val aad = Cval(TBytes); aad.b = Array.empty; a.arr += aad
    val pl = Cval(TBytes); pl.b = payload; a.arr += pl
    encode(a)

  // -------------------------------------------------------------------------
  // Signature verification per algorithm
  // -------------------------------------------------------------------------
  def onCurve(x: BigInteger, y: BigInteger): Boolean =
    val lhs = y.multiply(y).mod(P256P)
    val rhs = x.multiply(x).multiply(x).add(P256A.multiply(x)).add(P256B).mod(P256P)
    lhs == rhs

  def es256(key: JsonNode, preimage: Array[Byte], sig: Array[Byte]): Boolean =
    try
      if sig.length != 64 then false
      else
        val x = new BigInteger(1, hexb(key.get("x").asText()))
        val y = new BigInteger(1, hexb(key.get("y").asText()))
        if !onCurve(x, y) then false
        else
          val ap = AlgorithmParameters.getInstance("EC")
          ap.init(ECGenParameterSpec("secp256r1"))
          val spec = ap.getParameterSpec(classOf[ECParameterSpec])
          val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
          val v = Signature.getInstance("SHA256withECDSAinP1363Format")
          v.initVerify(pub); v.update(preimage); v.verify(sig)
    catch case _: Exception => false

  def eddsa(key: JsonNode, preimage: Array[Byte], sig: Array[Byte]): Boolean =
    try
      val pk = hexb(key.get("x").asText())
      if pk.length != 32 || sig.length != 64 then false
      else
        val signer = new Ed25519Signer()
        signer.init(false, new Ed25519PublicKeyParameters(pk, 0))
        signer.update(preimage, 0, preimage.length)
        signer.verifySignature(sig)
    catch case _: Exception => false

  def ps256(key: JsonNode, preimage: Array[Byte], sig: Array[Byte]): Boolean =
    try
      val n = new BigInteger(1, hexb(key.get("n").asText()))
      val e = new BigInteger(1, hexb(key.get("e").asText()))
      val pub = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))
      val v = Signature.getInstance("RSASSA-PSS")
      v.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      v.initVerify(pub); v.update(preimage); v.verify(sig)
    catch case _: Exception => false

  def verdict(buf: Array[Byte], key: JsonNode): Boolean =
    val p = parseSign1(buf)
    if p == null then return false
    val alg = mapGet(p.phdr, 1)
    if alg == null || alg.t != TInt then return false
    val crit = mapGet(p.phdr, 2)
    if crit != null then
      if crit.t != TArray || crit.arr.isEmpty then return false
      crit.arr.foreach(l => if l.t != TInt || !knownLabel(l.i) then return false)
    val wantKty = algKty(alg.i)
    if wantKty == null then return false
    val kty = if key.hasNonNull("kty") then key.get("kty").asText() else null
    if kty != wantKty then return false
    val preimage = sigStructure(p.protectedBytes, p.payload)
    alg.i match
      case -7L => es256(key, preimage, p.sig)
      case -8L => eddsa(key, preimage, p.sig)
      case -37L => ps256(key, preimage, p.sig)
      case _ => false

  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else DefaultPath
    val corpus = Mapper.readTree(new File(path))
    val keys = corpus.get("keys")

    val fails = ArrayBuffer[(String, String)]()
    var total = 0
    var matched = 0
    for sec <- Sections do
      val arr = corpus.get(sec)
      if arr != null then
        arr.elements().asScala.foreach { c =>
          val accept =
            if sec == "cose_deterministic_cbor" then isDeterministic(hexb(c.get("cbor_hex").asText()))
            else verdict(hexb(c.get("cose_hex").asText()), keys.get(c.get("key").asText()))
          total += 1
          if accept == c.get("expect_valid").asBoolean() then matched += 1
          else fails += ((sec, if c.hasNonNull("note") then c.get("note").asText() else ""))
        }
    fails.foreach { case (s, n) => println(s"FAIL  [$s] $n") }
    println(s"\nscala (cose): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
