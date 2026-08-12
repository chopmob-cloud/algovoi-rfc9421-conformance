// Scala/JVM runner for the JSON Web Signature corpus (jws_v0).
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
// JSON via Jackson; RS256 ("SHA256withRSA") and ES256 ("SHA256withECDSAinP1363Format"
// over raw r||s, with an explicit on-curve check) via the JDK crypto provider;
// EdDSA (Ed25519) via Bouncy Castle. Same `using` deps as the sibling runners.
//
// Run:  scala-cli run --server=false verify_jws.scala -- <corpus path>
// Corpus path: argv[0], else the sibling repo default. Exit 0 iff every case matches.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.78.1"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{AlgorithmParameters, KeyFactory, Signature}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPoint, ECPublicKeySpec}
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

object VerifyJws:
  val DefaultPath = "../../corpus/jws_v0/jws_v0.json"
  val Mapper = ObjectMapper()

  val Sections = Seq("jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
    "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid")

  val P256P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
  val P256A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
  val P256B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

  def hexBytes(s: String): Array[Byte] =
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < s.length do
      out(i / 2) = Integer.parseInt(s.substring(i, i + 2), 16).toByte
      i += 2
    out

  val EdSpkiPrefix = hexBytes("302a300506032b6570032100")

  def algKty(alg: String): String = alg match
    case "RS256" => "RSA"; case "ES256" => "EC"; case "EdDSA" => "OKP"; case "HS256" => "oct"; case _ => null

  // Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
  def b64url(seg: String): Array[Byte] =
    var i = 0
    while i < seg.length do
      val ch = seg.charAt(i)
      val ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
      if !ok then return null
      i += 1
    if seg.length % 4 == 1 then return null
    try Base64.getUrlDecoder.decode(seg) catch case _: IllegalArgumentException => null

  def b64uInt(seg: String): BigInteger =
    val b = b64url(seg)
    if b == null then null else new BigInteger(1, b)

  def note(c: JsonNode): String = if c.hasNonNull("note") then c.get("note").asText() else ""

  // (header, sig, signingInput) or null on any structural fault.
  def parseCompact(token: String): (JsonNode, Array[Byte], Array[Byte]) =
    val parts = token.split("\\.", -1)
    if parts.length != 3 then return null
    val headerBytes = b64url(parts(0))
    if headerBytes == null then return null
    val header =
      try Mapper.readTree(new String(headerBytes, StandardCharsets.UTF_8))
      catch case _: Exception => null
    if header == null || !header.isObject then return null
    if !header.has("alg") then return null
    if b64url(parts(1)) == null then return null
    val sig = b64url(parts(2))
    if sig == null then return null
    (header, sig, (parts(0) + "." + parts(1)).getBytes(StandardCharsets.US_ASCII))

  def selectKey(header: JsonNode, keysObj: JsonNode, keyNames: JsonNode, byKid: Boolean): JsonNode =
    if byKid then
      if !header.hasNonNull("kid") then return null
      val kid = header.get("kid").asText()
      val it = keyNames.elements()
      while it.hasNext do
        val jwk = keysObj.get(it.next().asText())
        if jwk != null && jwk.hasNonNull("kid") && jwk.get("kid").asText() == kid then return jwk
      null
    else keysObj.get(keyNames.get(0).asText())

  def rs256(jwk: JsonNode, si: Array[Byte], sig: Array[Byte]): Boolean =
    try
      val n = b64uInt(jwk.get("n").asText())
      val e = b64uInt(jwk.get("e").asText())
      if n == null || e == null then return false
      val key = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))
      val v = Signature.getInstance("SHA256withRSA")
      v.initVerify(key); v.update(si); v.verify(sig)
    catch case _: Exception => false

  def onCurve(x: BigInteger, y: BigInteger): Boolean =
    val lhs = y.multiply(y).mod(P256P)
    val rhs = x.multiply(x).multiply(x).add(P256A.multiply(x)).add(P256B).mod(P256P)
    lhs == rhs

  def es256(jwk: JsonNode, si: Array[Byte], sig: Array[Byte]): Boolean =
    try
      if sig.length != 64 then return false
      val x = b64uInt(jwk.get("x").asText())
      val y = b64uInt(jwk.get("y").asText())
      if x == null || y == null || !onCurve(x, y) then return false
      val ap = AlgorithmParameters.getInstance("EC")
      ap.init(ECGenParameterSpec("secp256r1"))
      val spec = ap.getParameterSpec(classOf[ECParameterSpec])
      val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
      val v = Signature.getInstance("SHA256withECDSAinP1363Format")
      v.initVerify(key); v.update(si); v.verify(sig)
    catch case _: Exception => false

  def eddsa(jwk: JsonNode, si: Array[Byte], sig: Array[Byte]): Boolean =
    try
      val pk = b64url(jwk.get("x").asText())
      if pk == null || pk.length != 32 || sig.length != 64 then false
      else
        val signer = new Ed25519Signer()
        signer.init(false, new Ed25519PublicKeyParameters(pk, 0))
        signer.update(si, 0, si.length)
        signer.verifySignature(sig)
    catch case _: Exception => false

  def verdict(token: String, keysObj: JsonNode, keyNames: JsonNode, byKid: Boolean): Boolean =
    val parsed = parseCompact(token)
    if parsed == null then return false
    val (header, sig, si) = parsed
    val alg = if header.hasNonNull("alg") then header.get("alg").asText() else null
    if alg == null || alg == "none" then return false
    if header.has("crit") then return false
    val wantKty = algKty(alg)
    if wantKty == null then return false
    val jwk = selectKey(header, keysObj, keyNames, byKid)
    if jwk == null then return false
    val kty = if jwk.hasNonNull("kty") then jwk.get("kty").asText() else null
    if kty != wantKty then return false
    alg match
      case "RS256" => rs256(jwk, si, sig)
      case "ES256" => es256(jwk, si, sig)
      case "EdDSA" => eddsa(jwk, si, sig)
      case _ => false

  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else DefaultPath
    val corpus = Mapper.readTree(new File(path))
    val keysObj = corpus.get("keys")

    val fails = ArrayBuffer[(String, String)]()
    var total = 0
    var matched = 0
    for sec <- Sections do
      val arr = corpus.get(sec)
      if arr != null then
        arr.elements().asScala.foreach { c =>
          val verify = c.get("verify")
          val accept = verdict(c.get("jws").asText(), keysObj,
            verify.get("key_names"), verify.get("select_by_kid").asBoolean())
          total += 1
          if accept == c.get("expect_valid").asBoolean() then matched += 1
          else fails += ((sec, note(c)))
        }
    fails.foreach { case (s, n) => println(s"FAIL  [$s] $n") }
    println(s"\nscala (jws): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
