// Scala runner for the rfc9421_negative_v1 / _v2 CORE cross-language battery.
//
// Independent Scala/JVM port of the verdict surface (signing_base.py, parse.py,
// keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
// (no Scala RFC 9421 verifier exists); must produce byte-identical verdicts to
// every other runner. Ed25519 verify + canonical-S via Bouncy Castle; the
// small-order / non-canonical key gate is ported with java.math.BigInteger
// (RFC 8032 Appendix A arithmetic); ECDSA P-256/P-384 via the JDK provider with
// explicit range / width / on-curve / strict-low-s checks. JSON via Jackson.
//
// Run: scala-cli run negative_v1.scala -- <corpus path>
// Corpus path: argv[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.78.1"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import org.bouncycastle.asn1.{ASN1EncodableVector, ASN1Integer, DERSequence}
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{AlgorithmParameters, KeyFactory, Signature}
import java.security.spec.{ECFieldFp, ECGenParameterSpec, ECParameterSpec, ECPoint, ECPublicKeySpec}
import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec, X509EncodedKeySpec}
import java.util.Base64
import scala.jdk.CollectionConverters.*

class SigningBaseError(m: String) extends RuntimeException(m)
class ParseError(m: String) extends RuntimeException(m)
class WeakKeyError(m: String) extends RuntimeException(m)

object NegativeV1:
  val DefaultPath = "../../corpus/rfc9421_negative_v2/rfc9421_negative_v2.json"

  // ================= signing base (port of signing_base.py) =================
  def buildSigningBase(in: JsonNode, mode: String, spr: String): String =
    if mode != "algovoi-v0" && mode != "rfc9421" then throw SigningBaseError("bad mode")
    if mode == "rfc9421" && spr == null then throw SigningBaseError("rfc9421 needs spr")
    val headers = scala.collection.mutable.LinkedHashMap[String, String]()
    val h = in.get("headers")
    if h != null && h.isObject then
      h.fieldNames().asScala.foreach(k => headers(k.toLowerCase) = h.get(k).asText())
    val params = in.get("parameters")

    def strOr(field: String, msg: String): String =
      val n = in.get(field); if n == null || n.isNull then throw SigningBaseError(msg) else n.asText()
    def paramOr(key: String, msg: String): String =
      if params == null || !params.has(key) then throw SigningBaseError(msg)
      val v = params.get(key); if v.isIntegralNumber then v.bigIntegerValue().toString else v.asText()

    val lines = scala.collection.mutable.ArrayBuffer[String]()
    in.get("covered_components").elements().asScala.foreach { compNode =>
      val component = compNode.asText()
      val c = component.toLowerCase
      val value = c match
        case "@method"     => val v = strOr("method", "@method covered but not supplied"); if mode == "rfc9421" then v else v.toLowerCase
        case "@authority"  => strOr("authority", "@authority covered but not supplied").toLowerCase
        case "@path"       => strOr("path", "@path covered but not supplied")
        case "@target-uri" => strOr("target_uri", "@target-uri covered but not supplied")
        case "@scheme"     => strOr("scheme", "@scheme covered but not supplied").toLowerCase
        case "@status" =>
          val n = in.get("status"); if n == null || n.isNull then throw SigningBaseError("@status covered but not supplied")
          n.bigIntegerValue().toString
        case "created" => paramOr("created", "'created' covered but no created parameter")
        case "expires" => paramOr("expires", "'expires' covered but no expires parameter")
        case _ =>
          if c.startsWith("@") then throw SigningBaseError(s"unsupported derived component: $component")
          headers.getOrElse(c, throw SigningBaseError(s"covered header $component not present"))
      lines += s"\"$c\": $value"
    }
    if mode == "rfc9421" then lines += s"\"@signature-params\": $spr"
    lines.mkString("\n")

  // ================= structured-field parse (port of parse.py) =================
  val LabelRe = "^\\s*([A-Za-z][A-Za-z0-9_-]*)\\s*=\\s*".r
  val CoveredRe = "^\\(\\s*(?:\"[^\"]*\"\\s*)*\\)".r

  def parseSignatureInput(header: String): Unit =
    if header == null then throw ParseError("header must be str")
    val hv = header.strip
    if hv.isEmpty then throw ParseError("empty header value")
    val rest = LabelRe.findPrefixMatchOf(hv) match
      case Some(m) => hv.substring(m.end)
      case None    => if hv.startsWith("(") then hv else throw ParseError("no label")
    if CoveredRe.findPrefixMatchOf(rest).isEmpty then throw ParseError("no covered list")

  def parseSignatureValue(header: String): Unit =
    if header == null then throw ParseError("header must be str")
    val hv = header.strip
    if hv.isEmpty then throw ParseError("empty Signature header value")
    val rest = LabelRe.findPrefixMatchOf(hv) match
      case Some(m) => hv.substring(m.end).strip
      case None    => if hv.startsWith(":") then hv else throw ParseError("no prefix")
    if !rest.startsWith(":") || !rest.endsWith(":") || rest.length < 2 then throw ParseError("not colon-wrapped")
    val sigB64 = rest.substring(1, rest.length - 1)
    val decoded = try Base64.getDecoder.decode(sigB64) catch case _: IllegalArgumentException => throw ParseError("bad base64")
    if Base64.getEncoder.encodeToString(decoded) != sigB64 then throw ParseError("non-canonical base64")

  // ================= Ed25519 key gate (port of keycheck.py) =================
  val P: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
  val D: BigInteger = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
  val SqrtM1: BigInteger = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)
  val LOrder: BigInteger = BigInteger.TWO.pow(252).add(BigInteger("27742317777372353535851937790883648493"))

  def recoverX(y: BigInteger, sign: Int): BigInteger =
    if y.compareTo(P) >= 0 then return null
    val y2 = y.multiply(y).mod(P)
    val x2 = y2.subtract(BigInteger.ONE).mod(P)
      .multiply(D.multiply(y2).add(BigInteger.ONE).mod(P).modInverse(P)).mod(P)
    if x2.signum == 0 then return if sign == 1 then null else BigInteger.ZERO
    var x = x2.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P)
    if x.multiply(x).subtract(x2).mod(P).signum != 0 then x = x.multiply(SqrtM1).mod(P)
    if x.multiply(x).subtract(x2).mod(P).signum != 0 then return null
    if (if x.testBit(0) then sign == 0 else sign == 1) then x = P.subtract(x)
    x

  def decodePoint(pk: Array[Byte]): Array[BigInteger] =
    if pk.length != 32 then return null
    val le = Array.tabulate(32)(i => pk(31 - i))
    var y = new BigInteger(1, le)
    val sign = if y.testBit(255) then 1 else 0
    y = y.clearBit(255)
    val x = recoverX(y, sign)
    if x == null then null else Array(x, y, BigInteger.ONE, x.multiply(y).mod(P))

  def add(p: Array[BigInteger], q: Array[BigInteger]): Array[BigInteger] =
    val a = p(1).subtract(p(0)).multiply(q(1).subtract(q(0))).mod(P)
    val b = p(1).add(p(0)).multiply(q(1).add(q(0))).mod(P)
    val c = BigInteger.TWO.multiply(p(3)).multiply(q(3)).multiply(D).mod(P)
    val dd = BigInteger.TWO.multiply(p(2)).multiply(q(2)).mod(P)
    val e = b.subtract(a); val f = dd.subtract(c); val g = dd.add(c); val hh = b.add(a)
    Array(e.multiply(f).mod(P), g.multiply(hh).mod(P), f.multiply(g).mod(P), e.multiply(hh).mod(P))

  def mul8(p: Array[BigInteger]): Array[BigInteger] =
    val p2 = add(p, p); val p4 = add(p2, p2); add(p4, p4)

  def isIdentity(p: Array[BigInteger]): Boolean =
    p(0).mod(P).signum == 0 && p(1).subtract(p(2)).mod(P).signum == 0

  def isSmallOrder(pk: Array[Byte]): Boolean =
    val p = decodePoint(pk); p != null && isIdentity(mul8(p))

  def checkEd25519PublicKey(pk: Array[Byte]): Unit =
    val p = decodePoint(pk)
    if p == null then throw WeakKeyError("non-canonical/off-curve")
    if isIdentity(mul8(p)) then throw WeakKeyError("small-order")

  // ================= Ed25519 verify (port of verify.py) =================
  def ed25519Verify(msg: Array[Byte], sig: Array[Byte], pk: Array[Byte]): Boolean =
    if sig.length != 64 || pk.length != 32 then false
    else
      val gate = try { checkEd25519PublicKey(pk); true } catch case _: WeakKeyError => false
      if !gate then false
      else
        val signer = Ed25519Signer()
        signer.init(false, Ed25519PublicKeyParameters(pk, 0))
        signer.update(msg, 0, msg.length)
        signer.verifySignature(sig)

  // ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
  def ecdsaVerify(curve: String, msg: Array[Byte], sigRaw: Array[Byte], pub: Array[Byte], strict: Boolean): Boolean =
    try
      val fieldSize = if curve == "p256" then 32 else 48
      val stdName = if curve == "p256" then "secp256r1" else "secp384r1"
      val sigAlg = if curve == "p256" then "SHA256withECDSA" else "SHA384withECDSA"
      if sigRaw.length != 2 * fieldSize then return false
      val r = new BigInteger(1, sigRaw.slice(0, fieldSize))
      val s = new BigInteger(1, sigRaw.slice(fieldSize, 2 * fieldSize))
      val ap = AlgorithmParameters.getInstance("EC"); ap.init(ECGenParameterSpec(stdName))
      val spec = ap.getParameterSpec(classOf[ECParameterSpec]); val n = spec.getOrder
      if r.signum <= 0 || r.compareTo(n) >= 0 || s.signum <= 0 || s.compareTo(n) >= 0 then return false
      if strict && s.compareTo(n.shiftRight(1)) > 0 then return false
      if pub.length != 1 + 2 * fieldSize || (pub(0) & 0xff) != 0x04 then return false
      val x = new BigInteger(1, pub.slice(1, 1 + fieldSize))
      val yc = new BigInteger(1, pub.slice(1 + fieldSize, 1 + 2 * fieldSize))
      val pMod = spec.getCurve.getField.asInstanceOf[ECFieldFp].getP
      val lhs = yc.multiply(yc).mod(pMod)
      val rhs = x.multiply(x).multiply(x).add(spec.getCurve.getA.multiply(x)).add(spec.getCurve.getB).mod(pMod)
      if lhs != rhs then return false
      val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, yc), spec))
      val v = ASN1EncodableVector(); v.add(ASN1Integer(r)); v.add(ASN1Integer(s))
      val der = DERSequence(v).getEncoded("DER")
      val verifier = Signature.getInstance(sigAlg); verifier.initVerify(key); verifier.update(msg)
      verifier.verify(der)
    catch case _: Exception => false

  // ================= RSA verify (rsa-pss-sha512 / rsa-v1_5-sha256) =================
  def rsaVerify(alg: String, base: Array[Byte], sig: Array[Byte], spki: Array[Byte]): Boolean =
    try
      val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki))
      val s = alg match
        case "rsa-pss-sha512" =>
          val sg = Signature.getInstance("RSASSA-PSS")
          sg.setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)); sg
        case "rsa-v1_5-sha256" => Signature.getInstance("SHA256withRSA")
        case _ => return false
      s.initVerify(key); s.update(base); s.verify(sig)
    catch case _: Exception => false

  def hex(s: String): Array[Byte] =
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < s.length do { out(i / 2) = Integer.parseInt(s.substring(i, i + 2), 16).toByte; i += 2 }
    out

  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else Option(System.getenv("ALGOVOI_NEGATIVE_V1")).getOrElse(DefaultPath)
    val corpus = ObjectMapper().readTree(new File(path))
    var total = 0; var matched = 0
    val fails = scala.collection.mutable.ArrayBuffer[String]()
    def rec(ok: Boolean, section: String, c: JsonNode): Unit =
      total += 1
      if ok then matched += 1
      else fails += s"[$section] " + (if c.hasNonNull("note") then c.get("note").asText() else "")

    corpus.get("signing_base").elements().asScala.foreach { c =>
      val want = new String(Base64.getDecoder.decode(c.get("signing_base_b64").asText()), StandardCharsets.UTF_8)
      val spr = if c.hasNonNull("signature_params_raw") then c.get("signature_params_raw").asText() else null
      val ok = try
        val built = buildSigningBase(c.get("in"), c.get("mode").asText(), spr)
        c.get("ok").asBoolean() && built == want
      catch case _: RuntimeException => !c.get("ok").asBoolean()
      rec(ok, "signing_base", c)
    }
    corpus.get("signature_input_parse").elements().asScala.foreach { c =>
      val p = try { parseSignatureInput(c.get("header").asText()); true } catch case _: ParseError => false
      rec(p == c.get("ok").asBoolean(), "sig_input_parse", c)
    }
    corpus.get("signature_value_parse").elements().asScala.foreach { c =>
      val p = try { parseSignatureValue(c.get("header").asText()); true } catch case _: ParseError => false
      rec(p == c.get("ok").asBoolean(), "sig_value_parse", c)
    }
    corpus.get("keygate").elements().asScala.foreach { c =>
      val raw = hex(c.get("pk_hex").asText())
      val rejected = try { checkEd25519PublicKey(raw); null } catch case _: WeakKeyError => "WeakKeyError"
      val want = if c.hasNonNull("rejected") then c.get("rejected").asText() else null
      rec(rejected == want && isSmallOrder(raw) == c.get("small_order").asBoolean(), "keygate", c)
    }
    corpus.get("ed25519_verify").elements().asScala.foreach { c =>
      val base = Base64.getDecoder.decode(c.get("signing_base_b64").asText())
      val valid = ed25519Verify(base, hex(c.get("sig_hex").asText()), hex(c.get("pk_hex").asText()))
      rec(valid == c.get("expect_valid").asBoolean(), "ed25519_verify", c)
    }
    corpus.get("ecdsa_verify").elements().asScala.foreach { c =>
      val strict = c.hasNonNull("strict_low_s") && c.get("strict_low_s").asBoolean()
      val valid = ecdsaVerify(c.get("curve").asText(), hex(c.get("msg_hex").asText()),
        hex(c.get("sig_raw_hex").asText()), hex(c.get("pub_uncompressed_hex").asText()), strict)
      rec(valid == c.get("expect_valid").asBoolean(), "ecdsa_verify", c)
    }

    if corpus.has("rsa_verify") then corpus.get("rsa_verify").elements().asScala.foreach { c =>
      val base = Base64.getDecoder.decode(c.get("signing_base_b64").asText())
      val valid = rsaVerify(c.get("alg").asText(), base, hex(c.get("sig_hex").asText()), hex(c.get("pub_spki_hex").asText()))
      rec(valid == c.get("expect_valid").asBoolean(), "rsa_verify", c)
    }

    fails.foreach(f => println(s"FAIL  $f"))
    println(s"\nscala: $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
