// Scala/JVM runner for the FAPI 2.0 Message Signing profile corpus
// (fapi_messagesigning_v0).
//
// Independently reproduces every verdict in the frozen corpus. The signing base
// (RFC 9421 Section 2.5), the PROFILE rules (mandated coverage, Content-Digest
// body binding, algorithm restriction) and the PS256/ES256 crypto are
// re-implemented here from the corpus `policy` block, NOT imported from the
// generator's oracle, so a runner passing is genuine agreement rather than an
// echo. This mirrors the Python reference runner (runners/python/verify_fapi.py)
// and the go/typescript runners case for case.
//
// JSON via Jackson; PS256 (RSASSA-PSS/SHA-256, salt 32) and ES256 (ECDSA
// P-256/SHA-256, raw r||s) via the JDK built-in crypto provider. Same `using`
// deps as the sibling runners (runners/scala/negative_v1.scala,
// runners/scala/verify_wba.scala); Bouncy Castle is pulled for parity with the
// siblings though the FAPI crypto here is JDK-only.
//
// Run:  scala-cli run --server=false verify_fapi.scala -- <corpus path>
// Corpus path: argv[0], else the sibling repo default (runners/scala relative).
// Exit 0 iff every case matches, else 1.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.78.1"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}

import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{AlgorithmParameters, KeyFactory, MessageDigest, Signature}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPoint, ECPublicKeySpec}
import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec, X509EncodedKeySpec}
import java.util.Base64
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

class SigningBaseError(m: String) extends RuntimeException(m)

object VerifyFapi:
  val DefaultPath = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json"

  // -------- generic JSON helpers --------

  def note(c: JsonNode): String =
    if c.hasNonNull("note") then c.get("note").asText() else ""

  def strList(n: JsonNode): Seq[String] =
    if n == null || !n.isArray then Seq.empty[String]
    else n.elements().asScala.map(_.asText()).toSeq

  def hex(s: String): Array[Byte] =
    if s == null || (s.length % 2) != 0 then throw new NumberFormatException("bad hex")
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < s.length do
      out(i / 2) = Integer.parseInt(s.substring(i, i + 2), 16).toByte
      i += 2
    out

  // ================= Rule 1: RFC 9421 Section 2.5 signing base =================
  // Hand-built by direct concatenation. The derived components @method,
  // @target-uri, @status, @authority and @path pull their VERBATIM value from the
  // matching `in` field (no case-folding: this corpus is always rfc9421 mode);
  // every other covered name is a header, read verbatim from in.headers[name].
  // Throws when a covered component's value is missing (build impossible); the
  // driver maps an unbuildable case to !ok. "@signature-params" is always
  // appended (mode is always rfc9421 in this corpus).
  def reqStr(in: JsonNode, field: String, msg: String): String =
    val v = in.get(field)
    if v == null || v.isNull then throw new SigningBaseError(msg) else v.asText()

  def buildSigningBase(in: JsonNode, paramsRaw: String): String =
    val cc = in.get("covered_components")
    if cc == null || !cc.isArray then throw new SigningBaseError("no covered_components")
    val lines = ArrayBuffer[String]()
    cc.elements().asScala.foreach { compNode =>
      val name = compNode.asText().toLowerCase
      val value = name match
        case "@method"     => reqStr(in, "method", "@method covered but not supplied")
        case "@target-uri" => reqStr(in, "target_uri", "@target-uri covered but not supplied")
        case "@authority"  => reqStr(in, "authority", "@authority covered but not supplied")
        case "@path"       => reqStr(in, "path", "@path covered but not supplied")
        case "@status" =>
          val n = in.get("status")
          if n == null || n.isNull || !n.isIntegralNumber then
            throw new SigningBaseError("@status covered but not supplied")
          n.bigIntegerValue().toString
        case _ =>
          val h = in.get("headers")
          if h == null || !h.isObject || h.get(name) == null || h.get(name).isNull then
            throw new SigningBaseError(s"covered header $name not present")
          h.get(name).asText()
      lines += s"\"$name\": $value"
    }
    lines += s"\"@signature-params\": $paramsRaw"
    lines.mkString("\n")

  // ================= Rule 2: mandated coverage =================
  // Accept iff every required component (lowercased) for the message_type is
  // present in the covered set (lowercased).
  def coverageOk(messageType: String, covered: JsonNode, policy: JsonNode): Boolean =
    val key = if messageType == "request" then "required_covered_request" else "required_covered_response"
    val have = strList(covered).map(_.toLowerCase).toSet
    strList(policy.get(key)).forall(r => have.contains(r.toLowerCase))

  // ================= Rule 3: Content-Digest body binding =================
  // Reject unless content-digest is covered; the header algorithm (before the
  // first '=') must be an allowed digest algorithm; and the whole header must
  // equal <alg>=:<base64(digest of body)>:.
  def contentDigestOk(bodyB64: String, header: String, covered: JsonNode, policy: JsonNode): Boolean =
    val have = strList(covered).map(_.toLowerCase).toSet
    if !have.contains("content-digest") then return false
    val eq = header.indexOf('=')
    if eq < 0 then return false
    val algorithm = header.substring(0, eq).trim.toLowerCase
    val allowed = strList(policy.get("content_digest_algorithms")).map(_.toLowerCase).toSet
    if !allowed.contains(algorithm) then return false
    val body = Base64.getDecoder.decode(bodyB64)
    val md = if algorithm == "sha-256" then MessageDigest.getInstance("SHA-256")
             else MessageDigest.getInstance("SHA-512")
    val digest = md.digest(body)
    val expect = s"$algorithm=:${Base64.getEncoder.encodeToString(digest)}:"
    header.trim == expect

  // ================= Rule 5: PS256 (RSASSA-PSS/SHA-256, salt 32) =================
  def ps256Ok(base: Array[Byte], sig: Array[Byte], spkiDer: Array[Byte]): Boolean =
    try
      val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spkiDer))
      val sg = Signature.getInstance("RSASSA-PSS")
      sg.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
      sg.initVerify(key)
      sg.update(base)
      sg.verify(sig)
    catch case _: Exception => false

  // ================= Rule 6: ES256 (ECDSA P-256/SHA-256, raw r||s) =================
  // The signature is a raw 64-byte r||s (IEEE P1363). Under require_low_s a
  // signature with s > n/2 (n from policy.p256_n) is rejected as malleable;
  // otherwise a standard ECDSA verify over the uncompressed public point.
  def es256Ok(base: Array[Byte], sigRaw: Array[Byte], pubUncompressed: Array[Byte],
              requireLowS: Boolean, policy: JsonNode): Boolean =
    try
      if sigRaw.length != 64 then return false
      val s = new BigInteger(1, sigRaw.slice(32, 64))
      if requireLowS then
        val n = new BigInteger(policy.get("p256_n").asText().trim)
        if s.compareTo(n.shiftRight(1)) > 0 then return false
      if pubUncompressed.length != 65 || (pubUncompressed(0) & 0xff) != 0x04 then return false
      val x = new BigInteger(1, pubUncompressed.slice(1, 33))
      val y = new BigInteger(1, pubUncompressed.slice(33, 65))
      val ap = AlgorithmParameters.getInstance("EC")
      ap.init(ECGenParameterSpec("secp256r1"))
      val spec = ap.getParameterSpec(classOf[ECParameterSpec])
      val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
      val v = Signature.getInstance("SHA256withECDSAinP1363Format")
      v.initVerify(key)
      v.update(base)
      v.verify(sigRaw)
    catch case _: Exception => false

  // ================= driver =================
  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else DefaultPath
    val corpus = ObjectMapper().readTree(new File(path))
    val policy = corpus.get("policy")

    val fails = ArrayBuffer[(String, String)]()
    var total = 0
    var matched = 0
    def rec(section: String, n: String, ok: Boolean): Unit =
      total += 1
      if ok then matched += 1 else fails += ((section, n))

    // 1. fapi_signing_base
    corpus.get("fapi_signing_base").elements().asScala.foreach { c =>
      val decoded = new String(Base64.getDecoder.decode(c.get("signing_base_b64").asText()), StandardCharsets.UTF_8)
      val okFlag = c.get("ok").asBoolean()
      val pr = { val p = c.get("signature_params_raw"); if p == null || p.isNull then "" else p.asText() }
      // Build FIRST; guarding on okFlag would skip the build-failure path on
      // negative cases.
      val ok = try
        val built = buildSigningBase(c.get("in"), pr)
        okFlag && built == decoded
      catch case _: Exception => !okFlag
      rec("fapi_signing_base", note(c), ok)
    }

    // 2. fapi_required_coverage
    corpus.get("fapi_required_coverage").elements().asScala.foreach { c =>
      rec("fapi_required_coverage", note(c),
        coverageOk(c.get("message_type").asText(), c.get("covered_components"), policy) == c.get("expect_accept").asBoolean())
    }

    // 3. fapi_content_digest
    corpus.get("fapi_content_digest").elements().asScala.foreach { c =>
      rec("fapi_content_digest", note(c),
        contentDigestOk(c.get("body_b64").asText(), c.get("content_digest").asText(),
          c.get("covered_components"), policy) == c.get("expect_accept").asBoolean())
    }

    // 4. fapi_alg
    corpus.get("fapi_alg").elements().asScala.foreach { c =>
      val allowed = strList(policy.get("allowed_algs")).map(_.toLowerCase).toSet
      rec("fapi_alg", note(c),
        allowed.contains(c.get("alg").asText().toLowerCase) == c.get("expect_accept").asBoolean())
    }

    // 5. fapi_ps256_verify
    corpus.get("fapi_ps256_verify").elements().asScala.foreach { c =>
      val base = Base64.getDecoder.decode(c.get("signing_base_b64").asText())
      val valid = ps256Ok(base, hex(c.get("sig_hex").asText()), hex(c.get("pub_spki_hex").asText()))
      rec("fapi_ps256_verify", note(c), valid == c.get("expect_valid").asBoolean())
    }

    // 6. fapi_es256_verify
    corpus.get("fapi_es256_verify").elements().asScala.foreach { c =>
      val base = Base64.getDecoder.decode(c.get("signing_base_b64").asText())
      val requireLowS = c.hasNonNull("require_low_s") && c.get("require_low_s").asBoolean()
      val valid = es256Ok(base, hex(c.get("sig_raw_hex").asText()), hex(c.get("pub_uncompressed_hex").asText()),
        requireLowS, policy)
      rec("fapi_es256_verify", note(c), valid == c.get("expect_valid").asBoolean())
    }

    fails.foreach { case (s, n) => println(s"FAIL  [$s] $n") }
    println(s"\nscala (fapi): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
