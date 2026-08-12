// Scala/JVM runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Independently reproduces every verdict in the frozen corpus. The PROFILE rules
// (signing base, coverage completeness, freshness window, directory keyid
// resolution, Signature-Agent SSRF, Ed25519 verification) are re-implemented here
// from the corpus `policy` block, NOT imported from the generator's oracle, so a
// runner passing is genuine agreement rather than an echo. This mirrors the
// Python reference runner (runners/python/verify_wba.py), the independent KAT gate
// (tools/check_kat_wba.py) and the go/typescript runners case for case.
//
// JSON via Jackson; Ed25519 verify via Bouncy Castle; IPv4/IPv6 CIDR membership
// by byte-mask over java.net.InetAddress. Same `using` deps as the sibling runner
// (runners/scala/negative_v1.scala).
//
// Run:  scala-cli run --server=false verify_wba.scala -- <corpus path>
// Corpus path: argv[0], else the sibling repo default (runners/scala relative).
// Exit 0 iff every case matches, else 1.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.78.1"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

import java.io.File
import java.net.{InetAddress, URI}
import java.nio.charset.StandardCharsets
import java.util.Base64
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

class SigningBaseError(m: String) extends RuntimeException(m)

object VerifyWba:
  val DefaultPath = "../../corpus/webbotauth_v0/webbotauth_v0.json"

  // -------- generic JSON helpers --------

  // Null-safe string field access, mirroring dict.get(field) returning None.
  def txt(n: JsonNode, field: String): String =
    if n == null then null
    else
      val v = n.get(field)
      if v == null || v.isNull then null else v.asText()

  def note(c: JsonNode): String =
    if c.hasNonNull("note") then c.get("note").asText() else ""

  def hex(s: String): Array[Byte] =
    if s == null || (s.length % 2) != 0 then throw new NumberFormatException("bad hex")
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < s.length do
      out(i / 2) = Integer.parseInt(s.substring(i, i + 2), 16).toByte
      i += 2
    out

  // ================= Rule 1: RFC 9421 Section 2.5 signing base =================
  // Hand-built by direct concatenation. Throws when a covered component's value
  // is missing (build impossible); the driver maps an unbuildable case to !ok.
  def reqStr(in: JsonNode, field: String, msg: String): String =
    val v = in.get(field)
    if v == null || v.isNull then throw new SigningBaseError(msg) else v.asText()

  def buildSigningBase(in: JsonNode, paramsRaw: String): String =
    val lines = ArrayBuffer[String]()
    val cc = in.get("covered_components")
    if cc == null || !cc.isArray then throw new SigningBaseError("no covered_components")
    cc.elements().asScala.foreach { compNode =>
      val name = compNode.asText().toLowerCase
      val value = name match
        case "@authority" => reqStr(in, "authority", "@authority covered but not supplied")
        case "@method"    => reqStr(in, "method", "@method covered but not supplied")
        case "@path"      => reqStr(in, "path", "@path covered but not supplied")
        case _ =>
          val h = in.get("headers")
          if h == null || !h.isObject || h.get(name) == null || h.get(name).isNull then
            throw new SigningBaseError(s"covered header $name not present")
          h.get(name).asText()
      lines += s"\"$name\": $value"
    }
    lines += s"\"@signature-params\": $paramsRaw"
    lines.mkString("\n")

  // ================= Rule 2: coverage completeness =================
  def coverageOk(covered: JsonNode, required: Seq[String]): Boolean =
    val have =
      if covered == null then Set.empty[String]
      else covered.elements().asScala.map(_.asText().toLowerCase).toSet
    required.forall(r => have.contains(r.toLowerCase))

  // ================= Rule 3: freshness window =================
  // All three must be JSON integers; expires > created; (created - skew) <= now < expires.
  def isIntNode(n: JsonNode): Boolean = n != null && n.isIntegralNumber

  def freshnessOk(c: JsonNode, skew: Long): Boolean =
    val cr = c.get("created"); val ex = c.get("expires"); val nw = c.get("now")
    if !(isIntNode(cr) && isIntNode(ex) && isIntNode(nw)) then return false
    val created = cr.asLong(); val expires = ex.asLong(); val now = nw.asLong()
    if expires <= created then return false
    (created - skew) <= now && now < expires

  // ================= Rule 4: directory keyid resolution =================
  def directoryOk(dir: JsonNode, keyid: String): Boolean =
    if dir == null then return false
    val it = dir.elements()
    while it.hasNext do
      val j = it.next()
      if txt(j, "kid") == keyid then
        val x = txt(j, "x")
        return txt(j, "kty") == "OKP" && txt(j, "crv") == "Ed25519" && x != null && x.nonEmpty
    false

  // ================= Rule 5: Signature-Agent SSRF guard =================
  // Strict IPv4 literal parse (no leading zeros, mirroring py3.9+ ipaddress).
  def parseV4(s: String): Array[Byte] =
    val parts = s.split("\\.", -1)
    if parts.length != 4 then return null
    val out = new Array[Byte](4)
    var i = 0
    while i < 4 do
      val p = parts(i)
      if p.isEmpty || p.length > 3 || !p.forall(_.isDigit) then return null
      if p.length > 1 && p(0) == '0' then return null // reject leading zeros
      val n = p.toInt
      if n > 255 then return null
      out(i) = n.toByte
      i += 1
    out

  // Parse an IP LITERAL to its network bytes (4 or 16). Never performs DNS:
  // strings containing ':' are treated as IPv6 literals (InetAddress parses them
  // numerically, never resolving); all others go through the strict IPv4 parser,
  // so a hostname returns null and the caller falls back to resolved_ip.
  def parseIp(s: String): Array[Byte] =
    if s == null || s.isEmpty then null
    else if s.contains(":") then
      try
        val a = InetAddress.getByName(s)
        val b = a.getAddress
        if b.length == 16 then b
        else
          // v4-mapped collapse (e.g. ::ffff:0:0): re-expand to 16 bytes so an
          // IPv6 literal always compares as IPv6.
          val b16 = new Array[Byte](16)
          b16(10) = 0xff.toByte; b16(11) = 0xff.toByte
          System.arraycopy(b, 0, b16, 12, 4)
          b16
      catch case _: Exception => null
    else parseV4(s)

  // Byte-mask CIDR membership. Same width (version) is required by the caller.
  def inNet(addr: Array[Byte], net: Array[Byte], prefix: Int): Boolean =
    if addr.length != net.length then return false
    val bits = addr.length * 8
    if prefix < 0 || prefix > bits then return false
    val fullBytes = prefix / 8
    val rem = prefix % 8
    var i = 0
    while i < fullBytes do
      if addr(i) != net(i) then return false
      i += 1
    if rem > 0 then
      val mask = (0xff << (8 - rem)) & 0xff
      if (addr(fullBytes) & mask) != (net(fullBytes) & mask) then return false
    true

  def ssrfOk(url: String, resolvedIp: String, requireHttps: Boolean, deniedCidrs: Seq[String]): Boolean =
    val uri = try new URI(url) catch case _: Exception => return false
    val scheme = Option(uri.getScheme).map(_.toLowerCase).getOrElse("")
    if requireHttps && scheme != "https" then return false
    val authority = uri.getRawAuthority
    if authority != null && authority.contains("@") then return false // userinfo -> reject
    var host = uri.getHost
    if host == null || host.isEmpty then return false
    if host.startsWith("[") && host.endsWith("]") then host = host.substring(1, host.length - 1)
    var addr = parseIp(host)
    if addr == null then
      // Not an IP literal: fall back to the resolved address.
      if resolvedIp == null || resolvedIp.isEmpty then return false
      addr = parseIp(resolvedIp)
      if addr == null then return false
    for cidr <- deniedCidrs do
      val slash = cidr.lastIndexOf('/')
      if slash > 0 then
        val netBytes = parseIp(cidr.substring(0, slash))
        val prefix = try cidr.substring(slash + 1).toInt catch case _: Exception => -1
        // Same IP version (byte width) only, mirroring the Python reference.
        if netBytes != null && prefix >= 0 && netBytes.length == addr.length && inNet(addr, netBytes, prefix) then
          return false
    true

  // ================= Rule 6: Ed25519 verify (Bouncy Castle) =================
  def ed25519Verify(msg: Array[Byte], sigHex: String, pkHex: String): Boolean =
    try
      val pk = hex(pkHex)
      if pk.length != 32 then false
      else
        val sig = hex(sigHex)
        val signer = new Ed25519Signer()
        signer.init(false, new Ed25519PublicKeyParameters(pk, 0))
        signer.update(msg, 0, msg.length)
        signer.verifySignature(sig)
    catch case _: Exception => false

  // ================= driver =================
  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else DefaultPath
    val corpus = ObjectMapper().readTree(new File(path))
    val policy = corpus.get("policy")

    val required =
      val n = policy.get("required_covered_components")
      if n == null then Seq.empty[String] else n.elements().asScala.map(_.asText()).toSeq
    val skew =
      val n = policy.get("clock_skew_seconds")
      if n != null && n.isIntegralNumber then n.asLong() else 0L
    val ssrf = policy.get("ssrf")
    val requireHttps =
      val n = if ssrf == null then null else ssrf.get("require_https")
      if n != null && n.isBoolean then n.asBoolean() else true
    val deniedCidrs =
      val n = if ssrf == null then null else ssrf.get("denied_cidrs")
      if n == null then Seq.empty[String] else n.elements().asScala.map(_.asText()).toSeq

    val fails = ArrayBuffer[(String, String)]()
    var total = 0
    var matched = 0
    def rec(section: String, n: String, ok: Boolean): Unit =
      total += 1
      if ok then matched += 1 else fails += ((section, n))

    // 1. wba_signing_base
    corpus.get("wba_signing_base").elements().asScala.foreach { c =>
      val decoded = new String(Base64.getDecoder.decode(c.get("signing_base_b64").asText()), StandardCharsets.UTF_8)
      val okFlag = c.get("ok").asBoolean()
      val pr = { val p = txt(c, "signature_params_raw"); if p == null then "" else p }
      // Build FIRST; guarding on okFlag would skip the build-failure path on
      // negative cases.
      val ok = try
        val built = buildSigningBase(c.get("in"), pr)
        okFlag && built == decoded
      catch case _: Exception => !okFlag
      rec("wba_signing_base", note(c), ok)
    }

    // 2. wba_coverage
    corpus.get("wba_coverage").elements().asScala.foreach { c =>
      rec("wba_coverage", note(c), coverageOk(c.get("covered_components"), required) == c.get("expect_accept").asBoolean())
    }

    // 3. wba_freshness
    corpus.get("wba_freshness").elements().asScala.foreach { c =>
      rec("wba_freshness", note(c), freshnessOk(c, skew) == c.get("expect_accept").asBoolean())
    }

    // 4. wba_directory
    corpus.get("wba_directory").elements().asScala.foreach { c =>
      rec("wba_directory", note(c), directoryOk(c.get("directory"), c.get("keyid").asText()) == c.get("expect_accept").asBoolean())
    }

    // 5. wba_directory_ssrf
    corpus.get("wba_directory_ssrf").elements().asScala.foreach { c =>
      val resolved = txt(c, "resolved_ip")
      rec("wba_directory_ssrf", note(c),
        ssrfOk(c.get("signature_agent_url").asText(), resolved, requireHttps, deniedCidrs) == c.get("expect_fetch_allowed").asBoolean())
    }

    // 6. wba_ed25519_verify
    corpus.get("wba_ed25519_verify").elements().asScala.foreach { c =>
      val msg = Base64.getDecoder.decode(c.get("signing_base_b64").asText())
      val valid = ed25519Verify(msg, c.get("sig_hex").asText(), c.get("pk_hex").asText())
      rec("wba_ed25519_verify", note(c), valid == c.get("expect_valid").asBoolean())
    }

    fails.foreach { case (s, n) => println(s"FAIL  [$s] $n") }
    println(s"\nscala (wba): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
