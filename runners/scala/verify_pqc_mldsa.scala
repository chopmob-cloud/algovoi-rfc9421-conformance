// Scala/JVM runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
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
//
// Run:  scala-cli run --server=false verify_pqc_mldsa.scala -- <corpus path>
// Corpus path: argv[0], else $ALGOVOI_PQC_MLDSA, else the sibling repo default.
// Exit 0 iff every case matches.

//> using scala "3.8.4"
//> using dep "org.bouncycastle:bcprov-jdk18on:1.81"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import org.bouncycastle.pqc.crypto.mldsa.{MLDSAParameters, MLDSAPublicKeyParameters, MLDSASigner}

import java.io.File
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

object VerifyPqcMldsa:
  val DefaultPath = "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json"
  val Mapper = ObjectMapper()
  val Sections = Seq("mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat")
  val PkLen = 1952
  val SigLen = 3309

  def hex(s: String): Array[Byte] =
    if s == null || s.length % 2 != 0 then null
    else
      val o = new Array[Byte](s.length / 2)
      var i = 0
      var ok = true
      while i < o.length && ok do
        val hi = Character.digit(s.charAt(2 * i), 16)
        val lo = Character.digit(s.charAt(2 * i + 1), 16)
        if hi < 0 || lo < 0 then ok = false else o(i) = ((hi << 4) | lo).toByte
        i += 1
      if ok then o else null

  def verdict(pkHex: String, msgHex: String, sigHex: String): Boolean =
    val pk = hex(pkHex)
    val msg = hex(msgHex)
    val sig = hex(sigHex)
    if pk == null || msg == null || sig == null then false
    else if pk.length != PkLen || sig.length != SigLen then false
    else
      try
        val pub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk)
        val s = new MLDSASigner()
        s.init(false, pub)
        s.update(msg, 0, msg.length)
        s.verifySignature(sig)
      catch case _: Throwable => false

  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else Option(System.getenv("ALGOVOI_PQC_MLDSA")).getOrElse(DefaultPath)
    val corpus = Mapper.readTree(new File(path))

    val fails = ArrayBuffer[String]()
    var total = 0
    var matched = 0
    for sec <- Sections do
      val arr = corpus.get(sec)
      if arr != null then
        arr.elements().asScala.foreach { c =>
          val accept = verdict(
            c.get("public_key").asText(),
            c.get("message").asText(),
            c.get("signature").asText()
          )
          total += 1
          val note = if c.hasNonNull("note") then c.get("note").asText() else ""
          if accept == c.get("expect_valid").asBoolean() then matched += 1
          else fails += s"[$sec] $note"
        }
    fails.foreach(f => println(s"FAIL  $f"))
    println(s"\nscala (pqc_mldsa): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
