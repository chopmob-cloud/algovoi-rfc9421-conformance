// Scala/JVM runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
// case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
// are equal.
//
// No canonical RFC 8941 library ships for the JVM, so this is a compact
// hand-rolled RFC 8941 parser + canonical serializer, ported from the reference
// tools/oracle_sfv.py. JSON via Jackson (same deps as the sibling scala runner).
// Independence for the profile comes from the five native-library runners
// (typescript/go/rust/ruby/php) and the http_sfv KAT gate.
//
// Run:  scala-cli run --server=false verify_sfv.scala -- <corpus path>
// Corpus path: argv[0], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff all match.

//> using scala "3.8.4"
//> using dep "com.fasterxml.jackson.core:jackson-databind:2.17.0"

import com.fasterxml.jackson.databind.ObjectMapper

import java.io.File
import java.math.BigInteger
import java.util.Base64
import scala.collection.mutable.ArrayBuffer
import scala.jdk.CollectionConverters.*

class SFVError(m: String) extends RuntimeException(m)

final class Bare:
  var kind: String = ""
  var i: Long = 0L
  var dec: String = ""
  var s: String = ""
  var by: Array[Byte] = Array.emptyByteArray
  var b: Boolean = false

final class Param(val key: String, val value: Bare)
final class Member(val bare: Bare, val params: Seq[Param])
final class Node:
  var innerList: Boolean = false
  var bare: Bare = null
  var params: Seq[Param] = Seq.empty
  var members: Seq[Member] = Seq.empty
final class Entry(val key: String, val node: Node)

object VerifySfv:
  val DefaultPath = "../../corpus/sfv_v0/sfv_v0.json"
  val Sections = Seq("sfv_item", "sfv_list", "sfv_dictionary",
    "sfv_parameters", "sfv_canonical", "sfv_reject")

  val IntMin = -999999999999999L
  val IntMax = 999999999999999L

  val Digits = "0123456789"
  val Lcalpha = "abcdefghijklmnopqrstuvwxyz"
  val Ucalpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  val TokenTail = Lcalpha + Ucalpha + Digits + "!#$%&'*+-.^_`|~:/"
  val KeyTail = Lcalpha + Digits + "_-.*"
  val B64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

  def isAlpha(c: Char): Boolean = Lcalpha.indexOf(c) >= 0 || Ucalpha.indexOf(c) >= 0

  final class Parser(text: String):
    for c <- text do if c.toInt > 0x7F then throw SFVError("non-ASCII in field value")
    val s: String = text
    var i: Int = 0

    def eof: Boolean = i >= s.length
    def peek: Int = if eof then -1 else s.charAt(i).toInt

    def discardSp(): Unit = while !eof && s.charAt(i) == ' ' do i += 1
    def discardOws(): Unit = while !eof && (s.charAt(i) == ' ' || s.charAt(i) == '\t') do i += 1

    def bareItem(): Bare =
      if eof then throw SFVError("empty bare item")
      val c = s.charAt(i)
      if c == '-' || Digits.indexOf(c) >= 0 then number()
      else if c == '"' then { val b = Bare(); b.kind = "string"; b.s = parseString(); b }
      else if c == ':' then { val b = Bare(); b.kind = "bytes"; b.by = byteseq(); b }
      else if c == '?' then { val b = Bare(); b.kind = "boolean"; b.b = bool(); b }
      else if c == '*' || isAlpha(c) then { val b = Bare(); b.kind = "token"; b.s = token(); b }
      else throw SFVError("unexpected char starting a bare item")

    def number(): Bare =
      var isDecimal = false
      var sign = 1
      val num = StringBuilder()
      if !eof && s.charAt(i) == '-' then { i += 1; sign = -1 }
      if eof || Digits.indexOf(s.charAt(i)) < 0 then throw SFVError("number with no digits")
      var loop = true
      while loop && !eof do
        val c = s.charAt(i)
        if Digits.indexOf(c) >= 0 then { num.append(c); i += 1 }
        else if !isDecimal && c == '.' then
          if num.length > 12 then throw SFVError("too many integer digits before decimal")
          num.append('.'); isDecimal = true; i += 1
        else loop = false
        if loop then
          if !isDecimal && num.length > 15 then throw SFVError("integer too long")
          if isDecimal && num.length > 16 then throw SFVError("decimal too long")
      if !isDecimal then
        val v = sign * num.toString.toLong
        if v < IntMin || v > IntMax then throw SFVError("integer out of range")
        val b = Bare(); b.kind = "integer"; b.i = v; b
      else
        val t = num.toString
        if t.endsWith(".") then throw SFVError("decimal ends with a dot")
        val dot = t.indexOf('.')
        if t.length - dot - 1 > 3 then throw SFVError("too many fractional digits")
        val b = Bare(); b.kind = "decimal"; b.dec = serDecimal(sign, t.substring(0, dot), t.substring(dot + 1)); b

    def parseString(): String =
      i += 1
      val out = StringBuilder()
      while !eof do
        val c = s.charAt(i); i += 1
        if c == '\\' then
          if eof then throw SFVError("trailing backslash in string")
          val nxt = s.charAt(i); i += 1
          if nxt != '"' && nxt != '\\' then throw SFVError("bad string escape")
          out.append(nxt)
        else if c == '"' then return out.toString
        else if c.toInt < 0x20 || c.toInt > 0x7E then throw SFVError("control char in string")
        else out.append(c)
      throw SFVError("unterminated string")

    def token(): String =
      val start = i; i += 1
      while !eof && TokenTail.indexOf(s.charAt(i)) >= 0 do i += 1
      s.substring(start, i)

    def byteseq(): Array[Byte] =
      i += 1
      val start = i
      while !eof && s.charAt(i) != ':' do
        if B64Alphabet.indexOf(s.charAt(i)) < 0 then throw SFVError("non-base64 char")
        i += 1
      if eof then throw SFVError("unterminated byte sequence")
      val content = s.substring(start, i)
      i += 1
      strictB64Decode(content)

    def bool(): Boolean =
      i += 1
      if !eof && s.charAt(i) == '1' then { i += 1; true }
      else if !eof && s.charAt(i) == '0' then { i += 1; false }
      else throw SFVError("boolean must be ?0 or ?1")

    def key(): String =
      if eof then throw SFVError("key must start with lcalpha or *")
      val c = s.charAt(i)
      if Lcalpha.indexOf(c) < 0 && c != '*' then throw SFVError("key must start with lcalpha or *")
      val start = i; i += 1
      while !eof && KeyTail.indexOf(s.charAt(i)) >= 0 do i += 1
      s.substring(start, i)

    def parameters(): Seq[Param] =
      val ps = ArrayBuffer[Param]()
      while !eof && s.charAt(i) == ';' do
        i += 1
        discardSp()
        val k = key()
        val value: Bare =
          if !eof && s.charAt(i) == '=' then { i += 1; bareItem() }
          else { val b = Bare(); b.kind = "boolean"; b.b = true; b }
        // duplicate key: overwrite value in place, keeping original position.
        val existing = ps.indexWhere(_.key == k)
        if existing >= 0 then ps(existing) = Param(k, value)
        else ps += Param(k, value)
      ps.toSeq

    def item(): Node =
      val n = Node(); n.innerList = false; n.bare = bareItem(); n.params = parameters(); n

    def innerList(): Node =
      i += 1
      val members = ArrayBuffer[Member]()
      while true do
        discardSp()
        if !eof && s.charAt(i) == ')' then
          i += 1
          val n = Node(); n.innerList = true; n.members = members.toSeq; n.params = parameters()
          return n
        if eof then throw SFVError("unterminated inner list")
        val bare = bareItem()
        val ps = parameters()
        members += Member(bare, ps)
        if eof || (s.charAt(i) != ' ' && s.charAt(i) != ')') then
          throw SFVError("inner-list items must be space separated")
      throw SFVError("unreachable")

    def itemOrInnerList(): Node = if !eof && s.charAt(i) == '(' then innerList() else item()

    def parseItem(): Node = { discardSp(); item() }

    def parseList(): Seq[Node] =
      val members = ArrayBuffer[Node]()
      discardSp()
      if eof then return members.toSeq
      while true do
        members += itemOrInnerList()
        discardOws()
        if eof then return members.toSeq
        if s.charAt(i) != ',' then throw SFVError("list members must be comma separated")
        i += 1
        discardOws()
        if eof then throw SFVError("trailing comma in list")
      members.toSeq

    def parseDictionary(): Seq[Entry] =
      val members = ArrayBuffer[Entry]()
      discardSp()
      if eof then return members.toSeq
      while true do
        val k = key()
        val value: Node =
          if !eof && s.charAt(i) == '=' then { i += 1; itemOrInnerList() }
          else
            val ps = parameters()
            val n = Node(); n.innerList = false
            val bb = Bare(); bb.kind = "boolean"; bb.b = true
            n.bare = bb; n.params = ps; n
        // duplicate key: overwrite value in place, keeping original position.
        val existing = members.indexWhere(_.key == k)
        if existing >= 0 then members(existing) = Entry(k, value)
        else members += Entry(k, value)
        discardOws()
        if eof then return members.toSeq
        if s.charAt(i) != ',' then throw SFVError("dictionary members must be comma separated")
        i += 1
        discardOws()
        if eof then throw SFVError("trailing comma in dictionary")
      members.toSeq

  def strictB64Decode(content: String): Array[Byte] =
    if content.length % 4 != 0 then throw SFVError("bad base64 length")
    var pad = 0
    for k <- content.indices do
      val c = content.charAt(k)
      if c == '=' then
        pad += 1
        if k < content.length - 2 then throw SFVError("misplaced padding")
      else
        if pad > 0 then throw SFVError("data after padding")
        if B64Alphabet.indexOf(c) < 0 || c == '=' then throw SFVError("non-base64 char")
    try Base64.getDecoder.decode(content)
    catch case _: IllegalArgumentException => throw SFVError("invalid base64")

  def serDecimal(sign: Int, intpart: String, frac: String): String =
    val frac3 = (frac + "000").substring(0, 3)
    var stripped = frac3
    while stripped.endsWith("0") do stripped = stripped.substring(0, stripped.length - 1)
    if stripped.isEmpty then stripped = "0"
    val whole = BigInteger(if intpart.isEmpty then "0" else intpart)
    if whole.compareTo(BigInteger.TEN.pow(12)) >= 0 then throw SFVError("decimal integer part too large")
    val isZero = whole.signum() == 0 && stripped == "0"
    val neg = if sign < 0 && !isZero then "-" else ""
    neg + whole.toString + "." + stripped

  def serBare(b: Bare): String = b.kind match
    case "integer" =>
      if b.i < IntMin || b.i > IntMax then throw SFVError("integer out of range")
      b.i.toString
    case "decimal" => b.dec
    case "string" =>
      val out = StringBuilder("\"")
      for c <- b.s do
        if c.toInt < 0x20 || c.toInt > 0x7E then throw SFVError("control char in string")
        if c == '"' || c == '\\' then out.append('\\')
        out.append(c)
      out.append('"').toString
    case "token" => b.s
    case "bytes" => ":" + Base64.getEncoder.encodeToString(b.by) + ":"
    case "boolean" => if b.b then "?1" else "?0"
    case _ => throw SFVError("unknown bare kind")

  def isBoolTrue(b: Bare): Boolean = b.kind == "boolean" && b.b

  def serParams(ps: Seq[Param]): String =
    val out = StringBuilder()
    for p <- ps do
      if isBoolTrue(p.value) then out.append(";").append(p.key)
      else out.append(";").append(p.key).append("=").append(serBare(p.value))
    out.toString

  def serMember(node: Node): String =
    if node.innerList then
      val inner = StringBuilder()
      for k <- node.members.indices do
        if k > 0 then inner.append(" ")
        val m = node.members(k)
        inner.append(serBare(m.bare)).append(serParams(m.params))
      "(" + inner.toString + ")" + serParams(node.params)
    else serBare(node.bare) + serParams(node.params)

  def serializeList(members: Seq[Node]): String = members.map(serMember).mkString(", ")

  def serializeDict(members: Seq[Entry]): String =
    val out = StringBuilder()
    for k <- members.indices do
      if k > 0 then out.append(", ")
      val e = members(k)
      if !e.node.innerList && isBoolTrue(e.node.bare) then out.append(e.key).append(serParams(e.node.params))
      else out.append(e.key).append("=").append(serMember(e.node))
    out.toString

  def verdict(fieldType: String, text: String): (Boolean, String) =
    var value: AnyRef = null
    try
      val p = Parser(text)
      value = fieldType match
        case "item" => p.parseItem()
        case "list" => p.parseList()
        case "dictionary" => p.parseDictionary()
        case _ => return (false, null)
      p.discardSp()
      if !p.eof then throw SFVError("trailing characters after value")
    catch case _: SFVError => return (false, null)
    try
      val canon = fieldType match
        case "item" => serMember(value.asInstanceOf[Node])
        case "list" => serializeList(value.asInstanceOf[Seq[Node]])
        case "dictionary" => serializeDict(value.asInstanceOf[Seq[Entry]])
        case _ => throw SFVError("unknown field type")
      (true, canon)
    catch case _: SFVError => (false, null)

  def main(args: Array[String]): Unit =
    val path = if args.nonEmpty then args(0) else DefaultPath
    val corpus = ObjectMapper().readTree(File(path))

    var total = 0
    var matched = 0
    val fails = ArrayBuffer[String]()
    for sec <- Sections do
      val cases = corpus.get(sec)
      if cases != null then
        cases.elements().asScala.foreach { c =>
          val (ok, canon) = verdict(c.get("field_type").asText(), c.get("input").asText())
          val expect = c.get("expect_parse_ok").asBoolean()
          val wantCanon = if c.hasNonNull("canonical") then c.get("canonical").asText() else null
          val m = (ok == expect) && (!ok || canon == wantCanon)
          total += 1
          if m then matched += 1
          else fails += s"[$sec] " + (if c.hasNonNull("note") then c.get("note").asText() else "")
        }
    fails.foreach(f => println(s"FAIL  $f"))
    println(s"\nscala (sfv): $matched/$total cases matched")
    System.exit(if matched == total then 0 else 1)
