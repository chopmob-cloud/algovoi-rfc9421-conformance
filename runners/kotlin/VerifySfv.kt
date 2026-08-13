// Kotlin runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
// case matches iff parse_ok == expect_parse_ok and, when ok, canonical bytes are
// equal.
//
// No canonical RFC 8941 library ships for the JVM, so this is a compact
// hand-rolled RFC 8941 parser + canonical serializer, ported from the reference
// tools/oracle_sfv.py. JSON via Jackson (the same jars as the sibling kotlin
// runners). Independence for the profile comes from the five native-library
// runners (typescript/go/rust/ruby/php) and the http_sfv KAT gate.
//
// Corpus path: argv[0], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff every
// case matches.

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File
import java.math.BigInteger
import java.util.Base64
import kotlin.system.exitProcess

private const val DEFAULT_PATH = "../../corpus/sfv_v0/sfv_v0.json"
private val SECTIONS = listOf(
    "sfv_item", "sfv_list", "sfv_dictionary",
    "sfv_parameters", "sfv_canonical", "sfv_reject"
)

private const val INT_MIN = -999_999_999_999_999L
private const val INT_MAX = 999_999_999_999_999L

private const val DIGITS = "0123456789"
private const val LCALPHA = "abcdefghijklmnopqrstuvwxyz"
private const val UCALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
private const val TOKEN_TAIL = LCALPHA + UCALPHA + DIGITS + "!#$%&'*+-.^_`|~:/"
private const val KEY_TAIL = LCALPHA + DIGITS + "_-.*"
private const val B64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

private class SFVError(m: String) : RuntimeException(m)

private class Bare {
    var kind: String = ""     // integer|decimal|string|token|bytes|boolean
    var i: Long = 0
    var dec: String = ""
    var s: String = ""
    var by: ByteArray = ByteArray(0)
    var b: Boolean = false
}

private class Param(val key: String, val value: Bare)
private class Member(val bare: Bare, val params: List<Param>)
private class Node {
    var innerList = false
    var bare: Bare? = null
    var params: List<Param> = emptyList()
    var members: List<Member> = emptyList()
}
private class Entry(val key: String, val node: Node)

private fun isAlpha(c: Char) = LCALPHA.indexOf(c) >= 0 || UCALPHA.indexOf(c) >= 0

private class Parser(text: String) {
    private val s: String
    var i = 0

    init {
        for (c in text) if (c.code > 0x7F) throw SFVError("non-ASCII in field value")
        s = text
    }

    fun eof() = i >= s.length
    private fun peek(): Char? = if (eof()) null else s[i]

    fun discardSp() { while (!eof() && s[i] == ' ') i++ }
    private fun discardOws() { while (!eof() && (s[i] == ' ' || s[i] == '\t')) i++ }

    private fun bareItem(): Bare {
        val c = peek() ?: throw SFVError("empty bare item")
        if (c == '-' || DIGITS.indexOf(c) >= 0) return number()
        if (c == '"') return Bare().apply { kind = "string"; s = parseString() }
        if (c == ':') return Bare().apply { kind = "bytes"; by = byteseq() }
        if (c == '?') return Bare().apply { kind = "boolean"; b = bool() }
        if (c == '*' || isAlpha(c)) return Bare().apply { kind = "token"; s = token() }
        throw SFVError("unexpected char starting a bare item")
    }

    private fun number(): Bare {
        var isDecimal = false
        var sign = 1
        val num = StringBuilder()
        if (peek() == '-') { i++; sign = -1 }
        if (eof() || DIGITS.indexOf(s[i]) < 0) throw SFVError("number with no digits")
        while (!eof()) {
            val c = s[i]
            if (DIGITS.indexOf(c) >= 0) { num.append(c); i++ }
            else if (!isDecimal && c == '.') {
                if (num.length > 12) throw SFVError("too many integer digits before decimal")
                num.append('.'); isDecimal = true; i++
            } else break
            if (!isDecimal && num.length > 15) throw SFVError("integer too long")
            if (isDecimal && num.length > 16) throw SFVError("decimal too long")
        }
        if (!isDecimal) {
            val v = sign * num.toString().toLong()
            if (v < INT_MIN || v > INT_MAX) throw SFVError("integer out of range")
            return Bare().apply { kind = "integer"; i = v }
        }
        val text = num.toString()
        if (text.endsWith(".")) throw SFVError("decimal ends with a dot")
        val dot = text.indexOf('.')
        if (text.length - dot - 1 > 3) throw SFVError("too many fractional digits")
        return Bare().apply { kind = "decimal"; dec = serDecimal(sign, text.substring(0, dot), text.substring(dot + 1)) }
    }

    private fun parseString(): String {
        i++
        val out = StringBuilder()
        while (!eof()) {
            val c = s[i]; i++
            if (c == '\\') {
                if (eof()) throw SFVError("trailing backslash in string")
                val nxt = s[i]; i++
                if (nxt != '"' && nxt != '\\') throw SFVError("bad string escape")
                out.append(nxt)
            } else if (c == '"') return out.toString()
            else if (c.code < 0x20 || c.code > 0x7E) throw SFVError("control char in string")
            else out.append(c)
        }
        throw SFVError("unterminated string")
    }

    private fun token(): String {
        val start = i; i++
        while (!eof() && TOKEN_TAIL.indexOf(s[i]) >= 0) i++
        return s.substring(start, i)
    }

    private fun byteseq(): ByteArray {
        i++
        val start = i
        while (!eof() && s[i] != ':') {
            if (B64_ALPHABET.indexOf(s[i]) < 0) throw SFVError("non-base64 char")
            i++
        }
        if (eof()) throw SFVError("unterminated byte sequence")
        val content = s.substring(start, i)
        i++
        return strictB64Decode(content)
    }

    private fun bool(): Boolean {
        i++
        val c = peek()
        if (c == '1') { i++; return true }
        if (c == '0') { i++; return false }
        throw SFVError("boolean must be ?0 or ?1")
    }

    private fun key(): String {
        val c = peek()
        if (c == null || (LCALPHA.indexOf(c) < 0 && c != '*')) throw SFVError("key must start with lcalpha or *")
        val start = i; i++
        while (!eof() && KEY_TAIL.indexOf(s[i]) >= 0) i++
        return s.substring(start, i)
    }

    private fun parameters(): List<Param> {
        val ps = ArrayList<Param>()
        while (peek() == ';') {
            i++
            discardSp()
            val k = key()
            val value: Bare = if (peek() == '=') { i++; bareItem() }
                else Bare().apply { kind = "boolean"; b = true }
            // duplicate key: overwrite value in place, keeping original position.
            val existing = ps.indexOfFirst { it.key == k }
            if (existing >= 0) ps[existing] = Param(k, value)
            else ps.add(Param(k, value))
        }
        return ps
    }

    private fun item(): Node = Node().apply { innerList = false; bare = bareItem(); params = parameters() }

    private fun innerList(): Node {
        i++
        val members = ArrayList<Member>()
        while (true) {
            discardSp()
            if (peek() == ')') {
                i++
                return Node().apply { innerList = true; this.members = members; params = parameters() }
            }
            if (eof()) throw SFVError("unterminated inner list")
            val bare = bareItem()
            val ps = parameters()
            members.add(Member(bare, ps))
            val c = peek()
            if (c == null || (c != ' ' && c != ')')) throw SFVError("inner-list items must be space separated")
        }
    }

    private fun itemOrInnerList(): Node = if (peek() == '(') innerList() else item()

    fun parseItem(): Node { discardSp(); return item() }

    fun parseList(): List<Node> {
        val members = ArrayList<Node>()
        discardSp()
        if (eof()) return members
        while (true) {
            members.add(itemOrInnerList())
            discardOws()
            if (eof()) return members
            if (peek() != ',') throw SFVError("list members must be comma separated")
            i++
            discardOws()
            if (eof()) throw SFVError("trailing comma in list")
        }
    }

    fun parseDictionary(): List<Entry> {
        val members = ArrayList<Entry>()
        discardSp()
        if (eof()) return members
        while (true) {
            val k = key()
            val value: Node = if (peek() == '=') { i++; itemOrInnerList() }
                else Node().apply {
                    innerList = false
                    bare = Bare().apply { kind = "boolean"; b = true }
                    params = parameters()
                }
            // duplicate key: overwrite value in place, keeping original position.
            val existing = members.indexOfFirst { it.key == k }
            if (existing >= 0) members[existing] = Entry(k, value)
            else members.add(Entry(k, value))
            discardOws()
            if (eof()) return members
            if (peek() != ',') throw SFVError("dictionary members must be comma separated")
            i++
            discardOws()
            if (eof()) throw SFVError("trailing comma in dictionary")
        }
    }
}

private fun strictB64Decode(content: String): ByteArray {
    if (content.length % 4 != 0) throw SFVError("bad base64 length")
    var pad = 0
    for (k in content.indices) {
        val c = content[k]
        if (c == '=') {
            pad++
            if (k < content.length - 2) throw SFVError("misplaced padding")
        } else {
            if (pad > 0) throw SFVError("data after padding")
            if (B64_ALPHABET.indexOf(c) < 0 || c == '=') throw SFVError("non-base64 char")
        }
    }
    return try { Base64.getDecoder().decode(content) } catch (e: IllegalArgumentException) { throw SFVError("invalid base64") }
}

private fun serDecimal(sign: Int, intpart: String, frac: String): String {
    val frac3 = (frac + "000").substring(0, 3)
    var stripped = frac3.trimEnd('0')
    if (stripped.isEmpty()) stripped = "0"
    val whole = BigInteger(if (intpart.isEmpty()) "0" else intpart)
    if (whole >= BigInteger.TEN.pow(12)) throw SFVError("decimal integer part too large")
    val isZero = whole.signum() == 0 && stripped == "0"
    val neg = if (sign < 0 && !isZero) "-" else ""
    return neg + whole.toString() + "." + stripped
}

private fun serBare(b: Bare): String = when (b.kind) {
    "integer" -> {
        if (b.i < INT_MIN || b.i > INT_MAX) throw SFVError("integer out of range")
        b.i.toString()
    }
    "decimal" -> b.dec
    "string" -> {
        val out = StringBuilder("\"")
        for (c in b.s) {
            if (c.code < 0x20 || c.code > 0x7E) throw SFVError("control char in string")
            if (c == '"' || c == '\\') out.append('\\')
            out.append(c)
        }
        out.append('"').toString()
    }
    "token" -> b.s
    "bytes" -> ":" + Base64.getEncoder().encodeToString(b.by) + ":"
    "boolean" -> if (b.b) "?1" else "?0"
    else -> throw SFVError("unknown bare kind")
}

private fun isBoolTrue(b: Bare) = b.kind == "boolean" && b.b

private fun serParams(ps: List<Param>): String {
    val out = StringBuilder()
    for (p in ps) {
        if (isBoolTrue(p.value)) out.append(";").append(p.key)
        else out.append(";").append(p.key).append("=").append(serBare(p.value))
    }
    return out.toString()
}

private fun serMember(node: Node): String {
    if (node.innerList) {
        val inner = StringBuilder()
        for (k in node.members.indices) {
            if (k > 0) inner.append(" ")
            val m = node.members[k]
            inner.append(serBare(m.bare)).append(serParams(m.params))
        }
        return "(" + inner + ")" + serParams(node.params)
    }
    return serBare(node.bare!!) + serParams(node.params)
}

private fun serializeList(members: List<Node>): String =
    members.joinToString(", ") { serMember(it) }

private fun serializeDict(members: List<Entry>): String {
    val out = StringBuilder()
    for (k in members.indices) {
        if (k > 0) out.append(", ")
        val e = members[k]
        if (!e.node.innerList && isBoolTrue(e.node.bare!!)) out.append(e.key).append(serParams(e.node.params))
        else out.append(e.key).append("=").append(serMember(e.node))
    }
    return out.toString()
}

private fun verdict(fieldType: String, text: String): Pair<Boolean, String?> {
    val value: Any
    try {
        val p = Parser(text)
        value = when (fieldType) {
            "item" -> p.parseItem()
            "list" -> p.parseList()
            "dictionary" -> p.parseDictionary()
            else -> return Pair(false, null)
        }
        p.discardSp()
        if (!p.eof()) throw SFVError("trailing characters after value")
    } catch (e: SFVError) {
        return Pair(false, null)
    }
    return try {
        @Suppress("UNCHECKED_CAST")
        val canon = when (fieldType) {
            "item" -> serMember(value as Node)
            "list" -> serializeList(value as List<Node>)
            "dictionary" -> serializeDict(value as List<Entry>)
            else -> throw SFVError("unknown field type")
        }
        Pair(true, canon)
    } catch (e: SFVError) {
        Pair(false, null)
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else DEFAULT_PATH
    val corpus = ObjectMapper().readTree(File(path))

    var total = 0
    var matched = 0
    val fails = ArrayList<String>()
    for (sec in SECTIONS) {
        val cases = corpus.get(sec) ?: continue
        for (c in cases) {
            val (ok, canon) = verdict(c.get("field_type").asText(), c.get("input").asText())
            val expect = c.get("expect_parse_ok").asBoolean()
            val wantCanon = if (c.hasNonNull("canonical")) c.get("canonical").asText() else null
            val match = (ok == expect) && (!ok || canon == wantCanon)
            total++
            if (match) matched++
            else fails.add("[$sec] " + if (c.hasNonNull("note")) c.get("note").asText() else "")
        }
    }
    fails.forEach { println("FAIL  $it") }
    println("\nkotlin (sfv): $matched/$total cases matched")
    exitProcess(if (matched == total) 0 else 1)
}
