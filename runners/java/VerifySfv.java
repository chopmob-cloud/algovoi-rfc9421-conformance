// Java runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: for each case it
// parses `input` as its declared field type (item|list|dictionary) and, if it
// parses, serializes it canonically (RFC 8941 Section 4.1) and compares to the
// frozen `canonical`. A case matches iff parse_ok == expect_parse_ok and, when
// ok, the canonical bytes are equal.
//
// No canonical RFC 8941 library ships for the JDK, so this is a compact
// hand-rolled RFC 8941 parser + canonical serializer, ported line-for-line from
// the reference tools/oracle_sfv.py. JSON via org.json (the same library as the
// sibling java runners). Independence for the profile comes from the five
// native-library runners (typescript/go/rust/ruby/php) and the http_sfv KAT gate.
//
// Corpus path: args[0], else ../../corpus/sfv_v0/sfv_v0.json relative to the
// runner directory (runners/java). Exit 0 iff every case matches, else 1.

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class VerifySfv {

    static final String DEFAULT_PATH = "../../corpus/sfv_v0/sfv_v0.json";
    static final String[] SECTIONS = {
        "sfv_item", "sfv_list", "sfv_dictionary",
        "sfv_parameters", "sfv_canonical", "sfv_reject"
    };

    static final long INT_MIN = -999_999_999_999_999L;
    static final long INT_MAX = 999_999_999_999_999L;

    static final String DIGITS = "0123456789";
    static final String LCALPHA = "abcdefghijklmnopqrstuvwxyz";
    static final String UCALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    // tchar set plus ":" and "/" (RFC 8941 4.2.6).
    static final String TOKEN_TAIL = LCALPHA + UCALPHA + DIGITS + "!#$%&'*+-.^_`|~:/";
    static final String KEY_TAIL = LCALPHA + DIGITS + "_-.*";
    static final String B64_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    static final class SFVError extends RuntimeException {
        SFVError(String m) { super(m); }
    }

    // ---- bare item representation ----
    static final class Bare {
        String kind;      // integer|decimal|string|token|bytes|boolean
        long i;           // integer
        String dec;       // decimal (already canonical text)
        String s;         // string or token value
        byte[] by;        // bytes
        boolean b;        // boolean
    }

    static final class Param {
        String key;
        Bare val;
        Param(String key, Bare val) { this.key = key; this.val = val; }
    }

    // an inner-list member: a bare item with its parameters
    static final class Member {
        Bare bare;
        List<Param> params;
        Member(Bare bare, List<Param> params) { this.bare = bare; this.params = params; }
    }

    // a top-level node: either an item (bare + params) or an inner list.
    static final class Node {
        boolean innerList;
        Bare bare;                 // when item
        List<Param> params;        // item params or inner-list params
        List<Member> members;      // when innerList
    }

    // ================= Parser (RFC 8941 Section 4.2) =================
    static final class Parser {
        final String s;
        int i;

        Parser(String text) {
            for (int k = 0; k < text.length(); k++) {
                if (text.charAt(k) > 0x7F) throw new SFVError("non-ASCII in field value");
            }
            this.s = text;
            this.i = 0;
        }

        boolean eof() { return i >= s.length(); }
        Character peek() { return eof() ? null : s.charAt(i); }

        void discardSp() { while (!eof() && s.charAt(i) == ' ') i++; }
        void discardOws() { while (!eof() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++; }

        Bare bareItem() {
            Character c = peek();
            if (c == null) throw new SFVError("empty bare item");
            if (c == '-' || DIGITS.indexOf(c) >= 0) return number();
            if (c == '"') { Bare b = new Bare(); b.kind = "string"; b.s = parseString(); return b; }
            if (c == ':') { Bare b = new Bare(); b.kind = "bytes"; b.by = byteseq(); return b; }
            if (c == '?') { Bare b = new Bare(); b.kind = "boolean"; b.b = bool(); return b; }
            if (c == '*' || isAlpha(c)) { Bare b = new Bare(); b.kind = "token"; b.s = token(); return b; }
            throw new SFVError("unexpected char starting a bare item");
        }

        boolean isAlpha(char c) {
            return LCALPHA.indexOf(c) >= 0 || UCALPHA.indexOf(c) >= 0;
        }

        Bare number() {
            boolean isDecimal = false;
            int sign = 1;
            StringBuilder num = new StringBuilder();
            if (peek() != null && peek() == '-') { i++; sign = -1; }
            if (eof() || DIGITS.indexOf(s.charAt(i)) < 0) throw new SFVError("number with no digits");
            while (!eof()) {
                char c = s.charAt(i);
                if (DIGITS.indexOf(c) >= 0) { num.append(c); i++; }
                else if (!isDecimal && c == '.') {
                    if (num.length() > 12) throw new SFVError("too many integer digits before decimal");
                    num.append('.'); isDecimal = true; i++;
                } else break;
                if (!isDecimal && num.length() > 15) throw new SFVError("integer too long");
                if (isDecimal && num.length() > 16) throw new SFVError("decimal too long");
            }
            Bare b = new Bare();
            if (!isDecimal) {
                long val = sign * Long.parseLong(num.toString());
                if (val < INT_MIN || val > INT_MAX) throw new SFVError("integer out of range");
                b.kind = "integer"; b.i = val;
                return b;
            }
            String text = num.toString();
            if (text.endsWith(".")) throw new SFVError("decimal ends with a dot");
            int dot = text.indexOf('.');
            if (text.length() - dot - 1 > 3) throw new SFVError("too many fractional digits");
            b.kind = "decimal";
            b.dec = serDecimal(sign, text.substring(0, dot), text.substring(dot + 1));
            return b;
        }

        String parseString() {
            i++; // opening quote
            StringBuilder out = new StringBuilder();
            while (!eof()) {
                char c = s.charAt(i); i++;
                if (c == '\\') {
                    if (eof()) throw new SFVError("trailing backslash in string");
                    char nxt = s.charAt(i); i++;
                    if (nxt != '"' && nxt != '\\') throw new SFVError("bad string escape");
                    out.append(nxt);
                } else if (c == '"') {
                    return out.toString();
                } else if (c < 0x20 || c > 0x7E) {
                    throw new SFVError("control or non-printable char in string");
                } else {
                    out.append(c);
                }
            }
            throw new SFVError("unterminated string");
        }

        String token() {
            int start = i;
            i++; // first char validated as ALPHA or '*'
            while (!eof() && TOKEN_TAIL.indexOf(s.charAt(i)) >= 0) i++;
            return s.substring(start, i);
        }

        byte[] byteseq() {
            i++; // opening ':'
            int start = i;
            while (!eof() && s.charAt(i) != ':') {
                if (B64_ALPHABET.indexOf(s.charAt(i)) < 0) throw new SFVError("non-base64 char");
                i++;
            }
            if (eof()) throw new SFVError("unterminated byte sequence");
            String content = s.substring(start, i);
            i++; // closing ':'
            return strictB64Decode(content);
        }

        boolean bool() {
            i++; // '?'
            Character c = peek();
            if (c != null && c == '1') { i++; return true; }
            if (c != null && c == '0') { i++; return false; }
            throw new SFVError("boolean must be ?0 or ?1");
        }

        String key() {
            Character c = peek();
            if (c == null || (LCALPHA.indexOf(c) < 0 && c != '*'))
                throw new SFVError("key must start with lcalpha or *");
            int start = i; i++;
            while (!eof() && KEY_TAIL.indexOf(s.charAt(i)) >= 0) i++;
            return s.substring(start, i);
        }

        List<Param> parameters() {
            List<Param> params = new ArrayList<>();
            while (peek() != null && peek() == ';') {
                i++;
                discardSp();
                String k = key();
                Bare value;
                if (peek() != null && peek() == '=') {
                    i++;
                    value = bareItem();
                } else {
                    value = new Bare(); value.kind = "boolean"; value.b = true;
                }
                // duplicate key: overwrite value in place, keeping original position.
                int existing = -1;
                for (int idx = 0; idx < params.size(); idx++) {
                    if (params.get(idx).key.equals(k)) { existing = idx; break; }
                }
                if (existing >= 0) params.set(existing, new Param(k, value));
                else params.add(new Param(k, value));
            }
            return params;
        }

        Node item() {
            Node n = new Node();
            n.innerList = false;
            n.bare = bareItem();
            n.params = parameters();
            return n;
        }

        Node innerList() {
            i++; // '('
            List<Member> members = new ArrayList<>();
            while (true) {
                discardSp();
                if (peek() != null && peek() == ')') {
                    i++;
                    Node n = new Node();
                    n.innerList = true;
                    n.members = members;
                    n.params = parameters();
                    return n;
                }
                if (eof()) throw new SFVError("unterminated inner list");
                Bare bare = bareItem();
                List<Param> ps = parameters();
                members.add(new Member(bare, ps));
                Character c = peek();
                if (c == null || (c != ' ' && c != ')'))
                    throw new SFVError("inner-list items must be space separated");
            }
        }

        Node itemOrInnerList() {
            if (peek() != null && peek() == '(') return innerList();
            return item();
        }

        List<Node> parseList() {
            List<Node> members = new ArrayList<>();
            discardSp();
            if (eof()) return members;
            while (true) {
                members.add(itemOrInnerList());
                discardOws();
                if (eof()) return members;
                if (peek() != ',') throw new SFVError("list members must be comma separated");
                i++;
                discardOws();
                if (eof()) throw new SFVError("trailing comma in list");
            }
        }

        // dictionary entry: key + node
        static final class Entry { String key; Node node; Entry(String k, Node n) { key = k; node = n; } }

        List<Entry> parseDictionary() {
            List<Entry> members = new ArrayList<>();
            discardSp();
            if (eof()) return members;
            while (true) {
                String k = key();
                Node value;
                if (peek() != null && peek() == '=') {
                    i++;
                    value = itemOrInnerList();
                } else {
                    List<Param> ps = parameters();
                    value = new Node();
                    value.innerList = false;
                    value.bare = new Bare();
                    value.bare.kind = "boolean";
                    value.bare.b = true;
                    value.params = ps;
                }
                // duplicate key: overwrite value in place, keeping original position.
                int existing = -1;
                for (int idx = 0; idx < members.size(); idx++) {
                    if (members.get(idx).key.equals(k)) { existing = idx; break; }
                }
                if (existing >= 0) members.set(existing, new Entry(k, value));
                else members.add(new Entry(k, value));
                discardOws();
                if (eof()) return members;
                if (peek() != ',') throw new SFVError("dictionary members must be comma separated");
                i++;
                discardOws();
                if (eof()) throw new SFVError("trailing comma in dictionary");
            }
        }
    }

    // ---- strict base64 (mirrors python base64.b64decode(validate=True)) ----
    static byte[] strictB64Decode(String content) {
        if (content.length() % 4 != 0) throw new SFVError("bad base64 length");
        int pad = 0;
        for (int k = 0; k < content.length(); k++) {
            char c = content.charAt(k);
            if (c == '=') {
                pad++;
                if (k < content.length() - 2) throw new SFVError("misplaced padding");
            } else {
                if (pad > 0) throw new SFVError("data after padding");
                if (B64_ALPHABET.indexOf(c) < 0 || c == '=') throw new SFVError("non-base64 char");
            }
        }
        try {
            return Base64.getDecoder().decode(content);
        } catch (IllegalArgumentException e) {
            throw new SFVError("invalid base64");
        }
    }

    // ================= Canonical serialization (Section 4.1) =================
    static String serDecimal(int sign, String intpart, String frac) {
        // frac has at most 3 digits (enforced at parse). Quantize to 3 (pad right),
        // strip trailing zeros, keep at least one fractional digit.
        String frac3 = (frac + "000").substring(0, 3);
        String stripped = frac3;
        while (stripped.endsWith("0")) stripped = stripped.substring(0, stripped.length() - 1);
        if (stripped.isEmpty()) stripped = "0";
        // normalize integer part (strip leading zeros)
        java.math.BigInteger whole = new java.math.BigInteger(intpart.isEmpty() ? "0" : intpart);
        if (whole.compareTo(java.math.BigInteger.TEN.pow(12)) >= 0)
            throw new SFVError("decimal integer part too large");
        boolean isZero = whole.signum() == 0 && stripped.equals("0");
        String neg = (sign < 0 && !isZero) ? "-" : "";
        return neg + whole.toString() + "." + stripped;
    }

    static String serBare(Bare b) {
        switch (b.kind) {
            case "integer":
                if (b.i < INT_MIN || b.i > INT_MAX) throw new SFVError("integer out of range");
                return Long.toString(b.i);
            case "decimal":
                return b.dec;
            case "string": {
                StringBuilder out = new StringBuilder("\"");
                for (int k = 0; k < b.s.length(); k++) {
                    char c = b.s.charAt(k);
                    if (c < 0x20 || c > 0x7E) throw new SFVError("control char in string");
                    if (c == '"' || c == '\\') out.append('\\');
                    out.append(c);
                }
                out.append('"');
                return out.toString();
            }
            case "token":
                return b.s;
            case "bytes":
                return ":" + Base64.getEncoder().encodeToString(b.by) + ":";
            case "boolean":
                return b.b ? "?1" : "?0";
            default:
                throw new SFVError("unknown bare kind");
        }
    }

    static boolean isBoolTrue(Bare b) {
        return "boolean".equals(b.kind) && b.b;
    }

    static String serParams(List<Param> params) {
        StringBuilder out = new StringBuilder();
        for (Param p : params) {
            if (isBoolTrue(p.val)) out.append(";").append(p.key);
            else out.append(";").append(p.key).append("=").append(serBare(p.val));
        }
        return out.toString();
    }

    static String serMember(Node node) {
        if (node.innerList) {
            StringBuilder inner = new StringBuilder();
            for (int k = 0; k < node.members.size(); k++) {
                if (k > 0) inner.append(" ");
                Member m = node.members.get(k);
                inner.append(serBare(m.bare)).append(serParams(m.params));
            }
            return "(" + inner + ")" + serParams(node.params);
        }
        return serBare(node.bare) + serParams(node.params);
    }

    static String serialize(String fieldType, Object value) {
        if (fieldType.equals("item")) {
            return serMember((Node) value);
        }
        if (fieldType.equals("list")) {
            @SuppressWarnings("unchecked")
            List<Node> members = (List<Node>) value;
            StringBuilder out = new StringBuilder();
            for (int k = 0; k < members.size(); k++) {
                if (k > 0) out.append(", ");
                out.append(serMember(members.get(k)));
            }
            return out.toString();
        }
        if (fieldType.equals("dictionary")) {
            @SuppressWarnings("unchecked")
            List<Parser.Entry> members = (List<Parser.Entry>) value;
            StringBuilder out = new StringBuilder();
            for (int k = 0; k < members.size(); k++) {
                if (k > 0) out.append(", ");
                Parser.Entry e = members.get(k);
                if (!e.node.innerList && isBoolTrue(e.node.bare)) {
                    out.append(e.key).append(serParams(e.node.params));
                } else {
                    out.append(e.key).append("=").append(serMember(e.node));
                }
            }
            return out.toString();
        }
        throw new SFVError("unknown field type");
    }

    // ================= verdict =================
    static String[] verdict(String fieldType, String text) {
        Object value;
        try {
            Parser p = new Parser(text);
            if (fieldType.equals("item")) {
                p.discardSp();
                value = p.item();
            } else if (fieldType.equals("list")) {
                value = p.parseList();
            } else if (fieldType.equals("dictionary")) {
                value = p.parseDictionary();
            } else {
                return new String[]{"reject", null};
            }
            p.discardSp();
            if (!p.eof()) throw new SFVError("trailing characters after value");
        } catch (SFVError e) {
            return new String[]{"reject", null};
        }
        try {
            return new String[]{"ok", serialize(fieldType, value)};
        } catch (SFVError e) {
            return new String[]{"reject", null};
        }
    }

    // ================= driver =================
    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : DEFAULT_PATH;
        String content = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        JSONObject corpus = new JSONObject(content);

        int total = 0, matched = 0;
        List<String> fails = new ArrayList<>();
        for (String sec : SECTIONS) {
            JSONArray cases = corpus.optJSONArray(sec);
            if (cases == null) continue;
            for (int idx = 0; idx < cases.length(); idx++) {
                JSONObject c = cases.getJSONObject(idx);
                String[] v = verdict(c.getString("field_type"), c.getString("input"));
                boolean ok = v[0].equals("ok");
                boolean expect = c.getBoolean("expect_parse_ok");
                boolean match = (ok == expect)
                    && (!ok || v[1].equals(c.optString("canonical", null)));
                total++;
                if (match) matched++;
                else fails.add("[" + sec + "] " + c.optString("note", ""));
            }
        }
        for (String f : fails) System.out.println("FAIL  " + f);
        System.out.println("\njava (sfv): " + matched + "/" + total + " cases matched");
        System.exit(matched == total ? 0 : 1);
    }
}
