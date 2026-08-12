//! Rust runner for the Structured Field Values corpus (sfv_v0).
//!
//! Independently reproduces every verdict in the frozen corpus: parse `input` as
//! its declared field type (item|list|dictionary), and if it parses, serialize it
//! canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
//! case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
//! are equal.
//!
//! This is a compact hand-rolled RFC 8941 parser + canonical serializer, ported
//! from the reference tools/oracle_sfv.py. The `sfv` crate is NOT used because it
//! does not strip trailing decimal zeros (serializes 1.50 as "1.50" rather than
//! "1.5") and it repairs non-canonical base64, neither of which matches the
//! frozen corpus. Independence for the profile comes from the native-library
//! runners (typescript/go/ruby/php) and the http_sfv KAT gate.
//!
//! Corpus path: argv[1], else ../../corpus/sfv_v0/sfv_v0.json (resolved relative
//! to this crate). Exit 0 iff every case matches, else 1.

use base64::Engine;
use serde_json::Value;

type R<T> = Result<T, ()>;

const INT_MIN: i64 = -999_999_999_999_999;
const INT_MAX: i64 = 999_999_999_999_999;

fn is_lcalpha(c: u8) -> bool { c.is_ascii_lowercase() }
fn is_alpha(c: u8) -> bool { c.is_ascii_alphabetic() }
fn is_digit(c: u8) -> bool { c.is_ascii_digit() }
fn is_token_tail(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || b"!#$%&'*+-.^_`|~:/".contains(&c)
}
fn is_key_tail(c: u8) -> bool {
    is_lcalpha(c) || is_digit(c) || b"_-.*".contains(&c)
}
fn is_b64(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == b'+' || c == b'/' || c == b'='
}

#[derive(Clone)]
enum Bare {
    Integer(i64),
    Decimal(String), // already canonical text
    Str(String),
    Token(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

#[derive(Clone)]
struct Param {
    key: String,
    val: Bare,
}

#[derive(Clone)]
struct Member {
    bare: Bare,
    params: Vec<Param>,
}

#[derive(Clone)]
enum Node {
    Item { bare: Bare, params: Vec<Param> },
    Inner { members: Vec<Member>, params: Vec<Param> },
}

struct Entry {
    key: String,
    node: Node,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> R<Parser<'a>> {
        let b = text.as_bytes();
        if b.iter().any(|&c| c > 0x7F) {
            return Err(());
        }
        Ok(Parser { s: b, i: 0 })
    }

    fn eof(&self) -> bool { self.i >= self.s.len() }
    fn peek(&self) -> Option<u8> { if self.eof() { None } else { Some(self.s[self.i]) } }

    fn discard_sp(&mut self) { while !self.eof() && self.s[self.i] == b' ' { self.i += 1; } }
    fn discard_ows(&mut self) {
        while !self.eof() && (self.s[self.i] == b' ' || self.s[self.i] == b'\t') { self.i += 1; }
    }

    fn bare_item(&mut self) -> R<Bare> {
        let c = self.peek().ok_or(())?;
        if c == b'-' || is_digit(c) {
            self.number()
        } else if c == b'"' {
            Ok(Bare::Str(self.parse_string()?))
        } else if c == b':' {
            Ok(Bare::Bytes(self.byteseq()?))
        } else if c == b'?' {
            Ok(Bare::Boolean(self.boolean()?))
        } else if c == b'*' || is_alpha(c) {
            Ok(Bare::Token(self.token()))
        } else {
            Err(())
        }
    }

    fn number(&mut self) -> R<Bare> {
        let mut is_decimal = false;
        let mut sign = 1i64;
        let mut num = String::new();
        if self.peek() == Some(b'-') { self.i += 1; sign = -1; }
        if self.eof() || !is_digit(self.s[self.i]) { return Err(()); }
        loop {
            if self.eof() { break; }
            let c = self.s[self.i];
            if is_digit(c) {
                num.push(c as char);
                self.i += 1;
            } else if !is_decimal && c == b'.' {
                if num.len() > 12 { return Err(()); }
                num.push('.');
                is_decimal = true;
                self.i += 1;
            } else {
                break;
            }
            if !is_decimal && num.len() > 15 { return Err(()); }
            if is_decimal && num.len() > 16 { return Err(()); }
        }
        if !is_decimal {
            let v: i64 = num.parse().map_err(|_| ())?;
            let v = sign * v;
            if v < INT_MIN || v > INT_MAX { return Err(()); }
            Ok(Bare::Integer(v))
        } else {
            if num.ends_with('.') { return Err(()); }
            let dot = num.find('.').unwrap();
            if num.len() - dot - 1 > 3 { return Err(()); }
            Ok(Bare::Decimal(ser_decimal(sign, &num[..dot], &num[dot + 1..])?))
        }
    }

    fn parse_string(&mut self) -> R<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        while !self.eof() {
            let c = self.s[self.i];
            self.i += 1;
            if c == b'\\' {
                if self.eof() { return Err(()); }
                let nxt = self.s[self.i];
                self.i += 1;
                if nxt != b'"' && nxt != b'\\' { return Err(()); }
                out.push(nxt as char);
            } else if c == b'"' {
                return Ok(out);
            } else if c < 0x20 || c > 0x7E {
                return Err(());
            } else {
                out.push(c as char);
            }
        }
        Err(())
    }

    fn token(&mut self) -> String {
        let start = self.i;
        self.i += 1; // first char validated as ALPHA or '*'
        while !self.eof() && is_token_tail(self.s[self.i]) { self.i += 1; }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }

    fn byteseq(&mut self) -> R<Vec<u8>> {
        self.i += 1; // opening ':'
        let start = self.i;
        while !self.eof() && self.s[self.i] != b':' {
            if !is_b64(self.s[self.i]) { return Err(()); }
            self.i += 1;
        }
        if self.eof() { return Err(()); }
        let content = &self.s[start..self.i];
        self.i += 1; // closing ':'
        strict_b64_decode(content)
    }

    fn boolean(&mut self) -> R<bool> {
        self.i += 1; // '?'
        match self.peek() {
            Some(b'1') => { self.i += 1; Ok(true) }
            Some(b'0') => { self.i += 1; Ok(false) }
            _ => Err(()),
        }
    }

    fn key(&mut self) -> R<String> {
        let c = self.peek().ok_or(())?;
        if !is_lcalpha(c) && c != b'*' { return Err(()); }
        let start = self.i;
        self.i += 1;
        while !self.eof() && is_key_tail(self.s[self.i]) { self.i += 1; }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn parameters(&mut self) -> R<Vec<Param>> {
        let mut params: Vec<Param> = Vec::new();
        while self.peek() == Some(b';') {
            self.i += 1;
            self.discard_sp();
            let k = self.key()?;
            let val = if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare_item()?
            } else {
                Bare::Boolean(true)
            };
            if let Some(pos) = params.iter().position(|p| p.key == k) {
                params.remove(pos);
            }
            params.push(Param { key: k, val });
        }
        Ok(params)
    }

    fn item(&mut self) -> R<Node> {
        let bare = self.bare_item()?;
        let params = self.parameters()?;
        Ok(Node::Item { bare, params })
    }

    fn inner_list(&mut self) -> R<Node> {
        self.i += 1; // '('
        let mut members: Vec<Member> = Vec::new();
        loop {
            self.discard_sp();
            if self.peek() == Some(b')') {
                self.i += 1;
                let params = self.parameters()?;
                return Ok(Node::Inner { members, params });
            }
            if self.eof() { return Err(()); }
            let bare = self.bare_item()?;
            let params = self.parameters()?;
            members.push(Member { bare, params });
            match self.peek() {
                Some(b' ') | Some(b')') => {}
                _ => return Err(()),
            }
        }
    }

    fn item_or_inner_list(&mut self) -> R<Node> {
        if self.peek() == Some(b'(') { self.inner_list() } else { self.item() }
    }

    fn parse_list(&mut self) -> R<Vec<Node>> {
        let mut members: Vec<Node> = Vec::new();
        self.discard_sp();
        if self.eof() { return Ok(members); }
        loop {
            members.push(self.item_or_inner_list()?);
            self.discard_ows();
            if self.eof() { return Ok(members); }
            if self.peek() != Some(b',') { return Err(()); }
            self.i += 1;
            self.discard_ows();
            if self.eof() { return Err(()); }
        }
    }

    fn parse_dictionary(&mut self) -> R<Vec<Entry>> {
        let mut members: Vec<Entry> = Vec::new();
        self.discard_sp();
        if self.eof() { return Ok(members); }
        loop {
            let k = self.key()?;
            let node = if self.peek() == Some(b'=') {
                self.i += 1;
                self.item_or_inner_list()?
            } else {
                let params = self.parameters()?;
                Node::Item { bare: Bare::Boolean(true), params }
            };
            if let Some(pos) = members.iter().position(|e| e.key == k) {
                members.remove(pos);
            }
            members.push(Entry { key: k, node });
            self.discard_ows();
            if self.eof() { return Ok(members); }
            if self.peek() != Some(b',') { return Err(()); }
            self.i += 1;
            self.discard_ows();
            if self.eof() { return Err(()); }
        }
    }
}

// strict base64 decode, mirroring python base64.b64decode(validate=True).
fn strict_b64_decode(content: &[u8]) -> R<Vec<u8>> {
    if content.len() % 4 != 0 { return Err(()); }
    let mut pad = 0;
    for (k, &c) in content.iter().enumerate() {
        if c == b'=' {
            pad += 1;
            if k < content.len().saturating_sub(2) { return Err(()); }
        } else {
            if pad > 0 { return Err(()); }
            if !is_b64(c) || c == b'=' { return Err(()); }
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|_| ())
}

fn ser_decimal(sign: i64, intpart: &str, frac: &str) -> R<String> {
    let mut frac3 = String::from(frac);
    while frac3.len() < 3 { frac3.push('0'); }
    frac3.truncate(3);
    let stripped = frac3.trim_end_matches('0');
    let stripped = if stripped.is_empty() { "0" } else { stripped };
    let whole: i128 = if intpart.is_empty() { 0 } else { intpart.parse().map_err(|_| ())? };
    if whole >= 1_000_000_000_000i128 { return Err(()); }
    let is_zero = whole == 0 && stripped == "0";
    let neg = if sign < 0 && !is_zero { "-" } else { "" };
    Ok(format!("{}{}.{}", neg, whole, stripped))
}

fn ser_bare(b: &Bare) -> R<String> {
    match b {
        Bare::Integer(v) => {
            if *v < INT_MIN || *v > INT_MAX { return Err(()); }
            Ok(v.to_string())
        }
        Bare::Decimal(d) => Ok(d.clone()),
        Bare::Str(s) => {
            let mut out = String::from("\"");
            for c in s.bytes() {
                if c < 0x20 || c > 0x7E { return Err(()); }
                if c == b'"' || c == b'\\' { out.push('\\'); }
                out.push(c as char);
            }
            out.push('"');
            Ok(out)
        }
        Bare::Token(t) => Ok(t.clone()),
        Bare::Bytes(v) => Ok(format!(":{}:", base64::engine::general_purpose::STANDARD.encode(v))),
        Bare::Boolean(x) => Ok(if *x { "?1".into() } else { "?0".into() }),
    }
}

fn is_bool_true(b: &Bare) -> bool {
    matches!(b, Bare::Boolean(true))
}

fn ser_params(params: &[Param]) -> R<String> {
    let mut out = String::new();
    for p in params {
        if is_bool_true(&p.val) {
            out.push(';');
            out.push_str(&p.key);
        } else {
            out.push(';');
            out.push_str(&p.key);
            out.push('=');
            out.push_str(&ser_bare(&p.val)?);
        }
    }
    Ok(out)
}

fn ser_member(node: &Node) -> R<String> {
    match node {
        Node::Inner { members, params } => {
            let mut inner = String::new();
            for (k, m) in members.iter().enumerate() {
                if k > 0 { inner.push(' '); }
                inner.push_str(&ser_bare(&m.bare)?);
                inner.push_str(&ser_params(&m.params)?);
            }
            Ok(format!("({}){}", inner, ser_params(params)?))
        }
        Node::Item { bare, params } => Ok(format!("{}{}", ser_bare(bare)?, ser_params(params)?)),
    }
}

fn serialize_list(members: &[Node]) -> R<String> {
    let parts: Result<Vec<String>, ()> = members.iter().map(ser_member).collect();
    Ok(parts?.join(", "))
}

fn serialize_dict(members: &[Entry]) -> R<String> {
    let mut out = String::new();
    for (k, e) in members.iter().enumerate() {
        if k > 0 { out.push_str(", "); }
        match &e.node {
            Node::Item { bare, params } if is_bool_true(bare) => {
                out.push_str(&e.key);
                out.push_str(&ser_params(params)?);
            }
            _ => {
                out.push_str(&e.key);
                out.push('=');
                out.push_str(&ser_member(&e.node)?);
            }
        }
    }
    Ok(out)
}

fn verdict(field_type: &str, text: &str) -> (bool, Option<String>) {
    let parsed: Result<Canon, ()> = (|| {
        let mut p = Parser::new(text)?;
        let canon = match field_type {
            "item" => {
                p.discard_sp();
                let node = p.item()?;
                p.discard_sp();
                if !p.eof() { return Err(()); }
                ser_member(&node)?
            }
            "list" => {
                let nodes = p.parse_list()?;
                p.discard_sp();
                if !p.eof() { return Err(()); }
                serialize_list(&nodes)?
            }
            "dictionary" => {
                let entries = p.parse_dictionary()?;
                p.discard_sp();
                if !p.eof() { return Err(()); }
                serialize_dict(&entries)?
            }
            _ => return Err(()),
        };
        Ok(Canon(canon))
    })();
    match parsed {
        Ok(Canon(c)) => (true, Some(c)),
        Err(()) => (false, None),
    }
}

struct Canon(String);

const SECTIONS: [&str; 6] = [
    "sfv_item", "sfv_list", "sfv_dictionary",
    "sfv_parameters", "sfv_canonical", "sfv_reject",
];

fn default_corpus_path() -> String {
    format!("{}/../../corpus/sfv_v0/sfv_v0.json", env!("CARGO_MANIFEST_DIR"))
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(default_corpus_path);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read corpus {path}: {e}");
            std::process::exit(1);
        }
    };
    let corpus: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot parse corpus {path}: {e}");
            std::process::exit(1);
        }
    };

    let mut total = 0usize;
    let mut matched = 0usize;
    let mut fails: Vec<String> = Vec::new();
    for sec in SECTIONS.iter() {
        if let Some(cases) = corpus[*sec].as_array() {
            for c in cases {
                let ft = c["field_type"].as_str().unwrap_or("");
                let input = c["input"].as_str().unwrap_or("");
                let (ok, canon) = verdict(ft, input);
                let expect = c["expect_parse_ok"].as_bool().unwrap_or(false);
                let want = c["canonical"].as_str();
                let m = (ok == expect) && (!ok || canon.as_deref() == want);
                total += 1;
                if m {
                    matched += 1;
                } else {
                    fails.push(format!("[{}] {}", sec, c["note"].as_str().unwrap_or("")));
                }
            }
        }
    }
    for f in &fails {
        println!("FAIL  {f}");
    }
    println!("\nrust (sfv): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
