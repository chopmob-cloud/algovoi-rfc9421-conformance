//! Rust runner for the COSE_Sign1 corpus (cose_v0).
//!
//! Independently reproduces every verdict in the frozen corpus, mirroring the Python
//! reference runner (runners/python/verify_cose.py) and its decision surface
//! (tools/oracle_cose.py) case for case. Parses each COSE_Sign1 (CBOR array of 4,
//! tagged 18 or untagged), applies the COSE security gates in order (protected header
//! deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in the
//! protected header, an unknown crit (label 2) label rejected, alg/key-type match),
//! builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
//! CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
//! section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is
//! NOT enforced (a COSE base rule, not a FAPI rule).
//!
//! The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
//! canonical encoder) so the deterministic judgement and the Sig_structure bytes are
//! byte-identical to the frozen corpus, independent of any CBOR library's default
//! map-key ordering (bytewise-lexicographic, not length-first).
//!
//! PS256 with the `rsa` crate (Pss), ES256 with `p256` (from_sec1_bytes rejects an
//! off-curve point), EdDSA with `ed25519-dalek`.
//!
//! Corpus path: argv[1], else the frozen repo corpus. Exits 0 iff every case matched.

use serde_json::Value;

fn default_corpus_path() -> String {
    format!("{}/../../corpus/cose_v0/cose_v0.json", env!("CARGO_MANIFEST_DIR"))
}

const SECTIONS: [&str; 7] = [
    "cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
    "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit",
];

const COSE_SIGN1_TAG: u64 = 18;

fn alg_kty(alg: i64) -> Option<&'static str> {
    match alg {
        -7 => Some("EC2"),
        -8 => Some("OKP"),
        -37 => Some("RSA"),
        _ => None,
    }
}

fn known_label(l: i64) -> bool {
    (1..=5).contains(&l)
}

fn hexb(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < b.len() {
        out.push((hv(b[i])? << 4) | hv(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Cval {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cval>),
    Map(Vec<(Cval, Cval)>),
    Null,
    Tag(u64, Box<Cval>),
    Bool(bool),
}

fn decode(buf: &[u8], pos: usize) -> Option<(Cval, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let ib = buf[pos];
    let mut pos = pos + 1;
    let major = ib >> 5;
    let ai = ib & 0x1f;
    let arg: u64;
    if ai < 24 {
        arg = ai as u64;
    } else if ai == 24 {
        if pos + 1 > buf.len() {
            return None;
        }
        arg = buf[pos] as u64;
        pos += 1;
    } else if ai == 25 {
        if pos + 2 > buf.len() {
            return None;
        }
        arg = (buf[pos] as u64) << 8 | buf[pos + 1] as u64;
        pos += 2;
    } else if ai == 26 {
        if pos + 4 > buf.len() {
            return None;
        }
        let mut a = 0u64;
        for i in 0..4 {
            a = a << 8 | buf[pos + i] as u64;
        }
        arg = a;
        pos += 4;
    } else if ai == 27 {
        if pos + 8 > buf.len() {
            return None;
        }
        let mut a = 0u64;
        for i in 0..8 {
            a = a << 8 | buf[pos + i] as u64;
        }
        arg = a;
        pos += 8;
    } else if ai == 31 {
        if major < 2 || major > 5 {
            return None;
        }
        return decode_indefinite(buf, pos, major);
    } else {
        return None;
    }

    match major {
        0 => Some((Cval::Int(arg as i64), pos)),
        1 => Some((Cval::Int(-1 - arg as i64), pos)),
        2 => {
            let end = pos.checked_add(arg as usize)?;
            if end > buf.len() {
                return None;
            }
            Some((Cval::Bytes(buf[pos..end].to_vec()), end))
        }
        3 => {
            let end = pos.checked_add(arg as usize)?;
            if end > buf.len() {
                return None;
            }
            let s = std::str::from_utf8(&buf[pos..end]).ok()?.to_string();
            Some((Cval::Text(s), end))
        }
        4 => {
            let mut items = Vec::new();
            for _ in 0..arg {
                let (v, np) = decode(buf, pos)?;
                items.push(v);
                pos = np;
            }
            Some((Cval::Array(items), pos))
        }
        5 => {
            let mut pairs = Vec::new();
            for _ in 0..arg {
                let (k, p1) = decode(buf, pos)?;
                let (v, p2) = decode(buf, p1)?;
                pairs.push((k, v));
                pos = p2;
            }
            Some((Cval::Map(pairs), pos))
        }
        6 => {
            let (inner, np) = decode(buf, pos)?;
            Some((Cval::Tag(arg, Box::new(inner)), np))
        }
        7 => match ai {
            22 => Some((Cval::Null, pos)),
            20 => Some((Cval::Bool(false), pos)),
            21 => Some((Cval::Bool(true), pos)),
            _ => None,
        },
        _ => None,
    }
}

fn decode_indefinite(buf: &[u8], mut pos: usize, major: u8) -> Option<(Cval, usize)> {
    if major == 2 || major == 3 {
        let mut acc: Vec<u8> = Vec::new();
        loop {
            if pos >= buf.len() {
                return None;
            }
            if buf[pos] == 0xff {
                pos += 1;
                break;
            }
            let (chunk, np) = decode(buf, pos)?;
            match (&chunk, major) {
                (Cval::Bytes(b), 2) => acc.extend_from_slice(b),
                (Cval::Text(s), 3) => acc.extend_from_slice(s.as_bytes()),
                _ => return None,
            }
            pos = np;
        }
        if major == 2 {
            return Some((Cval::Bytes(acc), pos));
        }
        return Some((Cval::Text(String::from_utf8(acc).ok()?), pos));
    }
    if major == 4 {
        let mut items = Vec::new();
        loop {
            if pos >= buf.len() {
                return None;
            }
            if buf[pos] == 0xff {
                pos += 1;
                break;
            }
            let (v, np) = decode(buf, pos)?;
            items.push(v);
            pos = np;
        }
        return Some((Cval::Array(items), pos));
    }
    let mut pairs = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        if buf[pos] == 0xff {
            pos += 1;
            break;
        }
        let (k, p1) = decode(buf, pos)?;
        let (v, p2) = decode(buf, p1)?;
        pairs.push((k, v));
        pos = p2;
    }
    Some((Cval::Map(pairs), pos))
}

fn head(major: u8, n: u64) -> Vec<u8> {
    let base = major << 5;
    if n < 24 {
        vec![base | n as u8]
    } else if n < 0x100 {
        vec![base | 24, n as u8]
    } else if n < 0x10000 {
        vec![base | 25, (n >> 8) as u8, n as u8]
    } else if n < 0x1_0000_0000 {
        vec![base | 26, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    } else {
        let mut out = vec![base | 27];
        for i in (0..8).rev() {
            out.push((n >> (8 * i)) as u8);
        }
        out
    }
}

fn encode(v: &Cval) -> Option<Vec<u8>> {
    match v {
        Cval::Int(i) => {
            if *i >= 0 {
                Some(head(0, *i as u64))
            } else {
                Some(head(1, (-1 - *i) as u64))
            }
        }
        Cval::Bytes(b) => {
            let mut out = head(2, b.len() as u64);
            out.extend_from_slice(b);
            Some(out)
        }
        Cval::Text(s) => {
            let mut out = head(3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
            Some(out)
        }
        Cval::Array(a) => {
            let mut out = head(4, a.len() as u64);
            for it in a {
                out.extend(encode(it)?);
            }
            Some(out)
        }
        Cval::Map(m) => {
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            for (k, val) in m {
                pairs.push((encode(k)?, encode(val)?));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = head(5, pairs.len() as u64);
            for (k, val) in pairs {
                out.extend(k);
                out.extend(val);
            }
            Some(out)
        }
        Cval::Null => Some(vec![0xf6]),
        _ => None,
    }
}

fn is_deterministic(buf: &[u8]) -> bool {
    match decode(buf, 0) {
        Some((v, np)) if np == buf.len() && !matches!(v, Cval::Tag(_, _)) => {
            matches!(encode(&v), Some(e) if e == buf)
        }
        _ => false,
    }
}

fn map_get<'a>(m: &'a Cval, key: i64) -> Option<&'a Cval> {
    if let Cval::Map(pairs) = m {
        for (k, v) in pairs {
            if let Cval::Int(ki) = k {
                if *ki == key {
                    return Some(v);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parse + gates
// ---------------------------------------------------------------------------

struct Sign1 {
    protected: Vec<u8>,
    phdr: Cval,
    payload: Vec<u8>,
    sig: Vec<u8>,
}

fn parse_sign1(buf: &[u8]) -> Option<Sign1> {
    let (top, _) = decode(buf, 0)?;
    let arr = match top {
        Cval::Tag(t, inner) => {
            if t != COSE_SIGN1_TAG {
                return None;
            }
            *inner
        }
        other => other,
    };
    let items = match arr {
        Cval::Array(v) if v.len() == 4 => v,
        _ => return None,
    };
    let protected = match &items[0] {
        Cval::Bytes(b) => b.clone(),
        _ => return None,
    };
    if !matches!(items[1], Cval::Map(_)) {
        return None;
    }
    let payload = match &items[2] {
        Cval::Bytes(b) => b.clone(),
        Cval::Null => Vec::new(),
        _ => return None,
    };
    let sig = match &items[3] {
        Cval::Bytes(b) => b.clone(),
        _ => return None,
    };
    let phdr = if protected.is_empty() {
        Cval::Map(Vec::new())
    } else {
        if !is_deterministic(&protected) {
            return None;
        }
        match decode(&protected, 0) {
            Some((m @ Cval::Map(_), _)) => m,
            _ => return None,
        }
    };
    Some(Sign1 { protected, phdr, payload, sig })
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    encode(&Cval::Array(vec![
        Cval::Text("Signature1".to_string()),
        Cval::Bytes(protected.to_vec()),
        Cval::Bytes(Vec::new()),
        Cval::Bytes(payload.to_vec()),
    ]))
    .unwrap()
}

// ---------------------------------------------------------------------------
// Signature verification per algorithm
// ---------------------------------------------------------------------------

fn verify_es256(key: &Value, preimage: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if sig.len() != 64 {
        return false;
    }
    let x = match key.get("x").and_then(|v| v.as_str()).and_then(hexb) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let y = match key.get("y").and_then(|v| v.as_str()).and_then(hexb) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let vk = match VerifyingKey::from_sec1_bytes(&uncompressed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(preimage, &signature).is_ok()
}

fn verify_eddsa(key: &Value, preimage: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk = match key.get("x").and_then(|v| v.as_str()).and_then(hexb) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_arr: [u8; 64] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    vk.verify(preimage, &Signature::from_bytes(&sig_arr)).is_ok()
}

fn verify_ps256(key: &Value, preimage: &[u8], sig: &[u8]) -> bool {
    use rsa::sha2::{Digest, Sha256};
    use rsa::{BigUint, Pss, RsaPublicKey};
    let n = match key.get("n").and_then(|v| v.as_str()).and_then(hexb) {
        Some(b) => BigUint::from_bytes_be(&b),
        None => return false,
    };
    let e = match key.get("e").and_then(|v| v.as_str()).and_then(hexb) {
        Some(b) => BigUint::from_bytes_be(&b),
        None => return false,
    };
    let pk = match RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // Pss::new::<Sha256>() uses a salt length equal to the digest size (32),
    // matching the reference verifier's salt_length=32.
    pk.verify(Pss::new::<Sha256>(), &Sha256::digest(preimage), sig).is_ok()
}

fn verdict(buf: &[u8], key: &Value) -> bool {
    let parsed = match parse_sign1(buf) {
        Some(p) => p,
        None => return false,
    };
    let alg = match map_get(&parsed.phdr, 1) {
        Some(Cval::Int(a)) => *a,
        _ => return false,
    };
    if let Some(crit) = map_get(&parsed.phdr, 2) {
        match crit {
            Cval::Array(labels) if !labels.is_empty() => {
                for l in labels {
                    match l {
                        Cval::Int(li) if known_label(*li) => {}
                        _ => return false,
                    }
                }
            }
            _ => return false,
        }
    }
    let want_kty = match alg_kty(alg) {
        Some(k) => k,
        None => return false,
    };
    if key.get("kty").and_then(|v| v.as_str()) != Some(want_kty) {
        return false;
    }
    let preimage = sig_structure(&parsed.protected, &parsed.payload);
    match alg {
        -7 => verify_es256(key, &preimage, &parsed.sig),
        -8 => verify_eddsa(key, &preimage, &parsed.sig),
        -37 => verify_ps256(key, &preimage, &parsed.sig),
        _ => false,
    }
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
    let material = &corpus["keys"];

    let mut total = 0usize;
    let mut matched = 0usize;
    for sec in SECTIONS {
        if let Some(cases) = corpus[sec].as_array() {
            for c in cases {
                let note = c["note"].as_str().unwrap_or("");
                let expect = c["expect_valid"].as_bool().unwrap_or(false);
                let accept = if sec == "cose_deterministic_cbor" {
                    match hexb(c["cbor_hex"].as_str().unwrap_or("")) {
                        Some(b) => is_deterministic(&b),
                        None => false,
                    }
                } else {
                    let key = &material[c["key"].as_str().unwrap_or("")];
                    match hexb(c["cose_hex"].as_str().unwrap_or("")) {
                        Some(b) => verdict(&b, key),
                        None => false,
                    }
                };
                total += 1;
                if accept == expect {
                    matched += 1;
                } else {
                    println!("FAIL  [{sec}] {note}");
                }
            }
        }
    }
    println!("\nrust (cose): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
