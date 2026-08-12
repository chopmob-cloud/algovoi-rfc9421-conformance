//! Rust runner for the JSON Web Signature corpus (jws_v0).
//!
//! Self-contained: it re-implements the JOSE gate logic from the corpus, parses
//! each compact JWS, applies the security gates in order (reject alg:none, reject
//! any crit, reject alg/key-type mismatch such as HS256 keyed with an RSA public
//! key, select the key by kid when required), then verifies the RS256 / ES256 /
//! EdDSA signature over ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced
//! (plain JOSE permits a high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0
//! rule). It mirrors the Python reference runner (runners/python/verify_jws.py) and
//! its decision surface (tools/oracle_jws.py) so a pass is genuine agreement.
//!
//! RS256 with the `rsa` crate, ES256 with the `p256` crate (from_sec1_bytes rejects
//! an off-curve point), EdDSA with `ed25519-dalek`.
//!
//! Corpus path: argv[1], else the frozen repo corpus. Exits 0 iff every case
//! matched, else 1.

use base64::Engine;
use serde_json::Value;

fn default_corpus_path() -> String {
    format!("{}/../../corpus/jws_v0/jws_v0.json", env!("CARGO_MANIFEST_DIR"))
}

const SECTIONS: [&str; 8] = [
    "jws_compact_parse", "jws_alg_none", "jws_alg_confusion", "jws_rs256_verify",
    "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid",
];

/// RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
fn alg_kty(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" => Some("RSA"),
        "ES256" => Some("EC"),
        "EdDSA" => Some("OKP"),
        "HS256" => Some("oct"),
        _ => None,
    }
}

/// Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
fn b64url(seg: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(seg).ok()
}

struct Parsed {
    header: Value,
    sig: Vec<u8>,
    signing_input: Vec<u8>,
}

fn parse_compact(token: &str) -> Option<Parsed> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header_bytes = b64url(parts[0])?;
    let header: Value = serde_json::from_slice(&header_bytes).ok()?;
    if !header.is_object() {
        return None;
    }
    header.get("alg")?;
    b64url(parts[1])?;
    let sig = b64url(parts[2])?;
    let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
    Some(Parsed { header, sig, signing_input })
}

fn select_key<'a>(header: &Value, keys: &'a [(String, &'a Value)], select_by_kid: bool) -> Option<&'a Value> {
    if select_by_kid {
        let kid = header.get("kid")?.as_str()?;
        for (k_kid, jwk) in keys {
            if k_kid == kid {
                return Some(jwk);
            }
        }
        None
    } else {
        keys.first().map(|(_, jwk)| *jwk)
    }
}

fn verify_rs256(jwk: &Value, signing_input: &[u8], sig: &[u8]) -> bool {
    use rsa::sha2::{Digest, Sha256};
    use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
    let n = match jwk.get("n").and_then(|v| v.as_str()).and_then(b64url) {
        Some(b) => BigUint::from_bytes_be(&b),
        None => return false,
    };
    let e = match jwk.get("e").and_then(|v| v.as_str()).and_then(b64url) {
        Some(b) => BigUint::from_bytes_be(&b),
        None => return false,
    };
    let key = match RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(signing_input), sig)
        .is_ok()
}

fn verify_es256(jwk: &Value, signing_input: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if sig.len() != 64 {
        return false;
    }
    let x = match jwk.get("x").and_then(|v| v.as_str()).and_then(b64url) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let y = match jwk.get("y").and_then(|v| v.as_str()).and_then(b64url) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    // from_sec1_bytes rejects a point that is not on secp256r1.
    let vk = match VerifyingKey::from_sec1_bytes(&uncompressed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(signing_input, &signature).is_ok()
}

fn verify_eddsa(jwk: &Value, signing_input: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk = match jwk.get("x").and_then(|v| v.as_str()).and_then(b64url) {
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
    vk.verify(signing_input, &Signature::from_bytes(&sig_arr)).is_ok()
}

fn verdict(token: &str, keys: &[(String, &Value)], select_by_kid: bool) -> bool {
    let parsed = match parse_compact(token) {
        Some(p) => p,
        None => return false,
    };
    let alg = match parsed.header.get("alg").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return false,
    };
    if alg == "none" {
        return false;
    }
    if parsed.header.get("crit").is_some() {
        return false;
    }
    let want_kty = match alg_kty(alg) {
        Some(k) => k,
        None => return false,
    };
    let jwk = match select_key(&parsed.header, keys, select_by_kid) {
        Some(j) => j,
        None => return false,
    };
    if jwk.get("kty").and_then(|v| v.as_str()) != Some(want_kty) {
        return false;
    }
    match alg {
        "RS256" => verify_rs256(jwk, &parsed.signing_input, &parsed.sig),
        "ES256" => verify_es256(jwk, &parsed.signing_input, &parsed.sig),
        "EdDSA" => verify_eddsa(jwk, &parsed.signing_input, &parsed.sig),
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
                let token = c["jws"].as_str().unwrap_or("");
                let verify = &c["verify"];
                let select_by_kid = verify["select_by_kid"].as_bool().unwrap_or(false);
                let mut keys: Vec<(String, &Value)> = Vec::new();
                if let Some(names) = verify["key_names"].as_array() {
                    for nm in names {
                        if let Some(name) = nm.as_str() {
                            let jwk = &material[name];
                            let kid = jwk.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            keys.push((kid, jwk));
                        }
                    }
                }
                let accept = verdict(token, &keys, select_by_kid);
                total += 1;
                if accept == expect {
                    matched += 1;
                } else {
                    println!("FAIL  [{sec}] {note}");
                }
            }
        }
    }
    println!("\nrust (jws): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
