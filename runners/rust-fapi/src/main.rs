//! Rust runner for the FAPI 2.0 Message Signing RFC 9421 profile corpus
//! (fapi_messagesigning_v0).
//!
//! Self-contained: it re-implements the PROFILE rules (mandated covered-component
//! completeness by message type, Content-Digest / RFC 9530 body binding, the
//! PS256/ES256 algorithm restriction) from first principles against the corpus
//! `policy` block, hand-builds the RFC 9421 Section 2.5 signing base by direct
//! concatenation, verifies PS256 (RSA-PSS SHA-256, salt 32) with the `rsa` crate
//! and ES256 (ECDSA P-256 SHA-256, low-s enforced) with the `p256` crate. It
//! mirrors the Python reference runner (runners/python/verify_fapi.py) so a pass
//! is genuine agreement, not an echo of the generator's oracle.
//!
//! Corpus path: argv[1], else the frozen repo corpus (default resolved relative
//! to this crate so it works from any cwd). Prints `FAIL  [section] note` per
//! mismatch, then `rust (fapi): N/N cases matched`; exits 0 iff every case
//! matched, else 1.

use base64::Engine;
use num_bigint::BigUint;
use serde_json::Value;

/// Default corpus path, resolved relative to this crate (runners/rust-fapi ->
/// repo root/corpus/...), so `cargo run` works regardless of the cwd.
fn default_corpus_path() -> String {
    format!(
        "{}/../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn b64_decode_str(s: &str) -> Option<String> {
    String::from_utf8(b64_decode(s)?).ok()
}

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

// -------- Section 1: hand-built RFC 9421 Section 2.5 signing base --------

/// Mirror of verify_fapi.py's signing-base build. Each lowercased covered
/// component becomes `"name": value`, where derived components map onto the
/// `in` fields (`@method`->method, `@target-uri`->target_uri, `@status`->status
/// as string, `@authority`->authority, `@path`->path) and everything else is a
/// header looked up (lowercased) in `in.headers`. The `@signature-params` line
/// carries the raw params string verbatim. Returns None when the base cannot be
/// built (a covered component references a missing value).
fn hand_signing_base(src: &Value, params_raw: &str) -> Option<String> {
    let covered = src.get("covered_components")?.as_array()?;
    let mut lines: Vec<String> = Vec::with_capacity(covered.len() + 1);
    for comp in covered {
        let name = comp.as_str()?.to_lowercase();
        let val: String = match name.as_str() {
            "@method" => src.get("method")?.as_str()?.to_string(),
            "@target-uri" => src.get("target_uri")?.as_str()?.to_string(),
            "@status" => {
                let s = src.get("status")?;
                if let Some(i) = s.as_i64() {
                    i.to_string()
                } else if let Some(st) = s.as_str() {
                    st.to_string()
                } else {
                    return None;
                }
            }
            "@authority" => src.get("authority")?.as_str()?.to_string(),
            "@path" => src.get("path")?.as_str()?.to_string(),
            _ => src.get("headers")?.as_object()?.get(&name)?.as_str()?.to_string(),
        };
        lines.push(format!("\"{name}\": {val}"));
    }
    lines.push(format!("\"@signature-params\": {params_raw}"));
    Some(lines.join("\n"))
}

// -------- Section 2: required covered-component completeness --------

fn coverage_ok(message_type: &str, covered: &[Value], policy: &Value) -> bool {
    let key = if message_type == "request" {
        "required_covered_request"
    } else {
        "required_covered_response"
    };
    let have: Vec<String> = covered
        .iter()
        .filter_map(|c| c.as_str().map(|s| s.to_lowercase()))
        .collect();
    policy[key]
        .as_array()
        .map(|reqs| {
            reqs.iter().all(|r| {
                r.as_str()
                    .map(|s| have.contains(&s.to_lowercase()))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

// -------- Section 3: Content-Digest (RFC 9530) body binding --------

fn content_digest_ok(body_b64: &str, header_value: &str, covered: &[Value], policy: &Value) -> bool {
    let covered_lower: Vec<String> = covered
        .iter()
        .filter_map(|c| c.as_str().map(|s| s.to_lowercase()))
        .collect();
    if !covered_lower.iter().any(|c| c == "content-digest") {
        return false;
    }
    // Split at the first '='; the prefix is the algorithm label.
    let algorithm = match header_value.split_once('=') {
        Some((alg, _)) => alg.trim().to_lowercase(),
        None => return false,
    };
    let allowed = policy["content_digest_algorithms"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(algorithm.as_str())))
        .unwrap_or(false);
    if !allowed {
        return false;
    }
    let body = match b64_decode(body_b64) {
        Some(b) => b,
        None => return false,
    };
    let digest: Vec<u8> = if algorithm == "sha-256" {
        use sha2::{Digest, Sha256};
        Sha256::digest(&body).to_vec()
    } else {
        use sha2::{Digest, Sha512};
        Sha512::digest(&body).to_vec()
    };
    let expect = format!("{algorithm}=:{}:", b64_encode(&digest));
    header_value.trim() == expect
}

// -------- Section 5: PS256 (RSA-PSS SHA-256, salt 32) --------

fn ps256_ok(base: &[u8], sig: &[u8], spki_der: &[u8]) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::Sha256;
    use rsa::{Pss, RsaPublicKey};
    match RsaPublicKey::from_public_key_der(spki_der) {
        // Pss::new::<Sha256>() uses a salt length equal to the digest size (32),
        // matching the reference verifier's salt_length=32.
        Ok(key) => {
            use rsa::sha2::Digest;
            key.verify(Pss::new::<Sha256>(), &Sha256::digest(base), sig)
                .is_ok()
        }
        Err(_) => false,
    }
}

// -------- Section 6: ES256 (ECDSA P-256 SHA-256, low-s enforced) --------

fn es256_ok(
    base: &[u8],
    sig_raw: &[u8],
    pub_uncompressed: &[u8],
    require_low_s: bool,
    policy: &Value,
) -> bool {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if sig_raw.len() != 64 {
        return false;
    }
    if require_low_s {
        let s = BigUint::from_bytes_be(&sig_raw[32..64]);
        let n = match policy["p256_n"].as_str().and_then(|v| v.parse::<BigUint>().ok()) {
            Some(n) => n,
            None => return false,
        };
        if s > &n / 2u32 {
            return false;
        }
    }
    let vk = match VerifyingKey::from_sec1_bytes(pub_uncompressed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // Raw 64-byte r||s signature.
    let sig = match Signature::from_slice(sig_raw) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(base, &sig).is_ok()
}

// -------- Driver --------

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
    let policy = &corpus["policy"];

    // (section, note, matched)
    let mut results: Vec<(&str, String, bool)> = Vec::new();

    // Section 1: fapi_signing_base
    if let Some(cases) = corpus["fapi_signing_base"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let ok_flag = c["ok"].as_bool().unwrap_or(false);
            let params_raw = c["signature_params_raw"].as_str().unwrap_or("");
            let want = c["signing_base_b64"].as_str().and_then(b64_decode_str);
            let matched = match (hand_signing_base(&c["in"], params_raw), want) {
                (Some(built), Some(decoded)) => ok_flag && built == decoded,
                // unbuildable base: matches iff the case was flagged not-ok
                _ => !ok_flag,
            };
            results.push(("fapi_signing_base", note, matched));
        }
    }

    // Section 2: fapi_required_coverage
    if let Some(cases) = corpus["fapi_required_coverage"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let message_type = c["message_type"].as_str().unwrap_or("");
            let covered = c["covered_components"].as_array().cloned().unwrap_or_default();
            let matched = coverage_ok(message_type, &covered, policy) == expect;
            results.push(("fapi_required_coverage", note, matched));
        }
    }

    // Section 3: fapi_content_digest
    if let Some(cases) = corpus["fapi_content_digest"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let body_b64 = c["body_b64"].as_str().unwrap_or("");
            let header = c["content_digest"].as_str().unwrap_or("");
            let covered = c["covered_components"].as_array().cloned().unwrap_or_default();
            let matched = content_digest_ok(body_b64, header, &covered, policy) == expect;
            results.push(("fapi_content_digest", note, matched));
        }
    }

    // Section 4: fapi_alg
    if let Some(cases) = corpus["fapi_alg"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let alg = c["alg"].as_str().unwrap_or("").to_lowercase();
            let allowed = policy["allowed_algs"]
                .as_array()
                .map(|a| a.iter().any(|v| v.as_str() == Some(alg.as_str())))
                .unwrap_or(false);
            results.push(("fapi_alg", note, allowed == expect));
        }
    }

    // Section 5: fapi_ps256_verify
    if let Some(cases) = corpus["fapi_ps256_verify"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_valid"].as_bool().unwrap_or(false);
            let base = c["signing_base_b64"].as_str().and_then(b64_decode);
            let sig = c["sig_hex"].as_str().and_then(|s| hex::decode(s).ok());
            let spki = c["pub_spki_hex"].as_str().and_then(|s| hex::decode(s).ok());
            let valid = match (base, sig, spki) {
                (Some(b), Some(s), Some(k)) => ps256_ok(&b, &s, &k),
                _ => false,
            };
            results.push(("fapi_ps256_verify", note, valid == expect));
        }
    }

    // Section 6: fapi_es256_verify
    if let Some(cases) = corpus["fapi_es256_verify"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_valid"].as_bool().unwrap_or(false);
            let require_low_s = c["require_low_s"].as_bool().unwrap_or(false);
            let base = c["signing_base_b64"].as_str().and_then(b64_decode);
            let sig = c["sig_raw_hex"].as_str().and_then(|s| hex::decode(s).ok());
            let pk = c["pub_uncompressed_hex"].as_str().and_then(|s| hex::decode(s).ok());
            let valid = match (base, sig, pk) {
                (Some(b), Some(s), Some(k)) => es256_ok(&b, &s, &k, require_low_s, policy),
                _ => false,
            };
            results.push(("fapi_es256_verify", note, valid == expect));
        }
    }

    let total = results.len();
    let mut matched = 0usize;
    for (section, note, ok) in &results {
        if *ok {
            matched += 1;
        } else {
            println!("FAIL  [{section}] {note}");
        }
    }
    println!("\nrust (fapi): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
