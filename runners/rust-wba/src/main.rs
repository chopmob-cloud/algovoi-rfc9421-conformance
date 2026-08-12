//! Rust runner for the Web Bot Auth RFC 9421 profile corpus (webbotauth_v0).
//!
//! Self-contained: it re-implements the PROFILE rules (covered-component
//! completeness, freshness/replay window, directory keyid resolution,
//! Signature-Agent SSRF) from first principles against the corpus `policy`
//! block, hand-builds the RFC 9421 Section 2.5 signing base by direct
//! concatenation, and verifies Ed25519 with `ed25519-dalek`. It mirrors the
//! Python reference runner (runners/python/verify_wba.py) and the independent
//! KAT gate (tools/check_kat_wba.py) so a pass is genuine agreement, not an echo
//! of the generator's oracle.
//!
//! Corpus path: argv[1], else the frozen repo corpus (default resolved relative
//! to this crate so it works from any cwd). Prints `FAIL  [section] note` per
//! mismatch, then `rust (wba): N/N cases matched`; exits 0 iff every case
//! matched, else 1.

use std::net::IpAddr;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

/// Default corpus path, resolved relative to this crate (runners/rust-wba ->
/// repo root/corpus/...), so `cargo run` works regardless of the cwd.
fn default_corpus_path() -> String {
    format!(
        "{}/../../corpus/webbotauth_v0/webbotauth_v0.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn b64_decode_str(s: &str) -> Option<String> {
    String::from_utf8(b64_decode(s)?).ok()
}

// -------- Rule 1: hand-built RFC 9421 Section 2.5 signing base --------

/// Mirror of tools/check_kat_wba.py::hand_signing_base. Returns None when the
/// base cannot be built (a covered component references a missing value).
fn hand_signing_base(src: &Value, params_raw: &str) -> Option<String> {
    let covered = src.get("covered_components")?.as_array()?;
    let mut lines: Vec<String> = Vec::with_capacity(covered.len() + 1);
    for comp in covered {
        let name = comp.as_str()?.to_lowercase();
        let val: &str = match name.as_str() {
            "@authority" => src.get("authority")?.as_str()?,
            "@method" => src.get("method")?.as_str()?,
            "@path" => src.get("path")?.as_str()?,
            _ => src.get("headers")?.as_object()?.get(&name)?.as_str()?,
        };
        lines.push(format!("\"{name}\": {val}"));
    }
    lines.push(format!("\"@signature-params\": {params_raw}"));
    Some(lines.join("\n"))
}

// -------- Rule 2: coverage completeness --------

fn coverage_ok(covered: &[Value], policy: &Value) -> bool {
    let have: Vec<String> = covered
        .iter()
        .filter_map(|c| c.as_str().map(|s| s.to_lowercase()))
        .collect();
    policy["required_covered_components"]
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

// -------- Rule 3: freshness window --------

fn freshness_ok(created: &Value, expires: &Value, now: &Value, policy: &Value) -> bool {
    let skew = policy
        .get("clock_skew_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    // All three must be JSON integers.
    let (created, expires, now) = match (created.as_i64(), expires.as_i64(), now.as_i64()) {
        (Some(c), Some(e), Some(n))
            if created.is_i64() && expires.is_i64() && now.is_i64() =>
        {
            (c, e, n)
        }
        _ => return false,
    };
    if expires <= created {
        return false;
    }
    (created - skew) <= now && now < expires
}

// -------- Rule 4: directory keyid resolution --------

fn directory_ok(directory: &[Value], keyid: &str) -> bool {
    for jwk in directory {
        if jwk.get("kid").and_then(|v| v.as_str()) == Some(keyid) {
            let kty = jwk.get("kty").and_then(|v| v.as_str());
            let crv = jwk.get("crv").and_then(|v| v.as_str());
            let x_ok = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            return kty == Some("OKP") && crv == Some("Ed25519") && x_ok;
        }
    }
    false
}

// -------- Rule 5: Signature-Agent SSRF --------

/// Minimal urlsplit-equivalent: returns (scheme, netloc). netloc runs up to the
/// first '/', '?' or '#' after "scheme://".
fn split_url(url: &str) -> Option<(String, String)> {
    let idx = url.find("://")?;
    let scheme = url[..idx].to_lowercase();
    let rest = &url[idx + 3..];
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    Some((scheme, rest[..end].to_string()))
}

/// Host from a netloc: drop userinfo (after '@'), strip port, unbracket IPv6,
/// lowercase. Mirrors urlsplit(...).hostname.
fn host_from_netloc(netloc: &str) -> Option<String> {
    let after_userinfo = match netloc.rfind('@') {
        Some(i) => &netloc[i + 1..],
        None => netloc,
    };
    if after_userinfo.is_empty() {
        return None;
    }
    let host = if let Some(stripped) = after_userinfo.strip_prefix('[') {
        // IPv6 literal: content up to ']'
        let close = stripped.find(']')?;
        &stripped[..close]
    } else {
        // strip :port if present
        match after_userinfo.find(':') {
            Some(i) => &after_userinfo[..i],
            None => after_userinfo,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// True iff `addr` falls within the CIDR string (e.g. "10.0.0.0/8", "::1/128").
/// Only compares when the IP versions match.
fn addr_in_cidr(addr: &IpAddr, cidr: &str) -> bool {
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };
    let prefix: u32 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let net: IpAddr = match net_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => bits_match(&a.octets(), &n.octets(), prefix),
        (IpAddr::V6(a), IpAddr::V6(n)) => bits_match(&a.octets(), &n.octets(), prefix),
        _ => false,
    }
}

fn bits_match(a: &[u8], n: &[u8], prefix: u32) -> bool {
    let full = (prefix / 8) as usize;
    let rem = (prefix % 8) as u8;
    if full > a.len() {
        return false;
    }
    if a[..full] != n[..full] {
        return false;
    }
    if rem > 0 && full < a.len() {
        let mask: u8 = 0xFFu8 << (8 - rem);
        if (a[full] & mask) != (n[full] & mask) {
            return false;
        }
    }
    true
}

fn ssrf_ok(url: &str, resolved_ip: Option<&str>, policy: &Value) -> bool {
    let ssrf = &policy["ssrf"];
    let (scheme, netloc) = match split_url(url) {
        Some(v) => v,
        None => return false,
    };
    let require_https = ssrf
        .get("require_https")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if require_https && scheme != "https" {
        return false;
    }
    if netloc.contains('@') {
        return false;
    }
    let host = match host_from_netloc(&netloc) {
        Some(h) => h,
        None => return false,
    };
    // IP literal directly, else fall back to the resolved address.
    let addr: IpAddr = match host.parse::<IpAddr>() {
        Ok(a) => a,
        Err(_) => match resolved_ip {
            Some(rip) if !rip.is_empty() => match rip.parse::<IpAddr>() {
                Ok(a) => a,
                Err(_) => return false,
            },
            _ => return false,
        },
    };
    if let Some(cidrs) = ssrf.get("denied_cidrs").and_then(|v| v.as_array()) {
        for cidr in cidrs {
            if let Some(cs) = cidr.as_str() {
                if addr_in_cidr(&addr, cs) {
                    return false;
                }
            }
        }
    }
    true
}

// -------- Rule 6: Ed25519 signature verdict --------

fn ed25519_valid(base: &[u8], sig_hex: &str, pk_hex: &str) -> bool {
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(base, &sig).is_ok()
}

// -------- Driver --------

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(default_corpus_path);
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

    // Section 1: wba_signing_base
    if let Some(cases) = corpus["wba_signing_base"].as_array() {
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
            results.push(("wba_signing_base", note, matched));
        }
    }

    // Section 2: wba_coverage
    if let Some(cases) = corpus["wba_coverage"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let covered = c["covered_components"].as_array().cloned().unwrap_or_default();
            let matched = coverage_ok(&covered, policy) == expect;
            results.push(("wba_coverage", note, matched));
        }
    }

    // Section 3: wba_freshness
    if let Some(cases) = corpus["wba_freshness"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let matched = freshness_ok(&c["created"], &c["expires"], &c["now"], policy) == expect;
            results.push(("wba_freshness", note, matched));
        }
    }

    // Section 4: wba_directory
    if let Some(cases) = corpus["wba_directory"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_accept"].as_bool().unwrap_or(false);
            let directory = c["directory"].as_array().cloned().unwrap_or_default();
            let keyid = c["keyid"].as_str().unwrap_or("");
            let matched = directory_ok(&directory, keyid) == expect;
            results.push(("wba_directory", note, matched));
        }
    }

    // Section 5: wba_directory_ssrf
    if let Some(cases) = corpus["wba_directory_ssrf"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_fetch_allowed"].as_bool().unwrap_or(false);
            let url = c["signature_agent_url"].as_str().unwrap_or("");
            let resolved = c["resolved_ip"].as_str();
            let matched = ssrf_ok(url, resolved, policy) == expect;
            results.push(("wba_directory_ssrf", note, matched));
        }
    }

    // Section 6: wba_ed25519_verify
    if let Some(cases) = corpus["wba_ed25519_verify"].as_array() {
        for c in cases {
            let note = c["note"].as_str().unwrap_or("").to_string();
            let expect = c["expect_valid"].as_bool().unwrap_or(false);
            let base = c["signing_base_b64"].as_str().and_then(b64_decode);
            let sig_hex = c["sig_hex"].as_str().unwrap_or("");
            let pk_hex = c["pk_hex"].as_str().unwrap_or("");
            let valid = match base {
                Some(b) => ed25519_valid(&b, sig_hex, pk_hex),
                None => false,
            };
            results.push(("wba_ed25519_verify", note, valid == expect));
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
    println!("\nrust (wba): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
