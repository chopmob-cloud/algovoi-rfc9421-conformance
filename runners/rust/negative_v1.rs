//! Rust runner for the rfc9421_negative_v1 CORE cross-language battery.
//!
//! Lives in the ecdsa crate's tests because it exercises both the core
//! primitives and the ECDSA add-on, mirroring the Python reference runner so all
//! four languages produce identical verdicts per case. Verify setup errors are
//! treated as fail-closed (valid = false), matching the other runners.
//!
//! Corpus path: ALGOVOI_NEGATIVE_V1 env override, else the sibling multilang repo.

use std::collections::HashMap;

use base64::Engine;
use serde_json::Value;

use algovoi_rfc9421_verifier::{
    build_signing_base, check_ed25519_public_key, is_small_order, parse_signature_input,
    parse_signature_value, verify_signature, Mode, ParamValue, SigningBaseInput,
};
use algovoi_rfc9421_ecdsa::{set_strict_low_s, verify_p256, verify_p384, PublicKeyInput};

// Default assumes the algovoi-rfc9421-conformance repo is checked out alongside
// this one; override with ALGOVOI_NEGATIVE_V1. Tests no-op if neither resolves.
const DEFAULT_PATH: &str =
    "../../../algovoi-rfc9421-conformance/corpus/rfc9421_negative_v1/rfc9421_negative_v1.json";

fn load_corpus() -> Value {
    let path = std::env::var("ALGOVOI_NEGATIVE_V1").unwrap_or_else(|_| DEFAULT_PATH.to_string());
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).expect("parse negative_v1 corpus"),
        // Corpus not present (e.g. conformance repo not checked out): no-op so
        // this repo's CI does not depend on a sibling checkout. Set
        // ALGOVOI_NEGATIVE_V1 to run the battery.
        Err(_) => serde_json::json!({
            "signing_base": [], "signature_input_parse": [], "signature_value_parse": [],
            "keygate": [], "ed25519_verify": [], "ecdsa_verify": []
        }),
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("valid base64 in vector")
}

fn value_to_param(v: &Value) -> ParamValue {
    if let Some(i) = v.as_i64() {
        ParamValue::Int(i)
    } else if let Some(s) = v.as_str() {
        ParamValue::Str(s.to_string())
    } else {
        ParamValue::Str(v.to_string())
    }
}

#[test]
fn signing_base_cases() {
    let corpus = load_corpus();
    let cases = corpus["signing_base"].as_array().expect("signing_base array");
    for (idx, case) in cases.iter().enumerate() {
        let input = &case["in"];
        let mode = Mode::parse(case["mode"].as_str().unwrap()).expect("valid mode");
        let covered: Vec<String> = input["covered_components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        let headers: HashMap<String, String> = input
            .get("headers")
            .and_then(|h| h.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let parameters: HashMap<String, ParamValue> = input
            .get("parameters")
            .and_then(|p| p.as_object())
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), value_to_param(v))).collect())
            .unwrap_or_default();
        let sb_input = SigningBaseInput {
            covered_components: covered,
            method: input.get("method").and_then(|v| v.as_str()),
            authority: input.get("authority").and_then(|v| v.as_str()),
            path: input.get("path").and_then(|v| v.as_str()),
            target_uri: input.get("target_uri").and_then(|v| v.as_str()),
            scheme: input.get("scheme").and_then(|v| v.as_str()),
            status: input.get("status").and_then(|v| v.as_i64()),
            headers,
            parameters,
            mode,
            signature_params_raw: case
                .get("signature_params_raw")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };
        let expect_ok = case["ok"].as_bool().unwrap();
        match build_signing_base(&sb_input) {
            Ok(got) => {
                assert!(expect_ok, "signing_base case {idx} expected error, built ok");
                let expected = b64_decode(case["signing_base_b64"].as_str().unwrap());
                assert_eq!(got.as_bytes(), expected.as_slice(), "signing_base case {idx} mismatch");
            }
            Err(_) => assert!(!expect_ok, "signing_base case {idx} unexpected error"),
        }
    }
}

#[test]
fn signature_input_parse_cases() {
    let corpus = load_corpus();
    for (idx, case) in corpus["signature_input_parse"].as_array().unwrap().iter().enumerate() {
        let ok = parse_signature_input(case["header"].as_str().unwrap()).is_ok();
        assert_eq!(ok, case["ok"].as_bool().unwrap(), "sig_input_parse case {idx}");
    }
}

#[test]
fn signature_value_parse_cases() {
    let corpus = load_corpus();
    for (idx, case) in corpus["signature_value_parse"].as_array().unwrap().iter().enumerate() {
        let ok = parse_signature_value(case["header"].as_str().unwrap()).is_ok();
        assert_eq!(ok, case["ok"].as_bool().unwrap(), "sig_value_parse case {idx}");
    }
}

#[test]
fn keygate_cases() {
    let corpus = load_corpus();
    for (idx, case) in corpus["keygate"].as_array().unwrap().iter().enumerate() {
        let pk = hex::decode(case["pk_hex"].as_str().unwrap()).expect("hex pk");
        let rejected = check_ed25519_public_key(&pk).is_err();
        assert_eq!(rejected, !case["rejected"].is_null(), "keygate case {idx} rejection");
        assert_eq!(is_small_order(&pk), case["small_order"].as_bool().unwrap(), "keygate case {idx} small_order");
    }
}

#[test]
fn ed25519_verify_cases() {
    let corpus = load_corpus();
    for (idx, case) in corpus["ed25519_verify"].as_array().unwrap().iter().enumerate() {
        let signing_base = String::from_utf8(b64_decode(case["signing_base_b64"].as_str().unwrap()))
            .expect("utf-8 signing base");
        let sig = hex::decode(case["sig_hex"].as_str().unwrap()).expect("hex sig");
        let pk = hex::decode(case["pk_hex"].as_str().unwrap()).expect("hex pk");
        let valid = matches!(verify_signature(&signing_base, &sig, &pk, "ed25519"), Ok(true));
        assert_eq!(valid, case["expect_valid"].as_bool().unwrap(), "ed25519_verify case {idx}");
    }
}

#[test]
fn ecdsa_verify_cases() {
    let corpus = load_corpus();
    for (idx, case) in corpus["ecdsa_verify"].as_array().unwrap().iter().enumerate() {
        let msg = String::from_utf8(hex::decode(case["msg_hex"].as_str().unwrap()).unwrap())
            .expect("utf-8 msg");
        let sig = hex::decode(case["sig_raw_hex"].as_str().unwrap()).expect("hex sig");
        let pk = PublicKeyInput::Hex(case["pub_uncompressed_hex"].as_str().unwrap().to_string());
        let strict = case["strict_low_s"].as_bool().unwrap_or(false);
        set_strict_low_s(strict);
        let verdict = if case["curve"].as_str().unwrap() == "p256" {
            verify_p256(&msg, &sig, &pk)
        } else {
            verify_p384(&msg, &sig, &pk)
        };
        set_strict_low_s(false);
        let valid = matches!(verdict, Ok(true));
        assert_eq!(valid, case["expect_valid"].as_bool().unwrap(), "ecdsa_verify case {idx}");
    }
}

// RSA is not part of the Ed25519/ECDSA verifier; verify it with the `rsa` crate
// so the rsa_verify section is genuine cross-language consensus. Requires the
// `rsa` and `sha2` dev-dependencies.
#[test]
fn rsa_verify_cases() {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::{Digest, Sha256, Sha512};
    use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};
    let corpus = load_corpus();
    let empty = vec![];
    let cases = corpus["rsa_verify"].as_array().unwrap_or(&empty);
    for (idx, case) in cases.iter().enumerate() {
        let base = b64_decode(case["signing_base_b64"].as_str().unwrap());
        let sig = hex::decode(case["sig_hex"].as_str().unwrap()).expect("hex sig");
        let spki = hex::decode(case["pub_spki_hex"].as_str().unwrap()).expect("hex spki");
        let valid = match RsaPublicKey::from_public_key_der(&spki) {
            Ok(key) => match case["alg"].as_str().unwrap() {
                "rsa-pss-sha512" => key.verify(Pss::new::<Sha512>(), &Sha512::digest(&base), &sig).is_ok(),
                "rsa-v1_5-sha256" => key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&base), &sig).is_ok(),
                _ => false,
            },
            Err(_) => false,
        };
        assert_eq!(valid, case["expect_valid"].as_bool().unwrap(), "rsa_verify case {idx}");
    }
}
