//! Rust runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//!
//! Independently reproduces every verdict in the frozen corpus, mirroring the
//! Python reference runner (runners/python/verify_pqc_mldsa.py) and its decision
//! surface (tools/oracle_pqc_mldsa.py) case for case: decode the hex public key,
//! message and signature, reject a wrong-length public key (must be 1952) or
//! signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
//! signature over the exact message bytes with the EMPTY context string.
//!
//! The ML-DSA implementation is the RustCrypto `ml-dsa` crate (MlDsa65), a
//! pure-Rust FIPS-204 (final) implementation independent of the reference liboqs.
//! The `Verifier` trait verifies over the empty context (the pure ML-DSA variant
//! this corpus fixes). A round-3 Dilithium library would fail the valid controls;
//! that is the built-in tripwire.
//!
//! Corpus path: argv[1], else $ALGOVOI_PQC_MLDSA, else the frozen repo corpus.
//! Exits 0 iff every case matched, else 1.

use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde_json::Value;

fn default_corpus_path() -> String {
    format!(
        "{}/../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

const SECTIONS: [&str; 3] = ["mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"];
const PK_LEN: usize = 1952;
const SIG_LEN: usize = 3309;

fn verdict(pk_hex: &str, msg_hex: &str, sig_hex: &str) -> bool {
    let pk = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let msg = match hex::decode(msg_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if pk.len() != PK_LEN || sig.len() != SIG_LEN {
        return false;
    }
    let enc = match EncodedVerifyingKey::<MlDsa65>::try_from(&pk[..]) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc);
    let esig = match EncodedSignature::<MlDsa65>::try_from(&sig[..]) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let signature = match Signature::<MlDsa65>::decode(&esig) {
        Some(s) => s,
        None => return false,
    };
    vk.verify(&msg, &signature).is_ok()
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ALGOVOI_PQC_MLDSA").ok())
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

    let mut total = 0usize;
    let mut matched = 0usize;
    for sec in SECTIONS {
        if let Some(cases) = corpus[sec].as_array() {
            for c in cases {
                let note = c["note"].as_str().unwrap_or("");
                let expect = c["expect_valid"].as_bool().unwrap_or(false);
                let pk = c["public_key"].as_str().unwrap_or("");
                let msg = c["message"].as_str().unwrap_or("");
                let sig = c["signature"].as_str().unwrap_or("");
                let accept = verdict(pk, msg, sig);
                total += 1;
                if accept == expect {
                    matched += 1;
                } else {
                    println!("FAIL  [{sec}] {note}");
                }
            }
        }
    }
    println!("\nrust (pqc_mldsa): {matched}/{total} cases matched");
    std::process::exit(if matched == total { 0 } else { 1 });
}
