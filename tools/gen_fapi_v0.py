#!/usr/bin/env python3
"""Deterministically generate the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).

Consumes the frozen public material (vectors/fapi_material_v0.json) and stamps
every expected verdict with tools/oracle_fapi.py. The runners and the KAT gate
re-derive the verdicts independently. Deterministic and LF-only.

Run:  python tools/gen_fapi_v0.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_fapi as O  # noqa: E402

REPO = os.path.dirname(HERE)
MATERIAL = os.path.join(REPO, "vectors", "fapi_material_v0.json")
OUT_DIR = os.path.join(REPO, "corpus", "fapi_messagesigning_v0")
OUT = os.path.join(OUT_DIR, "fapi_messagesigning_v0.json")


def _flip(hexstr):
    b = bytearray.fromhex(hexstr); b[0] ^= 0x01; return b.hex()


def build(m):
    body_b64 = m["body_b64"]
    cd_req = m["content_digest_request"]
    body = base64.b64decode(body_b64)
    cd_sha512 = O.compute_content_digest(body, "sha-512")
    cd_swapped = m["content_digest_response"]           # digest of a DIFFERENT body
    # md5 is deliberately weak here: this builds the NEGATIVE Content-Digest vector
    # the FAPI verifier must reject. usedforsecurity=False documents that (and keeps
    # the digest bytes identical, so the corpus is unchanged).
    cd_md5 = "md5=:" + base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode() + ":"

    corpus = {
        "name": "fapi_messagesigning_v0",
        "description": ("Signed cross-language conformance battery for the FAPI 2.0 Message "
                        "Signing profile: mandated covered-component completeness, Content-Digest "
                        "(RFC 9530) body binding, PS256/ES256 algorithm restriction, and the "
                        "RSA-PSS-SHA256 / ECDSA-P256 signature verdicts (low-s enforced)."),
        "profile": "fapi-2-message-signing",
        "policy": O.POLICY,
        "fapi_signing_base": [
            {"in": {"covered_components": m["request_covered"], "method": "POST",
                    "target_uri": "https://api.bank.example/payments",
                    "headers": {"authorization": "Bearer eyJhbGciOiJ...redacted",
                                "content-digest": cd_req}},
             "mode": "rfc9421", "signature_params_raw": m["signature_params_ps256"],
             "signing_base_b64": m["base_ps256_b64"], "ok": True,
             "note": "FAPI request signing base (PS256): method + target-uri + authorization + content-digest"},
            {"in": {"covered_components": m["response_covered"], "status": 200,
                    "headers": {"content-digest": m["content_digest_response"]}},
             "mode": "rfc9421", "signature_params_raw": m["signature_params_resp"],
             "signing_base_b64": m["base_resp_ps256_b64"], "ok": True,
             "note": "FAPI response signing base: status + content-digest"},
        ],
        "fapi_required_coverage": [],
        "fapi_content_digest": [],
        "fapi_alg": [],
        "fapi_ps256_verify": [],
        "fapi_es256_verify": [],
    }

    cov_rows = [
        ("request", ["@method", "@target-uri", "authorization", "content-digest"], "request covers the full mandated set"),
        ("request", ["@method", "@target-uri", "content-digest"], "request omits authorization (access token unbound)"),
        ("request", ["@method", "@target-uri", "authorization"], "request omits content-digest (body unbound)"),
        ("request", ["@target-uri", "authorization", "content-digest"], "request omits @method"),
        ("response", ["@status", "content-digest"], "response covers the mandated set"),
        ("response", ["@status"], "response omits content-digest (body unbound)"),
    ]
    for mt, cov, note in cov_rows:
        accept, reason = O.required_coverage_verdict(mt, cov)
        corpus["fapi_required_coverage"].append(
            {"message_type": mt, "covered_components": cov, "expect_accept": accept, "reason": reason, "note": note})

    cd_rows = [
        (cd_req, ["content-digest"], "correct sha-256 digest, covered"),
        (cd_sha512, ["content-digest"], "correct sha-512 digest, covered"),
        (cd_swapped, ["content-digest"], "digest of a different body (body-swap), covered"),
        (cd_req, ["@method"], "correct digest but content-digest not covered"),
        (cd_md5, ["content-digest"], "weak md5 digest algorithm"),
    ]
    for hv, cov, note in cd_rows:
        accept, reason = O.content_digest_verdict(body_b64, hv, cov)
        corpus["fapi_content_digest"].append(
            {"body_b64": body_b64, "content_digest": hv, "covered_components": cov,
             "expect_accept": accept, "reason": reason, "note": note})

    for alg, note in [("ps256", "PS256 (RSA-PSS SHA-256) allowed"), ("es256", "ES256 (ECDSA P-256) allowed"),
                      ("rs256", "RS256 (RSA PKCS#1) not FAPI-allowed"), ("rsa-v1_5-sha256", "raw PKCS#1 not allowed"),
                      ("hs256", "symmetric HS256 not allowed"), ("none", "unsigned not allowed")]:
        accept, reason = O.alg_verdict(alg)
        corpus["fapi_alg"].append({"alg": alg, "expect_accept": accept, "reason": reason, "note": note})

    corpus["fapi_ps256_verify"] = [
        {"signing_base_b64": m["base_ps256_b64"], "sig_hex": m["sig_ps256_hex"],
         "pub_spki_hex": m["rsa_pub_spki_hex"], "expect_valid": True, "note": "valid PS256 control"},
        {"signing_base_b64": m["base_ps256_b64"], "sig_hex": _flip(m["sig_ps256_hex"]),
         "pub_spki_hex": m["rsa_pub_spki_hex"], "expect_valid": False, "note": "tampered PS256 signature"},
        {"signing_base_b64": m["base_ps256_b64"], "sig_hex": m["sig_ps256_hex"],
         "pub_spki_hex": m["wrong_rsa_pub_spki_hex"], "expect_valid": False, "note": "PS256 under the wrong key"},
        {"signing_base_b64": m["base_resp_ps256_b64"], "sig_hex": m["sig_resp_ps256_hex"],
         "pub_spki_hex": m["rsa_pub_spki_hex"], "expect_valid": True, "note": "valid PS256 response control"},
    ]

    corpus["fapi_es256_verify"] = [
        {"signing_base_b64": m["base_es256_b64"], "sig_raw_hex": m["sig_es256_low_hex"],
         "pub_uncompressed_hex": m["ec_pub_uncompressed_hex"], "require_low_s": True,
         "expect_valid": True, "note": "valid ES256 control (low-s)"},
        {"signing_base_b64": m["base_es256_b64"], "sig_raw_hex": m["sig_es256_high_hex"],
         "pub_uncompressed_hex": m["ec_pub_uncompressed_hex"], "require_low_s": True,
         "expect_valid": False, "note": "high-s malleable twin, MUST reject under low-s"},
        {"signing_base_b64": m["base_es256_b64"], "sig_raw_hex": _flip(m["sig_es256_low_hex"]),
         "pub_uncompressed_hex": m["ec_pub_uncompressed_hex"], "require_low_s": True,
         "expect_valid": False, "note": "tampered ES256 signature"},
        {"signing_base_b64": m["base_es256_b64"], "sig_raw_hex": m["sig_es256_low_hex"],
         "pub_uncompressed_hex": m["wrong_ec_pub_uncompressed_hex"], "require_low_s": True,
         "expect_valid": False, "note": "ES256 under the wrong key"},
    ]
    return corpus


def main() -> int:
    m = json.load(open(MATERIAL, encoding="utf-8"))
    corpus = build(m)
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2)
        fh.write("\n")
    counts = {k: len(v) for k, v in corpus.items() if isinstance(v, list)}
    print("generated", OUT)
    print("  sections", counts, "total", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
