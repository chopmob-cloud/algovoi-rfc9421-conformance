#!/usr/bin/env python3
"""Python reference runner for the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).

Independently reproduces every verdict in the frozen corpus. The signing base comes
from the published reference verifier (build_signing_base); the PROFILE rules
(mandated coverage, Content-Digest body binding, algorithm restriction) and the
PS256/ES256 crypto are re-implemented here from the corpus `policy`, NOT imported
from the generator's oracle, so a runner passing is genuine agreement. The other
runners mirror these rules.

Exit 0 iff every case matches. Corpus: argv[1], else $ALGOVOI_FAPI, else repo.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import build_signing_base

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT = os.path.join(REPO, "corpus", "fapi_messagesigning_v0", "fapi_messagesigning_v0.json")


def _coverage_ok(message_type, covered, policy):
    key = "required_covered_request" if message_type == "request" else "required_covered_response"
    have = {c.lower() for c in covered}
    return all(r.lower() in have for r in policy[key])


def _content_digest_ok(body_b64, header_value, covered, policy):
    if "content-digest" not in {c.lower() for c in covered}:
        return False
    try:
        algorithm, _ = header_value.split("=", 1)
    except ValueError:
        return False
    algorithm = algorithm.strip().lower()
    if algorithm not in policy["content_digest_algorithms"]:
        return False
    body = base64.b64decode(body_b64)
    digest = hashlib.sha256(body).digest() if algorithm == "sha-256" else hashlib.sha512(body).digest()
    expect = f"{algorithm}=:{base64.b64encode(digest).decode('ascii')}:"
    return header_value.strip() == expect


def _ps256_ok(base, sig, spki_der):
    try:
        pub = serialization.load_der_public_key(spki_der)
        pub.verify(sig, base, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return True
    except Exception:
        return False


def _es256_ok(base, sig_raw, pub_uncompressed, require_low_s, policy):
    if len(sig_raw) != 64:
        return False
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    if require_low_s and s > int(policy["p256_n"]) // 2:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_uncompressed)
        pub.verify(utils.encode_dss_signature(r, s), base, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def run(corpus):
    policy = corpus["policy"]
    results = []

    for c in corpus["fapi_signing_base"]:
        src = c["in"]
        want = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        try:
            got = build_signing_base(
                covered_components=src["covered_components"], method=src.get("method"),
                target_uri=src.get("target_uri"), status=src.get("status"),
                headers=src.get("headers"), mode=c["mode"],
                signature_params_raw=c.get("signature_params_raw"))
            ok = c["ok"] and got == want
        except Exception:
            ok = not c["ok"]
        results.append(("fapi_signing_base", c["note"], ok))

    for c in corpus["fapi_required_coverage"]:
        results.append(("fapi_required_coverage", c["note"],
                        _coverage_ok(c["message_type"], c["covered_components"], policy) == c["expect_accept"]))

    for c in corpus["fapi_content_digest"]:
        results.append(("fapi_content_digest", c["note"],
                        _content_digest_ok(c["body_b64"], c["content_digest"], c["covered_components"], policy) == c["expect_accept"]))

    for c in corpus["fapi_alg"]:
        results.append(("fapi_alg", c["note"],
                        (c["alg"].lower() in policy["allowed_algs"]) == c["expect_accept"]))

    for c in corpus["fapi_ps256_verify"]:
        base = base64.b64decode(c["signing_base_b64"])
        ok = _ps256_ok(base, bytes.fromhex(c["sig_hex"]), bytes.fromhex(c["pub_spki_hex"]))
        results.append(("fapi_ps256_verify", c["note"], ok == c["expect_valid"]))

    for c in corpus["fapi_es256_verify"]:
        base = base64.b64decode(c["signing_base_b64"])
        ok = _es256_ok(base, bytes.fromhex(c["sig_raw_hex"]), bytes.fromhex(c["pub_uncompressed_hex"]),
                       c.get("require_low_s", False), policy)
        results.append(("fapi_es256_verify", c["note"], ok == c["expect_valid"]))

    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_FAPI", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (fapi): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
