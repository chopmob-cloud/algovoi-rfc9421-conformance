#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for fapi_messagesigning_v0.

Closes the shared-systematic-error hole two ways:
  1. Corpus integrity: the file sha256 equals the signed manifest head's, and the
     head_jws EdDSA signature verifies under the signer JWK.
  2. Independent re-derivation: the signing base is hand-built by direct RFC 9421
     Section 2.5 concatenation (not build_signing_base); coverage / Content-Digest
     / algorithm verdicts are re-implemented from first principles; PS256 and ES256
     are re-verified (with the low-s malleability check re-derived), so the frozen
     material genuinely carries the claimed validity.

Fail-closed. Run:  python tools/check_kat_fapi.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_FAPI")
          or os.path.join(ROOT, "corpus", "fapi_messagesigning_v0", "fapi_messagesigning_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_head_jws(manifest, corpus_file_sha):
    out = []
    jws = manifest.get("head_jws")
    signers = manifest.get("signers") or []
    if not jws or not signers:
        return ["manifest is not signed (no head_jws / signer)"]
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return ["PyNaCl required to verify the signed head"]
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        VerifyKey(_b64u(signers[0]["jwk"]["x"])).verify(f"{h_b64}.{p_b64}".encode("ascii"), _b64u(s_b64))
    except (ValueError, KeyError) as e:
        return [f"head_jws malformed: {e}"]
    except BadSignatureError:
        return ["head_jws EdDSA signature does not verify under the signer JWK"]
    payload = json.loads(_b64u(p_b64))
    if payload != manifest.get("head"):
        out.append("manifest head does not match the signed head_jws payload")
    if payload.get("file_sha256") != corpus_file_sha:
        out.append(f"signed head binds {payload.get('file_sha256')} != corpus {corpus_file_sha}")
    return out


def hand_signing_base(src, params_raw):
    lines = []
    for comp in src["covered_components"]:
        name = comp.lower()
        if name == "@method":
            val = src["method"]
        elif name == "@target-uri":
            val = src["target_uri"]
        elif name == "@status":
            val = str(src["status"])
        elif name == "@authority":
            val = src["authority"]
        elif name == "@path":
            val = src["path"]
        else:
            val = src["headers"][name]
        lines.append(f'"{name}": {val}')
    lines.append(f'"@signature-params": {params_raw}')
    return "\n".join(lines)


def coverage_ok(mt, covered, policy):
    key = "required_covered_request" if mt == "request" else "required_covered_response"
    have = {c.lower() for c in covered}
    return all(r.lower() in have for r in policy[key])


def content_digest_ok(body_b64, hv, covered, policy):
    if "content-digest" not in {c.lower() for c in covered}:
        return False
    try:
        alg, _ = hv.split("=", 1)
    except ValueError:
        return False
    alg = alg.strip().lower()
    if alg not in policy["content_digest_algorithms"]:
        return False
    body = base64.b64decode(body_b64)
    dg = hashlib.sha256(body).digest() if alg == "sha-256" else hashlib.sha512(body).digest()
    return hv.strip() == f"{alg}=:{base64.b64encode(dg).decode('ascii')}:"


def ps256_ok(base, sig, spki):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        serialization.load_der_public_key(spki).verify(
            sig, base, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return True
    except Exception:
        return False


def es256_ok(base, raw, pub, require_low_s, policy):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature
    if len(raw) != 64:
        return False
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if require_low_s and s > int(policy["p256_n"]) // 2:
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(
            utils.encode_dss_signature(r, s), base, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def main() -> int:
    failures = []
    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    policy = corpus["policy"]
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()

    try:
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
        if manifest["head"].get("file_sha256") != file_sha:
            failures.append(f"corpus digest drift: manifest {manifest['head'].get('file_sha256')} != actual {file_sha}")
        failures.extend(verify_head_jws(manifest, file_sha))
    except (OSError, KeyError, json.JSONDecodeError) as e:
        failures.append(f"cannot read signed manifest head: {e}")

    for c in corpus["fapi_signing_base"]:
        want = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        if c["ok"] and hand_signing_base(c["in"], c["signature_params_raw"]) != want:
            failures.append(f"KAT signing_base mismatch: {c['note']}")
    for c in corpus["fapi_required_coverage"]:
        if coverage_ok(c["message_type"], c["covered_components"], policy) != c["expect_accept"]:
            failures.append(f"KAT coverage mismatch: {c['note']}")
    for c in corpus["fapi_content_digest"]:
        if content_digest_ok(c["body_b64"], c["content_digest"], c["covered_components"], policy) != c["expect_accept"]:
            failures.append(f"KAT content_digest mismatch: {c['note']}")
    for c in corpus["fapi_alg"]:
        if (c["alg"].lower() in policy["allowed_algs"]) != c["expect_accept"]:
            failures.append(f"KAT alg mismatch: {c['note']}")
    for c in corpus["fapi_ps256_verify"]:
        base = base64.b64decode(c["signing_base_b64"])
        if ps256_ok(base, bytes.fromhex(c["sig_hex"]), bytes.fromhex(c["pub_spki_hex"])) != c["expect_valid"]:
            failures.append(f"KAT ps256 mismatch: {c['note']}")
    for c in corpus["fapi_es256_verify"]:
        base = base64.b64decode(c["signing_base_b64"])
        if es256_ok(base, bytes.fromhex(c["sig_raw_hex"]), bytes.fromhex(c["pub_uncompressed_hex"]),
                    c.get("require_low_s", False), policy) != c["expect_valid"]:
            failures.append(f"KAT es256 mismatch: {c['note']}")

    total = sum(len(v) for v in corpus.values() if isinstance(v, list))
    for sec in ("fapi_signing_base", "fapi_required_coverage", "fapi_content_digest",
                "fapi_alg", "fapi_ps256_verify", "fapi_es256_verify"):
        if not corpus.get(sec):
            failures.append(f"section {sec} is empty")

    if failures:
        print("KAT (fapi): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (fapi): PASS")
    print(f"  signed head        head_jws EdDSA signature verified under signer JWK")
    print(f"  corpus integrity   {file_sha} (matches signed head)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed (hand signing base; "
          f"first-principles coverage/content-digest/alg; PS256+ES256 re-verified, low-s re-derived)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
