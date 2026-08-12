#!/usr/bin/env python3
"""One-time material freezer for the FAPI 2.0 Message Signing corpus.

Generates a fixed RSA-2048 + P-256 test keypair (the PRIVATE keys are held
OFF-REPO at ~/.algovoi/keys/fapi-material-v0.json), builds the FAPI request and
response RFC 9421 signing bases, signs them with PS256 (RSA-PSS SHA-256) and ES256
(ECDSA P-256), and writes the PUBLIC material (public keys + frozen signatures +
bases + bodies + Content-Digests) to vectors/fapi_material_v0.json.

Idempotent and frozen: if the material file already exists it is left untouched,
so the corpus never churns (PS256 salt is randomised, so re-signing would change
the bytes). Delete the material file only to intentionally re-freeze. The gen
script (gen_fapi_v0.py) consumes this frozen material; only public keys and
signatures ever ship.

Run once:  python tools/gen_fapi_material_v0.py
"""
from __future__ import annotations

import base64
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import build_signing_base

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_fapi as O  # noqa: E402

REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "fapi_material_v0.json")
KEY_PATH = os.path.join(os.path.expanduser("~"), ".algovoi", "keys", "fapi-material-v0.json")

BODY = b'{"instructedAmount":{"currency":"GBP","amount":"1250.00"},"creditor":"GB33BUKB20201555555555"}'
RESP_BODY = b'{"paymentId":"pay-9f3c","status":"AcceptedSettlementInProgress"}'


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def load_or_create_keys():
    if os.path.exists(KEY_PATH):
        d = json.load(open(KEY_PATH, encoding="utf-8"))
        rsa_key = serialization.load_pem_private_key(d["rsa_pem"].encode(), password=None)
        ec_key = serialization.load_pem_private_key(d["ec_pem"].encode(), password=None)
        return rsa_key, ec_key
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = lambda k: k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    json.dump({"rsa_pem": pem(rsa_key), "ec_pem": pem(ec_key),
               "note": "SECRET FAPI material signing keys. Never commit."},
              open(KEY_PATH, "w", encoding="utf-8"), indent=2)
    return rsa_key, ec_key


def spki_hex(pub) -> str:
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo).hex()


def ec_uncompressed_hex(pub) -> str:
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint).hex()


def base_bytes(covered, keyid, alg, *, method=None, target_uri=None, status=None, headers=None):
    raw = O.signature_params_raw(covered, keyid, alg)
    kw = dict(covered_components=covered, headers=headers, mode="rfc9421", signature_params_raw=raw)
    if method is not None:
        kw["method"] = method
    if target_uri is not None:
        kw["target_uri"] = target_uri
    if status is not None:
        kw["status"] = status
    b = build_signing_base(**{k: v for k, v in kw.items() if v is not None})
    return b.encode("utf-8") if isinstance(b, str) else b


def es256_raw(ec_key, base: bytes) -> tuple[str, str]:
    """Return (low_s_raw_hex, high_s_raw_hex) 64-byte r||s ECDSA signatures."""
    der = ec_key.sign(base, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    n = int(O.POLICY["p256_n"])
    if s > n // 2:
        s = n - s  # normalise to low-s
    low = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    high = r.to_bytes(32, "big") + (n - s).to_bytes(32, "big")
    return low.hex(), high.hex()


def main() -> int:
    if os.path.exists(OUT):
        print("frozen material already present, leaving untouched:", OUT)
        return 0

    rsa_key, ec_key = load_or_create_keys()
    rsa_pub, ec_pub = rsa_key.public_key(), ec_key.public_key()
    wrong_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    wrong_ec = ec.generate_private_key(ec.SECP256R1()).public_key()

    rsa_kid, ec_kid = "fapi-rsa-1", "fapi-ec-1"
    cd_req = O.compute_content_digest(BODY, "sha-256")
    cd_resp = O.compute_content_digest(RESP_BODY, "sha-256")

    req_covered = ["@method", "@target-uri", "authorization", "content-digest"]
    req_headers = {"authorization": "Bearer eyJhbGciOiJ...redacted", "content-digest": cd_req}
    resp_covered = ["@status", "content-digest"]
    resp_headers = {"content-digest": cd_resp}

    base_ps = base_bytes(req_covered, rsa_kid, "ps256", method="POST",
                         target_uri="https://api.bank.example/payments", headers=req_headers)
    base_es = base_bytes(req_covered, ec_kid, "es256", method="POST",
                         target_uri="https://api.bank.example/payments", headers=req_headers)
    base_resp = base_bytes(resp_covered, rsa_kid, "ps256", status=200, headers=resp_headers)

    sig_ps = rsa_key.sign(base_ps, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    sig_resp = rsa_key.sign(base_resp, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    es_low, es_high = es256_raw(ec_key, base_es)

    material = {
        "note": "Frozen FAPI 2.0 message-signing material. Public keys + signatures only.",
        "rsa_kid": rsa_kid, "ec_kid": ec_kid,
        "rsa_pub_spki_hex": spki_hex(rsa_pub),
        "wrong_rsa_pub_spki_hex": spki_hex(wrong_rsa),
        "ec_pub_uncompressed_hex": ec_uncompressed_hex(ec_pub),
        "wrong_ec_pub_uncompressed_hex": ec_uncompressed_hex(wrong_ec),
        "request_covered": req_covered, "response_covered": resp_covered,
        "body_b64": _b64(BODY), "content_digest_request": cd_req,
        "resp_body_b64": _b64(RESP_BODY), "content_digest_response": cd_resp,
        "base_ps256_b64": _b64(base_ps), "sig_ps256_hex": sig_ps.hex(),
        "base_es256_b64": _b64(base_es), "sig_es256_low_hex": es_low, "sig_es256_high_hex": es_high,
        "base_resp_ps256_b64": _b64(base_resp), "sig_resp_ps256_hex": sig_resp.hex(),
        "signature_params_ps256": O.signature_params_raw(req_covered, rsa_kid, "ps256"),
        "signature_params_es256": O.signature_params_raw(req_covered, ec_kid, "es256"),
        "signature_params_resp": O.signature_params_raw(resp_covered, rsa_kid, "ps256"),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(material, fh, indent=2)
        fh.write("\n")
    print("froze FAPI material ->", OUT)
    print("  RSA-2048 + P-256 test keys (private off-repo), PS256 + ES256 signatures frozen")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
