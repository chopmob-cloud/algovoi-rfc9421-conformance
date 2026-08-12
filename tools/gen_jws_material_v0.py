#!/usr/bin/env python3
"""One-time material freezer for the JSON Web Signature corpus (jws_v0).

Generates a fixed RSA-2048 + EC P-256 + Ed25519 test keyset (the PRIVATE keys and
a demonstration HMAC secret are held OFF-REPO at ~/.algovoi/keys/jws-material-v0.json),
signs a fixed payload with RS256 / ES256 / EdDSA, forges the classic HS256 key/alg
confusion token (the RSA public-key DER bytes used as the HMAC secret), and writes
the PUBLIC material (public JWKs + their kids + the frozen valid compact JWS
strings) to vectors/jws_material_v0.json.

Idempotent and frozen: if the private key file already exists it is loaded and the
keys are never regenerated (RSA keygen is not deterministic; ECDSA signing draws a
random nonce), so the corpus never churns. If the public material file already
exists it is left untouched. Delete a file only to intentionally re-freeze. The
gen script (gen_jws_v0.py) consumes this frozen material; only public JWKs and
signatures over public payloads ever ship.

Run once:  python tools/gen_jws_material_v0.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_jws as O  # noqa: E402

REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "jws_material_v0.json")
KEY_PATH = os.path.join(os.path.expanduser("~"), ".algovoi", "keys", "jws-material-v0.json")

RSA_KID, EC_KID, ED_KID = "jws-rsa-1", "jws-ec-1", "jws-ed25519-1"
PAYLOAD = b'{"iss":"did:web:algovoi.co.uk","sub":"agent-01","htm":"POST","htu":"https://api.example/resource"}'


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _int_b64u(n: int) -> str:
    return _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


# ---------------------------------------------------------------------------
# Key material: generate once, then always load the frozen private file.
# ---------------------------------------------------------------------------

def load_or_create_keys():
    if os.path.exists(KEY_PATH):
        d = json.load(open(KEY_PATH, encoding="utf-8"))
        rsa_key = serialization.load_pem_private_key(d["rsa_pem"].encode(), password=None)
        ec_key = serialization.load_pem_private_key(d["ec_pem"].encode(), password=None)
        ed_key = serialization.load_pem_private_key(d["ed_pem"].encode(), password=None)
        hmac_secret = bytes.fromhex(d["hmac_secret_hex"])
        return rsa_key, ec_key, ed_key, hmac_secret, False
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = Ed25519PrivateKey.generate()
    # A demonstration HMAC secret. It is never the accepted secret for any case;
    # the confusion vector MACs with the RSA public-key bytes, not this value.
    hmac_secret = os.urandom(32)
    pem = lambda k: k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    json.dump({"rsa_pem": pem(rsa_key), "ec_pem": pem(ec_key), "ed_pem": pem(ed_key),
               "hmac_secret_hex": hmac_secret.hex(),
               "note": "SECRET jws_v0 material signing keys + demo HMAC secret. Never commit."},
              open(KEY_PATH, "w", encoding="utf-8"), indent=2)
    return rsa_key, ec_key, ed_key, hmac_secret, True


# ---------------------------------------------------------------------------
# Public JWK builders (RFC 7517 / RFC 7518 / RFC 8037).
# ---------------------------------------------------------------------------

def rsa_jwk(pub, kid) -> dict:
    n = pub.public_numbers()
    return {"kty": "RSA", "n": _int_b64u(n.n), "e": _int_b64u(n.e), "kid": kid, "alg": "RS256"}


def ec_jwk(pub, kid) -> dict:
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _int_b64u(n.x), "y": _int_b64u(n.y),
            "kid": kid, "alg": "ES256"}


def ed_jwk(pub, kid) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw), "kid": kid, "alg": "EdDSA"}


def offcurve_ec_jwk(pub, kid) -> dict:
    """A P-256 JWK whose y is off the curve: a valid x, y+1. Reconstructing it must
    fail the on-curve check, so a verifier that trusts it before validation is
    caught."""
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _int_b64u(n.x), "y": _int_b64u((n.y + 1) % O.P256_P),
            "kid": kid, "alg": "ES256"}


# ---------------------------------------------------------------------------
# Compact JWS assembly over the fixed payload.
# ---------------------------------------------------------------------------

def rs256_token(rsa_key, kid=RSA_KID):
    header = {"alg": "RS256", "kid": kid}
    p = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pl = _b64u(PAYLOAD)
    si = (p + "." + pl).encode("ascii")
    sig = rsa_key.sign(si, padding.PKCS1v15(), hashes.SHA256())
    return p + "." + pl + "." + _b64u(sig)


def es256_token(ec_key, kid=EC_KID):
    from cryptography.hazmat.primitives.asymmetric import utils
    header = {"alg": "ES256", "kid": kid}
    p = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pl = _b64u(PAYLOAD)
    si = (p + "." + pl).encode("ascii")
    der = ec_key.sign(si, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    # JOSE fixed-width R||S (RFC 7518 3.4). Plain JOSE permits high-s; we do NOT
    # normalize to low-s here (that is a FAPI profile rule, out of jws_v0 scope).
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return p + "." + pl + "." + _b64u(raw)


def eddsa_token(ed_key, kid=ED_KID):
    header = {"alg": "EdDSA", "kid": kid}
    p = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pl = _b64u(PAYLOAD)
    si = (p + "." + pl).encode("ascii")
    sig = ed_key.sign(si)
    return p + "." + pl + "." + _b64u(sig)


def hs256_confusion_token(rsa_pub, kid=RSA_KID):
    """The classic key/alg confusion forgery (CVE-2015-9235 class): a token whose
    header claims HS256 and whose signature is HMAC-SHA256 keyed with the RSA
    public-key DER bytes that every verifier already holds. A verifier that reads
    alg from the token and reuses its RSA public key as an HMAC secret is forged."""
    header = {"alg": "HS256", "kid": kid}
    p = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pl = _b64u(PAYLOAD)
    si = (p + "." + pl).encode("ascii")
    rsa_pub_der = rsa_pub.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = hmac.new(rsa_pub_der, si, hashlib.sha256).digest()
    return p + "." + pl + "." + _b64u(sig)


def main() -> int:
    if os.path.exists(OUT):
        print("frozen material already present, leaving untouched:", OUT)
        return 0

    rsa_key, ec_key, ed_key, _hmac_secret, created = load_or_create_keys()
    rsa_pub, ec_pub, ed_pub = rsa_key.public_key(), ec_key.public_key(), ed_key.public_key()
    wrong_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    wrong_ec = ec.generate_private_key(ec.SECP256R1()).public_key()
    wrong_ed = Ed25519PrivateKey.generate().public_key()

    material = {
        "note": "Frozen jws_v0 material. Public JWKs + compact JWS strings only; private keys off-repo.",
        "payload_b64u": _b64u(PAYLOAD),
        "keys": {
            "rsa": rsa_jwk(rsa_pub, RSA_KID),
            "ec": ec_jwk(ec_pub, EC_KID),
            "ed25519": ed_jwk(ed_pub, ED_KID),
            "wrong_rsa": rsa_jwk(wrong_rsa, RSA_KID),
            "wrong_ec": ec_jwk(wrong_ec, EC_KID),
            "wrong_ed25519": ed_jwk(wrong_ed, ED_KID),
            "offcurve_ec": offcurve_ec_jwk(ec_pub, EC_KID),
        },
        "tokens": {
            "rs256": rs256_token(rsa_key),
            "es256": es256_token(ec_key),
            "eddsa": eddsa_token(ed_key),
            "hs256_confusion": hs256_confusion_token(rsa_pub),
        },
        "kids": {"rsa": RSA_KID, "ec": EC_KID, "ed25519": ED_KID},
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(material, fh, indent=2)
        fh.write("\n")
    print("froze jws material ->", OUT)
    print("  RSA-2048 + P-256 + Ed25519 test keys (private off-repo), RS256/ES256/EdDSA tokens frozen")
    print("  private keys + demo HMAC secret", "created" if created else "loaded", "at", KEY_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
