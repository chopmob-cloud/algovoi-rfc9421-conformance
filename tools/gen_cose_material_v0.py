#!/usr/bin/env python3
"""One-time material freezer for the COSE_Sign1 corpus (cose_v0).

Generates a fixed EC P-256 + Ed25519 + RSA-2048 test keyset (the PRIVATE keys are
held OFF-REPO at ~/.algovoi/keys/cose-material-v0.json), signs a fixed payload as a
COSE_Sign1 (RFC 9052 Section 4.2) with ES256 / EdDSA / PS256 (RFC 9053), and builds
the crafted security messages the corpus needs a real signature for (alg carried in
the unprotected header only, crit honored, crit unknown). It then writes the PUBLIC
material (public keys as COSE_Key hex plus a JWK-style view, their kids, and the
frozen COSE_Sign1 messages as hex) to vectors/cose_material_v0.json.

A COSE_Sign1 is the CBOR analog of a compact JWS: a CBOR array of four items
[protected: bstr, unprotected: map, payload: bstr/nil, signature: bstr], optionally
CBOR-tagged 18. The signature is over the Sig_structure = ["Signature1", protected
(bstr), external_aad (bstr, empty here), payload (bstr)], encoded as deterministic
CBOR (RFC 8949 Section 4.2), then signed with the algorithm. Header label 1 is alg,
label 2 is crit, label 4 is kid.

Idempotent and frozen: if the private key file already exists it is loaded and the
keys are never regenerated (RSA keygen is not deterministic; ECDSA and RSASSA-PSS
draw a random nonce/salt), so the corpus never churns. If the public material file
already exists it is left untouched. Delete a file only to intentionally re-freeze.
The gen script (gen_cose_v0.py) consumes this frozen material; only public keys and
signatures over public payloads ever ship.

Run once:  python tools/gen_cose_material_v0.py
"""
from __future__ import annotations

import base64
import json
import os
import sys

import cbor2
from cbor2 import CBORTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "cose_material_v0.json")
KEY_PATH = os.path.join(os.path.expanduser("~"), ".algovoi", "keys", "cose-material-v0.json")

EC_KID, ED_KID, RSA_KID = b"cose-ec-1", b"cose-ed25519-1", b"cose-rsa-1"

# COSE header labels (RFC 9052 Section 3.1) and algorithm ids (RFC 9053).
HDR_ALG, HDR_CRIT, HDR_KID = 1, 2, 4
ALG_ES256, ALG_EDDSA, ALG_PS256 = -7, -8, -37
COSE_SIGN1_TAG = 18

PAYLOAD = b'{"iss":"did:web:algovoi.co.uk","sub":"agent-01","htm":"POST","htu":"https://api.example/resource"}'

# A crit label the verifier does not understand: an unregistered private-use int.
UNKNOWN_CRIT_LABEL = -70000


def _hexb(b: bytes) -> str:
    return b.hex()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 Section 4.2) and the COSE_Sign1 assembly.
# ---------------------------------------------------------------------------

def dcbor(obj) -> bytes:
    """Deterministic CBOR encode (RFC 8949 Section 4.2): shortest-form ints,
    definite lengths, bytewise-lexicographic map key order. cbor2's canonical
    mode implements exactly this ordering."""
    return cbor2.dumps(obj, canonical=True)


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """The COSE_Sign1 signing preimage (RFC 9052 Section 4.4): the array
    ["Signature1", protected (bstr), external_aad (bstr), payload (bstr)] encoded
    as deterministic CBOR. protected is the exact bstr content of the protected
    header (a serialized map, or empty for an empty protected header)."""
    return dcbor(["Signature1", protected, external_aad, payload])


def protected_bytes(phdr_map: dict) -> bytes:
    """Serialize a protected header map to its bstr content. An empty protected
    header is the zero-length byte string, never an encoded empty map (RFC 9052
    Section 3)."""
    return b"" if not phdr_map else dcbor(phdr_map)


def sign_es256(ec_key, sig_struct: bytes) -> bytes:
    der = ec_key.sign(sig_struct, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    # COSE ECDSA is fixed-width R || S, 32 bytes each (RFC 9053 Section 2.1), the
    # same layout as JOSE. High-s is permitted; low-s is a FAPI rule, not enforced.
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_eddsa(ed_key, sig_struct: bytes) -> bytes:
    return ed_key.sign(sig_struct)


def sign_ps256(rsa_key, sig_struct: bytes) -> bytes:
    # RSASSA-PSS with SHA-256 and a salt length equal to the hash length (RFC 9053
    # Section 6.2 / RFC 8230).
    return rsa_key.sign(sig_struct, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=32), hashes.SHA256())


def sign1(protected_map: dict, unprotected_map: dict, payload: bytes, signer, kind: str) -> str:
    """Build a full tagged COSE_Sign1 and return its hex. `signer` is the private
    key; `kind` selects the algorithm signer."""
    prot = protected_bytes(protected_map)
    preimage = sig_structure(prot, payload)
    if kind == "es256":
        sig = sign_es256(signer, preimage)
    elif kind == "eddsa":
        sig = sign_eddsa(signer, preimage)
    elif kind == "ps256":
        sig = sign_ps256(signer, preimage)
    else:
        raise ValueError(kind)
    msg = [prot, unprotected_map, payload, sig]
    return cbor2.dumps(CBORTag(COSE_SIGN1_TAG, msg), canonical=True).hex()


# ---------------------------------------------------------------------------
# Key material: generate once, then always load the frozen private file.
# ---------------------------------------------------------------------------

def load_or_create_keys():
    if os.path.exists(KEY_PATH):
        d = json.load(open(KEY_PATH, encoding="utf-8"))
        ec_key = serialization.load_pem_private_key(d["ec_pem"].encode(), password=None)
        ed_key = serialization.load_pem_private_key(d["ed_pem"].encode(), password=None)
        rsa_key = serialization.load_pem_private_key(d["rsa_pem"].encode(), password=None)
        return ec_key, ed_key, rsa_key, False
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = Ed25519PrivateKey.generate()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = lambda k: k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    json.dump({"ec_pem": pem(ec_key), "ed_pem": pem(ed_key), "rsa_pem": pem(rsa_key),
               "note": "SECRET cose_v0 material signing keys. Never commit."},
              open(KEY_PATH, "w", encoding="utf-8"), indent=2)
    return ec_key, ed_key, rsa_key, True


# ---------------------------------------------------------------------------
# Public key views: a COSE_Key hex (RFC 9052 Section 7) plus explicit fields the
# oracle/runner reconstruct from. Only public material ships.
# ---------------------------------------------------------------------------

def ec2_key(pub, kid, x=None, y=None) -> dict:
    n = pub.public_numbers()
    xb = (x if x is not None else n.x).to_bytes(32, "big")
    yb = (y if y is not None else n.y).to_bytes(32, "big")
    cose = {1: 2, 2: kid, 3: ALG_ES256, -1: 1, -2: xb, -3: yb}  # kty EC2, crv P-256
    return {"kty": "EC2", "crv": "P-256", "alg": "ES256", "kid": kid.decode("ascii"),
            "x": _hexb(xb), "y": _hexb(yb), "cose_key_hex": dcbor(cose).hex()}


def okp_key(pub, kid) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cose = {1: 1, 2: kid, 3: ALG_EDDSA, -1: 6, -2: raw}  # kty OKP, crv Ed25519
    return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid.decode("ascii"),
            "x": _hexb(raw), "cose_key_hex": dcbor(cose).hex()}


def rsa_key_pub(pub, kid) -> dict:
    n = pub.public_numbers()
    nb = n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")
    eb = n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")
    cose = {1: 3, 2: kid, 3: ALG_PS256, -1: nb, -2: eb}  # kty RSA
    return {"kty": "RSA", "alg": "PS256", "kid": kid.decode("ascii"),
            "n": _hexb(nb), "e": _hexb(eb), "cose_key_hex": dcbor(cose).hex()}


def offcurve_ec2(pub, kid) -> dict:
    """A P-256 key whose y is off the curve (valid x, y+1). Reconstructing it must
    fail the on-curve check, catching a verifier that trusts it before validation."""
    n = pub.public_numbers()
    return ec2_key(pub, kid, x=n.x, y=n.y + 1)


def main() -> int:
    if os.path.exists(OUT):
        print("frozen material already present, leaving untouched:", OUT)
        return 0

    ec_key, ed_key, rsa_key, created = load_or_create_keys()
    ec_pub, ed_pub, rsa_pub = ec_key.public_key(), ed_key.public_key(), rsa_key.public_key()
    wrong_ec = ec.generate_private_key(ec.SECP256R1()).public_key()
    wrong_ed = Ed25519PrivateKey.generate().public_key()
    wrong_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    material = {
        "note": "Frozen cose_v0 material. Public COSE keys + COSE_Sign1 hex only; private keys off-repo.",
        "payload_hex": _hexb(PAYLOAD),
        "labels": {"alg": HDR_ALG, "crit": HDR_CRIT, "kid": HDR_KID},
        "algs": {"ES256": ALG_ES256, "EdDSA": ALG_EDDSA, "PS256": ALG_PS256},
        "keys": {
            "ec": ec2_key(ec_pub, EC_KID),
            "ed25519": okp_key(ed_pub, ED_KID),
            "rsa": rsa_key_pub(rsa_pub, RSA_KID),
            "wrong_ec": ec2_key(wrong_ec, EC_KID),
            "wrong_ed25519": okp_key(wrong_ed, ED_KID),
            "wrong_rsa": rsa_key_pub(wrong_rsa, RSA_KID),
            "offcurve_ec": offcurve_ec2(ec_pub, EC_KID),
        },
        "messages": {
            "es256": sign1({HDR_ALG: ALG_ES256, HDR_KID: EC_KID}, {}, PAYLOAD, ec_key, "es256"),
            "eddsa": sign1({HDR_ALG: ALG_EDDSA, HDR_KID: ED_KID}, {}, PAYLOAD, ed_key, "eddsa"),
            "ps256": sign1({HDR_ALG: ALG_PS256, HDR_KID: RSA_KID}, {}, PAYLOAD, rsa_key, "ps256"),
            # alg carried ONLY in the unprotected header, protected is empty. The
            # signature is genuine over the empty-protected Sig_structure, so a
            # verifier that trusts an unprotected alg would accept; ours rejects.
            "es256_alg_unprotected": sign1({}, {HDR_ALG: ALG_ES256, HDR_KID: EC_KID},
                                           PAYLOAD, ec_key, "es256"),
            # crit lists label 1 (alg), which the verifier understands: honored, accept.
            "es256_crit_honored": sign1({HDR_ALG: ALG_ES256, HDR_CRIT: [HDR_ALG], HDR_KID: EC_KID},
                                        {}, PAYLOAD, ec_key, "es256"),
            # crit lists an unregistered label the verifier does not understand: reject.
            "es256_crit_unknown": sign1({HDR_ALG: ALG_ES256, HDR_CRIT: [UNKNOWN_CRIT_LABEL],
                                         HDR_KID: EC_KID}, {}, PAYLOAD, ec_key, "es256"),
        },
        "kids": {"ec": EC_KID.decode("ascii"), "ed25519": ED_KID.decode("ascii"),
                 "rsa": RSA_KID.decode("ascii")},
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(material, fh, indent=2)
        fh.write("\n")
    print("froze cose material ->", OUT)
    print("  P-256 + Ed25519 + RSA-2048 test keys (private off-repo), ES256/EdDSA/PS256 messages frozen")
    print("  private keys", "created" if created else "loaded", "at", KEY_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
