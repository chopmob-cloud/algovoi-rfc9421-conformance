#!/usr/bin/env python3
"""Generate rfc9421_negative_v3.json: the v2 battery plus an RSA verify section.

v3 is a strict SUPERSET of v2 and adds the `rsa_verify` section, extending the
battery beyond the crypto-native Ed25519/ECDSA algorithms to the RSA algorithms
RFC 9421 registers -- `rsa-pss-sha512` (Section 3.3.1) and `rsa-v1_5-sha256`
(Section 3.3.2) -- which are what the RSA-dominant regulated industries (open
banking, eIDAS/government, healthcare, enterprise) actually run on.

RSA-PSS is randomised, so the valid signatures are generated once and FROZEN in
vectors/rsa_material_v0.json (a fixed test keypair + its signatures); this
generator only reads them, so the corpus stays reproducible. Verify is
deterministic. Every verdict is computed from the reference (Python
`cryptography`), never hand-asserted.

Case schema (rsa_verify):
  { "alg": "rsa-pss-sha512"|"rsa-v1_5-sha256", "signing_base_b64": "...",
    "sig_hex": "...", "pub_spki_hex": "...", "expect_valid": bool, "note": "..." }
pub_spki_hex is the RSA public key as SubjectPublicKeyInfo DER, hex-encoded.

Run:  python tools/gen_negative_v3.py
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V2 = os.path.join(ROOT, "corpus", "rfc9421_negative_v2", "rfc9421_negative_v2.json")
MATERIAL = os.path.join(ROOT, "vectors", "rsa_material_v0.json")
OUT = os.path.join(ROOT, "corpus", "rfc9421_negative_v3", "rfc9421_negative_v3.json")


def rsa_verdict(alg: str, base: bytes, sig: bytes, spki_der: bytes) -> bool:
    """Reference RSA verify verdict via cryptography (SPKI public key)."""
    try:
        pub = serialization.load_der_public_key(spki_der)
        if alg == "rsa-pss-sha512":
            pub.verify(sig, base, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
        elif alg == "rsa-v1_5-sha256":
            pub.verify(sig, base, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except Exception:
        return False


def main() -> int:
    d = json.load(open(V2, encoding="utf-8"))
    m = json.load(open(MATERIAL, encoding="utf-8"))
    d["name"] = "rfc9421_negative_v3"
    d["description"] = ("Signed cross-language negative battery for RFC 9421, v3. "
                        "Strict superset of rfc9421_negative_v2: adds the rsa_verify "
                        "section (rsa-pss-sha512 and rsa-v1_5-sha256) so the suite covers "
                        "the RSA algorithms RFC 9421 registers, not only Ed25519/ECDSA. "
                        "Verdicts computed from the reference (Python cryptography).")
    d["rsa_verify"] = []

    sb = m["signing_base_b64"]
    base = base64.b64decode(sb)
    pub = m["pub_spki_hex"]
    wrong = m["wrong_pub_spki_hex"]
    pss = m["sig_pss_sha512_hex"]
    v15 = m["sig_v15_sha256_hex"]

    # tampered base: flip the last byte, re-encode; the frozen signature no longer matches
    tb = bytearray(base); tb[-1] ^= 0x01
    tampered_b64 = base64.b64encode(bytes(tb)).decode()
    # tampered signature: flip the last byte of each signature
    def flip(hexsig: str) -> str:
        b = bytearray.fromhex(hexsig); b[-1] ^= 0x01; return b.hex()

    cases = [
        ("rsa-pss-sha512", sb, pss, pub, "valid rsa-pss-sha512 control"),
        ("rsa-pss-sha512", sb, flip(pss), pub, "tampered rsa-pss-sha512 signature, MUST reject"),
        ("rsa-pss-sha512", sb, pss, wrong, "rsa-pss-sha512 under the wrong key, MUST reject"),
        ("rsa-pss-sha512", tampered_b64, pss, pub, "rsa-pss-sha512 over a tampered base, MUST reject"),
        ("rsa-v1_5-sha256", sb, v15, pub, "valid rsa-v1_5-sha256 control"),
        ("rsa-v1_5-sha256", sb, flip(v15), pub, "tampered rsa-v1_5-sha256 signature, MUST reject"),
        ("rsa-v1_5-sha256", sb, v15, wrong, "rsa-v1_5-sha256 under the wrong key, MUST reject"),
    ]
    for alg, sbb, sig_hex, pub_hex, note in cases:
        verdict = rsa_verdict(alg, base64.b64decode(sbb), bytes.fromhex(sig_hex), bytes.fromhex(pub_hex))
        d["rsa_verify"].append({"alg": alg, "signing_base_b64": sbb, "sig_hex": sig_hex,
                                "pub_spki_hex": pub_hex, "expect_valid": verdict, "note": note})

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(d, open(OUT, "w", encoding="utf-8"), indent=1)
    counts = {k: len(v) for k, v in d.items() if isinstance(v, list)}
    print("wrote", OUT)
    print("counts:", counts, "total", sum(counts.values()))
    valids = sum(1 for c in d["rsa_verify"] if c["expect_valid"])
    print(f"rsa_verify: {len(d['rsa_verify'])} cases, {valids} valid controls, {len(d['rsa_verify'])-valids} rejects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
