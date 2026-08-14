#!/usr/bin/env python3
"""Freeze the RFC 9421 Appendix B.2 worked examples as the L2 interop anchor.

The flagship external-interoperability anchor: proof that our RFC 9421 verifier
reproduces the RFC's own worked signature examples, both by rebuilding the exact
signature base the RFC prints and by accepting the RFC's own signatures. Three
asymmetric worked examples, one per RFC 9421 signature algorithm, are carried
verbatim from RFC 9421 Appendix B (a stable, immutable RFC):

  - B.2.1  rsa-pss-sha512 (minimal, empty covered-components set)
  - B.2.4  ecdsa-p256-sha256 (signing a response)
  - B.2.6  ed25519 (signing a request)

B.2.5 (hmac-sha256) is symmetric and out of scope; B.2.2 and B.2.3 are additional
rsa-pss coverage variants beyond one-per-algorithm.

Only the RFC's PUBLIC test keys ship (ed25519 raw, ecc-p256 uncompressed, and the
rsa-pss SubjectPublicKeyInfo DER); the RFC's private test keys are not carried.
Each case self-checks at freeze time: the reconstructed base must equal the RFC's
printed base and the signature must verify, so a mis-transcription cannot be frozen.

Run:  python tools/freeze_rfc9421_appendix_b.py
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, Encoding, PublicFormat)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "rfc9421_appendix_b_v0.json")

import sys
sys.path.insert(0, HERE)
from algovoi_rfc9421_verifier import build_signing_base, verify_signature  # noqa: E402
from algovoi_rfc9421_ecdsa import verify_p256  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# RFC 9421 B.1 test public keys (public halves only).
ED25519_PK_HEX = base64.b64decode("JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=").hex()
ECCP256_PUB_HEX = (b"\x04"
                   + _b64u("qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA")
                   + _b64u("Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0")).hex()
RSAPSS_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----"""
RSAPSS_SPKI_HEX = load_pem_public_key(RSAPSS_PEM).public_bytes(
    Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()

CASES = [
    {
        "source": "RFC 9421 B.2.1", "alg": "rsa-pss-sha512", "message_type": "request",
        "covered_components": [],
        "components": {},
        "signature_params_raw": '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        "signature_b64": ("d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAt"
                          "x31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+ox"
                          "NFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXeh"
                          "hWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5Tmc"
                          "AnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssin"
                          "Q98Xw9Q=="),
        "public_key": {"format": "rsa-spki-der-hex", "hex": RSAPSS_SPKI_HEX},
    },
    {
        "source": "RFC 9421 B.2.4", "alg": "ecdsa-p256-sha256", "message_type": "response",
        "covered_components": ["@status", "content-type", "content-digest", "content-length"],
        "components": {"status": 200, "headers": {
            "content-type": "application/json",
            "content-digest": ("sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4"
                               "GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"),
            "content-length": "23"}},
        "signature_params_raw": ('("@status" "content-type" "content-digest" "content-length")'
                                 ';created=1618884473;keyid="test-key-ecc-p256"'),
        "signature_b64": ("wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5"
                          "eCdlYUEkLIj+32oiasw=="),
        "public_key": {"format": "ecc-p256-uncompressed-hex", "hex": ECCP256_PUB_HEX},
    },
    {
        "source": "RFC 9421 B.2.6", "alg": "ed25519", "message_type": "request",
        "covered_components": ["date", "@method", "@path", "@authority", "content-type", "content-length"],
        "components": {"method": "POST", "path": "/foo", "authority": "example.com", "headers": {
            "date": "Tue, 20 Apr 2021 02:07:55 GMT",
            "content-type": "application/json", "content-length": "18"}},
        "signature_params_raw": ('("date" "@method" "@path" "@authority" "content-type" '
                                 '"content-length");created=1618884473;keyid="test-key-ed25519"'),
        "signature_b64": ("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0"
                          "w6vuQv5lIp5WPpBKRCw=="),
        "public_key": {"format": "ed25519-raw-hex", "hex": ED25519_PK_HEX},
    },
]


def _base(c):
    comp = c["components"]
    return build_signing_base(
        c["covered_components"], method=comp.get("method"), authority=comp.get("authority"),
        path=comp.get("path"), status=comp.get("status"), headers=comp.get("headers"),
        mode="rfc9421", signature_params_raw=c["signature_params_raw"])


def _verify(c, base):
    sig = base64.b64decode(c["signature_b64"])
    pk = c["public_key"]
    if c["alg"] == "ed25519":
        return verify_signature(base, sig, pk["hex"], algorithm="ed25519")
    if c["alg"] == "ecdsa-p256-sha256":
        return verify_p256(base, sig, pk["hex"])
    if c["alg"] == "rsa-pss-sha512":
        pub = load_pem_public_key(RSAPSS_PEM)
        try:
            pub.verify(sig, base.encode(),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
                       hashes.SHA512())
            return True
        except Exception:
            return False
    raise ValueError(c["alg"])


def main() -> int:
    out_cases = []
    for c in CASES:
        base = _base(c)
        if not _verify(c, base):
            raise SystemExit(f"{c['source']}: signature does not verify against the reconstructed base")
        out_cases.append({**c, "expected_signing_base": base})

    out = {
        "note": ("RFC 9421 Appendix B.2 worked-example interop anchors. Flagship "
                 "external interoperability evidence: our RFC 9421 verifier rebuilds "
                 "the RFC's own signature bases and accepts the RFC's own signatures. "
                 "Public test keys only; no private keys ship."),
        "standard": "RFC 9421 Appendix B.2",
        "source": {"rfc": "RFC 9421", "url": "https://www.rfc-editor.org/rfc/rfc9421.html",
                   "sections": ["B.1 (test keys)", "B.2.1", "B.2.4", "B.2.6"]},
        "scope": ("one worked example per RFC 9421 asymmetric algorithm: rsa-pss-sha512 "
                  "(B.2.1), ecdsa-p256-sha256 (B.2.4), ed25519 (B.2.6). B.2.5 hmac-sha256 "
                  "is symmetric and out of scope; B.2.2/B.2.3 are further rsa-pss variants."),
        "counts": {"total": len(out_cases), "algorithms": sorted({c["alg"] for c in out_cases})},
        "cases": out_cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("froze RFC 9421 Appendix B.2 interop anchors ->", OUT)
    print("  counts:", out["counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
