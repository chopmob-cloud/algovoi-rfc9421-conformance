#!/usr/bin/env python3
"""RFC 9421 Appendix B.2 interop gate: reproduce the RFC's own worked examples.

The flagship external interoperability proof for the L2 stage. Where the 12-way
corpus proves twelve of our runners agree on our crafted battery, this proves our
RFC 9421 verifier reproduces the RFC's own worked signature examples
(vectors/rfc9421_appendix_b_v0.json, one per asymmetric algorithm). Each case is
checked two ways, fail-closed:

  1. Builder: build_signing_base(...) rebuilds the exact signature base the RFC
     prints for that example (byte-for-byte), from the covered components and
     message inputs.
  2. Verifier: our signature verify accepts the RFC's own signature over that base
     under the RFC's public test key -- ed25519 (verify_signature), ecdsa-p256
     (verify_p256), and rsa-pss-sha512 (RSASSA-PSS/SHA-512 via cryptography).

Rebuilding the RFC's base AND accepting the RFC's signature is two-sided interop
with the standard's own vectors, not agreement with ourselves.

Fail-closed: a base that does not match the RFC's printed base, or a signature that
does not verify, exits non-zero.

Requires: the algovoi_rfc9421 verifier packages and cryptography.
Run:  python tools/check_rfc9421_appendix_b.py [anchors.json]
"""
from __future__ import annotations

import base64
import json
import os
import sys

from algovoi_rfc9421_verifier import build_signing_base, verify_signature
from algovoi_rfc9421_ecdsa import verify_p256
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANCHORS = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(ROOT, "vectors", "rfc9421_appendix_b_v0.json"))


def rebuild_base(c):
    comp = c["components"]
    return build_signing_base(
        c["covered_components"], method=comp.get("method"), authority=comp.get("authority"),
        path=comp.get("path"), status=comp.get("status"), headers=comp.get("headers"),
        mode="rfc9421", signature_params_raw=c["signature_params_raw"])


def verify_case(c, base):
    sig = base64.b64decode(c["signature_b64"])
    pk = c["public_key"]
    if c["alg"] == "ed25519":
        return bool(verify_signature(base, sig, pk["hex"], algorithm="ed25519"))
    if c["alg"] == "ecdsa-p256-sha256":
        return bool(verify_p256(base, sig, pk["hex"]))
    if c["alg"] == "rsa-pss-sha512":
        pub = load_der_public_key(bytes.fromhex(pk["hex"]))
        try:
            pub.verify(sig, base.encode(),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
                       hashes.SHA512())
            return True
        except Exception:
            return False
    return False


def main() -> int:
    data = json.load(open(ANCHORS, encoding="utf-8"))
    if data.get("standard", "").split()[0:2] != ["RFC", "9421"]:
        print("RFC 9421 App-B gate: FAIL -- anchors are not RFC 9421 Appendix B")
        return 1
    cases = data.get("cases") or []
    if not cases:
        print("RFC 9421 App-B gate: FAIL -- no anchor cases")
        return 1

    failures = []
    for c in cases:
        base = rebuild_base(c)
        if base != c["expected_signing_base"]:
            failures.append(f"{c['source']} ({c['alg']}): rebuilt base != the RFC's printed base")
            continue
        if not verify_case(c, base):
            failures.append(f"{c['source']} ({c['alg']}): the RFC's signature did not verify")

    if failures:
        print("RFC 9421 App-B gate: FAIL")
        for f in failures:
            print("  -", f)
        return 1

    print("RFC 9421 App-B gate: PASS")
    print(f"  source     {data.get('standard')} ({data['source']['url']})")
    print(f"  builder    {len(cases)}/{len(cases)} signature bases rebuilt byte-for-byte from the RFC's inputs")
    print(f"  verifier   {len(cases)}/{len(cases)} of the RFC's own signatures accepted "
          f"({', '.join(sorted(c['alg'] for c in cases))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
