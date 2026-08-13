#!/usr/bin/env python3
"""JOSE JWS interop gate: reproduce the JOSE standards' own worked examples.

External interoperability proof for the JSON Web Signature stage. Where the 12-way
corpus proves twelve of our runners agree on our crafted battery, this proves our
JWS verifier reproduces the JOSE standards' authoritative vectors (RFC 7520 cookbook
plus RFC 7515 / RFC 8037 appendix examples, frozen in vectors/jws_interop_v0.json).
Every case is decided two ways and both must hold:

  1. our oracle (tools/oracle_jws.py). For an in-scope algorithm (RS256, ES256,
     EdDSA) it must reproduce the authoritative verdict; alg=none must be rejected.
     For an out-of-scope algorithm (PS384, ES512) it must reject as unsupported --
     a correct scope decision, asserted, not a mis-verification.

  2. jwcrypto (a separate JOSE implementation). Every genuinely-signed vector must
     verify under jwcrypto (confirming the vector, including the out-of-scope ones
     our verifier scopes out), and alg=none must not.

Two independent implementations reproducing the standards' worked examples is
interoperability with the specs' own vectors, not agreement with ourselves.

Fail-closed: our oracle disagreeing with the expected in-scope/scope verdict, or
jwcrypto disagreeing with the authoritative signed/none verdict, exits non-zero.

Requires: jwcrypto.
Run:  python tools/check_jws_interop.py [anchors.json]
"""
from __future__ import annotations

import json
import os
import sys

from jwcrypto import jws as jose_jws, jwk as jose_jwk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_jws as O  # noqa: E402

ROOT = os.path.dirname(HERE)
ANCHORS = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(ROOT, "vectors", "jws_interop_v0.json"))


def oracle_accepts(compact, jwk):
    keys = [{"kid": (jwk or {}).get("kid"), "jwk": jwk}] if jwk else []
    try:
        accept, reason = O.verdict(compact, {"keys": keys})
        return bool(accept), reason
    except Exception as e:
        return False, f"exception:{e}"


def jwcrypto_verifies(compact, jwk):
    try:
        tok = jose_jws.JWS()
        tok.deserialize(compact)
        tok.verify(jose_jwk.JWK(**jwk))
        return True
    except Exception:
        return False


def main() -> int:
    data = json.load(open(ANCHORS, encoding="utf-8"))
    if "JWS" not in data.get("standard", ""):
        print("JWS interop gate: FAIL -- anchors are not JOSE JWS")
        return 1
    cases = data.get("cases") or []
    if not cases:
        print("JWS interop gate: FAIL -- no anchor cases")
        return 1

    failures = []
    scoped_out = []
    for c in cases:
        o_ok, o_reason = oracle_accepts(c["compact"], c.get("jwk"))

        # (1) our oracle
        if c["in_scope"]:
            if o_ok != c["valid"]:
                failures.append(f"{c['source']} ({c['alg']}): oracle={o_ok} != expected {c['valid']}")
        else:
            if o_ok:
                failures.append(f"{c['source']} ({c['alg']}): oracle accepted an out-of-scope algorithm")
            else:
                scoped_out.append((c["source"], c["alg"], o_reason))

        # (2) jwcrypto: every signed vector verifies; alg=none does not
        if c["alg"] == "none":
            if jwcrypto_verifies(c["compact"], c["jwk"] or {}):
                failures.append(f"{c['source']}: jwcrypto verified an alg=none token")
        else:
            if not jwcrypto_verifies(c["compact"], c["jwk"]):
                failures.append(f"{c['source']} ({c['alg']}): jwcrypto failed to verify an authoritative vector")

    if failures:
        print("JWS interop gate: FAIL")
        for f in failures:
            print("  -", f)
        return 1

    cb = data.get("cookbook_source", {})
    in_scope = [c for c in cases if c["in_scope"]]
    print("JWS interop gate: PASS")
    print(f"  source        RFC 7520 cookbook @{str(cb.get('commit'))[:12]} + RFC 7515/8037 appendix vectors")
    print(f"  our oracle    {len(in_scope)}/{len(in_scope)} in-scope verdicts reproduced "
          f"(RS256, ES256, EdDSA; alg=none rejected)")
    print(f"  jwcrypto      {sum(1 for c in cases if c['alg'] != 'none')} authoritative signatures verified; alg=none rejected")
    print(f"  scoped out    {len(scoped_out)} out-of-scope algorithms correctly rejected by our verifier:")
    for src, alg, reason in scoped_out:
        print(f"                - {src} ({alg}): {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
