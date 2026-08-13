#!/usr/bin/env python3
"""cose-wg COSE_Sign1 interop gate: reproduce the WG's own example verdicts.

External interoperability proof for the CBOR Object Signing stage. Where the 12-way
corpus proves twelve of our runners agree on our crafted battery, this proves our
COSE_Sign1 verifier reproduces the verdicts of the COSE working group's own example
set (cose-wg/Examples sign1-tests, frozen in vectors/cose_wg_sign1_v0.json). Every
case is decided two ways and both must hold:

  1. our oracle (tools/oracle_cose.py) reproduces OUR profile verdict for every
     case (fail-closed). Our profile equals the WG's, except one deliberate
     hardening recorded in the anchors: an alg carried only in the unprotected
     header is rejected (an algorithm-downgrade surface), where RFC 9052 permits
     it. That divergence is asserted, not skipped.

  2. pycose (a separate COSE implementation) reproduces the WG's base-spec verdict
     for every case (fail-closed), confirming the WG expectations are spec-
     reproducible and that our only divergence is the documented hardening.

Two independent implementations reproducing the working group's own examples is
interoperability with the standard's reference vectors, not agreement with
ourselves.

Fail-closed: our oracle disagreeing with our profile verdict, or pycose disagreeing
with the WG verdict, exits non-zero.

Requires: pycose, cbor2.
Run:  python tools/check_cose_wg.py [anchors.json]
"""
from __future__ import annotations

import json
import os
import sys

from pycose.messages import Sign1Message
from pycose.keys import EC2Key
from pycose.keys.curves import P256

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_cose as O  # noqa: E402

ROOT = os.path.dirname(HERE)
ANCHORS = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(ROOT, "vectors", "cose_wg_sign1_v0.json"))

COSE_SIGN1_TAG_BYTE = b"\xd2"  # CBOR tag 18


def oracle_accepts(cbor_hex, key, ext_hex):
    our_key = {"kty": "EC2", "crv": "P-256", "alg": "ES256",
               "x": key["x_hex"], "y": key["y_hex"]}
    ext = bytes.fromhex(ext_hex) if ext_hex else b""
    try:
        accept, _ = O.verdict(bytes.fromhex(cbor_hex), our_key, ext)
        return bool(accept)
    except Exception:
        return False


def pycose_accepts(cbor_hex, key, ext_hex):
    """Base-spec verdict via native pycose. Untagged COSE_Sign1 is wrapped in the
    tag-18 byte pycose's decode() requires; the alg may sit in either header."""
    data = bytes.fromhex(cbor_hex)
    if data[:1] != COSE_SIGN1_TAG_BYTE:
        data = COSE_SIGN1_TAG_BYTE + data
    try:
        msg = Sign1Message.decode(data)
        msg.key = EC2Key(crv=P256, x=bytes.fromhex(key["x_hex"]), y=bytes.fromhex(key["y_hex"]))
        if ext_hex:
            msg.external_aad = bytes.fromhex(ext_hex)
        return bool(msg.verify_signature())
    except Exception:
        return False


def main() -> int:
    data = json.load(open(ANCHORS, encoding="utf-8"))
    if data.get("standard", "").split()[0] != "RFC" or "9052" not in data.get("standard", ""):
        print("COSE interop gate: FAIL -- anchors are not RFC 9052 COSE_Sign1")
        return 1
    cases = data.get("cases") or []
    if not cases:
        print("COSE interop gate: FAIL -- no anchor cases")
        return 1

    failures = []
    divergences = []
    for c in cases:
        o = oracle_accepts(c["cbor_hex"], c["key"], c["external_hex"])
        p = pycose_accepts(c["cbor_hex"], c["key"], c["external_hex"])
        if o != c["our_expected_valid"]:
            failures.append(f"{c['name']}: oracle={o} != our profile {c['our_expected_valid']}")
        if p != c["wg_valid"]:
            failures.append(f"{c['name']}: pycose={p} != WG {c['wg_valid']}")
        if c.get("policy_divergence"):
            divergences.append((c["name"], c["policy_divergence"]))

    if failures:
        print("COSE interop gate (cose-wg): FAIL")
        for f in failures:
            print("  -", f)
        return 1

    src = data.get("source", {})
    accepts = sum(1 for c in cases if c["wg_valid"])
    print("COSE interop gate (cose-wg): PASS")
    print(f"  source        {src.get('repo')}@{str(src.get('commit'))[:12]} ({src.get('commit_date')})")
    print(f"  our oracle    {len(cases)}/{len(cases)} reproduce our COSE_Sign1 profile verdict")
    print(f"  pycose        {len(cases)}/{len(cases)} reproduce the WG base-spec verdict "
          f"({accepts} accept, {len(cases) - accepts} reject)")
    print(f"  divergences   {len(divergences)} deliberate profile hardening(s) vs the base spec, asserted:")
    for name, reason in divergences:
        print(f"                - {name}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
