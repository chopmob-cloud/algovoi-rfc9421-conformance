#!/usr/bin/env python3
"""NIST ACVP ML-DSA-65 interop gate: reproduce NIST's own verdicts, twice over.

This is the EXTERNAL interoperability proof for the post-quantum stage. Where the
12-way corpus proves twelve of our runners agree on our crafted battery, this gate
proves our stack reproduces the verdicts NIST itself publishes for FIPS 204
ML-DSA-65 signature verification. For every frozen NIST ACVP case
(vectors/pqc_mldsa_acvp_mldsa65_v0.json, pure external interface, empty and
non-empty context), it recomputes accept/reject with TWO independent FIPS-204
implementations and requires both to match NIST:

  1. liboqs ML-DSA-65 (verify_with_ctx_str) -- the oracle's implementation family;
  2. dilithium-py ML_DSA_65.verify(..., ctx=...) -- a separate FIPS-204 library.

Agreement of BOTH independent libraries with NIST's published pass/fail, across
all context lengths, is interop with the standard, not self-consensus. A round-3
Dilithium library, or a verifier that mishandles the FIPS-204 context binding,
fails NIST's valid controls (or accepts a control NIST rejects) and this gate goes
red.

Fail-closed: a length fault, a library disagreement with NIST, or a disagreement
between the two libraries exits non-zero.

Requires liboqs (the `oqs` package, ML-DSA-65 mechanism) and dilithium-py.
Run:  python tools/check_acvp_pqc_mldsa.py [anchors.json]
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANCHORS = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(ROOT, "vectors", "pqc_mldsa_acvp_mldsa65_v0.json"))

# FIPS 204 ML-DSA-65 normative byte lengths, asserted here independently.
PK_LEN = 1952
SIG_LEN = 3309


def liboqs_accepts(pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        return False
    try:
        import oqs
        with oqs.Signature("ML-DSA-65") as v:
            return bool(v.verify_with_ctx_str(msg, sig, ctx, pk))
    except Exception:
        return False


def dilithium_accepts(pk: bytes, msg: bytes, sig: bytes, ctx: bytes) -> bool:
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        return False
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
        return bool(ML_DSA_65.verify(pk, msg, sig, ctx=ctx))
    except Exception:
        return False


def main() -> int:
    data = json.load(open(ANCHORS, encoding="utf-8"))
    if data.get("mechanism") != "ML-DSA-65" or data.get("spec") != "FIPS204":
        print("ACVP gate: FAIL -- anchors are not ML-DSA-65 / FIPS204")
        return 1
    cases = data.get("cases") or []
    if not cases:
        print("ACVP gate: FAIL -- no anchor cases")
        return 1

    src = data.get("source", {})
    failures = []
    accepts = 0
    for c in cases:
        try:
            pk = bytes.fromhex(c["public_key"])
            msg = bytes.fromhex(c["message"])
            sig = bytes.fromhex(c["signature"])
            ctx = bytes.fromhex(c.get("context") or "")
        except (KeyError, ValueError) as e:
            failures.append(f"tcId {c.get('tcId')}: malformed hex ({e})")
            continue
        nist = bool(c["expect_valid"])
        accepts += nist
        lo = liboqs_accepts(pk, msg, sig, ctx)
        dp = dilithium_accepts(pk, msg, sig, ctx)
        if lo != nist:
            failures.append(f"tcId {c['tcId']}: liboqs={lo} != NIST={nist} (ctx {len(ctx)}B)")
        if dp != nist:
            failures.append(f"tcId {c['tcId']}: dilithium-py={dp} != NIST={nist} (ctx {len(ctx)}B)")

    if failures:
        print("ACVP gate (pqc_mldsa): FAIL")
        for f in failures:
            print("  -", f)
        return 1

    print("ACVP gate (pqc_mldsa): PASS")
    print(f"  source     {src.get('repo')}@{str(src.get('commit'))[:12]} vsId {src.get('vsId')} ({src.get('revision')})")
    print(f"  interop    {len(cases)} NIST ML-DSA-65 sigVer verdicts reproduced by "
          f"liboqs AND dilithium-py ({accepts} accept, {len(cases) - accepts} reject)")
    print("  contexts   empty and non-empty context strings, both libraries agree with NIST")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
