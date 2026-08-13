#!/usr/bin/env python3
"""httpwg SFV interop gate: reproduce the SFV editors' shared test suite.

External interoperability proof for the Structured Field Values stage. Where the
12-way corpus proves twelve of our runners agree on our crafted battery, this
proves our RFC 8941 implementation reproduces the verdicts of the shared cross-
implementation suite the SFV editors maintain (httpwg/structured-field-tests,
frozen in vectors/sfv_httpwg_v0.json). That suite is itself the authoritative
multi-implementation reference; reproducing it is interoperability with the
standard's shared tests, not agreement with ourselves.

Primary assertion (FAIL-CLOSED): our oracle (tools/oracle_sfv.py) reproduces every
strict test. A must_fail input must be rejected; otherwise the input must parse and
serialize to the suite's canonical form (or, when the suite omits canonical, back
to the input). can_fail tests are genuinely ambiguous in RFC 8941 and are not
asserted (counted and reported, never failed).

Secondary cross-check (REPORTED, not fatal): the same verdicts are recomputed with
http_sfv (Mark Nottingham's), a separate RFC 8941 implementation, and its agreement
rate is printed. http_sfv is intentionally lenient on a few points the shared suite
marks must_fail (e.g. non-canonical base64 padding) and rejects the empty
List/Dictionary the suite accepts; those are http_sfv's own divergences from the
suite, not ours, so they are listed for transparency but do not fail this gate. Our
oracle is the conformance claim; http_sfv is corroboration where it agrees.

Requires: http_sfv (pip install http-sfv).
Run:  python tools/check_sfv_httpwg.py [anchors.json]
"""
from __future__ import annotations

import json
import os
import sys

import http_sfv

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_sfv as O  # noqa: E402

ROOT = os.path.dirname(HERE)
ANCHORS = (sys.argv[1] if len(sys.argv) > 1
           else os.path.join(ROOT, "vectors", "sfv_httpwg_v0.json"))

TYPES = {"item": http_sfv.Item, "list": http_sfv.List, "dictionary": http_sfv.Dictionary}


def oracle_verdict(field_type, text):
    try:
        return O.verdict(field_type, text)
    except Exception:
        return False, None


def http_sfv_verdict(field_type, text):
    obj = TYPES[field_type]()
    data = text.encode("utf-8")
    try:
        consumed = obj.parse(data)
    except Exception:
        return False, None
    if isinstance(consumed, int) and data[consumed:].strip(b" "):
        return False, None
    try:
        return True, str(obj)
    except Exception:
        return False, None


def main() -> int:
    data = json.load(open(ANCHORS, encoding="utf-8"))
    if data.get("standard") != "RFC 8941":
        print("SFV interop gate: FAIL -- anchors are not RFC 8941")
        return 1
    tests = data.get("tests") or []
    if not tests:
        print("SFV interop gate: FAIL -- no anchor tests")
        return 1

    oracle_failures = []       # fatal: our conformance claim
    http_sfv_divergences = []  # reported: http_sfv's own leniencies
    checked = must_fail = can_fail = http_sfv_agree = 0
    for t in tests:
        ht = t.get("header_type")
        if ht not in TYPES:
            continue
        if t.get("can_fail"):
            can_fail += 1
            continue
        text = ", ".join(t.get("raw", []))
        name = f"[{t.get('file')}] {t.get('name')}"
        checked += 1

        o_ok, o_canon = oracle_verdict(ht, text)
        h_ok, h_canon = http_sfv_verdict(ht, text)

        if t.get("must_fail"):
            must_fail += 1
            expected_ok, expected_canon = False, None
        else:
            expected_ok = True
            expected_canon = ", ".join(t["canonical"]) if t.get("canonical") is not None else text

        # Primary (fatal): our oracle must reproduce the suite verdict exactly.
        if expected_ok:
            if not o_ok or o_canon != expected_canon:
                oracle_failures.append(f"{name}: oracle -> ok={o_ok} canon={o_canon!r} != {expected_canon!r}")
        elif o_ok:
            oracle_failures.append(f"{name}: oracle parsed a must_fail input")

        # Secondary (reported): http_sfv agreement with the suite.
        if expected_ok:
            h_match = h_ok and h_canon == expected_canon
        else:
            h_match = not h_ok
        if h_match:
            http_sfv_agree += 1
        else:
            got = "parsed" if h_ok else "rejected"
            http_sfv_divergences.append(f"{name}: http_sfv {got} (suite expected "
                                        f"{'reject' if not expected_ok else 'accept'})")

    src = data.get("source", {})
    if oracle_failures:
        print("SFV interop gate (httpwg): FAIL")
        for f in oracle_failures[:40]:
            print("  -", f)
        if len(oracle_failures) > 40:
            print(f"  ... and {len(oracle_failures) - 40} more")
        return 1

    print("SFV interop gate (httpwg): PASS")
    print(f"  source        {src.get('repo')}@{str(src.get('commit'))[:12]} ({src.get('commit_date')})")
    print(f"  our oracle    {checked}/{checked} strict RFC 8941 tests reproduced "
          f"({must_fail} must-fail, {checked - must_fail} canonical)")
    print(f"  http_sfv      {http_sfv_agree}/{checked} agree; "
          f"{len(http_sfv_divergences)} known http_sfv divergences from the suite (not ours):")
    for d in http_sfv_divergences:
        print(f"                - {d}")
    print(f"  ambiguous     {can_fail} can_fail tests reported, not asserted (RFC 8941 leaves them optional)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
