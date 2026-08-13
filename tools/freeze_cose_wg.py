#!/usr/bin/env python3
"""Freeze the cose-wg COSE_Sign1 examples as a COSE interop anchor.

External interoperability anchor for the CBOR Object Signing stage: proof that our
COSE_Sign1 verifier reproduces the verdicts of the COSE working group's own example
set (cose-wg/Examples, sign1-tests), the cross-implementation reference many COSE
libraries validate against. NIST/WG public example vectors, carried verbatim with
upstream provenance pinned to an exact commit.

Selection: the sign1-tests directory (COSE_Sign1, single signer, ES256/P-256), the
pass and fail vectors. Each carries the message CBOR, the signer's key, the optional
external AAD, and the WG's pass/fail expectation.

One deliberate policy divergence is recorded, not hidden: cose-wg sign-pass-01 puts
the signature algorithm in the UNPROTECTED header, which RFC 9052 permits but our
profile rejects (an unprotected alg is not integrity-protected, an algorithm-
downgrade surface; our cose_v0 corpus tests exactly this rejection). The base-spec
verdict (accept) is what pycose reproduces; our profile verdict (reject) is what our
oracle reproduces. Both are asserted by the gate.

Re-derive: fetch the sign1-tests JSON files at the pinned commit into a directory
and run  python tools/freeze_cose_wg.py --src <dir>
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "cose_wg_sign1_v0.json")

SOURCE = {
    "repo": "cose-wg/Examples",
    "path": "sign1-tests",
    "commit": "9478ee1cbd805b65ef3d4d2599ec3568ab06d346",
    "commit_date": "2017-04-06T02:18:16Z",
    "url_base": ("https://raw.githubusercontent.com/cose-wg/Examples/"
                 "9478ee1cbd805b65ef3d4d2599ec3568ab06d346/sign1-tests/"),
    "fetched_at": "2026-08-13",
}

# Our profile rejects an alg carried only in the unprotected header; RFC 9052
# permits it. This maps a cose-wg example name to the reason our verdict diverges
# from the base-spec (WG) verdict, so the divergence is asserted, never silent.
POLICY_DIVERGENCE = {
    "sign-pass-01": ("alg is only in the unprotected header; our profile requires the "
                     "alg in the integrity-protected header (RFC 9052 permits either). "
                     "An unprotected alg is an algorithm-downgrade surface, so we "
                     "reject where the base spec accepts."),
}


def _b64u_hex(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).hex()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="directory of cose-wg sign1-tests *.json")
    args = ap.parse_args()

    cases = []
    for path in sorted(glob.glob(os.path.join(args.src, "*.json"))):
        d = json.load(open(path, encoding="utf-8"))
        name = os.path.splitext(os.path.basename(path))[0]
        s0 = d["input"]["sign0"]
        k = s0["key"]
        if k.get("kty") != "EC" or k.get("crv") != "P-256":
            continue  # this corpus's COSE key scope is ES256/P-256
        wg_valid = not bool(d.get("fail"))
        reason = POLICY_DIVERGENCE.get(name)
        our_valid = False if reason else wg_valid
        cases.append({
            "name": name,
            "title": d.get("title"),
            "cbor_hex": d["output"]["cbor"].lower(),
            "key": {"kty": "EC2", "crv": "P-256",
                    "x_hex": _b64u_hex(k["x"]), "y_hex": _b64u_hex(k["y"])},
            "external_hex": (s0.get("external") or "").lower(),
            "wg_valid": wg_valid,
            "our_expected_valid": our_valid,
            "policy_divergence": reason,
        })
    if not cases:
        raise SystemExit("no ES256/P-256 sign1 cases found")
    cases.sort(key=lambda c: c["name"])

    out = {
        "note": ("cose-wg COSE_Sign1 interop anchors (sign1-tests, ES256/P-256). "
                 "External interoperability evidence: our COSE_Sign1 verifier "
                 "reproduces the COSE working group's own example verdicts, cross-"
                 "checked by pycose. WG public example vectors, carried verbatim; no "
                 "secrets."),
        "standard": "RFC 9052 (COSE_Sign1)",
        "selection": "sign1-tests, COSE_Sign1 single-signer, ES256 / P-256 (pass and fail)",
        "source": SOURCE,
        "counts": {
            "total": len(cases),
            "wg_accept": sum(1 for c in cases if c["wg_valid"]),
            "wg_reject": sum(1 for c in cases if not c["wg_valid"]),
            "policy_divergences": sum(1 for c in cases if c["policy_divergence"]),
            "uses_external_aad": sum(1 for c in cases if c["external_hex"]),
        },
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("froze cose-wg COSE_Sign1 interop anchors ->", OUT)
    print("  counts:", out["counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
