#!/usr/bin/env python3
"""Freeze authoritative JOSE JWS vectors as a JWS interop anchor.

External interoperability anchor for the JSON Web Signature stage: proof that our
JWS verifier reproduces the JOSE standards' own worked examples. Two authoritative
sources, all public keys only (private JWK components are stripped; no symmetric
secrets ship):

  - RFC 7520 (the JOSE cookbook), fetched from ietf-jose/cookbook, provenance
    pinned to an exact commit: 4_1 (RS256, in scope), 4_2 (PS384) and 4_3 (ES512)
    as out-of-scope asymmetric examples.
  - RFC 7515 Appendix A.3 (ES256) and A.5 (alg=none), and RFC 8037 Appendix A.4
    (Ed25519), embedded verbatim from the RFC text (the gate self-checks each: a
    mis-transcribed vector would not verify under jwcrypto or our oracle).

Our jws_v0 verifier covers RS256, ES256 and EdDSA plus the JOSE security rules. For
an in-scope vector our oracle must reproduce the authoritative verdict; for an
out-of-scope algorithm (PS384, ES512) our oracle must reject it as unsupported (a
correct scope decision, not a mis-verification) while the independent jwcrypto
library still verifies it, confirming the vector is genuine. alg=none must be
rejected by both.

Re-derive: fetch the cookbook jws/*.json at the pinned commit into a directory and
run  python tools/freeze_jws_interop.py --src <dir>
"""
from __future__ import annotations

import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "jws_interop_v0.json")

COOKBOOK = {
    "repo": "ietf-jose/cookbook",
    "commit": "d09e99d6838e44020396d1f92fe1f5f36a796ae1",
    "commit_date": "2015-05-18T17:07:34Z",
    "url_base": ("https://raw.githubusercontent.com/ietf-jose/cookbook/"
                 "d09e99d6838e44020396d1f92fe1f5f36a796ae1/jws/"),
    "fetched_at": "2026-08-13",
}

# Private JWK members that must never ship (RFC 7518 Section 6).
PRIVATE_JWK = {"d", "p", "q", "dp", "dq", "qi", "k"}

IN_SCOPE_ALGS = {"RS256", "ES256", "EdDSA"}

# Which cookbook files to carry, and whether the algorithm is in our verifier scope.
COOKBOOK_CASES = [
    ("4_1.rsa_v15_signature", True),   # RS256  in scope
    ("4_2.rsa-pss_signature", False),  # PS384  out of scope (asymmetric)
    ("4_3.ecdsa_signature", False),    # ES512  out of scope (asymmetric)
]

# RFC-text worked examples (public key only), embedded verbatim and self-checked.
RFC_CASES = [
    {
        "source": "RFC 7515 Appendix A.3",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
        "compact": ("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO"
                    "DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3lj"
                    "bEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfK"
                    "TUJqPP3-Kg6NU1Q"),
        "valid": True,
    },
    {
        "source": "RFC 8037 Appendix A.4",
        "alg": "EdDSA",
        "jwk": {"kty": "OKP", "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
        "compact": ("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0"
                    "il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsP"
                    "t9g7sVvpAr_MuM0KAg"),
        "valid": True,
    },
    {
        "source": "RFC 7515 Appendix A.5",
        "alg": "none",
        "jwk": None,
        "compact": ("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzOD"
                    "AsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."),
        "valid": False,  # alg=none must be rejected
    },
]


def public_jwk(jwk: dict) -> dict:
    return {k: v for k, v in jwk.items() if k not in PRIVATE_JWK}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="directory of cookbook jws/*.json")
    args = ap.parse_args()

    cases = []
    for stem, in_scope in COOKBOOK_CASES:
        d = json.load(open(os.path.join(args.src, stem + ".json"), encoding="utf-8"))
        alg = d["input"].get("alg") or d["input"]["key"].get("alg")
        cases.append({
            "source": f"RFC 7520 {stem.split('.')[0].replace('_', '.')}",
            "alg": alg,
            "in_scope": bool(in_scope),
            "jwk": public_jwk(d["input"]["key"]),
            "compact": d["output"]["compact"],
            "valid": True,
        })
    for rc in RFC_CASES:
        cases.append({
            "source": rc["source"],
            "alg": rc["alg"],
            "in_scope": rc["alg"] in IN_SCOPE_ALGS or rc["alg"] == "none",
            "jwk": rc["jwk"],
            "compact": rc["compact"],
            "valid": rc["valid"],
        })

    out = {
        "note": ("Authoritative JOSE JWS interop anchors (RFC 7520 cookbook + RFC "
                 "7515 / RFC 8037 appendix worked examples). External "
                 "interoperability evidence: our JWS verifier reproduces the JOSE "
                 "standards' own vectors, cross-checked by jwcrypto. Public keys "
                 "only; no private JWK members or symmetric secrets ship."),
        "standard": "RFC 7515 / 7518 / 8037 (JOSE JWS)",
        "scope": ("our verifier covers RS256, ES256, EdDSA and alg=none; PS384 and "
                  "ES512 are carried as out-of-scope asymmetric examples our verifier "
                  "must reject as unsupported while jwcrypto still verifies them"),
        "cookbook_source": COOKBOOK,
        "counts": {
            "total": len(cases),
            "in_scope": sum(1 for c in cases if c["in_scope"]),
            "out_of_scope": sum(1 for c in cases if not c["in_scope"]),
            "must_reject": sum(1 for c in cases if not c["valid"]),
        },
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("froze JOSE JWS interop anchors ->", OUT)
    print("  counts:", out["counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
