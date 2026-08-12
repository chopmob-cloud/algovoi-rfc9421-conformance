#!/usr/bin/env python3
"""Generate rfc9421_negative_v2.json: the v1 CORE battery plus coverage-gap negatives.

v2 is a strict SUPERSET: it carries every frozen v1 case verbatim (so v1 stays the
shipped, signed artifact and the KAT anchors that index the v1 signing_base
positives still apply) and appends the negative classes the security review found
missing from v1:

  signing_base   the fail-closed error paths were never exercised (v1 had zero
                 negative signing_base cases): a covered @-component / header /
                 'created' parameter with no supplied value, and an unsupported
                 derived component, all of which MUST raise rather than build.
  ed25519_verify S = 0 (a degenerate scalar) MUST NOT verify.
  ecdsa_verify   s = 0 and the upper boundary r = n / s = n are all out of
                 [1, n-1] and MUST reject (v1 only tested r = 0).

Every appended verdict is computed from the reference verifier / ecdsa provider,
never hand-asserted. Run:  python tools/gen_negative_v2.py

Install the reference packages or point ALGOVOI_LOCAL_SRC at their source dirs.
"""
from __future__ import annotations

import base64
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import build_signing_base, verify_signature, VerifyError
from algovoi_rfc9421_ecdsa import verify_p256, verify_p384, set_strict_low_s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(ROOT, "corpus", "rfc9421_negative_v1")
V1 = os.path.join(CORPUS_DIR, "rfc9421_negative_v1.json")
OUT = os.path.join(ROOT, "corpus", "rfc9421_negative_v2", "rfc9421_negative_v2.json")

N = {
    "p256": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "p384": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
}
FLEN = {"p256": 32, "p384": 48}
DUMMY_SB = base64.b64encode(b"unused-negative-build-must-raise").decode()


def build_raises(**kw) -> bool:
    try:
        build_signing_base(**kw)
        return False
    except Exception:
        return True


def ed_verdict(base_b64, sig_hex, pk_hex) -> bool:
    base = base64.b64decode(base_b64).decode("utf-8")
    try:
        return bool(verify_signature(base, bytes.fromhex(sig_hex), pk_hex))
    except VerifyError:
        return False


def ecdsa_verdict(curve, msg_hex, pub_hex, sig_hex, strict) -> bool:
    fn = verify_p256 if curve == "p256" else verify_p384
    set_strict_low_s(bool(strict))
    try:
        return bool(fn(bytes.fromhex(msg_hex).decode("utf-8"), bytes.fromhex(sig_hex), pub_hex))
    except Exception:
        return False
    finally:
        set_strict_low_s(False)


def main() -> int:
    d = json.load(open(V1, encoding="utf-8"))
    d["name"] = "rfc9421_negative_v2"
    d["description"] = ("Signed cross-language CORE negative battery for RFC 9421, v2. "
                        "Strict superset of rfc9421_negative_v1: adds fail-closed "
                        "signing-base error paths and additional Ed25519/ECDSA range "
                        "negatives found by security review. Verdicts computed from the "
                        "reference verifier 0.4.2 / ecdsa 0.1.0.")

    # --- signing_base: the fail-closed error paths (v1 had none) ---
    sb_neg = [
        (dict(covered_components=["@method"], mode="algovoi-v0"),
         "@method covered but not supplied, MUST raise"),
        (dict(covered_components=["@query"], mode="algovoi-v0"),
         "unsupported derived component @query, MUST raise"),
        (dict(covered_components=["x-missing"], mode="algovoi-v0"),
         "covered header not supplied, MUST raise"),
        (dict(covered_components=["created"], mode="algovoi-v0"),
         "'created' covered but no created parameter, MUST raise"),
    ]
    for kw, note in sb_neg:
        assert build_raises(**kw), f"expected build to raise: {note}"
        d["signing_base"].append({"in": {k: v for k, v in kw.items() if k != "mode"},
                                  "mode": kw["mode"], "ok": False,
                                  "signing_base_b64": DUMMY_SB, "note": note})

    # --- ed25519_verify: S = 0 ---
    good = next(c for c in d["ed25519_verify"] if c["expect_valid"])
    sig = bytes.fromhex(good["sig_hex"])
    s0 = (sig[:32] + b"\x00" * 32).hex()
    d["ed25519_verify"].append(
        {"signing_base_b64": good["signing_base_b64"], "sig_hex": s0, "pk_hex": good["pk_hex"],
         "expect_valid": ed_verdict(good["signing_base_b64"], s0, good["pk_hex"]),
         "note": "S = 0 scalar, MUST reject"})

    # --- ecdsa_verify: s = 0 and the r = n / s = n upper boundary ---
    for curve in ("p256", "p384"):
        flen, n = FLEN[curve], N[curve]
        v = next(c for c in d["ecdsa_verify"] if c["curve"] == curve and c["expect_valid"])
        r_b = v["sig_raw_hex"][:flen * 2]
        s_b = v["sig_raw_hex"][flen * 2:]
        nn = n.to_bytes(flen, "big").hex()
        cases = [
            (r_b + ("00" * flen), "s = 0 out of [1,n-1], MUST reject"),
            (nn + s_b, "r = n (upper bound) out of [1,n-1], MUST reject"),
            (r_b + nn, "s = n (upper bound) out of [1,n-1], MUST reject"),
        ]
        for sig_hex, note in cases:
            d["ecdsa_verify"].append(
                {"curve": curve, "msg_hex": v["msg_hex"], "pub_uncompressed_hex": v["pub_uncompressed_hex"],
                 "sig_raw_hex": sig_hex, "strict_low_s": False,
                 "expect_valid": ecdsa_verdict(curve, v["msg_hex"], v["pub_uncompressed_hex"], sig_hex, False),
                 "note": note})

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(d, open(OUT, "w", encoding="utf-8"), indent=1)
    counts = {k: len(x) for k, x in d.items() if isinstance(x, list)}
    print("wrote", OUT)
    print("counts:", counts, "total", sum(counts.values()))
    # every appended case must be a true negative (expect reject / non-valid)
    appended_ok = all(c["expect_valid"] is False for c in d["ed25519_verify"][-1:] ) \
        and all(not c["expect_valid"] for c in d["ecdsa_verify"][-6:])
    print("appended negatives verdicts all reject:", appended_ok)
    return 0 if appended_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
