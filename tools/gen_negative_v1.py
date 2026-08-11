#!/usr/bin/env python3
"""Generate the signed CORE negative battery rfc9421_negative_v1.json.

Authoritative source is the published Python verifier (algovoi-rfc9421-verifier
0.4.2 + algovoi-rfc9421-ecdsa 0.1.0). Every crypto verdict here is COMPUTED from
that reference implementation, never hand-asserted, so the frozen corpus is the
objective target the four language runners must reproduce byte-for-byte.

Sections:
  signing_base           positive controls + adversarial canonicalisation (exact bytes)
  signature_input_parse  well-formed accept / malformed reject
  signature_value_parse  canonical-base64 accept / non-canonical + wrong-length reject
  keygate                valid accept / small-order + non-canonical reject
  ed25519_verify         valid / tampered / wrong-key / byte-level malleability
  ecdsa_verify           valid / tampered / off-curve / out-of-range / wrong-width / high-s

Run:  python gen_negative_v1.py     ->  rfc9421_negative_v1.json
"""
from __future__ import annotations

import base64
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import (
    build_signing_base,
    parse_signature_input,
    parse_signature_value,
    verify_signature,
    check_ed25519_public_key,
    is_small_order,
    WeakKeyError,
    SignatureInputParseError,
    VerifyError,
)
from algovoi_rfc9421_ecdsa import verify_p256, verify_p384, set_strict_low_s


HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
REF_V0 = os.path.join(REPO, "vectors", "reference_vectors_v0.json")
REF_ECDSA = os.path.join(REPO, "vectors", "reference_ecdsa_v0.json")
CORPUS_DIR = os.path.join(REPO, "corpus", "rfc9421_negative_v1")

SP_RAW = '("@method" "@authority" "@path");created=1778955520;keyid="did:web:api";alg="ed25519"'


# ---- helpers: compute authoritative verdicts from the reference impl ----------

def base_ok(**kw):
    """Return signing_base_b64 for an input that must build, else raise loudly."""
    b = build_signing_base(**kw)
    return base64.b64encode(b.encode("utf-8")).decode()


def parses_input(header: str) -> bool:
    try:
        parse_signature_input(header)
        return True
    except SignatureInputParseError:
        return False


def parses_value(header: str) -> bool:
    try:
        parse_signature_value(header)
        return True
    except SignatureInputParseError:
        return False


def ed_verdict(base_b64: str, sig_hex: str, pk_hex: str) -> bool:
    """Fail-closed verdict: True only if verify returns True with no error."""
    base = base64.b64decode(base_b64).decode("utf-8")
    try:
        return bool(verify_signature(base, bytes.fromhex(sig_hex), pk_hex))
    except VerifyError:
        return False


def ecdsa_verdict(curve: str, msg_hex: str, pub_hex: str, sig_hex: str, strict: bool) -> bool:
    fn = verify_p256 if curve == "p256" else verify_p384
    msg = bytes.fromhex(msg_hex).decode("utf-8")
    set_strict_low_s(strict)
    try:
        return bool(fn(msg, bytes.fromhex(sig_hex), pub_hex))
    except Exception:
        return False
    finally:
        set_strict_low_s(False)


def keygate_entry(pk_hex: str, note: str) -> dict:
    raw = bytes.fromhex(pk_hex)
    try:
        check_ed25519_public_key(raw)
        rejected = None
    except WeakKeyError:
        rejected = "WeakKeyError"
    return {"pk_hex": pk_hex, "small_order": is_small_order(raw),
            "rejected": rejected, "note": note}


# ---- non-canonical base64 search ---------------------------------------------

def non_canonical_b64_value(sig: bytes) -> str:
    """Find a Signature header value whose base64 has non-zero pad bits (must be
    rejected). Search by mutating the last base64 char; verify the reference
    parser rejects it before returning."""
    canon = base64.b64encode(sig).decode()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    stem, last = canon[:-2], canon[-2]  # char before the single '=' pad
    assert canon.endswith("="), "expected one pad char for a 64-byte sequence"
    for ch in alphabet:
        cand = stem + ch + "="
        if cand == canon:
            continue
        try:
            base64.b64decode(cand, validate=True)
        except Exception:
            continue
        header = f"sig=:{cand}:"
        if not parses_value(header):  # reference rejects it -> genuine non-canonical
            return header
    raise SystemExit("could not synthesise a non-canonical base64 value")


def main():
    v0 = json.load(open(REF_V0, encoding="utf-8"))
    ev0 = json.load(open(REF_ECDSA, encoding="utf-8"))

    out = {
        "name": "rfc9421_negative_v1",
        "description": "Signed cross-language CORE negative battery for RFC 9421 "
                       "HTTP Message Signatures (AlgoVoi four-verifier set). Reject "
                       "every negative, accept every control; verdicts computed from "
                       "the reference Python verifier 0.4.2 / ecdsa 0.1.0.",
        "signing_base": [],
        "signature_input_parse": [],
        "signature_value_parse": [],
        "keygate": [],
        "ed25519_verify": [],
        "ecdsa_verify": [],
    }

    # 1) signing_base: carry every frozen v0 positive verbatim (already 4-way parity),
    #    then add adversarial-but-deterministic canonicalisation controls.
    for rec in v0["signing_base"]:
        r = dict(rec)
        r["note"] = "carried from reference_vectors_v0 (frozen byte-parity control)"
        out["signing_base"].append(r)

    extra = [
        (dict(covered_components=["@authority"], authority="EXAMPLE.AlgoVoi.CO.uk"),
         "authority MUST lowercase"),
        (dict(covered_components=["x-ows"], headers={"X-OWS": "   trimmed   "}),
         "header value OWS trimmed"),
        (dict(covered_components=["@scheme"], scheme="HTTPS"),
         "scheme MUST lowercase"),
    ]
    for c, note in extra:
        for mode in ("algovoi-v0", "rfc9421"):
            kw = dict(c, mode=mode)
            if mode == "rfc9421":
                kw["signature_params_raw"] = SP_RAW
            rec = {"in": c, "mode": mode, "ok": True,
                   "signing_base_b64": base_ok(**kw), "note": note}
            if mode == "rfc9421":
                rec["signature_params_raw"] = SP_RAW
            out["signing_base"].append(rec)

    # 2) signature_input_parse: accept well-formed, reject malformed (fail closed).
    si_cases = [
        (f'sig={SP_RAW}', "well-formed labelled Signature-Input"),
        (SP_RAW, "well-formed unlabelled form"),
        ('sig=("@method" "@path");created=1;alg="ed25519"', "minimal well-formed"),
        ("garbage not a valid structured field", "unparseable rubbish"),
        ('sig=("@method"', "unterminated component list"),
        ("", "empty header"),
        ('sig=;created=1', "missing component list"),
        ('sig=("@method" @path)', "unquoted component token"),
    ]
    for header, note in si_cases:
        out["signature_input_parse"].append(
            {"header": header, "ok": parses_input(header), "note": note})

    # 3) signature_value_parse: canonical base64 accept, non-canonical / wrong reject.
    good_sig = bytes(range(64))
    good_val = "sig=:" + base64.b64encode(good_sig).decode() + ":"
    sv_cases = [
        (good_val, "canonical base64, 64-byte sequence"),
        (non_canonical_b64_value(good_sig), "non-canonical base64 (non-zero pad bits)"),
        ("sig=" + base64.b64encode(good_sig).decode(), "not colon-wrapped byte sequence"),
        ("sig=:not+valid+base64!!:", "invalid base64 alphabet"),
        ("", "empty header"),
        ("sig=::", "empty byte sequence"),
    ]
    for header, note in sv_cases:
        out["signature_value_parse"].append(
            {"header": header, "ok": parses_value(header), "note": note})

    # 4) keygate: carry the frozen v0 accept/reject set, annotated.
    for rec in v0["keygate"]:
        note = ("small-order / non-canonical, MUST reject"
                if rec["rejected"] else "valid key, MUST accept")
        out["keygate"].append({**{k: rec[k] for k in ("pk_hex", "small_order", "rejected")},
                               "note": note})

    # 5) ed25519_verify: carry frozen v0, then byte-level malleability negatives.
    for rec in v0["ed25519_verify"]:
        r = {k: rec[k] for k in ("signing_base_b64", "sig_hex", "pk_hex", "expect_valid")}
        r["note"] = ("valid control" if rec["expect_valid"]
                     else "tampered base or wrong key, MUST reject")
        out["ed25519_verify"].append(r)

    good = v0["ed25519_verify"][0]
    gb64, gsig, gpk = good["signing_base_b64"], good["sig_hex"], good["pk_hex"]
    sig = bytes.fromhex(gsig)
    mall = [
        (gb64, (sig[:-1]).hex(), gpk, "signature one byte short, MUST reject"),
        (gb64, (sig + b"\x00").hex(), gpk, "signature one byte long, MUST reject"),
        (gb64, ("00" * 64), gpk, "all-zero signature, MUST reject"),
        (gb64, (bytes([sig[0] ^ 0x01]) + sig[1:]).hex(), gpk, "flipped bit in R, MUST reject"),
        (gb64, (sig[:32] + bytes([sig[32] ^ 0x01]) + sig[33:]).hex(), gpk, "flipped bit in S, MUST reject"),
    ]
    # Non-canonical S encoding malleability: S and S+L both satisfy the verify
    # equation (L*B = identity), so a verifier that does not require S < L accepts
    # a second encoding of the same signature -- breaking replay/dedup keys. All
    # four impls (libsodium, noble, Go stdlib, dalek) reject S >= L; freeze it.
    _L = (1 << 252) + 27742317777372353535851937790883648493
    _s_nc = int.from_bytes(sig[32:], "little") + _L
    if _s_nc < (1 << 256):
        mall.append((gb64, (sig[:32] + _s_nc.to_bytes(32, "little")).hex(), gpk,
                     "non-canonical S (S+L, S>=L) encoding malleability, MUST reject"))
    for b64, sh, pk, note in mall:
        out["ed25519_verify"].append(
            {"signing_base_b64": b64, "sig_hex": sh, "pk_hex": pk,
             "expect_valid": ed_verdict(b64, sh, pk), "note": note})

    # 6) ecdsa_verify: carry frozen v0 pairs, then curve negatives + high-s under strict.
    for curve in ("p256", "p384"):
        for rec in ev0[curve]:
            note = "valid control" if rec["expect_valid"] else "tampered signature, MUST reject"
            out["ecdsa_verify"].append(
                {"curve": curve, "msg_hex": rec["msg_hex"],
                 "pub_uncompressed_hex": rec["pub_uncompressed_hex"],
                 "sig_raw_hex": rec["sig_raw_hex"], "expect_valid": rec["expect_valid"],
                 "strict_low_s": False, "note": note})

    def add_ecdsa(curve, msg_hex, pub_hex, sig_hex, strict, note):
        out["ecdsa_verify"].append(
            {"curve": curve, "msg_hex": msg_hex, "pub_uncompressed_hex": pub_hex,
             "sig_raw_hex": sig_hex, "strict_low_s": strict,
             "expect_valid": ecdsa_verdict(curve, msg_hex, pub_hex, sig_hex, strict),
             "note": note})

    curveinfo = {
        "p256": (32,
                 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
        "p384": (48,
                 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
    }
    for curve, (flen, n) in curveinfo.items():
        p0 = ev0[curve][0]  # a FROZEN valid vector (deterministic source)
        msg_hex, pub_hex = p0["msg_hex"], p0["pub_uncompressed_hex"]
        # off-curve pubkey: flip the final Y byte so the point is not on the curve
        bad_pub = bytearray(bytes.fromhex(pub_hex))
        bad_pub[-1] ^= 0x01
        add_ecdsa(curve, msg_hex, bad_pub.hex(), p0["sig_raw_hex"], False,
                  "public key point not on curve, MUST reject")
        # r out of range (r = 0)
        add_ecdsa(curve, msg_hex, pub_hex, ("00" * flen) + p0["sig_raw_hex"][flen * 2:], False,
                  "r = 0 out of [1,n-1], MUST reject")
        # wrong fixed width (one byte short)
        add_ecdsa(curve, msg_hex, pub_hex, p0["sig_raw_hex"][:-2], False,
                  "signature wrong fixed width, MUST reject")
        # high-s malleable twin of the frozen valid vector: (r, n-s). Valid under
        # non-strict ECDSA malleability, rejected under strict-low-s. Derived from
        # the pinned key/signature -> fully deterministic and reproducible.
        vsig = bytes.fromhex(p0["sig_raw_hex"])
        r_b, s_b = vsig[:flen], vsig[flen:]
        s = int.from_bytes(s_b, "big")
        s_high = n - s if 2 * s < n else s
        hs_hex = r_b.hex() + s_high.to_bytes(flen, "big").hex()
        add_ecdsa(curve, msg_hex, pub_hex, hs_hex, True,
                  "high-s malleable signature under strict-low-s, MUST reject")
        add_ecdsa(curve, msg_hex, pub_hex, hs_hex, False,
                  "same high-s signature accepted when strict-low-s OFF (control)")

    p = os.path.join(CORPUS_DIR, "rfc9421_negative_v1.json")
    json.dump(out, open(p, "w", encoding="utf-8"), indent=1)
    counts = {k: len(v) for k, v in out.items() if isinstance(v, list)}
    print("wrote", p)
    print("counts:", counts, "total", sum(counts.values()))


if __name__ == "__main__":
    main()
