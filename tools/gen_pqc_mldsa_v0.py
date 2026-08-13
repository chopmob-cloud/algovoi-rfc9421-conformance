#!/usr/bin/env python3
"""Deterministically generate the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).

Consumes the frozen public material (vectors/pqc_mldsa_material_v0.json) and stamps
every expected verdict with tools/oracle_pqc_mldsa.py, the single reference decision
surface (liboqs FIPS-204 ML-DSA-65 verify). The python runner re-uses that surface
(python is the reference language); the KAT gate (tools/check_kat_pqc_mldsa.py)
re-derives every verdict with a SEPARATE FIPS-204 ML-DSA-65 implementation
(dilithium-py), so a corpus that merely agrees with our own surface cannot pass,
and a Dilithium-vs-ML-DSA mismatch is caught.

Every case is fully self-describing: it carries the public key, the message, and
the signature as hex, an `expect_valid` bool, and a `note`. Negatives are
tamperings of the frozen valid material (flipped signature byte, altered message,
wrong public key) and malformed inputs (wrong-length signature / public key, empty
signature). Deterministic and LF-only for a byte-stable signed digest.

Optional NIST ACVP anchors: if vectors/pqc_mldsa_acvp_anchors.json is present (a
small set of official ML-DSA-65 sigVer known-answer vectors), an mldsa65_acvp_kat
section is emitted. Stage-1 does not block on ACVP; absent that file the section is
omitted with the corpus noting so.

Run (needs liboqs / the oqs package):  python tools/gen_pqc_mldsa_v0.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_pqc_mldsa as O  # noqa: E402

REPO = os.path.dirname(HERE)
MATERIAL = os.path.join(REPO, "vectors", "pqc_mldsa_material_v0.json")
ACVP = os.path.join(REPO, "vectors", "pqc_mldsa_acvp_anchors.json")
OUT_DIR = os.path.join(REPO, "corpus", "pqc_mldsa_v0")
OUT = os.path.join(OUT_DIR, "pqc_mldsa_v0.json")

BASE_SECTIONS = ("mldsa65_verify", "mldsa65_malformed")
ACVP_SECTION = "mldsa65_acvp_kat"


def _flip_first_byte(hexstr: str) -> str:
    return _flip_byte_at(hexstr, 0)


def _flip_byte_at(hexstr: str, idx: int) -> str:
    b = bytearray(bytes.fromhex(hexstr))
    b[idx] ^= 0x01
    return bytes(b).hex()


def _truncate(hexstr: str, drop: int) -> str:
    b = bytes.fromhex(hexstr)
    return b[:len(b) - drop].hex()


def _extend(hexstr: str, add: int) -> str:
    return (bytes.fromhex(hexstr) + b"\x00" * add).hex()


def _const_sig(byte_val: int) -> str:
    """A right-length (FIPS-204 3309) signature of a single repeated byte: a
    structurally degenerate value that must reach the verify and be rejected, not
    caught by the length gate."""
    return (bytes([byte_val]) * O.SIG_LEN).hex()


def _garbage_pk() -> str:
    """A deterministic right-length (FIPS-204 1952) but meaningless public key: a
    well-sized key that no signature was produced under, so every valid signature
    must reject against it."""
    return bytes(((i * 7 + 3) & 0xFF) for i in range(O.PK_LEN)).hex()


def build(m, acvp):
    pk = m["public_key_hex"]
    wrong_pk = m["wrong_public_key_hex"]
    msg = m["messages"]
    sig = m["signatures"]
    ds = m["domain_separation"]
    ds_pk = ds["public_key_hex"]
    ds_sig = ds["signatures"]
    ds_ctx = ds["context_label"]

    corpus = {
        "name": "pqc_mldsa_v0",
        "description": ("Signed cross-language conformance battery for post-quantum "
                        "ML-DSA-65 signature verification (NIST FIPS 204 final, 2024): "
                        "the valid-signature accept controls, the tamper rejections "
                        "(flipped signature byte, altered message, wrong public key), "
                        "the malformed-input rejections (wrong-length signature or "
                        "public key, empty signature), the FIPS-204 domain-separation "
                        "negatives (a non-empty context-string signature and a "
                        "HashML-DSA-65 pre-hash signature that both reject under pure "
                        "empty-context verify), and the structural / degenerate-key "
                        "rejections (all-zero and all-0xFF right-length signatures, "
                        "z-region and hint-region tampers, all-zero and garbage "
                        "right-length public keys). This is the post-quantum "
                        "sign/verify stage of the signing-flow bridge, the ML-DSA "
                        "sibling of the classical jws_v0 / cose_v0 corpora. FIPS 204 "
                        "final ML-DSA is NOT interoperable with round-3 Dilithium."),
        "profile": "pqc-ml-dsa",
        "policy": {
            "spec": O.SPEC,
            "parameter_set": O.MECHANISM,
            "context_string": "empty (pure ML-DSA variant)",
            "lengths": {"public_key": O.PK_LEN, "signature": O.SIG_LEN},
            "fips204_not_dilithium": ("FIPS 204 (final, 2024) added domain separation and "
                                      "revised encodings; an ML-DSA-65 signature does NOT "
                                      "verify under a round-3 Dilithium3 verifier and vice "
                                      "versa. Every implementation here is FIPS-204 final "
                                      "ML-DSA-65, cross-checked by an independent FIPS-204 "
                                      "library in the KAT gate."),
            "security_rules": [
                "a wrong-length public key is rejected before verify",
                "a wrong-length signature (empty included) is rejected before verify",
                "a one-byte-tampered signature is rejected",
                "a signature verified against an altered message is rejected",
                "a signature verified under the wrong public key is rejected",
                "a non-empty context-string signature is rejected under pure empty-context verify (FIPS-204 domain separation)",
                "a HashML-DSA-65 pre-hash signature is rejected under pure ML-DSA-65 verify (algorithm/domain separation)",
                "an all-zero or all-0xFF right-length signature reaches the verify and is rejected, not caught by the length gate",
                "a z-region and a hint-region single-byte tamper are both rejected",
                "an all-zero or garbage right-length public key reaches the verify and is rejected uniformly, without erroring out",
            ],
            "adversarial_notes": (
                "The domain-separation negatives are genuine verdict distinguishers: a "
                "lenient verifier that ignores the context string, or a round-3 Dilithium "
                "port that lacks FIPS-204 domain separation, would WRONGLY accept them. "
                "The structural-signature and degenerate-key negatives are rejected by "
                "every FIPS-204 implementation via the challenge recomputation; they are "
                "not forgery distinguishers (a norm-bound or hint bypass is caught by the "
                "challenge check regardless) but decode-robustness and reject-consistency "
                "coverage across all twelve runtimes."),
            "documented_divergences": [],
        },
    }
    for s in BASE_SECTIONS:
        corpus[s] = []

    # -- mldsa65_verify: accept controls + cryptographic rejections ------------
    corpus["mldsa65_verify"] = [
        {"public_key": pk, "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": True,
         "note": "valid ML-DSA-65 control (primary message), accepts"},
        {"public_key": pk, "message": msg["empty"], "signature": sig["empty"],
         "expect_valid": True,
         "note": "valid ML-DSA-65 signature over the empty message, accepts"},
        {"public_key": pk, "message": msg["short"], "signature": sig["short"],
         "expect_valid": True,
         "note": "valid ML-DSA-65 control (short message), accepts"},
        {"public_key": pk, "message": msg["primary"], "signature": _flip_first_byte(sig["primary"]),
         "expect_valid": False,
         "note": "one-byte-tampered signature (first byte flipped), rejects"},
        {"public_key": pk, "message": _flip_first_byte(msg["primary"]), "signature": sig["primary"],
         "expect_valid": False,
         "note": "altered message (first byte flipped), signature no longer covers it, rejects"},
        {"public_key": pk, "message": msg["empty"], "signature": sig["primary"],
         "expect_valid": False,
         "note": "primary-message signature verified against a different (empty) message, rejects"},
        {"public_key": wrong_pk, "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": False,
         "note": "valid signature verified under a different (wrong) ML-DSA-65 public key, rejects"},

        # -- domain separation (FIPS-204's headline change vs round-3 Dilithium):
        #    same throwaway key + same message; only the signing domain differs. A
        #    lenient verifier that ignores the context string, or a round-3 port
        #    without domain separation, would WRONGLY accept the two negatives.
        {"public_key": ds_pk, "message": msg["primary"], "signature": ds_sig["pure"],
         "expect_valid": True,
         "note": "domain-sep control: pure empty-context ML-DSA-65 signature, accepts"},
        {"public_key": ds_pk, "message": msg["primary"], "signature": ds_sig["context"],
         "expect_valid": False,
         "note": (f"domain separation: signature made with a non-empty context string "
                  f"({ds_ctx!r}) rejects under pure empty-context ML-DSA-65 verify")},
        {"public_key": ds_pk, "message": msg["primary"], "signature": ds_sig["prehash"],
         "expect_valid": False,
         "note": ("domain separation: a HashML-DSA-65 (SHA-512 pre-hash) signature "
                  "rejects under pure ML-DSA-65 verify")},

        # -- structural signatures: right length (reach the verify, not the length
        #    gate), degenerate or region-tampered content; every implementation
        #    must decode and reject without diverging or crashing.
        {"public_key": pk, "message": msg["primary"], "signature": _const_sig(0x00),
         "expect_valid": False,
         "note": "all-zero signature of the correct FIPS-204 length, rejects"},
        {"public_key": pk, "message": msg["primary"], "signature": _const_sig(0xFF),
         "expect_valid": False,
         "note": "all-0xFF signature of the correct FIPS-204 length, rejects"},
        {"public_key": pk, "message": msg["primary"], "signature": _flip_byte_at(sig["primary"], 100),
         "expect_valid": False,
         "note": "signature byte flipped in the z-vector region (offset 100), rejects"},
        {"public_key": pk, "message": msg["primary"], "signature": _flip_byte_at(sig["primary"], O.SIG_LEN - 9),
         "expect_valid": False,
         "note": "signature byte flipped in the hint region (near end), rejects"},

        # -- malformed-but-right-length public key: passes the length gate, reaches
        #    the verify, and must reject (not error out) uniformly.
        {"public_key": ("00" * O.PK_LEN), "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": False,
         "note": "all-zero public key of the correct FIPS-204 length, rejects"},
        {"public_key": _garbage_pk(), "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": False,
         "note": "deterministic garbage public key of the correct FIPS-204 length, rejects"},
    ]

    # -- mldsa65_malformed: structural rejection before any verify -------------
    corpus["mldsa65_malformed"] = [
        {"public_key": pk, "message": msg["primary"], "signature": _truncate(sig["primary"], 1),
         "expect_valid": False,
         "note": f"signature one byte short of the FIPS-204 {O.SIG_LEN}, rejects"},
        {"public_key": pk, "message": msg["primary"], "signature": _extend(sig["primary"], 1),
         "expect_valid": False,
         "note": f"signature one byte over the FIPS-204 {O.SIG_LEN}, rejects"},
        {"public_key": pk, "message": msg["primary"], "signature": "",
         "expect_valid": False,
         "note": "empty signature, rejects"},
        {"public_key": _truncate(pk, 1), "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": False,
         "note": f"public key one byte short of the FIPS-204 {O.PK_LEN}, rejects"},
        {"public_key": _extend(pk, 1), "message": msg["primary"], "signature": sig["primary"],
         "expect_valid": False,
         "note": f"public key one byte over the FIPS-204 {O.PK_LEN}, rejects"},
    ]

    # -- mldsa65_acvp_kat: official NIST ACVP anchors, only if fetched ---------
    if acvp:
        cases = []
        for a in acvp["cases"]:
            cases.append({
                "public_key": a["public_key"], "message": a["message"],
                "signature": a["signature"], "expect_valid": bool(a["expect_valid"]),
                "note": "NIST ACVP ML-DSA-65 sigVer anchor: " + a.get("note", a.get("tcId", "")),
            })
        corpus[ACVP_SECTION] = cases
        corpus["policy"]["acvp_anchors"] = {
            "included": True, "source": acvp.get("source", "usnistgov/ACVP-Server"),
            "count": len(cases),
        }
    else:
        corpus["policy"]["acvp_anchors"] = {
            "included": False,
            "reason": ("NIST ACVP ML-DSA-65 sigVer vectors were not bundled for stage-1 "
                       "(no vectors/pqc_mldsa_acvp_anchors.json). Independence is proven "
                       "by the second FIPS-204 implementation in the KAT gate; ACVP "
                       "anchors are a later, non-blocking enhancement."),
        }
    return corpus


def sections_of(corpus):
    return [s for s in (*BASE_SECTIONS, ACVP_SECTION) if s in corpus]


def main() -> int:
    m = json.load(open(MATERIAL, encoding="utf-8"))
    acvp = json.load(open(ACVP, encoding="utf-8")) if os.path.exists(ACVP) else None
    corpus = build(m, acvp)

    # Stamp every verdict from the oracle and assert the intended sign of each
    # case, so a mislabeled positive/negative cannot slip into the corpus.
    for sec in sections_of(corpus):
        if not corpus[sec]:
            raise SystemExit(f"section {sec} is empty")
        for c in corpus[sec]:
            accept, reason = O.verdict(c["public_key"], c["message"], c["signature"])
            if accept != c["expect_valid"]:
                raise SystemExit(
                    f"oracle disagrees with the intended verdict [{sec}]: {c['note']!r} "
                    f"(expect_valid={c['expect_valid']} oracle={accept} reason={reason})")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    counts = {s: len(corpus[s]) for s in sections_of(corpus)}
    print("generated", OUT)
    print("  sections", counts)
    print("  total_cases", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
