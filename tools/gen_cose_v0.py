#!/usr/bin/env python3
"""Deterministically generate the COSE_Sign1 corpus (cose_v0).

Consumes the frozen public material (vectors/cose_material_v0.json) and stamps
every expected verdict with tools/oracle_cose.py, the single reference decision
surface. The python runner re-uses that surface (python is the reference
language); the KAT gate re-derives every verdict with a SEPARATE third-party COSE
library (pycose) plus an independent cbor2 canonical check, so a corpus that merely
agrees with our own surface cannot pass.

Every case is self-describing. A COSE_Sign1 case carries the message hex, the name
of the public key the verifier holds (into the corpus `keys` map), an `expect_valid`
bool, and a `note`. A deterministic-CBOR case carries a raw CBOR datum hex and
whether it is accepted as RFC 8949 Section 4.2 canonical. Negatives are CBOR
surgery on the frozen valid messages (tampered signature, truncated R||S) or a
change of the held key (wrong key, off-curve point, alg/key mismatch).

Sections (RFC 9052 Section 4.2 COSE_Sign1, RFC 9053 algorithms, RFC 8949 Section
4.2 deterministic CBOR):
  cose_sig_structure     the exact Sig_structure preimage, byte-for-byte
  cose_deterministic_cbor  accept canonical, reject non-canonical CBOR
  cose_protected_header  alg in protected vs only unprotected; crit honored
  cose_es256_verify      ES256 (alg -7) verify verdicts
  cose_eddsa_verify      EdDSA (alg -8) verify verdicts
  cose_ps256_verify      PS256 (alg -37) verify verdicts
  cose_crit              unknown critical header label rejected

ECDSA low-s is deliberately deferred to the FAPI profile, not enforced here (see
the policy block). Deterministic and LF-only for a byte-stable signed digest.

Run:  python tools/gen_cose_v0.py
"""
from __future__ import annotations

import json
import os
import sys

import cbor2
from cbor2 import CBORTag

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_cose as O  # noqa: E402

REPO = os.path.dirname(HERE)
MATERIAL = os.path.join(REPO, "vectors", "cose_material_v0.json")
OUT_DIR = os.path.join(REPO, "corpus", "cose_v0")
OUT = os.path.join(OUT_DIR, "cose_v0.json")

SECTIONS = ("cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
            "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit")


# ---------------------------------------------------------------------------
# COSE_Sign1 surgery helpers, for building tampered and malformed negatives.
# ---------------------------------------------------------------------------

def _decode(hexstr: str):
    """Return the mutable 4-element array of a tagged COSE_Sign1 hex."""
    top = cbor2.loads(bytes.fromhex(hexstr))
    return O._mutable(top.value)


def _encode(arr) -> str:
    return cbor2.dumps(CBORTag(O.COSE_SIGN1_TAG, arr), canonical=True).hex()


def _tamper_sig(hexstr: str) -> str:
    arr = _decode(hexstr)
    sig = bytearray(arr[3])
    sig[0] ^= 0x01
    arr[3] = bytes(sig)
    return _encode(arr)


def _truncate_sig(hexstr: str, nbytes: int) -> str:
    arr = _decode(hexstr)
    arr[3] = arr[3][:nbytes]
    return _encode(arr)


# ---------------------------------------------------------------------------
# Deterministic-CBOR datums (RFC 8949 Section 4.2), by hand so the exact bytes
# are auditable. Accept = canonical; reject = decodes fine but re-encodes shorter,
# definite, or sorted.
# ---------------------------------------------------------------------------

DCBOR_CASES = [
    ("a10126", True, "canonical map {1: -7} (a COSE protected header for ES256)"),
    ("83010203", True, "canonical definite-length array [1, 2, 3]"),
    ("63616263", True, "canonical definite-length text string \"abc\""),
    ("1817", False, "non-shortest integer: 23 encoded in a uint8 (0x1817) not 0x17"),
    ("9f010203ff", False, "indefinite-length array (0x9f ... 0xff)"),
    ("bf0102ff", False, "indefinite-length map (0xbf ... 0xff)"),
    ("7f63616263ff", False, "indefinite-length text string (chunked \"abc\")"),
    ("a202000100", False, "unsorted map keys {2: 0, 1: 0} (canonical order is 1 then 2)"),
]


def build(m):
    keys = m["keys"]
    payload = bytes.fromhex(m["payload_hex"])
    es, ed, ps = m["messages"]["es256"], m["messages"]["eddsa"], m["messages"]["ps256"]
    alg_unprot = m["messages"]["es256_alg_unprotected"]
    crit_ok, crit_bad = m["messages"]["es256_crit_honored"], m["messages"]["es256_crit_unknown"]

    # The Sig_structure preimage for the frozen ES256 / EdDSA messages, rebuilt from
    # their protected bytes and payload, exactly as a signer/verifier computes it.
    es_prot = _decode(es)[0]
    ed_prot = _decode(ed)[0]
    es_sig_struct = O.sig_structure(es_prot, payload).hex()
    ed_sig_struct = O.sig_structure(ed_prot, payload).hex()

    corpus = {
        "name": "cose_v0",
        "description": ("Signed cross-language conformance battery for COSE_Sign1 "
                        "(CBOR Object Signing and Encryption, RFC 9052 Section 4.2) "
                        "with the RFC 9053 algorithms ES256 (alg -7), EdDSA (alg -8) "
                        "and PS256 (alg -37): the Sig_structure signing preimage, "
                        "RFC 8949 Section 4.2 deterministic CBOR, the protected-header "
                        "security rules that lenient verifiers get wrong (alg must be "
                        "integrity-protected, an unknown crit label rejected, the "
                        "protected header deterministically encoded, alg/key-type "
                        "match), and the ES256 / EdDSA / PS256 signature verdicts. "
                        "This is the CBOR sign/verify stage of the signing-flow bridge, "
                        "the COSE sibling of the jws_v0 JOSE corpus."),
        "profile": "cose-sign1",
        "policy": {
            "specs": ["RFC9052", "RFC9053", "RFC8949"],
            "algorithms": ["ES256", "EdDSA", "PS256"],
            "sig_structure": "[\"Signature1\", protected (bstr), external_aad (bstr, empty), payload (bstr)]",
            "deterministic_cbor": ("RFC 8949 Section 4.2 core deterministic encoding: "
                                   "shortest-form integers, definite lengths, and "
                                   "bytewise-lexicographic map key order. This is the "
                                   "ordering RFC 9052 references and the ordering the "
                                   "independent library (cbor2 canonical mode) enforces, "
                                   "so the corpus and the KAT agree on it. The older "
                                   "length-first (CTAP2) ordering is NOT used."),
            "security_rules": [
                "alg (label 1) must be in the protected header; alg only in the unprotected header is rejected",
                "an unknown or unsupported crit (label 2) label is rejected",
                "the protected header is deterministically encoded (RFC 8949 Section 4.2)",
                "alg must match the held key type (ES256->EC2, EdDSA->OKP, PS256->RSA)",
            ],
            "low_s": ("NOT enforced. Plain COSE/JOSE permit a high-s ECDSA signature; "
                      "low-s is a FAPI profile rule (fapi_messagesigning_v0), not a "
                      "COSE rule, so it is deliberately out of cose_v0 scope."),
            "documented_divergences": [],
        },
        # Public COSE keys the cases reference by name. Only public key material ships.
        "keys": keys,
    }
    for s in SECTIONS:
        corpus[s] = []

    # -- cose_sig_structure: the exact signing preimage, byte-for-byte -----------
    corpus["cose_sig_structure"] = [
        {"cose_hex": es, "key": "ec", "sig_structure_hex": es_sig_struct, "expect_valid": True,
         "note": "ES256 COSE_Sign1: Sig_structure = [\"Signature1\", protected, h'', payload], "
                 "deterministic CBOR; asserted byte-for-byte"},
        {"cose_hex": ed, "key": "ed25519", "sig_structure_hex": ed_sig_struct, "expect_valid": True,
         "note": "EdDSA COSE_Sign1: Sig_structure over the same four-element preimage, "
                 "asserted byte-for-byte"},
    ]

    # -- cose_deterministic_cbor: RFC 8949 Section 4.2 accept/reject --------------
    corpus["cose_deterministic_cbor"] = [
        {"cbor_hex": h, "expect_valid": ok, "note": note} for h, ok, note in DCBOR_CASES
    ]

    # -- cose_protected_header: alg placement and a honored crit -----------------
    corpus["cose_protected_header"] = [
        {"cose_hex": es, "key": "ec", "expect_valid": True,
         "note": "alg in the protected header (integrity-protected), accepted"},
        {"cose_hex": alg_unprot, "key": "ec", "expect_valid": False,
         "note": "alg carried ONLY in the unprotected header (not integrity-protected), rejected"},
        {"cose_hex": crit_ok, "key": "ec", "expect_valid": True,
         "note": "crit lists label 1 (alg), which the verifier understands: honored, accepted"},
    ]

    # -- cose_es256_verify: ECDSA P-256 SHA-256 (alg -7) -------------------------
    corpus["cose_es256_verify"] = [
        {"cose_hex": es, "key": "ec", "expect_valid": True,
         "note": "valid ES256 control (high-s permitted; low-s not enforced in cose_v0)"},
        {"cose_hex": _tamper_sig(es), "key": "ec", "expect_valid": False,
         "note": "one-byte-tampered ES256 signature"},
        {"cose_hex": _truncate_sig(es, 63), "key": "ec", "expect_valid": False,
         "note": "wrong-width R||S (63 bytes; a COSE ES256 signature is exactly 64)"},
        {"cose_hex": es, "key": "offcurve_ec", "expect_valid": False,
         "note": "public key point is not on secp256r1 (rejected before trust)"},
        {"cose_hex": es, "key": "wrong_ec", "expect_valid": False,
         "note": "valid ES256 message verified under a different (wrong) EC key"},
        {"cose_hex": es, "key": "ed25519", "expect_valid": False,
         "note": "ES256 message verified while holding an OKP key (alg/key-type mismatch)"},
    ]

    # -- cose_eddsa_verify: Ed25519 (alg -8) -------------------------------------
    corpus["cose_eddsa_verify"] = [
        {"cose_hex": ed, "key": "ed25519", "expect_valid": True,
         "note": "valid EdDSA (Ed25519) control"},
        {"cose_hex": _tamper_sig(ed), "key": "ed25519", "expect_valid": False,
         "note": "one-byte-tampered EdDSA signature"},
        {"cose_hex": ed, "key": "wrong_ed25519", "expect_valid": False,
         "note": "valid EdDSA message verified under a different (wrong) Ed25519 key"},
    ]

    # -- cose_ps256_verify: RSASSA-PSS SHA-256 (alg -37) -------------------------
    corpus["cose_ps256_verify"] = [
        {"cose_hex": ps, "key": "rsa", "expect_valid": True,
         "note": "valid PS256 control"},
        {"cose_hex": _tamper_sig(ps), "key": "rsa", "expect_valid": False,
         "note": "one-byte-tampered PS256 signature"},
    ]

    # -- cose_crit: an unknown critical header label must be rejected -------------
    corpus["cose_crit"] = [
        {"cose_hex": crit_bad, "key": "ec", "expect_valid": False,
         "note": "crit lists an unregistered label the verifier does not understand, rejected"},
        {"cose_hex": crit_ok, "key": "ec", "expect_valid": True,
         "note": "crit lists label 1 (alg), understood by the verifier: honored, accepted (control)"},
    ]
    return corpus


def main() -> int:
    m = json.load(open(MATERIAL, encoding="utf-8"))
    corpus = build(m)

    # Stamp every verdict from the oracle and assert the intended sign of each case,
    # so a mislabeled positive/negative cannot slip into the corpus.
    for sec in SECTIONS:
        for c in corpus[sec]:
            if sec == "cose_deterministic_cbor":
                accept, reason = O.is_deterministic_cbor(bytes.fromhex(c["cbor_hex"]))
            else:
                accept, reason = O.verdict(bytes.fromhex(c["cose_hex"]), corpus["keys"][c["key"]])
            if accept != c["expect_valid"]:
                raise SystemExit(
                    f"oracle disagrees with the intended verdict [{sec}]: {c['note']!r} "
                    f"(expect_valid={c['expect_valid']} oracle={accept} reason={reason})")
            if sec == "cose_sig_structure":
                built = O.sig_structure(_decode(c["cose_hex"])[0], bytes.fromhex(m["payload_hex"])).hex()
                if built != c["sig_structure_hex"]:
                    raise SystemExit(f"Sig_structure hex mismatch [{sec}]: {c['note']!r}")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    counts = {k: len(v) for k, v in corpus.items() if isinstance(v, list)}
    print("generated", OUT)
    print("  sections", counts)
    print("  total_cases", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
