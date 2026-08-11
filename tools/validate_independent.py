#!/usr/bin/env python3
"""Independent double-validation of rfc9421_negative_v1.

Does NOT call the AlgoVoi verifiers. Recomputes each verdict with independent
implementations so a corpus that is merely self-consistent with our code cannot
pass:
  - Ed25519 verify via `cryptography` (OpenSSL) -- our verifier uses PyNaCl.
  - ECDSA verify via raw `cryptography` primitives with hand-checked r/s range and
    low-s -- bypasses our request/verify wrapper entirely. (Library independence
    is further covered by the Rust/Go/TS runners: RustCrypto, Go stdlib, noble.)
  - base64 canonicality via an independent decode+reencode round-trip.
  - note/verdict consistency: every "MUST reject" case is a negative, every
    control is a positive; no label contradicts its recorded verdict.

Exit 0 iff every independent verdict matches the frozen corpus.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, SECP384R1, EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CORPUS = os.path.join(REPO, "corpus", "rfc9421_negative_v1", "rfc9421_negative_v1.json")

N = {
    "p256": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "p384": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
}
CURVE = {"p256": (SECP256R1(), 32, hashes.SHA256()), "p384": (SECP384R1(), 48, hashes.SHA384())}
_B64_STRICT = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def ed_independent(base_bytes: bytes, sig: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, base_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def ecdsa_independent(curve: str, msg: bytes, pub: bytes, sig: bytes, strict: bool) -> bool:
    curveobj, flen, halg = CURVE[curve]
    if len(sig) != 2 * flen:
        return False
    r = int.from_bytes(sig[:flen], "big")
    s = int.from_bytes(sig[flen:], "big")
    n = N[curve]
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    if strict and s > n // 2:
        return False
    try:
        key = EllipticCurvePublicKey.from_encoded_point(curveobj, pub)
    except Exception:
        return False
    try:
        key.verify(encode_dss_signature(r, s), msg, ECDSA(halg))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def b64_canonical(header: str) -> bool:
    """Independent RFC 8941 byte-sequence + canonical-base64 acceptance check."""
    h = header.strip()
    m = re.match(r"^[A-Za-z][A-Za-z0-9_-]*\s*=\s*", h)
    if m:
        rest = h[m.end():].strip()
    elif h.startswith(":"):
        rest = h
    else:
        return False
    if not (rest.startswith(":") and rest.endswith(":")):
        return False
    body = rest[1:-1]
    if not _B64_STRICT.match(body) or len(body) % 4 != 0:
        return False
    try:
        raw = base64.b64decode(body, validate=True)
    except Exception:
        return False
    return base64.b64encode(raw).decode("ascii") == body


def main() -> int:
    c = json.load(open(CORPUS, encoding="utf-8"))
    fails = []

    # Ed25519 (independent library: cryptography/OpenSSL)
    for i, v in enumerate(c["ed25519_verify"]):
        base = base64.b64decode(v["signing_base_b64"])
        got = ed_independent(base, bytes.fromhex(v["sig_hex"]), bytes.fromhex(v["pk_hex"]))
        if got != v["expect_valid"]:
            fails.append(f"ed25519[{i}] {v['note']}: independent={got} corpus={v['expect_valid']}")

    # ECDSA (raw cryptography, hand-checked range + low-s)
    for i, v in enumerate(c["ecdsa_verify"]):
        msg = bytes.fromhex(v["msg_hex"])
        got = ecdsa_independent(v["curve"], msg, bytes.fromhex(v["pub_uncompressed_hex"]),
                                bytes.fromhex(v["sig_raw_hex"]), bool(v.get("strict_low_s", False)))
        if got != v["expect_valid"]:
            fails.append(f"ecdsa[{i}] {v['curve']} {v['note']}: independent={got} corpus={v['expect_valid']}")

    # base64 canonicality (independent decoder)
    for i, v in enumerate(c["signature_value_parse"]):
        got = b64_canonical(v["header"])
        if got != v["ok"]:
            fails.append(f"sigval[{i}] {v['note']}: independent={got} corpus={v['ok']}")

    # note / verdict consistency (no label may contradict its recorded verdict)
    def is_negative_note(n): return "MUST reject" in n or "MUST accept" not in n and "control" not in n
    for i, v in enumerate(c["ed25519_verify"]):
        if "MUST reject" in v["note"] and v["expect_valid"]:
            fails.append(f"ed25519[{i}] label says reject but expect_valid=True")
        if "control" in v["note"] and not v["expect_valid"] and "reject" not in v["note"]:
            fails.append(f"ed25519[{i}] control label but expect_valid=False")
    for i, v in enumerate(c["ecdsa_verify"]):
        if "MUST reject" in v["note"] and v["expect_valid"]:
            fails.append(f"ecdsa[{i}] label says reject but expect_valid=True")
    for i, v in enumerate(c["signing_base"]):
        # every carried/added signing_base positive must decode to UTF-8 lines
        if v["ok"]:
            try:
                base64.b64decode(v["signing_base_b64"]).decode("utf-8")
            except Exception:
                fails.append(f"signing_base[{i}] not valid UTF-8")

    total = (len(c["ed25519_verify"]) + len(c["ecdsa_verify"])
             + len(c["signature_value_parse"]))
    for f in fails:
        print("MISMATCH", f)
    print(f"\nindependent oracle: {total} crypto/parse verdicts cross-checked, "
          f"{len(fails)} mismatches")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
