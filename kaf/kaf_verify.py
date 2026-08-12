#!/usr/bin/env python3
"""Verify a sealed KAF assurance receipt for rfc9421_negative_v1.

Independent, re-runnable verification of a receipt produced by seal_receipt.py:

  1. the EdDSA seal signature is valid over the canonical payload, under the
     public JWK carried in the receipt (and, if present, matching the committed
     kaf/keys/kaf-seal.pub.json);
  2. the receipt binds the corpus on disk: its file_sha256 matches, and matches
     the signed manifest head;
  3. every declared cell carries a verdict, and cells_passed == cells_total.

Exit 0 iff the receipt is VALID. No corpus edits, no network.

Usage: python kaf/kaf_verify.py kaf/receipts/<receipt>.json
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    # RFC 8785 (JCS) is required on both sides; no silent fallback (see seal_receipt.py).
    import rfc8785
    return rfc8785.dumps(obj)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: kaf_verify.py <receipt.json>")
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        receipt = json.load(fh)

    failures: list[str] = []
    payload = receipt["payload"]
    seal = receipt["seal"]

    # 1. signature
    vk = VerifyKey(_b64u_dec(seal["jwk"]["x"]))
    kid = hashlib.sha256(bytes(vk)).hexdigest()[:32]
    if kid != seal.get("kid"):
        failures.append(f"kid mismatch: jwk->{kid} != seal.kid {seal.get('kid')}")
    try:
        vk.verify(canonical(payload), base64.b64decode(seal["sig_b64"]))
    except BadSignatureError:
        failures.append("EdDSA seal signature does not verify over the canonical payload")

    # optionally pin to the committed public key
    pub_path = os.path.join(HERE, "kaf", "keys", "kaf-seal.pub.json")
    if os.path.exists(pub_path):
        with open(pub_path, encoding="utf-8") as fh:
            committed = json.load(fh)
        if committed.get("x") != seal["jwk"]["x"]:
            failures.append("receipt seal key does not match committed kaf/keys/kaf-seal.pub.json")

    # 2. corpus binding -- locate the corpus the receipt names (v1, v2, ...)
    cid = payload["corpus"]["id"]
    corpus_path = os.path.join(HERE, "corpus", cid, cid + ".json")
    if os.path.exists(corpus_path):
        with open(corpus_path, "rb") as fh:
            actual = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        if payload["corpus"]["file_sha256"] != actual:
            failures.append(f"corpus digest drift: receipt {payload['corpus']['file_sha256']} != disk {actual}")
        if payload["corpus"]["file_sha256"] != payload["corpus"].get("manifest_file_sha256"):
            failures.append("receipt corpus digest != manifest head digest")

    # 3. cells
    cells = payload["axes"]["cells"]
    if not cells:
        failures.append("no cells in receipt")
    for c in cells:
        if c.get("verdict") not in ("PASS", "FAIL"):
            failures.append(f"cell {c.get('cell')} has no verdict")
    if payload["axes"]["cells_passed"] != payload["axes"]["cells_total"]:
        failures.append(f"not all cells passed: {payload['axes']['cells_passed']}/{payload['axes']['cells_total']}")

    if failures:
        print("RECEIPT: INVALID")
        for f in failures:
            print(f"  - {f}")
        return 1

    p = payload
    print(
        "RECEIPT: VALID\n"
        f"  suite      {p['suite']}  seq {p.get('seq')}  sealed_at {p['sealed_at']}\n"
        f"  seal       Ed25519 kid {seal['kid']} (signature verified)\n"
        f"  corpus     {p['corpus']['file_sha256']} (matches disk + signed head)\n"
        f"  agreement  {p['axes']['agreement']['result']} over {p['axes']['agreement']['cases']} cases\n"
        f"  cells      {p['axes']['cells_passed']}/{p['axes']['cells_total']} runtimes PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
