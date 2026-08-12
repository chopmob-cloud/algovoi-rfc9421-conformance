#!/usr/bin/env python3
"""Seal a KAF assurance receipt for rfc9421_negative_v1.

Binds the three KAF axes that this repo proves into one signed, re-verifiable
receipt:

  - Agreement : the 10-way byte-for-byte consensus (tools/run_consensus.sh).
  - Cells     : the per-runtime verdicts from kaf/run_cells.sh (image digests).
  - Seal      : this receipt, EdDSA-signed over the canonical payload, bound to
                the corpus's signed manifest head (corpus_digest / file_sha256).

The signing (seal) secret is an Ed25519 key held OFF-REPO; only the public JWK
(kaf/keys/kaf-seal.pub.json) is committed, so a receipt is forgery-resistant and
anyone can verify it with kaf/kaf_verify.py.

Usage:
  python kaf/seal_receipt.py --secret <path> --sealed-at <iso8601> [--seq N]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys

from nacl.signing import SigningKey

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(HERE, "corpus", "rfc9421_negative_v1")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def canonical(obj) -> bytes:
    """Canonical seal preimage: RFC 8785 (JCS), the AlgoVoi canonicalization
    standard, REQUIRED on both the seal and verify sides. No silent fallback: a
    divergent canonicalizer would let a valid receipt fail to verify or mask a
    canonicalization split, so we pin one and fail loudly if it is absent."""
    import rfc8785
    return rfc8785.dumps(obj)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret", required=True, help="path to the Ed25519 seal secret (32-byte seed, hex)")
    ap.add_argument("--sealed-at", required=True, help="ISO-8601 timestamp (passed in; the script does not read the clock)")
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--corpus", default=os.path.join(
        HERE, "corpus", "rfc9421_negative_v2", "rfc9421_negative_v2.json"),
        help="corpus path to seal (defaults to the v2 superset)")
    args = ap.parse_args()

    corpus_path = args.corpus
    corpus_dir = os.path.dirname(corpus_path)
    with open(corpus_path, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    with open(corpus_path[:-len(".json")] + ".manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    head = manifest["head"]
    with open(os.path.join(HERE, "kaf", "cells.results.json"), encoding="utf-8") as fh:
        cells = json.load(fh)
    with open(os.path.join(corpus_dir, "kat_anchors_v1.json"), encoding="utf-8") as fh:
        anchors = json.load(fh)["anchors"]

    # every list-valued section counts (so new sections like rsa_verify are included)
    total_cases = sum(len(v) for v in corpus.values() if isinstance(v, list))
    cells_pass = [c for c in cells if c["verdict"] == "PASS"]

    # Hardening: a seal must never lend cryptographic confidence to an unverified
    # or partial result. Refuse to produce a receipt unless (a) the KAT integrity
    # gate passes (corpus is the exact signed artifact and its signing bases match
    # the independent anchors) and (b) every cell passed. The agreement claim is
    # then DERIVED from the distinct languages that actually passed, never asserted.
    kat = subprocess.run([sys.executable, os.path.join(HERE, "tools", "check_kat.py"), corpus_path],
                         capture_output=True, text=True)
    if kat.returncode != 0:
        print("refusing to seal: KAT integrity gate failed\n" + kat.stdout + kat.stderr, file=sys.stderr)
        return 1
    if not cells or len(cells_pass) != len(cells):
        print(f"refusing to seal: {len(cells_pass)}/{len(cells)} cells passed "
              "(a receipt must attest a complete, all-pass run)", file=sys.stderr)
        return 1
    independent_langs = sorted({c["lang"] for c in cells_pass})

    sk = SigningKey(bytes.fromhex(open(args.secret).read().strip()))
    vk = sk.verify_key
    kid = hashlib.sha256(bytes(vk)).hexdigest()[:32]

    payload = {
        "framework": "KAF",
        "layer": "L2",
        "suite": corpus["name"],
        "sealed_at": args.sealed_at,
        "seq": args.seq,
        "corpus": {
            "id": corpus["name"],
            "file_sha256": "sha256:" + hashlib.sha256(corpus_bytes).hexdigest(),
            "manifest_file_sha256": head.get("file_sha256"),
            "manifest_corpus_digest": head.get("corpus_digest"),
            "signed_head": bool(manifest.get("head_jws")),
            "total_cases": total_cases,
        },
        "axes": {
            "agreement": {
                "independent_runners": len(independent_langs),
                "languages": independent_langs,
                "result": f"full {len(independent_langs)}-way byte-for-byte consensus",
                "cases": total_cases,
            },
            "kat": {
                "independent_anchors": len(anchors),
                "corpus_integrity": "matches signed manifest head",
            },
            "cells": [
                {"cell": c["cell"], "lang": c["lang"], "image": c["image"],
                 "image_digest": c["image_digest"], "verdict": c["verdict"]}
                for c in cells
            ],
            "cells_passed": len(cells_pass),
            "cells_total": len(cells),
        },
    }

    preimage = canonical(payload)
    sig = sk.sign(preimage).signature
    receipt = {
        "payload": payload,
        "seal": {
            "alg": "Ed25519",
            "canonicalization": "JCS(RFC8785)",
            "kid": kid,
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(bytes(vk)), "kid": kid},
            "sig_b64": base64.b64encode(sig).decode("ascii"),
        },
    }

    out = os.path.join(HERE, "kaf", "receipts", f"{corpus['name']}.seq{args.seq}.receipt.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2)
        fh.write("\n")

    # publish the public verify key (idempotent)
    keys_dir = os.path.join(HERE, "kaf", "keys")
    os.makedirs(keys_dir, exist_ok=True)
    with open(os.path.join(keys_dir, "kaf-seal.pub.json"), "w", encoding="utf-8") as fh:
        json.dump(receipt["seal"]["jwk"], fh, indent=2)
        fh.write("\n")

    print(f"sealed: {out}")
    print(f"  kid {kid}  cells {len(cells_pass)}/{len(cells)}  cases {total_cases}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
