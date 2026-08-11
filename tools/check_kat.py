#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for rfc9421_negative_v1.

The 10-way consensus proves all runners AGREE; it cannot, by itself, rule out a
systematic error shared by the corpus generator and every runner (they would all
agree on the same wrong value). This gate closes that hole two ways:

  1. Corpus integrity: sha256(corpus file) must equal the file_sha256 recorded in
     the signed manifest head, so the bytes under test are the exact signed
     artifact, not a drifted copy.
  2. Independent anchors: for each anchor, the expected signing base is hand-
     derived from the case inputs by applying RFC 9421 Section 2.5 directly (see
     kat_anchors_v1.json), never through the reference build_signing_base. The
     frozen corpus's signing_base_b64 must decode to exactly that.

Fail-closed: any mismatch, a missing manifest digest, or zero anchors present
(which would mean a shared systematic error cannot be ruled out) exits non-zero.

Run: python tools/check_kat.py   (from the repo root)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(ROOT, "corpus", "rfc9421_negative_v1")
CORPUS = os.path.join(CORPUS_DIR, "rfc9421_negative_v1.json")
MANIFEST = os.path.join(CORPUS_DIR, "rfc9421_negative_v1.manifest.json")
ANCHORS = os.path.join(CORPUS_DIR, "kat_anchors_v1.json")


def main() -> int:
    failures: list[str] = []

    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)

    # 1. corpus integrity against the signed manifest head
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()
    try:
        with open(MANIFEST, encoding="utf-8") as fh:
            head = json.load(fh)["head"]
        recorded = head.get("file_sha256")
        if not recorded:
            failures.append("manifest head has no file_sha256")
        elif recorded != file_sha:
            failures.append(f"corpus digest drift: manifest {recorded} != actual {file_sha}")
    except (OSError, KeyError, json.JSONDecodeError) as e:
        failures.append(f"cannot read signed manifest head: {e}")

    # 2. independent known-answer anchors
    with open(ANCHORS, encoding="utf-8") as fh:
        anchors = json.load(fh)["anchors"]

    if not anchors:
        failures.append("no independent KAT anchors present (cannot rule out shared systematic error)")

    sb_cases = corpus["signing_base"]
    for a in anchors:
        idx = a["signing_base_index"]
        if idx >= len(sb_cases):
            failures.append(f"anchor index {idx} out of range")
            continue
        actual = base64.b64decode(sb_cases[idx]["signing_base_b64"]).decode("utf-8")
        if actual != a["expected_signing_base"]:
            failures.append(
                f"KAT mismatch at signing_base[{idx}] ({a['rule'][:48]})\n"
                f"    expected {a['expected_signing_base']!r}\n"
                f"    corpus   {actual!r}"
            )

    if failures:
        print("KAT: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        "KAT: PASS\n"
        f"  corpus integrity   {file_sha} (matches signed manifest head)\n"
        f"  independent anchors {len(anchors)}/{len(anchors)} match the frozen corpus"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
