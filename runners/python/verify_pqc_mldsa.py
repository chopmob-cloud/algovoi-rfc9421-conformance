#!/usr/bin/env python3
"""Python reference runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).

Independently reproduces every verdict in the frozen corpus: for each case decode
the hex public key, message, and signature, reject malformed lengths, and verify
the FIPS-204 ML-DSA-65 signature. Python is the reference language, so it uses our
reference decision surface (tools/oracle_pqc_mldsa.py, liboqs ML-DSA-65), exactly
as the crypto runners use the published reference verifier. Independence is
provided by the KAT gate (tools/check_kat_pqc_mldsa.py), which re-derives every
verdict with a SEPARATE FIPS-204 ML-DSA-65 implementation (dilithium-py).

Requires liboqs (via the oqs package) exposing the "ML-DSA-65" mechanism.

Exit 0 iff every case matches. Corpus path: argv[1], else $ALGOVOI_PQC_MLDSA, else
the repo corpus.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools"))
import oracle_pqc_mldsa as O  # noqa: E402

DEFAULT = os.path.join(REPO, "corpus", "pqc_mldsa_v0", "pqc_mldsa_v0.json")
BASE_SECTIONS = ("mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat")


def run(corpus):
    results = []
    for sec in BASE_SECTIONS:
        for c in corpus.get(sec, []):
            accept, _reason = O.verdict(c["public_key"], c["message"], c["signature"])
            results.append((sec, c["note"], accept == c["expect_valid"]))
    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_PQC_MLDSA", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n in fails:
        print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (pqc_mldsa): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
