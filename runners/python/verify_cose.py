#!/usr/bin/env python3
"""Python reference runner for the COSE_Sign1 corpus (cose_v0).

Independently reproduces every verdict in the frozen corpus: for a COSE_Sign1 case,
parse the message, apply the COSE security rules (alg integrity-protected, unknown
crit rejected, protected header deterministically encoded, alg/key-type match), and
verify the ES256 / EdDSA / PS256 signature under the key the case says the verifier
holds; for a deterministic-CBOR case, decide whether the datum is RFC 8949 Section
4.2 canonical. Python is the reference language, so it uses our reference decision
surface (tools/oracle_cose.py), exactly as the crypto runners use the published
reference verifier. Independence is provided by the other language runners and by
the KAT gate, which re-derives every verdict with a separate third-party COSE
library (pycose) plus an independent cbor2 canonical check.

Exit 0 iff every case matches. Corpus path: argv[1], else $ALGOVOI_COSE, else the
repo corpus.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools"))
import oracle_cose as O  # noqa: E402

DEFAULT = os.path.join(REPO, "corpus", "cose_v0", "cose_v0.json")
SECTIONS = ("cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
            "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit")


def run(corpus):
    keys = corpus["keys"]
    results = []
    for sec in SECTIONS:
        for c in corpus.get(sec, []):
            if sec == "cose_deterministic_cbor":
                accept, _reason = O.is_deterministic_cbor(bytes.fromhex(c["cbor_hex"]))
            else:
                accept, _reason = O.verdict(bytes.fromhex(c["cose_hex"]), keys[c["key"]])
            results.append((sec, c["note"], accept == c["expect_valid"]))
    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_COSE", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (cose): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
