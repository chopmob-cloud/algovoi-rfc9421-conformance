#!/usr/bin/env python3
"""Python reference runner for the Structured Field Values corpus (sfv_v0).

Independently reproduces every verdict in the frozen corpus: parse each input as
its declared field type and, if it parses, serialize it canonically. Python is
the reference language, so it uses our reference parser (tools/oracle_sfv.py),
exactly as the crypto runners use the published reference verifier. Independence
is provided by the eleven other-language runners (each on a native RFC 8941
library) and by the KAT gate, which re-derives every verdict with a separate
third-party implementation (http_sfv).

Exit 0 iff every case matches. Corpus path: argv[1], else $ALGOVOI_SFV, else the
repo corpus.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools"))
import oracle_sfv as O  # noqa: E402

DEFAULT = os.path.join(REPO, "corpus", "sfv_v0", "sfv_v0.json")
SECTIONS = ("sfv_item", "sfv_list", "sfv_dictionary",
            "sfv_parameters", "sfv_canonical", "sfv_reject")


def run(corpus):
    results = []
    for sec in SECTIONS:
        for c in corpus.get(sec, []):
            ok, canonical = O.verdict(c["field_type"], c["input"])
            match = (ok == c["expect_parse_ok"]
                     and (not ok or canonical == c.get("canonical")))
            results.append((sec, c["note"], match))
    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_SFV", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (sfv): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
