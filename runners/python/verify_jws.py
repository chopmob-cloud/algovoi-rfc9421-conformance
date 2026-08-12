#!/usr/bin/env python3
"""Python reference runner for the JSON Web Signature corpus (jws_v0).

Independently reproduces every verdict in the frozen corpus: parse each compact
JWS, apply the JOSE security rules (alg:none, key/alg confusion, unknown crit, kid
selection), and verify the RS256 / ES256 / EdDSA signature under the key(s) the
case says the verifier holds. Python is the reference language, so it uses our
reference decision surface (tools/oracle_jws.py), exactly as the crypto runners
use the published reference verifier. Independence is provided by the other
language runners and by the KAT gate, which re-derives every verdict with a
separate third-party JOSE library (jwcrypto).

Exit 0 iff every case matches. Corpus path: argv[1], else $ALGOVOI_JWS, else the
repo corpus.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "tools"))
import oracle_jws as O  # noqa: E402

DEFAULT = os.path.join(REPO, "corpus", "jws_v0", "jws_v0.json")
SECTIONS = ("jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
            "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify",
            "jws_crit", "jws_kid")


def _ctx(verify, keys):
    return {"keys": [{"kid": keys[n].get("kid"), "jwk": keys[n]} for n in verify["key_names"]],
            "select_by_kid": verify["select_by_kid"]}


def run(corpus):
    keys = corpus["keys"]
    results = []
    for sec in SECTIONS:
        for c in corpus.get(sec, []):
            accept, _reason = O.verdict(c["jws"], _ctx(c["verify"], keys))
            results.append((sec, c["note"], accept == c["expect_valid"]))
    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_JWS", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (jws): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
