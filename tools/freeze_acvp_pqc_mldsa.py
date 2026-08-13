#!/usr/bin/env python3
"""Freeze the NIST ACVP ML-DSA-65 sigVer interop anchors.

This is an EXTERNAL interoperability anchor, distinct from AlgoVoi's own signed
corpora: it proves our stack reproduces the verdicts NIST itself publishes for
FIPS 204 ML-DSA-65 signature verification, rather than only agreeing with our own
crafted corpus. The frozen vectors are NIST's public ACVP test data, carried
verbatim (public keys, messages, contexts, signatures, and the expected pass/fail
bool), with their upstream provenance pinned to an exact commit.

Selection: parameterSet ML-DSA-65, signatureInterface "external", preHash "pure"
(all context lengths, empty and non-empty). The preHash (HashML-DSA) groups are
excluded because liboqs exposes no HashML-DSA verify (pure ML-DSA only), and the
internal-interface (externalMu) groups are a distinct interface out of this
corpus's scope. This yields the 15 pure external ML-DSA-65 cases.

The gate tools/check_acvp_pqc_mldsa.py re-derives every one of these verdicts with
TWO independent FIPS-204 implementations (liboqs and dilithium-py); agreement of
both with NIST's published answer is the interop proof.

Re-derive: fetch the two source files at the pinned commit and re-run --

  base=https://raw.githubusercontent.com/usnistgov/ACVP-Server/<COMMIT>/gen-val/json-files/ML-DSA-sigVer-FIPS204
  curl -sSo prompt.json  $base/prompt.json
  curl -sSo expected.json $base/expectedResults.json
  python tools/freeze_acvp_pqc_mldsa.py --prompt prompt.json --expected expected.json

Only NIST's PUBLIC test vectors are written; there are no secrets (ML-DSA sigVer
carries public keys and signatures only).
"""
from __future__ import annotations

import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "pqc_mldsa_acvp_mldsa65_v0.json")

# Upstream provenance, pinned. The commit is the last one to touch the source path
# at freeze time; the raw URLs below resolve to the exact bytes carried here.
SOURCE = {
    "repo": "usnistgov/ACVP-Server",
    "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204",
    "commit": "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324",
    "commit_date": "2026-07-31T17:00:12Z",
    "algorithm": "ML-DSA",
    "revision": "FIPS204",
    "vsId": 42,
    "url_prompt": ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
                   "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324/gen-val/json-files/"
                   "ML-DSA-sigVer-FIPS204/prompt.json"),
    "url_expected": ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
                     "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324/gen-val/json-files/"
                     "ML-DSA-sigVer-FIPS204/expectedResults.json"),
    "fetched_at": "2026-08-13",
}

PK_LEN = 1952
SIG_LEN = 3309


def extract(prompt: dict, expected: dict) -> list:
    verdict = {}
    for tg in expected["testGroups"]:
        for t in tg["tests"]:
            verdict[t["tcId"]] = bool(t["testPassed"])

    cases = []
    for tg in prompt["testGroups"]:
        if (tg.get("parameterSet") != "ML-DSA-65"
                or tg.get("signatureInterface") != "external"
                or tg.get("preHash") != "pure"):
            continue
        for t in tg["tests"]:
            tc = t["tcId"]
            if tc not in verdict:
                raise SystemExit(f"tcId {tc} has no expected verdict")
            pk, sig = t["pk"], t["signature"]
            if len(bytes.fromhex(pk)) != PK_LEN or len(bytes.fromhex(sig)) != SIG_LEN:
                raise SystemExit(f"tcId {tc} has a non-FIPS-204 length")
            ctx = t.get("context") or ""
            cases.append({
                "tcId": tc,
                "public_key": pk,
                "message": t["message"],
                "context": ctx,
                "signature": sig,
                "expect_valid": verdict[tc],
                "note": ("NIST ACVP ML-DSA-65 sigVer (pure, external) tcId "
                         f"{tc}: expected {'accept' if verdict[tc] else 'reject'}"
                         f", context {len(bytes.fromhex(ctx))} bytes"),
            })
    cases.sort(key=lambda c: c["tcId"])
    return cases


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", required=True, help="ACVP ML-DSA-sigVer prompt.json")
    ap.add_argument("--expected", required=True, help="ACVP ML-DSA-sigVer expectedResults.json")
    args = ap.parse_args()

    prompt = json.load(open(args.prompt, encoding="utf-8"))
    expected = json.load(open(args.expected, encoding="utf-8"))
    if prompt.get("algorithm") != "ML-DSA" or prompt.get("revision") != "FIPS204":
        raise SystemExit("source is not ML-DSA / FIPS204")

    cases = extract(prompt, expected)
    if not cases:
        raise SystemExit("no pure external ML-DSA-65 cases found")

    out = {
        "note": ("NIST ACVP ML-DSA-65 sigVer interop anchors (pure, external "
                 "interface). External interoperability evidence: AlgoVoi's stack "
                 "reproduces the verdicts NIST itself publishes, cross-checked by "
                 "two independent FIPS-204 implementations in "
                 "tools/check_acvp_pqc_mldsa.py. NIST public test vectors, carried "
                 "verbatim; no secrets."),
        "mechanism": "ML-DSA-65",
        "spec": "FIPS204",
        "variant": "pure ML-DSA, external interface, empty and non-empty context strings",
        "selection": ("parameterSet=ML-DSA-65, signatureInterface=external, "
                      "preHash=pure; preHash (HashML-DSA) and internalMu groups "
                      "excluded (liboqs has no HashML-DSA verify; internalMu is a "
                      "distinct interface)"),
        "lengths": {"public_key": PK_LEN, "signature": SIG_LEN},
        "source": SOURCE,
        "counts": {
            "total": len(cases),
            "expect_accept": sum(1 for c in cases if c["expect_valid"]),
            "expect_reject": sum(1 for c in cases if not c["expect_valid"]),
            "empty_context": sum(1 for c in cases if not c["context"]),
            "non_empty_context": sum(1 for c in cases if c["context"]),
        },
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("froze NIST ACVP ML-DSA-65 interop anchors ->", OUT)
    print("  cases:", out["counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
