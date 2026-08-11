#!/usr/bin/env python3
"""Python runner for rfc9421_negative_v1 (CORE cross-language battery).

Feeds every case to the published verifiers (algovoi-rfc9421-verifier +
algovoi-rfc9421-ecdsa) and checks the verdict against the frozen corpus. This is
the reference runner; the ts/rust/go runners mirror its verdict rules so all four
agree per case.

Install the packages (pip install algovoi-rfc9421-verifier algovoi-rfc9421-ecdsa)
or point ALGOVOI_LOCAL_SRC at their source dirs (os.pathsep-separated). The corpus
path defaults to ../../corpus/rfc9421_negative_v1/ or ALGOVOI_NEGATIVE_V1.

Exit 0 iff every case matches.
"""
from __future__ import annotations

import base64
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import (
    build_signing_base,
    parse_signature_input,
    parse_signature_value,
    verify_signature,
    check_ed25519_public_key,
    is_small_order,
    WeakKeyError,
    SignatureInputParseError,
    VerifyError,
)
from algovoi_rfc9421_ecdsa import verify_p256, verify_p384, set_strict_low_s

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT = os.path.join(REPO, "corpus", "rfc9421_negative_v1", "rfc9421_negative_v1.json")


def _build(case):
    src = dict(case["in"])
    kw = dict(
        covered_components=src["covered_components"],
        method=src.get("method"),
        authority=src.get("authority"),
        path=src.get("path"),
        target_uri=src.get("target_uri"),
        scheme=src.get("scheme"),
        status=src.get("status"),
        headers=src.get("headers"),
        parameters=src.get("parameters"),
        mode=case["mode"],
    )
    if case["mode"] == "rfc9421":
        kw["signature_params_raw"] = case.get("signature_params_raw")
    return build_signing_base(**{k: v for k, v in kw.items() if v is not None})


def run(corpus):
    results = []

    for c in corpus["signing_base"]:
        want = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        try:
            # attempt the build FIRST; `c["ok"] and _build(c)` would short-circuit
            # for negative cases and never verify that the build actually fails.
            built = _build(c)
            ok = c["ok"] and built == want
        except Exception:
            ok = not c["ok"]
        results.append(("signing_base", c.get("note", ""), ok))

    for c in corpus["signature_input_parse"]:
        try:
            parse_signature_input(c["header"]); parsed_ok = True
        except SignatureInputParseError:
            parsed_ok = False
        results.append(("sig_input_parse", c["note"], parsed_ok == c["ok"]))

    for c in corpus["signature_value_parse"]:
        try:
            parse_signature_value(c["header"]); parsed_ok = True
        except SignatureInputParseError:
            parsed_ok = False
        results.append(("sig_value_parse", c["note"], parsed_ok == c["ok"]))

    for c in corpus["keygate"]:
        raw = bytes.fromhex(c["pk_hex"])
        try:
            check_ed25519_public_key(raw); rejected = None
        except WeakKeyError:
            rejected = "WeakKeyError"
        ok = (rejected == c["rejected"]) and (is_small_order(raw) == c["small_order"])
        results.append(("keygate", c["note"], ok))

    for c in corpus["ed25519_verify"]:
        base = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        try:
            valid = bool(verify_signature(base, bytes.fromhex(c["sig_hex"]), c["pk_hex"]))
        except VerifyError:
            valid = False
        results.append(("ed25519_verify", c["note"], valid == c["expect_valid"]))

    for c in corpus["ecdsa_verify"]:
        fn = verify_p256 if c["curve"] == "p256" else verify_p384
        msg = bytes.fromhex(c["msg_hex"]).decode("utf-8")
        set_strict_low_s(bool(c.get("strict_low_s", False)))
        try:
            valid = bool(fn(msg, bytes.fromhex(c["sig_raw_hex"]), c["pub_uncompressed_hex"]))
        except Exception:
            valid = False
        finally:
            set_strict_low_s(False)
        results.append(("ecdsa_verify", c["note"], valid == c["expect_valid"]))

    return results


def main():
    path = (sys.argv[1] if len(sys.argv) > 1
            else os.environ.get("ALGOVOI_NEGATIVE_V1", DEFAULT))
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython: {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
