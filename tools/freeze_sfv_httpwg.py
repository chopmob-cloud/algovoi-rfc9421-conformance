#!/usr/bin/env python3
"""Freeze the httpwg structured-field-tests suite as an SFV interop anchor.

External interoperability anchor for the Structured Field Values stage: proof that
our RFC 8941 parser/serializer reproduces the verdicts of the shared cross-
implementation test suite the SFV editors maintain (httpwg/structured-field-tests),
which most independent SFV libraries test against. Distinct from AlgoVoi's own
sfv_v0 corpus: these are the community reference vectors, carried verbatim with
upstream provenance pinned to an exact commit.

Selection: the hand-written RFC 8941 core files (Items, Lists, Dictionaries, bare
types, parameters, inner lists, canonical serialization, rejects). Excluded:
date.json and display-string.json (those are RFC 9651 additions our RFC 8941 oracle
does not implement), the machine-generated fuzz files (*-generated, large-generated)
and examples.json (a different shape).

Each test keeps the suite's own fields: name, raw (input field line(s)), header_type
(item/list/dictionary), must_fail / can_fail flags, and canonical (the expected
canonical serialization). The gate tools/check_sfv_httpwg.py reproduces every
must_fail and canonical verdict with our oracle and the independent http_sfv library.

Re-derive: fetch the core files at the pinned commit into a directory and run
  python tools/freeze_sfv_httpwg.py --src <dir>
"""
from __future__ import annotations

import argparse
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "sfv_httpwg_v0.json")

SOURCE = {
    "repo": "httpwg/structured-field-tests",
    "commit": "ae07345845e55abc338221f1e9325272e40985e8",
    "commit_date": "2026-05-11T12:31:13Z",
    "url_base": ("https://raw.githubusercontent.com/httpwg/structured-field-tests/"
                 "ae07345845e55abc338221f1e9325272e40985e8/"),
    "fetched_at": "2026-08-13",
}

# RFC 8941 core files only (see module docstring for exclusions).
CORE_FILES = [
    "binary", "boolean", "dictionary", "item", "list", "listlist",
    "number", "param-dict", "param-list", "param-listlist", "string", "token",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="directory of httpwg *.json test files")
    args = ap.parse_args()

    tests = []
    for stem in CORE_FILES:
        path = os.path.join(args.src, stem + ".json")
        if not os.path.exists(path):
            raise SystemExit(f"missing source file: {path}")
        for t in json.load(open(path, encoding="utf-8")):
            tests.append({
                "file": stem,
                "name": t.get("name"),
                "raw": t.get("raw", []),
                "header_type": t.get("header_type"),
                "must_fail": bool(t.get("must_fail")),
                "can_fail": bool(t.get("can_fail")),
                "canonical": t.get("canonical"),  # None => canonical == raw when it parses
            })

    strict = [t for t in tests if not t["can_fail"]]
    out = {
        "note": ("httpwg structured-field-tests interop anchors (RFC 8941 core). "
                 "External interoperability evidence: our RFC 8941 parser and "
                 "serializer reproduce the verdicts of the SFV editors' shared "
                 "cross-implementation test suite. Community reference vectors, "
                 "carried verbatim; no secrets."),
        "standard": "RFC 8941",
        "selection": ("hand-written RFC 8941 core files (Items/Lists/Dictionaries, "
                      "bare types, parameters, inner lists, canonical, rejects); "
                      "excludes date.json and display-string.json (RFC 9651), the "
                      "*-generated fuzz files, and examples.json"),
        "source": SOURCE,
        "files": CORE_FILES,
        "counts": {
            "total": len(tests),
            "must_fail": sum(1 for t in tests if t["must_fail"]),
            "can_fail": sum(1 for t in tests if t["can_fail"]),
            "strict": len(strict),
        },
        "tests": tests,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("froze httpwg SFV interop anchors ->", OUT)
    print("  counts:", out["counts"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
