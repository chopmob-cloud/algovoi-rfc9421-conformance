#!/usr/bin/env python3
"""Deterministically generate the Structured Field Values corpus (sfv_v0).

Every expected verdict (parse_ok, and the canonical serialization for the ones
that parse) is stamped by tools/oracle_sfv.py, the single reference decision
surface. The twelve runners re-derive the verdicts independently; the KAT gate
(tools/check_kat_sfv.py) re-checks every verdict with a separate third-party
implementation (http_sfv) so a corpus that merely agrees with our own parser
cannot pass.

Scope: RFC 8941 core, the part RFC 9651 keeps byte-identical. Written LF-only for
a byte-stable signed digest.

Run:  python tools/gen_sfv_v0.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_sfv as O  # noqa: E402

REPO = os.path.dirname(HERE)
OUT_DIR = os.path.join(REPO, "corpus", "sfv_v0")
OUT = os.path.join(OUT_DIR, "sfv_v0.json")

# Each row: (field_type, input, note). The generator stamps the verdict.
ITEM = [
    ("item", "1", "bare integer"),
    ("item", "-42", "negative integer"),
    ("item", "4.5", "decimal"),
    ("item", "-0.001", "small negative decimal"),
    ("item", '"hello world"', "string with a space"),
    ("item", '"escaped \\" quote"', "string with an escaped quote"),
    ("item", "foo123", "token"),
    ("item", "*special", "token starting with star"),
    ("item", "a/b:c", "token containing slash and colon"),
    ("item", ":aGVsbG8=:", "byte sequence (base64 of hello)"),
    ("item", "::", "empty byte sequence"),
    ("item", "?1", "boolean true"),
    ("item", "?0", "boolean false"),
    ("item", "5;foo=bar", "integer with a token parameter"),
    ("item", "sugar;a;b=?0", "token with boolean parameters"),
]

LIST = [
    ("list", "1, 2, 3", "list of integers"),
    ("list", "foo, bar", "list of tokens"),
    ("list", '"a", "b"', "list of strings"),
    ("list", "(1 2 3)", "single inner list"),
    ("list", "(a b c);x=1", "inner list with a parameter"),
    ("list", "sugar, tea, rum", "list of tokens (spec example)"),
    ("list", "1, (2 3), 4", "item, inner list, item"),
    ("list", "()", "empty inner list member"),
    ("list", "(1)", "one-element inner list"),
    ("list", "a;b=1, c", "member with a parameter then a bare member"),
]

DICTIONARY = [
    ("dictionary", "a=1, b=2", "two integer entries"),
    ("dictionary", 'en="Applepie", da=:aGVsbG8=:', "string and byte-sequence entries"),
    ("dictionary", "a=?0, b, c=?1", "boolean values incl an omitted-true key"),
    ("dictionary", "rating=1.5, feature=(a b)", "decimal and inner-list values"),
    ("dictionary", "a=(1 2), b=3", "inner-list value then integer"),
    ("dictionary", "foo=bar;x=1", "entry value carrying a parameter"),
]

PARAMETERS = [
    ("item", "1;a=1;b=2", "two parameters"),
    ("item", "1;a;b", "two boolean-true parameters"),
    ("item", '"x";key="val"', "string item with a string parameter"),
    ("item", "tok;*=1", "star is a valid parameter key"),
    ("item", "1;a=1;a=2", "duplicate parameter key, last value wins"),
    ("item", "5; foo=bar", "space after semicolon is allowed and normalized away"),
]

# Inputs that parse but whose canonical form differs from the input: the point
# is that serialization normalizes.
CANONICAL = [
    ("item", "01", "leading zeros stripped"),
    ("item", "-0", "negative zero normalizes to 0"),
    ("item", "1.50", "trailing fractional zero stripped"),
    ("item", "1.230", "trailing fractional zero stripped (to 1.23)"),
    ("item", " 5 ", "leading and trailing spaces stripped"),
    ("list", "1 , 2", "whitespace around list comma normalized"),
    ("list", "a;b=1,  c", "extra spaces after comma normalized"),
    ("dictionary", "a=1, a=2", "duplicate dictionary key, last wins"),
    ("dictionary", "a=1,  b=2", "extra space after comma normalized"),
    ("item", "1;a=1;a=2", "duplicate parameter collapses to the last value"),
]

REJECT = [
    ("item", "", "empty item"),
    ("item", "1.0000", "too many fractional digits"),
    ("item", "1000000000000000", "integer too long (16 digits)"),
    ("item", "?2", "boolean must be 0 or 1"),
    ("item", "?", "incomplete boolean"),
    ("item", '"unterminated', "unterminated string"),
    ("item", '"bad\\x"', "invalid string escape"),
    ("item", ":not_base64:", "non-base64 character in byte sequence"),
    ("item", ":aGVsbG8:", "non-canonical (unpadded) base64 rejected"),
    ("item", "1;A=2", "uppercase parameter key rejected"),
    ("item", "1 2", "trailing content after the item"),
    ("item", "@nope", "invalid character starting a bare item"),
    ("item", "9abc", "token-like input starting with a digit"),
    ("item", "é", "non-ASCII byte in a field value"),
    ("item", '"tab\there"', "raw control character inside a string"),
    ("list", "1, 2,", "trailing comma in a list"),
    ("list", "1,,2", "empty member in a list"),
    ("list", "(1 2", "unterminated inner list"),
    ("dictionary", "=1", "dictionary member with no key"),
    ("dictionary", "a=1,,b=2", "double comma in a dictionary"),
]

SECTIONS = [
    ("sfv_item", ITEM),
    ("sfv_list", LIST),
    ("sfv_dictionary", DICTIONARY),
    ("sfv_parameters", PARAMETERS),
    ("sfv_canonical", CANONICAL),
    ("sfv_reject", REJECT),
]


def build_case(field_type, text, note):
    ok, canonical = O.verdict(field_type, text)
    case = {"field_type": field_type, "input": text,
            "expect_parse_ok": ok, "note": note}
    if ok:
        case["canonical"] = canonical
    return case


def main() -> int:
    corpus = {
        "name": "sfv_v0",
        "description": ("Signed cross-language conformance battery for RFC 8941 "
                        "Structured Field Values: parsing of Items, Lists and "
                        "Dictionaries across every bare-item type, parameters, "
                        "inner lists, canonical serialization (normalization), "
                        "and the strict-reject negatives where lenient parsers "
                        "silently diverge. This is the parse/serialize stage of "
                        "the signing flow, underneath RFC 9421 Signature-Input "
                        "and RFC 9530 Content-Digest."),
        "profile": "structured-field-values",
        "policy": {
            "spec": "RFC8941",
            "field_types": ["item", "list", "dictionary"],
            "integer_range": [O.INT_MIN, O.INT_MAX],
            "excluded": ["Date (RFC9651)", "Display String (RFC9651)"],
            "note": ("Scope is the RFC 8941 core that RFC 9651 keeps "
                     "byte-identical, so the corpus is version-neutral. Date and "
                     "Display String are a later sfv_v1 section."),
            "documented_divergences": [
                {"input": "", "field_types": ["list", "dictionary"],
                 "reason": ("The RFC parse algorithm yields an empty structure, "
                            "but mature implementations (including http_sfv, the "
                            "spec author's) reject an empty field. Genuinely "
                            "ambiguous across implementations, so it is excluded "
                            "from the agreement battery rather than asserted.")},
                {"input": "1.", "field_type": "item",
                 "reason": ("RFC 8941 Section 4.2.4 rejects a decimal ending in "
                            "'.', but lenient parsers (http_sfv accepts it as "
                            "1.0) do not, so it is not a portable agreement "
                            "vector. Reserved for a future strictness profile.")},
            ],
        },
    }
    for name, rows in SECTIONS:
        cases = []
        for field_type, text, note in rows:
            case = build_case(field_type, text, note)
            if name == "sfv_reject" and case["expect_parse_ok"]:
                raise SystemExit(f"reject case unexpectedly parsed: {note!r} ({text!r})")
            if name == "sfv_canonical" and (not case["expect_parse_ok"]
                                            or case["canonical"] == text):
                raise SystemExit(f"canonical case is not a normalization: {note!r} ({text!r})")
            cases.append(case)
        corpus[name] = cases

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    counts = {k: len(v) for k, v in corpus.items() if isinstance(v, list)}
    print("generated", OUT)
    print("  sections", counts)
    print("  total_cases", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
