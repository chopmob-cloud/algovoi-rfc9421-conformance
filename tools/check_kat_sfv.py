#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for sfv_v0.

N-way consensus proves the runners AGREE; it cannot alone rule out a systematic
error shared by the generator and every runner. This gate closes that hole:

  1. Corpus integrity: the corpus file sha256 must equal the file_sha256 in the
     signed manifest head, and the head_jws EdDSA signature must verify under the
     signer JWK (forgery-resistant, not just a digest compare).
  2. Independent re-derivation: every verdict (parse_ok, and the canonical
     serialization for cases that parse) is recomputed here with a SEPARATE
     third-party RFC 8941 implementation (http_sfv, Mark Nottingham's), never the
     generator's oracle and never the runners' path. A corpus that merely agrees
     with our own parser cannot pass this gate.

Fail-closed: any mismatch, a missing manifest digest, or an empty section exits
non-zero.

Requires: http_sfv (pip install http-sfv) and PyNaCl.
Run:  python tools/check_kat_sfv.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import http_sfv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_SFV")
          or os.path.join(ROOT, "corpus", "sfv_v0", "sfv_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"

TYPES = {"item": http_sfv.Item, "list": http_sfv.List, "dictionary": http_sfv.Dictionary}
SECTIONS = ("sfv_item", "sfv_list", "sfv_dictionary",
            "sfv_parameters", "sfv_canonical", "sfv_reject")


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_head_jws(manifest, corpus_file_sha):
    out = []
    jws = manifest.get("head_jws")
    signers = manifest.get("signers") or []
    if not jws or not signers:
        return ["manifest is not signed (no head_jws / signer)"]
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return ["PyNaCl required to verify the signed head"]
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        VerifyKey(_b64u(signers[0]["jwk"]["x"])).verify(f"{h_b64}.{p_b64}".encode("ascii"), _b64u(s_b64))
    except (ValueError, KeyError) as e:
        return [f"head_jws malformed: {e}"]
    except BadSignatureError:
        return ["head_jws EdDSA signature does not verify under the signer JWK"]
    payload = json.loads(_b64u(p_b64))
    if payload != manifest.get("head"):
        out.append("manifest head does not match the signed head_jws payload")
    if payload.get("file_sha256") != corpus_file_sha:
        out.append(f"signed head binds {payload.get('file_sha256')} != corpus {corpus_file_sha}")
    return out


def independent(field_type, text):
    """Verdict from the third-party http_sfv parser, independent of our oracle."""
    obj = TYPES[field_type]()
    data = text.encode("utf-8")
    try:
        consumed = obj.parse(data)
    except Exception:
        return False, None
    if isinstance(consumed, int) and data[consumed:].strip(b" "):
        return False, None
    try:
        return True, str(obj)
    except Exception:
        return False, None


def main() -> int:
    failures = []
    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()

    try:
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
        recorded = manifest["head"].get("file_sha256")
        if recorded != file_sha:
            failures.append(f"corpus digest drift: manifest {recorded} != actual {file_sha}")
        failures.extend(verify_head_jws(manifest, file_sha))
    except (OSError, KeyError, json.JSONDecodeError) as e:
        failures.append(f"cannot read signed manifest head: {e}")

    total = 0
    for sec in SECTIONS:
        cases = corpus.get(sec)
        if not cases:
            failures.append(f"section {sec} is empty (cannot rule out shared systematic error)")
            continue
        for c in cases:
            total += 1
            got_ok, got_canon = independent(c["field_type"], c["input"])
            if got_ok != c["expect_parse_ok"]:
                failures.append(f"KAT parse_ok mismatch [{sec}]: {c['note']} "
                                f"(input={c['input']!r} corpus={c['expect_parse_ok']} http_sfv={got_ok})")
            elif got_ok and got_canon != c.get("canonical"):
                failures.append(f"KAT canonical mismatch [{sec}]: {c['note']} "
                                f"(corpus={c.get('canonical')!r} http_sfv={got_canon!r})")

    if failures:
        print("KAT (sfv): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (sfv): PASS")
    print(f"  signed head        head_jws EdDSA signature verified under signer JWK")
    print(f"  corpus integrity   {file_sha} (matches signed head)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed with "
          f"http_sfv (a separate RFC 8941 implementation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
