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
# The corpus under test: argv[1], else $ALGOVOI_NEGATIVE_V1, else the v1 default.
# The signed manifest and the KAT anchors are resolved alongside it, so the same
# gate validates v1 and any later superset (v2, ...) without code changes.
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_NEGATIVE_V1")
          or os.path.join(ROOT, "corpus", "rfc9421_negative_v3", "rfc9421_negative_v3.json"))
CORPUS_DIR = os.path.dirname(CORPUS)
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"
ANCHORS = os.path.join(CORPUS_DIR, "kat_anchors_v1.json")


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_head_jws(manifest: dict, corpus_file_sha: str) -> list[str]:
    """Verify the manifest's signed head: the EdDSA compact-JWS signature under
    the signer's published Ed25519 JWK, and that the head's own file_sha256
    binds the corpus on disk. This is strictly stronger than a digest compare --
    it proves the manifest is the exact signed artifact, forgery-resistant."""
    out: list[str] = []
    jws = manifest.get("head_jws")
    signers = manifest.get("signers") or []
    if not jws or not signers:
        return ["manifest is not signed (no head_jws / signer)"]
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        return ["PyNaCl required to verify the signed head (pip install pynacl)"]
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        pk = _b64u(signers[0]["jwk"]["x"])
        VerifyKey(pk).verify(f"{h_b64}.{p_b64}".encode("ascii"), _b64u(s_b64))
    except (ValueError, KeyError) as e:
        return [f"head_jws is malformed: {e}"]
    except BadSignatureError:
        return ["head_jws EdDSA signature does not verify under the signer JWK"]
    payload = json.loads(_b64u(p_b64))
    # the signed JWS payload is the authoritative head; the manifest's displayed
    # head object must equal it byte-for-byte-in-value, or a field was tampered.
    if payload != manifest.get("head"):
        out.append("manifest head object does not match the signed head_jws payload")
    if payload.get("file_sha256") != corpus_file_sha:
        out.append(f"signed head binds file_sha256 {payload.get('file_sha256')} != corpus {corpus_file_sha}")
    return out


def main() -> int:
    failures: list[str] = []

    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)

    # 1. corpus integrity against the signed manifest head
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()
    try:
        with open(MANIFEST, encoding="utf-8") as fh:
            manifest = json.load(fh)
        head = manifest["head"]
        recorded = head.get("file_sha256")
        if not recorded:
            failures.append("manifest head has no file_sha256")
        elif recorded != file_sha:
            failures.append(f"corpus digest drift: manifest {recorded} != actual {file_sha}")
        # 1b. verify the SIGNATURE on the head, not just the digest. A tampered
        # manifest that recomputes file_sha256 to match a tampered corpus still
        # fails here, because head_jws cannot be forged without the signing key.
        failures.extend(verify_head_jws(manifest, file_sha))
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
        f"  signed head        head_jws EdDSA signature verified under signer JWK\n"
        f"  corpus integrity   {file_sha} (matches signed head)\n"
        f"  independent anchors {len(anchors)}/{len(anchors)} match the frozen corpus"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
