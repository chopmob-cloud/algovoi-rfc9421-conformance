#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for pqc_mldsa_v0.

N-way consensus proves the runners AGREE; it cannot alone rule out a systematic
error shared by the generator and every runner (for a post-quantum corpus, the
worst such error is a Dilithium-vs-ML-DSA scheme mismatch that every liboqs-based
component would share). This gate closes that hole:

  1. Corpus integrity: the corpus file sha256 must equal the file_sha256 in the
     signed manifest head, and the head_jws EdDSA signature must verify under the
     signer JWK (forgery-resistant, not just a digest compare).
  2. Independent re-derivation: every accept/reject verdict is recomputed here with
     a SEPARATE FIPS-204 ML-DSA-65 implementation (dilithium-py's ML_DSA_65), never
     liboqs and never our oracle. Because dilithium-py is an independent FIPS-204
     implementation, its agreement on the SAME frozen signatures is positive proof
     that the frozen material is genuine FIPS-204 ML-DSA (not round-3 Dilithium).

The independent re-derivation runs standalone: if the signed manifest is not
present yet (signing is a later, gated step) it prints a clear note and still
re-derives every verdict, so this gate is useful before the corpus is signed.

Fail-closed: any verdict mismatch, a signed-head fault, or an empty section exits
non-zero.

Requires: dilithium-py (pip install dilithium-py) and, to verify a signed head,
PyNaCl.
Run:  python tools/check_kat_pqc_mldsa.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from dilithium_py.ml_dsa import ML_DSA_65

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_PQC_MLDSA")
          or os.path.join(ROOT, "corpus", "pqc_mldsa_v0", "pqc_mldsa_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"

CANDIDATE_SECTIONS = ("mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat")

# FIPS 204 (Table 2) ML-DSA-65 normative byte lengths, asserted here independently
# of the oracle's constants so this gate is a genuinely separate spec check.
MLDSA65_PK_LEN = 1952
MLDSA65_SIG_LEN = 3309


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


def dilithium_accepts(public_key_hex, message_hex, signature_hex):
    """The independent verdict: does dilithium-py's FIPS-204 ML_DSA_65 accept this
    (public key, message, signature)? Malformed lengths (the FIPS-204 normative
    sizes, asserted independently here) and any exception are a reject."""
    try:
        pk = bytes.fromhex(public_key_hex)
        msg = bytes.fromhex(message_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(pk) != MLDSA65_PK_LEN or len(sig) != MLDSA65_SIG_LEN:
        return False
    try:
        return bool(ML_DSA_65.verify(pk, msg, sig))
    except Exception:
        return False


def main() -> int:
    failures = []
    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()

    manifest_present = os.path.exists(MANIFEST)
    if manifest_present:
        try:
            manifest = json.load(open(MANIFEST, encoding="utf-8"))
            recorded = manifest["head"].get("file_sha256")
            if recorded != file_sha:
                failures.append(f"corpus digest drift: manifest {recorded} != actual {file_sha}")
            failures.extend(verify_head_jws(manifest, file_sha))
        except (OSError, KeyError, json.JSONDecodeError) as e:
            failures.append(f"cannot read signed manifest head: {e}")
    else:
        print("note: signed manifest not present yet (signing is a later gated step);"
              " running the independent re-derivation standalone")

    sections = [s for s in CANDIDATE_SECTIONS if s in corpus]
    total = 0
    for sec in sections:
        cases = corpus.get(sec)
        if not cases:
            failures.append(f"section {sec} is empty (cannot rule out shared systematic error)")
            continue
        for c in cases:
            total += 1
            got = dilithium_accepts(c["public_key"], c["message"], c["signature"])
            if got != c["expect_valid"]:
                failures.append(f"KAT verdict mismatch [{sec}]: {c['note']} "
                                f"(corpus={c['expect_valid']} dilithium-py={got})")

    if failures:
        print("KAT (pqc_mldsa): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (pqc_mldsa): PASS")
    if manifest_present:
        print("  signed head        head_jws EdDSA signature verified under signer JWK")
        print(f"  corpus integrity   {file_sha} (matches signed head)")
    else:
        print(f"  corpus integrity   {file_sha} (manifest not present yet; signing is gated)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed with "
          f"dilithium-py (a separate FIPS-204 ML-DSA-65 implementation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
