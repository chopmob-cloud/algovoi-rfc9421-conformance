#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for jws_v0.

N-way consensus proves the runners AGREE; it cannot alone rule out a systematic
error shared by the generator and every runner. This gate closes that hole:

  1. Corpus integrity: the corpus file sha256 must equal the file_sha256 in the
     signed manifest head, and the head_jws EdDSA signature must verify under the
     signer JWK (forgery-resistant, not just a digest compare).
  2. Independent re-derivation: every accept/reject verdict is recomputed here
     with a SEPARATE third-party JOSE library (jwcrypto), never our oracle_jws and
     never the runners' path. jwcrypto natively rejects alg:none, an alg/key-type
     mismatch, and an unknown crit, so it is a genuine independent check of the
     JOSE security semantics, not merely of the raw signature bytes.

The independent re-derivation runs standalone: if the signed manifest is not
present yet (signing is a later, gated step) it prints a clear note and still
re-derives every verdict, so this gate is useful before the corpus is signed.

Fail-closed: any verdict mismatch, a signed-head fault, or an empty section exits
non-zero.

Requires: jwcrypto (pip install jwcrypto) and PyNaCl.
Run:  python tools/check_kat_jws.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from jwcrypto import jwk as jwkmod, jws as jwsmod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_JWS")
          or os.path.join(ROOT, "corpus", "jws_v0", "jws_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"

SECTIONS = ("jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
            "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify",
            "jws_crit", "jws_kid")


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


def _select_jwk(token, verify, keys):
    """Resolve the JWK the verifier applies, mirroring RFC 7515 4.1.4 selection but
    implemented independently of our oracle: a keyset selects by header kid, a
    single-key verifier applies its one key. Returns the JWK dict, or None."""
    if verify.get("select_by_kid"):
        try:
            header = json.loads(_b64u(token.split(".")[0]))
        except Exception:
            return None
        kid = header.get("kid") if isinstance(header, dict) else None
        if kid is None:
            return None
        for n in verify["key_names"]:
            if keys[n].get("kid") == kid:
                return keys[n]
        return None
    return keys[verify["key_names"][0]]


def jwcrypto_accepts(token, verify, keys):
    """The independent verdict: does jwcrypto accept this compact JWS under the
    selected public JWK? Any structural, security, or signature fault is a reject."""
    jwk_dict = _select_jwk(token, verify, keys)
    if jwk_dict is None:
        return False
    try:
        key = jwkmod.JWK(**jwk_dict)
    except Exception:
        return False
    try:
        verifier = jwsmod.JWS()
        verifier.deserialize(token)
        verifier.verify(key)
        return True
    except Exception:
        return False


def main() -> int:
    failures = []
    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    keys = corpus["keys"]
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

    total = 0
    for sec in SECTIONS:
        cases = corpus.get(sec)
        if not cases:
            failures.append(f"section {sec} is empty (cannot rule out shared systematic error)")
            continue
        for c in cases:
            total += 1
            got = jwcrypto_accepts(c["jws"], c["verify"], keys)
            if got != c["expect_valid"]:
                failures.append(f"KAT verdict mismatch [{sec}]: {c['note']} "
                                f"(corpus={c['expect_valid']} jwcrypto={got})")

    if failures:
        print("KAT (jws): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (jws): PASS")
    if manifest_present:
        print("  signed head        head_jws EdDSA signature verified under signer JWK")
        print(f"  corpus integrity   {file_sha} (matches signed head)")
    else:
        print(f"  corpus integrity   {file_sha} (manifest not present yet; signing is gated)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed with "
          f"jwcrypto (a separate JOSE implementation)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
