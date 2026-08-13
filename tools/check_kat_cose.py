#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for cose_v0.

N-way consensus proves the runners AGREE; it cannot alone rule out a systematic
error shared by the generator and every runner. This gate closes that hole:

  1. Corpus integrity: the corpus file sha256 must equal the file_sha256 in the
     signed manifest head, and the head_jws EdDSA signature must verify under the
     signer JWK (forgery-resistant, not just a digest compare).
  2. Independent re-derivation: every accept/reject verdict is recomputed here with
     a SEPARATE third-party COSE library (pycose) for the signature crypto plus
     cbor2's own canonical encoder for the deterministic-CBOR cases, never our
     oracle_cose and never the runners' path. The COSE security gates (alg must be
     integrity-protected, an unknown crit rejected, the protected header
     deterministically encoded, alg/key-type match) are re-implemented here from
     the spec, independently of oracle_cose, because pycose is a permissive
     encoder/decoder and does not enforce them natively; the signature itself is
     verified by pycose, a genuinely separate implementation.

The independent re-derivation runs standalone: if the signed manifest is not
present yet (signing is a later, gated step) it prints a clear note and still
re-derives every verdict, so this gate is useful before the corpus is signed.

Fail-closed: any verdict mismatch, a signed-head fault, or an empty section exits
non-zero.

Requires: pycose, cbor2, PyNaCl.
Run:  python tools/check_kat_cose.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import cbor2
from cbor2 import CBORTag
from pycose.messages import Sign1Message
from pycose.keys import EC2Key, OKPKey, RSAKey
from pycose.keys.curves import P256, Ed25519

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_COSE")
          or os.path.join(ROOT, "corpus", "cose_v0", "cose_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"

# COSE constants, re-declared here so this gate never imports oracle_cose.
HDR_ALG, HDR_CRIT = 1, 2
COSE_SIGN1_TAG = 18
ALG_KTY = {-7: "EC2", -8: "OKP", -37: "RSA"}
KNOWN_LABELS = {1, 2, 3, 4, 5}  # alg, crit, kid, content type, IV
SECTIONS = ("cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
            "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit")


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


# ---------------------------------------------------------------------------
# Independent re-derivation (pycose crypto + cbor2 canonical), never oracle_cose.
# ---------------------------------------------------------------------------

def _mut(x):
    """cbor2 6.x decodes tag content with immutable containers (tuples,
    frozendicts); convert back to plain lists/dicts."""
    if isinstance(x, (list, tuple)):
        return [_mut(i) for i in x]
    if hasattr(x, "items"):
        return {k: _mut(v) for k, v in x.items()}
    return x


def _canonical(data: bytes) -> bool:
    """Independent RFC 8949 Section 4.2 check: the datum must be its own cbor2
    canonical encoding (shortest ints, definite lengths, bytewise-sorted keys)."""
    try:
        v = cbor2.loads(data)
    except Exception:
        return False
    if isinstance(v, CBORTag):
        return False
    try:
        return cbor2.dumps(v, canonical=True) == data
    except Exception:
        return False


def _pycose_key(key: dict, alg: int):
    if alg == -7:
        return EC2Key(crv=P256, x=bytes.fromhex(key["x"]), y=bytes.fromhex(key["y"]))
    if alg == -8:
        return OKPKey(crv=Ed25519, x=bytes.fromhex(key["x"]))
    if alg == -37:
        return RSAKey(n=bytes.fromhex(key["n"]), e=bytes.fromhex(key["e"]))
    raise ValueError(alg)


def pycose_accepts(data: bytes, key: dict) -> bool:
    """The independent verdict for a COSE_Sign1: the COSE security gates
    re-derived from the spec, then pycose for the signature crypto."""
    try:
        top = cbor2.loads(data)
    except Exception:
        return False
    if isinstance(top, CBORTag):
        if top.tag != COSE_SIGN1_TAG:
            return False
        arr = _mut(top.value)
    else:
        arr = _mut(top)
    if not isinstance(arr, list) or len(arr) != 4:
        return False
    protected, uhdr, payload, sig = arr
    if not isinstance(protected, bytes) or not isinstance(uhdr, dict) or not isinstance(sig, bytes):
        return False
    if payload is not None and not isinstance(payload, bytes):
        return False
    if protected == b"":
        phdr = {}
    else:
        if not _canonical(protected):
            return False
        phdr = cbor2.loads(protected)
        if not isinstance(phdr, dict):
            return False
    if HDR_ALG not in phdr:
        return False
    alg = phdr[HDR_ALG]
    if HDR_CRIT in phdr:
        crit = phdr[HDR_CRIT]
        if not isinstance(crit, list) or not crit or any(l not in KNOWN_LABELS for l in crit):
            return False
    if alg not in ALG_KTY or key.get("kty") != ALG_KTY[alg]:
        return False
    try:
        msg = Sign1Message.from_cose_obj([arr[0], arr[1], arr[2], arr[3]], True)
        msg.key = _pycose_key(key, alg)
        return bool(msg.verify_signature())
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
            if sec == "cose_deterministic_cbor":
                got = _canonical(bytes.fromhex(c["cbor_hex"]))
            else:
                got = pycose_accepts(bytes.fromhex(c["cose_hex"]), keys[c["key"]])
            if got != c["expect_valid"]:
                failures.append(f"KAT verdict mismatch [{sec}]: {c['note']} "
                                f"(corpus={c['expect_valid']} pycose={got})")

    if failures:
        print("KAT (cose): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (cose): PASS")
    if manifest_present:
        print("  signed head        head_jws EdDSA signature verified under signer JWK")
        print(f"  corpus integrity   {file_sha} (matches signed head)")
    else:
        print(f"  corpus integrity   {file_sha} (manifest not present yet; signing is gated)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed with "
          f"pycose (a separate COSE implementation) + cbor2 canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
