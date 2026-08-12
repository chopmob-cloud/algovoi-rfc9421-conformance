#!/usr/bin/env python3
"""Sign + version rfc9421_negative_v2 with the algovoi-corpus-cm backbone.

Identical trust model to sign_negative_v1.py: a compact CORPUS HEAD (corpus_id +
version + JCS digest + per-section digests) is EdDSA-signed with a genuine SECRET
Ed25519 seed held OFF-REPO. Only the public JWK ships in the manifest, so the
signature is unforgeable. v2 uses its own key (rfc9421-negative-v2.ed25519.json);
override with ALGOVOI_NV2_SIGNING_KEY. Foundation/KMS custody and publish are gated.

Run:  python tools/sign_negative_v2.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_corpus_cm.canonical import digest
from algovoi_corpus_cm.signing import LocalEd25519KeyProvider, sign_statement, verify_jws
from algovoi_corpus_cm.manifest import new_manifest, register_signer
from algovoi_corpus_cm.provenance import ProvenanceLog

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CORPUS_DIR = os.path.join(REPO, "corpus", "rfc9421_negative_v2")
CORPUS = os.path.join(CORPUS_DIR, "rfc9421_negative_v2.json")

CORPUS_ID = "rfc9421_negative_v2"
VERSION = "0.2.0"
CANONICALIZER = "JCS(RFC8785)+EdDSA"
HEAD_TYP = "corpus-head+jws"
TS = "2026-08-12T00:00:00Z"
SECTIONS = ("signing_base", "signature_input_parse", "signature_value_parse",
            "keygate", "ed25519_verify", "ecdsa_verify")

KEY_ENV = "ALGOVOI_NV2_SIGNING_KEY"
DEFAULT_KEY_PATH = os.path.join(
    os.path.expanduser("~"), ".algovoi", "keys", "rfc9421-negative-v2.ed25519.json")


def _restrict_perms(path: str) -> None:
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if not user:
        return
    try:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
                       check=False, capture_output=True)
    except Exception:
        pass


def load_or_create_key():
    path = os.environ.get(KEY_ENV, DEFAULT_KEY_PATH)
    if os.path.exists(path):
        d = json.loads(open(path, encoding="utf-8").read())
        return LocalEd25519KeyProvider.from_seed(bytes.fromhex(d["seed_hex"]), kid=d.get("kid")), path, False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    seed = os.urandom(32)
    key = LocalEd25519KeyProvider.from_seed(seed)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"seed_hex": seed.hex(), "kid": key.kid, "alg": "Ed25519",
                   "purpose": "rfc9421_negative_v2 corpus signing (local secret dev key)",
                   "note": "SECRET. Never commit or put in a memory-graph claim."}, f, indent=2)
    _restrict_perms(path)
    return key, path, True


def build_head(corpus: dict, raw_bytes: bytes) -> dict:
    return {
        "corpus_id": CORPUS_ID,
        "version": VERSION,
        "canonicalizer": CANONICALIZER,
        "corpus_digest": digest(corpus),
        "file_sha256": "sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
        "section_counts": {s: len(corpus.get(s, [])) for s in SECTIONS},
        "section_digests": {s: digest(corpus.get(s, [])) for s in SECTIONS},
        "total_cases": sum(len(corpus.get(s, [])) for s in SECTIONS),
    }


def main() -> int:
    raw = open(CORPUS, "rb").read()
    corpus = json.loads(raw)
    key, key_path, created = load_or_create_key()
    jwk = key.public_jwk()

    head = build_head(corpus, raw)
    head_jws = sign_statement(head, key, typ=HEAD_TYP)

    manifest = new_manifest(CORPUS_ID, CANONICALIZER)
    manifest = register_signer(manifest, jwk, signer_did="did:web:algovoi.co.uk")
    manifest = {**manifest, "version": VERSION,
                "custody": "local secret Ed25519 key held off-repo; rotate to KMS/foundation before publish (gated)",
                "head": head, "head_jws": head_jws, "head_typ": HEAD_TYP, "signed_at": TS}

    log = ProvenanceLog(issuer_id="did:web:algovoi.co.uk")
    log.append({"event": "sign_corpus_head", "corpus_id": CORPUS_ID, "version": VERSION,
                "corpus_digest": head["corpus_digest"], "signer_kid": key.kid, "ts": TS,
                "note": "local dev-key signing; foundation/KMS custody and publish are gated"})

    recovered = verify_jws(head_jws, lambda kid: jwk, expected_typ=HEAD_TYP)
    assert recovered == head, "head JWS payload does not match head"
    assert digest(json.loads(open(CORPUS, "rb").read())) == head["corpus_digest"], "corpus digest drift"
    assert log.verify(), "provenance chain does not verify"

    mpath = os.path.join(CORPUS_DIR, "rfc9421_negative_v2.manifest.json")
    ppath = os.path.join(CORPUS_DIR, "rfc9421_negative_v2.provenance.json")
    json.dump(manifest, open(mpath, "w", encoding="utf-8"), indent=2)
    json.dump({"issuer_id": log.issuer_id, "records": log.records},
              open(ppath, "w", encoding="utf-8"), indent=2)

    print("signed corpus head:", CORPUS_ID, VERSION)
    print("  total_cases   ", head["total_cases"], head["section_counts"])
    print("  signer kid    ", key.kid, "(", "created" if created else "loaded", "secret off-repo )")
    print("  head JWS verifies: yes   provenance verifies: yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
