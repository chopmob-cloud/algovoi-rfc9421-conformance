#!/usr/bin/env python3
"""Sign + version cose_v0 with the algovoi-corpus-cm backbone.

Same trust model as the other corpora: a compact CORPUS HEAD is EdDSA-signed
with a genuine SECRET Ed25519 seed held OFF-REPO; only the public JWK ships.
Override the key with ALGOVOI_COSE_SIGNING_KEY. Manifest/provenance are written
LF-only for a byte-stable signed digest on any platform. Foundation/KMS custody
and publish are gated.

This signs the corpus HEAD only. It reads nothing but the public corpus file; the
cose_v0 material's private keys are not needed here and stay off-repo.

Run:  ALGOVOI_LOCAL_SRC=/path/to/algovoi-corpus-cm/src python tools/sign_cose_v0.py
"""
from __future__ import annotations

import hashlib
import json
import os
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
CORPUS_DIR = os.path.join(REPO, "corpus", "cose_v0")
CORPUS = os.path.join(CORPUS_DIR, "cose_v0.json")

CORPUS_ID = "cose_v0"
VERSION = "0.1.0"
CANONICALIZER = "JCS(RFC8785)+EdDSA"
HEAD_TYP = "corpus-head+jws"
TS = "2026-08-12T00:00:00Z"
SECTIONS = ("cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
            "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit")

KEY_ENV = "ALGOVOI_COSE_SIGNING_KEY"
DEFAULT_KEY_PATH = os.path.join(
    os.path.expanduser("~"), ".algovoi", "keys", "cose-v0.ed25519.json")


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
                   "purpose": "cose_v0 corpus signing (local secret dev key)",
                   "note": "SECRET. Never commit or put in a memory-graph claim."}, f, indent=2)
    return key, path, True


def build_head(corpus: dict, raw_bytes: bytes) -> dict:
    return {
        "corpus_id": CORPUS_ID, "version": VERSION, "canonicalizer": CANONICALIZER,
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

    assert verify_jws(head_jws, lambda kid: jwk, expected_typ=HEAD_TYP) == head, "head JWS mismatch"
    assert digest(json.loads(open(CORPUS, "rb").read())) == head["corpus_digest"], "digest drift"
    assert log.verify(), "provenance chain does not verify"

    json.dump(manifest, open(os.path.join(CORPUS_DIR, "cose_v0.manifest.json"), "w", encoding="utf-8", newline="\n"), indent=2)
    json.dump({"issuer_id": log.issuer_id, "records": log.records},
              open(os.path.join(CORPUS_DIR, "cose_v0.provenance.json"), "w", encoding="utf-8", newline="\n"), indent=2)

    print("signed corpus head:", CORPUS_ID, VERSION)
    print("  total_cases   ", head["total_cases"], head["section_counts"])
    print("  signer kid    ", key.kid, "(", "created" if created else "loaded", "secret off-repo )")
    print("  head JWS verifies: yes   provenance verifies: yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
