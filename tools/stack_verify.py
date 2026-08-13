#!/usr/bin/env python3
"""Stack self-proving gate: prove L2 is internally consistent and untampered.

One command that binds the three trust layers of this repository together and
fails closed on any discrepancy:

  1. Every signed corpus head. For each corpus/<id>/<id>.json that carries a
     <id>.manifest.json, recompute the file sha256 and assert it equals
     head.file_sha256; verify the manifest head_jws EdDSA signature under
     signers[0].jwk with PyNaCl (forgery-resistant, not a bare digest compare);
     and, when <id>.provenance.json is present, verify its append-only hash chain.
  2. Every KAF assurance receipt. For each kaf/receipts/*.receipt.json, verify the
     Ed25519 seal over the canonical payload under the seal JWK, assert the seal
     kid is the one committed KAF identity, and assert the receipt's recorded
     corpus sha256 matches the corpus file on disk.
  3. One signing authority. All receipts must carry the same single KAF seal kid.

Optionally extend ONLY the shared-KAF-identity check to sibling stack checkouts
(L0/L1) via argv paths or ALGOVOI_L0 / ALGOVOI_L1. The default is L2-only; no
sibling is a hard dependency.

Exit 0 iff everything verifies. No corpus edits, no network.

Usage: python tools/stack_verify.py [sibling_repo_path ...]
       ALGOVOI_L0=/path/to/l0 ALGOVOI_L1=/path/to/l1 python tools/stack_verify.py
"""
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import sys

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KAF_KID = "4bbcedc71692d3dc9491239d2fff1ea2"

# Allow the caller to point at a local algovoi-corpus-cm source tree so the
# provenance chain is verified by the same code that wrote it. Falls back to a
# self-contained re-implementation below.
for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _canonical(obj) -> bytes:
    # RFC 8785 (JCS) on both sides; no silent fallback (matches the signers).
    import rfc8785
    return rfc8785.dumps(obj)


def _file_sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return "sha256:" + hashlib.sha256(fh.read()).hexdigest()


def verify_head_jws(manifest, corpus_file_sha):
    """Verify the manifest head_jws EdDSA signature under signers[0].jwk (PyNaCl).

    Mirrors tools/check_kat_wba.verify_head_jws: signature validity, head/payload
    agreement, and the signed file_sha256 binding.
    """
    out = []
    jws = manifest.get("head_jws")
    signers = manifest.get("signers") or []
    if not jws or not signers:
        return ["manifest is not signed (no head_jws / signer)"]
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        VerifyKey(_b64u(signers[0]["jwk"]["x"])).verify(
            f"{h_b64}.{p_b64}".encode("ascii"), _b64u(s_b64))
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


def _provenance_verify_native(prov):
    """Verify the hash chain with algovoi_corpus_cm if importable, else None."""
    try:
        from algovoi_corpus_cm.provenance import ProvenanceLog
    except ImportError:
        return None
    log = ProvenanceLog(issuer_id=prov["issuer_id"], records=list(prov["records"]))
    return bool(log.verify())


def _provenance_verify_self(prov):
    """Re-implement the algovoi-retention-chain verification (JCS hash chain).

    receipt_hash = sha256: over JCS(payload); chain_ref = sha256: over
    JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}); chain_seq is
    contiguous and prev_receipt_hash links each record to its predecessor.
    """
    def digest(obj):
        return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()

    records = prov["records"]
    for i, rec in enumerate(records):
        if rec["receipt_hash"] != digest(rec["payload"]):
            return False
        preimage = {
            "chain_seq": rec["chain_seq"],
            "issuer_id": rec["issuer_id"],
            "prev_receipt_hash": rec["prev_receipt_hash"],
            "receipt_hash": rec["receipt_hash"],
        }
        if digest(preimage) != rec["chain_ref"]:
            return False
        if i == 0:
            if rec["chain_seq"] != 0 or rec["prev_receipt_hash"] != "":
                return False
        else:
            prev = records[i - 1]
            if rec["chain_seq"] != prev["chain_seq"] + 1:
                return False
            if rec["prev_receipt_hash"] != prev["receipt_hash"]:
                return False
    return True


def verify_provenance(path, failures):
    """Verify one provenance log; returns True iff it verified."""
    with open(path, encoding="utf-8") as fh:
        prov = json.load(fh)
    native = _provenance_verify_native(prov)
    ok = native if native is not None else _provenance_verify_self(prov)
    if not ok:
        failures.append(f"provenance chain does not verify: {os.path.relpath(path, ROOT)}")
    return ok


def verify_corpus_heads(repo, failures):
    """Verify every signed corpus head under repo. Returns (heads, provenance)."""
    heads = 0
    chains = 0
    for corpus_json in sorted(glob.glob(os.path.join(repo, "corpus", "*", "*.json"))):
        if corpus_json.endswith(".manifest.json") or corpus_json.endswith(".provenance.json"):
            continue
        stem = corpus_json[: -len(".json")]
        manifest_path = stem + ".manifest.json"
        if not os.path.exists(manifest_path):
            continue
        rel = os.path.relpath(corpus_json, repo)
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        actual = _file_sha256(corpus_json)
        recorded = (manifest.get("head") or {}).get("file_sha256")
        if recorded != actual:
            failures.append(f"corpus digest drift: {rel} manifest {recorded} != disk {actual}")
        jws_failures = verify_head_jws(manifest, actual)
        if jws_failures:
            failures.extend(f"{rel}: {m}" for m in jws_failures)
        else:
            heads += 1
        prov_path = stem + ".provenance.json"
        if os.path.exists(prov_path):
            if verify_provenance(prov_path, failures):
                chains += 1
    return heads, chains


def verify_receipt(path, failures):
    """Verify one KAF receipt seal + corpus binding. Returns the seal kid or None."""
    with open(path, encoding="utf-8") as fh:
        receipt = json.load(fh)
    rel = os.path.relpath(path, ROOT)
    payload = receipt["payload"]
    seal = receipt["seal"]

    vk = VerifyKey(_b64u(seal["jwk"]["x"]))
    derived_kid = hashlib.sha256(bytes(vk)).hexdigest()[:32]
    if derived_kid != seal.get("kid"):
        failures.append(f"{rel}: kid mismatch jwk->{derived_kid} != seal.kid {seal.get('kid')}")
    try:
        vk.verify(_canonical(payload), base64.b64decode(seal["sig_b64"]))
    except BadSignatureError:
        failures.append(f"{rel}: EdDSA seal does not verify over the canonical payload")

    # pin to the committed KAF public key when present
    pub_path = os.path.join(ROOT, "kaf", "keys", "kaf-seal.pub.json")
    if os.path.exists(pub_path):
        with open(pub_path, encoding="utf-8") as fh:
            committed = json.load(fh)
        if committed.get("x") != seal["jwk"]["x"]:
            failures.append(f"{rel}: seal key does not match committed kaf/keys/kaf-seal.pub.json")

    if seal.get("kid") != KAF_KID:
        failures.append(f"{rel}: seal kid {seal.get('kid')} != the one KAF identity {KAF_KID}")

    cid = payload["corpus"]["id"]
    corpus_path = os.path.join(ROOT, "corpus", cid, cid + ".json")
    if not os.path.exists(corpus_path):
        failures.append(f"{rel}: corpus {cid} not found on disk")
    else:
        actual = _file_sha256(corpus_path)
        if payload["corpus"]["file_sha256"] != actual:
            failures.append(
                f"{rel}: corpus digest drift receipt {payload['corpus']['file_sha256']} != disk {actual}")
    return seal.get("kid")


def collect_receipt_kids(repo):
    """Return the set of seal kids across a repo's receipts (cross-stack check)."""
    kids = set()
    for path in sorted(glob.glob(os.path.join(repo, "kaf", "receipts", "*.receipt.json"))):
        with open(path, encoding="utf-8") as fh:
            kids.add((json.load(fh).get("seal") or {}).get("kid"))
    return kids


def main() -> int:
    failures: list[str] = []

    heads, chains = verify_corpus_heads(ROOT, failures)

    receipts = 0
    kids = set()
    for path in sorted(glob.glob(os.path.join(ROOT, "kaf", "receipts", "*.receipt.json"))):
        kids.add(verify_receipt(path, failures))
        receipts += 1

    if receipts == 0:
        failures.append("no KAF receipts found")
    if kids - {KAF_KID}:
        failures.append(f"receipts do not all share the KAF identity: {sorted(k for k in kids)}")

    # optional cross-stack identity check over sibling checkouts (L0/L1)
    siblings = list(sys.argv[1:])
    for env in ("ALGOVOI_L0", "ALGOVOI_L1"):
        p = os.environ.get(env)
        if p:
            siblings.append(p)
    cross = []
    for repo in siblings:
        repo = os.path.abspath(repo)
        if not os.path.isdir(repo):
            failures.append(f"sibling stack path not found: {repo}")
            continue
        sib_kids = collect_receipt_kids(repo)
        cross.append((repo, sib_kids))
        if sib_kids and sib_kids - {KAF_KID}:
            failures.append(f"sibling {repo} receipts not under KAF identity: {sorted(k for k in sib_kids)}")

    if failures:
        print("STACK VERIFY: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("STACK VERIFY: PASS")
    print(f"  corpus heads     {heads} signed heads verified (file sha256 == signed head, EdDSA head_jws valid)")
    print(f"  provenance       {chains} hash chains verified (append-only JCS chain)")
    print(f"  receipts         {receipts} KAF receipts valid under the one identity kid {KAF_KID}")
    if cross:
        for repo, sib_kids in cross:
            shown = ", ".join(sorted(k for k in sib_kids)) or "(no receipts)"
            print(f"  cross-stack      {os.path.basename(repo)}: {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
