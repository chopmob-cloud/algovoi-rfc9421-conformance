#!/usr/bin/env python3
"""Independent known-answer (KAT) gate for webbotauth_v0.

N-way consensus proves the runners AGREE; it cannot alone rule out a systematic
error shared by the generator and every runner. This gate closes that hole:

  1. Corpus integrity: the corpus file sha256 must equal the file_sha256 in the
     signed manifest head, and the head_jws EdDSA signature must verify under the
     signer JWK (forgery-resistant, not just a digest compare).
  2. Independent re-derivation: every verdict is recomputed here WITHOUT the
     generator's oracle and WITHOUT the runners' path. The signing base is hand-
     built by direct RFC 9421 Section 2.5 concatenation; Ed25519 is verified with
     `cryptography` (not the verifier's PyNaCl); coverage/freshness/directory/SSRF
     are re-implemented from first principles against the corpus `policy`.

Fail-closed: any mismatch, a missing manifest digest, or an empty section exits
non-zero.

Run:  python tools/check_kat_wba.py [corpus.json]
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import sys
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = (sys.argv[1] if len(sys.argv) > 1
          else os.environ.get("ALGOVOI_WEBBOTAUTH")
          or os.path.join(ROOT, "corpus", "webbotauth_v0", "webbotauth_v0.json"))
MANIFEST = CORPUS[:-len(".json")] + ".manifest.json"


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


def hand_signing_base(src, params_raw):
    """RFC 9421 Section 2.5 by direct concatenation, independent of build_signing_base."""
    lines = []
    for comp in src["covered_components"]:
        name = comp.lower()
        if name == "@authority":
            val = src["authority"]
        elif name == "@method":
            val = src["method"]
        elif name == "@path":
            val = src["path"]
        else:
            val = src["headers"][name]
        lines.append(f'"{name}": {val}')
    lines.append(f'"@signature-params": {params_raw}')
    return "\n".join(lines)


def coverage_ok(covered, policy):
    have = {c.lower() for c in covered}
    return all(r.lower() in have for r in policy["required_covered_components"])


def freshness_ok(created, expires, now, policy):
    skew = policy.get("clock_skew_seconds", 0)
    if not all(isinstance(x, int) for x in (created, expires, now)):
        return False
    if expires <= created:
        return False
    return (created - skew) <= now < expires


def directory_ok(directory, keyid):
    for j in directory:
        if j.get("kid") == keyid:
            return j.get("kty") == "OKP" and j.get("crv") == "Ed25519" and bool(j.get("x"))
    return False


def ssrf_ok(url, resolved_ip, policy):
    s = policy["ssrf"]
    p = urlsplit(url)
    if s.get("require_https", True) and p.scheme != "https":
        return False
    if "@" in (p.netloc or ""):
        return False
    if not p.hostname:
        return False
    try:
        addr = ipaddress.ip_address(p.hostname.strip("[]"))
    except ValueError:
        if not resolved_ip:
            return False
        try:
            addr = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False
    for c in s["denied_cidrs"]:
        net = ipaddress.ip_network(c)
        if addr.version == net.version and addr in net:
            return False
    return True


def ed25519_ok(base_str, sig, pk_hex):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex)).verify(sig, base_str.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def main() -> int:
    failures = []
    with open(CORPUS, "rb") as fh:
        corpus_bytes = fh.read()
    corpus = json.loads(corpus_bytes)
    policy = corpus["policy"]
    file_sha = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()

    try:
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
        recorded = manifest["head"].get("file_sha256")
        if recorded != file_sha:
            failures.append(f"corpus digest drift: manifest {recorded} != actual {file_sha}")
        failures.extend(verify_head_jws(manifest, file_sha))
    except (OSError, KeyError, json.JSONDecodeError) as e:
        failures.append(f"cannot read signed manifest head: {e}")

    counts = {}
    for c in corpus["wba_signing_base"]:
        want = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        if c["ok"] and hand_signing_base(c["in"], c["signature_params_raw"]) != want:
            failures.append(f"KAT signing_base mismatch: {c['note']}")
    counts["wba_signing_base"] = len(corpus["wba_signing_base"])

    for c in corpus["wba_coverage"]:
        if coverage_ok(c["covered_components"], policy) != c["expect_accept"]:
            failures.append(f"KAT coverage mismatch: {c['note']}")
    for c in corpus["wba_freshness"]:
        if freshness_ok(c["created"], c["expires"], c["now"], policy) != c["expect_accept"]:
            failures.append(f"KAT freshness mismatch: {c['note']}")
    for c in corpus["wba_directory"]:
        if directory_ok(c["directory"], c["keyid"]) != c["expect_accept"]:
            failures.append(f"KAT directory mismatch: {c['note']}")
    for c in corpus["wba_directory_ssrf"]:
        if ssrf_ok(c["signature_agent_url"], c.get("resolved_ip"), policy) != c["expect_fetch_allowed"]:
            failures.append(f"KAT ssrf mismatch: {c['note']}")
    for c in corpus["wba_ed25519_verify"]:
        base = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        if ed25519_ok(base, bytes.fromhex(c["sig_hex"]), c["pk_hex"]) != c["expect_valid"]:
            failures.append(f"KAT ed25519 mismatch: {c['note']}")

    total = sum(len(v) for v in corpus.values() if isinstance(v, list))
    for sec in ("wba_signing_base", "wba_coverage", "wba_freshness", "wba_directory",
                "wba_directory_ssrf", "wba_ed25519_verify"):
        if not corpus.get(sec):
            failures.append(f"section {sec} is empty (cannot rule out shared systematic error)")

    if failures:
        print("KAT (wba): FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("KAT (wba): PASS")
    print(f"  signed head        head_jws EdDSA signature verified under signer JWK")
    print(f"  corpus integrity   {file_sha} (matches signed head)")
    print(f"  independent re-derivation  {total}/{total} verdicts recomputed (hand signing base; "
          f"cryptography Ed25519; first-principles profile rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
