#!/usr/bin/env python3
"""Python reference runner for the Web Bot Auth profile corpus (webbotauth_v0).

Independently reproduces every verdict in the frozen corpus. Crypto and signing
base come from the published reference verifier (algovoi-rfc9421-verifier); the
PROFILE rules (coverage completeness, freshness window, directory keyid
resolution, Signature-Agent SSRF) are re-implemented here from the corpus `policy`
block, NOT imported from the generator's oracle, so a runner passing is genuine
agreement rather than an echo. The ts/rust/go/... runners mirror these rules.

Exit 0 iff every case matches. Corpus path: argv[1], else $ALGOVOI_WEBBOTAUTH,
else the repo corpus.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import sys
from urllib.parse import urlsplit

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import build_signing_base, verify_signature, VerifyError

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT = os.path.join(REPO, "corpus", "webbotauth_v0", "webbotauth_v0.json")


def _coverage_ok(covered, policy):
    have = {c.lower() for c in covered}
    return all(req.lower() in have for req in policy["required_covered_components"])


def _freshness_ok(created, expires, now, policy):
    skew = policy.get("clock_skew_seconds", 0)
    if not all(isinstance(x, int) for x in (created, expires, now)):
        return False
    if expires <= created:
        return False
    return (created - skew) <= now < expires


def _directory_ok(directory, keyid):
    for jwk in directory:
        if jwk.get("kid") == keyid:
            return jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and bool(jwk.get("x"))
    return False


def _ssrf_ok(url, resolved_ip, policy):
    ssrf = policy["ssrf"]
    parts = urlsplit(url)
    if ssrf.get("require_https", True) and parts.scheme != "https":
        return False
    if "@" in (parts.netloc or ""):
        return False
    host = parts.hostname
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not resolved_ip:
            return False
        try:
            addr = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False
    for cidr in ssrf["denied_cidrs"]:
        net = ipaddress.ip_network(cidr)
        if addr.version == net.version and addr in net:
            return False
    return True


def run(corpus):
    policy = corpus["policy"]
    results = []

    for c in corpus["wba_signing_base"]:
        src = c["in"]
        want = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        try:
            got = build_signing_base(
                covered_components=src["covered_components"], method=src.get("method"),
                authority=src.get("authority"), path=src.get("path"),
                headers=src.get("headers"), mode=c["mode"],
                signature_params_raw=c.get("signature_params_raw"))
            ok = c["ok"] and got == want
        except Exception:
            ok = not c["ok"]
        results.append(("wba_signing_base", c["note"], ok))

    for c in corpus["wba_coverage"]:
        results.append(("wba_coverage", c["note"],
                        _coverage_ok(c["covered_components"], policy) == c["expect_accept"]))

    for c in corpus["wba_freshness"]:
        results.append(("wba_freshness", c["note"],
                        _freshness_ok(c["created"], c["expires"], c["now"], policy) == c["expect_accept"]))

    for c in corpus["wba_directory"]:
        results.append(("wba_directory", c["note"],
                        _directory_ok(c["directory"], c["keyid"]) == c["expect_accept"]))

    for c in corpus["wba_directory_ssrf"]:
        results.append(("wba_directory_ssrf", c["note"],
                        _ssrf_ok(c["signature_agent_url"], c.get("resolved_ip"), policy) == c["expect_fetch_allowed"]))

    for c in corpus["wba_ed25519_verify"]:
        base = base64.b64decode(c["signing_base_b64"]).decode("utf-8")
        try:
            valid = bool(verify_signature(base, bytes.fromhex(c["sig_hex"]), c["pk_hex"]))
        except VerifyError:
            valid = False
        results.append(("wba_ed25519_verify", c["note"], valid == c["expect_valid"]))

    return results


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ALGOVOI_WEBBOTAUTH", DEFAULT)
    corpus = json.load(open(path, encoding="utf-8"))
    results = run(corpus)
    fails = [(s, n) for s, n, ok in results if not ok]
    for s, n, ok in results:
        if not ok:
            print(f"FAIL  [{s}] {n}")
    total = len(results)
    print(f"\npython (wba): {total - len(fails)}/{total} cases matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
