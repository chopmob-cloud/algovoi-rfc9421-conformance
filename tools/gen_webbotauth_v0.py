#!/usr/bin/env python3
"""Deterministically generate the Web Bot Auth profile corpus (webbotauth_v0).

Every expected verdict is stamped by tools/oracle_wba.py (the one reference
decision surface). Signing bases are built with the published reference verifier
(algovoi-rfc9421-verifier build_signing_base) so the byte-exact base is the real
RFC 9421 Section 2.5 construction, not a re-implementation. The runners and the
KAT gate re-derive the verdicts independently.

Deterministic: fixed Ed25519 seeds, per-case `now` (no clock), carried directory
bytes (no network). Written LF-only for a byte-stable signed digest.

Run:  python tools/gen_webbotauth_v0.py
"""
from __future__ import annotations

import base64
import json
import os
import sys

for _d in os.environ.get("ALGOVOI_LOCAL_SRC", "").split(os.pathsep):
    if _d and _d not in sys.path:
        sys.path.insert(0, _d)

from algovoi_rfc9421_verifier import build_signing_base

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_wba as O  # noqa: E402

REPO = os.path.dirname(HERE)
OUT_DIR = os.path.join(REPO, "corpus", "webbotauth_v0")
OUT = os.path.join(OUT_DIR, "webbotauth_v0.json")

# Deterministic Ed25519 seeds (RFC 8032 test-1 seed for A; distinct fixed seeds
# for the others). Never secret in any meaningful sense: these are corpus keys.
SEED_A = bytes.fromhex("9d61b19deff7c049f11f83a6d17f3d76e6a3c5c30bceb9a2e6a1e5b0c7d4e8f0")
SEED_B = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fa")
SEED_C = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _base(covered, created, expires, keyid, agent_url):
    """The exact RFC 9421 signing base for a web-bot-auth request."""
    raw = O.signature_params_raw(covered, created, expires, keyid)
    base = build_signing_base(
        covered_components=covered,
        method="GET",
        authority="bot.example",
        path="/",
        headers={"signature-agent": f'"{agent_url}"'},
        mode="rfc9421",
        signature_params_raw=raw,
    )
    return base.encode("utf-8") if isinstance(base, str) else base


def build_signing_base_section():
    jwk = O.ed25519_jwk(SEED_A)
    covered = ["@authority", "@method", "signature-agent"]
    url = "https://directory.example/keys"
    cases = []
    for created, expires, note in [
        (1000, 2000, "canonical web-bot-auth signing base (authority + method + signature-agent)"),
        (5000, 6000, "same profile, different created/expires window"),
    ]:
        base = _base(covered, created, expires, jwk["kid"], url)
        cases.append({
            "in": {"covered_components": covered, "method": "GET", "authority": "bot.example",
                   "path": "/", "headers": {"signature-agent": f'"{url}"'},
                   "created": created, "expires": expires, "keyid": jwk["kid"]},
            "mode": "rfc9421",
            "signature_params_raw": O.signature_params_raw(covered, created, expires, jwk["kid"]),
            "signing_base_b64": _b64(base),
            "ok": True,
            "note": note,
        })
    return cases


def build_coverage_section():
    reqs = ["@authority", "signature-agent"]
    rows = [
        (["@authority", "@method", "signature-agent"], "full coverage of the required components"),
        (["@authority", "signature-agent"], "exactly the required components"),
        (["@method", "signature-agent"], "missing @authority (cross-origin replay)"),
        (["@authority", "@method"], "missing signature-agent (directory substitution)"),
        (["@method"], "missing both required components"),
    ]
    cases = []
    for covered, note in rows:
        accept, reason = O.coverage_verdict(covered)
        cases.append({"covered_components": covered, "required": reqs,
                      "expect_accept": accept, "reason": reason, "note": note})
    return cases


def build_freshness_section():
    rows = [
        (1000, 2000, 1500, "inside the validity window"),
        (1000, 2000, 1000, "boundary: now == created (valid)"),
        (1000, 2000, 1999, "boundary: last valid second"),
        (1000, 2000, 2000, "boundary: now == expires (expired)"),
        (1000, 2000, 2500, "past expiry"),
        (1000, 2000, 900, "before created (not yet valid)"),
        (2000, 1000, 1500, "expires not after created (malformed window)"),
    ]
    cases = []
    for created, expires, now, note in rows:
        accept, reason = O.freshness_verdict(created, expires, now)
        cases.append({"created": created, "expires": expires, "now": now,
                      "expect_accept": accept, "reason": reason, "note": note})
    return cases


def build_directory_section():
    jwkA = O.ed25519_jwk(SEED_A)
    jwkB = O.ed25519_jwk(SEED_B)
    jwkEC = {"kty": "EC", "crv": "P-256",
             "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
             "kid": "ec-key-1"}
    directory = [jwkA, jwkB, jwkEC]
    rows = [
        (jwkA["kid"], "known Ed25519 key A"),
        (jwkB["kid"], "known Ed25519 key B"),
        ("ec-key-1", "keyid resolves to a non-Ed25519 (EC) key"),
        ("unknown-thumbprint", "keyid absent from the directory"),
    ]
    cases = []
    for keyid, note in rows:
        accept, reason = O.directory_verdict(directory, keyid)
        cases.append({"directory": directory, "keyid": keyid,
                      "expect_accept": accept, "reason": reason, "note": note})
    return cases


def build_ssrf_section():
    rows = [
        ("https://93.184.216.34/keys", None, "public https directory (allowed)"),
        ("http://93.184.216.34/keys", None, "http scheme rejected (must be https)"),
        ("https://127.0.0.1/keys", None, "loopback rejected"),
        ("https://169.254.169.254/latest/meta-data/", None, "cloud metadata address rejected"),
        ("https://10.1.2.3/keys", None, "private RFC1918 address rejected"),
        ("https://[::1]/keys", None, "IPv6 loopback rejected"),
        ("https://user@93.184.216.34/keys", None, "userinfo in URL rejected"),
        ("https://directory.example/keys", "93.184.216.34", "hostname resolving to public address (allowed)"),
        ("https://internal.example/keys", "192.168.1.10", "hostname resolving to private address rejected"),
        ("https://directory.example/keys", None, "hostname with no resolution rejected"),
    ]
    cases = []
    for url, rip, note in rows:
        accept, reason = O.ssrf_verdict(url, rip)
        cases.append({"signature_agent_url": url, "resolved_ip": rip,
                      "expect_fetch_allowed": accept, "reason": reason, "note": note})
    return cases


def build_ed25519_verify_section():
    covered = ["@authority", "@method", "signature-agent"]
    url = "https://directory.example/keys"
    jwkA = O.ed25519_jwk(SEED_A)
    base = _base(covered, 1000, 2000, jwkA["kid"], url)
    sig = O.ed25519_sign(SEED_A, base)
    tampered = bytearray(sig); tampered[0] ^= 0x01
    cases = [
        {"signing_base_b64": _b64(base), "sig_hex": sig.hex(),
         "pk_hex": O.ed25519_public_hex(SEED_A), "expect_valid": True,
         "note": "valid Ed25519 signature over the web-bot-auth signing base"},
        {"signing_base_b64": _b64(base), "sig_hex": bytes(tampered).hex(),
         "pk_hex": O.ed25519_public_hex(SEED_A), "expect_valid": False,
         "note": "one signature byte flipped"},
        {"signing_base_b64": _b64(base), "sig_hex": sig.hex(),
         "pk_hex": O.ed25519_public_hex(SEED_B), "expect_valid": False,
         "note": "correct signature verified against the wrong public key"},
    ]
    return cases


def main() -> int:
    corpus = {
        "name": "webbotauth_v0",
        "description": ("Signed cross-language conformance battery for the Web Bot Auth "
                        "RFC 9421 profile: covered-component completeness, freshness/replay "
                        "windows, directory keyid resolution, Signature-Agent SSRF, and the "
                        "Ed25519 signature verdict over the profile signing base."),
        "profile": "web-bot-auth",
        "policy": O.POLICY,
        "wba_signing_base": build_signing_base_section(),
        "wba_coverage": build_coverage_section(),
        "wba_freshness": build_freshness_section(),
        "wba_directory": build_directory_section(),
        "wba_directory_ssrf": build_ssrf_section(),
        "wba_ed25519_verify": build_ed25519_verify_section(),
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2)
        fh.write("\n")

    counts = {k: len(v) for k, v in corpus.items() if isinstance(v, list)}
    print("generated", OUT)
    print("  sections", counts)
    print("  total_cases", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
