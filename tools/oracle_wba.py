#!/usr/bin/env python3
"""Reference decision surface for the Web Bot Auth RFC 9421 profile (webbotauth_v0).

Web Bot Auth (draft-meunier-web-bot-auth-architecture + the HTTP Message
Signatures directory draft) is an RFC 9421 profile: an automated agent signs its
HTTP request to an origin with Ed25519, carrying a `Signature-Agent` header (a URL
to a directory of the agent's public keys), the `tag="web-bot-auth"` label, and
`created`/`expires` bounds. The origin resolves the key from the directory by
`keyid`, enforces freshness, and checks that the security-critical components are
actually covered.

This module is the ONE reference decision surface the generator uses to stamp the
expected verdict for every case. The runners re-implement these rules in their own
language, and the KAT gate re-derives them a third way, so the corpus never trusts
a single implementation. Everything is deterministic: no clock (a per-case `now` is
carried), no network (directory bytes are carried), Ed25519 keys are RFC 8032
reference seeds. All rules are pure structural / arithmetic properties.

Defensive scope: this validates a verifier's ACCEPT/REJECT logic. It ships public
keys and crafted requests only, never private signing keys of any real agent.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from urllib.parse import urlsplit

from nacl.signing import SigningKey

# ---------------------------------------------------------------------------
# Profile policy. Shipped in the corpus `policy` block so runners read it rather
# than hardcoding, exactly as the keyhygiene ROCA section ships its generator.
# ---------------------------------------------------------------------------
POLICY = {
    "profile": "web-bot-auth",
    "tag": "web-bot-auth",
    "alg": "ed25519",
    # RFC 9421 verifiers MUST reject a signature that does not cover the
    # security-critical components. For web-bot-auth the origin binds the request
    # to the authority it was sent to and to the agent directory that vouches for
    # the key; without both, a valid signature is replayable across origins /
    # swappable to another agent's directory.
    "required_covered_components": ["@authority", "signature-agent"],
    # No runtime clock: freshness is decided against the per-case `now`. Skew is a
    # policy constant (0 here, so boundaries are exact and reproducible).
    "clock_skew_seconds": 0,
    # SSRF gate on the Signature-Agent / directory URL (security-profiler: a
    # key-resolution URL is an attacker-influenced fetch target). https only, and
    # the resolved address must be a public unicast address.
    # The address must be public unicast, decided PURELY by membership in this
    # explicit denied list (no language-specific is_global heuristic), so every
    # runner computes the identical verdict from the same policy bytes. The list
    # covers every IANA special-purpose / non-global range.
    "ssrf": {
        "require_https": True,
        "denied_cidrs": [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
            "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
            "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
            "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
        ],
    },
}


# ---------------------------------------------------------------------------
# Deterministic key material (RFC 8032 style seeds -> Ed25519 JWK).
# ---------------------------------------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def ed25519_jwk(seed: bytes) -> dict:
    """Public Ed25519 JWK with an RFC 8037 thumbprint as `kid`."""
    vk = SigningKey(seed).verify_key
    x = _b64u(bytes(vk))
    thumb_input = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x},
                             separators=(",", ":"), sort_keys=True).encode("ascii")
    kid = _b64u(hashlib.sha256(thumb_input).digest())
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}


def ed25519_public_hex(seed: bytes) -> str:
    return bytes(SigningKey(seed).verify_key).hex()


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return SigningKey(seed).sign(message).signature


# ---------------------------------------------------------------------------
# Profile decision functions. Each returns (accept: bool, reason: str). The reason
# strings are part of the frozen contract, so every runner must agree on WHY too.
# ---------------------------------------------------------------------------
def coverage_verdict(covered_components, policy=POLICY):
    """A signature is accepted only if every required component is covered."""
    covered = {c.lower() for c in covered_components}
    for req in policy["required_covered_components"]:
        if req.lower() not in covered:
            return False, f"missing_required_covered_component:{req}"
    return True, "ok"


def freshness_verdict(created, expires, now, policy=POLICY):
    """Accept iff created - skew <= now < expires (half-open window)."""
    skew = policy["clock_skew_seconds"]
    if not (isinstance(created, int) and isinstance(expires, int) and isinstance(now, int)):
        return False, "non_integer_timestamp"
    if expires <= created:
        return False, "expires_not_after_created"
    if now < created - skew:
        return False, "not_yet_valid"
    if now >= expires:
        return False, "expired"
    return True, "ok"


def directory_verdict(directory, keyid, policy=POLICY):
    """Resolve `keyid` in the carried JWKS directory; accept iff a matching key
    exists and it is an Ed25519 OKP key (the only algorithm this profile allows)."""
    match = None
    for jwk in directory:
        if jwk.get("kid") == keyid:
            match = jwk
            break
    if match is None:
        return False, "keyid_not_in_directory"
    if match.get("kty") != "OKP" or match.get("crv") != "Ed25519":
        return False, "key_algorithm_not_ed25519"
    if not match.get("x"):
        return False, "malformed_jwk"
    return True, "ok"


def _host_ip(url):
    """Return (ip_or_None, host, has_userinfo). For a literal-IP host the IP is
    taken directly; for a hostname the caller supplies resolved_ip separately."""
    parts = urlsplit(url)
    host = parts.hostname
    has_userinfo = "@" in (parts.netloc or "")
    ip = None
    if host:
        stripped = host.strip("[]")
        try:
            ip = ipaddress.ip_address(stripped)
        except ValueError:
            ip = None
    return ip, host, has_userinfo, parts.scheme


def ssrf_verdict(url, resolved_ip=None, policy=POLICY):
    """Decide whether the directory URL may be fetched. Rejecting (must-not-fetch)
    is the safe verdict; accept only for https + a public unicast address."""
    ip, host, has_userinfo, scheme = _host_ip(url)
    if policy["ssrf"]["require_https"] and scheme != "https":
        return False, "scheme_not_https"
    if has_userinfo:
        return False, "url_contains_userinfo"
    if host is None:
        return False, "no_host"
    addr = ip
    if addr is None:
        if resolved_ip is None:
            return False, "unresolved_host"
        try:
            addr = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False, "malformed_resolved_ip"
    for cidr in policy["ssrf"]["denied_cidrs"]:
        if addr.version == ipaddress.ip_network(cidr).version and addr in ipaddress.ip_network(cidr):
            return False, "address_in_denied_range"
    return True, "ok"


def signature_params_raw(covered, created, expires, keyid, tag="web-bot-auth", alg="ed25519"):
    """Serialise the @signature-params inner list exactly (RFC 9421 Section 2.3)."""
    inner = " ".join(f'"{c}"' for c in covered)
    return (f'({inner});created={created};expires={expires};'
            f'keyid="{keyid}";alg="{alg}";tag="{tag}"')
