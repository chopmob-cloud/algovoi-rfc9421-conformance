#!/usr/bin/env python3
"""Reference decision surface for JSON Web Signature (jws_v0).

JWS (RFC 7515) is the JOSE object that carries a signature over a payload in the
compact serialization `BASE64URL(protected) . BASE64URL(payload) . BASE64URL(sig)`.
The signing input is `ASCII(protected) + "." + ASCII(payload)` (RFC 7515 Section
5.1), so a verifier must sign/verify over the exact segment bytes, never over a
re-encoding of the decoded values.

This module is the ONE reference decision surface the generator uses to stamp the
expected verdict for every jws_v0 case. The python runner re-uses it (python is
the reference language); the KAT gate and the independence cross-check re-derive
every verdict with a SEPARATE third-party JOSE library (jwcrypto), so a corpus
that merely agrees with this surface cannot pass.

It enforces the JOSE security rules that lenient verifiers get wrong:

  - `alg: none` is always rejected (RFC 7515 Section 4.1.1: an unsecured JWS must
    never be accepted by a verifier that expects a signature).
  - the header `alg` must match the key type the verifier holds. HS256 with an
    RSA public key used as the HMAC secret is the classic key/alg confusion
    attack (a forger MACs the signing input with the public key bytes that every
    verifier already has); RS256 against an EC key, ES256 against an RSA key, and
    friends are the same bug. All are rejected here.
  - an unknown / unsupported `crit` header parameter is rejected (RFC 7515
    Section 4.1.11: a param the verifier does not understand MUST cause rejection).
  - a `kid` that selects no held key is rejected (key selection, RFC 7515 4.1.4).

Scope: RFC 7515 (JWS) + RFC 7518 (JWA: RS256, ES256) + RFC 8037 (EdDSA / Ed25519).
Deliberately NOT enforced: ECDSA low-s. Plain JOSE (RFC 7518 Section 3.4) permits
a high-s signature, so low-s is a FAPI profile rule (see fapi_messagesigning_v0),
never a jws_v0 rule. Keeping it out is what makes jws_v0 the version-neutral base.

Public keys and crafted tokens only; never a private signing key (the material's
private keys are generated off-repo).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

# RFC 7518 Section 3.1 alg -> the JWK key type (kty) a verifier must hold for it.
# HS256 needs an "oct" symmetric secret; presenting it an asymmetric public key is
# the confusion attack, caught by the kty mismatch below.
ALG_KTY = {"RS256": "RSA", "ES256": "EC", "EdDSA": "OKP", "HS256": "oct"}

# secp256r1 curve parameters, for reconstructing / validating an EC public point.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

_B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class JWSError(ValueError):
    """A compact JWS that must be rejected before any signature check."""


# ---------------------------------------------------------------------------
# Compact serialization parsing (RFC 7515 Section 7.1 / 5.2)
# ---------------------------------------------------------------------------

def b64url_decode(seg: str) -> bytes:
    """Strict base64url decode of one compact segment (RFC 7515 Appendix C).

    JOSE base64url is unpadded and uses only the URL-safe alphabet, so any other
    character (including '=' padding) is a malformed segment and rejected."""
    if any(c not in _B64URL for c in seg):
        raise JWSError("non-base64url character in segment")
    pad = "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg + pad)
    except (ValueError, base64.binascii.Error):
        raise JWSError("segment is not valid base64url")


def parse_compact(token: str):
    """Split and decode a compact JWS into (protected_header, payload, sig,
    signing_input). Raise JWSError on any structural fault the verifier must
    reject before touching a key."""
    parts = token.split(".")
    if len(parts) != 3:
        raise JWSError(f"compact JWS must have exactly 3 segments, got {len(parts)}")
    p_b64, pl_b64, s_b64 = parts
    header_bytes = b64url_decode(p_b64)
    try:
        header = json.loads(header_bytes)
    except ValueError:
        raise JWSError("protected header is not valid JSON")
    if not isinstance(header, dict):
        raise JWSError("protected header is not a JSON object")
    if "alg" not in header:
        raise JWSError("protected header is missing the alg parameter")
    payload = b64url_decode(pl_b64)
    sig = b64url_decode(s_b64)
    # The signing input is the exact ASCII of the two encoded segments, not a
    # re-encoding of the decoded header/payload (RFC 7515 Section 5.1).
    signing_input = (p_b64 + "." + pl_b64).encode("ascii")
    return header, payload, sig, signing_input


# ---------------------------------------------------------------------------
# Signature verification per algorithm (RFC 7518 / RFC 8037)
# ---------------------------------------------------------------------------

def _int_from_b64u(s: str) -> int:
    return int.from_bytes(b64url_decode(s), "big")


def _verify_rs256(jwk, signing_input, sig) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.exceptions import InvalidSignature
    try:
        pub = rsa.RSAPublicNumbers(_int_from_b64u(jwk["e"]), _int_from_b64u(jwk["n"])).public_key()
        pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _verify_es256(jwk, signing_input, sig) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature
    # A JOSE ECDSA signature is the fixed-width concatenation R || S, 32 bytes
    # each (RFC 7518 Section 3.4). Any other width is malformed.
    if len(sig) != 64:
        return False
    try:
        x, y = _int_from_b64u(jwk["x"]), _int_from_b64u(jwk["y"])
        # Reject a public key whose point is not on secp256r1 before trusting it.
        if (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P != 0:
            return False
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        pub.verify(utils.encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _verify_eddsa(jwk, signing_input, sig) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
        pub.verify(sig, signing_input)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _verify_hs256(jwk, signing_input, sig) -> bool:
    # Present only so the surface is total; jws_v0 never legitimately holds an
    # oct key, so the confusion attack is caught by the kty mismatch, not here.
    try:
        secret = b64url_decode(jwk["k"])
    except (JWSError, KeyError):
        return False
    return hmac.compare_digest(hmac.new(secret, signing_input, hashlib.sha256).digest(), sig)


_VERIFIERS = {"RS256": _verify_rs256, "ES256": _verify_es256,
              "EdDSA": _verify_eddsa, "HS256": _verify_hs256}


# ---------------------------------------------------------------------------
# The verdict surface used by the generator
# ---------------------------------------------------------------------------

def _select_key(header, ctx):
    """Return the JWK the verifier applies, or None if selection fails.

    A keyset verifier selects by the header `kid` (RFC 7515 Section 4.1.4): an
    absent or unmatched kid selects no key. A single-key verifier applies the one
    key it holds regardless of kid."""
    keys = ctx["keys"]
    if ctx.get("select_by_kid"):
        kid = header.get("kid")
        if kid is None:
            return None
        for k in keys:
            if k.get("kid") == kid:
                return k["jwk"]
        return None
    return keys[0]["jwk"]


def verdict(token: str, ctx: dict):
    """Decide accept/reject for one compact JWS under a verifier context.

    ctx = {"keys": [{"kid": str, "jwk": {...}}, ...], "select_by_kid": bool}.
    Returns (accept: bool, reason: str). The reason is informational; the corpus
    asserts only the bool, which the independent library re-derives.

    Order of rejection is deliberate: structural parse, then alg=none, then an
    unknown crit, then key selection, then the alg/key-type match (the confusion
    guard), then the cryptographic signature. Each earlier rule is a security
    gate that must fire before the signature is ever checked."""
    try:
        header, payload, sig, signing_input = parse_compact(token)
    except JWSError as e:
        return False, f"parse_error:{e}"

    alg = header["alg"]
    if alg == "none":
        return False, "alg_none_rejected"
    if "crit" in header:
        # We understand no crit extension, so any crit parameter is unsupported.
        return False, f"unknown_crit_rejected:{header.get('crit')}"
    if alg not in ALG_KTY:
        return False, f"unsupported_alg:{alg}"

    jwk = _select_key(header, ctx)
    if jwk is None:
        return False, f"no_key_for_kid:{header.get('kid')}"
    if jwk.get("kty") != ALG_KTY[alg]:
        return False, f"alg_key_type_mismatch:alg={alg} kty={jwk.get('kty')}"

    ok = _VERIFIERS[alg](jwk, signing_input, sig)
    return (ok, "ok" if ok else "signature_invalid")
