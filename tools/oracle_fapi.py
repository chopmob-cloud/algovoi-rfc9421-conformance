#!/usr/bin/env python3
"""Reference decision surface for the FAPI 2.0 Message Signing profile.

FAPI 2.0 Message Signing (OpenID Foundation, financial-grade API) uses RFC 9421
HTTP Message Signatures for non-repudiation of high-value API calls. The profile
adds strict rules on top of a merely-valid signature:

  - allowed algorithms are PS256 (RSA-PSS SHA-256) and ES256 (ECDSA P-256) only;
  - the signature MUST cover a mandated set of components so the token and the
    body are bound (request: @method, @target-uri, authorization, content-digest;
    response: @status, content-digest);
  - when a message has a body, a Content-Digest (RFC 9530) MUST be present, MUST
    be covered by the signature, and MUST match the body (body-swap protection).

This module is the ONE reference decision surface the generator uses to stamp the
expected verdict for every case. The runners re-implement these rules and the KAT
gate re-derives them independently. Everything is deterministic: fixed test keys,
signatures frozen once into vectors/fapi_material_v0.json, bodies carried in the
corpus. Defensive scope: public keys and crafted messages only, never a private
signing key (the material's private key is generated off-repo).
"""
from __future__ import annotations

import base64
import hashlib

# ---------------------------------------------------------------------------
# Profile policy (shipped in the corpus `policy` block; runners read it).
# ---------------------------------------------------------------------------
POLICY = {
    "profile": "fapi-2-message-signing",
    # PS256 = rsa-pss-sha256; ES256 = ecdsa-p256-sha256. Nothing else is FAPI.
    "allowed_algs": ["ps256", "es256"],
    "required_covered_request": ["@method", "@target-uri", "authorization", "content-digest"],
    "required_covered_response": ["@status", "content-digest"],
    # Content-Digest (RFC 9530) hashes a body may use.
    "content_digest_algorithms": ["sha-256", "sha-512"],
    # ECDSA is malleable: a non-repudiation profile rejects the high-s twin.
    "require_low_s": True,
    # secp256r1 group order n; s is malleable iff s > n/2.
    "p256_n": "115792089210356248762697446949407573529996955224135760342422259061068512044369",
}


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Profile decision functions. Each returns (accept: bool, reason: str).
# ---------------------------------------------------------------------------
def required_coverage_verdict(message_type, covered, policy=POLICY):
    """A FAPI signature must cover every mandated component for its message type,
    or the token / body it is supposed to bind is left unprotected."""
    key = "required_covered_request" if message_type == "request" else "required_covered_response"
    have = {c.lower() for c in covered}
    for req in policy[key]:
        if req.lower() not in have:
            return False, f"missing_required_covered_component:{req}"
    return True, "ok"


def alg_verdict(alg, policy=POLICY):
    """Only the FAPI-allowed algorithms are accepted; RS256/HS256/none are not."""
    if alg.lower() in policy["allowed_algs"]:
        return True, "ok"
    return False, f"algorithm_not_allowed:{alg}"


def compute_content_digest(body: bytes, algorithm: str) -> str:
    """RFC 9530 Content-Digest field value for a body, e.g. `sha-256=:<b64>:`."""
    h = hashlib.sha256(body).digest() if algorithm == "sha-256" else hashlib.sha512(body).digest()
    return f"{algorithm}=:{base64.b64encode(h).decode('ascii')}:"


def content_digest_verdict(body_b64, header_value, covered, policy=POLICY):
    """Accept iff the Content-Digest is covered, uses an allowed algorithm, and
    matches the body (RFC 9530). A body-swap or an uncovered digest is rejected."""
    if "content-digest" not in {c.lower() for c in covered}:
        return False, "content_digest_not_covered"
    try:
        algorithm, rest = header_value.split("=", 1)
    except ValueError:
        return False, "content_digest_malformed"
    algorithm = algorithm.strip().lower()
    if algorithm not in policy["content_digest_algorithms"]:
        return False, f"content_digest_algorithm_not_allowed:{algorithm}"
    body = _b64d(body_b64)
    if header_value.strip() != compute_content_digest(body, algorithm):
        return False, "content_digest_mismatch"
    return True, "ok"


def is_high_s(s_int: int, policy=POLICY) -> bool:
    return s_int > int(policy["p256_n"]) // 2


def signature_params_raw(covered, keyid, alg, created=None, tag="fapi-2"):
    """Serialise the @signature-params inner list (RFC 9421 Section 2.3)."""
    inner = " ".join(f'"{c}"' for c in covered)
    parts = [f"({inner})"]
    if created is not None:
        parts.append(f"created={created}")
    parts.append(f'keyid="{keyid}";alg="{alg}";tag="{tag}"')
    return ";".join(parts)
