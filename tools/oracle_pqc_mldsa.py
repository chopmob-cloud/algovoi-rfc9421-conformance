#!/usr/bin/env python3
"""Reference decision surface for post-quantum ML-DSA-65 verification (pqc_mldsa_v0).

ML-DSA is the NIST-standardised lattice signature of FIPS 204 (final, August 2024).
This corpus is the post-quantum sign/verify stage of the signing-flow bridge, the
ML-DSA sibling of the classical jws_v0 / cose_v0 verification corpora.

CRITICAL: ML-DSA (FIPS 204 final) is NOT interoperable with the earlier round-3
"Dilithium" scheme. FIPS 204 added domain separation (a signer prepends a domain
byte and a context-string length/value to the message before hashing) and revised
encodings, so a signature produced by an old Dilithium library will NOT verify
under a FIPS-204 ML-DSA verifier and vice versa. Every implementation this corpus
touches (this oracle, the KAT's independent library, every runner) MUST be
FIPS-204 final ML-DSA-65 (the parameter set with Dilithium3 lattice dimensions but
the final domain separation, empty context string). The KAT gate re-derives every
verdict with a SEPARATE FIPS-204 ML-DSA-65 implementation; if the two independent
implementations disagree on the SAME frozen signature, that is a Dilithium-vs-
ML-DSA (or parameter) mismatch and must be resolved before the corpus is trusted.

This module is the ONE reference decision surface the generator uses to stamp the
expected verdict for every pqc_mldsa_v0 case, and the python runner re-uses it
(python is the reference language). It:

  - rejects a malformed public key (wrong byte length) before any verify,
  - rejects a malformed signature (wrong byte length, including empty) before any
    verify,
  - otherwise returns the liboqs ML-DSA-65 verify verdict over the exact message
    bytes with the empty context string (the pure ML-DSA variant).

Public key material and signatures only; never a private signing key (the
material's private key is generated and held off-repo).

Requires liboqs (via the `oqs` python package) exposing the "ML-DSA-65" mechanism.
If the installed liboqs only offers "Dilithium3", that is the wrong/old build.
"""
from __future__ import annotations

# FIPS 204 (Table 2) parameter set ML-DSA-65. The mechanism name is the FIPS-204
# name; a build that only exposes "Dilithium3" is the round-3 scheme, not this one.
MECHANISM = "ML-DSA-65"
SPEC = "FIPS204"

# FIPS 204 ML-DSA-65 fixed byte lengths. Held as constants so malformed-length
# rejection is deterministic and needs no liboqs call. The material generator
# asserts these equal the lengths liboqs reports, so a drift is caught at freeze.
PK_LEN = 1952
SIG_LEN = 3309
SK_LEN = 4032


class MLDSAError(ValueError):
    """An input that must be rejected before any signature check."""


def _as_bytes(x) -> bytes:
    """Coerce bytes or a hex string to bytes; anything else is malformed."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise MLDSAError(f"expected bytes or hex string, got {type(x).__name__}")


def verdict(public_key, message, signature):
    """Decide accept/reject for one ML-DSA-65 (public_key, message, signature).

    Each of public_key / message / signature may be raw bytes or a hex string
    (the corpus ships hex). Order of rejection is deliberate: malformed hex, then
    a wrong-length public key, then a wrong-length signature (empty included), and
    only then the FIPS-204 ML-DSA-65 cryptographic verify over the exact message
    bytes with the empty context string.

    Returns (accept: bool, reason: str). The reason is informational; the corpus
    asserts only the bool, which the independent KAT library re-derives."""
    try:
        pk = _as_bytes(public_key)
        msg = _as_bytes(message)
        sig = _as_bytes(signature)
    except (MLDSAError, ValueError) as e:
        return False, f"malformed_hex:{e}"

    if len(pk) != PK_LEN:
        return False, f"malformed_public_key_length:{len(pk)}!={PK_LEN}"
    if len(sig) != SIG_LEN:
        return False, f"malformed_signature_length:{len(sig)}!={SIG_LEN}"

    import oqs
    with oqs.Signature(MECHANISM) as verifier:
        ok = bool(verifier.verify(msg, sig, pk))
    return (ok, "ok" if ok else "signature_invalid")
