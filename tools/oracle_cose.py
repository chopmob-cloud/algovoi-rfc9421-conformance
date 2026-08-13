#!/usr/bin/env python3
"""Reference decision surface for COSE_Sign1 (cose_v0).

COSE (RFC 9052) is the CBOR object signing format; COSE_Sign1 (Section 4.2) is the
single-signer message, the CBOR analog of a compact JWS. A COSE_Sign1 is a CBOR
array of four items [protected: bstr, unprotected: map, payload: bstr/nil,
signature: bstr], optionally CBOR-tagged 18. The signature is computed over the
Sig_structure (Section 4.4) = ["Signature1", protected (bstr), external_aad (bstr,
empty here), payload (bstr)], encoded as deterministic CBOR (RFC 8949 Section 4.2),
then signed/verified with the algorithm (RFC 9053).

This module is the ONE reference decision surface the generator uses to stamp the
expected verdict for every cose_v0 case. The python runner re-uses it (python is
the reference language); the KAT gate re-derives every verdict with a SEPARATE
third-party COSE library (pycose) plus an independent cbor2 canonical check, so a
corpus that merely agrees with this surface cannot pass.

It enforces the COSE security rules a lenient verifier gets wrong:

  - the header `alg` (label 1) MUST be in the PROTECTED header. An alg carried only
    in the unprotected header is not integrity-protected (an attacker can rewrite
    it), so it is rejected (RFC 9052 Section 3.1 makes alg a header a recipient
    relies on; putting it in the unprotected bucket defeats that).
  - an unknown / unsupported `crit` label (label 2) is rejected (RFC 9052 Section
    3.1: a critical header the recipient does not understand MUST cause rejection).
  - the protected header and the Sig_structure are deterministically encoded
    (RFC 8949 Section 4.2, bytewise-lexicographic map key order). A protected
    header that is not its own canonical encoding is rejected.
  - `alg` must match the key type the verifier holds (ES256 needs an EC2 key,
    EdDSA an OKP key, PS256 an RSA key); a mismatch is the COSE key/alg confusion
    and is rejected before any signature check.

Deliberately NOT enforced: ECDSA low-s. Plain COSE/JOSE permit a high-s signature,
so low-s is a FAPI profile rule (see fapi_messagesigning_v0), never a cose_v0 rule.
Keeping it out is what makes cose_v0 the version-neutral base.

Public keys and crafted messages only; never a private signing key (the material's
private keys are generated off-repo).

Requires: cbor2, cryptography, PyNaCl.
"""
from __future__ import annotations

import cbor2
from cbor2 import CBORTag

# COSE header labels (RFC 9052 Section 3.1) and algorithm ids (RFC 9053).
HDR_ALG, HDR_CRIT, HDR_KID = 1, 2, 4
ALG_ES256, ALG_EDDSA, ALG_PS256 = -7, -8, -37
COSE_SIGN1_TAG = 18

# alg -> the COSE key type (kty) a verifier must hold for it. Presenting an alg an
# EC2 key with an RSA-only alg, or vice versa, is the confusion attack.
ALG_KTY = {ALG_ES256: "EC2", ALG_EDDSA: "OKP", ALG_PS256: "RSA"}

# Header labels this verifier understands, for the crit check. A crit entry naming
# a label outside this set is an extension we cannot honor, so we reject.
KNOWN_LABELS = {HDR_ALG, HDR_CRIT, HDR_KID, 3, 5}  # alg, crit, kid, content type, IV

# secp256r1 parameters, for validating an EC public point before trusting it.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


class COSEError(ValueError):
    """A COSE_Sign1 that must be rejected before any signature check."""


# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 Section 4.2)
# ---------------------------------------------------------------------------

def dcbor(obj) -> bytes:
    """Deterministic CBOR encode: shortest-form integers, definite lengths,
    bytewise-lexicographic map key order. cbor2's canonical mode implements exactly
    the RFC 8949 Section 4.2 ordering (bytewise on the encoded key, e.g. the 2-byte
    key 100 sorts before the 1-byte key -1)."""
    return cbor2.dumps(obj, canonical=True)


def is_deterministic_cbor(data: bytes):
    """Decide whether `data` is well-formed CBOR encoded in RFC 8949 Section 4.2
    deterministic form. Returns (accept: bool, reason: str).

    A datum is deterministic iff decoding it and re-encoding it canonically
    reproduces the exact bytes: this catches non-shortest integers, indefinite
    lengths, and unsorted map keys, all of which decode fine but re-encode to
    different (shorter / definite / sorted) bytes."""
    try:
        value = cbor2.loads(data)
    except Exception as e:  # noqa: BLE001 - any decode fault is non-deterministic/invalid
        return False, f"not_well_formed_cbor:{e}"
    if isinstance(value, CBORTag):
        return False, "unexpected_tag_in_deterministic_datum"
    try:
        canon = dcbor(value)
    except Exception as e:  # noqa: BLE001
        return False, f"cannot_canonicalize:{e}"
    if canon != data:
        return False, "not_canonical_encoding"
    return True, "canonical"


# ---------------------------------------------------------------------------
# COSE_Sign1 parsing (RFC 9052 Section 4.2)
# ---------------------------------------------------------------------------

def _mutable(x):
    """cbor2 6.x decodes the content of a CBOR tag with immutable containers
    (tuples, frozendicts) so a tagged value stays hashable. Convert back to plain
    lists/dicts so the structure is uniform for both us and pycose."""
    if isinstance(x, (list, tuple)):
        return [_mutable(i) for i in x]
    if hasattr(x, "items"):
        return {k: _mutable(v) for k, v in x.items()}
    return x


def parse_sign1(data: bytes):
    """Split a COSE_Sign1 (tagged 18 or untagged) into
    (protected_bytes, phdr_map, uhdr_map, payload, signature). Raise COSEError on
    any structural fault the verifier must reject before touching a key.

    The protected header is a bstr wrapping a serialized CBOR map; an empty
    protected header is the zero-length byte string (RFC 9052 Section 3), decoded
    here as the empty map."""
    try:
        top = cbor2.loads(data)
    except Exception as e:  # noqa: BLE001
        raise COSEError(f"not well-formed CBOR: {e}")
    if isinstance(top, CBORTag):
        if top.tag != COSE_SIGN1_TAG:
            raise COSEError(f"unexpected CBOR tag {top.tag} (COSE_Sign1 is tag 18)")
        arr = _mutable(top.value)
    else:
        arr = _mutable(top)
    if not isinstance(arr, list) or len(arr) != 4:
        raise COSEError("COSE_Sign1 must be a 4-element array")
    protected, uhdr, payload, signature = arr
    if not isinstance(protected, bytes):
        raise COSEError("protected header must be a byte string")
    if not isinstance(uhdr, dict):
        raise COSEError("unprotected header must be a map")
    if payload is not None and not isinstance(payload, bytes):
        raise COSEError("payload must be a byte string or nil")
    if not isinstance(signature, bytes):
        raise COSEError("signature must be a byte string")

    if protected == b"":
        phdr = {}
    else:
        # The protected header must be deterministically encoded (RFC 9052 requires
        # a canonical map; RFC 8949 Section 4.2 is the deterministic form).
        ok, _reason = is_deterministic_cbor(protected)
        if not ok:
            raise COSEError("protected header is not deterministically encoded")
        phdr = cbor2.loads(protected)
        if not isinstance(phdr, dict):
            raise COSEError("protected header does not wrap a map")
    return protected, phdr, uhdr, payload, signature


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """The COSE_Sign1 signing preimage (RFC 9052 Section 4.4), deterministic CBOR."""
    return dcbor(["Signature1", protected, external_aad, payload])


# ---------------------------------------------------------------------------
# Signature verification per algorithm (RFC 9053)
# ---------------------------------------------------------------------------

def _verify_es256(key: dict, preimage: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature
    # COSE ECDSA is fixed-width R || S, 32 bytes each (RFC 9053 Section 2.1). Any
    # other width is malformed.
    if len(sig) != 64:
        return False
    try:
        x = int.from_bytes(bytes.fromhex(key["x"]), "big")
        y = int.from_bytes(bytes.fromhex(key["y"]), "big")
        # Reject a public key whose point is not on secp256r1 before trusting it.
        if (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P != 0:
            return False
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        pub.verify(utils.encode_dss_signature(r, s), preimage, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _verify_eddsa(key: dict, preimage: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["x"]))
        pub.verify(sig, preimage)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _verify_ps256(key: dict, preimage: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.exceptions import InvalidSignature
    try:
        n = int.from_bytes(bytes.fromhex(key["n"]), "big")
        e = int.from_bytes(bytes.fromhex(key["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        pub.verify(sig, preimage, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=32), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


_VERIFIERS = {ALG_ES256: _verify_es256, ALG_EDDSA: _verify_eddsa, ALG_PS256: _verify_ps256}


# ---------------------------------------------------------------------------
# The verdict surface used by the generator
# ---------------------------------------------------------------------------

def verdict(data: bytes, key: dict):
    """Decide accept/reject for one COSE_Sign1 verified under the held public key.

    `data` is the message bytes; `key` is the public COSE key the verifier holds
    (a dict from the material's `keys` map). Returns (accept: bool, reason: str).
    The reason is informational; the corpus asserts only the bool, which the
    independent library re-derives.

    Order of rejection is deliberate: structural parse (which also enforces the
    protected-header determinism), then alg-in-protected, then an unknown crit,
    then the alg/key-type match (the confusion guard), then the cryptographic
    signature. Each earlier rule is a security gate that must fire before the
    signature is ever checked."""
    try:
        protected, phdr, uhdr, payload, sig = parse_sign1(data)
    except COSEError as e:
        return False, f"parse_error:{e}"

    if HDR_ALG not in phdr:
        # An alg only in the unprotected header is not integrity-protected.
        if HDR_ALG in uhdr:
            return False, "alg_only_in_unprotected_header"
        return False, "alg_missing_from_protected_header"
    alg = phdr[HDR_ALG]

    if HDR_CRIT in phdr:
        crit = phdr[HDR_CRIT]
        if not isinstance(crit, list) or not crit:
            return False, "crit_must_be_a_non_empty_array"
        for label in crit:
            if label not in KNOWN_LABELS:
                return False, f"unknown_crit_label:{label}"

    if alg not in ALG_KTY:
        return False, f"unsupported_alg:{alg}"
    if key.get("kty") != ALG_KTY[alg]:
        return False, f"alg_key_type_mismatch:alg={alg} kty={key.get('kty')}"

    preimage = sig_structure(protected, payload if payload is not None else b"")
    ok = _VERIFIERS[alg](key, preimage, sig)
    return (ok, "ok" if ok else "signature_invalid")
