#!/usr/bin/env python3
"""Deterministically generate the JSON Web Signature corpus (jws_v0).

Consumes the frozen public material (vectors/jws_material_v0.json) and stamps
every expected verdict with tools/oracle_jws.py, the single reference decision
surface. The python runner re-uses that surface (python is the reference
language); the KAT gate and the independence cross-check re-derive every verdict
with a SEPARATE third-party JOSE library (jwcrypto), so a corpus that merely
agrees with our own surface cannot pass.

Every case is self-describing: it carries the compact JWS (or its malformed
parts), a `verify` block naming the key(s) the verifier holds (into the corpus
`keys` map) and whether selection is by `kid`, an `expect_valid` bool, and a
`note`. Negatives are tamperings of the frozen valid tokens.

Scope: RFC 7515 (JWS) + RFC 7518 (RS256, ES256) + RFC 8037 (EdDSA). ECDSA low-s
is deliberately deferred to the FAPI profile, not enforced here (see the policy
block). Deterministic and LF-only for a byte-stable signed digest.

Run:  python tools/gen_jws_v0.py
"""
from __future__ import annotations

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_jws as O  # noqa: E402

REPO = os.path.dirname(HERE)
MATERIAL = os.path.join(REPO, "vectors", "jws_material_v0.json")
OUT_DIR = os.path.join(REPO, "corpus", "jws_v0")
OUT = os.path.join(OUT_DIR, "jws_v0.json")

SECTIONS = ("jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
            "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify",
            "jws_crit", "jws_kid")


# ---------------------------------------------------------------------------
# Compact-JWS surgery helpers, for building malformed and tampered negatives.
# ---------------------------------------------------------------------------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _flip_first_byte(seg: str) -> str:
    """Flip one bit of a base64url segment's decoded bytes: a one-byte tamper."""
    b = bytearray(_b64u_d(seg))
    b[0] ^= 0x01
    return _b64u(bytes(b))


def _retype_header(token: str, mutate) -> str:
    """Decode the protected header, apply `mutate(dict)`, re-encode, keep the rest.

    The signature is left untouched, so any header change breaks the signature,
    but for these cases an earlier rule (missing alg, kid selection) is what
    rejects, before the signature is ever checked."""
    p, pl, s = token.split(".")
    header = json.loads(_b64u_d(p))
    mutate(header)
    p2 = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return p2 + "." + pl + "." + s


def _swap_payload(token: str, new_payload: bytes) -> str:
    p, _pl, s = token.split(".")
    return p + "." + _b64u(new_payload) + "." + s


def _tamper_sig(token: str) -> str:
    p, pl, s = token.split(".")
    return p + "." + pl + "." + _flip_first_byte(s)


def _truncate_sig(token: str, nbytes: int) -> str:
    """Drop trailing bytes from the signature: a wrong-width R||S for ES256."""
    p, pl, s = token.split(".")
    return p + "." + pl + "." + _b64u(_b64u_d(s)[:nbytes])


def _synthetic(header: dict, payload: bytes, sig: bytes) -> str:
    p = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return p + "." + _b64u(payload) + "." + _b64u(sig)


# ---------------------------------------------------------------------------
# Verifier-context shorthands. `key_names` index into corpus["keys"]; the runner
# and the oracle resolve them, so a case never inlines a whole JWK.
# ---------------------------------------------------------------------------

def _held(*names) -> dict:
    return {"key_names": list(names), "select_by_kid": False}


def _keyset(*names) -> dict:
    return {"key_names": list(names), "select_by_kid": True}


def build(m):
    keys = m["keys"]
    payload = _b64u_d(m["payload_b64u"])
    rs, es, ed = m["tokens"]["rs256"], m["tokens"]["es256"], m["tokens"]["eddsa"]
    hs_conf = m["tokens"]["hs256_confusion"]

    corpus = {
        "name": "jws_v0",
        "description": ("Signed cross-language conformance battery for JSON Web Signature "
                        "(RFC 7515) with the RFC 7518 RS256 / ES256 and RFC 8037 EdDSA "
                        "algorithms: compact-serialization parsing, and the JOSE security "
                        "rejections that lenient verifiers get wrong (alg:none, key/alg "
                        "confusion such as HS256 keyed with an RSA public key, unknown crit, "
                        "kid selection), plus the RS256 / ES256 / EdDSA signature verdicts. "
                        "This is the JOSE sign/verify stage of the signing-flow bridge, the "
                        "JWS sibling of the RFC 9421 HTTP Message Signatures corpora."),
        "profile": "json-web-signature",
        "policy": {
            "specs": ["RFC7515", "RFC7518", "RFC8037"],
            "algorithms": ["RS256", "ES256", "EdDSA"],
            "compact_signing_input": "ASCII(BASE64URL(protected)) + '.' + ASCII(BASE64URL(payload))",
            "security_rules": [
                "alg:none is always rejected",
                "header alg must match the held key type (key/alg confusion rejected)",
                "an unknown or unsupported crit parameter is rejected",
                "a kid that selects no held key is rejected",
            ],
            "low_s": ("NOT enforced. Plain JOSE (RFC 7518 Section 3.4) permits a high-s "
                      "ECDSA signature; low-s is a FAPI profile rule (fapi_messagesigning_v0), "
                      "not a JWS rule, so it is deliberately out of jws_v0 scope."),
            "documented_divergences": [],
        },
        # Public JWKs the cases reference by name. Only public key material ships.
        "keys": keys,
    }
    for s in SECTIONS:
        corpus[s] = []

    # -- jws_compact_parse: structural parse before any key is touched ---------
    corpus["jws_compact_parse"] = [
        {"jws": rs, "verify": _held("rsa"), "expect_valid": True,
         "note": "valid 3-segment compact JWS (RS256), parses and verifies"},
        {"jws": rs.rsplit(".", 1)[0], "verify": _held("rsa"), "expect_valid": False,
         "note": "only 2 segments (missing signature segment)"},
        {"jws": rs + ".extra", "verify": _held("rsa"), "expect_valid": False,
         "note": "4 segments (a compact JWS has exactly 3; 5 would be a JWE)"},
        {"jws": (lambda p, pl, s: p + "." + pl[:-1] + "!" + "." + s)(*rs.split(".")),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "non-base64url character in the payload segment"},
        {"jws": _b64u(b"not-json{") + "." + m["payload_b64u"] + "." + "AA",
         "verify": _held("rsa"), "expect_valid": False,
         "note": "protected header is valid base64url but not valid JSON"},
        {"jws": _synthetic({"kid": "jws-rsa-1", "typ": "JWT"}, payload, b"\x00"),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "protected header is valid JSON but is missing the alg parameter"},
    ]

    # -- jws_alg_none: an unsecured JWS is never accepted ----------------------
    none_sig = _b64u_d(rs.split(".")[2])  # any bytes; alg:none rejects before verify
    corpus["jws_alg_none"] = [
        {"jws": _synthetic({"alg": "none", "kid": "jws-rsa-1"}, payload, none_sig),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "alg:none carrying a (bogus) signature segment"},
        {"jws": _synthetic({"alg": "none", "kid": "jws-rsa-1"}, payload, b""),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "alg:none with an empty signature segment (the unsecured JWS)"},
    ]

    # -- jws_alg_confusion: the header alg must match the held key type --------
    corpus["jws_alg_confusion"] = [
        {"jws": rs, "verify": _held("rsa"), "expect_valid": True,
         "note": "genuine RS256 verified with the RSA key (the accept control)"},
        {"jws": hs_conf, "verify": _held("rsa"), "expect_valid": False,
         "note": "HS256 forged with the RSA public-key bytes as the HMAC secret; "
                 "held key is RSA (classic key/alg confusion), rejected on kty mismatch"},
        {"jws": rs, "verify": _held("ec"), "expect_valid": False,
         "note": "RS256 token verified while holding an EC key (alg/key mismatch)"},
        {"jws": es, "verify": _held("rsa"), "expect_valid": False,
         "note": "ES256 token verified while holding the RSA key (alg/key mismatch)"},
    ]

    # -- jws_rs256_verify: RSASSA-PKCS1-v1_5 SHA-256 ---------------------------
    corpus["jws_rs256_verify"] = [
        {"jws": rs, "verify": _held("rsa"), "expect_valid": True,
         "note": "valid RS256 control"},
        {"jws": _tamper_sig(rs), "verify": _held("rsa"), "expect_valid": False,
         "note": "one-byte-tampered RS256 signature"},
        {"jws": _swap_payload(rs, payload + b" "), "verify": _held("rsa"), "expect_valid": False,
         "note": "tampered payload (signature no longer covers the signing input)"},
        {"jws": rs, "verify": _held("wrong_rsa"), "expect_valid": False,
         "note": "valid RS256 token verified under a different (wrong) RSA key"},
    ]

    # -- jws_es256_verify: ECDSA P-256 SHA-256 ---------------------------------
    corpus["jws_es256_verify"] = [
        {"jws": es, "verify": _held("ec"), "expect_valid": True,
         "note": "valid ES256 control (high-s permitted; low-s not enforced in jws_v0)"},
        {"jws": _tamper_sig(es), "verify": _held("ec"), "expect_valid": False,
         "note": "one-byte-tampered ES256 signature"},
        {"jws": _truncate_sig(es, 63), "verify": _held("ec"), "expect_valid": False,
         "note": "wrong-width R||S (63 bytes; a JOSE ES256 signature is exactly 64)"},
        {"jws": es, "verify": _held("offcurve_ec"), "expect_valid": False,
         "note": "public key point is not on secp256r1 (rejected before trust)"},
        {"jws": es, "verify": _held("wrong_ec"), "expect_valid": False,
         "note": "valid ES256 token verified under a different (wrong) EC key"},
    ]

    # -- jws_eddsa_verify: Ed25519 (RFC 8037) ----------------------------------
    corpus["jws_eddsa_verify"] = [
        {"jws": ed, "verify": _held("ed25519"), "expect_valid": True,
         "note": "valid EdDSA (Ed25519) control"},
        {"jws": _tamper_sig(ed), "verify": _held("ed25519"), "expect_valid": False,
         "note": "one-byte-tampered EdDSA signature"},
        {"jws": ed, "verify": _held("wrong_ed25519"), "expect_valid": False,
         "note": "valid EdDSA token verified under a different (wrong) Ed25519 key"},
    ]

    # -- jws_crit: an unknown crit parameter must be rejected ------------------
    corpus["jws_crit"] = [
        {"jws": _retype_header(rs, lambda h: h.update({"crit": ["urn:example:unknown"],
                                                       "urn:example:unknown": True})),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "crit lists an extension the verifier does not understand"},
        {"jws": _retype_header(rs, lambda h: h.update({"crit": ["b64"], "b64": False})),
         "verify": _held("rsa"), "expect_valid": False,
         "note": "crit:[\"b64\"] (RFC 7797) is not understood by a base JWS verifier"},
    ]

    # -- jws_kid: selection by kid from a keyset -------------------------------
    corpus["jws_kid"] = [
        {"jws": rs, "verify": _keyset("rsa", "ec", "ed25519"), "expect_valid": True,
         "note": "kid selects the correct RSA key from the keyset"},
        {"jws": _retype_header(rs, lambda h: h.update({"kid": "jws-unknown-9"})),
         "verify": _keyset("rsa", "ec", "ed25519"), "expect_valid": False,
         "note": "kid names a key not in the keyset (selects nothing)"},
        {"jws": _retype_header(rs, lambda h: h.pop("kid", None)),
         "verify": _keyset("rsa", "ec", "ed25519"), "expect_valid": False,
         "note": "no kid, so a keyset verifier can select no key"},
    ]
    return corpus


def _resolve_ctx(verify, keys):
    return {"keys": [{"kid": keys[n].get("kid"), "jwk": keys[n]} for n in verify["key_names"]],
            "select_by_kid": verify["select_by_kid"]}


def main() -> int:
    m = json.load(open(MATERIAL, encoding="utf-8"))
    corpus = build(m)

    # Stamp every verdict from the oracle and assert the intended sign of each
    # case, so a mislabeled positive/negative cannot slip into the corpus.
    for sec in SECTIONS:
        for c in corpus[sec]:
            ctx = _resolve_ctx(c["verify"], corpus["keys"])
            accept, reason = O.verdict(c["jws"], ctx)
            if accept != c["expect_valid"]:
                raise SystemExit(
                    f"oracle disagrees with the intended verdict [{sec}]: {c['note']!r} "
                    f"(expect_valid={c['expect_valid']} oracle={accept} reason={reason})")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    counts = {k: len(v) for k, v in corpus.items() if isinstance(v, list)}
    print("generated", OUT)
    print("  sections", counts)
    print("  total_cases", sum(counts.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
