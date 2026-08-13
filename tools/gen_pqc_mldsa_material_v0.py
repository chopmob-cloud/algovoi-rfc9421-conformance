#!/usr/bin/env python3
"""One-time material freezer for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).

Generates a fixed FIPS-204 ML-DSA-65 keypair with liboqs (the PRIVATE key is held
OFF-REPO at ~/.algovoi/keys/pqc-mldsa-material-v0.json), signs a small set of fixed
messages, generates a second independent keypair whose PUBLIC key is the wrong-key
negative control, and writes the PUBLIC material (public keys hex, messages hex,
valid signatures hex, and the FIPS-204 byte lengths) to
vectors/pqc_mldsa_material_v0.json.

Idempotent and frozen: if the private key file already exists it is loaded and the
keys are never regenerated (ML-DSA keygen and signing draw randomness), so the
corpus never churns. If the public material file already exists it is left
untouched. Delete a file only to intentionally re-freeze. The gen script
(gen_pqc_mldsa_v0.py) consumes this frozen material; only public keys and
signatures over public messages ever ship.

CRITICAL: this MUST be FIPS-204 final ML-DSA-65, not round-3 Dilithium3 (see
oracle_pqc_mldsa.py). We assert the liboqs mechanism is "ML-DSA-65" and that the
reported key/signature lengths match the FIPS-204 constants before freezing.

Never ship the private key: only public_key_hex, wrong_public_key_hex, the
messages, and the signatures are written to the vectors file.

Run once (needs liboqs / the oqs package):  python tools/gen_pqc_mldsa_material_v0.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oracle_pqc_mldsa as O  # noqa: E402

REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "vectors", "pqc_mldsa_material_v0.json")
KEY_PATH = os.path.join(os.path.expanduser("~"), ".algovoi", "keys",
                        "pqc-mldsa-material-v0.json")

# Fixed messages, frozen once and signed. Deterministic bytes so the freeze is
# reproducible in shape (the signatures themselves are randomised by ML-DSA and
# frozen once). "primary" mirrors the DPoP-style payload used across the bridge.
MESSAGES = {
    "primary": b'{"iss":"did:web:algovoi.co.uk","sub":"agent-01","htm":"POST","htu":"https://api.example/resource"}',
    "empty": b"",
    "short": b"ML-DSA-65 FIPS-204 conformance anchor",
}

# Domain-separation adversarial material. Unlike the main controls (off-repo
# randomised signer), this is a DETERMINISTIC throwaway keypair derived from a
# fixed public seed with a separate FIPS-204 implementation (dilithium-py), so it
# regenerates byte-identically and needs no off-repo secret: it exists only to
# produce signatures crafted to be REJECTED (plus one positive control proving the
# key works), which carry no secrecy value. It proves FIPS-204 domain separation:
# a context-string signature and a HashML-DSA-65 (pre-hash) signature over the SAME
# key and message must NOT verify under pure, empty-context ML-DSA-65 -- exactly
# the confusion a lenient verifier (or a round-3 Dilithium port) would accept.
DOMAINSEP_SEED = bytes([0xA5]) * 48
DOMAINSEP_CTX = b"algovoi-rfc9421"


def freeze_domain_sep(primary_msg_hex: str) -> dict:
    """Deterministically derive the domain-separation material from a fixed seed and
    an independent FIPS-204 implementation (dilithium-py). Asserts, with liboqs
    (the oracle's implementation), that the pure control accepts and both the
    context-string and pre-hash signatures reject under pure empty-context verify,
    so the frozen material can only encode a genuine domain-separation split."""
    import oqs
    from dilithium_py.ml_dsa import ML_DSA_65, HASH_ML_DSA_65_WITH_SHA512 as H

    msg = bytes.fromhex(primary_msg_hex)
    ML_DSA_65.set_drbg_seed(DOMAINSEP_SEED)
    pk, sk = ML_DSA_65.keygen()
    pure = ML_DSA_65.sign(sk, msg, deterministic=True)
    context = ML_DSA_65.sign(sk, msg, ctx=DOMAINSEP_CTX, deterministic=True)
    try:
        prehash = H.sign(sk, msg, deterministic=True)
    except TypeError:  # older dilithium-py without the deterministic kwarg on HashML-DSA
        prehash = H.sign(sk, msg)

    if len(pk) != O.PK_LEN or any(len(s) != O.SIG_LEN for s in (pure, context, prehash)):
        raise SystemExit("domain-sep material has a non-FIPS-204 length")
    with oqs.Signature(O.MECHANISM) as v:  # cross-check against the oracle's implementation
        if not v.verify(msg, pure, pk):
            raise SystemExit("domain-sep pure control does not verify (bad key/material)")
        if v.verify(msg, context, pk) or v.verify(msg, prehash, pk):
            raise SystemExit("domain-sep negative unexpectedly verifies under pure ML-DSA-65")

    return {
        "note": ("Deterministic throwaway negative-vector key (fixed public seed), "
                 "distinct from the off-repo main signer, no secrecy value. Proves "
                 "FIPS-204 domain separation: the pure control accepts; the "
                 "context-string and HashML-DSA-65 signatures over the SAME key and "
                 "message reject under pure empty-context ML-DSA-65 verify."),
        "seed_hex": DOMAINSEP_SEED.hex(),
        "context_label": DOMAINSEP_CTX.decode("ascii"),
        "public_key_hex": pk.hex(),
        "signatures": {"pure": pure.hex(), "context": context.hex(), "prehash": prehash.hex()},
    }


def load_or_create_keys():
    """Return (public_key, secret_key, wrong_public_key, created). The secret key
    is loaded from / persisted to the off-repo key file and never returned to the
    shipped material."""
    import oqs

    if os.path.exists(KEY_PATH):
        d = json.load(open(KEY_PATH, encoding="utf-8"))
        pk = bytes.fromhex(d["public_key_hex"])
        sk = bytes.fromhex(d["secret_key_hex"])
        wrong_pk = bytes.fromhex(d["wrong_public_key_hex"])
        return pk, sk, wrong_pk, False

    with oqs.Signature(O.MECHANISM) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    with oqs.Signature(O.MECHANISM) as wrong_signer:
        wrong_pk = wrong_signer.generate_keypair()

    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({
            "mechanism": O.MECHANISM,
            "spec": O.SPEC,
            "public_key_hex": pk.hex(),
            "secret_key_hex": sk.hex(),
            "wrong_public_key_hex": wrong_pk.hex(),
            "seed": None,
            "note": ("SECRET pqc_mldsa_v0 material. liboqs ML-DSA-65 keygen does not "
                     "expose a standalone FIPS-204 keygen seed via the python API; the "
                     "secret_key_hex IS the private material. Never commit."),
        }, fh, indent=2)
        fh.write("\n")
    return pk, sk, wrong_pk, True


def sign_messages(sk: bytes) -> dict:
    """Sign every fixed message with the (off-repo) secret key held internally by a
    liboqs ML-DSA-65 signer. Returns {name: signature_hex}."""
    import oqs

    sigs = {}
    with oqs.Signature(O.MECHANISM, secret_key=sk) as signer:
        for name, msg in MESSAGES.items():
            sigs[name] = signer.sign(msg).hex()
    return sigs


def _assert_fips204(pk: bytes, sig_hex: dict) -> None:
    """Fail loudly if liboqs is not the FIPS-204 ML-DSA-65 build we require."""
    import oqs

    enabled = oqs.get_enabled_sig_mechanisms()
    if O.MECHANISM not in enabled:
        raise SystemExit(
            f"liboqs does not expose {O.MECHANISM!r} (this is the wrong/old build; "
            f"a build offering only 'Dilithium3' is round-3, NOT FIPS-204 ML-DSA).")
    details = oqs.Signature(O.MECHANISM).details
    got_pk, got_sig = details["length_public_key"], details["length_signature"]
    if got_pk != O.PK_LEN or len(pk) != O.PK_LEN:
        raise SystemExit(f"public-key length {got_pk}/{len(pk)} != FIPS-204 {O.PK_LEN}")
    if got_sig != O.SIG_LEN:
        raise SystemExit(f"signature length {got_sig} != FIPS-204 {O.SIG_LEN}")
    for name, h in sig_hex.items():
        if len(bytes.fromhex(h)) != O.SIG_LEN:
            raise SystemExit(f"frozen signature {name!r} length != FIPS-204 {O.SIG_LEN}")


def main() -> int:
    if os.path.exists(OUT):
        # The main frozen material (off-repo randomised signer) is preserved
        # exactly; only the deterministic domain-separation material is added if a
        # prior freeze predates it. Nothing that needs the off-repo key is touched.
        material = json.load(open(OUT, encoding="utf-8"))
        if "domain_separation" not in material:
            material["domain_separation"] = freeze_domain_sep(material["messages"]["primary"])
            with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(material, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            print("augmented frozen material with deterministic domain-separation vectors:", OUT)
        else:
            print("frozen material already complete, leaving untouched:", OUT)
        return 0

    pk, sk, wrong_pk, created = load_or_create_keys()
    signatures = sign_messages(sk)
    _assert_fips204(pk, signatures)

    material = {
        "note": ("Frozen pqc_mldsa_v0 material. Public ML-DSA-65 keys + messages + "
                 "signatures only; the private key is off-repo. FIPS 204 final, NOT "
                 "round-3 Dilithium."),
        "mechanism": O.MECHANISM,
        "spec": O.SPEC,
        "lengths": {"public_key": O.PK_LEN, "signature": O.SIG_LEN, "secret_key": O.SK_LEN},
        "public_key_hex": pk.hex(),
        "wrong_public_key_hex": wrong_pk.hex(),
        "messages": {name: msg.hex() for name, msg in MESSAGES.items()},
        "message_text_preview": {name: (msg.decode("utf-8", "replace") if msg else "")
                                 for name, msg in MESSAGES.items()},
        "signatures": signatures,
        "domain_separation": freeze_domain_sep(MESSAGES["primary"].hex()),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(material, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print("froze pqc_mldsa material ->", OUT)
    print(f"  {O.MECHANISM} (FIPS-204) public key {len(pk)}B, "
          f"{len(signatures)} signatures over fixed messages")
    print("  private key", "created" if created else "loaded", "off-repo at", KEY_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
