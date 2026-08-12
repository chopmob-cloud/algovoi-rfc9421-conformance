# rfc9421_negative_v1

Signed, cross-language CORE conformance battery for RFC 9421 HTTP Message
Signatures. Every one of the eleven independent runners (python, typescript, go,
rust, c, java, kotlin, dotnet, ruby, php, elixir) consumes this one JSON corpus and
must produce byte-identical verdicts: reject every negative, accept every
positive control. The strict superset `rfc9421_negative_v2` adds the fail-closed
signing-base error paths and additional Ed25519/ECDSA range negatives.

This is the CORE layer only. It exercises the primitive surface all the
verifiers share (proven byte-for-byte by `reference_vectors_v0.json` and
`reference_ecdsa_v0.json`):

1. `build_signing_base` (modes `algovoi-v0` and `rfc9421`) produces exact bytes.
2. `parse Signature-Input` accepts well-formed, rejects malformed.
3. `parse Signature value` accepts canonical base64, rejects non-canonical
   (base64 malleability) and wrong-length byte sequences.
4. key gate rejects small-order / non-canonical Ed25519 public keys fail-closed.
5. Ed25519 verify returns valid/invalid, including byte-level malleability.
6. ECDSA verify (P-256 `ecdsa-p256-sha256`, P-384 `ecdsa-p384-sha384`) returns
   valid/invalid, including off-curve keys, r/s out of range, wrong width, and
   high-s under strict-low-s.

A2A application-layer negatives (extension activation, tag context, nonce
replay) are NOT here. They are Python-only and live in
`algovoi-rfc9421-a2a/vectors/` (relabelled `a2a_negative`).

Out of scope, by roadmap: kenneives/aeoess taxonomy, key_origin_proof,
cache_parent_ref. Signer ports and PQC are later phases.

## Corpus format

One file, `rfc9421_negative_v1.json`, six sections. Every case is fully formed
(pre-computed inputs, not "apply this mutation") so each language feeds bytes to
the verifier and checks a verdict. Deterministic and reproducible; no
runtime timestamps (freshness cases carry explicit created/now).

```
{
  "name": "rfc9421_negative_v1",
  "description": "...",
  "signing_base":   [ { "in": {...}, "mode": "...", "ok": bool,
                        "signing_base_b64": "...", "signature_params_raw": "...",
                        "note": "..." } ],
  "signature_input_parse": [ { "header": "...", "ok": bool, "note": "..." } ],
  "signature_value_parse": [ { "header": "...", "ok": bool, "note": "..." } ],
  "keygate":        [ { "pk_hex": "...", "small_order": bool,
                        "rejected": "WeakKeyError"|null, "note": "..." } ],
  "ed25519_verify": [ { "signing_base_b64": "...", "sig_hex": "...",
                        "pk_hex": "...", "expect_valid": bool, "note": "..." } ],
  "ecdsa_verify":   [ { "curve": "p256"|"p384", "msg_hex": "...",
                        "pub_uncompressed_hex": "...", "sig_raw_hex": "...",
                        "expect_valid": bool, "note": "..." } ]
}
```

`signing_base_b64` is standard base64 of the UTF-8 signing base string.
Integer `parameters` (created/expires) MUST be decoded as exact integers, never
floats (Go: `dec.UseNumber()`; JS: keep as string then to number carefully;
Rust: serde_json arbitrary precision). ECDSA signatures are raw big-endian
`r||s` (64 bytes P-256, 96 bytes P-384), NOT DER. Ed25519/ECDSA public keys are
hex; ECDSA keys are SEC1 uncompressed (`04...`).

## What each section asserts

- signing_base: for `ok:true`, the built base equals `signing_base_b64` exactly.
  Carries every positive from v0 plus adversarial-but-deterministic
  canonicalisation inputs (authority lowercasing, header OWS trimming,
  `@signature-params` SF serialisation).
- signature_input_parse: malformed Signature-Input must fail closed (return an
  error), never panic/throw.
- signature_value_parse: non-canonical base64 (non-zero pad bits), wrong length,
  and non-colon-wrapped forms must be rejected.
- keygate: `rejected` is `"WeakKeyError"` iff the key must be refused; the six
  valid keys accept, the small-order/non-canonical set rejects.
- ed25519_verify: `expect_valid` is the verdict for (base, sig, pk). Includes
  tampered base, wrong key, and byte-level malleability (non-canonical S,
  wrong-length signature, all-zero signature).
- ecdsa_verify: `expect_valid` verdict for (msg, pub, sig). Includes the frozen
  valid/tampered pairs plus off-curve pubkey, r or s out of [1,n-1], wrong fixed
  width, and high-s with strict-low-s ON.

## Signing (Phase 4 A4)

The frozen `rfc9421_negative_v1.json` is admitted and signed through
`algovoi-corpus-cm` (JCS canonicalisation, EdDSA, KeyProvider; local dev key
today, foundation/KMS later with no code change). The shipped artifact is the
signed corpus plus its hash-chained provenance, not a bare JSON.

## Runners

Ten independent runners; run them all through the fail-closed consensus gate with
`bash tools/run_consensus.sh --require 10` (see the root README for the full
assurance stack: KAT, hermetic cells, sealed receipt, mutation test).

- Python: `runners/python/verify_py.py`
- TypeScript: `runners/typescript/verify_ts.mjs`
- Rust: integration test in `algovoi-rfc9421-verifier-rs`
- Go: `_test.go` in `algovoi-rfc9421-verifier-go`, env override `ALGOVOI_NEGATIVE_V1`
- C / Java / Kotlin / .NET / Ruby / PHP / Elixir: self-contained under `runners/<lang>/`

Each exits 0 iff every case matches. N-way parity = all eleven agree per case.

Each exits 0 iff every case matches. 4-way parity = all four agree per case.
