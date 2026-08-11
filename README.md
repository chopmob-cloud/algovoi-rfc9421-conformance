# algovoi-rfc9421-conformance

A signed, cross-language conformance battery for RFC 9421 HTTP Message
Signatures as implemented by the four AlgoVoi verifiers (Python, TypeScript,
Rust, Go). One frozen corpus, four independent runners, byte-identical verdicts:
reject every negative, accept every positive control.

## What is here

```
corpus/rfc9421_negative_v1/
  rfc9421_negative_v1.json            frozen battery, 78 cases across 6 sections
  rfc9421_negative_v1.manifest.json   signed corpus head (JCS + EdDSA compact JWS)
  rfc9421_negative_v1.provenance.json hash-chained provenance log
  README.md                           the corpus schema
vectors/                              frozen reference vectors (reproducibility inputs)
tools/                                gen (regenerate) / sign / validate_independent
runners/{python,typescript,go,rust}/  one runner per language
LICENSE  NOTICE  CONTRIBUTING.md
```

## The six sections

`signing_base` (exact bytes, both modes), `signature_input_parse` (malformed
rejected), `signature_value_parse` (non-canonical / malformed base64 rejected),
`keygate` (small-order / non-canonical Ed25519 keys rejected), `ed25519_verify`
(tamper + byte-level malleability incl. non-canonical S), `ecdsa_verify` (P-256 /
P-384 tamper, off-curve, r/s range, wrong width, high-s under strict-low-s).

Every verdict is computed from the reference implementation, never hand-asserted.

## Running

Each runner exits 0 iff all cases match; 4-way parity means all four agree per case.

```bash
# Python  (pip install -r runners/python/requirements.txt)
python runners/python/verify_py.py

# TypeScript  (cd runners/typescript && npm install)
node runners/typescript/verify_ts.mjs

# Go / Rust runners are also vendored as in-tree conformance tests in the
# verifier repos so they compile against the module/crate; point them at the
# corpus with ALGOVOI_NEGATIVE_V1.
```

Set `ALGOVOI_NEGATIVE_V1` to run any runner against a corpus at another path.

## Signing and verification

The corpus head is canonicalised (RFC 8785 JCS), signed EdDSA (compact JWS) and
recorded in a hash-chained provenance log by
[algovoi-corpus-cm](https://github.com/chopmob-cloud/algovoi-corpus-cm). The
manifest carries only the public JWK; the signing key is held off-repo. Verify:

```bash
python tools/validate_independent.py    # independent oracle, different crypto libs
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`. Contributions require a DCO sign-off
(`git commit -s`); see `CONTRIBUTING.md`.
