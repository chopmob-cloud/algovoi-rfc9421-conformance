# algovoi-rfc9421-conformance

A signed, cross-language conformance battery for RFC 9421 HTTP Message
Signatures. **Ten independent implementations, one frozen signed corpus,
byte-identical verdicts:** reject every negative, accept every positive control.

Ten languages: **python, typescript, go, rust, java, kotlin, dotnet, ruby, php,
elixir**. The python/typescript/go/rust runners drive the published AlgoVoi
verifiers; the other six are self-contained ports of the same verdict surface,
each backed by that language's own crypto stack. Consensus is the property a
two-implementation corpus cannot express: not "the reference agrees with one
recompute" but "ten distinct stacks agree, per case, on the exact bytes".

## What is here

```
corpus/
  rfc9421_negative_v1/   frozen CORE battery, 78 cases, 6 sections (signed + shipped)
  rfc9421_negative_v2/   strict superset, 89 cases (v1 + fail-closed signing-base and
                         Ed25519/ECDSA range negatives found by security review)
    *.json               the battery
    *.manifest.json      signed corpus head (JCS + EdDSA compact JWS)
    *.provenance.json    hash-chained provenance log
    kat_anchors_v1.json  independent, no-library known-answer anchors
runners/{python,typescript,go,rust,java,kotlin,dotnet,ruby,php,elixir}/
tools/
  run_consensus.sh       N-way consensus gate (fail-closed --require)
  check_kat.py           KAT integrity gate (signed-head signature + anchors)
  mutation_test.sh       proves the gate is not vacuous
  gen_negative_v1/v2.py  regenerate the corpus from the reference
  sign_negative_v1/v2.py  sign + version via algovoi-corpus-cm
kaf/                     hermetic runtime cells + EdDSA sealed assurance receipt
LICENSE  NOTICE  CONTRIBUTING.md
```

## The six sections

`signing_base` (exact bytes, both modes, **plus fail-closed error paths in v2**),
`signature_input_parse` (malformed rejected), `signature_value_parse`
(non-canonical / malformed base64 rejected), `keygate` (small-order /
non-canonical Ed25519 keys rejected), `ed25519_verify` (tamper + byte-level
malleability incl. non-canonical S, and S=0 in v2), `ecdsa_verify` (P-256 / P-384
tamper, off-curve, r/s range incl. s=0 and the r=n/s=n upper bound in v2, wrong
width, high-s under strict-low-s).

Every verdict is computed from the reference implementation, never hand-asserted.

## The assurance stack

Four axes, each a runnable gate that fails closed:

1. **Agreement** — `tools/run_consensus.sh --require 10` runs all ten runners
   against the one corpus; because the frozen corpus is the shared oracle,
   all-pass = all ten agree byte-for-byte. A missing toolchain shrinks N below
   `--require` and fails closed; any disagreeing runner fails the gate.
2. **KAT** — `tools/check_kat.py` verifies the corpus is the exact signed
   artifact: the **head_jws EdDSA signature** under the signer's JWK (not just a
   digest compare, so a re-digested tampered manifest still fails), and that the
   signing bases match anchors hand-derived from the RFC without the reference
   code (catching a systematic error shared by the generator and every runner).
   It runs as a fail-closed pre-gate inside `run_consensus.sh`.
3. **Cells** — `kaf/run_cells.sh` re-runs each runner inside its pinned Docker
   image, so the verdicts are shown to hold in ten clean, independent runtimes.
4. **Seal** — `kaf/seal_receipt.py` binds the three above into one EdDSA-signed,
   re-verifiable receipt (`kaf/kaf_verify.py`); the seal secret is off-repo.

`tools/mutation_test.sh` flips one expected verdict per section and requires the
consensus to go red each time — proving the runners compute verdicts rather than
echo the corpus (no fail-open runner).

## Running

```bash
# the whole gate in one command (KAT -> 10-way consensus, fail-closed)
bash tools/run_consensus.sh --require 10

# a single runner (each exits 0 iff every case matches):
python runners/python/verify_py.py            # pip install -r runners/python/requirements.txt
node   runners/typescript/verify_ts.mjs       # cd runners/typescript && npm install
# go / rust are vendored as in-tree tests in the verifier repos; point them at
# the corpus with ALGOVOI_NEGATIVE_V1. java/kotlin/dotnet/ruby/php/elixir are
# self-contained under runners/<lang>/.
```

Set `ALGOVOI_NEGATIVE_V1` (or pass a path) to run any runner or gate against a
corpus at another path — e.g. the v2 superset.

## Adding a language

A runner is a self-contained probe: read the corpus JSON, and for every case
reproduce the reference verdict across all six sections — signing-base
construction (both `algovoi-v0` and `rfc9421` modes; **attempt the build even for
negative cases so a build that must fail is actually exercised**), `Signature-Input`
and `Signature` structured-field parsing with base64-canonicality rejection, the
Ed25519 small-order / non-canonical key gate (RFC 8032 Appendix A arithmetic in
the language's big-integer type), Ed25519 verify with canonical-S (`S < L`)
malleability rejection, and ECDSA P-256/P-384 over a raw `r||s` signature with
explicit `[1,n-1]` range, fixed-width, on-curve and strict-low-s checks. Exit 0
iff every case matches. Candidate next stacks: **C** (OpenSSL + a bignum lib),
**Scala/Clojure** (JVM, reuse the java approach), **Swift** (CryptoKit/Sodium).
Add the runner to `tools/run_consensus.sh` and a pinned image to `kaf/cells.json`;
it must pass the mutation test, which will catch a fail-open or echoing port.

## Signing and verification

The corpus head is canonicalised (RFC 8785 JCS), EdDSA-signed (compact JWS) and
recorded in a hash-chained provenance log by
[algovoi-corpus-cm](https://github.com/chopmob-cloud/algovoi-corpus-cm). The
manifest carries only the public JWK; the signing key is a genuine secret held
off-repo. `tools/check_kat.py` verifies the signature at runtime;
`tools/validate_independent.py` is an independent oracle over different crypto
libraries.

## License

Apache-2.0. See `LICENSE` and `NOTICE`. Contributions require a DCO sign-off
(`git commit -s`); see `CONTRIBUTING.md`.
