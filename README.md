> **AlgoVoi is available for acquisition** - [docs.algovoi.co.uk/acquisition](https://docs.algovoi.co.uk/acquisition)

---

# algovoi-rfc9421-conformance

[![12-way consensus](https://github.com/chopmob-cloud/algovoi-rfc9421-conformance/actions/workflows/consensus.yml/badge.svg)](https://github.com/chopmob-cloud/algovoi-rfc9421-conformance/actions/workflows/consensus.yml)
[![RFC 9421](./assets/badges/rfc9421.svg)](https://www.rfc-editor.org/rfc/rfc9421.html)
[![Cross-validated](./assets/badges/languages.svg)](#cross-implementation-validation-matrix)
[![Cases](./assets/badges/cases.svg)](#the-seven-sections)
[![Algorithms](./assets/badges/algorithms.svg)](#cross-implementation-validation-matrix)
[![Apache 2.0](./assets/badges/license.svg)](./LICENSE)

A signed, cross-language conformance battery for RFC 9421 HTTP Message
Signatures. **12-way byte-for-byte consensus:** twelve independent
implementations, in twelve programming languages, each consuming one frozen,
signed corpus and producing byte-identical verdicts, per case: reject every
negative, accept every positive control. This is the property a
two-implementation corpus (reference plus one recompute) cannot express, and the
one that matters, because a verdict only carries assurance when genuinely
independent implementations concur on it. The suite is algorithm-pluggable — it covers Ed25519, ECDSA P-256/P-384 and RSA (PSS + PKCS#1 v1.5), validating the crypto-native and the RSA-dominant regulated worlds alike.

Three batteries, each a signed strict superset of the last: **`rfc9421_negative_v1`**
(78 cases, the frozen CORE layer), **`rfc9421_negative_v2`** (89 cases; adds the
fail-closed signing-base error paths and Ed25519/ECDSA range negatives from
security review), and **`rfc9421_negative_v3`** (96 cases, the default; adds the
`rsa_verify` section for rsa-pss-sha512 and rsa-v1_5-sha256). Every verdict is
computed from the reference implementation and frozen; authoritative counts live
in each corpus's signed `manifest.json`.

Twelve languages: **python, typescript, go, rust, c, java, kotlin, scala,
dotnet, ruby, php, elixir**. The python/typescript/go/rust runners drive the published AlgoVoi
verifiers; the other eight are self-contained ports of the same verdict surface,
each backed by that language's own crypto stack.

## The battery

```
corpus/
  rfc9421_negative_v1/   frozen CORE battery, 78 cases, 6 sections (signed)
  rfc9421_negative_v2/   strict superset, 89 cases (signing-base + ecdsa/ed25519 edges)
  rfc9421_negative_v3/   strict superset, 96 cases, 7 sections (default corpus; adds rsa_verify)
    *.json               the battery
    *.manifest.json      signed corpus head (JCS + EdDSA compact JWS)
    *.provenance.json    hash-chained provenance log
    kat_anchors_v1.json  independent, no-library known-answer anchors
runners/{python,typescript,go,rust,c,java,kotlin,scala,dotnet,ruby,php,elixir}/
tools/
  run_consensus.sh       N-way consensus gate (fail-closed --require)
  check_kat.py           KAT integrity gate (signed-head signature + anchors)
  mutation_test.sh       proves the gate is not vacuous
  gen_negative_v1/v2/v3.py   regenerate the corpus from the reference
  sign_negative_v1/v2/v3.py  sign + version via algovoi-corpus-cm
kaf/                     hermetic runtime cells + EdDSA sealed assurance receipt
assets/  LICENSE  NOTICE  CONTRIBUTING.md
```

## The seven sections

| Section | What it exercises |
|---|---|
| `signing_base` | exact signing-base bytes, both `algovoi-v0` and `rfc9421` modes; **v2** adds the fail-closed error paths (missing @-component / header / `created`, unsupported derived component) |
| `signature_input_parse` | well-formed accepted, malformed rejected (fail-closed) |
| `signature_value_parse` | canonical base64 accepted; non-canonical (non-zero pad bits), wrong length, non-colon-wrapped rejected |
| `keygate` | small-order / non-canonical Ed25519 public keys rejected fail-closed |
| `ed25519_verify` | tamper + byte-level malleability (non-canonical S, wrong length, all-zero); **v2** adds S = 0 |
| `ecdsa_verify` | P-256 / P-384 tamper, off-curve, r/s range, wrong width, high-s under strict-low-s; **v2** adds s = 0 and the r = n / s = n upper bound |
| `rsa_verify` | **v3**: `rsa-pss-sha512` and `rsa-v1_5-sha256` verify (SPKI key) — valid control, tampered base, tampered signature, wrong key |

Every verdict is computed from the reference implementation, never hand-asserted.

## The assurance stack

Four axes, each a runnable gate that fails closed:

1. **Agreement** - `tools/run_consensus.sh --require 12` runs all twelve runners
   against the one corpus; because the frozen corpus is the shared oracle,
   all-pass = all twelve agree byte-for-byte. A missing toolchain shrinks N below
   `--require` and fails closed; any disagreeing runner fails the gate.
2. **KAT** - `tools/check_kat.py` verifies the corpus is the exact signed
   artifact: the **head_jws EdDSA signature** under the signer's JWK (not just a
   digest compare, so a re-digested tampered manifest still fails), and that the
   signing bases match anchors hand-derived from the RFC without the reference
   code (catching a systematic error shared by the generator and every runner).
   It runs as a fail-closed pre-gate inside `run_consensus.sh`.
3. **Cells** - `kaf/run_cells.sh` re-runs each runner inside its pinned Docker
   image, so the verdicts are shown to hold in twelve clean, independent runtimes.
4. **Seal** - `kaf/seal_receipt.py` binds the three above into one EdDSA-signed,
   re-verifiable receipt (`kaf/kaf_verify.py`); the seal secret is held off-repo.

`tools/mutation_test.sh` flips one expected verdict per section and requires the
consensus to go red each time - proving the runners compute verdicts rather than
echo the corpus (no fail-open runner).

## Running

```bash
# the whole gate in one command (KAT -> 12-way consensus, fail-closed)
bash tools/run_consensus.sh --require 12
```

Set `ALGOVOI_NEGATIVE_V1` (or pass a path) to run any runner or gate against a
specific corpus; the default is the v3 superset. Individual runners live under
`runners/<lang>/` and each exits 0 iff every case matches.

## Cross-implementation validation matrix

Twelve independent implementations, each with its own crypto backend, reproduce
every case byte-for-byte (v1 78/78, v2 89/89, v3 96/96):

| Language | Runner | Ed25519 + key gate | ECDSA P-256/P-384 | RSA (PSS / PKCS1) |
|---|---|---|---|---|
| Python | published `algovoi-rfc9421-verifier` | PyNaCl / libsodium | `cryptography` | `cryptography` |
| TypeScript | published `@algovoi/rfc9421-verifier` | `@noble/ed25519` | `@noble/curves` | `node:crypto` |
| Go | `algovoi-rfc9421-verifier-go` (in-tree test) | Go stdlib `crypto/ed25519` | Go stdlib `crypto/ecdsa` | Go stdlib `crypto/rsa` |
| Rust | `algovoi-rfc9421-verifier-rs` (in-tree test) | `ed25519-dalek` | RustCrypto `p256`/`p384` | RustCrypto `rsa` |
| C | self-contained | OpenSSL EVP + BIGNUM key gate | OpenSSL EC | OpenSSL EVP |
| Java | self-contained | Bouncy Castle | JDK `java.security` | JDK `RSASSA-PSS` |
| Kotlin | self-contained | Bouncy Castle | JDK `java.security` | JDK `RSASSA-PSS` |
| Scala | self-contained | Bouncy Castle | JDK `java.security` | JDK `RSASSA-PSS` |
| .NET | self-contained | Bouncy Castle | `System.Security.Cryptography` | `RSA` (Pss/Pkcs1) |
| Ruby | self-contained | OpenSSL (SPKI-DER) | OpenSSL | OpenSSL `verify_pss` |
| PHP | self-contained | ext-sodium + ext-gmp | OpenSSL | OpenSSL + manual EMSA-PSS |
| Elixir | self-contained | Erlang `:crypto` | Erlang `:crypto` | Erlang `:crypto` |

The small-order / non-canonical Ed25519 key gate is ported into each
self-contained runner directly from RFC 8032 Appendix A arithmetic in that
language's big-integer type, so its correctness is validated by the same
byte-for-byte consensus, not assumed.

## Cell / KAF: hermetic runs, sealed offline

Each runner is re-run inside its pinned Docker image (`kaf/cells.json`), building
or installing deps fresh in-container, so the byte-for-byte verdict is shown to
hold in twelve clean, independent runtimes rather than only on the build host.
The per-cell image digests and the consensus are bound into one EdDSA-signed,
re-verifiable receipt (`kaf/receipts/`), which refuses to attest a partial or
unverified run. See [`kaf/README.md`](./kaf/README.md).

## Comparison with the JCS conformance corpus

This corpus and [algovoi-jcs-conformance-vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors)
are complementary layers of the same deterministic-interop vertical, built to the
same assurance discipline. JCS is **L1** - the RFC 8785 canonicalisation that a
signing base and a receipt are canonicalised with; this repo is **L2** - the RFC
9421 HTTP-signature verdict over those bytes. Beneath both sits **L0**, [algovoi-keyhygiene-conformance](https://github.com/chopmob-cloud/algovoi-keyhygiene-conformance), the RSA/EC key-hygiene and primality soundness floor (is the key or prime sound at all, before you sign with it). The three read: is the key sound (L0) → canonicalise (L1) → sign → verify (L2).

| | [JCS conformance vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors) (L1) | rfc9421-conformance (L2, this repo) |
|---|---|---|
| Standard | RFC 8785 (JCS) canonicalisation | RFC 9421 (+ RFC 9530) HTTP Message Signatures |
| What a case tests | the canonical bytes / hash of a JSON value | the accept/reject verdict over signing-base bytes + keys |
| Independent implementations | 10 languages, 10 distinct JCS libraries | **12 languages**, per-language crypto stacks |
| Consensus property | N-way agreement on the canonical hash + a divergence hazard map | N-way agreement on the crypto verdict |
| Corpus | 374 vectors across 45 anchor sets | 78 / 89 / 96 cases (v1/v2/v3) across 7 sections |
| Adversarial focus | Unicode / number-form / duplicate-key canonicalisation hazards | signature malleability, small-order keys, ECDSA range / off-curve |
| Algorithm coverage | one primitive (JCS) | **Ed25519 · ECDSA P-256/P-384 · RSA-PSS · RSA-PKCS1** (algorithm-pluggable) |
| Assurance axes (KAF) | Agreement · Strata · Cells · Seal | Agreement · KAT · Cells · Seal |
| Hermetic cells + signed receipt | yes | yes |

The vector counts differ by design: canonicalisation has a broad input space
(strata sampled into many vectors), while the signature surface is a small, sharp
set of primitives where the value is N-way agreement on each verdict, not count.
Together the two corpora cover canonicalise → sign → verify end to end. And where JCS is one narrow primitive, RFC 9421 signatures are a general request/response authenticity primitive: adding algorithm families (RSA joined Ed25519/ECDSA in v3) is how this repo grows past payment rails into the RSA-dominant regulated industries — open banking, eIDAS/government, healthcare — without changing the assurance machinery.

## Profile: Web Bot Auth (`webbotauth_v0`)

The same machinery instantiates a named industry profile. **Web Bot Auth**
(`draft-meunier-web-bot-auth-architecture` plus the HTTP Message Signatures
directory draft) is how an automated agent authenticates itself to an origin: it
signs its HTTP request with **Ed25519** under RFC 9421, carrying a
`Signature-Agent` header (a URL to a directory of the agent's public keys), the
`tag="web-bot-auth"` label, and `created`/`expires` bounds. The origin resolves
the key from that directory by `keyid`, enforces freshness, and checks that the
security-critical components are actually covered. This is the emerging standard
for agentic-web traffic (Cloudflare, IETF), and it sits directly on AlgoVoi's
agent-trust substrate.

A valid signature is not enough: the profile is where the *enforcement semantics*
live, and the battery tests exactly those.

| Section | Each case | Verdict |
|---|---|---|
| `wba_signing_base` | a web-bot-auth request (`@authority`, `@method`, `signature-agent` covered; `created`/`expires`/`keyid`/`tag`) | the exact RFC 9421 Section 2.5 signing base, byte-for-byte |
| `wba_coverage` | a set of covered components | are the required components (`@authority`, `signature-agent`) all covered? |
| `wba_freshness` | `created`, `expires`, and a per-case `now` | is the signature inside its validity window? |
| `wba_directory` | a JWKS directory plus a `keyid` | does the keyid resolve to a usable Ed25519 key? |
| `wba_directory_ssrf` | a `Signature-Agent` URL (plus an optional resolved address) | may the directory be fetched, or is it an SSRF target? |
| `wba_ed25519_verify` | a signing base, signature and key | the Ed25519 verdict over the profile signing base |

The adversarial focus is the profile's real failure modes: **covered-component
downgrade** (a valid signature that omits `@authority` or `signature-agent`, so it
replays cross-origin or swaps the vouching directory), **replay** (an expired or
not-yet-valid window), **wrong-algorithm keys** in the directory, and
**Signature-Agent SSRF** (a directory URL pointing at loopback, RFC 1918, the
`169.254.169.254` cloud-metadata address, IPv6 `::1`, a userinfo-bearing URL, or an
unresolved host, all of which must be refused and never fetched). Freshness is
decided against a per-case `now` and the directory bytes are carried in the
corpus, so the battery is fully deterministic (no clock, no network) and the SSRF
verdict is a pure denied-CIDR membership test that every language computes
identically.

Determinism and assurance match the negative battery: the corpus is JCS+EdDSA
signed (`webbotauth_v0`), `tools/check_kat_wba.py` re-derives every verdict
independently (hand-built signing base, `cryptography` Ed25519, first-principles
profile rules), `tools/run_consensus_wba.sh --require 12` runs the twelve runners
fail-closed, and `kaf/run_cells_wba.sh` re-runs each in its pinned Docker image.
Latest sealed run (`kaf/receipts/webbotauth_v0.seq1.receipt.json`) binds **full
12-way byte-for-byte consensus over 31 cases, 12/12 hermetic cells PASS**, under
the same KAF seal identity as the negative-battery receipts.

Where the negative battery asks "is this one signature valid?", the Web Bot Auth
profile asks "does the verifier enforce the deployment rules?", which is what a
real origin accepting agent traffic has to get right.

## Profile: FAPI 2.0 Message Signing (`fapi_messagesigning_v0`)

A second named industry profile on the same machinery. **FAPI 2.0 Message
Signing** (OpenID Foundation, financial-grade API) uses RFC 9421 for
non-repudiation of high-value API calls (UK Open Banking, Berlin Group NextGenPSD2,
FDX). It is stricter than a merely-valid signature: only **PS256** (RSA-PSS
SHA-256) and **ES256** (ECDSA P-256) are allowed; the signature MUST cover a
mandated set of components so the access token and the body are bound (request:
`@method`, `@target-uri`, `authorization`, `content-digest`; response: `@status`,
`content-digest`); and when a message has a body a **Content-Digest (RFC 9530)**
MUST be present, covered, and match the body.

| Section | Each case | Verdict |
|---|---|---|
| `fapi_signing_base` | a FAPI request/response with the mandated covered components | the exact RFC 9421 Section 2.5 signing base, byte-for-byte |
| `fapi_required_coverage` | a message type plus a set of covered components | are all the mandated components covered? |
| `fapi_content_digest` | a body plus a `Content-Digest` header | does the digest match the body, cover it, and use an allowed hash? |
| `fapi_alg` | a signature algorithm label | is it one of the FAPI-allowed PS256 / ES256? |
| `fapi_ps256_verify` | a signing base, signature and RSA key | the RSA-PSS SHA-256 verdict |
| `fapi_es256_verify` | a signing base, signature and EC key | the ECDSA P-256 verdict, with the high-s malleable twin rejected |

The adversarial focus is the profile's real failure modes: **coverage downgrade**
(a valid signature that omits `authorization`, so the token is unbound, or
`content-digest`, so the body is unbound), **body-swap** (a Content-Digest that
does not match the body, or is present but not covered, or uses a weak hash like
md5), **algorithm downgrade** (RS256 / HS256 / `none` where only PS256 and ES256
are allowed), and **ECDSA malleability** (the high-s twin of a valid ES256
signature, rejected under a strict low-s rule). All keys are fixed test material,
signatures are frozen once (`vectors/fapi_material_v0.json`, public keys and
signatures only, the RSA and EC private keys held off-repo), and bodies are
carried in the corpus, so the battery is fully deterministic.

Assurance matches the other batteries: the corpus is JCS+EdDSA signed
(`fapi_messagesigning_v0`), `tools/check_kat_fapi.py` re-derives every verdict
independently (hand-built signing base, first-principles profile rules, PS256 and
ES256 re-verified with the low-s check re-derived), `tools/run_consensus_fapi.sh
--require 12` runs the twelve runners fail-closed, and `kaf/run_cells_fapi.sh`
re-runs each in its pinned Docker image. Latest sealed run
(`kaf/receipts/fapi_messagesigning_v0.seq1.receipt.json`) binds **full 12-way
byte-for-byte consensus over 27 cases, 12/12 hermetic cells PASS**, under the same
KAF seal identity as the negative-battery and Web Bot Auth receipts.

Where Web Bot Auth secures agentic-web traffic, FAPI 2.0 secures the RSA/ECDSA
financial-grade world, so the two profiles reach the two industries RFC 9421
signatures matter most in today, on one shared, signed assurance substrate.

## Adding a language

A runner is a self-contained probe: read the corpus JSON, and for every case
reproduce the reference verdict across all seven sections - signing-base
construction (both modes; **attempt the build even for negative cases** so a
build that must fail is actually exercised), `Signature-Input` and `Signature`
structured-field parsing with base64-canonicality rejection, the Ed25519
small-order / non-canonical key gate (RFC 8032 Appendix A arithmetic in the
language's big-integer type), Ed25519 verify with canonical-S (`S < L`)
malleability rejection, ECDSA P-256/P-384 over a raw `r||s` signature with explicit `[1,n-1]` range,
fixed-width, on-curve and strict-low-s checks, and (v3) RSA-PSS-SHA512 /
RSA-PKCS1v1.5-SHA256 verify from an SPKI key. Exit 0
iff every case matches. Add the runner to `tools/run_consensus.sh` and a pinned
image to `kaf/cells.json`; it must pass the mutation test, which will catch a
fail-open or echoing port. Candidate next stacks: **Clojure** (JVM),
**Swift** (CryptoKit/Sodium), **Zig** (via a C crypto lib).

## Signing and verification

The corpus head is canonicalised (RFC 8785 JCS), EdDSA-signed (compact JWS) and
recorded in a hash-chained provenance log by
[algovoi-corpus-cm](https://github.com/chopmob-cloud/algovoi-corpus-cm). The
manifest carries only the public JWK; the signing key is a genuine secret held
off-repo. `tools/check_kat.py` verifies the signature at runtime;
`tools/validate_independent.py` is an independent oracle over different crypto
libraries.

## Acknowledgments

The byte-for-byte cross-validation is empirically possible only because of the
independent crypto implementations each runner is backed by. AlgoVoi acknowledges
with thanks: OpenSSL, the Bouncy Castle project, the RustCrypto project,
`ed25519-dalek`, the `@noble` libraries (Paul Miller), PyNaCl / libsodium, the
Go and Erlang/OTP standard crypto, and jansson (JSON for the C runner). RFC 9421
was authored by Annie Sporny, Justin Richer, and Manu Sporny; RFC 8032 (Ed25519)
by Simon Josefsson and Ilari Liusvaara.

## Citing this corpus

> AlgoVoi RFC 9421 Conformance, <https://github.com/chopmob-cloud/algovoi-rfc9421-conformance>. 78 (v1) / 89 (v2) / 96 (v3) cases across 7 sections, byte-for-byte reproduced by twelve independent implementations (python, typescript, go, rust, c, java, kotlin, scala, dotnet, ruby, php, elixir), sealed across twelve hermetic runtime cells.

## Licence

Apache 2.0. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE). Contributions
require a DCO sign-off (`git commit -s`); see [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Author

AlgoVoi (Christopher Hopley, GitHub [`chopmob-cloud`](https://github.com/chopmob-cloud)).

## Attribution

This package is Apache-2.0. Use it freely and build whatever you are building on
top of it. The only ask is the one the licence already makes: keep the NOTICE,
and name who authored the substrate. To attribute it in your own product, add
this to your NOTICE file:

```
This product includes the AlgoVoi RFC 9421 conformance substrate,
authored by Christopher Hopley / AlgoVoi (chopmob-cloud), Apache-2.0.
https://github.com/chopmob-cloud/algovoi-rfc9421-conformance
```

## Related

- [AlgoVoi substrate hub](https://chopmob-cloud.github.io/): the open canonicalisation + HTTP-signature substrate for agentic payments
- [algovoi-jcs-conformance-vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors): the L1 RFC 8785 (JCS) canonicalisation conformance corpus
- [algovoi-keyhygiene-conformance](https://github.com/chopmob-cloud/algovoi-keyhygiene-conformance): the L0 RSA/EC key-hygiene and primality soundness conformance corpus
- [algovoi-corpus-cm](https://github.com/chopmob-cloud/algovoi-corpus-cm): the change-management backbone that signs and versions these corpora
