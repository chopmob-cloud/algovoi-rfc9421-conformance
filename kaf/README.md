# kaf — hermetic runtime cells + sealed assurance receipt

The Keystone Assurance Framework layer for this corpus. It carries two of the
four KAF axes for RFC 9421 (the L2 layer): **Cells** (the verdicts hold across
independent runtimes) and **Seal** (a signed, re-verifiable evidence chain). The
**Agreement** axis is `tools/run_consensus.sh`; the KAT part of the **Seal** axis
is `tools/check_kat.py`.

## Cells

`cells.json` pins one runtime image per language. `run_cells.sh` runs each
language's runner against the one frozen, signed corpus **inside its pinned Docker
image**, building or installing deps fresh in-container, so a passing verdict is
shown to hold in a clean, independent runtime rather than only on the build host.
The resolved image **digest** and per-cell verdict are written to
`cells.results.json` (gitignored) for sealing.

```bash
bash kaf/run_cells.sh                 # runs all cells; REPO/VGO/VRS/CELLS overridable
```

## Seal

`seal_receipt.py` binds the three proven axes into one EdDSA-signed receipt:

- **Agreement** — the N-way byte-for-byte consensus (derived from the passing
  cells, never hardcoded);
- **Cells** — each runtime + its image digest;
- bound to the corpus's signed manifest head (`corpus_digest` / `file_sha256`).

It **refuses to seal** unless the KAT integrity gate passes and every cell passed
— a seal must never lend cryptographic confidence to a partial or unverified run.
The seal secret is an Ed25519 key held **off-repo**; only the public JWK
(`keys/kaf-seal.pub.json`) ships, so a receipt is forgery-resistant. RFC 8785
(JCS) is pinned as the sole canonicalization on both the seal and verify sides.

```bash
python kaf/seal_receipt.py --secret <off-repo-seed> --sealed-at <iso8601> --seq N
python kaf/kaf_verify.py kaf/receipts/<receipt>.json   # independent re-verification
```

`kaf_verify.py` re-checks the EdDSA signature over the canonical payload, that the
receipt binds the corpus on disk and the signed head, and that every cell passed.
A forged payload or a partial run verifies INVALID.
