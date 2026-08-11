# Contributing

Contributions are accepted under the Apache License, Version 2.0.

## Developer Certificate of Origin (DCO)

Every commit must be signed off (`git commit -s`), certifying the DCO 1.1. The
sign-off line must read:

```
Signed-off-by: Your Name <your@email>
```

## Changing the corpus

The frozen corpus `corpus/rfc9421_negative_v1/rfc9421_negative_v1.json` is signed
(`.manifest.json` + `.provenance.json`). Do not edit it by hand. Regenerate it
deterministically with `tools/gen_negative_v1.py`, then re-sign with
`tools/sign_negative_v1.py`. Every crypto verdict is computed from the reference
verifier, never hand-asserted, and the four language runners must all reproduce
it byte-for-byte before a change is accepted.
