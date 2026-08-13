// TypeScript/Node runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_pqc_mldsa.py) and its decision
// surface (tools/oracle_pqc_mldsa.py) case for case: decode the hex public key,
// message and signature, reject a wrong-length public key (must be 1952) or
// signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
// signature over the exact message bytes with the EMPTY context string.
//
// The ML-DSA implementation is @noble/post-quantum's ml_dsa65 (pinned 0.7.0), a
// pure-JavaScript FIPS-204 implementation independent of the reference liboqs.
// Its verify signature is verify(signature, message, publicKey) and its default
// context is empty, i.e. the pure ML-DSA variant this corpus fixes. A round-3
// Dilithium library would fail the valid controls; that is the built-in tripwire.
//
//   node verify_pqc_mldsa.mjs [path/to/pqc_mldsa_v0.json]
// Corpus path: argv[2], else $ALGOVOI_PQC_MLDSA, else the repo corpus.
// Exit 0 iff every case matches.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "pqc_mldsa_v0", "pqc_mldsa_v0.json");
const SECTIONS = ["mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"];
const PK_LEN = 1952;
const SIG_LEN = 3309;

function hexToBytes(h) {
  if (typeof h !== "string" || h.length % 2 !== 0) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

function verdict(pkHex, msgHex, sigHex) {
  const pk = hexToBytes(pkHex);
  const msg = hexToBytes(msgHex);
  const sig = hexToBytes(sigHex);
  if (pk === null || msg === null || sig === null) return false;
  if (pk.length !== PK_LEN || sig.length !== SIG_LEN) return false;
  try {
    return ml_dsa65.verify(sig, msg, pk) === true;
  } catch {
    return false;
  }
}

const path = process.argv[2] || process.env.ALGOVOI_PQC_MLDSA || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const results = [];
for (const sec of SECTIONS) {
  for (const c of corpus[sec] || []) {
    const accept = verdict(c.public_key, c.message, c.signature);
    results.push({ section: sec, note: c.note, ok: accept === c.expect_valid });
  }
}
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript (pqc_mldsa): ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
