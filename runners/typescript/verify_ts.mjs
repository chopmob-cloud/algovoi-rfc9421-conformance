// TypeScript/Node runner for the rfc9421_negative_v1 CORE cross-language battery.
//
// Imports the published @algovoi/rfc9421-verifier (core) and
// @algovoi/rfc9421-ecdsa (add-on) and checks every case verdict against the
// frozen corpus, mirroring the Python reference runner so all four languages
// agree per case. Verify setup errors are fail-closed (valid = false).
//
// Install: npm install (see package.json), or point ALGOVOI_CORE_DIST /
// ALGOVOI_ECDSA_DIST at the built dist/index.js of each package for local dev.
// Corpus path defaults to ../../corpus/rfc9421_negative_v1/ or ALGOVOI_NEGATIVE_V1.
//
//   node verify_ts.mjs [path/to/rfc9421_negative_v1.json]
// Exit 0 iff every case matches.

import { readFileSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPublicKey, verify as nodeVerify, constants as cryptoConstants } from "node:crypto";

async function load(pkg, distEnv) {
  const override = process.env[distEnv];
  if (override) return import(pathToFileURL(override).href);
  return import(pkg);
}

const core = await load("@algovoi/rfc9421-verifier", "ALGOVOI_CORE_DIST");
const ecdsa = await load("@algovoi/rfc9421-ecdsa", "ALGOVOI_ECDSA_DIST");
const {
  buildSigningBase,
  parseSignatureInput,
  parseSignatureValue,
  verifySignature,
  checkEd25519PublicKey,
  isSmallOrder,
} = core;
const { verifyP256, verifyP384, setStrictLowS } = ecdsa;

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "rfc9421_negative_v1", "rfc9421_negative_v1.json");

const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const b64ToStr = (b) => Buffer.from(b, "base64").toString("utf8");

function buildInput(c) {
  const i = c.in;
  const input = {
    coveredComponents: i.covered_components,
    method: i.method,
    authority: i.authority,
    path: i.path,
    targetUri: i.target_uri,
    scheme: i.scheme,
    status: i.status,
    headers: i.headers,
    parameters: i.parameters,
    mode: c.mode,
  };
  if (c.mode === "rfc9421") input.signatureParamsRaw = c.signature_params_raw;
  return input;
}

async function run(corpus) {
  const results = [];
  const rec = (section, note, ok) => results.push({ section, note, ok });

  for (const c of corpus.signing_base) {
    let ok;
    // build FIRST; `c.ok && buildSigningBase(...)` would short-circuit for
    // negative cases and never verify that the build actually fails.
    try { const built = buildSigningBase(buildInput(c)); ok = c.ok && built === b64ToStr(c.signing_base_b64); }
    catch { ok = !c.ok; }
    rec("signing_base", c.note, ok);
  }
  for (const c of corpus.signature_input_parse) {
    let p; try { parseSignatureInput(c.header); p = true; } catch { p = false; }
    rec("sig_input_parse", c.note, p === c.ok);
  }
  for (const c of corpus.signature_value_parse) {
    let p; try { parseSignatureValue(c.header); p = true; } catch { p = false; }
    rec("sig_value_parse", c.note, p === c.ok);
  }
  for (const c of corpus.keygate) {
    const pk = hexToBytes(c.pk_hex);
    let rejected = null;
    try { checkEd25519PublicKey(pk); } catch { rejected = "WeakKeyError"; }
    rec("keygate", c.note, rejected === c.rejected && isSmallOrder(pk) === c.small_order);
  }
  for (const c of corpus.ed25519_verify) {
    let valid;
    try { valid = await verifySignature(b64ToStr(c.signing_base_b64), hexToBytes(c.sig_hex), c.pk_hex); }
    catch { valid = false; }
    rec("ed25519_verify", c.note, valid === c.expect_valid);
  }
  for (const c of corpus.ecdsa_verify) {
    const fn = c.curve === "p256" ? verifyP256 : verifyP384;
    const msg = Buffer.from(c.msg_hex, "hex").toString("utf8");
    setStrictLowS(Boolean(c.strict_low_s));
    let valid;
    try { valid = fn(msg, hexToBytes(c.sig_raw_hex), c.pub_uncompressed_hex); }
    catch { valid = false; }
    finally { setStrictLowS(false); }
    rec("ecdsa_verify", c.note, valid === c.expect_valid);
  }
  // RSA is not part of the Ed25519/ECDSA verifier; verify with node:crypto so
  // the rsa_verify section is genuine cross-language consensus.
  for (const c of corpus.rsa_verify ?? []) {
    const base = Buffer.from(c.signing_base_b64, "base64");
    const valid = rsaVerify(c.alg, base, Buffer.from(c.sig_hex, "hex"), c.pub_spki_hex);
    rec("rsa_verify", c.note, valid === c.expect_valid);
  }
  return results;
}

function rsaVerify(alg, base, sig, spkiHex) {
  try {
    const key = createPublicKey({ key: Buffer.from(spkiHex, "hex"), format: "der", type: "spki" });
    if (alg === "rsa-pss-sha512")
      return nodeVerify("sha512", base, { key, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }, sig);
    if (alg === "rsa-v1_5-sha256")
      return nodeVerify("sha256", base, { key, padding: cryptoConstants.RSA_PKCS1_PADDING }, sig);
    return false;
  } catch { return false; }
}

const path = process.argv[2] || process.env.ALGOVOI_NEGATIVE_V1 || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const results = await run(corpus);
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript: ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
