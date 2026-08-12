// TypeScript/Node runner for the JSON Web Signature corpus (jws_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_jws.py) and its decision surface
// (tools/oracle_jws.py) case for case. Parses each compact JWS, applies the JOSE
// security gates in order (reject alg:none, reject any crit, reject alg/key-type
// mismatch such as HS256 keyed with an RSA public key, select the key by kid when
// required), then verifies the RS256 / ES256 / EdDSA signature over
// ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
// high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule). The gate logic
// is re-implemented here from the corpus, not imported, so a pass is genuine
// agreement. Uses only Node built-ins (node:crypto, node:fs) - no npm deps.
//
//   node verify_jws.mjs [path/to/jws_v0.json]
// Exit 0 iff every case matches.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPublicKey, verify as nodeVerify, constants as cryptoConstants } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "jws_v0", "jws_v0.json");

const SECTIONS = ["jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
  "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"];

// RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
const ALG_KTY = { RS256: "RSA", ES256: "EC", EdDSA: "OKP", HS256: "oct" };

// secp256r1 parameters, for the explicit on-curve check.
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// Strict base64url decode of one compact segment (RFC 7515 Appendix C): unpadded,
// URL-safe alphabet only. Any other character (including '=') is malformed.
function b64urlDecode(seg) {
  if (!B64URL_RE.test(seg)) return null;
  if (seg.length % 4 === 1) return null;
  return Buffer.from(seg, "base64url");
}

function b64urlToBigInt(seg) {
  const b = b64urlDecode(seg);
  if (b === null) return null;
  return b.length === 0 ? 0n : BigInt("0x" + b.toString("hex"));
}

function parseCompact(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [pB64, plB64, sB64] = parts;
  const headerBytes = b64urlDecode(pB64);
  if (headerBytes === null) return null;
  let header;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
  } catch {
    return null;
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) return null;
  if (!Object.prototype.hasOwnProperty.call(header, "alg")) return null;
  const payload = b64urlDecode(plB64);
  if (payload === null) return null;
  const sig = b64urlDecode(sB64);
  if (sig === null) return null;
  const signingInput = Buffer.from(pB64 + "." + plB64, "ascii");
  return { header, sig, signingInput };
}

function selectKey(header, ctx) {
  if (ctx.select_by_kid) {
    const kid = header.kid;
    if (kid === undefined || kid === null) return null;
    for (const k of ctx.keys) if (k.kid === kid) return k.jwk;
    return null;
  }
  return ctx.keys[0].jwk;
}

function verifyRs256(jwk, signingInput, sig) {
  try {
    const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
    return nodeVerify("sha256", signingInput, { key, padding: cryptoConstants.RSA_PKCS1_PADDING }, sig);
  } catch {
    return false;
  }
}

function verifyEs256(jwk, signingInput, sig) {
  if (sig.length !== 64) return false;
  const x = b64urlToBigInt(jwk.x);
  const y = b64urlToBigInt(jwk.y);
  if (x === null || y === null) return false;
  // Reject a public key whose point is not on secp256r1 before trusting it.
  if (((y * y - (x * x * x + P256_A * x + P256_B)) % P256_P + P256_P) % P256_P !== 0n) return false;
  try {
    const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
    return nodeVerify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return false;
  }
}

function verifyEddsa(jwk, signingInput, sig) {
  try {
    const raw = b64urlDecode(jwk.x);
    if (raw === null || raw.length !== 32) return false;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return nodeVerify(null, signingInput, key, sig);
  } catch {
    return false;
  }
}

const VERIFIERS = { RS256: verifyRs256, ES256: verifyEs256, EdDSA: verifyEddsa };

function verdict(token, ctx) {
  const parsed = parseCompact(token);
  if (parsed === null) return false;
  const { header, sig, signingInput } = parsed;
  const alg = header.alg;
  if (alg === "none") return false;
  if (Object.prototype.hasOwnProperty.call(header, "crit")) return false;
  if (!Object.prototype.hasOwnProperty.call(ALG_KTY, alg)) return false;
  const jwk = selectKey(header, ctx);
  if (jwk === null || jwk === undefined) return false;
  if (jwk.kty !== ALG_KTY[alg]) return false;
  const fn = VERIFIERS[alg];
  if (!fn) return false;
  return fn(jwk, signingInput, sig);
}

function ctxOf(verify, keys) {
  return {
    keys: verify.key_names.map((n) => ({ kid: keys[n].kid, jwk: keys[n] })),
    select_by_kid: verify.select_by_kid,
  };
}

const path = process.argv[2] || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const keys = corpus.keys;
const results = [];
for (const sec of SECTIONS) {
  for (const c of corpus[sec] || []) {
    const accept = verdict(c.jws, ctxOf(c.verify, keys));
    results.push({ section: sec, note: c.note, ok: accept === c.expect_valid });
  }
}
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript (jws): ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
