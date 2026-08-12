// TypeScript/Node runner for the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_fapi.py) exactly. The PROFILE
// rules (mandated coverage, Content-Digest body binding, algorithm restriction,
// low-s enforcement) and the PS256/ES256 crypto are re-implemented here from the
// corpus `policy` read at RUNTIME, NOT hardcoded, so a runner passing is genuine
// agreement. Uses only Node built-ins (node:crypto, node:fs) — no npm deps.
//
//   node verify_fapi.mjs [path/to/fapi_messagesigning_v0.json]
// Exit 0 iff every case matches.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash, createPublicKey, verify as nodeVerify, constants as cryptoConstants } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "fapi_messagesigning_v0", "fapi_messagesigning_v0.json");

const b64ToStr = (b) => Buffer.from(b, "base64").toString("utf8");
const b64ToBytes = (b) => Buffer.from(b, "base64");
const hexToBytes = (h) => Buffer.from(h, "hex");

// --- Section 1: RFC 9421 Section 2.5 signing base, hand-built --------------
function buildSigningBase(src, signatureParamsRaw) {
  const lines = [];
  for (const raw of src.covered_components) {
    const name = raw.toLowerCase();
    let value;
    if (name === "@method") value = src.method;
    else if (name === "@target-uri") value = src.target_uri;
    else if (name === "@status") value = String(src.status);
    else if (name === "@authority") value = src.authority;
    else if (name === "@path") value = src.path;
    else value = (src.headers || {})[name];
    if (value === undefined || value === null) throw new Error(`unbuildable component: ${name}`);
    lines.push(`"${name}": ${value}`);
  }
  if (signatureParamsRaw === undefined || signatureParamsRaw === null)
    throw new Error("unbuildable: missing signature-params");
  lines.push(`"@signature-params": ${signatureParamsRaw}`);
  return lines.join("\n");
}

// --- Section 2: mandated covered-component completeness --------------------
function coverageOk(messageType, covered, policy) {
  const key = messageType === "request" ? "required_covered_request" : "required_covered_response";
  const have = new Set(covered.map((c) => c.toLowerCase()));
  return policy[key].every((r) => have.has(r.toLowerCase()));
}

// --- Section 3: Content-Digest (RFC 9530) body binding ---------------------
function contentDigestOk(bodyB64, headerValue, covered, policy) {
  if (!covered.map((c) => c.toLowerCase()).includes("content-digest")) return false;
  const eq = headerValue.indexOf("=");
  if (eq === -1) return false;
  const algorithm = headerValue.slice(0, eq).trim().toLowerCase();
  if (!policy.content_digest_algorithms.includes(algorithm)) return false;
  const body = b64ToBytes(bodyB64);
  const digest = algorithm === "sha-256"
    ? createHash("sha256").update(body).digest()
    : createHash("sha512").update(body).digest();
  const expect = `${algorithm}=:${digest.toString("base64")}:`;
  return headerValue.trim() === expect;
}

// --- Section 5: PS256 (RSA-PSS SHA-256, salt 32) ---------------------------
function ps256Ok(base, sig, spkiHex) {
  try {
    const key = createPublicKey({ key: hexToBytes(spkiHex), format: "der", type: "spki" });
    return nodeVerify("sha256", base, { key, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
  } catch {
    return false;
  }
}

// --- Section 6: ES256 (ECDSA P-256 SHA-256), raw r||s, low-s enforced ------
function derLenAndInt(intBytes) {
  // strip leading zero bytes, then re-pad a single 0x00 if high bit is set
  let i = 0;
  while (i < intBytes.length - 1 && intBytes[i] === 0) i++;
  let v = intBytes.subarray(i);
  if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
  return Buffer.concat([Buffer.from([0x02, v.length]), v]);
}

function rawToDer(rawSig) {
  const r = derLenAndInt(rawSig.subarray(0, 32));
  const s = derLenAndInt(rawSig.subarray(32, 64));
  const seq = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

function es256Ok(base, sigRaw, pubUncompressed, requireLowS, policy) {
  if (sigRaw.length !== 64) return false;
  const r = BigInt("0x" + sigRaw.subarray(0, 32).toString("hex"));
  const s = BigInt("0x" + sigRaw.subarray(32, 64).toString("hex"));
  if (requireLowS && s > BigInt(policy.p256_n) / 2n) return false;
  try {
    if (pubUncompressed.length !== 65 || pubUncompressed[0] !== 0x04) return false;
    const x = pubUncompressed.subarray(1, 33).toString("base64url");
    const y = pubUncompressed.subarray(33, 65).toString("base64url");
    const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
    return nodeVerify("sha256", base, { key, dsaEncoding: "der" }, rawToDer(sigRaw));
  } catch {
    return false;
  }
}

function run(corpus) {
  const policy = corpus.policy;
  const results = [];
  const rec = (section, note, ok) => results.push({ section, note, ok });

  for (const c of corpus.fapi_signing_base) {
    let ok;
    // build FIRST; a short-circuit on c.ok would never exercise the failure path
    try {
      const built = buildSigningBase(c.in, c.signature_params_raw);
      ok = c.ok && built === b64ToStr(c.signing_base_b64);
    } catch {
      ok = !c.ok;
    }
    rec("fapi_signing_base", c.note, ok);
  }

  for (const c of corpus.fapi_required_coverage) {
    rec("fapi_required_coverage", c.note,
      coverageOk(c.message_type, c.covered_components, policy) === c.expect_accept);
  }

  for (const c of corpus.fapi_content_digest) {
    rec("fapi_content_digest", c.note,
      contentDigestOk(c.body_b64, c.content_digest, c.covered_components, policy) === c.expect_accept);
  }

  for (const c of corpus.fapi_alg) {
    rec("fapi_alg", c.note,
      policy.allowed_algs.includes(c.alg.toLowerCase()) === c.expect_accept);
  }

  for (const c of corpus.fapi_ps256_verify) {
    const base = b64ToBytes(c.signing_base_b64);
    const ok = ps256Ok(base, hexToBytes(c.sig_hex), c.pub_spki_hex);
    rec("fapi_ps256_verify", c.note, ok === c.expect_valid);
  }

  for (const c of corpus.fapi_es256_verify) {
    const base = b64ToBytes(c.signing_base_b64);
    const ok = es256Ok(base, hexToBytes(c.sig_raw_hex), hexToBytes(c.pub_uncompressed_hex),
      Boolean(c.require_low_s), policy);
    rec("fapi_es256_verify", c.note, ok === c.expect_valid);
  }

  return results;
}

const path = process.argv[2] || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const results = run(corpus);
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript (fapi): ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
