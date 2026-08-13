// TypeScript/Node runner for the COSE_Sign1 corpus (cose_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_cose.py) and its decision surface
// (tools/oracle_cose.py) case for case. Parses each COSE_Sign1 (CBOR array of 4,
// tagged 18 or untagged), applies the COSE security gates in order (protected
// header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present
// in the protected header, an unknown crit (label 2) label rejected, alg/key-type
// match), builds the Sig_structure ["Signature1", protected, h'', payload] in
// deterministic CBOR and verifies the ES256 / EdDSA / PS256 signature. For the
// deterministic-CBOR section it decides whether the datum is RFC 8949 Section 4.2
// canonical. Low-s is NOT enforced (a COSE base rule, not a FAPI rule).
//
// The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
// canonical encoder) so the deterministic judgement and the Sig_structure bytes are
// byte-identical to the frozen corpus, independent of any CBOR library's default
// map-key ordering (bytewise-lexicographic, not length-first). Crypto uses only Node
// built-ins (node:crypto): ES256 (P-256, ieee-p1363), EdDSA (Ed25519 SPKI) and
// PS256 (RSA-PSS SHA-256, salt 32). No npm deps.
//
//   node verify_cose.mjs [path/to/cose_v0.json]
// Exit 0 iff every case matches.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPublicKey, verify as nodeVerify, constants as cryptoConstants } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "cose_v0", "cose_v0.json");

const SECTIONS = ["cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
  "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"];

const HDR_ALG = 1, HDR_CRIT = 2, COSE_SIGN1_TAG = 18;
const ALG_KTY = { [-7]: "EC2", [-8]: "OKP", [-37]: "RSA" };
const KNOWN_LABELS = new Set([1, 2, 3, 4, 5]);

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// ---------------------------------------------------------------------------
// Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
// ---------------------------------------------------------------------------
class CborError extends Error {}

function decode(buf, pos) {
  if (pos >= buf.length) throw new CborError("truncated");
  const ib = buf[pos++];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let arg = 0;
  if (ai < 24) {
    arg = ai;
  } else if (ai === 24) {
    if (pos + 1 > buf.length) throw new CborError("truncated arg");
    arg = buf[pos]; pos += 1;
  } else if (ai === 25) {
    if (pos + 2 > buf.length) throw new CborError("truncated arg");
    arg = buf.readUInt16BE(pos); pos += 2;
  } else if (ai === 26) {
    if (pos + 4 > buf.length) throw new CborError("truncated arg");
    arg = buf.readUInt32BE(pos); pos += 4;
  } else if (ai === 27) {
    if (pos + 8 > buf.length) throw new CborError("truncated arg");
    arg = Number(buf.readBigUInt64BE(pos)); pos += 8;
  } else if (ai === 31) {
    if (major < 2 || major > 5) throw new CborError("indefinite not allowed here");
    return decodeIndefinite(buf, pos, major);
  } else {
    throw new CborError("reserved additional info");
  }

  switch (major) {
    case 0: return [{ t: "int", v: arg }, pos];
    case 1: return [{ t: "int", v: -1 - arg }, pos];
    case 2: {
      if (pos + arg > buf.length) throw new CborError("truncated bstr");
      const v = buf.subarray(pos, pos + arg); return [{ t: "bytes", v }, pos + arg];
    }
    case 3: {
      if (pos + arg > buf.length) throw new CborError("truncated tstr");
      const v = buf.subarray(pos, pos + arg).toString("utf8"); return [{ t: "text", v }, pos + arg];
    }
    case 4: {
      const items = [];
      for (let i = 0; i < arg; i++) { const [val, np] = decode(buf, pos); items.push(val); pos = np; }
      return [{ t: "array", v: items }, pos];
    }
    case 5: {
      const pairs = [];
      for (let i = 0; i < arg; i++) {
        const [k, p1] = decode(buf, pos); const [val, p2] = decode(buf, p1);
        pairs.push([k, val]); pos = p2;
      }
      return [{ t: "map", v: pairs }, pos];
    }
    case 6: { const [inner, np] = decode(buf, pos); return [{ t: "tag", n: arg, v: inner }, np]; }
    case 7: {
      if (ai === 22) return [{ t: "null" }, pos];
      if (ai === 20) return [{ t: "bool", v: false }, pos];
      if (ai === 21) return [{ t: "bool", v: true }, pos];
      throw new CborError("unsupported simple/float");
    }
    default: throw new CborError("bad major");
  }
}

function decodeIndefinite(buf, pos, major) {
  if (major === 2 || major === 3) {
    const chunks = [];
    for (;;) {
      if (pos >= buf.length) throw new CborError("truncated indefinite");
      if (buf[pos] === 0xff) { pos += 1; break; }
      const [chunk, np] = decode(buf, pos);
      if (chunk.t !== (major === 2 ? "bytes" : "text")) throw new CborError("bad indefinite chunk");
      chunks.push(chunk.v); pos = np;
    }
    if (major === 2) return [{ t: "bytes", v: Buffer.concat(chunks) }, pos];
    return [{ t: "text", v: chunks.join("") }, pos];
  }
  if (major === 4) {
    const items = [];
    for (;;) {
      if (pos >= buf.length) throw new CborError("truncated indefinite");
      if (buf[pos] === 0xff) { pos += 1; break; }
      const [val, np] = decode(buf, pos); items.push(val); pos = np;
    }
    return [{ t: "array", v: items }, pos];
  }
  // major 5
  const pairs = [];
  for (;;) {
    if (pos >= buf.length) throw new CborError("truncated indefinite");
    if (buf[pos] === 0xff) { pos += 1; break; }
    const [k, p1] = decode(buf, pos); const [val, p2] = decode(buf, p1);
    pairs.push([k, val]); pos = p2;
  }
  return [{ t: "map", v: pairs }, pos];
}

function head(major, n) {
  const base = major << 5;
  if (n < 24) return Buffer.from([base | n]);
  if (n < 0x100) return Buffer.from([base | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = base | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 0x100000000) { const b = Buffer.alloc(5); b[0] = base | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = base | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
}

function encode(val) {
  switch (val.t) {
    case "int":
      return val.v >= 0 ? head(0, val.v) : head(1, -1 - val.v);
    case "bytes": return Buffer.concat([head(2, val.v.length), val.v]);
    case "text": { const b = Buffer.from(val.v, "utf8"); return Buffer.concat([head(3, b.length), b]); }
    case "array": return Buffer.concat([head(4, val.v.length), ...val.v.map(encode)]);
    case "map": {
      const enc = val.v.map(([k, v]) => [encode(k), encode(v)]);
      enc.sort((a, b) => Buffer.compare(a[0], b[0]));
      return Buffer.concat([head(5, enc.length), ...enc.flatMap(([k, v]) => [k, v])]);
    }
    case "null": return Buffer.from([0xf6]);
    default: throw new CborError("cannot canonically encode " + val.t);
  }
}

function isDeterministic(buf) {
  let value, np;
  try { [value, np] = decode(buf, 0); } catch { return false; }
  if (np !== buf.length) return false;
  if (value.t === "tag") return false;
  try { return Buffer.compare(encode(value), buf) === 0; } catch { return false; }
}

function mapGet(m, key) {
  for (const [k, v] of m.v) if (k.t === "int" && k.v === key) return v;
  return undefined;
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parse + gates
// ---------------------------------------------------------------------------
function parseSign1(buf) {
  let top;
  try { [top] = decode(buf, 0); } catch { return null; }
  let arr = top;
  if (top.t === "tag") { if (top.n !== COSE_SIGN1_TAG) return null; arr = top.v; }
  if (arr.t !== "array" || arr.v.length !== 4) return null;
  const [protected_, uhdr, payload, sig] = arr.v;
  if (protected_.t !== "bytes") return null;
  if (uhdr.t !== "map") return null;
  if (payload.t !== "bytes" && payload.t !== "null") return null;
  if (sig.t !== "bytes") return null;
  let phdr;
  if (protected_.v.length === 0) {
    phdr = { t: "map", v: [] };
  } else {
    if (!isDeterministic(protected_.v)) return null;
    let dec;
    try { [dec] = decode(protected_.v, 0); } catch { return null; }
    if (dec.t !== "map") return null;
    phdr = dec;
  }
  return { protected_: protected_.v, phdr, payload: payload.t === "null" ? Buffer.alloc(0) : payload.v, sig: sig.v };
}

function sigStructure(protectedBytes, payloadBytes) {
  return encode({ t: "array", v: [
    { t: "text", v: "Signature1" },
    { t: "bytes", v: protectedBytes },
    { t: "bytes", v: Buffer.alloc(0) },
    { t: "bytes", v: payloadBytes },
  ] });
}

// ---------------------------------------------------------------------------
// Signature verification per algorithm
// ---------------------------------------------------------------------------
function b64u(buf) { return buf.toString("base64url"); }

function verifyEs256(key, preimage, sig) {
  if (sig.length !== 64) return false;
  const x = BigInt("0x" + key.x), y = BigInt("0x" + key.y);
  if (((y * y - (x * x * x + P256_A * x + P256_B)) % P256_P + P256_P) % P256_P !== 0n) return false;
  try {
    const pub = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(Buffer.from(key.x, "hex")), y: b64u(Buffer.from(key.y, "hex")) }, format: "jwk" });
    return nodeVerify("sha256", preimage, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
  } catch { return false; }
}

function verifyEddsa(key, preimage, sig) {
  try {
    const raw = Buffer.from(key.x, "hex");
    if (raw.length !== 32) return false;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    const pub = createPublicKey({ key: der, format: "der", type: "spki" });
    return nodeVerify(null, preimage, pub, sig);
  } catch { return false; }
}

function verifyPs256(key, preimage, sig) {
  try {
    const pub = createPublicKey({ key: { kty: "RSA", n: b64u(Buffer.from(key.n, "hex")), e: b64u(Buffer.from(key.e, "hex")) }, format: "jwk" });
    return nodeVerify("sha256", preimage, { key: pub, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
  } catch { return false; }
}

const VERIFIERS = { [-7]: verifyEs256, [-8]: verifyEddsa, [-37]: verifyPs256 };

function verdict(buf, key) {
  const parsed = parseSign1(buf);
  if (parsed === null) return false;
  const alg = mapGet(parsed.phdr, HDR_ALG);
  if (alg === undefined || alg.t !== "int") return false;
  const crit = mapGet(parsed.phdr, HDR_CRIT);
  if (crit !== undefined) {
    if (crit.t !== "array" || crit.v.length === 0) return false;
    for (const label of crit.v) if (label.t !== "int" || !KNOWN_LABELS.has(label.v)) return false;
  }
  if (!(alg.v in ALG_KTY)) return false;
  if (key.kty !== ALG_KTY[alg.v]) return false;
  const preimage = sigStructure(parsed.protected_, parsed.payload);
  return VERIFIERS[alg.v](key, preimage, parsed.sig);
}

const path = process.argv[2] || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const keys = corpus.keys;
const results = [];
for (const sec of SECTIONS) {
  for (const c of corpus[sec] || []) {
    let accept;
    if (sec === "cose_deterministic_cbor") accept = isDeterministic(Buffer.from(c.cbor_hex, "hex"));
    else accept = verdict(Buffer.from(c.cose_hex, "hex"), keys[c.key]);
    results.push({ section: sec, note: c.note, ok: accept === c.expect_valid });
  }
}
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript (cose): ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
