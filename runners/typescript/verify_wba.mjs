#!/usr/bin/env node
// TypeScript/Node runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Self-contained port of the Python reference runner (runners/python/verify_wba.py)
// and its independent KAT gate (tools/check_kat_wba.py). Every PROFILE rule
// (signing base, coverage completeness, freshness window, directory keyid
// resolution, Signature-Agent SSRF) is re-implemented here directly from the
// corpus `policy` block, NOT imported from a shared oracle, so a runner passing
// is genuine agreement rather than an echo. Ed25519 is verified with Node's
// built-in crypto (raw 32-byte key wrapped in an Ed25519 SPKI DER). No third-
// party npm dependencies.
//
//   node verify_wba.mjs [path/to/webbotauth_v0.json]
//
// Corpus path defaults to ../../corpus/webbotauth_v0/webbotauth_v0.json relative
// to this file. Exit 0 iff every case matches, else exit 1.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPublicKey, verify as nodeVerify } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "webbotauth_v0", "webbotauth_v0.json");

const b64ToBytes = (b) => Buffer.from(b, "base64");
const b64ToStr = (b) => Buffer.from(b, "base64").toString("utf8");
const hexToBytes = (h) => Buffer.from(h, "hex");

// ---------------------------------------------------------------------------
// Rule 1: RFC 9421 Section 2.5 signing base, by direct concatenation.
// ---------------------------------------------------------------------------
function buildSigningBase(src, paramsRaw) {
  const lines = [];
  for (const comp of src.covered_components) {
    const name = String(comp).toLowerCase();
    let val;
    if (name === "@authority") val = src.authority;
    else if (name === "@method") val = src.method;
    else if (name === "@path") val = src.path;
    else val = (src.headers || {})[name];
    if (val === undefined || val === null) {
      throw new Error(`missing covered component: ${name}`);
    }
    lines.push(`"${name}": ${val}`);
  }
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Rule 2: coverage completeness (every required component present, lowercased).
// ---------------------------------------------------------------------------
function coverageOk(covered, policy) {
  const have = new Set((covered || []).map((c) => String(c).toLowerCase()));
  return policy.required_covered_components.every((r) => have.has(String(r).toLowerCase()));
}

// ---------------------------------------------------------------------------
// Rule 3: freshness window.  All three must be integers, expires > created,
// and (created - skew) <= now < expires.
// ---------------------------------------------------------------------------
const isInt = (x) => typeof x === "number" && Number.isInteger(x);
function freshnessOk(created, expires, now, policy) {
  const skew = policy.clock_skew_seconds ?? 0;
  if (!isInt(created) || !isInt(expires) || !isInt(now)) return false;
  if (expires <= created) return false;
  return created - skew <= now && now < expires;
}

// ---------------------------------------------------------------------------
// Rule 4: directory keyid resolution to a usable Ed25519 JWK.
// ---------------------------------------------------------------------------
function directoryOk(directory, keyid) {
  for (const jwk of directory || []) {
    if (jwk.kid === keyid) {
      return jwk.kty === "OKP" && jwk.crv === "Ed25519" && Boolean(jwk.x);
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Rule 5: Signature-Agent SSRF guard.  Needs IPv4 AND IPv6 CIDR membership by
// bit masking (Node has no built-in CIDR support).
// ---------------------------------------------------------------------------
function parseIPv4(s) {
  const parts = String(s).split(".");
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    if (p.length > 1 && p[0] === "0") return null; // reject leading zeros (py3.9+ strict)
    const n = Number(p);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

function parseIPv6(s) {
  if (typeof s !== "string" || s.length === 0) return null;
  if ((s.match(/::/g) || []).length > 1) return null; // at most one "::"

  const groupsOf = (part) => {
    if (part === "") return [];
    const segs = part.split(":");
    const out = [];
    for (let k = 0; k < segs.length; k++) {
      const seg = segs[k];
      if (seg.includes(".")) {
        if (k !== segs.length - 1) return null; // embedded IPv4 must be last
        const v4 = parseIPv4(seg);
        if (v4 === null) return null;
        out.push(Number((v4 >> 16n) & 0xffffn));
        out.push(Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(seg)) return null;
        out.push(parseInt(seg, 16));
      }
    }
    return out;
  };

  let value;
  if (s.includes("::")) {
    const idx = s.indexOf("::");
    const head = groupsOf(s.slice(0, idx));
    const tail = groupsOf(s.slice(idx + 2));
    if (head === null || tail === null) return null;
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null; // "::" must stand for at least one group
    value = [...head, ...Array(missing).fill(0), ...tail];
  } else {
    value = groupsOf(s);
    if (value === null || value.length !== 8) return null;
  }
  if (value.length !== 8) return null;

  let big = 0n;
  for (const g of value) {
    if (g < 0 || g > 0xffff) return null;
    big = (big << 16n) | BigInt(g);
  }
  return big;
}

function parseAddr(s) {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { version: 4, value: v4, bits: 32 };
  const v6 = parseIPv6(s);
  if (v6 !== null) return { version: 6, value: v6, bits: 128 };
  return null;
}

function parseCidr(cidr) {
  const slash = cidr.lastIndexOf("/");
  if (slash < 0) return null;
  const addr = parseAddr(cidr.slice(0, slash));
  if (!addr) return null;
  const prefix = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > addr.bits) return null;
  return { version: addr.version, value: addr.value, prefix, bits: addr.bits };
}

function inCidr(addr, net) {
  if (addr.version !== net.version) return false;
  const full = (1n << BigInt(net.bits)) - 1n;
  const hostBits = BigInt(net.bits - net.prefix);
  const mask = full ^ ((1n << hostBits) - 1n);
  return (addr.value & mask) === (net.value & mask);
}

function ssrfOk(url, resolvedIp, policy) {
  const ssrf = policy.ssrf;
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const scheme = u.protocol.replace(/:$/, "");
  if ((ssrf.require_https ?? true) && scheme !== "https") return false;
  if (u.username !== "" || u.password !== "") return false; // userinfo -> reject

  const host = u.hostname;
  if (!host) return false;

  let addr;
  if (host.startsWith("[") && host.endsWith("]")) {
    const v6 = parseIPv6(host.slice(1, -1));
    if (v6 === null) return false;
    addr = { version: 6, value: v6, bits: 128 };
  } else {
    const v4 = parseIPv4(host);
    if (v4 !== null) {
      addr = { version: 4, value: v4, bits: 32 };
    } else {
      // hostname is a domain -> rely on the resolved address
      if (!resolvedIp) return false;
      addr = parseAddr(resolvedIp);
      if (!addr) return false;
    }
  }

  for (const c of ssrf.denied_cidrs) {
    const net = parseCidr(c);
    if (net && addr.version === net.version && inCidr(addr, net)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Rule 6: Ed25519 verify of the raw signing-base bytes under a raw 32-byte key.
// ---------------------------------------------------------------------------
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function ed25519Verify(msgBytes, sig, pkHex) {
  try {
    const raw = hexToBytes(pkHex);
    if (raw.length !== 32) return false;
    const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return nodeVerify(null, msgBytes, key, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------
function run(corpus) {
  const policy = corpus.policy;
  const results = [];
  const rec = (section, note, ok) => results.push({ section, note, ok });

  for (const c of corpus.wba_signing_base) {
    const decoded = b64ToStr(c.signing_base_b64);
    let ok;
    // Build FIRST; `c.ok && buildSigningBase(...)` would short-circuit negative
    // cases and never exercise the build-failure path.
    try {
      const built = buildSigningBase(c.in, c.signature_params_raw);
      ok = c.ok && built === decoded;
    } catch {
      ok = !c.ok;
    }
    rec("wba_signing_base", c.note, ok);
  }

  for (const c of corpus.wba_coverage) {
    rec("wba_coverage", c.note, coverageOk(c.covered_components, policy) === c.expect_accept);
  }

  for (const c of corpus.wba_freshness) {
    rec("wba_freshness", c.note, freshnessOk(c.created, c.expires, c.now, policy) === c.expect_accept);
  }

  for (const c of corpus.wba_directory) {
    rec("wba_directory", c.note, directoryOk(c.directory, c.keyid) === c.expect_accept);
  }

  for (const c of corpus.wba_directory_ssrf) {
    rec(
      "wba_directory_ssrf",
      c.note,
      ssrfOk(c.signature_agent_url, c.resolved_ip ?? null, policy) === c.expect_fetch_allowed
    );
  }

  for (const c of corpus.wba_ed25519_verify) {
    const msg = b64ToBytes(c.signing_base_b64);
    const valid = ed25519Verify(msg, hexToBytes(c.sig_hex), c.pk_hex);
    rec("wba_ed25519_verify", c.note, valid === c.expect_valid);
  }

  return results;
}

const path = process.argv[2] || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));
const results = run(corpus);
const fails = results.filter((r) => !r.ok);
for (const f of fails) console.log(`FAIL  [${f.section}] ${f.note}`);
console.log(`\ntypescript (wba): ${results.length - fails.length}/${results.length} cases matched`);
process.exit(fails.length ? 1 : 0);
