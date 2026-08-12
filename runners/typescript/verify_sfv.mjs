#!/usr/bin/env node
// TypeScript/Node runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
// case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
// are equal.
//
// Parsing and canonical serialization use the third-party RFC 8941 library
// `structured-headers` (Evert Pot), so a pass is genuine agreement with an
// independent implementation, not an echo of the generator's oracle. That library
// silently repairs a non-canonically-padded Byte Sequence (e.g. `:aGVsbG8:`),
// which RFC 8941 and the frozen corpus reject; a small strict pre-check
// (strictBytesOk) rejects any input carrying a non-canonical base64 Byte Sequence
// before delegating, so the runner matches the corpus byte-for-byte.
//
//   node verify_sfv.mjs [path/to/sfv_v0.json]
//
// Exit 0 iff every case matches, else 1.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parseItem, parseList, parseDictionary,
  serializeItem, serializeList, serializeDictionary,
} from "structured-headers";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT = join(HERE, "..", "..", "corpus", "sfv_v0", "sfv_v0.json");
const SECTIONS = ["sfv_item", "sfv_list", "sfv_dictionary",
                  "sfv_parameters", "sfv_canonical", "sfv_reject"];

const TOKEN_TAIL = /[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/;
const B64_CHAR = /[A-Za-z0-9+/]/;

// A byte sequence's base64 must be canonical: length a multiple of 4 and padding
// only in the final one or two positions (mirrors python base64 validate=True).
function b64Canonical(content) {
  if (content.length % 4 !== 0) return false;
  let pad = 0;
  for (let k = 0; k < content.length; k++) {
    const c = content[k];
    if (c === "=") {
      pad++;
      if (k < content.length - 2) return false;
    } else {
      if (pad > 0) return false;
      if (!B64_CHAR.test(c)) return false;
    }
  }
  return true;
}

// Reject the whole input if any Byte Sequence token carries non-canonical base64.
// Strings are skipped and tokens are consumed whole (Tokens may contain ':'), so
// the only ':' this sees begins a Byte Sequence at a bare-item position.
function strictBytesOk(s) {
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '"') {
      i++;
      while (i < s.length) {
        if (s[i] === "\\") { i += 2; continue; }
        if (s[i] === '"') { i++; break; }
        i++;
      }
    } else if (/[A-Za-z*]/.test(c)) {
      i++;
      while (i < s.length && TOKEN_TAIL.test(s[i])) i++;
    } else if (c === ":") {
      const start = i + 1;
      let j = start;
      while (j < s.length && s[j] !== ":") j++;
      if (j >= s.length) return true; // unterminated: let the library reject
      if (!b64Canonical(s.slice(start, j))) return false;
      i = j + 1;
    } else {
      i++;
    }
  }
  return true;
}

function verdict(fieldType, input) {
  if (!strictBytesOk(input)) return [false, null];
  try {
    let canon;
    if (fieldType === "item") canon = serializeItem(parseItem(input));
    else if (fieldType === "list") canon = serializeList(parseList(input));
    else if (fieldType === "dictionary") canon = serializeDictionary(parseDictionary(input));
    else return [false, null];
    return [true, canon];
  } catch {
    return [false, null];
  }
}

const path = process.argv[2] || DEFAULT;
const corpus = JSON.parse(readFileSync(path, "utf8"));

let total = 0;
let matched = 0;
const fails = [];
for (const sec of SECTIONS) {
  for (const c of corpus[sec] || []) {
    const [ok, canon] = verdict(c.field_type, c.input);
    const match = (ok === c.expect_parse_ok) && (!ok || canon === c.canonical);
    total++;
    if (match) matched++;
    else fails.push(`[${sec}] ${c.note}`);
  }
}
for (const f of fails) console.log(`FAIL  ${f}`);
console.log(`\ntypescript (sfv): ${matched}/${total} cases matched`);
process.exit(matched === total ? 0 : 1);
