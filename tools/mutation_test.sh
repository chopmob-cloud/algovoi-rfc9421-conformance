#!/usr/bin/env bash
# Mutation meta-test: prove the byte-for-byte gate has teeth.
#
# A consensus battery is only meaningful if the runners genuinely COMPUTE each
# verdict rather than echo the corpus's expected value (a runner that just
# returned expect_valid would "pass" every case while verifying nothing). This
# test flips one expected verdict in each section, feeds the mutated corpus to
# every runner (KAT gate skipped, since it would reject the edit first), and
# requires the consensus to go NOT GREEN each time -- i.e. the runners detect the
# mutation. A mutation the runners do NOT catch is a fail-open / echoing runner.
#
# Env: same as tools/run_consensus.sh (VGO_DIR, VRS_DIR, PATH for toolchains).
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${ALGOVOI_NEGATIVE_V1:-$HERE/corpus/rfc9421_negative_v1/rfc9421_negative_v1.json}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# each mutation: "section:index:field:newvalue" -- flips one frozen expectation.
MUTATIONS=(
  "signing_base:0:ok:false"                  # a positive build now marked non-ok
  "signature_input_parse:0:ok:flip"          # flip a parse expectation
  "signature_value_parse:0:ok:flip"          # flip a parse expectation
  "keygate:0:small_order:flip"               # lie about small-order-ness
  "ed25519_verify:0:expect_valid:flip"       # lie about a signature verdict
  "ecdsa_verify:0:expect_valid:flip"         # lie about a signature verdict
)

mutate() { # <spec> -> writes mutated corpus to $TMP/mut.json, echoes a label
  python3 - "$CORPUS" "$TMP/mut.json" "$1" <<'PY'
import json, sys
src, dst, spec = sys.argv[1], sys.argv[2], sys.argv[3]
section, idx, field, val = spec.split(":")
d = json.load(open(src, encoding="utf-8"))
case = d[section][int(idx)]
cur = case.get(field)
if val == "flip":
    case[field] = (not cur) if isinstance(cur, bool) else (None if cur else "WeakKeyError")
elif val == "true":
    case[field] = True
elif val == "false":
    case[field] = False
json.dump(d, open(dst, "w", encoding="utf-8"), ensure_ascii=False)
print(f"{section}[{idx}].{field}: {cur!r} -> {case[field]!r}")
PY
}

echo "Mutation meta-test: every flipped expectation must be caught (NOT GREEN)"
echo "================================================================"
overall=0
for spec in "${MUTATIONS[@]}"; do
  label="$(mutate "$spec")"
  out="$(SKIP_KAT=1 ALGOVOI_NEGATIVE_V1="$TMP/mut.json" bash "$HERE/tools/run_consensus.sh" --require 1 2>&1)"
  if printf '%s' "$out" | grep -q "NOT GREEN"; then
    caught="$(printf '%s' "$out" | sed -n 's/.*consensus FAIL in:\s*//p')"
    n="$(printf '%s' "$caught" | wc -w)"
    printf "  CAUGHT  %-45s by %s runner(s):%s\n" "$label" "$n" "$caught"
  else
    printf "  MISSED  %-45s -- runners did NOT catch this mutation!\n" "$label"
    overall=1
  fi
done
echo "================================================================"
if [ "$overall" = 0 ]; then
  echo "RESULT: PASS -- every mutation was caught; the gate is not vacuous"
else
  echo "RESULT: FAIL -- a mutation slipped through (fail-open / echoing runner)"
fi
exit $overall
