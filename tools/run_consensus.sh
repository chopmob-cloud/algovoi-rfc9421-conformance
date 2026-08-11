#!/usr/bin/env bash
# N-way consensus driver for rfc9421_negative_v1.
#
# Runs every language runner against the ONE frozen, signed corpus and requires
# that all of them reproduce it. Each runner exits 0 iff it matched all 78 cases;
# because the frozen corpus is the shared oracle, every runner passing means all
# runners agree byte-for-byte per case. Fail-closed:
#
#   - a runner whose toolchain/deps are missing is ABSENT (it shrinks N);
#   - a runner that ran but did not fully match is a consensus FAIL;
#   - fewer than --require runners present  -> NOT GREEN;
#   - any present runner FAIL               -> NOT GREEN.
#
# This prevents a missing toolchain from silently shrinking the field while still
# "passing", the same integrity property the JCS differential substrate enforces.
#
# Usage:  tools/run_consensus.sh [--require N]
# Env:    ALGOVOI_NEGATIVE_V1  corpus path (default: repo corpus)
#         VGO_DIR / VRS_DIR    checkouts of the go / rust verifier repos
#                              (default: sibling dirs next to this repo)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # repo root
CORPUS="${ALGOVOI_NEGATIVE_V1:-$HERE/corpus/rfc9421_negative_v1/rfc9421_negative_v1.json}"
REQUIRE=10
[ "${1:-}" = "--require" ] && REQUIRE="${2:-10}"

VGO_DIR="${VGO_DIR:-$HERE/../algovoi-rfc9421-verifier-go}"
VRS_DIR="${VRS_DIR:-$HERE/../algovoi-rfc9421-verifier-rs}"

# ordered: the ten independent implementations
LANGS=(python typescript go rust java kotlin dotnet ruby php elixir)

have() { command -v "$1" >/dev/null 2>&1; }

# echo "PASS" | "FAIL" | "ABSENT: <why>" for one language
run_lang() {
  case "$1" in
    python)
      have python3 || { echo "ABSENT: no python3"; return; }
      python3 "$HERE/runners/python/verify_py.py" "$CORPUS" >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    typescript)
      have node || { echo "ABSENT: no node"; return; }
      [ -d "$HERE/runners/typescript/node_modules" ] || { echo "ABSENT: run npm install in runners/typescript"; return; }
      node "$HERE/runners/typescript/verify_ts.mjs" "$CORPUS" >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    go)
      have go || { echo "ABSENT: no go"; return; }
      [ -d "$VGO_DIR/ecdsa" ] || { echo "ABSENT: VGO_DIR not a verifier-go checkout"; return; }
      ( cd "$VGO_DIR" && GOTOOLCHAIN=local ALGOVOI_NEGATIVE_V1="$CORPUS" \
          go test ./ecdsa -run TestNegativeV1 ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    rust)
      have cargo || { echo "ABSENT: no cargo"; return; }
      [ -f "$VRS_DIR/Cargo.toml" ] || { echo "ABSENT: VRS_DIR not a verifier-rs checkout"; return; }
      ( cd "$VRS_DIR" && ALGOVOI_NEGATIVE_V1="$CORPUS" \
          cargo test -q -p algovoi-rfc9421-ecdsa --test negative_v1 ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    java)
      have javac && have java || { echo "ABSENT: no jdk"; return; }
      local d="$HERE/runners/java"
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/java/libs"; return; }
      ( cd "$d" && javac -cp "libs/*" NegativeV1.java && java -cp ".:libs/*" NegativeV1 "$CORPUS" ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    kotlin)
      have kotlinc && have java || { echo "ABSENT: no kotlinc/java"; return; }
      local d="$HERE/runners/kotlin"
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/kotlin/libs"; return; }
      local cp; cp="$(ls "$d"/libs/*.jar | tr '\n' ':')"
      ( cd "$d" && kotlinc NegativeV1.kt -cp "$cp" -include-runtime -d negativev1.jar >/dev/null 2>&1 \
          && java -cp "negativev1.jar:$cp" NegativeV1Kt "$CORPUS" ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    dotnet)
      have dotnet || { echo "ABSENT: no dotnet"; return; }
      ( cd "$HERE/runners/dotnet" && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
          dotnet run -c Release --verbosity quiet -- "$CORPUS" ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    ruby)
      have ruby || { echo "ABSENT: no ruby"; return; }
      ruby "$HERE/runners/ruby/negative_v1.rb" "$CORPUS" >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    php)
      have php || { echo "ABSENT: no php"; return; }
      php "$HERE/runners/php/negative_v1.php" "$CORPUS" >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
    elixir)
      have elixir || { echo "ABSENT: no elixir"; return; }
      elixir "$HERE/runners/elixir/negative_v1.exs" "$CORPUS" >/dev/null 2>&1 \
        && echo PASS || echo FAIL ;;
  esac
}

echo "N-way consensus over rfc9421_negative_v1 (require ${REQUIRE})"
echo "corpus: $CORPUS"
echo "----------------------------------------------------------------"

# KAT integrity gate (fail-closed): the corpus must be the exact signed artifact
# and its signing bases must match independent, hand-derived anchors, so a
# systematic error shared by the generator and every runner cannot pass as
# consensus. Runs before the runners; a KAT failure is NOT GREEN on its own.
if have python3; then
  if ! python3 "$HERE/tools/check_kat.py"; then
    echo "RESULT: NOT GREEN -- KAT integrity gate failed"
    exit 1
  fi
  echo "----------------------------------------------------------------"
fi

present=0; passed=0; failed_langs=""
for lang in "${LANGS[@]}"; do
  verdict="$(run_lang "$lang")"
  printf "  %-11s %s\n" "$lang" "$verdict"
  case "$verdict" in
    PASS) present=$((present+1)); passed=$((passed+1)) ;;
    FAIL) present=$((present+1)); failed_langs="$failed_langs $lang" ;;
  esac
done
echo "----------------------------------------------------------------"
echo "present: ${present}/${#LANGS[@]}   passed: ${passed}   require: ${REQUIRE}"

if [ -n "$failed_langs" ]; then
  echo "RESULT: NOT GREEN -- consensus FAIL in:${failed_langs}"
  exit 1
fi
if [ "$present" -lt "$REQUIRE" ]; then
  echo "RESULT: NOT GREEN -- only ${present} implementations present, require ${REQUIRE}"
  exit 1
fi
echo "RESULT: FULL ${present}-WAY CONSENSUS -- every implementation reproduces all 78 cases"
exit 0
