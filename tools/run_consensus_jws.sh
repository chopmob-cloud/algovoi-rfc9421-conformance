#!/usr/bin/env bash
# N-way consensus driver for the JSON Web Signature corpus (jws_v0).
#
# Runs every language runner against the ONE frozen, signed corpus and requires
# that all of them reproduce it. Each runner exits 0 iff it matched every case;
# because the frozen corpus is the shared oracle, every runner passing means all
# runners agree byte-for-byte per case. Fail-closed:
#
#   - a runner whose toolchain/deps are missing is ABSENT (it shrinks N);
#   - a runner that ran but did not fully match is a consensus FAIL;
#   - fewer than --require runners present -> NOT GREEN;
#   - any present runner FAIL              -> NOT GREEN.
#
# The go and rust jws runners are self-contained IN this repo (runners/go/verify_jws_go.go
# and the runners/rust-jws crate), so they run directly.
#
# Usage:  tools/run_consensus_jws.sh [--require N]
# Env:    ALGOVOI_JWS  corpus path (default: repo corpus)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${ALGOVOI_JWS:-$HERE/corpus/jws_v0/jws_v0.json}"
REQUIRE=12
[ "${1:-}" = "--require" ] && REQUIRE="${2:-12}"

LANGS=(python typescript go rust c java kotlin scala dotnet ruby php elixir)

have() { command -v "$1" >/dev/null 2>&1; }
PY="$(command -v python3 || command -v python || true)"

run_lang() {
  case "$1" in
    python)
      [ -n "$PY" ] || { echo "ABSENT: no python"; return; }
      "$PY" "$HERE/runners/python/verify_jws.py" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    typescript)
      have node || { echo "ABSENT: no node"; return; }
      node "$HERE/runners/typescript/verify_jws.mjs" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    go)
      have go || { echo "ABSENT: no go"; return; }
      [ -f "$HERE/runners/go/verify_jws_go.go" ] || { echo "ABSENT: go runner not present"; return; }
      ( cd "$HERE/runners/go" && GOTOOLCHAIN=local go run verify_jws_go.go "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    rust)
      have cargo || { echo "ABSENT: no cargo"; return; }
      [ -f "$HERE/runners/rust-jws/Cargo.toml" ] || { echo "ABSENT: rust-jws crate not present"; return; }
      ( cd "$HERE/runners/rust-jws" && cargo run -q -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    c)
      { have cc && pkg-config --exists jansson 2>/dev/null; } || { echo "ABSENT: no cc/jansson"; return; }
      [ -f "$HERE/runners/c/verify_jws.c" ] || { echo "ABSENT: c runner not present"; return; }
      ( cd "$HERE/runners/c" && cc -O2 -w -o verify_jws verify_jws.c $(pkg-config --cflags --libs jansson) -lcrypto && ./verify_jws "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    java)
      have javac && have java || { echo "ABSENT: no jdk"; return; }
      d="$HERE/runners/java"
      [ -f "$d/VerifyJws.java" ] || { echo "ABSENT: java runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/java/libs"; return; }
      ( cd "$d" && javac -cp "libs/*" VerifyJws.java && java -cp ".:libs/*" VerifyJws "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    kotlin)
      have kotlinc && have java || { echo "ABSENT: no kotlinc/java"; return; }
      d="$HERE/runners/kotlin"
      [ -f "$d/VerifyJws.kt" ] || { echo "ABSENT: kotlin runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/kotlin/libs"; return; }
      cp="$(ls "$d"/libs/*.jar | tr '\n' ':')"
      ( cd "$d" && kotlinc VerifyJws.kt -cp "$cp" -include-runtime -d verifyjws.jar >/dev/null 2>&1 && java -cp "verifyjws.jar:$cp" VerifyJwsKt "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    scala)
      have scala-cli || { echo "ABSENT: no scala-cli"; return; }
      [ -f "$HERE/runners/scala/verify_jws.scala" ] || { echo "ABSENT: scala runner not present"; return; }
      ( cd "$HERE/runners/scala" && scala-cli run --server=false verify_jws.scala -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    dotnet)
      have dotnet || { echo "ABSENT: no dotnet"; return; }
      [ -f "$HERE/runners/dotnet-jws/verify_jws.csproj" ] || { echo "ABSENT: dotnet-jws project not present"; return; }
      ( cd "$HERE/runners/dotnet-jws" && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet run -c Release --verbosity quiet -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    ruby)
      have ruby || { echo "ABSENT: no ruby"; return; }
      [ -f "$HERE/runners/ruby/verify_jws.rb" ] || { echo "ABSENT: ruby runner not present"; return; }
      ruby "$HERE/runners/ruby/verify_jws.rb" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    php)
      have php || { echo "ABSENT: no php"; return; }
      [ -f "$HERE/runners/php/verify_jws.php" ] || { echo "ABSENT: php runner not present"; return; }
      php "$HERE/runners/php/verify_jws.php" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    elixir)
      have elixir || { echo "ABSENT: no elixir"; return; }
      [ -f "$HERE/runners/elixir/verify_jws.exs" ] || { echo "ABSENT: elixir runner not present"; return; }
      elixir "$HERE/runners/elixir/verify_jws.exs" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
  esac
}

echo "N-way consensus over jws_v0 (require ${REQUIRE})"
echo "corpus: $CORPUS"
echo "----------------------------------------------------------------"

# KAT integrity gate (fail-closed): the corpus must be the exact signed artifact
# and every verdict independently re-derivable, so a systematic error shared by
# the generator and every runner cannot pass as consensus. SKIP_KAT=1 is used only
# by the mutation test (which feeds a deliberately mutated corpus).
if [ "${SKIP_KAT:-0}" != 1 ] && [ -n "$PY" ]; then
  if ! "$PY" "$HERE/tools/check_kat_jws.py" "$CORPUS"; then
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
echo "RESULT: FULL ${present}-WAY CONSENSUS -- every implementation reproduces every case"
exit 0
