#!/usr/bin/env bash
# N-way consensus driver for the Structured Field Values corpus (sfv_v0).
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
# The go/rust/typescript/ruby/php sfv runners depend on a third-party RFC 8941
# library, which each language step installs in a scratch dir. This is the "fast
# signal where the host toolchain permits"; the authoritative gate is the hermetic
# Docker cells (kaf/run_cells_sfv.sh).
#
# Usage:  tools/run_consensus_sfv.sh [--require N]
# Env:    ALGOVOI_SFV  corpus path (default: repo corpus)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${ALGOVOI_SFV:-$HERE/corpus/sfv_v0/sfv_v0.json}"
REQUIRE=12
[ "${1:-}" = "--require" ] && REQUIRE="${2:-12}"

LANGS=(python typescript go rust c java kotlin scala dotnet ruby php elixir)

have() { command -v "$1" >/dev/null 2>&1; }
PY="$(command -v python3 || command -v python || true)"

run_lang() {
  case "$1" in
    python)
      [ -n "$PY" ] || { echo "ABSENT: no python"; return; }
      "$PY" "$HERE/runners/python/verify_sfv.py" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    typescript)
      have node && have npm || { echo "ABSENT: no node/npm"; return; }
      d="$(mktemp -d)"
      cp "$HERE/runners/typescript/verify_sfv.mjs" "$d/"
      ( cd "$d" && npm init -y >/dev/null 2>&1 && npm i structured-headers >/dev/null 2>&1 \
          && node "$d/verify_sfv.mjs" "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL
      rm -rf "$d" ;;
    go)
      have go || { echo "ABSENT: no go"; return; }
      [ -f "$HERE/runners/go/verify_sfv_go.go" ] || { echo "ABSENT: go runner not present"; return; }
      d="$(mktemp -d)"
      cp "$HERE/runners/go/verify_sfv_go.go" "$d/"
      ( cd "$d" && GOCACHE="$d/gc" GOPATH="$d/gp" HOME="$d" go mod init sfvc >/dev/null 2>&1 \
          && GOCACHE="$d/gc" GOPATH="$d/gp" HOME="$d" go get github.com/dunglas/httpsfv >/dev/null 2>&1 \
          && GOCACHE="$d/gc" GOPATH="$d/gp" HOME="$d" GOTOOLCHAIN=local go run verify_sfv_go.go "$CORPUS" ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL
      rm -rf "$d" ;;
    rust)
      have cargo || { echo "ABSENT: no cargo"; return; }
      [ -f "$HERE/runners/rust-sfv/Cargo.toml" ] || { echo "ABSENT: rust-sfv crate not present"; return; }
      ( cd "$HERE/runners/rust-sfv" && cargo run -q -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    c)
      { have cc && pkg-config --exists jansson 2>/dev/null; } || { echo "ABSENT: no cc/jansson"; return; }
      [ -f "$HERE/runners/c/verify_sfv.c" ] || { echo "ABSENT: c runner not present"; return; }
      ( cd "$HERE/runners/c" && cc -O2 -w -o verify_sfv verify_sfv.c $(pkg-config --cflags --libs jansson) && ./verify_sfv "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    java)
      have javac && have java || { echo "ABSENT: no jdk"; return; }
      d="$HERE/runners/java"
      [ -f "$d/VerifySfv.java" ] || { echo "ABSENT: java runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/java/libs"; return; }
      ( cd "$d" && javac -cp "libs/*" VerifySfv.java && java -cp ".:libs/*" VerifySfv "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    kotlin)
      have kotlinc && have java || { echo "ABSENT: no kotlinc/java"; return; }
      d="$HERE/runners/kotlin"
      [ -f "$d/VerifySfv.kt" ] || { echo "ABSENT: kotlin runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jars into runners/kotlin/libs"; return; }
      cp="$(ls "$d"/libs/*.jar | tr '\n' ':')"
      ( cd "$d" && kotlinc VerifySfv.kt -cp "$cp" -include-runtime -d verifysfv.jar >/dev/null 2>&1 && java -cp "verifysfv.jar:$cp" VerifySfvKt "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    scala)
      have scala-cli || { echo "ABSENT: no scala-cli"; return; }
      [ -f "$HERE/runners/scala/verify_sfv.scala" ] || { echo "ABSENT: scala runner not present"; return; }
      ( cd "$HERE/runners/scala" && scala-cli run --server=false verify_sfv.scala -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    dotnet)
      have dotnet || { echo "ABSENT: no dotnet"; return; }
      [ -f "$HERE/runners/dotnet-sfv/verify_sfv.csproj" ] || { echo "ABSENT: dotnet-sfv project not present"; return; }
      ( cd "$HERE/runners/dotnet-sfv" && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet run -c Release --verbosity quiet -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    ruby)
      have ruby || { echo "ABSENT: no ruby"; return; }
      [ -f "$HERE/runners/ruby/verify_sfv.rb" ] || { echo "ABSENT: ruby runner not present"; return; }
      ruby -e "require 'starry'" >/dev/null 2>&1 || { echo "ABSENT: gem install starry"; return; }
      ruby "$HERE/runners/ruby/verify_sfv.rb" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    php)
      have php || { echo "ABSENT: no php"; return; }
      [ -f "$HERE/runners/php/verify_sfv.php" ] || { echo "ABSENT: php runner not present"; return; }
      have composer || { echo "ABSENT: no composer for bakame/http-structured-fields"; return; }
      d="$(mktemp -d)"
      ( cd "$d" && composer require bakame/http-structured-fields >/dev/null 2>&1 \
          && SFV_VENDOR="$d/vendor/autoload.php" php "$HERE/runners/php/verify_sfv.php" "$CORPUS" ) >/dev/null 2>&1 \
        && echo PASS || echo FAIL
      rm -rf "$d" ;;
    elixir)
      have elixir || { echo "ABSENT: no elixir"; return; }
      [ -f "$HERE/runners/elixir/verify_sfv.exs" ] || { echo "ABSENT: elixir runner not present"; return; }
      elixir "$HERE/runners/elixir/verify_sfv.exs" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
  esac
}

echo "N-way consensus over sfv_v0 (require ${REQUIRE})"
echo "corpus: $CORPUS"
echo "----------------------------------------------------------------"

# KAT integrity gate (fail-closed): the corpus must be the exact signed artifact
# and every verdict independently re-derivable with a separate implementation
# (http_sfv), so a systematic error shared by the generator and every runner
# cannot pass as consensus. SKIP_KAT=1 is used only by the mutation test.
if [ "${SKIP_KAT:-0}" != 1 ] && [ -n "$PY" ]; then
  if ! "$PY" "$HERE/tools/check_kat_sfv.py" "$CORPUS"; then
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
