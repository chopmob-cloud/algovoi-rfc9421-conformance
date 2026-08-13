#!/usr/bin/env bash
# N-way consensus driver for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
#
# Runs every covered-language runner against the ONE frozen, signed corpus and
# requires that all of them reproduce it. Each runner exits 0 iff it matched every
# case; because the frozen corpus is the shared oracle, every runner passing means
# all runners agree byte-for-byte per case. Fail-closed:
#
#   - a runner whose toolchain/deps are missing is ABSENT (it shrinks N);
#   - a runner that ran but did not fully match is a consensus FAIL;
#   - fewer than --require runners present -> NOT GREEN;
#   - any present runner FAIL              -> NOT GREEN.
#
# Coverage is a DOCUMENTED SUBSET, not a fixed 12: --require defaults to 9, the
# count of languages with a mature FIPS-204 (not round-3 Dilithium) ML-DSA-65
# verify library. ruby, php and elixir are DEFERRED (see the note printed below):
# no mature FIPS-204 ML-DSA library installs cleanly in their pinned runtimes,
# whose bundled OpenSSL predates ML-DSA (added in OpenSSL 3.5). The hermetic Docker
# proof lives in kaf/run_cells_pqc_mldsa.sh; this host driver needs the toolchains
# and one ML-DSA library per language present locally.
#
# Usage:  tools/run_consensus_pqc_mldsa.sh [--require N]
# Env:    ALGOVOI_PQC_MLDSA  corpus path (default: repo corpus)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="${ALGOVOI_PQC_MLDSA:-$HERE/corpus/pqc_mldsa_v0/pqc_mldsa_v0.json}"
REQUIRE=9
[ "${1:-}" = "--require" ] && REQUIRE="${2:-9}"

LANGS=(python typescript go rust c java kotlin scala dotnet)
DEFERRED=(ruby php elixir)

have() { command -v "$1" >/dev/null 2>&1; }
PY="$(command -v python3 || command -v python || true)"

run_lang() {
  case "$1" in
    python)
      [ -n "$PY" ] || { echo "ABSENT: no python"; return; }
      "$PY" "$HERE/runners/python/verify_pqc_mldsa.py" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    typescript)
      have node || { echo "ABSENT: no node"; return; }
      [ -d "$HERE/runners/typescript/node_modules/@noble/post-quantum" ] || { echo "ABSENT: npm i @noble/post-quantum in runners/typescript"; return; }
      node "$HERE/runners/typescript/verify_pqc_mldsa.mjs" "$CORPUS" >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    go)
      have go || { echo "ABSENT: no go"; return; }
      [ -f "$HERE/runners/go/verify_pqc_mldsa_go.go" ] || { echo "ABSENT: go runner not present"; return; }
      d="$(mktemp -d)"; cp "$HERE/runners/go/verify_pqc_mldsa_go.go" "$d/main.go"
      ( cd "$d" && GOTOOLCHAIN=local go mod init pqcrun >/dev/null 2>&1 && go get github.com/cloudflare/circl@v1.6.5 >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1 && go run main.go "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL
      rm -rf "$d" ;;
    rust)
      have cargo || { echo "ABSENT: no cargo"; return; }
      [ -f "$HERE/runners/rust-pqc-mldsa/Cargo.toml" ] || { echo "ABSENT: rust-pqc-mldsa crate not present"; return; }
      ( cd "$HERE/runners/rust-pqc-mldsa" && cargo run -q -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    c)
      { have cc && pkg-config --exists jansson 2>/dev/null && [ -f /usr/local/include/oqs/oqs.h -o -f /usr/include/oqs/oqs.h ]; } || { echo "ABSENT: no cc/jansson/liboqs"; return; }
      [ -f "$HERE/runners/c/verify_pqc_mldsa.c" ] || { echo "ABSENT: c runner not present"; return; }
      ( cd "$HERE/runners/c" && cc -O2 -w -o verify_pqc_mldsa verify_pqc_mldsa.c $(pkg-config --cflags --libs jansson) -loqs -lcrypto && ./verify_pqc_mldsa "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    java)
      have javac && have java || { echo "ABSENT: no jdk"; return; }
      d="$HERE/runners/java"
      [ -f "$d/VerifyPqcMldsa.java" ] || { echo "ABSENT: java runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch org.json + bcprov-jdk18on(>=1.81) jars into runners/java/libs"; return; }
      cp="$(ls "$d"/libs/*.jar | tr '\n' ':')"
      ( cd "$d" && javac -cp "$cp" VerifyPqcMldsa.java && java -cp ".:$cp" VerifyPqcMldsa "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    kotlin)
      have kotlinc && have java || { echo "ABSENT: no kotlinc/java"; return; }
      d="$HERE/runners/kotlin"
      [ -f "$d/VerifyPqcMldsa.kt" ] || { echo "ABSENT: kotlin runner not present"; return; }
      ls "$d"/libs/*.jar >/dev/null 2>&1 || { echo "ABSENT: fetch jackson + bcprov-jdk18on(>=1.81) jars into runners/kotlin/libs"; return; }
      cp="$(ls "$d"/libs/*.jar | tr '\n' ':')"
      ( cd "$d" && kotlinc VerifyPqcMldsa.kt -cp "$cp" -include-runtime -d vpm.jar >/dev/null 2>&1 && java -cp "vpm.jar:$cp" VerifyPqcMldsaKt "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    scala)
      have scala-cli || { echo "ABSENT: no scala-cli"; return; }
      [ -f "$HERE/runners/scala/verify_pqc_mldsa.scala" ] || { echo "ABSENT: scala runner not present"; return; }
      ( cd "$HERE/runners/scala" && scala-cli run --server=false verify_pqc_mldsa.scala -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
    dotnet)
      have dotnet || { echo "ABSENT: no dotnet"; return; }
      [ -f "$HERE/runners/dotnet-pqc-mldsa/verify_pqc_mldsa.csproj" ] || { echo "ABSENT: dotnet-pqc-mldsa project not present"; return; }
      ( cd "$HERE/runners/dotnet-pqc-mldsa" && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet run -c Release --verbosity quiet -- "$CORPUS" ) >/dev/null 2>&1 && echo PASS || echo FAIL ;;
  esac
}

echo "N-way consensus over pqc_mldsa_v0 (require ${REQUIRE})"
echo "corpus: $CORPUS"
echo "----------------------------------------------------------------"

# KAT integrity gate (fail-closed): the corpus must be the exact signed artifact
# and every verdict independently re-derivable with a SEPARATE FIPS-204 ML-DSA-65
# implementation (dilithium-py), so a Dilithium-vs-ML-DSA scheme error shared by
# the generator and every runner cannot pass as consensus. SKIP_KAT=1 is used only
# by the mutation test (which feeds a deliberately mutated corpus).
if [ "${SKIP_KAT:-0}" != 1 ] && [ -n "$PY" ]; then
  if ! "$PY" "$HERE/tools/check_kat_pqc_mldsa.py" "$CORPUS"; then
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
echo "DEFERRED (no mature FIPS-204 ML-DSA-65 library that installs cleanly):"
for lang in "${DEFERRED[@]}"; do
  printf "  %-11s %s\n" "$lang" "ABSENT/deferred: bundled OpenSSL predates ML-DSA (OpenSSL 3.5); no pure-language FIPS-204 lib"
done
echo "----------------------------------------------------------------"
echo "present: ${present}/${#LANGS[@]}   passed: ${passed}   require: ${REQUIRE}   deferred: ${#DEFERRED[@]} (ruby php elixir)"

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
