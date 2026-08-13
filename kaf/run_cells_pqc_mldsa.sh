#!/usr/bin/env bash
# KAF cell runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
#
# Runs each language's ML-DSA-65 runner against the one frozen, signed corpus
# inside its pinned image, so the byte-for-byte verdict is shown to hold in a
# clean, independent runtime (the KAF "Cells" axis). Each cell installs/builds the
# ONE ML-DSA library it uses fresh in-container:
#
#   python  liboqs (oqs)             -- image pqc-mldsa-v0:build (liboqs preinstalled)
#   node    @noble/post-quantum 0.7.0 (pure JS)
#   go      cloudflare/circl v1.6.5
#   rust    RustCrypto ml-dsa 0.1
#   c       liboqs 0.14.0 (built minimal, SIG_ml_dsa_65 only) via the OQS C API
#   java    Bouncy Castle bcprov-jdk18on 1.81
#   kotlin  Bouncy Castle bcprov-jdk18on 1.81
#   scala   Bouncy Castle bcprov-jdk18on 1.81
#   dotnet  BouncyCastle.Cryptography 2.6.1
#   ruby    liboqs 0.14.0 via the ffi gem (OQS C API)
#   php     liboqs 0.14.0 via ext-ffi (OQS C API)
#   elixir  liboqs 0.14.0 via an Erlang port to a tiny C helper (OQS C API)
#
# Six distinct FIPS-204 implementation families cover the twelve runners (liboqs,
# noble, circl, RustCrypto, Bouncy Castle), so this is genuine multi-implementation
# consensus, not one library wrapped everywhere. ruby, php and elixir add three
# more independent language runtimes on the Cells axis: each binds the liboqs C
# reference directly (its bundled OpenSSL predates ML-DSA and no mature pure
# library exists), so they widen the runtime spread without adding a new crypto
# family. A round-3 Dilithium build would fail the valid controls; that is the
# built-in tripwire.
#
# Env:
#   REPO   conformance repo checkout       (default: this repo)
#   CELLS  space-separated cell ids to run (default: all)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${REPO:-$HERE}"
CORPUS="${CORPUS:-corpus/pqc_mldsa_v0/pqc_mldsa_v0.json}"
CORPUS_IN="/work/$CORPUS"
RESULTS="$HERE/kaf/cells_pqc_mldsa.results.json"

ALL_CELLS="pqc-python node-20-slim go-1.26-bookworm rust-1-slim gcc-14-c temurin-17-java temurin-17-kotlin temurin-17-scala dotnet-sdk-9.0 ruby-33-slim php-83-cli elixir-116-otp26"
CELLS="${CELLS:-$ALL_CELLS}"

M2="https://repo1.maven.org/maven2"
JACKSON=2.17.0
BC=1.81
NOBLE=0.7.0
CIRCL=v1.6.5
LIBOQS=0.14.0

image_for() {
  case "$1" in
    pqc-python)        echo "pqc-mldsa-v0:build" ;;
    node-20-slim)      echo "node:20-slim" ;;
    go-1.26-bookworm)  echo "golang:1.26-bookworm" ;;
    rust-1-slim)       echo "rust:1-slim-bookworm" ;;
    gcc-14-c)          echo "gcc:14-bookworm" ;;
    temurin-17-java|temurin-17-kotlin|temurin-17-scala) echo "eclipse-temurin:17" ;;
    dotnet-sdk-9.0)    echo "mcr.microsoft.com/dotnet/sdk:9.0" ;;
    ruby-33-slim)      echo "ruby:3.3-slim" ;;
    php-83-cli)        echo "php:8.3-cli" ;;
    elixir-116-otp26)  echo "elixir:1.16-otp-26" ;;
  esac
}

lang_for() {
  case "$1" in
    pqc-python) echo python ;;
    node-20-slim) echo typescript ;;
    go-1.26-bookworm) echo go ;;
    rust-1-slim) echo rust ;;
    gcc-14-c) echo c ;;
    temurin-17-java) echo java ;;
    temurin-17-kotlin) echo kotlin ;;
    temurin-17-scala) echo scala ;;
    dotnet-sdk-9.0) echo dotnet ;;
    ruby-33-slim) echo ruby ;;
    php-83-cli) echo php ;;
    elixir-116-otp26) echo elixir ;;
  esac
}

cmd_for() {
  case "$1" in
    pqc-python)
      echo 'python /work/runners/python/verify_pqc_mldsa.py '"$CORPUS_IN" ;;
    node-20-slim)
      echo 'cd /tmp && npm init -y >/dev/null 2>&1 && npm i @noble/post-quantum@'"$NOBLE"' >/dev/null 2>&1 && cp /work/runners/typescript/verify_pqc_mldsa.mjs /tmp/vpm.mjs && node /tmp/vpm.mjs '"$CORPUS_IN" ;;
    go-1.26-bookworm)
      echo 'export GOTOOLCHAIN=local GOCACHE=/tmp/gc GOPATH=/tmp/gp HOME=/tmp && mkdir -p /tmp/gr && cp /work/runners/go/verify_pqc_mldsa_go.go /tmp/gr/main.go && cd /tmp/gr && go mod init pqcrun >/dev/null 2>&1 && go get github.com/cloudflare/circl@'"$CIRCL"' >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1 && go run main.go '"$CORPUS_IN" ;;
    rust-1-slim)
      echo 'export CARGO_HOME=/tmp/ch CARGO_TARGET_DIR=/tmp/tgt && cp -r /work/runners/rust-pqc-mldsa /tmp/rw && cd /tmp/rw && cargo run -q -- '"$CORPUS_IN" ;;
    gcc-14-c)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libjansson-dev libssl-dev pkg-config cmake ninja-build git >/dev/null && cd /tmp && git clone --depth 1 --branch '"$LIBOQS"' https://github.com/open-quantum-safe/liboqs >/dev/null 2>&1 && cmake -GNinja -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65 -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -S liboqs -B liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build install >/dev/null 2>&1 && ldconfig && cp /work/runners/c/verify_pqc_mldsa.c . && cc -O2 -w -o vpm verify_pqc_mldsa.c $(pkg-config --cflags --libs jansson) -loqs -lcrypto && ./vpm '"$CORPUS_IN" ;;
    temurin-17-java)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && cd /tmp && curl -fsSL '"$M2"'/org/json/json/20240303/json-20240303.jar -o json.jar && curl -fsSL '"$M2"'/org/bouncycastle/bcprov-jdk18on/'"$BC"'/bcprov-jdk18on-'"$BC"'.jar -o bc.jar && cp /work/runners/java/VerifyPqcMldsa.java . && javac -cp "json.jar:bc.jar" VerifyPqcMldsa.java && java -cp ".:json.jar:bc.jar" VerifyPqcMldsa '"$CORPUS_IN" ;;
    temurin-17-kotlin)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl unzip >/dev/null && curl -fsSL -o /tmp/k.zip https://github.com/JetBrains/kotlin/releases/download/v2.0.20/kotlin-compiler-2.0.20.zip && unzip -q /tmp/k.zip -d /opt && cd /tmp && mkdir -p libs && for u in '"$M2"'/com/fasterxml/jackson/core/jackson-databind/'"$JACKSON"'/jackson-databind-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-core/'"$JACKSON"'/jackson-core-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-annotations/'"$JACKSON"'/jackson-annotations-'"$JACKSON"'.jar '"$M2"'/org/bouncycastle/bcprov-jdk18on/'"$BC"'/bcprov-jdk18on-'"$BC"'.jar; do curl -fsSL "$u" -o "libs/$(basename $u)"; done && cp /work/runners/kotlin/VerifyPqcMldsa.kt . && CP=$(ls libs/*.jar | tr "\n" ":") && /opt/kotlinc/bin/kotlinc VerifyPqcMldsa.kt -cp "$CP" -include-runtime -d vpm.jar >/dev/null 2>&1 && java -cp "vpm.jar:$CP" VerifyPqcMldsaKt '"$CORPUS_IN" ;;
    temurin-17-scala)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && curl -fsLo /tmp/scala-cli.gz https://github.com/VirtusLab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz && gzip -df /tmp/scala-cli.gz && chmod +x /tmp/scala-cli && cp /work/runners/scala/verify_pqc_mldsa.scala /tmp/ && cd /tmp && HOME=/tmp /tmp/scala-cli run --server=false verify_pqc_mldsa.scala -- '"$CORPUS_IN" ;;
    dotnet-sdk-9.0)
      echo 'export HOME=/tmp DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 && mkdir -p /tmp/dn && cp /work/runners/dotnet-pqc-mldsa/Program.cs /work/runners/dotnet-pqc-mldsa/verify_pqc_mldsa.csproj /tmp/dn/ && cd /tmp/dn && dotnet run -c Release --verbosity quiet -- '"$CORPUS_IN" ;;
    ruby-33-slim)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q build-essential cmake ninja-build git libffi-dev pkg-config >/dev/null && cd /tmp && git clone --depth 1 --branch '"$LIBOQS"' https://github.com/open-quantum-safe/liboqs >/dev/null 2>&1 && cmake -GNinja -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65 -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release -S liboqs -B liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build install >/dev/null 2>&1 && ldconfig && gem install ffi >/dev/null 2>&1 && ruby /work/runners/ruby/verify_pqc_mldsa.rb '"$CORPUS_IN" ;;
    php-83-cli)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q build-essential cmake ninja-build git libffi-dev pkg-config >/dev/null && docker-php-ext-install ffi >/dev/null 2>&1 && cd /tmp && git clone --depth 1 --branch '"$LIBOQS"' https://github.com/open-quantum-safe/liboqs >/dev/null 2>&1 && cmake -GNinja -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65 -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release -S liboqs -B liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build install >/dev/null 2>&1 && ldconfig && php -d ffi.enable=1 /work/runners/php/verify_pqc_mldsa.php '"$CORPUS_IN" ;;
    elixir-116-otp26)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q build-essential cmake ninja-build git >/dev/null && cd /tmp && git clone --depth 1 --branch '"$LIBOQS"' https://github.com/open-quantum-safe/liboqs >/dev/null 2>&1 && cmake -GNinja -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65 -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release -S liboqs -B liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build >/dev/null 2>&1 && ninja -C liboqs/build install >/dev/null 2>&1 && ldconfig && export HOME=/tmp MIX_HOME=/tmp/.mix HEX_HOME=/tmp/.hex && mix local.hex --force >/dev/null 2>&1 && mkdir -p /tmp/ex && cp /work/runners/elixir/verify_pqc_mldsa.exs /work/runners/elixir/mldsa_verify_helper.c /tmp/ex/ && cd /tmp/ex && elixir verify_pqc_mldsa.exs '"$CORPUS_IN" ;;
  esac
}

echo "KAF cells for pqc_mldsa_v0"
echo "repo: $REPO"
echo "================================================================"
results="[]"
for cell in $CELLS; do
  image="$(image_for "$cell")"
  lang="$(lang_for "$cell")"
  printf "  %-20s %-32s " "$cell" "$image"
  if docker run --rm -v "$REPO":/work:ro "$image" \
        sh -c "$(cmd_for "$cell")" >/tmp/cell_pqc_mldsa_"$cell".log 2>&1; then
    verdict=PASS
  else
    verdict=FAIL
  fi
  digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$image" 2>/dev/null)"
  echo "$verdict"
  [ "$verdict" = FAIL ] && tail -6 /tmp/cell_pqc_mldsa_"$cell".log | sed 's/^/       /'
  results="$(printf '%s' "$results" | python3 -c "import json,sys; a=json.load(sys.stdin); a.append({'cell':'$cell','lang':'$lang','image':'$image','image_digest':'''$digest''','verdict':'$verdict'}); print(json.dumps(a))")"
done
echo "================================================================"
printf '%s' "$results" | python3 -m json.tool > "$RESULTS"
passed="$(printf '%s' "$results" | python3 -c "import json,sys; print(sum(1 for c in json.load(sys.stdin) if c['verdict']=='PASS'))")"
total="$(printf '%s' "$results" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
echo "cells passed: $passed/$total   -> $RESULTS"
[ "$passed" = "$total" ] && [ "$total" -gt 0 ]
