#!/usr/bin/env bash
# KAF cell runner for the Structured Field Values corpus (sfv_v0).
#
# Runs each language's sfv runner against the one frozen, signed corpus inside its
# pinned Docker image, so the byte-for-byte verdict is shown to hold in a clean,
# independent runtime (the KAF "Cells" axis). Each cell installs/builds its sfv
# dependency fresh in-container:
#
#   - python : hand-rolled reference (tools/oracle_sfv.py), no third-party dep;
#   - node   : structured-headers (npm);
#   - go     : github.com/dunglas/httpsfv (isolated temp module);
#   - ruby   : starry (gem);
#   - php    : bakame/http-structured-fields (composer);
#   - rust/c/java/kotlin/scala/dotnet/elixir : a hand-rolled RFC 8941 parser +
#     canonical serializer (no canonical native library ships for these), needing
#     only the JSON library the sibling wba runners already use.
#
# Env:
#   REPO   conformance repo checkout       (default: this repo)
#   CELLS  space-separated cell ids to run (default: all)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${REPO:-$HERE}"
CORPUS="${CORPUS:-corpus/sfv_v0/sfv_v0.json}"
CORPUS_IN="/work/$CORPUS"
RESULTS="$HERE/kaf/cells_sfv.results.json"

ALL_CELLS="python-3.12-slim node-20-slim go-1.26-bookworm rust-1-slim gcc-14-c temurin-17-java temurin-17-kotlin temurin-17-scala dotnet-sdk-9.0 ruby-3.2-slim php-8.3-cli elixir-1.16-otp26"
CELLS="${CELLS:-$ALL_CELLS}"

M2="https://repo1.maven.org/maven2"
JACKSON=2.17.0

image_for() {
  case "$1" in
    python-3.12-slim)  echo "python:3.12-slim" ;;
    node-20-slim)      echo "node:20-slim" ;;
    go-1.26-bookworm)  echo "golang:1.26-bookworm" ;;
    rust-1-slim)       echo "rust:1-slim-bookworm" ;;
    gcc-14-c)          echo "gcc:14-bookworm" ;;
    temurin-17-java|temurin-17-kotlin|temurin-17-scala) echo "eclipse-temurin:17" ;;
    dotnet-sdk-9.0)    echo "mcr.microsoft.com/dotnet/sdk:9.0" ;;
    ruby-3.2-slim)     echo "ruby:3.2-slim" ;;
    php-8.3-cli)       echo "php:8.3-cli" ;;
    elixir-1.16-otp26) echo "elixir:1.16-otp-26" ;;
  esac
}

lang_for() {
  case "$1" in
    python-3.12-slim) echo python ;;
    node-20-slim) echo typescript ;;
    go-1.26-bookworm) echo go ;;
    rust-1-slim) echo rust ;;
    gcc-14-c) echo c ;;
    temurin-17-java) echo java ;;
    temurin-17-kotlin) echo kotlin ;;
    temurin-17-scala) echo scala ;;
    dotnet-sdk-9.0) echo dotnet ;;
    ruby-3.2-slim) echo ruby ;;
    php-8.3-cli) echo php ;;
    elixir-1.16-otp26) echo elixir ;;
  esac
}

cmd_for() {
  case "$1" in
    python-3.12-slim)
      echo 'python /work/runners/python/verify_sfv.py '"$CORPUS_IN" ;;
    node-20-slim)
      echo 'cd /tmp && npm init -y >/dev/null 2>&1 && npm i structured-headers >/dev/null 2>&1 && cp /work/runners/typescript/verify_sfv.mjs . && node verify_sfv.mjs '"$CORPUS_IN" ;;
    go-1.26-bookworm)
      echo 'export GOCACHE=/tmp/gc GOPATH=/tmp/gp HOME=/tmp && mkdir -p /tmp/gs && cp /work/runners/go/verify_sfv_go.go /tmp/gs/ && cd /tmp/gs && go mod init sfvc >/dev/null 2>&1 && go get github.com/dunglas/httpsfv >/dev/null 2>&1 && GOTOOLCHAIN=local go run verify_sfv_go.go '"$CORPUS_IN" ;;
    rust-1-slim)
      echo 'export CARGO_HOME=/tmp/ch CARGO_TARGET_DIR=/tmp/tgt && cp -r /work/runners/rust-sfv /tmp/rs && cd /tmp/rs && cargo run -q -- '"$CORPUS_IN" ;;
    gcc-14-c)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libjansson-dev pkg-config >/dev/null && cd /tmp && cp /work/runners/c/verify_sfv.c . && cc -O2 -w -o vs verify_sfv.c $(pkg-config --cflags --libs jansson) && ./vs '"$CORPUS_IN" ;;
    temurin-17-java)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && cd /tmp && cp /work/runners/java/VerifySfv.java . && curl -fsSL '"$M2"'/org/json/json/20240303/json-20240303.jar -o json.jar && javac -cp json.jar VerifySfv.java && java -cp ".:json.jar" VerifySfv '"$CORPUS_IN" ;;
    temurin-17-kotlin)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl unzip >/dev/null && curl -fsSL -o /tmp/k.zip https://github.com/JetBrains/kotlin/releases/download/v2.0.20/kotlin-compiler-2.0.20.zip && unzip -q /tmp/k.zip -d /opt && cd /tmp && mkdir -p libs && for u in '"$M2"'/com/fasterxml/jackson/core/jackson-databind/'"$JACKSON"'/jackson-databind-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-core/'"$JACKSON"'/jackson-core-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-annotations/'"$JACKSON"'/jackson-annotations-'"$JACKSON"'.jar; do curl -fsSL "$u" -o "libs/$(basename $u)"; done && cp /work/runners/kotlin/VerifySfv.kt . && CP=$(ls libs/*.jar | tr "\n" ":") && /opt/kotlinc/bin/kotlinc VerifySfv.kt -cp "$CP" -include-runtime -d vs.jar >/dev/null 2>&1 && java -cp "vs.jar:$CP" VerifySfvKt '"$CORPUS_IN" ;;
    temurin-17-scala)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && curl -fsLo /tmp/scala-cli.gz https://github.com/VirtusLab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz && gzip -df /tmp/scala-cli.gz && chmod +x /tmp/scala-cli && cp /work/runners/scala/verify_sfv.scala /tmp/ && cd /tmp && HOME=/tmp /tmp/scala-cli run --server=false verify_sfv.scala -- '"$CORPUS_IN" ;;
    dotnet-sdk-9.0)
      echo 'export HOME=/tmp DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 && mkdir -p /tmp/dn && cp /work/runners/dotnet-sfv/Program.cs /work/runners/dotnet-sfv/verify_sfv.csproj /tmp/dn/ && cd /tmp/dn && dotnet run -c Release --verbosity quiet -- '"$CORPUS_IN" ;;
    ruby-3.2-slim)
      echo 'gem install starry >/dev/null 2>&1 && ruby /work/runners/ruby/verify_sfv.rb '"$CORPUS_IN" ;;
    php-8.3-cli)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q git unzip curl >/dev/null && curl -sS https://getcomposer.org/installer | php >/dev/null 2>&1 && mkdir -p /tmp/sfv && cd /tmp/sfv && php /composer.phar require bakame/http-structured-fields >/dev/null 2>&1 && SFV_VENDOR=/tmp/sfv/vendor/autoload.php php /work/runners/php/verify_sfv.php '"$CORPUS_IN" ;;
    elixir-1.16-otp26)
      echo 'export HOME=/tmp MIX_HOME=/tmp/.mix HEX_HOME=/tmp/.hex && mix local.hex --force >/dev/null 2>&1 && elixir /work/runners/elixir/verify_sfv.exs '"$CORPUS_IN" ;;
  esac
}

echo "KAF cells for sfv_v0"
echo "repo: $REPO"
echo "================================================================"
results="[]"
for cell in $CELLS; do
  image="$(image_for "$cell")"
  lang="$(lang_for "$cell")"
  printf "  %-20s %-32s " "$cell" "$image"
  if docker run --rm -v "$REPO":/work:ro "$image" \
        sh -c "$(cmd_for "$cell")" >/tmp/cell_sfv_"$cell".log 2>&1; then
    verdict=PASS
  else
    verdict=FAIL
  fi
  digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$image" 2>/dev/null)"
  echo "$verdict"
  [ "$verdict" = FAIL ] && tail -4 /tmp/cell_sfv_"$cell".log | sed 's/^/       /'
  results="$(printf '%s' "$results" | python3 -c "import json,sys; a=json.load(sys.stdin); a.append({'cell':'$cell','lang':'$lang','image':'$image','image_digest':'''$digest''','verdict':'$verdict'}); print(json.dumps(a))")"
done
echo "================================================================"
printf '%s' "$results" | python3 -m json.tool > "$RESULTS"
passed="$(printf '%s' "$results" | python3 -c "import json,sys; print(sum(1 for c in json.load(sys.stdin) if c['verdict']=='PASS'))")"
total="$(printf '%s' "$results" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
echo "cells passed: $passed/$total   -> $RESULTS"
[ "$passed" = "$total" ] && [ "$total" -gt 0 ]
