#!/usr/bin/env bash
# KAF cell runner for the Web Bot Auth profile corpus (webbotauth_v0).
#
# Runs each language's wba runner against the one frozen, signed corpus inside its
# pinned Docker image, so the byte-for-byte verdict is shown to hold in a clean,
# independent runtime (the KAF "Cells" axis). Each cell installs/builds its deps
# fresh in-container. The go and rust wba runners are self-contained IN this repo,
# so unlike the negative_v* cells there are no external verifier mounts.
#
# Env:
#   REPO   conformance repo checkout       (default: this repo)
#   CELLS  space-separated cell ids to run (default: all)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${REPO:-$HERE}"
CORPUS="${CORPUS:-corpus/webbotauth_v0/webbotauth_v0.json}"
CORPUS_IN="/work/$CORPUS"
RESULTS="$HERE/kaf/cells_wba.results.json"

ALL_CELLS="python-3.12-slim node-20-slim go-1.26-bookworm rust-1-slim gcc-14-c temurin-17-java temurin-17-kotlin temurin-17-scala dotnet-sdk-9.0 ruby-3.2-slim php-8.3-cli elixir-1.16-otp26"
CELLS="${CELLS:-$ALL_CELLS}"

M2="https://repo1.maven.org/maven2"
JACKSON=2.17.0
BC=1.78.1

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
      echo 'pip install -q --root-user-action=ignore algovoi-rfc9421-verifier && python /work/runners/python/verify_wba.py '"$CORPUS_IN" ;;
    node-20-slim)
      echo 'node /work/runners/typescript/verify_wba.mjs '"$CORPUS_IN" ;;
    go-1.26-bookworm)
      echo 'export GOCACHE=/tmp/gc GOPATH=/tmp/gp HOME=/tmp && cp -r /work/runners/go /tmp/gorun && cd /tmp/gorun && GOTOOLCHAIN=local go run verify_wba_go.go '"$CORPUS_IN" ;;
    rust-1-slim)
      echo 'export CARGO_HOME=/tmp/ch CARGO_TARGET_DIR=/tmp/tgt && cp -r /work/runners/rust-wba /tmp/rw && cd /tmp/rw && cargo run -q -- '"$CORPUS_IN" ;;
    gcc-14-c)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libjansson-dev libssl-dev pkg-config >/dev/null && cd /tmp && cp /work/runners/c/verify_wba.c . && cc -O2 -w -o vw verify_wba.c $(pkg-config --cflags --libs jansson) -lcrypto && ./vw '"$CORPUS_IN" ;;
    temurin-17-java)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && cd /tmp && cp /work/runners/java/VerifyWba.java . && curl -fsSL '"$M2"'/org/json/json/20240303/json-20240303.jar -o json.jar && javac -cp json.jar VerifyWba.java && java -cp ".:json.jar" VerifyWba '"$CORPUS_IN" ;;
    temurin-17-kotlin)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl unzip >/dev/null && curl -fsSL -o /tmp/k.zip https://github.com/JetBrains/kotlin/releases/download/v2.0.20/kotlin-compiler-2.0.20.zip && unzip -q /tmp/k.zip -d /opt && cd /tmp && mkdir -p libs && for u in '"$M2"'/com/fasterxml/jackson/core/jackson-databind/'"$JACKSON"'/jackson-databind-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-core/'"$JACKSON"'/jackson-core-'"$JACKSON"'.jar '"$M2"'/com/fasterxml/jackson/core/jackson-annotations/'"$JACKSON"'/jackson-annotations-'"$JACKSON"'.jar '"$M2"'/org/bouncycastle/bcprov-jdk18on/'"$BC"'/bcprov-jdk18on-'"$BC"'.jar; do curl -fsSL "$u" -o "libs/$(basename $u)"; done && cp /work/runners/kotlin/VerifyWba.kt . && CP=$(ls libs/*.jar | tr "\n" ":") && /opt/kotlinc/bin/kotlinc VerifyWba.kt -cp "$CP" -include-runtime -d vw.jar >/dev/null 2>&1 && java -cp "vw.jar:$CP" VerifyWbaKt '"$CORPUS_IN" ;;
    temurin-17-scala)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && curl -fsLo /tmp/scala-cli.gz https://github.com/VirtusLab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz && gzip -df /tmp/scala-cli.gz && chmod +x /tmp/scala-cli && cp /work/runners/scala/verify_wba.scala /tmp/ && cd /tmp && HOME=/tmp /tmp/scala-cli run --server=false verify_wba.scala -- '"$CORPUS_IN" ;;
    dotnet-sdk-9.0)
      echo 'export HOME=/tmp DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 && mkdir -p /tmp/dn && cp /work/runners/dotnet-wba/Program.cs /work/runners/dotnet-wba/verify_wba.csproj /tmp/dn/ && cd /tmp/dn && dotnet run -c Release --verbosity quiet -- '"$CORPUS_IN" ;;
    ruby-3.2-slim)
      echo 'ruby /work/runners/ruby/verify_wba.rb '"$CORPUS_IN" ;;
    php-8.3-cli)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libsodium-dev >/dev/null && (php -m | grep -qi sodium || docker-php-ext-install -j2 sodium >/dev/null 2>&1); php /work/runners/php/verify_wba.php '"$CORPUS_IN" ;;
    elixir-1.16-otp26)
      echo 'export HOME=/tmp MIX_HOME=/tmp/.mix HEX_HOME=/tmp/.hex && mix local.hex --force >/dev/null 2>&1 && elixir /work/runners/elixir/verify_wba.exs '"$CORPUS_IN" ;;
  esac
}

echo "KAF cells for webbotauth_v0"
echo "repo: $REPO"
echo "================================================================"
results="[]"
for cell in $CELLS; do
  image="$(image_for "$cell")"
  lang="$(lang_for "$cell")"
  printf "  %-20s %-32s " "$cell" "$image"
  if docker run --rm -v "$REPO":/work:ro "$image" \
        sh -c "$(cmd_for "$cell")" >/tmp/cell_wba_"$cell".log 2>&1; then
    verdict=PASS
  else
    verdict=FAIL
  fi
  digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$image" 2>/dev/null)"
  echo "$verdict"
  [ "$verdict" = FAIL ] && tail -4 /tmp/cell_wba_"$cell".log | sed 's/^/       /'
  results="$(printf '%s' "$results" | python3 -c "import json,sys; a=json.load(sys.stdin); a.append({'cell':'$cell','lang':'$lang','image':'$image','image_digest':'''$digest''','verdict':'$verdict'}); print(json.dumps(a))")"
done
echo "================================================================"
printf '%s' "$results" | python3 -m json.tool > "$RESULTS"
passed="$(printf '%s' "$results" | python3 -c "import json,sys; print(sum(1 for c in json.load(sys.stdin) if c['verdict']=='PASS'))")"
total="$(printf '%s' "$results" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
echo "cells passed: $passed/$total   -> $RESULTS"
[ "$passed" = "$total" ] && [ "$total" -gt 0 ]
