#!/usr/bin/env bash
# KAF cell runner for rfc9421_negative_v1.
#
# Runs each language's runner against the one frozen, signed corpus inside its
# pinned Docker image, so the byte-for-byte verdict is shown to hold in a clean,
# independent runtime (the KAF "Cells" axis). Each cell builds/installs its deps
# fresh in-container. The resolved image digest and per-cell verdict are written
# to kaf/cells.results.json for sealing (kaf/seal_receipt.py).
#
# Env:
#   REPO   conformance repo checkout      (default: this repo)
#   VGO    verifier-go checkout           (default: ../algovoi-rfc9421-verifier-go)
#   VRS    verifier-rs checkout           (default: ../algovoi-rfc9421-verifier-rs)
#   CELLS  space-separated cell ids to run (default: all in cells.json)
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${REPO:-$HERE}"
VGO="${VGO:-$HERE/../algovoi-rfc9421-verifier-go}"
VRS="${VRS:-$HERE/../algovoi-rfc9421-verifier-rs}"
# repo-relative corpus path (mounted at /work); defaults to the v2 superset.
CORPUS="${CORPUS:-corpus/rfc9421_negative_v2/rfc9421_negative_v2.json}"
CORPUS_IN="/work/$CORPUS"
RESULTS="$HERE/kaf/cells.results.json"

ALL_CELLS="python-3.12-slim node-20-slim go-1.26-bookworm rust-1-slim gcc-14-c temurin-17-java temurin-17-kotlin temurin-17-scala dotnet-sdk-9.0 ruby-3.2-slim php-8.3-cli elixir-1.16-otp26"
CELLS="${CELLS:-$ALL_CELLS}"

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

# the in-container command for each cell
cmd_for() {
  case "$1" in
    python-3.12-slim)
      echo 'pip install -q --root-user-action=ignore algovoi-rfc9421-verifier algovoi-rfc9421-ecdsa && python /work/runners/python/verify_py.py '"$CORPUS_IN" ;;
    node-20-slim)
      echo 'cd /tmp && cp /work/runners/typescript/verify_ts.mjs /work/runners/typescript/package.json . && npm install --silent --no-audit --no-fund && node verify_ts.mjs '"$CORPUS_IN" ;;
    go-1.26-bookworm)
      echo 'export GOCACHE=/tmp/gc GOPATH=/tmp/gp HOME=/tmp && cd /vgo && GOTOOLCHAIN=local ALGOVOI_NEGATIVE_V1='"$CORPUS_IN"' go test ./ecdsa -run TestNegativeV1' ;;
    rust-1-slim)
      echo 'export CARGO_HOME=/tmp/ch CARGO_TARGET_DIR=/tmp/tgt && cd /vrs && ALGOVOI_NEGATIVE_V1='"$CORPUS_IN"' cargo test -q -p algovoi-rfc9421-ecdsa --test negative_v1' ;;
    gcc-14-c)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libjansson-dev libssl-dev pkg-config >/dev/null && cd /tmp && cp /work/runners/c/negative_v1.c . && cc -O2 -w -o nv negative_v1.c $(pkg-config --cflags --libs jansson) -lcrypto && ./nv '"$CORPUS_IN" ;;
    temurin-17-java)
      echo 'cd /tmp && cp /work/runners/java/NegativeV1.java . && mkdir -p libs && cp /work/runners/java/libs/*.jar libs/ && javac -cp "libs/*" NegativeV1.java && java -cp ".:libs/*" NegativeV1 '"$CORPUS_IN" ;;
    temurin-17-kotlin)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl unzip >/dev/null && curl -fsSL -o /tmp/k.zip https://github.com/JetBrains/kotlin/releases/download/v2.0.20/kotlin-compiler-2.0.20.zip && unzip -q /tmp/k.zip -d /opt && cd /tmp && cp /work/runners/kotlin/NegativeV1.kt . && mkdir -p libs && cp /work/runners/kotlin/libs/*.jar libs/ && CP=$(ls libs/*.jar | tr "\n" ":") && /opt/kotlinc/bin/kotlinc NegativeV1.kt -cp "$CP" -include-runtime -d nv.jar >/dev/null 2>&1 && java -cp "nv.jar:$CP" NegativeV1Kt '"$CORPUS_IN" ;;
    temurin-17-scala)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q curl >/dev/null && curl -fsLo /tmp/scala-cli.gz https://github.com/VirtusLab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz && gzip -df /tmp/scala-cli.gz && chmod +x /tmp/scala-cli && cp /work/runners/scala/negative_v1.scala /tmp/ && cd /tmp && HOME=/tmp /tmp/scala-cli run --server=false negative_v1.scala -- '"$CORPUS_IN" ;;
    dotnet-sdk-9.0)
      echo 'export HOME=/tmp DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 && cd /tmp && cp /work/runners/dotnet/Program.cs /work/runners/dotnet/negative_v1.csproj . && dotnet run -c Release --verbosity quiet -- '"$CORPUS_IN" ;;
    ruby-3.2-slim)
      echo 'ruby /work/runners/ruby/negative_v1.rb '"$CORPUS_IN" ;;
    php-8.3-cli)
      echo 'apt-get update -q >/dev/null && apt-get install -y -q libgmp-dev libsodium-dev >/dev/null && docker-php-ext-install -j2 gmp >/dev/null 2>&1; php -m | grep -qi sodium || docker-php-ext-install -j2 sodium >/dev/null 2>&1; php /work/runners/php/negative_v1.php '"$CORPUS_IN" ;;
    elixir-1.16-otp26)
      echo 'export HOME=/tmp MIX_HOME=/tmp/.mix HEX_HOME=/tmp/.hex && mix local.hex --force >/dev/null 2>&1 && elixir /work/runners/elixir/negative_v1.exs '"$CORPUS_IN" ;;
  esac
}

mounts_for() {
  case "$1" in
    go-1.26-bookworm) echo "-v $VGO:/vgo:ro" ;;
    rust-1-slim)      echo "-v $VRS:/vrs:ro" ;;
    *)                echo "" ;;
  esac
}

echo "KAF cells for rfc9421_negative_v1"
echo "repo: $REPO"
echo "================================================================"
results="[]"
for cell in $CELLS; do
  image="$(image_for "$cell")"
  # authoritative language comes from cells.json, NOT the cell-id prefix
  # (temurin-17-java and temurin-17-kotlin share a prefix but are java / kotlin).
  lang="$(python3 -c "import json; print(next(c['lang'] for c in json.load(open('$HERE/kaf/cells.json'))['cells'] if c['id']=='$cell'))")"
  printf "  %-20s %-32s " "$cell" "$image"
  # shellcheck disable=SC2046
  if docker run --rm -v "$REPO":/work:ro $(mounts_for "$cell") "$image" \
        sh -c "$(cmd_for "$cell")" >/tmp/cell_"$cell".log 2>&1; then
    verdict=PASS
  else
    verdict=FAIL
  fi
  digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' "$image" 2>/dev/null)"
  echo "$verdict"
  [ "$verdict" = FAIL ] && tail -3 /tmp/cell_"$cell".log | sed 's/^/       /'
  results="$(printf '%s' "$results" | python3 -c "import json,sys; a=json.load(sys.stdin); a.append({'cell':'$cell','lang':'$lang','image':'$image','image_digest':'''$digest''','verdict':'$verdict'}); print(json.dumps(a))")"
done
echo "================================================================"
printf '%s' "$results" | python3 -m json.tool > "$RESULTS"
passed="$(printf '%s' "$results" | python3 -c "import json,sys; print(sum(1 for c in json.load(sys.stdin) if c['verdict']=='PASS'))")"
total="$(printf '%s' "$results" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")"
echo "cells passed: $passed/$total   -> $RESULTS"
[ "$passed" = "$total" ] && [ "$total" -gt 0 ]
