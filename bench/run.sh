#!/usr/bin/env bash
# One command: builds sentris, runs every available scanner on the same workloads, writes bench/results/.
# Missing competitor tools are skipped and listed; run bench/fetch-tools.sh first for the full comparison.
set -euo pipefail
cd "$(dirname "$0")/.."
source bench/tools.env
cargo build --release --quiet
CORPUS_DUMP=bench/work/corpus cargo test --quiet --test corpus_test >/dev/null
if [ ! -d bench/work/repo ]; then
  mkdir -p bench/work
  git clone --quiet --depth 1 --branch "$REPO_TAG" "$REPO_URL" bench/work/repo
  rm -rf bench/work/repo/.git # every tool scans the plain working tree, not history
fi
exec python3 bench/bench.py "$@"
