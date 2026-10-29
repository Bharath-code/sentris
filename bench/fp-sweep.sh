#!/usr/bin/env bash
# False-positive gate: scan a pinned, secret-free public checkout and fail if findings exceed bench/fp_baseline.txt.
# Django's remaining baseline hits are test constants (MASKED_TEST_SECRET, CSRF_TOKEN, "FORBIDDEN_VALUE2").
set -euo pipefail
cd "$(dirname "$0")/.."
source bench/tools.env
BIN=${SENTRIS_BIN:-target/release/sentris}
if [ ! -d bench/work/repo ]; then
  mkdir -p bench/work
  git clone --quiet --depth 1 --branch "$REPO_TAG" "$REPO_URL" bench/work/repo
  rm -rf bench/work/repo/.git
fi
count=$("$BIN" scan bench/work/repo -f json | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["findings"]))')
limit=$(cat bench/fp_baseline.txt)
echo "findings on $REPO_URL $REPO_TAG: $count (limit $limit)"
[ "$count" -le "$limit" ] || { echo "false-positive regression: raise bench/fp_baseline.txt only after reviewing every new finding" >&2; exit 1; }
