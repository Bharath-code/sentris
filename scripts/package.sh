#!/usr/bin/env bash
# Usage: scripts/package.sh <target-triple> <tag> [target-dir]
# Packages target/<triple>/release/sentris into dist/sentris-<tag>-<triple>.{tar.gz,zip}
set -euo pipefail

TARGET="${1:?target triple}"
TAG="${2:?tag, e.g. v0.1.0}"
TARGET_DIR="${3:-target}"

BIN=sentris
case "$TARGET" in *windows*) BIN=sentris.exe ;; esac

SRC="${TARGET_DIR}/${TARGET}/release/${BIN}"
[ -f "$SRC" ] || SRC="${TARGET_DIR}/release/${BIN}"
[ -f "$SRC" ] || { echo "binary not found for ${TARGET}" >&2; exit 1; }

NAME="sentris-${TAG}-${TARGET}"
rm -rf "dist/${NAME}" && mkdir -p "dist/${NAME}"
cp "$SRC" LICENSE "dist/${NAME}/"

(
  cd dist
  case "$TARGET" in
    *windows*) 7z a -bso0 "${NAME}.zip" "${NAME}/*" ;;
    *) tar -czf "${NAME}.tar.gz" -C "${NAME}" . ;;
  esac
  rm -rf "${NAME}"
)
ls -l dist
