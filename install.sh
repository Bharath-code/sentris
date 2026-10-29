#!/bin/sh
# Sentris installer. Downloads a release archive and verifies it against the release's SHA256SUMS.
# Usage: curl -fsSL https://raw.githubusercontent.com/Bharath-code/sentris/master/install.sh | sh
# Env:   SENTRIS_VERSION (default: latest release), SENTRIS_INSTALL_DIR, SENTRIS_RELEASE_BASE

set -eu

REPO="Bharath-code/sentris"

fail() { echo "Error: $*" >&2; exit 1; }

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) fail "unsupported architecture: $ARCH" ;;
        esac ;;
    Linux)
        case "$ARCH" in
            arm64|aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            x86_64) TARGET="x86_64-unknown-linux-musl" ;;
            *) fail "unsupported architecture: $ARCH" ;;
        esac ;;
    *) fail "unsupported operating system: $OS (Windows: download the .zip from the releases page)" ;;
esac

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
    else fail "curl or wget is required"; fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else fail "sha256sum or shasum is required to verify the download"; fi
}

VERSION="${SENTRIS_VERSION:-}"
if [ -z "$VERSION" ]; then
    command -v curl >/dev/null 2>&1 || fail "set SENTRIS_VERSION (e.g. v0.1.0) when curl is unavailable"
    VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
    VERSION="${VERSION##*/}"
    case "$VERSION" in v[0-9]*) ;; *) fail "could not determine the latest release (is one published?)" ;; esac
fi

BASE="${SENTRIS_RELEASE_BASE:-https://github.com/${REPO}/releases/download/${VERSION}}"
ARCHIVE="sentris-${VERSION}-${TARGET}.tar.gz"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Installing Sentris ${VERSION} (${TARGET})"
fetch "${BASE}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"
fetch "${BASE}/SHA256SUMS" "${TMP_DIR}/SHA256SUMS"

EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1 }' "${TMP_DIR}/SHA256SUMS")"
[ -n "$EXPECTED" ] || fail "${ARCHIVE} is not listed in SHA256SUMS"
ACTUAL="$(sha256_of "${TMP_DIR}/${ARCHIVE}")"
[ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch for ${ARCHIVE} (expected ${EXPECTED}, got ${ACTUAL})"

mkdir "${TMP_DIR}/x"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}/x"

INSTALL_DIR="${SENTRIS_INSTALL_DIR:-/usr/local/bin}"
if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="${SENTRIS_INSTALL_DIR:-${HOME}/.local/bin}"
    mkdir -p "$INSTALL_DIR"
fi

mv "${TMP_DIR}/x/sentris" "${INSTALL_DIR}/sentris"
chmod +x "${INSTALL_DIR}/sentris"

echo "Installed sentris to ${INSTALL_DIR}/sentris (checksum verified)"
case ":${PATH}:" in *":${INSTALL_DIR}:"*) ;; *) echo "Add ${INSTALL_DIR} to your PATH." ;; esac
"${INSTALL_DIR}/sentris" --version
