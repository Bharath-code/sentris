#!/bin/sh
# --- Sentris One-Line Automated Installer ---
# Usage: curl -fsSL https://raw.githubusercontent.com/Bharath-code/sentris/master/install.sh | sh

set -e

REPO="Bharath-code/sentris"
VERSION="v0.1.0"

echo "⚡ Installing Sentris Secret Scanner (${VERSION})..."

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            arm64|aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            x86_64) TARGET="x86_64-unknown-linux-musl" ;;
            *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported operating system: $OS"; exit 1 ;;
esac

ARCHIVE="sentris-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "⬇️  Downloading from ${URL}..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "${TMP_DIR}/${ARCHIVE}"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$URL" -O "${TMP_DIR}/${ARCHIVE}"
else
    echo "Error: curl or wget is required to download Sentris."; exit 1
fi

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

mv "${TMP_DIR}/sentris" "${INSTALL_DIR}/sentris"
chmod +x "${INSTALL_DIR}/sentris"

echo "✔ Successfully installed sentris to ${INSTALL_DIR}/sentris"
echo ""
echo "Quickstart:"
echo "  sentris scan .                  # Scan current directory"
echo "  sentris install                 # Install sub-35ms pre-commit hook"
echo "  sentris remediate --dry-run     # Test safe autonomous rotation"
echo ""
"${INSTALL_DIR}/sentris" --version
