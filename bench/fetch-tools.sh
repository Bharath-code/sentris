#!/usr/bin/env bash
# Downloads pinned gitleaks / trufflehog / kingfisher into bench/.tools.
# gitleaks + trufflehog archives are verified against the checksums file of the same release;
# kingfisher publishes none, so its sha256 is pinned in bench/tools.lock on first fetch (trust on first use).
set -euo pipefail
cd "$(dirname "$0")"
source tools.env
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) GL=darwin_arm64; TH=darwin_arm64; KF=darwin-arm64 ;;
  Darwin-x86_64) GL=darwin_x64; TH=darwin_amd64; KF=darwin-x64 ;;
  Linux-x86_64) GL=linux_x64; TH=linux_amd64; KF=linux-x64 ;;
  Linux-aarch64) GL=linux_arm64; TH=linux_arm64; KF=linux-arm64 ;;
  *) echo "unsupported platform" >&2; exit 1 ;;
esac
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
mkdir -p .tools/dl && cd .tools/dl

fetch_checked() { # name url checksums_url archive
  curl -sSLfo "$4" "$2"; curl -sSLfo "$1.sums" "$3"
  want=$(grep " $4\$" "$1.sums" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$(sha "$4")" ] || { echo "checksum mismatch for $4" >&2; exit 1; }
}

gl="gitleaks_${GITLEAKS_VERSION}_${GL}.tar.gz"
fetch_checked gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$gl" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" "$gl"
tar -xzf "$gl" -C .. gitleaks

th="trufflehog_${TRUFFLEHOG_VERSION}_${TH}.tar.gz"
fetch_checked trufflehog "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/$th" \
  "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" "$th"
tar -xzf "$th" -C .. trufflehog

kf="kingfisher-${KF}.tgz"
curl -sSLfo "$kf" "https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VERSION}/$kf"
got=$(sha "$kf"); lock=../../tools.lock; touch "$lock"
if pinned=$(grep "^$kf " "$lock" | cut -d' ' -f2) && [ -n "$pinned" ]; then
  [ "$pinned" = "$got" ] || { echo "kingfisher checksum differs from bench/tools.lock" >&2; exit 1; }
else
  echo "$kf $got" >> "$lock"; echo "pinned $kf in bench/tools.lock (commit it)"
fi
tar -xzf "$kf" -C .. kingfisher
chmod +x ../gitleaks ../trufflehog ../kingfisher
echo "tools ready in bench/.tools"
