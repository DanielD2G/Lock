#!/bin/sh
# Installs lock from the GitHub releases.
#
#   curl -fsSL https://raw.githubusercontent.com/DanielD2G/Lock/main/install.sh | sh
#
# LOCK_VERSION      tag to install (default: latest)
# LOCK_INSTALL_DIR  destination directory (default: ~/.local/bin)
#
# Run it again to upgrade.

set -eu

REPO="DanielD2G/Lock"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64 | Linux-amd64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-musl ;;
  *)
    echo "lock: unsupported platform: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

version="${LOCK_VERSION:-latest}"
if [ "$version" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$version"
fi
dir="${LOCK_INSTALL_DIR:-$HOME/.local/bin}"
file="lock-$target.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "lock: downloading $file ($version)" >&2
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/$file.sha256" -o "$tmp/$file.sha256"

expected="$(cut -d ' ' -f 1 <"$tmp/$file.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$file" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$tmp/$file" | cut -d ' ' -f 1)"
fi
if [ "$expected" != "$actual" ]; then
  echo "lock: checksum mismatch for $file" >&2
  exit 1
fi

tar -xzf "$tmp/$file" -C "$tmp"
mkdir -p "$dir"
install -m 0755 "$tmp/lock" "$dir/lock"
echo "lock: installed $("$dir/lock" --version) to $dir/lock" >&2

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "lock: add $dir to your PATH" >&2 ;;
esac
