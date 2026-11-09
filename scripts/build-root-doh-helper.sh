#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper_dir="$project_dir/roothelper/dohprobe"
assets_dir="$project_dir/app/src/main/assets"

command -v go >/dev/null || {
  echo 'Go 1.23+ is required to build the root encrypted DNS helper.' >&2
  exit 1
}

# go mod tidy necessarily changes go.mod and creates go.sum when the checked
# in module is minimal. Never run it against the source working tree: an
# official signed build must not dirty Git during its own compilation.
umask 077
staging="$(mktemp -d "${TMPDIR:-/tmp}/wonhee-doh-build.XXXXXXXX")"
cleanup() { rm -rf -- "$staging"; }
trap cleanup EXIT

# Work in an isolated copy. Its transient go.mod/go.sum are never committed
# or shipped; the Go checksum database remains enabled to verify modules.
cp -a -- "$helper_dir/." "$staging/"
(
  cd "$staging"
  # Keep the pinned quic-go dependency and verify all module checksums.
  go mod tidy
  go mod verify
  go test ./...
)
mkdir -p "$assets_dir"

# ARM64 is supported by the Pixel 8a and A36 test devices; other ABIs need
# separate verification before distribution.
(
  cd "$staging"
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build \
    -trimpath -ldflags='-s -w' \
    -o "$assets_dir/wonhee-doh-arm64" .
)
echo 'Built ARM64 root-bound DoH/DoQ/DoH3 probe and opt-in DNS relay asset without changing source files.'
