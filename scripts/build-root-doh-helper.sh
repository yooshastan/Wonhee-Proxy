#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper_dir="$project_dir/roothelper/dohprobe"
assets_dir="$project_dir/app/src/main/assets"

command -v go >/dev/null || { echo 'Go 1.23+ is required to build the optional root DoH helper.' >&2; exit 1; }
(
  cd "$helper_dir"
  go test ./...
)
mkdir -p "$assets_dir"
# ARM64 is supported by the Pixel 8a/A36 stage-2 test devices. Other Android
# ABIs require Android NDK external linking; don't publish unverified binaries.
(
  cd "$helper_dir"
  CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build \
    -trimpath -ldflags='-s -w' \
    -o "$assets_dir/wonhee-doh-arm64" .
)
echo 'Built ARM64 one-shot root DoH probe asset.'
