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
for platform in arm64:arm64 amd64:amd64 arm:arm 386:386; do
  arch="${platform%%:*}"
  target="${platform#*:}"
  (
    cd "$helper_dir"
    CGO_ENABLED=0 GOOS=android GOARCH="$arch" GOARM=7 go build \
      -trimpath -ldflags='-s -w' \
      -o "$assets_dir/wonhee-doh-$target" .
  )
done
echo 'Built four architecture-specific one-shot root DoH probe assets.'
