#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?Usage: build-wonhee-native-android.sh <jniLibs-output-dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
NDK="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK" ]]; then
  [[ -n "$SDK" ]] || { echo "ANDROID_HOME/ANDROID_SDK_ROOT is required." >&2; exit 2; }
  NDK="$SDK/ndk/27.2.12479018"
fi
HOST_TAG=linux-x86_64
CC="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android26-clang"
[[ -x "$CC" ]] || { echo "Android NDK 27.2.12479018 ARM64 compiler not found: $CC" >&2; exit 2; }
mkdir -p "$OUT/arm64-v8a"
OUT="$(cd "$OUT" && pwd)"
staging="$(mktemp -d "${TMPDIR:-/tmp}/wonhee-native-build.XXXXXXXX")"
trap 'rm -rf -- "$staging"' EXIT
cp -a "$ROOT/native/." "$staging/"
(
  cd "$staging"
  go mod tidy
  go mod verify
  test "$(go list -m -f '{{.Version}}' github.com/quic-go/quic-go)" = v0.50.0
  test "$(go list -m -f '{{.Version}}' golang.zx2c4.com/wireguard)" = v0.0.0-20261024220952-b3bc704ef0ee
  export GOOS=android GOARCH=arm64 CGO_ENABLED=1
  export CC
  go build -mod=readonly -trimpath -buildmode=c-shared \
    -ldflags='-s -w -extldflags=-Wl,-z,max-page-size=16384' \
    -o "$OUT/arm64-v8a/libwonhee_native.so" ./cmd/wonhee-jni
)
test -s "$OUT/arm64-v8a/libwonhee_native.so"
file "$OUT/arm64-v8a/libwonhee_native.so"
