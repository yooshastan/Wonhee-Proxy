#!/usr/bin/env bash
# Locally build and verify the OFFICIAL Wonhee Proxy release APK.
# Never install over or uninstall com.yooshastan.wonheeproxy.rootlab.
set -euo pipefail
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

store_root="${XDG_DATA_HOME:-$HOME/.local/share}/yooshastan/wonhee-signing"
store="$store_root/wonhee-release.p12"
alias="wonhee-release"
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"

for bin in git keytool go java; do
  command -v "$bin" >/dev/null || {
    echo "Missing required tool: $bin" >&2
    exit 1
  }
done

if [[ ! -f "$store" || -L "$store" ]]; then
  echo "REFUSED: original release keystore missing or symlinked: $store" >&2
  echo "Restore original keystore; NEVER regenerate a deployed release key." >&2
  exit 1
fi
if [[ -z "$sdk" || ! -x "$sdk/build-tools/35.0.0/apksigner" ||
      ! -x "$sdk/build-tools/35.0.0/aapt" ]]; then
  echo "Android SDK build-tools 35.0.0 missing; set ANDROID_SDK_ROOT." >&2
  echo "Install Android SDK platform android-36 and build-tools 35.0.0." >&2
  exit 1
fi

branch="$(git branch --show-current)"
if [[ "$branch" != feature/persistent-official-signing-01524 ]]; then
  echo "REFUSED: expected reviewed signing branch; currently: $branch" >&2
  exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "REFUSED: worktree has uncommitted tracked changes." >&2
  echo "Commit or stash changes before building a signed release candidate." >&2
  exit 1
fi
echo "Building official Wonhee app from commit:"
git rev-parse HEAD
echo "Package ID: com.yooshastan.wonheeproxy"
echo "Keystore kept private: $store"

read -r -s -p "Enter release keystore password (not shown): " secret
echo
if [[ -z "$secret" ]]; then
  echo "REFUSED: empty keystore password." >&2
  exit 1
fi
export WONHEE_SIGNING_STORE_FILE="$store"
export WONHEE_SIGNING_STORE_PASSWORD="$secret"
export WONHEE_SIGNING_KEY_PASSWORD="$secret"
export WONHEE_SIGNING_KEY_ALIAS="$alias"
unset secret
trap 'unset WONHEE_SIGNING_STORE_PASSWORD WONHEE_SIGNING_KEY_PASSWORD WONHEE_SIGNING_STORE_FILE WONHEE_SIGNING_KEY_ALIAS' EXIT

# JDK keytool emits the public X.509 certificate as DER.
expected="$(keytool -exportcert -keystore "$store" -storetype PKCS12 \
  -alias "$alias" -storepass:env WONHEE_SIGNING_STORE_PASSWORD |
  sha256sum | cut -d' ' -f1)"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Unable to read public release certificate; refusing to build." >&2
  exit 1
fi
echo "Release certificate SHA-256 (public): $expected"

bash scripts/build-root-doh-helper.sh
./gradlew :app:assembleRelease --no-daemon --console=plain

apk="app/build/outputs/apk/release/app-release.apk"
[[ -s "$apk" ]] || { echo "No release APK generated." >&2; exit 1; }
signer_output="$("$sdk/build-tools/35.0.0/apksigner" verify --verbose --print-certs "$apk")"
actual="$(printf '%s\n' "$signer_output" |
  sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 |
  tr -d ':[:space:]' | tr '[:upper:]' '[:lower:]')"
if [[ "$actual" != "$expected" ]]; then
  echo "REFUSED: APK signing identity does not match original local keystore." >&2
  exit 1
fi
manifest="$("$sdk/build-tools/35.0.0/aapt" dump badging "$apk" | head -n 1)"
if [[ "$manifest" != "package: name='com.yooshastan.wonheeproxy' "* ]]; then
  echo "REFUSED: wrong package identity: $manifest" >&2
  exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "REFUSED: root helper build unexpectedly changed tracked source files." >&2
  exit 1
fi

mkdir -p dist
cp "$apk" dist/wonhee-proxy-official-signed.apk
(
  cd dist
  sha256sum wonhee-proxy-official-signed.apk > wonhee-proxy-official-signed.sha256
)
echo
echo "SUCCESS: locally signed official APK verified."
echo "Package/version: $manifest"
echo "Public signer SHA-256: $expected"
echo "APK: $project_dir/dist/wonhee-proxy-official-signed.apk"
echo "APK SHA-256: $project_dir/dist/wonhee-proxy-official-signed.sha256"
echo
echo "This is a LOCAL signed build, NOT a published signed GitHub release."
echo "Do NOT uninstall the current rootlab app. Stop and audit its network"
echo "stack before installing official side-by-side. Never run both stacks"
echo "simultaneously. Existing rootlab profiles are not automatically migrated."
