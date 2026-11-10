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
# Use the SDK already configured by Gradle or installed locally, without
# imposing an older Build Tools version on a newer Android SDK.
sdk=""
sdk_candidates=()
if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
  sdk_candidates+=("$ANDROID_SDK_ROOT")
fi
if [[ -n "${ANDROID_HOME:-}" ]]; then
  sdk_candidates+=("$ANDROID_HOME")
fi
if [[ -f local.properties ]]; then
  local_sdk="$(sed -n 's/^sdk\.dir=//p' local.properties | head -n 1)"
  if [[ -n "$local_sdk" ]]; then
    sdk_candidates+=("${local_sdk//\\ / }")
  fi
fi
sdk_candidates+=("$HOME/Android/Sdk" "$HOME/Android/sdk" "/opt/android-sdk" "/usr/lib/android-sdk")
for candidate in "${sdk_candidates[@]}"; do
  if [[ -d "$candidate/build-tools" ]]; then
    sdk="$(cd "$candidate" && pwd)"
    break
  fi
done
if [[ -z "$sdk" ]]; then
  echo "Android SDK not found. Set ANDROID_SDK_ROOT to your existing SDK directory." >&2
  echo "Checked: environment variables, local.properties, ~/Android/Sdk and common system paths." >&2
  exit 1
fi

build_tools=""
while IFS= read -r version; do
  tools_dir="$sdk/build-tools/$version"
  if [[ -x "$tools_dir/apksigner" && -x "$tools_dir/aapt" ]]; then
    build_tools="$tools_dir"
    break
  fi
done < <(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -Vr)
if [[ -z "$build_tools" ]]; then
  echo "SDK found at: $sdk" >&2
  echo "No installed Build Tools version includes both apksigner and aapt." >&2
  echo "Inspect available versions with: ls -1 \"$sdk/build-tools\"" >&2
  exit 1
fi
export ANDROID_SDK_ROOT="$sdk"
export ANDROID_HOME="$sdk"
echo "Using Android SDK: $sdk"
echo "Using installed Build Tools: ${build_tools##*/}"

for bin in git keytool go java; do
  command -v "$bin" >/dev/null || {
    echo "Missing required tool: $bin" >&2
    exit 1
  }
done

# Gradle 8.13 is not compatible with Java 25. Respect the user's chosen
# Java and javac alternatives first, then discover Fedora's full JDK paths.
# This changes only this script's environment, NOT system alternatives.
select_gradle_jdk() {
  local candidate first_line javac_line major javac_major resolved binary
  local -a candidates=()

  if [[ -n "${JAVA_HOME:-}" ]]; then
    candidates+=("$JAVA_HOME")
  fi
  for binary in java javac; do
    resolved="$(readlink -f "$(command -v "$binary")" 2>/dev/null || true)"
    if [[ "$resolved" == */bin/"$binary" ]]; then
      candidates+=("${resolved%/bin/$binary}")
    fi
  done
  candidates+=(
    /usr/lib/jvm/java-21-openjdk
    /usr/lib/jvm/java-17-openjdk
    /usr/lib/jvm/java-21-openjdk-*
    /usr/lib/jvm/java-17-openjdk-*
    /usr/lib/jvm/*
    "$HOME"/.sdkman/candidates/java/*
    "$HOME"/.jdks/*
  )

  for candidate in "${candidates[@]}"; do
    [[ -x "$candidate/bin/java" && -x "$candidate/bin/javac" ]] || continue
    first_line="$("$candidate/bin/java" -version 2>&1 | head -n 1)"
    javac_line="$("$candidate/bin/javac" -version 2>&1 | head -n 1)"

    # Handles 'openjdk version "21"', '"21.0.9"' and vendor JDK variants
    # without relying on Fedora directory names or brittle major patterns.
    [[ "$first_line" == *\"* ]] || continue
    major="${first_line#*\"}"
    major="${major%%[!0-9]*}"
    javac_major="${javac_line#javac }"
    javac_major="${javac_major%%[!0-9]*}"
    if [[ ( "$major" == 17 || "$major" == 21 ) && "$javac_major" == "$major" ]]; then
      export JAVA_HOME="$(cd "$candidate" && pwd -P)"
      export PATH="$JAVA_HOME/bin:$PATH"
      return 0
    fi
  done
  return 1
}

if ! select_gradle_jdk; then
  echo "Could not find a Java 17/21 JDK with a matching javac compiler." >&2
  echo "Current Java: $(java -version 2>&1 | head -n 1)" >&2
  echo "Current javac: $(javac -version 2>&1 | head -n 1)" >&2
  echo "Installed Fedora JDKs:" >&2
  ls -1 /usr/lib/jvm/ 2>/dev/null >&2 || true
  echo "Install the JDK (not only JRE): sudo dnf install java-21-openjdk-devel" >&2
  echo "You can also set JAVA_HOME explicitly; system defaults are unchanged." >&2
  exit 1
fi
echo "Using Gradle JDK: $JAVA_HOME"
java -version 2>&1 | head -n 1

if [[ ! -f "$store" || -L "$store" ]]; then
  echo "REFUSED: original release keystore missing or symlinked: $store" >&2
  echo "Restore original keystore; NEVER regenerate a deployed release key." >&2
  exit 1
fi

branch="$(git branch --show-current)"
# Explicit release-candidate allowlist: never silently sign an arbitrary branch.
# The 0.15.28 UI/DNS branch remains a draft until on-device validation.
case "$branch" in
  feature/batch-f5-control-policy-ui-design|feature/dns-coverage-continuity-01528|fix/wonhee-01528-signed-upgrade-path|feature/update-preflight-01529|feature/dashboard-telemetry-01530|feature/incident-snapshot-01531|fix/dns-start-stage-report-01532|feature/per-app-route-audit-01533|feature/passive-socket-marks-01534|feature/targeted-socket-burst-01535|fix/dns-local-health-substages-01536|feature/live-peer-route-audit-01537|feature/direct-route-advisories-01538|feature/direct-route-diagnostics-ui-01539|feature/direct-route-classification-01540)
    ;;
  *)
    echo "REFUSED: branch is not an explicitly reviewed Wonhee signing candidate: $branch" >&2
    exit 1
    ;;
esac
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
signer_output="$("$build_tools/apksigner" verify --verbose --print-certs "$apk")"
actual="$(printf '%s\n' "$signer_output" |
  sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -1 |
  tr -d ':[:space:]' | tr '[:upper:]' '[:lower:]')"
if [[ "$actual" != "$expected" ]]; then
  echo "REFUSED: APK signing identity does not match original local keystore." >&2
  exit 1
fi
manifest="$("$build_tools/aapt" dump badging "$apk" | head -n 1)"
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
