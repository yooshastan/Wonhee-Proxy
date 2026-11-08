#!/usr/bin/env bash
# Run on the maintainer's Fedora workstation, NOT in GitHub Actions.
# Creates one long-lived Wonhee release signing identity and uploads only
# encrypted Actions secrets. The private keystore remains on this computer.
set -euo pipefail
umask 077
export LC_ALL=C

REPO="yooshastan/Wonhee-Proxy"
ALIAS="wonhee-release"
DIR="${XDG_DATA_HOME:-$HOME/.local/share}/yooshastan/wonhee-signing"
STORE="$DIR/wonhee-release.p12"

for bin in keytool gh base64 sed tr; do
  command -v "$bin" >/dev/null 2>&1 || {
    echo "Required command missing: $bin" >&2
    exit 1
  }
done
gh auth status -h github.com >/dev/null
gh repo view "$REPO" --json nameWithOwner --jq '.nameWithOwner' >/dev/null

echo "Repository: $REPO"
echo "Private keystore location: $STORE"
echo "Do not run from a shared/untrusted Linux workstation."
echo "RELEASE application ID: com.yooshastan.wonheeproxy"
echo "Existing debug rootlab app has a different ID/certificate."

mkdir -p -m 700 "$DIR"
chmod 700 "$DIR"
if [[ -L "$STORE" ]]; then
  echo "REFUSED: keystore path must not be a symlink." >&2
  exit 1
fi

if [[ ! -f "$STORE" ]]; then
  existing="$(gh secret list --repo "$REPO" --json name --jq \
    '.[] | select(.name | startswith("WONHEE_SIGNING_")) | .name')"
  if [[ -n "$existing" ]]; then
    echo "REFUSED: signing secrets exist but the local original keystore" >&2
    echo "is missing. Recover your original backup; do NOT generate another key." >&2
    exit 1
  fi
  echo "Generating ONE persistent release signing key."
  echo "Enter the strong password directly into your terminal; not chat."
  keytool -genkeypair \
    -keystore "$STORE" \
    -storetype PKCS12 \
    -alias "$ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 10000 \
    -dname "CN=Yooshastan Studios, O=Yooshastan Studios, C=US"
fi

[[ -f "$STORE" && -r "$STORE" ]] || {
  echo "Cannot read signing keystore." >&2
  exit 1
}
chmod 600 "$STORE"

echo "Checking the public certificate fingerprint (password prompt follows)."
cert_output="$(keytool -list -v -keystore "$STORE" \
    -storetype PKCS12 -alias "$ALIAS")"
fingerprint="$(printf '%s\n' "$cert_output" |
  sed -n 's/^[[:space:]]*SHA256:[[:space:]]*//p' |
  head -n 1 | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]')"
if [[ ! "$fingerprint" =~ ^[a-f0-9]{64}$ ]]; then
  echo "REFUSED: Cannot extract release certificate fingerprint." >&2
  exit 1
fi
echo "Public release certificate SHA-256: $fingerprint"
echo "Back up the original $STORE securely before publication."
echo "Never regenerate the key to fix a failed build."

read -r -p "Upload as encrypted GitHub Actions secrets? [y/N] " answer
if [[ "$answer" != y && "$answer" != Y ]]; then
  echo "Key kept local; secrets not uploaded."
  exit 0
fi
read -r -s -p "Enter local keystore password: " password
echo
read -r -s -p "Confirm local keystore password: " confirm
echo
if [[ -z "$password" || "$password" != "$confirm" ]]; then
  unset password confirm
  echo "REFUSED: password mismatch/empty." >&2
  exit 1
fi
unset confirm

existing="$(gh secret list --repo "$REPO" --json name --jq \
  '.[] | select(.name | startswith("WONHEE_SIGNING_")) | .name')"
if [[ -n "$existing" ]]; then
  echo "Some WONHEE_SIGNING_* secrets already exist."
  read -r -p "Re-upload this SAME local keystore over them? [y/N] " replace
  if [[ "$replace" != y && "$replace" != Y ]]; then
    unset password
    echo "No secrets modified."
    exit 0
  fi
fi

base64 -w0 "$STORE" |
  gh secret set WONHEE_SIGNING_STORE_B64 --repo "$REPO"
printf '%s' "$password" |
  gh secret set WONHEE_SIGNING_STORE_PASSWORD --repo "$REPO"
printf '%s' "$ALIAS" |
  gh secret set WONHEE_SIGNING_KEY_ALIAS --repo "$REPO"
printf '%s' "$password" |
  gh secret set WONHEE_SIGNING_KEY_PASSWORD --repo "$REPO"
unset password
printf '%s' "$fingerprint" |
  gh secret set WONHEE_SIGNING_CERT_SHA256 --repo "$REPO"

echo "Actions signing secrets configured. Original keystore remains at:"
echo "$STORE"
echo "Public cert SHA-256: $fingerprint"
echo "BACK UP THE ORIGINAL KEYSTORE AND PASSWORD OFFLINE."
echo "Run signed release only from main AFTER the tested branch has merged."
