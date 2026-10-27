# Wonhee Proxy — persistent release signing

**Goal:** every future installable release must use one maintained signing identity.
The Android package remains `com.yooshastan.wonheeproxy`.

## One-time maintainer setup

1. On a trusted Linux workstation, generate a **new, long-lived release keystore**.
   Choose and privately store strong passwords. Never put the keystore or passwords
   in Git, issue comments, ChatGPT, or Android device logs:

   ```bash
   keytool -genkeypair -v -keystore wonhee-release.jks -alias wonhee-release -keyalg RSA -keysize 4096 -validity 10000
   ```

2. Back up the encrypted keystore and its alias/passwords offline. Losing this
   signing key means existing installations cannot receive compatible updates.
3. In the GitHub repository **Settings → Secrets and variables → Actions**,
   add the following five repository secrets. Do this only in the GitHub UI:

   | Secret | Value |
   | --- | --- |
   | `WONHEE_SIGNING_STORE_B64` | Single-line base64 of the keystore bytes (e.g. `base64 -w0 wonhee-release.jks`; keep output private) |
   | `WONHEE_SIGNING_STORE_PASSWORD` | Keystore password |
   | `WONHEE_SIGNING_KEY_ALIAS` | `wonhee-release` |
   | `WONHEE_SIGNING_KEY_PASSWORD` | Key password |
   | `WONHEE_SIGNING_CERT_SHA256` | 64 hexadecimal characters of the public signing certificate SHA-256 fingerprint (no colons) |

   Obtain the certificate fingerprint locally with
   `keytool -list -v -keystore wonhee-release.jks -alias wonhee-release`.
   Copy the `SHA256:` certificate fingerprint without colons or spaces; this is
   public identity metadata, **not** the private key. The workflow refuses to
   upload a signed artifact if the fingerprint is missing or different.

4. From GitHub Actions, choose **Wonhee Proxy Android Alpha 0.8.4 Preview → Run
   workflow** on a trusted branch. This explicitly generates the separately
   signed artifact `wonhee-proxy-alpha08.4-preview-signed-apk` plus a SHA-256
   APK checksum file.
   PR/push builds keep using ephemeral debug signing and cannot access release keys.
5. Before distributing, verify signature SHA-256 fingerprints on two consecutive
   **signed release** APKs with `apksigner verify --print-certs`, and prove an
   in-place `adb install -r` succeeds without deleting the previous app's data.
   The workflow checks the expected release certificate before uploading; this
   is not a substitute for the real in-place upgrade test.
6. Keep the signing key safe and use this exact signing setup for every subsequent
   standalone APK and store deployment. Do not generate a replacement per build.

## Migration caveat

A pre-existing APK that was signed with another debug certificate **cannot be
updated in-place** by raising `versionCode`. That transition may require one
uninstall/reinstall, which destroys Android app data including Keystore-sealed
profiles. Back up all WireGuard source .conf files and Telegram proxy credentials
securely before changing signing identities. The app cannot export non-exportable
Android Keystore keys from an uninstalled copy.

The new workflow and signing configuration **do not automatically create or
publish a signed release**. They remain unusable until the maintainer privately
provisions the keystore secrets.

Never put release keys in repository files, logs, temporary artifacts, or chat.
