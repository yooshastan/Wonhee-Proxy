# Wonhee Proxy

An independent privacy and proxy companion for **Ultgram**, by Yooshastan
Studios. Alpha 0.1 is a real Android starter with a small, reusable Java core.

**Current scope:** Configure an MTProto or SOCKS5 endpoint, run a manual TCP
reachability test, and open its profile in an installed Ultgram client. An
optional self-hosted MTProxy server starter is included.

**Important:** This alpha is **not a VPN**, DNS ad blocker, traffic tunnel,
kill switch, Navidrome remote-access solution, or identity-anonymizing service.
It does not run in the background or save credentials. It transfers a proxy
secret only through an explicit package-scoped Android intent to Ultgram.

## First build

1. Open GitHub Actions → **Wonhee Proxy Android Alpha** on this branch.
2. Download the `wonhee-proxy-alpha01-debug-apk` artifact from a successful run.
3. Install the APK on Pixel 8a or Samsung A36.
4. Enter a trusted proxy endpoint and choose **Test TCP endpoint** to check only
   that the host's port answers. You must consent to an explicit network probe.
5. Choose **Open in Ultgram** to hand off the configuration to the installed
   `com.yooshastan.ultmessenger` app (or the beta package).
6. Activate the proxy in Ultgram, send messages and media, and independently
   verify server-side routing. TCP reachability is not proof of proxy use.

Build locally with JDK 17, Android SDK API 36, Gradle 8.13 and:
`gradle :app:assembleDebug`. If your Android Studio expects a wrapper,
generate it with `gradle wrapper --gradle-version 8.13` on your own workstation.

## Modules

- `app/` — simple native Android UI; no Google Play services needed.
- `app/src/main/java/.../core/` — pure Java validation, safe
  profile URL construction and opt-in TCP endpoint reachability.
- `core-tests/` — no-network-external test fixtures using localhost.
- `gateway/` — optional MTProxy container for a remote Linux VPS.
- `docs/ROADMAP.md` — privacy claims, limitations, and Tailscale alternative.

## Non-goals and safety

Wonhee Proxy does not add ads or analytics. Telegram-sponsored messages are
delivered through the Telegram API, and third-party clients must support them.
A proxy can hide a connection's originating IP from Telegram **only while**
Telegram traffic actually passes through that remote relay. It cannot remove
Telegram's phone-number/account associations or hide your IP from the proxy
operator. Do not assume a strict or fail-closed connection until separately
audited.

Not affiliated with Telegram, Telegram Messenger LLP, or any music artist or
agency. The project name and emblem are original brand assets.

Useful references:
- https://core.telegram.org/proxy
- https://core.telegram.org/api/sponsored-messages
