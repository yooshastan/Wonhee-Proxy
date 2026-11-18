# Wonhee 0.15.60 — common protocol presets & truthful multi-tunnel roles

**Status:** Draft development candidate for Android device testing, **not** live application-specific network routing. VersionCode **107**, versionName **0.15.60-common-protocol-presets**. This branch builds on stacked draft PR #90.

## User feedback and observed evidence

- User expects recognizable services instead of only TCP/UDP numeric transport selectors: **HTTP, HTTPS, DNS, POP3, SSH, time synchronization, remote access**, etc.
- User wants an easy way to assign these service ports to an *app-use category* which then references a saved tunnel; these category-wide protocol presets should supersede an app's **ordinary category assignment**.
- The screenshot shows **AirVPN Europe selected, Home WireGuard selected, AirVPN America selected**. The American profile is labeled **Regional / local services** but uses **original WireGuard routes**. The imported AllowedIPs may be full Internet defaults despite the category name.
- Screenshot shows **Not connected**, but does **not** show the latest Start result or preflight/DNS stage. This evidence is **not sufficient to identify the connection blocker**. Previous device tests reported encrypted DNS startup timeout, and the current root engine still enforces one full Internet exit plus non-overlapping destination-specific tunnels.

## What was implemented

### Human-facing presets

The global Protocols tab now offers one-click **templates of destination transport/port selectors**, with a readable name, an explicit TCP/UDP + port preview, and target app-use category:

| Preset | Port selectors |
| --- | --- |
| Web / HTTP | TCP 80 |
| Secure Web / HTTPS | TCP 443 |
| HTTP/3 / QUIC | UDP 443 |
| Conventional DNS | TCP 53 + UDP 53 |
| Encrypted DNS / DoT + DoQ | TCP 853 + UDP 853 |
| SSH / SFTP | TCP 22 |
| IMAP / IMAPS | TCP 143 + 993 |
| POP3 / POP3S | TCP 110 + 995 |
| SMTP / mail submission | TCP 25 + 465 + 587 |
| NTP / network time | UDP 123 |
| RDP / remote desktop | TCP + UDP 3389 |
| MQTT / IoT messaging | TCP 1883 + 8883 |

**Custom TCP/UDP + optional destination port** remains available under these presets. The modal previews each port and announces how many existing selectors would be replaced; cancel preserves the originals. Multi-port presets are committed atomically in one app-private preferences write, subject to the existing twenty-rule limit. A failure preserves the old draft. The category-to-tunnel choice must be configured separately under **Categories**.

### Important protocol limits

- Port numbers are not trustworthy identifiers for applications, websites or content; HTTPS, DoH, QUIC and proprietary protocols can share ports. Nonstandard ports are common.
- **No generic GPS port exists.** GPS satellite fixes are not Internet flows. Android may derive location from Wi-Fi, cellular signals, GNSS and HTTPS location APIs. VPN routing can change observed public IP but **does not spoof GNSS/device location**.
- The presets store **planning-only** TCP/UDP metadata. They do not decrypt, sniff, inspect, redirect, route, or enforce anything. Root policy activation remains explicitly disabled.
- Planning precedence remains: **explicit per-app transport/port override > global port-to-category rule > ordinary app category > default**.
- DNS routing presets must not bypass Wonhee's existing strictly bound encrypted DNS relay or substitute the system Private DNS setting. Android Private DNS remains OFF on the established Pixel 8a.

### Make imported tunnel roles truthful

- Home and Tunnel Settings now display **effective routes from the parsed profile**. A Regional-labeled AirVPN profile containing the two default routes reports **Full Internet exit — one active default**, not the ambiguous “Imported routes”.
- A split-only imported profile reports specific destination routing; an incomplete IPv4/IPv6 default is labelled as such.
- Selection still permits keeping multiple profiles checked, but the **existing supported live root mode** connects exactly one chosen Internet exit plus compatible destination-specific tunnels. Other unrestricted exits stay selected and **not connected**.
- The last **short, sanitized connection failure summary** now persists in local app-private preferences across app restart, so Home still indicates when a previous Start failed. No raw resolver, key, shell output or peer addresses are persisted in this record.

## What was NOT fixed

- A successful multi-profile checkbox selection is **not a successful connection**.
- The user screenshot says **Not connected** but does not expose the actual failing start stage. We have not proven a fix for root preflight, WireGuard handshake, routing or encrypted DNS startup. In particular, the earlier LOCAL_DNS_TIMEOUT cannot be blamed on two selected full exits without a new diagnostic result.
- Running two simultaneous unrestricted exits **by app/category/protocol is still blocked** pending live UID policy and DNS/firewall isolation (issue #89). Extra unrestricted exits are never secretly counted as connected.
- No all-traffic kill switch activation; no relaxed VPN, DNS or root firewall validation.

## Device acceptance and diagnostic sequence

1. Use original signing identity. Independently audit H.1 Safe Stop + H.2a `CLEAN_STOPPED` before updating. Do not uninstall the official app or install the CI debug APK as an in-place release.
2. Verify versionCode 107 in Android PackageManager; keep USB ADB recovery available.
3. Home: choose **AirVPN Europe + Home** (without America). Inspect effective role labels. Press Start exactly once. Note the **stage shown in the Latest Result** if it fails, and inspect H.1 rollback status. Do not repeat Start if rollback is not verified complete.
4. If the preceding two-profile Start passes, safely stop and independently verify `CLEAN_STOPPED`, then select **Europe + Home + America**. Choose Europe as primary. Confirmation should explicitly say America is selected but **not connected**.
5. Global Protocols: choose **DNS — conventional**, target **Private**. Save and confirm *two* draft rules TCP/53 + UDP/53, then reopen and verify persistence. Test POP3 and SSH templates and duplicate-selector replacement warning. No network changes should occur.
6. The American imported profile labeled Regional should show **Full Internet exit** if its WireGuard AllowedIPs contain both defaults. Category labels do not alter routes.
7. If Start fails, obtain the latest sanitized failure phase and the read-only H.2a audit. Do **not** work around DNS startup by enabling direct/plaintext fallback, altering Private DNS, or deleting Android netd policy rules.
8. Standard mode, Home, Stats, More, Protect and the file-picker Back flow must remain unchanged; test layout on Android 16.

## Fedora checkout after both CI jobs pass

```bash
cd ~/Wonhee-Proxy-UI || exit 1
git fetch origin
git switch feature/common-protocol-presets-01560 || \
  git switch --track origin/feature/common-protocol-presets-01560
git pull --ff-only origin feature/common-protocol-presets-01560
bash scripts/build-wonhee-official-local.sh
# Only after H.1 and independently verified H.2a CLEAN_STOPPED:
bash scripts/install-wonhee-safe-update.sh
```

See the CI status and manual acceptance on the draft pull request. **A passing build is not proof of working VPN routing or leak freedom.**
