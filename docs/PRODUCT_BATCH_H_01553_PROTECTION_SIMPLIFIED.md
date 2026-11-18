# Product H — 0.15.53: concise DNS Protection with offline hosts import

**Status:** draft front-end candidate, not a beta or validated all-traffic kill switch. Product H is still in on-device acceptance. App versionCode 100.

## Locked-in surfaces

- **Stats** and **More/Tools** are accepted by the device tester and **intentionally unchanged** in this batch.
- Home: select one or multiple tunnel profiles, Start/Stop, Add Tunnel.
- Tunnels: saved-profile library with one direct per-profile settings editor; no duplicate selection.
- **Protect:** three simple blocks, with details in advanced diagnostics:
  1. DNS: **verified local relay / off or unverified**, plus blocking on/off and the verified relay lifetime count when available.
  2. HOSTS FILE: saved domain count, **Import hosts file**.
  3. More protection: honest kill-switch unavailability and **Advanced DNS settings** shortcut.

## Import contract

- Existing offline `RootBlocklistStore.importFrom` parser and atomic snapshot mechanism are reused (no new DNS engine or remote downloads).
- Android SAF document picker accepts a hosts.txt or one-domain-per-line file, up to **20 MiB** and **250,000 unique blocked domains**.
- On success: shows number of domains saved. The previous import is retained as a recovery snapshot.
- Imported lists are **NOT** applied to the running DNS relay. New lists are picked up only on the next **explicit** DNS activation with tracker filtering enabled.
- Import is unavailable while Wonhee's root DNS ownership ledger is active or the root session is busy. User is directed to existing Safe Stop / audit controls; no automatic stops, restarts or route mutations.
- On failure: show clear short error; retain the previously saved list; don't print file contents, domains, or sensitive data.
- The non-root Standard Protect page gives basic DNS/profile and Android VPN lockdown information; it does **not** claim to support root-only hosts filtering.

## Safety rules

- An active interface or verified relay is not proof of full-device leak protection.
- Blocked request counts cover only requests that reached the **verified local DNS relay** since it started.
- The all-traffic kill switch remains paused/unverified. No guard feature is enabled by navigating to Protect.
- Android Private DNS must remain **OFF** for the established Pixel 8a test configuration. This UI pass never changes it.
- Nothing in this UI redesign restarts, reconfigures, enables, or disables a tunnel, DNS or firewall without the existing explicit guarded workflows.
- The separate Standard mode is privacy-first and maintains one Android VPN tunnel, no rooted functionality assumed.

## On-device acceptance — one batch

| ID | Test | Expected |
|---|---|---|
| P01 | Open Protect root mode | DNS state, block state, saved hosts count, Import hosts file are visible without a long scroll |
| P02 | Root DNS running with verified relay | Local relay status shown as verified; counts shown only when relay and tracker filtering verified |
| P03 | Root DNS off/unverified | Does not show fabricated blocked counts or claim DNS protection |
| P04 | Import hosts with DNS policy stopped | Android file picker opens directly; valid hosts file saves and displays a domain count |
| P05 | Cancel Android file picker | Returns directly to modern Protect tab, not Root Lab or legacy manager |
| P06 | Import duplicate domains and local-network names | Built-in parser deduplicates and excludes local names as before |
| P07 | Import invalid list, over 20 MiB, or over 250K domains | Safe rejection; previous valid saved list remains |
| P08 | Attempt import while owned DNS protection running | Clear explanation and shortcut to advanced DNS; no silent relay restart or list mutation |
| P09 | Reopen Protect after app restart | Last imported list count remains; no expensive file parse blocking the UI |
| P10 | Import a valid hosts list, then start DNS/filtering intentionally | New snapshot is used by next explicit DNS activation; verify known allowed and blocked domains independently |
| P11 | Advanced DNS settings | Existing detailed lab remains reachable, but isn't forced into everyday Protect page |
| P12 | Standard/non-root Protect | Simple DNS/profile information; root-only hosts action hidden; Android VPN lockdown settings reachable |
| P13 | Navigate Stats and More | Content and behavior unchanged from 0.15.52 |
| P14 | Launch, open Tunnels, import profile, hit Back | Modern Home/modern Tunnels only; no legacy screens resurrected |

**Install official signed builds only after H.1 Safe Stop + independent H.2a CLEAN_STOPPED.** In Fedora checkout:

```bash
cd ~/Wonhee-Proxy-UI
git fetch origin
git switch feature/unified-everyday-ui-01548
git pull --ff-only origin feature/unified-everyday-ui-01548
bash scripts/build-wonhee-official-local.sh
# After verified CLEAN_STOPPED
bash scripts/install-wonhee-safe-update.sh
```

GitHub CI debug package is not an in-place replacement for the official original-signed app. Do not change Android Private DNS.
