# Wonhee 0.15.62 — one release, no fake multi-exit success

**Status: DRAFT / DO NOT SIGN OR INSTALL YET.** Based on 0.15.61 (versionCode 108).
Do not increment to versionCode 109 or add this branch to the official release-signing allowlist until every release gate below has evidence. This milestone intentionally bundles reliability and **real** multi-exit routing; it is not complete when the UI looks finished.

## User outcome to accept on rooted Pixel 8a (Android 16)

The Home screen must let the user import or select multiple saved tunnels without a redundant Lab selector:
- AirVPN Europe (Netherlands) handles a chosen group of installed apps.
- AirVPN America (US) handles another chosen group of installed apps.
- Fedora Home (private destination 10.0.0.169/32 and 10.77.0.0/24) reaches Navidrome, while the other two tunnels remain connected.
- TCP/UDP destination-port overrides take precedence over an app's category default.
- User can see exactly what is **connected**, which exit each active rule uses, and what is merely **saved, planned, parked, unavailable, or blocked**.
- One Start and one Safe Stop remain on Home; Stop must work without asking the user to rediscover every active profile if the active identities can be verified from the persistent session record.
- Android Private DNS stays OFF. No hidden default/fallback when a required VPN fails.

The imported WireGuard profiles' keys, endpoints and AllowedIPs are immutable unless the user explicitly edits a profile. Never share keys or full private tunnel configurations in logs or GitHub.

## Work started on this branch

1. Fix strict owned-rule comparison when Android prints an exact IPv4 host **without /32**, or an IPv6 host **without /128**. The fix refuses different CIDRs, hosts, marks, UIDs, priorities and lookup tables.
2. Add tests reproducing the exact interrupted 2026-11-19 device state: saved 12500 /32 and 12501 /24, only 12500 live. Verify rollback preflight accepts the one exact remaining host and also accepts both already absent.
3. Show the primary exit picker directly on Home. Avoid Android dialog configurations in which a message obscures the option list. Do **not** misrepresent the parked full-exit profiles as running.

## Rootless multi-exit backend groundwork (2026-11-19)

- `RootMultiExitKernelPlan` now compiles an existing validated, dry-run
  `RootPerAppUidPolicyPlan` into **independent IPv4/IPv6 private-table route
  steps** and **per-UID TCP/UDP destination-port selection steps**. For each
  selected UID/protocol selector it produces a lookup-priority rule and an
  adjacent unreachable-priority rule in BOTH address families.
- Each proposed kernel operation has a precise inverse and a reverse-order
  rollback preview (remove selectors first, private table routes last).
- Compiler rejects incomplete IPv4/IPv6 Internet exits for assigned apps,
  duplicate/mismatched route ownership, duplicate default routes,
  system UIDs, collisions in reserved priorities, bad CIDRs and invalid
  port/transport selectors. No plan changes the installed profiles.
- The existing App Routing **read-only UID check** now reports the compiled
  policy counts alongside its visible blockers. Android CI includes Java
  tests and source checks confirming there is no shell execution.
- Linux iproute2 documents `uidrange`, `ipproto`, `dport`,
  `lookup` and `unreachable` selectors/actions. Actual **Android**
  tool/kernel compatibility, socket L4 classification and netd/mark behavior
  are not established by Linux documentation or a successful core test.
- Crucially: `activationAllowed()` remains `false` in BOTH planners.
  Do not call any generated install or rollback commands on a real phone.
  This is the preflight/compiler layer, **not live policy routing**.

## Pixel 8a Android 16 ip-rule compatibility audit (2026-11-19)

User-supplied **read-only device evidence** for kernel
`6.1.145-android14-11-gec45f20f38ea-ab15260282`:

- `ip -4 rule help` and `ip -6 rule help` advertise `fwmark`,
  `iif`, `pref` and `uidrange`. Both **omit** `ipproto`,
  `sport` and `dport`; the selected Android command-line utility must
  not be assumed to accept this project's direct L4 selector syntax.
- `ACTION` help also **omits** `unreachable`, despite the **existing**
  Android RPDB rule `32000: from all unreachable`. The existing rule is
  evidence that the kernel's policy database represents this action; it
  is **not proof** that the Android CLI can add/remove a specific rule
  with this action. No write probe is authorized.
- Android-owned priorities include 10000, 11000, 15040, 15998/15999,
  16000, 17000, 18000–20000, 22040, 22998/22999, 25000, 29040,
  29998, 31000 and 32000. Observed device tables include
  `wlan0`, `rmnet16`, `ipsec13`, and `local_network`; these are not
  Wonhee-owned and must never be flushed or repurposed.
- Both families report no Wonhee-owned 12500–12799 rules. This does
  **not** independently confirm DNS/firewall ownership cleanup; H.2a
  `CLEAN_STOPPED` remains a release gate.
- Added pure `RootIpRuleHelpCapabilities` and
  `RootIpRuleHelpCapabilitiesTest` to preserve this diagnostic, warn
  about missing direct L4 selectors, and refuse to equate help text
  with a kernel/traffic-safety check.
- **Backend decision**: do not attempt to execute conceptual
  `ip rule ... ipproto ... dport ...` rules on this Pixel 8a. Evaluate
  a separately verified per-app TCP/UDP classifier that writes an
  owned packet mark (netfilter or BPF, after feature detection), then
  restrict the RPDB to the device's available UID/mark selectors.
  Prove marks cannot collide with Android netd/protectedFromVpn bits,
  prove encrypted DNS ownership, and enforce selected-exit loss
  without leaking onto another VPN or the physical network.
  Neither alternate backend is implemented or activated by this PR.

## Mandatory unfinished engine work — blocks release

1. Start **multiple independent full Internet exits**, not only one default plus specific destination tunnels. Each must have an isolated IPv4 and IPv6 routing table, stable owned interface identity, encrypted DNS policy, correct WireGuard UDP endpoint path, and tracked kernel ownership. Avoid conflicts with Android netd and other VPN apps.
2. Enforce installed-app current UIDs and TCP/UDP destination-port overrides in actual traffic. Precedence: exact UID+transport+port, UID+transport, UID/category, device default. Never assume an old UID remains valid across reinstall/shared UID/multiuser change. Categories are not the transport enforcement engine.
3. Fail closed **for a selected app's required exit**, IPv4 and IPv6, without routing onto a different exit or the unprotected cellular/Wi-Fi path. All-traffic kill-switch (Batch F / issue #41) stays disabled until independent device tests prove safety; do not silently bypass its activation gate.
4. Verify actual handshakes, received bytes and controlled reachability for each selected WireGuard peer; an interface that is UP or a route simulation alone is not a success. Clearly distinguish endpoint IPv6 failures, server key/address mismatch and DNS startup failure (including LOCAL_DNS_TIMEOUT).
5. DNS relay and firewall ownership must be scoped and recovered consistently per exit; document any policy limitation before enabling multiple full exits. No DNS leakage on a failed required-exit path.
6. Update both Start and Safe Stop to journal every actual active/parked profile and its rule ownership. Safe Stop must clear exact DNS/routing ownership before disconnect and must tolerate a partially completed deletion. Never flush foreign firewall rules or guess who owns a route.
7. Provide direct Home presets/roles (default Internet, app-specific Internet, private destination, custom) with a simple one-screen flow and plain-language validation. No repeated port/tunnel mapping on separate screens.
8. On-device smoke tests: Europe+US+Fedora Home simultaneously connected, distinct app paths verified with packet evidence, Navidrome GET succeeds from browser, app behavior verified, cellular↔Wi-Fi transition tested, safe stop twice, reinstall and restore tested without loss of profiles. Run zero-fallback / no leaking / exact cleanup audits.

## Engineering safety: current constraints

Current RootTunnelStartSelection intentionally **parks additional full exits**. RootMultiTunnelPlan.validate rejects overlapping defaults. The persistent category/port rule editor is **planning-only**. Do not delete these guards to make the UI report three tunnels. Issue #89 tracks the actual backend implementation and #41 tracks the separate all-traffic firewall gate.

## Release / CI gates

- Java rootless routing tests, Python static UX tests, Android build and native WireGuard tests must pass.
- Never infer **real-device networking success** from CI. Explicit tests on a spare/rooted device with USB ADB recovery required.
- Independently verify H.2a **CLEAN_STOPPED**, IPv4/IPv6 reserved range 12500–12799 empty, no Wonhee kernel links, no tagged DNS firewall/relay and cleared ledgers before any official in-place install.
- Only after acceptance: raise versionCode from 108 to >=109, change versionName to 0.15.62, include the branch in signing allowlist, build with the existing official keystore, verify cert fingerprint, and use the safe installer. Do not uninstall the installed official app.

This document is a release gate, not evidence the unfinished multi-exit features work.
