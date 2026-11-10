# Wonhee 0.15.36 — separate local DNS upstream vs tracker health failure phases

## User-visible incident

On Pixel 8a running a newer locally signed Wonhee diagnostic build, a manual Safe Start returned:
`CHECK REQUIRED / START FAILED AT DNS / DNS activation phase: LOCAL_DNS_HEALTH`.
The app then reported a successful *automatic H.1 Safe Stop* with owned DNS OFF, owned split routing CLEAR and both selected WireGuard tunnels verified DOWN. No all-traffic guard was installed. **The screenshot cannot identify whether the encrypted upstream A reply or local tracker NXDOMAIN check failed.**

## Confirmed cause of ambiguous diagnostics

Current `RootMultiKernelSession.enableRootDns` performs both of these under the **same** `LOCAL_DNS_HEALTH` label before committing the DNS firewall ledger:
1. `RootDnsRelayRunner.healthQuery()` makes a UDP loopback `127.0.0.1:53535` query for a verified `example.com A` response forwarded via the strict configured encrypted upstream; local socket read timeout **9000ms**.
2. When tracker filtering is on, `RootDnsRelayRunner.blockedHealthQuery()` requests locally blocked `app-measurement.com A` and requires a particular `NXDOMAIN` response. It also waits at most 9000ms.

Thus `LOCAL_DNS_HEALTH` could mean a slow upstream response, unexpected DNS answer, tracker policy mismatch, or local tracker query timeout. Because the relay already had a listener, no conclusion about relay process death or the configured resolver's correctness follows from the failure alone.

## 0.15.36 fix: stage precision, not network changes

**One substage per test, with optional timeout classifications, and no skipped safety checks:**

- `LOCAL_DNS_HEALTH`: the encrypted upstream A-answer validation did not return a verified A record (excluding timeout).
- `LOCAL_DNS_TIMEOUT`: the local UDP health query timed out after its existing 9-second timeout. This alone does not separate slow upstream from a delayed local relay.
- `LOCAL_TRACKER_HEALTH`: upstream A-answer check passed, but the local block response was not the expected `NXDOMAIN`.
- `LOCAL_TRACKER_TIMEOUT`: upstream A-answer check passed, but the local tracker query timed out.

The existing allowlisted, privacy-safe `RootDnsStartFailure` renderer now recognizes these labels. No raw private DNS resolver URL, bootstrap, IP address, domain list, WireGuard endpoint/keys, or shell output is printed in the report.

**Unchanged:** no extra DNS retries, no longer timeout, no plaintext fallback, no relaxation of tracker checks, no firewall/routing/tunnel changes, no auto recovery, and the existing automatic full-stack Safe Stop continues unchanged. Android Private DNS remains OFF on the user's device (Automatic/custom previously caused Wi-Fi loss). All-traffic Batch F guard remains paused. No app reconfiguration or network restart is performed by this source change.

## Safe next steps

1. After the failed Safe Start, run the **read-only H.2a lifecycle recovery audit**. Expect `CLEAN_STOPPED`. If not clean, do not install, uninstall, reboot, change Wi-Fi, flush iptables or clear app data.
2. If normal Internet is restored and H.2a is clean, leave everything stopped unless a new test is necessary. The stopped DNS relay should **not** be expected to answer `dig @127.0.0.1 -p 53535`.
3. 0.15.36 (`versionCode=83`) is only a **source candidate**. Android/native CI must be green before any elective device install. Use original signing identity and independent guarded Fedora installer after H.1 Safe Stop/H.2a `CLEAN_STOPPED`. Do not substitute rootlab debug APK.
4. One elected Safe Start on an updated app may now identify which exact local health probe fails (if incident recurs). If it succeeds, preserve that stable session rather than forcing more starts.
5. Future substantive fix depends on the precise failing stage and reproducible timing/relay evidence. Do not assume DNS configuration or tracker list is broken from the earlier screenshot.

## Regression tests

`RootDnsStartFailureTest` now asserts all four substage labels and that upstream/host data is excluded from the UI. Android Gradle and native WireGuard CI remain required, but the change does **not** prove that the intermittent on-device DNS failure has been fixed.
