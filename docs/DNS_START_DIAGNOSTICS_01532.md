# Wonhee 0.15.32 — Safe Start DNS failure-stage reporting

## Observed device event

User screenshot: `CHECK REQUIRED / START FAILED AT DNS / Automatic safety rollback succeeded`. Batch H.1 then verified **DNS enforcement OFF**, owned split routing **CLEAR**, both selected kernel tunnels **DOWN (2)**, unattended recovery manually stopped and no all-traffic kill switch installed. The screenshot does not include a DNS substage. Do **not** infer that relay launch, DNS upstream route, blocklist compilation or firewall installation is the cause.

## Root cause of missing diagnostics

`RootMultiKernelSession.enableRootDns` already tracked `POLICY_PREFLIGHT`, `UPSTREAM_ROUTE`, `RELAY_LAUNCH`, `LOCAL_DNS_HEALTH`, `FIREWALL_INSTALL` and other stages, but `RootMultiKernelActivity.rollbackFailedStart(chosen, stage, reason)` discarded its `reason` entirely after performing Safe Stop. For failure after DNS ledger commit, `enableRootDns` also omitted the phase after successful rollback. Thus the UI couldn't show the failure phase.

## Fix in this release

- Preserve a whitelisted DNS activation *phase only*, with safe generic next steps. **Never display raw resolver URLs, numeric bootstrap, peer endpoint or shell exception**.
- Preserve the stage after post-ledger exact DNS owned-rule rollback or incomplete rollback.
- Add `RootDnsStartFailureTest` for recognized/missing stages, private content redaction, relaunch failure, upstream route failure and no unverified diagnosis.
- No changes to actual encrypted DNS transport, tracker filter, firewall rule install/remove, WireGuard interface setup, routing, automatic safety rollback, or Batch F all-traffic guard.
- Stage reporting is advisory. If a complete rollback failed, stop and follow ownership recovery rather than repeating starts.

## Safe device path

1. After the observed rollback, run existing read-only **H.2a lifecycle recovery audit**; expect `CLEAN_STOPPED`. If not clean, inspect rather than install or manually clear routes/iptables.
2. Keep ordinary Internet available until desired testing. **Android Private DNS remains OFF**, as Automatic or a custom provider previously broke Wi-Fi on the Pixel 8a.
3. This branch is an **official local signed candidate**, versionCode 79. Build with the same existing release keystore. Only replace the previous official app after H.1 Safe Stop, H.2a `CLEAN_STOPPED` and the guarded Fedora installer. Do not install debug/rootlab APK over production.
4. One elective Safe Start attempt can now show `DNS activation phase: ...` if it fails. Capture the sanitized report and compare with the root relay, route, profile and firewall diagnostics. Do not cycle failures repeatedly or enable Batch F.
5. Keep private PCAP files and raw resolver/proxy configurations off public PRs.

**This patch reports the cause's *stage*, not a validated fix for the underlying DNS startup failure.**
