# Wonhee 0.15.38 — User-invoked direct-route advisories

## What is new
This source-only candidate extends the existing **Compare actual public socket peer routes · read only** action, without adding another button or scrolling section. It reports a **READ-ONLY DIRECT ROUTE ADVISORY** separately for Android system, Google Messages, and Google Play services / compatible microG, resolving installed package UIDs on the phone rather than guessing from old captures.

Warnings are based on observed same-socket UID, explicit fwmark, validated numeric public destination, and a read-only kernel route lookup against that ACTUAL public peer. The result is a **route prediction, NOT proof a packet actually used the physical interface**.

- **POTENTIAL DIRECT PUBLIC ROUTE**: at least one observed peer/mark combination predicts physical Wi-Fi (wlan0). Reports protected and ordinary marks separately.
- **UDP/443 compatible with QUIC**: count only if the observed socket is UDP with public peer port 443 AND that peer/UID/mark predicts Wi-Fi. This is NOT protocol confirmation or inspection of encrypted content. It must not confuse carrier IPsec UDP/500 or /4500 with QUIC.
- **NO PUBLIC SOCKET PEER OBSERVED**: transient app may have been idle, short-lived, or have an unavailable peer; NOT a clean or VPN-only verdict.
- **ROUTE NEEDS REVIEW**: unknown route or other tunnel prediction.
- **NO DIRECT ROUTE PREDICTED among sampled sockets**: still NOT proof that an app or device cannot bypass VPN.
- Android system warns that some connections could be carrier IMS/Wi-Fi Calling; never advises automatically blocking. Messages and Play services RCS and push remain enabled.

## Resource boundaries
The existing bounded watch remains at **48 samples OR a 15-second monotonic sampling deadline**, at most six retained public peer+mark combinations per UID, 18 overall, and 18 read-only kernel route lookups. The existing **Stop live socket watch** control cancels before the next query after the current one returns. A foreground user action is required for each watch. There are no background monitoring, notifications, recurring tasks, or enforcement changes.

## Privacy
Only aggregation counts and categories are reported. The candidate stores a boolean UDP/443 hint, not a remote port history. Public peer literals, socket metadata, local network addresses, message data, DNS queries, cookies and raw root-shell output are NOT printed, uploaded, written to diagnostics/journal or committed. Local KDE Connect and Navidrome destinations are excluded from public peer sampling.

## Preserved baseline and QA
No VPN, routes, iptables, DNS, tracker blocking, Android permissions, RCS, microG/Google services, Wi-Fi Calling or Safe Stop changes. All-traffic Batch F guard is still PAUSED. Android Private DNS stays OFF as Automatic/custom previously broke the user's Wi-Fi. The separate intermittent DNS startup failure remains tracked in PR #72; this does not fix it.

Candidate 0.15.38 / versionCode 85 requires green Android/native CI and on-device testing before any release claim. To test the signed APK, first select every active profile, run H.1 Safe Stop, confirm H.2a CLEAN_STOPPED, sign with the original release key on Fedora, and install with the independent guarded updater. Do not replace the installed official app with a debug artifact or force a network interruption. After Safe Start check Internet, DNS filtering, Home/Navidrome, RCS and Wi-Fi Calling before the manual read-only audit.

A real per-app fail-closed routing policy is deferred to a separate opt-in and carrier-compatibility design.