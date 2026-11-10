# Wonhee 0.15.35 — Targeted, cancellable live-socket observation

## Why this follows PCAP 4

The user confirmed PCAPdroid captured **Google Messages (UID 10170) QUIC UDP/443** on the physical Wi-Fi underlay, and the 0.15.34 three-sample live `ss` inspection found actual protected fwmark `0xf009f` on **Google Play services** UID 10180 but no Messages sockets. Google Messages' direct QUIC sessions were shorter than a second; a 3-sample, 1.1-second-separated audit can easily miss them. KDE Connect's local Fedora TLS connection to port 48874 is a **LAN** flow and not itself a public Internet leak; Android UDP/500,4500 is likely user-enabled Wi-Fi Calling and must remain compatible.

## New opt-in Advanced Controls actions

- **Watch live socket marks for up to 15 seconds · read only** — starts a bounded, high-cadence `ss` TCP+UDP UID/fwmark metadata watch.
- **Stop live socket watch** — sets an immediate cancellation flag. Once any currently running read-only root-shell `ss` command returns, the worker stops before issuing further socket queries. Stop does not interrupt DNS, WireGuard or other apps.

The live watch records **no packet payloads or endpoints in the final report**. It uses the 0.15.34 parser, the exact same dynamic Android UIDs and verified WireGuard route ownership, collects only peak socket counts and *explicit* marks (missing `fwmark` remains UNKNOWN), and predicts fixed public routes with at most four distinct marks per UID. It never replays raw `ss` output into the journal.

## Resource / timing boundaries

- Maximum **48 sampling rounds**, monotonic elapsed deadline **15,000 ms** measured from the beginning of socket sampling, plus finite initial setup/verification and potentially the completion time of an already executing `ss` command. The 15 seconds is a sampling **target and stop condition, not a hard wall-clock process-kill deadline**.
- Between samples, nominal delay 150 ms; actual cadence is slower depending on root shell and device kernel performance. No background scheduler, no ongoing monitoring, no restart on errors. The user must explicitly tap Start again.
- **Stop** is always enabled only while this particular watch is active; cancellation yields a clearly partial report if one or more samples were gathered. If sockets are extremely short, even this watch may miss them.
- **No network probes/packets**, API mutations, app blocking or per-app configuration edits. The local `ss` tool uses kernel netlink for read-only inspection and does not open Internet sockets.
- `RootLiveSocketMarkEvidenceTest` now checks the bounded sample cap, monotonic deadline and cancellation predicate. CI does not prove device runtime socket visibility.

## Safe on-device usage

1. Use working, signed 0.15.34 as the baseline. 0.15.35 is an **optional locally signed candidate** on a separate draft branch. Do not install a debug/rootlab CI APK over the official app.
2. If elective installation is desired, first perform H.1 **Safe Stop** for all active profiles and H.2a **CLEAN_STOPPED**. Build using existing release keystore, then use the independently guarded Fedora updater. Preserve same signing identity and profiles.
3. After Safe Start, confirm AirVPN, Home/Navidrome, DNS relay and 3/3 owned split-route checks; keep Android Private DNS OFF and the all-traffic Batch F kill switch PAUSED.
4. Select both active profiles, tap **Watch live socket marks...**, then open Google Messages and use it normally while the approximately 15-second watch is active. Do not send messages to new recipients or induce a failed network state merely for testing.
5. Return to Wonhee and review the sanitized report. If you hit Stop, look for the **USER STOP REQUESTED** note. Use the old three-sample audit as a consistency check if useful.
6. If Messages marks still don't appear, do **not** infer that Messages is leak-free, protected or unprotected. PCAPdroid already showed real physical bypass flows; further correlation requires approved socket-specific tracing with strict privacy controls.
7. **Keep Wi-Fi Calling, RCS, Google Play services and microG enabled.** No firewall exception or app UID restriction should be introduced without separate compatibility tests.

## Limitations

The report is aggregate. The watch does **not** know that a socket's actual peer is Google, or that its actual public packets went over Wi-Fi. A captured `protectedFromVpn` mark is evidence of a marked socket only, not attribution of a specific historical PCAP flow. A fixed-address route prediction cannot prove a particular app packet's egress. This batch does not implement any form of all-app VPN-only guarantee.

**Protected code:** WireGuard kernel lifecycle, DNS relay/firewall and ad-blocking, Home split routes, Safe Stop, guard activation pause, Android app network permissions and local KDE Connect compatibility are unchanged.
