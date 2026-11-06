# Wonhee 0.13.0 — Batch E scoped observation + guard model

This is a **non-enforcing** batch that preserves the tested multi-tunnel kernel
interfaces and Batch B exact-match routing ledger. It supports any compatible
selection up to the encrypted store's current eight-profile limit.

The goal is one consolidated test of real packet observations (when available),
Android active-network DNS metadata, and hypothetical fail-closed decisions.
**No kill switch, firewall, DNS or route changes are installed by these checks.**

## One combined device test

1. Install `0.13.0-batchE-scoped-observation`. Keep USB ADB recovery ready and
   do not uninstall a differently signed build without saving its profiles.
2. Select the known working experimental profiles (currently `wgs_client1`
   and `AirVPNEurope`). They are not hardcoded tunnel slots. Leave your
   existing, verified split-route overrides unchanged.
3. Tap **Inspect UDP endpoint egress + Private DNS**. Capture the new
   **Active network Private DNS** and **Active Android network DNS** lines,
   in addition to the marked underlay endpoint routes. DNS addresses and
   provider hostnames are deliberately omitted from the report. This is
   configuration/UID-0 route metadata, **not observed resolver packets**.
4. Enter the numeric target `10.0.0.169:4533` and tap **Preview fail-closed
   decision · NO rules**. It should require the Home profile when all
   selected tunnels are hypothetically up and say **WOULD BLOCK** if that
   required tunnel is hypothetically down. Nothing is activated or blocked.
5. Optional, with informed consent: tap **Observe filtered TCP packet headers**
   and explicitly approve. Wonhee validates every selected public identity,
   then attempts a 4-second `tcpdump` capture per interface filtered to the
   numeric target and TCP port. It also opens one TCP handshake per profile.
   It reports only packet counts and whether each TCP connection completed.
   There is no raw address/packet output and no pcap file saved. The filter
   limits captured traffic, but it cannot attribute packets to a particular
   UID. If `tcpdump` or `timeout` is missing, expect **UNAVAILABLE** and do
   **not** install untrusted root binaries just to satisfy this test.
6. Optionally repeat the guard model and packet observation with an IPv4 or
   bracketed IPv6 numeric Internet service; this exercises a different
   selected route branch without changing the tunnels.
7. Confirm normal connectivity remains intact after returning to Wonhee.
   The new buttons must not create `WN_MULTI_GUARD4`/`WN_MULTI_GUARD6`,
   modify Android policy rule priorities, or change known tunnel identities.

**Send one report** combining the endpoint/DNS result, guard-model result,
and scoped-capture result (or UNAVAILABLE). Previous Batch C/D tests do not
need to be repeated unless an existing behavior regresses.

## Interpretation and current limits

- A filtered packet line on the expected WG interface is stronger evidence
  than a root route lookup or byte-counter change. It still does not prove
  which UID originated the packet or that all other traffic is leak-free.
- Zero observed packets is **inconclusive**: capture readiness, timing, filter
  conditions and connection failures can all explain it.
- Android `LinkProperties.isPrivateDnsActive()` reports the active network's
  status, not each application's DoH/DoQ use or real resolver packet routes.
- The fail-closed preview is a **pure hypothetical route model**. It neither
  constructs nor installs iptables/ip6tables rules. A down-tunnel WOULD BLOCK
  prediction is not proof that Android blocks traffic today.

## Gate before future enforcement

The later active guard must use **verified endpoint-specific underlay policy**
instead of globally trusting shared `0x20000` marks. It must handle DNS,
IPv6, endpoint changes, Wi-Fi/cellular handoff, tunnel stop/failure, app crash
and reboot. Firewall ownership and rollback must be exact-match and recoverable
over ADB before a fail-closed option can be offered.
