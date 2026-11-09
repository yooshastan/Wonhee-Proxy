# Wonhee 0.15.27 — Firewall frontend clarity and rooted PCAP baseline

**Scope:** UI labels and read-only verification only. Batch F activation remains quarantined. No iptables, ip6tables, DNS, tunnel, or route mutations in this batch.

## What the UI must distinguish

- **Encrypted DNS relay:** a locally running relay is not independently verified DNS-port enforcement.
- **DNS-port firewall:** persisted DNS ownership is not an audit of the live iptables/ip6tables chains. Show an explicit "run live audit" prompt.
- **All-traffic kill switch:** permanently display an unavailable/safety-paused state while `RootGuardSafetyGate.activationPaused()` is true. The ledger alone cannot prove chains absent or protection active.
- **Exact rollback:** owned-rule cleanup and live read-only audit remain visible in Advanced Controls. Never present the disabled "enable guard" / underlay challenge controls as a usable feature.

The dashboard is read-only, so the existing Batch H.1 manager retains Connect / Safe Stop.

## Rooted packet-capture baseline: safe observational pass

Run only after verifying that two chosen WireGuard tunnels are healthy and the Batch F guard is **not enabled**. Use an external rooted packet-capture app in passive mode; whether it can see kernel `wnm*` interfaces depends on the capture backend and Android kernel. Android Private DNS remains OFF for this test setup. **Do not enable Batch F** to produce a capture.

1. In Wonhee, use **Verify live IPv4/IPv6 guard + rollback ledger · read only**. Confirm no owned `WN_MULTI_GUARD4` / `WN_MULTI_GUARD6` OUTPUT anchors/chains exist. If the audit is inconclusive, stop the test rather than changing rules.
2. **PCAPdroid:** Settings → enable **Root capture**, leave **TLS decryption / MITM addon off**, select **PCAP file** dump mode if saving evidence. Root mode works without creating a competing Android VpnService and automatically follows the internet-facing interface; it does not support MITM/TLS decryption. Start with the physical underlay (`wlan0` or `rmnet*`). If your PCAPdroid version exposes a **capture interface** selector, make separate, labeled captures for the Home `wnm*` and Internet `wnm*` interfaces, rather than assuming all interfaces are present in the default capture. If tunnel selection is unavailable, record that limitation instead of interpreting missing packets as zero traffic.
3. Begin a bounded capture while both tunnels remain stable. Use a browser to open the known Navidrome endpoint `http://10.0.0.169:4533` **without submitting credentials**, and load one HTTPS website through the Internet tunnel. Moka is currently expected to refuse its Android-VPN-only private HTTP route check.
4. Stop capture promptly. Compare by **interface**: the physical underlay should carry encrypted WireGuard UDP toward peer endpoints, not plaintext TCP to `10.0.0.169:4533`; the Home tunnel may show private TCP if that interface is visible. Plain HTTP on the tunnel interface is not an underlay escape.
5. Record only redacted interface names, protocol/port summaries, direction and packet counts; optionally the timestamped result of Wonhee's read-only live guard audit. Do **not** share full unredacted PCAPs, authentication headers, DNS names or WireGuard peer IPs/keys in public issues.
6. Confirm browser and HOME connectivity after the capture. Repeat only if the first capture is incomplete or the interfaces were misidentified. When sharing, prefer screenshots of **Connections**, protocol/destination summaries, and only the necessary redacted metadata. A full plaintext Navidrome PCAP may include server credentials, headers or library details; review or sanitize it before sending to anyone.

**Important limitations:** Capturing a packet on an interface is not proof that it crossed Android's local `OUTPUT` netfilter hook or which UID generated it. A clean five-second window does not prove leak immunity, reliable handoff or kill-switch behavior. Never interpret normal direct traffic *after Safe Stop* as a failure of a kill switch that is intentionally OFF.

## Do not attempt in this batch

- Turn on Batch F, remove the compile-time safety gate, insert test reject rules, or flush broad firewall chains.
- Intentionally drop a tunnel, toggle Wi-Fi/cellular, or force DHCP/IPv6 neighbor renewal under an active guard on the primary device.
- Claim whole-device leak prevention from a browser IP-checker or a short PCAP.

## Exit criteria

- Dashboard Home and Protection show identical all-traffic kill-switch meaning.
- DNS relay, DNS-port enforcement ledger, and all-traffic guard are clearly separate.
- Lab activation and underlay test controls are visually marked safety-paused and remain disabled.
- Android build passes; UI tests on device verify labels and unchanged working tunnels.
- A sanitized baseline capture is reviewed before any **separately staged**, independently recoverable firewall-enforcement test.

## PCAPdroid-specific reference

- [Official root capture limitations](https://emanuele-f.github.io/PCAPdroid/advanced_features.html): root capture auto-detects the physical network interface, can coexist with other VPNs, and cannot use the MITM/TLS decryption addon in root mode. Root mode's app identification can also miss some DNS handled by Android netd.
- [Official capture instructions](https://emanuele-f.github.io/PCAPdroid/quick_start.html): choose PCAP file output to save evidence, use Connections to review flows, and avoid a global app filter when testing system-level DNS and control-plane traffic.
