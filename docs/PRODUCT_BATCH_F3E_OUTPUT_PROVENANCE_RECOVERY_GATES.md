# Wonhee Batch F.3e — OUTPUT provenance and independent recovery gates

**Status: design and evidence gate only. No APK build, enforcement, new kernel tracing hooks, packet generation, firewall rule installation or rule/counter reset authorized.** Branch is based on the passing 0.15.18 F.3d diagnostic. Product Batch F remains **unimplemented and unsafe to activate**; issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains open.

## Why stop creating read-only counter versions

The Pixel 8a captured an outgoing physical `wlan0` **ICMPv6 Neighbor Solicitation (type 135)**. During the same five-second F.3d observation, pre-existing global filter/OUTPUT counters increased: IPv4 default-policy +33, five of six rule counters advanced (summed +166); IPv6 default-policy +44, four of six rule counters advanced (summed +176); physical `wlan0` TX +37. Both selected WireGuard identities and the exact three recorded/live HOME split-routing overrides matched; Batch F owned IPv4/IPv6 guard was OFF/ABSENT.

This is evidence of two **concurrent observations** — physical IPv6 neighbor discovery and global OUTPUT counter movement — **not** evidence of the observed packet traversing INPUT, OUTPUT, raw/mangle, netfilter, a specific chain or rule. Rule-counter sums are not unique packets. Neither UID nor process nor kernel socket origin was established. No evidence isolates the original 0.15.12 connectivity incident to a particular packet class. Post-0.15.18 Navidrome and public browsing regression is not yet explicitly reconfirmed.

## Initial Pixel 8a capability inventory (user-provided, 2026-11-08)

- Root command execution confirmed: `uid=0(root)`, Magisk context.
- Present: `/system/bin/tcpdump`, `strace`, `simpleperf`, `bpftool`, `tc`, `iptables-save`, `ip6tables-save`.
- Not found on PATH: `perf`, `bpftrace`, `nft`. These are not required for the next read-only inventory; do not install them yet.
- `/sys/kernel/tracing` exists and is mounted as tracefs with read/write mount flags; `/sys/kernel/debug/tracing` is absent, and debugfs is not shown as mounted. `/sys/fs/bpf` is mounted; `/sys/kernel/btf/vmlinux` exists (about 5.4 MiB).
- Trace state: `tracing_on=0`, `current_tracer=nop`, and `available_tracers=nop` only. No tracer was enabled or changed.
- The initial event search was truncated to the first 80 matches and returned wireless/cfg80211/mac80211 and TIPC events. It did not establish whether the needed core network, skb, socket, neighbor, IP, or netfilter tracepoints exist. Do not infer absence from this partial output.
- **Interpretation:** tracefs, BTF and bpffs being mounted establishes that relevant inspection surfaces exist, not that attaching an eBPF program or trace event is safe or permitted. Tracepoint availability and formats, plus currently loaded BPF program/link inventory, remain unverified. No kernel state changed during this inspection.

## F.3e, Phase 1: capabilities only (non-invasive)

Design a small, **explicitly requested, read-only, local device capability inventory**. Do not run this automatically and do not mark missing capabilities as leaks. Prefer inspecting kernel-exposed metadata/available events, not attaching tracers or changing tracefs knobs. Any root read must be finite, output-limited, validated against expected paths, and leave only aggregate booleans in the UI.

Record whether:

- The device exposes readable Linux trace-event listings under expected `/sys/kernel/tracing` or `/sys/kernel/debug/tracing` paths. **Do not mount tracefs/debugfs merely to make it accessible.**
- Relevant packet/netfilter/skb or WireGuard tracepoints are *advertised* by the running kernel, and whether their format metadata is readable. **Presence means capability candidate only**; it does not prove attach permissions, stable packet identity, UID visibility, or that the hook receives Neighbor Discovery.
- Existing IPv4/IPv6 filtering backends can be identified from **read-only** tool metadata. Avoid probing by inserting, zeroing, flushing or setting defaults. Never assume that reading `iptables -S OUTPUT` inventories all active Android networking hooks, including eBPF and other netfilter tables.
- Existing root- and shell-access prerequisites can be checked **without requiring network connectivity**. A working Termux session is *not* an independent rescue channel.

The summary must distinguish `AVAILABLE`, `NOT EXPOSED`, `PERMISSION DENIED`, `INDETERMINATE`, and `UNSAFE TO PROBE`. Do not display event payloads, socket addresses, keys, endpoint tuples, private UID associations, process names or raw kernel state. No pcap or persistence of raw readings.

## Pixel 8a targeted network tracepoint and BPF inventory (user-provided, 2026-11-08)

### Tracepoint availability

The full targeted prefix query returned these relevant events:

- skb: `kfree_skb`, `consume_skb`, `skb_copy_datagram_iovec`.
- net: `net_dev_start_xmit`, `net_dev_xmit`, `net_dev_xmit_timeout`, `net_dev_queue`, `netif_receive_skb`, `netif_rx`, and NAPI/receive entry/exit events.
- sock: `sock_rcvqueue_full`, `sock_exceed_buf_limit`, `inet_sock_set_state`, `inet_sk_error_report`.
- udp: `udp_fail_queue_rcv_skb`.
- tcp: retransmit, reset, destroy, receive-space, probe and congestion-state events.
- fib: `fib_table_lookup`.
- neigh: `neigh_create`, `neigh_update`, `neigh_update_done`, `neigh_timer_handler`, `neigh_event_send_done`, `neigh_event_send_dead`, and lifecycle events.

No `nf:`, `netfilter:`, `ip:`, `ipv6:` or `wireguard:` event groups appeared in the user's full matching output. This does not mean netfilter is absent; only that these named tracepoint groups were not advertised by `available_events` in this query.

### Existing BPF inventory

- `bpftool prog show` displays Android system programs including `sched_cls` tether/ingress/egress, `sched_act`, `cgroup_skb` ingress/egress, socket filters and `cgroup_sock`. Program output was capped at 60 lines, so total inventory was not established.
- Visible map names include tethering statistics/limits/downstream/upstream, CLAT ingress/egress, socket policy and IPv4/IPv6 DSCP policy. Do not inspect map values.
- `bpftool link show` showed one raw tracepoint link to `sched_process_free`; this is **not** a complete attachment inventory because TC `sched_cls` programs may be attached through qdiscs/netlink rather than BPF links.
- `bpftool btf show` lists `vmlinux` BTF and many module BTF objects. BTF existence is metadata availability only.
- No BPF program, link, map or attachment was changed, detached, loaded or pinned by the inspection.

### Interpretation and next read-only checks

The skb/net transmit and FIB/neighbor events are promising for packet lifecycle and egress correlation. They still do not expose a named netfilter local OUTPUT tracepoint in the reported event groups. Exact event `format` metadata must be reviewed to see whether skb identity, device, protocol, length and neighbour context are available. Any packet correlation must handle skb cloning/reallocation; an skb pointer alone is not guaranteed to remain a stable packet identity across the whole path.

Next: read format metadata only for `skb:kfree_skb`, `net:net_dev_queue`, `net:net_dev_start_xmit`, `net:net_dev_xmit`, `fib:fib_table_lookup`, `neigh:neigh_event_send_done`, and `sock:inet_sock_set_state`; then inspect existing BPF/TC attachment metadata using `bpftool net show`, `ip -br link`, `tc qdisc show`, and `tc filter show` for wlan0 and the two selected tunnel interfaces. These are inventory commands only. Do not run BPF feature probes that load test programs, enable trace events, mount filesystems, dump map values, or mutate TC state.

## Pixel 8a event-format and attachment inspection (user-provided, 2026-11-08)

### Event formats

- `skb:kfree_skb` exposes `skbaddr`, `location`, protocol and `skb_drop_reason`. The printed reason enum includes `NETFILTER_DROP`, `BPF_CGROUP_EGRESS`, `TC_EGRESS`, `TC_INGRESS`, `QDISC_DROP`, `IP_OUTNOROUTES`, `NEIGH_FAILED` and others. This can classify certain skb drop outcomes, but does not by itself identify the exact firewall rule or prove successful packet traversal through OUTPUT.
- `net:net_dev_queue`, `net_dev_start_xmit`, and `net_dev_xmit` expose device, skb address, length and (for xmit) return code; start_xmit also includes protocol/segmentation metadata.
- `fib:fib_table_lookup` exposes table ID, input/output interface indices, protocol, addresses, ports and selected device/gateway fields. This is useful for correlating route decisions, not a substitute for packet-hook evidence.
- `neigh:neigh_event_send_done` exposes address family, device, neighbor target/state and error; it does not identify a specific skb.
- `sock:inet_sock_set_state` exposes socket pointer, address family, protocol, endpoints and state transitions, but no UID field.
- Correlation across these events is only provisional: skb clones/reallocation/segmentation may change skb identity, and a time/tuple match alone is not a unique packet proof.

### Attachment inventory

- `bpftool net show` displayed empty XDP, TC, flow-dissector and netfilter sections.
- `tc filter show` returned no displayed filters for `wlan0`, HOME tunnel `wnma292ddb4b6da`, AirVPN tunnel `wnm68fe81200daa`, `rmnet16`, or `ipsec171`. The latter two were checked after the initial inventory.
- `tc qdisc show` shows `clsact` qdiscs on `rmnet16`, `wlan0`, and `ipsec171`, but the inspected devices showed no attached TC filters. An empty `clsact` qdisc does not itself mean a filter is attached.
- `bpftool cgroup tree /sys/fs/cgroup` confirms **14 Android cgroup BPF attachments at the cgroup-v2 root**: inet ingress/egress, inet sock create/release, IPv4/IPv6 bind, IPv4/IPv6 connect, UDP4/UDP6 sendmsg and recvmsg, getsockopt, and setsockopt. These are existing Android networking programs; do not detach, replace, pin, load over, or modify them. Root-cgroup attachment means the cgroup/socket policy layer must be accounted for when reasoning about app traffic.
- `bpftool net show` displayed empty XDP, TC, flow-dissector and netfilter sections. This does not negate the cgroup attachments shown by `bpftool cgroup tree`; the commands inventory different attachment families.
- `bpftool prog show` lists Android system programs including tethering `sched_cls`, CLAT, cgroup-skb ingress/egress, socket filters and cgroup-sock. Loaded does not mean attached to a selected network interface. Do not inspect map values or alter any Android BPF program/map.
- Remaining read-only question: identify the currently active physical underlay carrying the WireGuard outer transport before attributing any device-level observations. No TC/BPF mutation.

### Active network topology — 2026-11-08 (read-only)

- `dumpsys connectivity` reports **Active default network: 176**, whose `NetworkAgentInfo` is validated `WIFI` on `wlan0` (`192.168.50.84/24`, gateway `192.168.50.1`). This identifies Wi-Fi as Android's current default network at capture time.
- A separate validated `MOBILE[LTE]` network is on `rmnet16`, with `INTERNET` capability and its own IPv4/IPv6 default routes. It is connected, but it is not the active default network in this snapshot.
- `ipsec171` belongs to `MOBILE[IWLAN]` with `extra: IMS`; its capabilities include `IMS`/`IA` but omit `INTERNET`. Its IPv6 default route is scoped to that network. Treat it as a carrier IMS/IWLAN path, not as the general Internet underlay and not as proof of WireGuard transport.
- The main IPv4 table contains only the directly connected Wi-Fi subnet; Android's policy rules and per-network routing tables determine the other paths. The displayed rules include both WireGuard interface/table identities and marks, but they do not reveal the peer endpoint route or prove which physical device carries either tunnel's outer UDP packets.
- **Conclusion:** `wlan0` is the current Android default network; `rmnet16` is a connected validated cellular Internet network; `ipsec171` is a separate IMS/IWLAN network. The actual outer transport for each WireGuard peer remains **UNPROVEN** until its endpoint address and applicable socket/fwmark route are resolved. Do not infer tunnel underlay solely from the default network.
- Next read-only step: obtain each tunnel peer endpoint IP/port without exposing private keys, then run endpoint-specific `ip route get`/`ip -6 route get` with the relevant mark (if established) and inspect the corresponding per-network route tables. No packet generation or routing changes.

### Decision update

Tracepoint metadata is sufficiently promising to design a *future* bounded observational prototype, but there is still no proven direct local-OUTPUT success tracepoint in the inventory. A drop reason `NETFILTER_DROP` is useful only for packets actually dropped with that reason; it cannot certify that another packet traversed or bypassed OUTPUT. Keep all active tracing and attachment work unauthorized. Batch F stays OFF.

## Phase 2: separately reviewed hook-level experiment (NOT YET AUTHORIZED)

Do **not** mistake a tracing attachment for a read-only operation. Registering eBPF programs/kprobes, changing tracefs event-enable switches, adding netfilter TRACE/NFLOG targets, installing nftables/iptables counters, attaching tc/XDP programs or creating audit rules **changes running kernel state** and needs its own safety review.

Any later controlled experiment must be independently reviewed and prove, where technically feasible:

1. A known hook identity and packet identity/family/type from an **actual** packet event rather than time-correlated aggregate counters.
2. Whether the observed type-135 packet entered local OUTPUT (or did not) with consistent on-device hook evidence; unknown/missing data must be `INDETERMINATE`, not `BYPASS`.
3. Whether the packet is kernel-generated or userspace-originated. If a kernel-origin packet has no meaningful process UID, classify `KERNEL / UID UNAVAILABLE` rather than manufacture a UID.
4. Source-bound, privacy-preserving correlation of the same event across observation points where supported. Never assume packet tuple or timestamp alone uniquely matches a packet.
5. IPv4/IPv6 parity, dynamic routing/endpoint change, physical underlay continuity, exact owned chain inspection, and tool behavior when unsupported.
6. No payload capture or export; retain only explicitly user-approved, minimal, time-limited metadata and ensure reversible cleanup of all temporary tracing resources.

If the kernel cannot expose enough evidence or the experiment would modify enforcement paths, **stop at the evidence gap**. Do not add broad ICMPv6, DNS, DHCP or physical-underlay exceptions to paper over it.

## Independent recovery gate BEFORE active enforcement

A connected USB ADB session must work from a separate computer, independently of either tunnel, Wi-Fi, cellular and Termux. Verify root access, stable device identification, authorization across a brief screen lock, and the ability to inspect owner-ledger/live firewall state without executing destructive commands. Record only **PASS/FAIL and prerequisites**, not phone identifiers.

A later emergency rollback procedure must be reviewed in advance, exact-owner only, and must preserve other owners' rules. Do not use generic `iptables -F`, `ip6tables -F`, `ip rule flush`, delete all tunnels, or blindly restore connectivity by allowing direct traffic. If ledgers or kernel identities disagree, refuse automatic removal and use independent manual diagnosis.

Before *any* live Batch F guard trial there must also be a deterministic bounded activation window, safe sequencing, observed local rollback independent of affected network, power/reboot/crash recovery, and separate HOME/private/public IPv4/IPv6 no-fallback tests. No automatic disable-to-direct-internet bypass. Explicit written acceptance of the planned behavior is required.

## Acceptance checklist (not yet met)

- [x] F.3d on-device passive capture and aggregate OUTPUT counter diagnostics completed with 2 selected WireGuard identities, exact split routing 3/3 and Batch F OFF/ABSENT.
- [ ] Independent post-0.15.18 HOME Navidrome streaming and public Internet smoke check documented.
- [ ] F.3e read-only capability inventory designed and implemented with static path allowlists, output bounds, no kernel changes and pure regression coverage.
- [ ] Android build/native CI PASS for any new APK, with unchanged old guard activation lock.
- [ ] Independent USB ADB/root recovery readiness independently demonstrated before designing live kernel hook attachment tests.
- [ ] Safe hook-level evidence method reviewed for packet-origin/OUTPUT traversal and its effects on the running kernel.
- [ ] F.3c source-bound exception protocol and dynamic endpoint/underlay reconciliation validated **in isolation**, not installed onto the active Pixel 8a.
- [ ] F.4 controlled fail-closed enforcement protocol approved independently and verified with safe recovery, both IP families and tunnel/route failure behavior.

## Decision

**Go** for read-only *capability discovery* and formal USB ADB recovery readiness. **No-go** for active Batch F or experimental tracepoint hooks until the above gates are met. Avoid another APK whose only difference is another five-second aggregated counter sample.

References: [F.3 redesign RFC](PRODUCT_BATCH_F3_FAIL_CLOSED_REDESIGN_RFC.md), [F.3d counter test plan](PRODUCT_BATCH_F3D_EXISTING_OUTPUT_COUNTER_TEST_PLAN.md), [product A–I roadmap](PRODUCT_BATCH_ROADMAP_A_I.md), [incident #41](https://github.com/yooshastan/Wonhee-Proxy/issues/41).
