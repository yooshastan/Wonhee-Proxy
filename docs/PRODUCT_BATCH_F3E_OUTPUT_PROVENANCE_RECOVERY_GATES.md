# Wonhee Batch F.3e — OUTPUT provenance and independent recovery gates

**Status: design and evidence gate only. No APK build, enforcement, new kernel tracing hooks, packet generation, firewall rule installation or rule/counter reset authorized.** Branch is based on the passing 0.15.18 F.3d diagnostic. Product Batch F remains **unimplemented and unsafe to activate**; issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains open.

## Why stop creating read-only counter versions

The Pixel 8a captured an outgoing physical `wlan0` **ICMPv6 Neighbor Solicitation (type 135)**. During the same five-second F.3d observation, pre-existing global filter/OUTPUT counters increased: IPv4 default-policy +33, five of six rule counters advanced (summed +166); IPv6 default-policy +44, four of six rule counters advanced (summed +176); physical `wlan0` TX +37. Both selected WireGuard identities and the exact three recorded/live HOME split-routing overrides matched; Batch F owned IPv4/IPv6 guard was OFF/ABSENT.

This is evidence of two **concurrent observations** — physical IPv6 neighbor discovery and global OUTPUT counter movement — **not** evidence of the observed packet traversing INPUT, OUTPUT, raw/mangle, netfilter, a specific chain or rule. Rule-counter sums are not unique packets. Neither UID nor process nor kernel socket origin was established. No evidence isolates the original 0.15.12 connectivity incident to a particular packet class. Post-0.15.18 Navidrome and public browsing regression is not yet explicitly reconfirmed.

## F.3e, Phase 1: capabilities only (non-invasive)

Design a small, **explicitly requested, read-only, local device capability inventory**. Do not run this automatically and do not mark missing capabilities as leaks. Prefer inspecting kernel-exposed metadata/available events, not attaching tracers or changing tracefs knobs. Any root read must be finite, output-limited, validated against expected paths, and leave only aggregate booleans in the UI.

Record whether:

- The device exposes readable Linux trace-event listings under expected `/sys/kernel/tracing` or `/sys/kernel/debug/tracing` paths. **Do not mount tracefs/debugfs merely to make it accessible.**
- Relevant packet/netfilter/skb or WireGuard tracepoints are *advertised* by the running kernel, and whether their format metadata is readable. **Presence means capability candidate only**; it does not prove attach permissions, stable packet identity, UID visibility, or that the hook receives Neighbor Discovery.
- Existing IPv4/IPv6 filtering backends can be identified from **read-only** tool metadata. Avoid probing by inserting, zeroing, flushing or setting defaults. Never assume that reading `iptables -S OUTPUT` inventories all active Android networking hooks, including eBPF and other netfilter tables.
- Existing root- and shell-access prerequisites can be checked **without requiring network connectivity**. A working Termux session is *not* an independent rescue channel.

The summary must distinguish `AVAILABLE`, `NOT EXPOSED`, `PERMISSION DENIED`, `INDETERMINATE`, and `UNSAFE TO PROBE`. Do not display event payloads, socket addresses, keys, endpoint tuples, private UID associations, process names or raw kernel state. No pcap or persistence of raw readings.

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
