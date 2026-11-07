# Wonhee 0.15.16 — Batch F.3b.1 capture-coverage refinement

**Draft / optional read-only diagnostic.** Batch F firewall activation and its packet challenge remain blocked in both UI and root-session code. This branch is based on the 0.15.15 F.3b device build that completed a 5-second physical-interface capture with 0 parsed header rows while public Internet and private Navidrome remained functional.

## Problem identified

The previous F.3b `tcpdump` command discarded stderr (`2>/dev/null`). That suppressed tcpdump's startup and packet-count report. The UI displayed "0" for every category, even though it had no way to distinguish a genuinely empty matching capture window from missing capture statistics or a packet-output parser mismatch.

A five-second zero matching-filter window cannot establish that Android does not emit DHCP, DNS, HTTP validation or IPv6 neighbor-control traffic, and does not prove local OUTPUT-chain passage or origin.

## Change scope

- Same *user-consented*, **outgoing-only**, **up to 5 seconds**, **up to 32 captured frames**, **64-byte snap length**, same physical interface selection and traffic-category filter. No packets are generated, no background job, and no firewall, tunnel, DNS or routing mutations.
- `tcpdump` stderr is now **captured transiently in app memory** along with stdout, only to count documented metadata: "listening on", N packets captured, and kernel drops. No raw error text, packet addresses or tool output is displayed/saved. The ephemeral list is cleared after aggregation and in a `finally` block.
- Read-only `/sys/class/net/<physical>/statistics/tx_packets` is sampled just before and after the capture. The report shows a **physical TX packet count delta for all outbound traffic**, including WireGuard outer UDP, not an attribution or leak proof.
- The capture result is explicitly classified:
  - `HEADERS_OBSERVED`: matching packet headers parsed.
  - `EMPTY_MATCH_WINDOW`: capture startup was seen and tcpdump itself reports **0 packets captured** for the short filter window.
  - `PARSER_COVERAGE_GAP`: tcpdump says packets were captured but the parser recognized none, or a timestamped packet format was unrecognized.
  - `CAPTURE_COVERAGE_UNKNOWN`: timeout returned but capture metadata are insufficient to establish a genuinely empty window.
  - `CAPTURE_FAILED`: tool exited unsuccessfully.
- Parser mismatch and capture unknown must produce CHECK REQUIRED / not an unconditional COMPLETE. A confirmed empty window may complete *the diagnostic*, but remains explicitly **inconclusive about Android's behavior**.
- Does not broaden packet filters, introduce netfilter counters, attribute packet UIDs, inspect payloads, save pcap files, re-enable the kill switch or authorize exception policies.

## Device test — one normal-usage sample only

1. Preserve the working two selected HOME + AirVPN WireGuard tunnels. Keep Batch B.1 ledger 3 / live 3 exact and private/public routes correct. Leave Batch F OFF.
2. Run existing **Verify live IPv4/IPv6 guard + rollback ledger**; require ledger OFF, anchors absent and reserved chains absent.
3. Install 0.15.16 only if the Android signing certificate is compatible. Do not uninstall the existing working build to force an APK update, as doing so can erase app-stored routing ownership.
4. In Multi-Tunnel Lab → Network Protection choose **Batch F.3b.1 · Inspect passive capture coverage · opt in** and approve once under ordinary Wi-Fi/cellular use. No network transition, forced DHCP renewal, traffic generation or tunnel disconnect required.
5. Report should show an evidence classification, tcpdump capture startup and packet counters where available, a sanitized physical TX delta and candidate category counts. If capture is unavailable, classify the failure and stop; do not repeatedly run it to chase packets.
6. After the test, confirm Internet browsing and private Navidrome still function, and guard remains OFF. Share only the app's sanitized summary, not raw tcpdump or root logs.

## Verification

Pure Java tests in `RootUnderlayControlEvidenceTest` exercise observed headers, tcpdump startup and packet summary, a zero-packet filtered window, timeout without summary, parser mismatch, short-form tcpdump format, sysfs counter validation, strict interface name validation and redaction. Android APK compilation and native WireGuard tests must pass in CI before device testing.

## Remaining blockers

The collected metadata are not evidence of UID, process, kernel socket provenance, local netfilter OUTPUT traversal, DNS isolation, source-bound WireGuard transport allowances, endpoint/underlay handoff safety, or fail-closed behavior. Original incident [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) stays open. No F.3c firewall-policy exception work or F.4 activation is allowed solely because of this refinement.
