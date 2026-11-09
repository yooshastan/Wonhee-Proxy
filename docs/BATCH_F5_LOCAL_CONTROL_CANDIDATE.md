# Wonhee Batch F.5 — non-enforcing control-traffic candidate and UX planning

**Status: offline development only; no device firewall changes.** Source-level `RootGuardSafetyGate.activationPaused()` remains true, and no new code path installs F.5 firewall rules.

## Why F.5 is deliberately not a new iptables ruleset

On Pixel 8a, the user ran the F.3d read-only five-second capture on physical Wi-Fi underlay `wlan0` while the Batch F kill switch was OFF. It observed one outgoing ICMPv6 Neighbor Solicitation (type 135). The IPv4/IPv6 filter/OUTPUT counters moved, **without** proving that that specific Neighbor Solicitation traversed OUTPUT or establishing which process created it. The earlier offline simulation of the old F guard predicted rejection of representative DHCPv4 and ND flows. The cause of the prior lost-connection incident remains uncertain.

The proposed `RootGuardF5LocalControlCandidate` class is intentionally incapable of turning on the firewall, generating shell rules or granting a system-network exception. It *labels hypothetical packets* as plausible local Wi-Fi control candidates or direct-underlay packets that are denied by default. Even a candidate is **not** approved for real egress.

## Candidate inventory — strictly illustrative, not yet deployable

| Hypothetical traffic | Classifier outcome | Remaining unknown |
| --- | --- | --- |
| Wi-Fi DHCPv4 initial client broadcast 0.0.0.0:68 to 255.255.255.255:67 | Local control candidate | Real Android source/hook, DHCP options, NIC ownership |
| Wi-Fi IPv6 Router Solicitation type 133, hop limit 255, local/unspecified source, ff02::2 | Local control candidate | Real OUTPUT traversal and sender |
| Wi-Fi IPv6 multicast Neighbor Solicitation type 135, hop limit 255, local/unspecified source, solicited-node multicast | Local control candidate | Real neighbor target, code, checksum, options, sender |
| Wi-Fi IPv6 Neighbor Advertisement type 136, hop limit 255, link-local source, link-local/all-nodes destination | Local control candidate | Flags, target, checksum, sender |
| Cellular (rmnet) control traffic | Deny by default | Modem control path may differ; no evidence for an exception |
| Wi-Fi unicast DHCP renewal | Deny by default | Needs independent destination/subnet and server identity validation |
| Wi-Fi underlay direct IPv4/IPv6 public HTTP(S), DNS, or non-ND ICMPv6 | Deny by default | Leak policy must not be weakened |
| Any incorrect ND hop limit, non-link-scoped destination, mismatched DHCP ports | Deny by default | Insufficient proof of genuine control traffic |

These input patterns alone are **insufficient to implement safe iptables allowances**. Real Neighbor Discovery requires checks beyond the packet summary (ICMP checksum, code, target address and options). UDP 68→67 can be forged by arbitrary userspace with suitable privileges. Attributing kernel-generated or system service packets and verifying they traverse local OUTPUT is a prerequisite.

Protocol reference: [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html) (Neighbor Discovery) and [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html) (DHCP). These are standards for general protocol behavior, not proof of the Pixel's specific kernel paths.

## Offline regression

`RootGuardF5LocalControlCandidateTest` checks positive synthetic candidates for the narrow Wi-Fi cases and negative synthetic cases for direct leaks, cellular, unsafe/unknown inputs, changed hop limit, wrong multicast scope, global-source ND, and unverified DHCP renewal. The test asserts both the classifier's `activationAllowed() == false` and the unchanged `RootGuardSafetyGate.activationPaused() == true`.

## Parallel UI redesign track

See [WONHEE_UI_REDESIGN_V1.md](WONHEE_UI_REDESIGN_V1.md). The app currently creates a single heavy `ScrollView` with many control and recovery sections. The proposed design has four destinations: **Home / Profiles / Protection / Activity**, with one prominent Connect action, always-accessible Safe Disconnect, an honest connection/privacy status summary and progressively disclosed technical tools. Emergency recovery and firewall lifecycle correctness remain available; **do not** simultaneously rewrite the UI and activate Batch F.

### Next implementation milestones

1. Obtain safe host/hook provenance for IPv6 Neighbor Solicitation and DHCP-like control flows, preferably on a dedicated test device; do not enable root OUTPUT guard on daily phone.
2. Create a separate passive/diagnostic view model for real tunnel + DNS + ownership statuses without changing session controller behavior.
3. Implement one-screen consumer dashboard and navigation in an independent feature branch; ensure screenshot/accessibility testing and preserve the current emergency rollback controls.
4. Validate automatic rollback and dynamic Wi-Fi↔cellular WireGuard endpoint changes independently before planning any live firewall packet-enforcement test.

**No signed APK needs to be installed for this F.5 batch; the UI mockup is a design specification, not a functional app screen.**
