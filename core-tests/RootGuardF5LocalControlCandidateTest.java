package com.yooshastan.wonheeproxy;

/** Source-only F.5 classification tests. No actual root/firewall networking. */
public final class RootGuardF5LocalControlCandidateTest {
    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }

    private static RootGuardF5LocalControlCandidate.Packet p(
            int family, String out, String protocol, String source,
            String destination, int sport, int dport, int type, int hop) {
        return new RootGuardF5LocalControlCandidate.Packet(
                family, out, protocol, source, destination, sport, dport, type, hop);
    }

    private static void candidate(RootGuardF5LocalControlCandidate.Packet packet, String why) {
        check(RootGuardF5LocalControlCandidate.inspect(packet)
                        == RootGuardF5LocalControlCandidate.Verdict.LOCAL_CONTROL_CANDIDATE, why);
    }

    private static void deny(RootGuardF5LocalControlCandidate.Packet packet, String why) {
        check(RootGuardF5LocalControlCandidate.inspect(packet)
                        == RootGuardF5LocalControlCandidate.Verdict.DENY_DIRECT_UNDERLAY, why);
    }

    public static void main(String[] args) {
        candidate(p(4, "wlan0", "udp", "0.0.0.0", "255.255.255.255",
                        68, 67, 0, 0), "initial Wi-Fi DHCP candidate");
        candidate(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::2",
                        0, 0, 133, 255), "link-local router solicitation candidate");
        candidate(p(6, "wlan0", "icmpv6", "::", "ff02::2",
                        0, 0, 133, 255), "unspecified-source router solicitation candidate");
        candidate(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1:ff00:1",
                        0, 0, 135, 255), "link-local Neighbor Solicitation candidate");
        candidate(p(6, "wlan0", "icmpv6", "::", "ff02::1:ff00:1",
                        0, 0, 135, 255), "duplicate-address Neighbor Solicitation candidate");
        candidate(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1",
                        0, 0, 136, 255), "unsolicited Neighbor Advertisement candidate");
        candidate(p(6, "wlan0", "icmpv6", "fe80::abcd", "fe80::1234",
                        0, 0, 136, 255), "unicast link-local Neighbor Advertisement candidate");

        deny(p(4, "rmnet16", "udp", "0.0.0.0", "255.255.255.255",
                        68, 67, 0, 0), "cellular controls are not implicitly permitted");
        deny(p(6, "rmnet16", "icmpv6", "fe80::abcd", "ff02::1:ff00:1",
                        0, 0, 135, 255), "cellular ND does not inherit Wi-Fi candidate");
        deny(p(4, "wlan0", "udp", "192.168.1.25", "192.168.1.1",
                        68, 67, 0, 0), "DHCP unicast renewal requires separate evidence");
        deny(p(4, "wlan0", "udp", "0.0.0.0", "255.255.255.255",
                        67, 68, 0, 0), "reversed DHCP ports rejected");
        deny(p(4, "wlan0", "udp", "0.0.0.0", "255.255.255.255",
                        68, 53, 0, 0), "DNS cannot be relabeled DHCP");
        deny(p(4, "wlan0", "udp", "192.168.1.25", "1.1.1.1",
                        40000, 53, 0, 0), "underlay plaintext DNS blocked");
        deny(p(4, "wlan0", "tcp", "192.168.1.25", "1.1.1.1",
                        40000, 443, 0, 0), "underlay HTTPS blocked");
        deny(p(6, "wlan0", "tcp", "fe80::abcd", "2606:4700:4700::1111",
                        40000, 443, 0, 0), "underlay IPv6 HTTPS blocked");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1:ff00:1",
                        0, 0, 135, 64), "ND must not use arbitrary hop limit");
        deny(p(6, "wlan0", "icmpv6", "2001:db8::2", "ff02::1:ff00:1",
                        0, 0, 135, 255), "global-address source needs separate assessment");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1",
                        0, 0, 135, 255), "NS to wrong multicast group refused");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff05::1:ff00:1",
                        0, 0, 135, 255), "site-scoped multicast ND refused");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1",
                        0, 0, 128, 255), "ICMP echo request is not ND");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::1",
                        0, 0, 134, 255), "router advertisement is not locally emitted RS");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd", "ff02::2",
                        200, 0, 133, 255), "nonzero port metadata refused");
        deny(p(6, "wlan0", "icmpv6", "fe80::abcd%wlan0", "ff02::2",
                        0, 0, 133, 255), "scope identifier not accepted as plain address");
        deny(p(6, "wlan0", "icmpv6", "evil.example", "ff02::2",
                        0, 0, 133, 255), "model never resolves untrusted hostnames");
        deny(p(6, "wlan0;iptables", "icmpv6", "fe80::abcd", "ff02::2",
                        0, 0, 133, 255), "unsafe physical interface not accepted");
        check(!RootGuardF5LocalControlCandidate.activationAllowed(),
                "candidate classification can NEVER activate F");
        check(RootGuardSafetyGate.activationPaused(),
                "actual root firewall activation remains paused");

        System.out.println("RootGuardF5LocalControlCandidateTest PASS");
    }
}
