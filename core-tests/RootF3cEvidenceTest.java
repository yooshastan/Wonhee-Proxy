package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootF3cEvidenceTest {
    private static void check(boolean test, String message) {
        if (!test) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(RootF3cEvidence.classifyIcmp6(
                        "1730000000.0 IP6 fe80::1 > ff02::2: ICMP6, router solicitation, length 8")
                        == RootF3cEvidence.Icmp6.ROUTER_SOLICITATION,
                "classify router solicitation from explicit text");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, router advertisement, length 16")
                        == RootF3cEvidence.Icmp6.ROUTER_ADVERTISEMENT,
                "classify router advertisement");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, neighbor solicitation, who has ::2")
                        == RootF3cEvidence.Icmp6.NEIGHBOR_SOLICITATION,
                "classify neighbor solicitation");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, neighbour advertisement, tgt is ::2")
                        == RootF3cEvidence.Icmp6.NEIGHBOR_ADVERTISEMENT,
                "classify neighbor advertisement");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, redirect, length 24")
                        == RootF3cEvidence.Icmp6.REDIRECT, "redirect");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, echo request, id 1")
                        == RootF3cEvidence.Icmp6.ECHO_REQUEST, "echo request");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, echo reply, id 1")
                        == RootF3cEvidence.Icmp6.ECHO_REPLY, "echo reply");
        check(RootF3cEvidence.classifyIcmp6("ICMP6, packet too big, length 12")
                        == RootF3cEvidence.Icmp6.OTHER_KNOWN, "known ICMPv6 type");
        check(RootF3cEvidence.classifyIcmp6("IP6 fe80::1 > ff02::2: ICMP6, length 8")
                        == RootF3cEvidence.Icmp6.UNKNOWN,
                "never infer type from address");
        check(RootF3cEvidence.classifyIcmp6("IP6 fe80::1 > ff02::2")
                        == RootF3cEvidence.Icmp6.UNKNOWN,
                "unknown when no ICMPv6 type printed");
        check(RootF3cEvidence.classifyIcmp6(null)
                        == RootF3cEvidence.Icmp6.UNKNOWN, "null unknown");

        RootUnderlayControlEvidence.Summary s = RootUnderlayControlEvidence.reduce(
                Arrays.asList(
                        "1730000000.01 IP6 fe80::1 > ff02::2: ICMP6, router solicitation, length 8",
                        "1730000000.02 IP6 fe80::1 > ff02::1: ICMP6, neighbor advertisement, length 8",
                        "1730000000.03 IP6 fe80::1 > ff02::1: ICMP6, unknown subtype, length 8",
                        "3 packets captured"));
        check(s.icmp6 == 3 && s.routerSolicitation == 1
                        && s.neighborAdvertisement == 1 && s.unknownIcmp == 1,
                "count known and unknown ICMPv6 types without forcing a guess");
        String summary = s.report(0, 100, 103);
        check(summary.contains("router solicitation (type 133): 1")
                        && summary.contains("unknown: 0 / 1")
                        && !summary.contains("fe80::")
                        && !summary.contains("ff02::"),
                "ICMPv6 type counts are anonymous");

        RootF3cEvidence.OutputInventory inv = RootF3cEvidence.inventory(0,
                Arrays.asList("-P OUTPUT ACCEPT",
                        "-A OUTPUT -m owner --uid-owner 1234 -j fw_OUTPUT",
                        "-A OUTPUT -d 198.51.100.3/32 -j RETURN",
                        "-A INPUT -j DROP"));
        check(inv.readable && inv.appendedRules == 2 && inv.jumps == 2
                        && inv.defaultPolicyKnown && "ACCEPT".equals(inv.policy),
                "count only OUTPUT rules and known policy");
        check(!inv.render("IPv4").contains("198.51.100.3")
                        && !inv.render("IPv4").contains("uid-owner"),
                "never disclose raw firewall rule contents");
        check(!RootF3cEvidence.inventory(127,
                        Arrays.asList("permission denied")).readable,
                "failed root inventory is unavailable");
        check(!RootF3cEvidence.inventory(0,
                        Collections.emptyList()).readable,
                "empty unverified command output must not mean firewall is empty");
        check(!RootF3cEvidence.inventory(0,
                        Arrays.asList("-A OTHER -j ACCEPT")).readable,
                "unrelated chain is not evidence of OUTPUT inspection");

        System.out.println("RootF3cEvidenceTest PASS");
    }
}
