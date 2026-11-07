package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

/** Deterministic tests: no capture, root, sockets, Android APIs or packets. */
public final class RootUnderlayControlEvidenceTest {
    private static void check(boolean condition, String why) {
        if (!condition) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        RootUnderlayControlEvidence.Summary s =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "tcpdump: listening on wlan0, link-type EN10MB (Ethernet)",
                    "1730000000.1 IP 192.0.2.2.68 > 255.255.255.255.67: UDP, length 300",
                    "1730000000.2 IP 192.0.2.2.49322 > 1.1.1.1.53: UDP, length 30",
                    "1730000000.3 IP 192.0.2.2.48000 > 1.1.1.1.53: Flags [S], seq 10",
                    "1730000000.4 IP 192.0.2.2.48001 > 203.0.113.20.80: Flags [S], seq 20",
                    "1730000000.5 IP6 fe80::1 > ff02::2: ICMP6, router solicitation, length 8",
                    "1730000000.6 IP 192.0.2.2.2222 > 198.51.100.2.1234: UDP, length 10",
                    "6 packets captured",
                    "6 packets received by filter",
                    "0 packets dropped by kernel"
                ));
        check(s.samples == 6 && s.tcpdumpCaptured == 6 && s.tcpdumpDropped == 0
                        && s.captureStarted, "parse header rows and tcpdump capture metadata");
        check(s.dhcp4 == 1 && s.dnsUdp == 1 && s.dnsTcp == 1
                        && s.http80 == 1 && s.icmp6 == 1 && s.other == 1,
                "categorize sample packet-header candidates");
        check(s.evidence(124) == RootUnderlayControlEvidence.Evidence.HEADERS_OBSERVED,
                "bounded capture with sample headers is informative");
        String report = s.report(124, 500, 650);
        check(report.contains("UDP/53 candidate: 1")
                        && report.contains("TX packets during window: +150")
                        && report.contains("NOT verified")
                        && !report.contains("192.0.2.")
                        && !report.contains("203.0.113.")
                        && !report.contains("fe80::"),
                "report only safe aggregate metrics and conservative interpretation");

        RootUnderlayControlEvidence.Summary quiet =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "tcpdump: listening on wlan0, link-type EN10MB (Ethernet)",
                    "0 packets captured",
                    "0 packets received by filter",
                    "0 packets dropped by kernel"
                ));
        check(quiet.samples == 0 && quiet.tcpdumpCaptured == 0
                        && quiet.evidence(124)
                        == RootUnderlayControlEvidence.Evidence.EMPTY_MATCH_WINDOW,
                "capture-start plus zero captured confirms only an empty filtered window");
        check(quiet.report(124, 100, 105).contains("EMPTY_MATCH_WINDOW"),
                "quiet window still notes physical interface TX activity");
        check(quiet.report(124, -1, -1).contains("UNAVAILABLE"),
                "missing interface counters are never inferred as zero");

        RootUnderlayControlEvidence.Summary noStats =
                RootUnderlayControlEvidence.reduce(Collections.emptyList());
        check(noStats.evidence(124)
                        == RootUnderlayControlEvidence.Evidence.CAPTURE_COVERAGE_UNKNOWN
                        && noStats.report(124, -1, -1).contains("INCONCLUSIVE"),
                "timeout with no sample or tcpdump summary is NOT a verified quiet window");

        RootUnderlayControlEvidence.Summary mismatch =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "tcpdump: listening on wlan0, link-type EN10MB (Ethernet)",
                    "2 packets captured", "0 packets dropped by kernel"));
        check(mismatch.evidence(124)
                        == RootUnderlayControlEvidence.Evidence.PARSER_COVERAGE_GAP,
                "tcpdump says packets captured but no parsable rows is a parser gap");
        RootUnderlayControlEvidence.Summary malformed =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "1730000001.2 SLL2 packet representation not handled",
                    "1 packets captured"));
        check(malformed.malformedPacketRows == 1
                        && malformed.evidence(0)
                        == RootUnderlayControlEvidence.Evidence.PARSER_COVERAGE_GAP,
                "timestamped unexpected packet format must not be silently ignored");

        RootUnderlayControlEvidence.Summary shortForm =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "1730000000.1 IP 192.0.2.2.32101 > 1.1.1.1.53: tcp 0",
                    "1730000000.2 IP 192.0.2.2.32102 > 1.1.1.1.53: udp 35",
                    "1730000000.3 IP 192.0.2.2.32103 > 192.0.2.9.80: tcp 0"));
        check(shortForm.dnsTcp == 1 && shortForm.dnsUdp == 1
                        && shortForm.http80 == 1,
                "short-form tcpdump packet descriptions remain countable");

        check(RootUnderlayControlEvidence.readCounter(
                        Arrays.asList("12345")) == 12345,
                "read a strict single sysfs tx_packets value");
        check(RootUnderlayControlEvidence.readCounter(
                        Arrays.asList("1", "2")) < 0,
                "untrusted multiple sysfs values rejected");
        check(RootUnderlayControlEvidence.readCounter(
                        Arrays.asList("-1")) < 0,
                "negative packet counter rejected");
        check(RootUnderlayControlEvidence.readCounter(null) < 0,
                "missing packet counter unavailable");

        check(RootUnderlayControlEvidence.completed(0)
                        && RootUnderlayControlEvidence.completed(124)
                        && !RootUnderlayControlEvidence.completed(1)
                        && !RootUnderlayControlEvidence.completed(127)
                        && noStats.evidence(1)
                        == RootUnderlayControlEvidence.Evidence.CAPTURE_FAILED,
                "unsupported/incomplete capture must be labeled unavailable");
        String cmd = RootUnderlayControlEvidence.command("wlan0");
        check(cmd.contains("timeout 5 tcpdump") && cmd.contains("-Q out")
                        && cmd.contains("-c 32") && cmd.contains("-s 64")
                        && cmd.contains("2>&1") && !cmd.contains(" -w "),
                "bounded non-persistent header-only capture with ephemeral stderr stats");
        check(RootUnderlayControlEvidence.command("rmnet16").contains("-i rmnet16"),
                "cellular underlay candidate supported");
        check(RootUnderlayControlEvidence.txCounterCommand("wlan0")
                        .equals("cat /sys/class/net/wlan0/statistics/tx_packets"),
                "only read numeric interface packet counter");
        for (String bad : new String[]{"wnm68fe81200daa", "wlan0;reboot",
                "wlan0 $(id)", "", "lo", null}) {
            try {
                RootUnderlayControlEvidence.command(bad);
                throw new AssertionError("unsafe interface allowed " + bad);
            } catch (IllegalArgumentException expected) { /* required */ }
            try {
                RootUnderlayControlEvidence.txCounterCommand(bad);
                throw new AssertionError("unsafe sysfs path allowed " + bad);
            } catch (IllegalArgumentException expected) { /* required */ }
        }
        System.out.println("RootUnderlayControlEvidenceTest PASS");
    }
}
