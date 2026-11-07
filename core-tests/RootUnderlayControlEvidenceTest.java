package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

/** No root, Android, packet capture, or network calls. */
public final class RootUnderlayControlEvidenceTest {
    private static void check(boolean condition, String why) {
        if (!condition) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        RootUnderlayControlEvidence.Summary s =
                RootUnderlayControlEvidence.reduce(Arrays.asList(
                    "1730000000.1 IP 192.0.2.2.68 > 255.255.255.255.67: UDP, length 300",
                    "1730000000.2 IP 192.0.2.2.49322 > 1.1.1.1.53: UDP, length 30",
                    "1730000000.3 IP 192.0.2.2.48000 > 1.1.1.1.53: Flags [S], seq 10",
                    "1730000000.4 IP 192.0.2.2.48001 > 203.0.113.20.80: Flags [S], seq 20",
                    "1730000000.5 IP6 fe80::1 > ff02::2: ICMP6, router solicitation, length 8",
                    "tcpdump: 5 packets captured",
                    "not a packet",
                    "1730000000.6 IP 192.0.2.2.2222 > 198.51.100.2.1234: UDP, length 10"
                ));
        check(s.samples == 6, "only parse packet-header rows");
        check(s.dhcp4 == 1 && s.dnsUdp == 1 && s.dnsTcp == 1
                        && s.http80 == 1 && s.icmp6 == 1 && s.other == 1,
                "separate candidate categories from arbitrary headers");
        String report = s.report();
        check(report.contains("UDP/53 candidate: 1")
                        && report.contains("NOT proof")
                        && !report.contains("192.0.2.")
                        && !report.contains("203.0.113.")
                        && !report.contains("fe80::"),
                "redacted totals only, without underlying host identifiers");

        check(RootUnderlayControlEvidence.reduce(Collections.emptyList()).samples == 0,
                "missing activity does not mean a clean underlay");
        check(RootUnderlayControlEvidence.completed(0)
                        && RootUnderlayControlEvidence.completed(124)
                        && !RootUnderlayControlEvidence.completed(1)
                        && !RootUnderlayControlEvidence.completed(127),
                "unsuccessful or unsupported capture must be marked unavailable");
        String cmd = RootUnderlayControlEvidence.command("wlan0");
        check(cmd.contains("timeout 5 tcpdump") && cmd.contains("-Q out")
                        && cmd.contains("-c 32") && cmd.contains("-s 64")
                        && !cmd.contains(" -w "),
                "passive bounded header-only capture with no persistent pcap");
        check(RootUnderlayControlEvidence.command("rmnet16").contains("-i rmnet16"),
                "cellular physical underlay candidate supported");
        for (String bad : new String[]{"wnm68fe81200daa", "wlan0;reboot",
                "wlan0 $(id)", "", "lo"}) {
            try {
                RootUnderlayControlEvidence.command(bad);
                throw new AssertionError("unsafe interface allowed " + bad);
            } catch (IllegalArgumentException expected) { /* required */ }
        }
        System.out.println("RootUnderlayControlEvidenceTest PASS");
    }
}
