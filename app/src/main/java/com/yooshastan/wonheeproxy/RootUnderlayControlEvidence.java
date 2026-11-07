package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Locale;

/**
 * Batch F.3b: reduce transient tcpdump text to coarse counts in memory.
 *
 * Do not print, persist, copy, log or export raw interface packet summaries,
 * endpoint addresses, payloads or port tuples. Observed physical egress does
 * not prove the local OUTPUT chain was traversed or identify Android's sender.
 */
final class RootUnderlayControlEvidence {
    private RootUnderlayControlEvidence() { }

    static final class Summary {
        int dhcp4;
        int dnsUdp;
        int dnsTcp;
        int http80;
        int icmp6;
        int other;
        int samples;

        String report() {
            return "OUTGOING HEADER OBSERVATIONS (aggregate counts only)\n"
                    + "DHCPv4 UDP/67 or 68 candidate: " + dhcp4 + "\n"
                    + "Plain DNS UDP/53 candidate: " + dnsUdp + "\n"
                    + "Plain DNS TCP/53 candidate: " + dnsTcp + "\n"
                    + "HTTP TCP/80 candidate: " + http80 + "\n"
                    + "ICMPv6 candidate: " + icmp6 + "\n"
                    + "Other/uncategorized matching headers: " + other + "\n"
                    + "Total parsed outgoing packet headers: " + samples + "\n"
                    + "These are interface-level samples, NOT proof of Android "
                    + "control-plane origin, local OUTPUT traversal, actual "
                    + "app identity, leak prevention, or successful delivery. "
                    + "HTTP/80 may be ordinary app traffic; ICMPv6 may include "
                    + "neighbor discovery or other messages. A zero count is "
                    + "not proof of absence.";
        }
    }

    static Summary reduce(List<String> transientLines) {
        Summary s = new Summary();
        if (transientLines == null) return s;
        // Defensively cap the amount parsed even if the tool exceeds its count.
        for (int i = 0; i < transientLines.size() && i < 48; i++) {
            String line = transientLines.get(i);
            if (line == null || line.length() > 1024) continue;
            String t = line.trim();
            // Numeric epoch from tcpdump -tt, followed by IP or IP6.
            if (!t.matches("^[0-9]+(?:\\.[0-9]+)?\\s+IP6?\\s+.+")) continue;
            s.samples++;
            String lower = t.toLowerCase(Locale.ROOT);
            // Short summaries do not distinguish DNS questions from replies.
            boolean udp = lower.contains(" udp,") || lower.contains(" udp ");
            boolean tcp = lower.contains(" flags [");
            boolean dnsPort = lower.matches(".*\\.53(?:\\s*[:>]|:).*");
            boolean dhcpPort = lower.matches(".*\\.(67|68)(?:\\s*[:>]|:).*");
            boolean httpPort = lower.matches(".*\\.80(?:\\s*[:>]|:).*");
            if (udp && dhcpPort) s.dhcp4++;
            else if (udp && dnsPort) s.dnsUdp++;
            else if (tcp && dnsPort) s.dnsTcp++;
            else if (tcp && httpPort) s.http80++;
            else if (lower.contains("icmp6")) s.icmp6++;
            else s.other++;
        }
        return s;
    }

    /**
     * Bounded passive header capture only on a validated physical interface.
     * timeout kills the capture after five seconds without generating packets.
     * No pcap file, hostname lookup or complete payloads.
     */
    static String command(String interfaceName) {
        if (interfaceName == null || !interfaceName.matches(
                "(wlan|rmnet|eth|usb|clat)[A-Za-z0-9_.-]*")) {
            throw new IllegalArgumentException("Verified physical underlay required.");
        }
        return "timeout 5 tcpdump -p -Q out -tt -n -l -q -s 64 -c 32 -i "
                + interfaceName
                + " '((udp and (port 67 or port 68 or port 53))"
                + " or (tcp and (port 53 or port 80)) or icmp6)' 2>/dev/null";
    }

    static boolean completed(int exit) {
        // 124 is timeout's normal five-second expiry; 0 means packet cap hit.
        return exit == 0 || exit == 124;
    }
}
