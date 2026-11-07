package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Batch F.3b.1: transient header-only passive capture diagnostics.
 *
 * Only sanitized metrics leave this classifier. Raw tcpdump output, addresses,
 * endpoints, peer keys and packet header lines must NOT enter app journals,
 * logs, preferences or UI. No packet generation or firewall modifications.
 */
final class RootUnderlayControlEvidence {
    private RootUnderlayControlEvidence() { }

    private static final Pattern HEADER = Pattern.compile(
            "^[0-9]+(?:\\.[0-9]+)?\\s+IP6?\\s+.+");
    private static final Pattern STATS_CAPTURED = Pattern.compile(
            "^([0-9]+)\\s+packets? captured(?:\\s+.*)?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern STATS_RECEIVED = Pattern.compile(
            "^([0-9]+)\\s+packets? received by filter(?:\\s+.*)?$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STATS_DROPPED = Pattern.compile(
            "^([0-9]+)\\s+packets? dropped by kernel(?:\\s+.*)?$",
            Pattern.CASE_INSENSITIVE);

    enum Evidence {
        HEADERS_OBSERVED, EMPTY_MATCH_WINDOW, PARSER_COVERAGE_GAP,
        CAPTURE_COVERAGE_UNKNOWN, CAPTURE_FAILED
    }

    static final class Summary {
        int dhcp4;
        int dnsUdp;
        int dnsTcp;
        int http80;
        int icmp6;
        int routerSolicitation;
        int routerAdvertisement;
        int neighborSolicitation;
        int neighborAdvertisement;
        int redirect;
        int echoRequest;
        int echoReply;
        int otherKnownIcmp;
        int unknownIcmp;
        int other;
        int samples;
        int malformedPacketRows;
        int rawLineCount;
        boolean captureStarted;
        long tcpdumpCaptured = -1;
        long tcpdumpReceived = -1;
        long tcpdumpDropped = -1;

        Evidence evidence(int exit) {
            if (!completed(exit)) return Evidence.CAPTURE_FAILED;
            if (malformedPacketRows > 0
                    || (tcpdumpCaptured > 0 && samples == 0)
                    || (tcpdumpCaptured >= 0 && samples > tcpdumpCaptured)) {
                return Evidence.PARSER_COVERAGE_GAP;
            }
            if (samples > 0) return Evidence.HEADERS_OBSERVED;
            if (captureStarted && tcpdumpCaptured == 0) {
                return Evidence.EMPTY_MATCH_WINDOW;
            }
            return Evidence.CAPTURE_COVERAGE_UNKNOWN;
        }

        String report(int exit, long txBefore, long txAfter) {
            StringBuilder out = new StringBuilder("OUTGOING HEADER OBSERVATIONS (counts only)\n")
                    .append("DHCPv4 UDP/67 or 68 candidate: ").append(dhcp4).append('\n')
                    .append("Plain DNS UDP/53 candidate: ").append(dnsUdp).append('\n')
                    .append("Plain DNS TCP/53 candidate: ").append(dnsTcp).append('\n')
                    .append("HTTP TCP/80 candidate: ").append(http80).append('\n')
                    .append("ICMPv6 candidate: ").append(icmp6).append('\n')
                    .append("ICMPv6 router solicitation (type 133): ")
                    .append(routerSolicitation).append('\n')
                    .append("ICMPv6 router advertisement (type 134): ")
                    .append(routerAdvertisement).append('\n')
                    .append("ICMPv6 neighbor solicitation (type 135): ")
                    .append(neighborSolicitation).append('\n')
                    .append("ICMPv6 neighbor advertisement (type 136): ")
                    .append(neighborAdvertisement).append('\n')
                    .append("ICMPv6 redirect candidate (type 137): ")
                    .append(redirect).append('\n')
                    .append("ICMPv6 echo request/reply: ")
                    .append(echoRequest).append(" / ").append(echoReply).append('\n')
                    .append("ICMPv6 other known/unknown: ")
                    .append(otherKnownIcmp).append(" / ").append(unknownIcmp).append('\n')
                    .append("Other/uncategorized matching headers: ").append(other).append('\n')
                    .append("Parsed outgoing headers: ").append(samples).append('\n')
                    .append("Unrecognized IP header rows: ").append(malformedPacketRows).append('\n')
                    .append("tcpdump capture startup observed: ")
                    .append(captureStarted ? "YES" : "NOT CONFIRMED").append('\n')
                    .append("tcpdump reported packets captured: ")
                    .append(tcpdumpCaptured >= 0 ? Long.toString(tcpdumpCaptured)
                            : "NOT REPORTED")
                    .append('\n')
                    .append("tcpdump packets received by filter: ")
                    .append(tcpdumpReceived >= 0 ? Long.toString(tcpdumpReceived)
                            : "NOT REPORTED")
                    .append('\n')
                    .append("Kernel capture drops reported: ")
                    .append(tcpdumpDropped >= 0 ? Long.toString(tcpdumpDropped)
                            : "NOT REPORTED")
                    .append('\n')
                    .append("Physical interface TX packets during window: ");
            if (txBefore >= 0 && txAfter >= txBefore) {
                out.append('+').append(txAfter - txBefore);
            } else {
                out.append("UNAVAILABLE / COUNTER RESET");
            }
            out.append('\n').append("Evidence classification: ").append(evidence(exit))
                    .append('\n');
            switch (evidence(exit)) {
                case EMPTY_MATCH_WINDOW:
                    out.append("No matching headers reported in this five-second "
                            + "filter window. This does NOT show Android never "
                            + "generates those flows.");
                    break;
                case HEADERS_OBSERVED:
                    out.append("Matching physical-interface headers observed. "
                            + "Origin and local OUTPUT-chain traversal remain unknown.");
                    break;
                case PARSER_COVERAGE_GAP:
                    out.append("CAPTURE/PARSER MISMATCH: some reported packet headers "
                            + "could not be counted. Do not infer a quiet network.");
                    break;
                case CAPTURE_COVERAGE_UNKNOWN:
                    out.append("INCONCLUSIVE: tcpdump did not report a verifiable "
                            + "empty matching window. Zero parsed lines is not "
                            + "evidence of zero packets.");
                    break;
                default:
                    out.append("Capture failed or unsupported. Do not use this "
                            + "result for firewall policy decisions.");
            }
            return out.append('\n')
                    .append("These are interface-level observations, NOT verified "
                            + "Android control-plane origin, creator UID, local OUTPUT "
                            + "traversal, a network leak test or delivery proof. "
                            + "Physical TX counts include all traffic, including "
                            + "outer VPN UDP; they do not authenticate this filter.")
                    .toString();
        }
    }

    static Summary reduce(List<String> transientLines) {
        Summary s = new Summary();
        if (transientLines == null) return s;
        // Always parse transient data in memory and keep all raw lines private.
        for (int i = 0; i < transientLines.size() && i < 128; i++) {
            String line = transientLines.get(i);
            if (line == null || line.length() > 1024) continue;
            s.rawLineCount++;
            String t = line.trim();
            String lower = t.toLowerCase(Locale.ROOT);
            if (lower.startsWith("listening on ")
                    || lower.startsWith("tcpdump: listening on ")) {
                s.captureStarted = true;
                continue;
            }
            Matcher captured = STATS_CAPTURED.matcher(t);
            if (captured.matches()) {
                s.tcpdumpCaptured = positiveCounter(captured.group(1));
                continue;
            }
            Matcher received = STATS_RECEIVED.matcher(t);
            if (received.matches()) {
                s.tcpdumpReceived = positiveCounter(received.group(1));
                continue;
            }
            Matcher dropped = STATS_DROPPED.matcher(t);
            if (dropped.matches()) {
                s.tcpdumpDropped = positiveCounter(dropped.group(1));
                continue;
            }
            if (!HEADER.matcher(t).matches()) {
                // Timestamped, but nonstandard packet header: explicitly
                // report parser coverage gap rather than silently count zero.
                if (t.matches("^[0-9]+\\.[0-9]+\\s+.+")) {
                    s.malformedPacketRows++;
                }
                continue;
            }
            s.samples++;
            boolean udp = lower.contains(" udp,") || lower.matches(".*:\\s+udp\\s+\\d+.*");
            boolean tcp = lower.contains(" flags [")
                    || lower.matches(".*:\\s+tcp\\s+\\d+.*");
            boolean dnsPort = lower.matches(".*\\.53(?:\\s*[:>]|:).*");
            boolean dhcpPort = lower.matches(".*\\.(67|68)(?:\\s*[:>]|:).*");
            boolean httpPort = lower.matches(".*\\.80(?:\\s*[:>]|:).*");
            if (udp && dhcpPort) s.dhcp4++;
            else if (udp && dnsPort) s.dnsUdp++;
            else if (tcp && dnsPort) s.dnsTcp++;
            else if (tcp && httpPort) s.http80++;
            else if (lower.contains("icmp6") || lower.contains("icmpv6")) {
                s.icmp6++;
                switch (RootF3cEvidence.classifyIcmp6(t)) {
                    case ROUTER_SOLICITATION: s.routerSolicitation++; break;
                    case ROUTER_ADVERTISEMENT: s.routerAdvertisement++; break;
                    case NEIGHBOR_SOLICITATION: s.neighborSolicitation++; break;
                    case NEIGHBOR_ADVERTISEMENT: s.neighborAdvertisement++; break;
                    case REDIRECT: s.redirect++; break;
                    case ECHO_REQUEST: s.echoRequest++; break;
                    case ECHO_REPLY: s.echoReply++; break;
                    case OTHER_KNOWN: s.otherKnownIcmp++; break;
                    default: s.unknownIcmp++; break;
                }
            }
            else s.other++;
        }
        return s;
    }

    private static long positiveCounter(String text) {
        if (text == null || !text.matches("[0-9]{1,19}")) return -1;
        try { return Long.parseLong(text); }
        catch (NumberFormatException malformed) { return -1; }
    }

    static long readCounter(List<String> text) {
        if (text == null || text.size() != 1) return -1;
        return positiveCounter(text.get(0).trim());
    }

    /** Validated physical interface path, for read-only packet counter access. */
    static String txCounterCommand(String interfaceName) {
        verifyInterface(interfaceName);
        return "cat /sys/class/net/" + interfaceName + "/statistics/tx_packets";
    }

    /**
     * Bounded passive header capture only on the predicted physical underlay.
     * stderr is captured to a *transient in-memory list* only so tcpdump's
     * startup / summary counters can distinguish empty and unrecognized output.
     * Never display/serialize the raw output.
     */
    static String command(String interfaceName) {
        verifyInterface(interfaceName);
        return "timeout 5 tcpdump -p -Q out -tt -n -l -s 64 -c 32 -i "
                + interfaceName
                + " '((udp and (port 67 or port 68 or port 53))"
                + " or (tcp and (port 53 or port 80)) or icmp6)' 2>&1";
    }

    private static void verifyInterface(String interfaceName) {
        if (interfaceName == null || !interfaceName.matches(
                "(wlan|rmnet|eth|usb|clat)[A-Za-z0-9_.-]*")) {
            throw new IllegalArgumentException("Verified physical underlay required.");
        }
    }

    static boolean completed(int exit) {
        // 124 is timeout's normal five-second expiry; 0 means packet cap hit.
        return exit == 0 || exit == 124;
    }
}
