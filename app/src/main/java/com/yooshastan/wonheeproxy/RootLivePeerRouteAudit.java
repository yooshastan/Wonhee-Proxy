package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ephemeral, user-requested socket/route correlation.
 *
 * Input is root iproute2 ss output (including sensitive peer IP/ports);
 * only local transient Candidate objects retain addresses. Never print,
 * persist, journal or export the raw input, peers, endpoints, inodes or
 * socket cookies. Route decisions are hypothetical and do not prove a
 * particular packet's actual egress interface.
 */
final class RootLivePeerRouteAudit {
    static final int MAX_SS_LINES = 4096;
    static final int MAX_LINE_CHARS = 4096;
    static final int MAX_CANDIDATES_PER_UID = 6;
    static final int MAX_TOTAL_CANDIDATES = 18;
    static final int MAX_ROUTE_QUERIES = 18;

    private static final Pattern UID = Pattern.compile(
            "(?:^|\\s)uid:([0-9]{1,8})(?=\\s|$)");
    private static final Pattern MARK = Pattern.compile(
            "(?:^|\\s)fwmark:(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})(?=\\s|$)");
    private static final Pattern IPV4 = Pattern.compile(
            "[0-9]{1,3}(?:\\.[0-9]{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile(
            "[0-9a-fA-F:]{2,45}");

    private RootLivePeerRouteAudit() { }

    static final class Candidate {
        final int uid;
        final int family;
        final String publicPeerAddress;
        final long mark;
        final String transport;
        // Only a boolean port class is stored, not the actual peer port.
        // UDP/443 is compatible with QUIC, but is not QUIC proof.
        final boolean udp443;

        Candidate(int uid, int family, String publicPeerAddress,
                  long mark, String transport, boolean udp443) {
            this.uid = uid;
            this.family = family;
            this.publicPeerAddress = publicPeerAddress;
            this.mark = mark;
            this.transport = transport;
            this.udp443 = udp443;
        }

        String key() {
            return uid + "|" + family + "|" + publicPeerAddress + "|"
                    + mark + "|" + transport + "|" + udp443;
        }

        boolean protectedMark() {
            return (mark & RootLiveSocketMarkEvidence.PROTECTED_BIT) != 0;
        }
    }

    static final class Aggregate {
        private final Set<Integer> requested;
        private final Map<Integer, LinkedHashMap<String, Candidate>> byUid =
                new LinkedHashMap<>();
        int samples;
        int observedMatchingRecords;
        int missingOrAmbiguousMark;
        int localOrUnconnected;
        int rejectedMalformed;
        int candidateLimitReached;
        boolean complete = true;

        Aggregate(Set<Integer> requested) {
            this.requested = new LinkedHashSet<>();
            for (Integer uid : requested) {
                if (uid != null && RootUidRouteAudit.supportedUid(uid)) {
                    this.requested.add(uid);
                    byUid.put(uid, new LinkedHashMap<>());
                }
            }
        }

        void accept(List<String> tcp, List<String> udp) {
            samples++;
            acceptTransport(tcp, "TCP");
            acceptTransport(udp, "UDP");
        }

        private void acceptTransport(List<String> lines, String transport) {
            if (lines == null || lines.size() > MAX_SS_LINES) {
                complete = false;
                return;
            }
            StringBuilder current = new StringBuilder();
            for (String line : lines) {
                if (line == null || line.length() > MAX_LINE_CHARS) {
                    rejectedMalformed++;
                    complete = false;
                    continue;
                }
                String trim = line.trim();
                if (trim.isEmpty()) continue;
                if (!Character.isWhitespace(line.charAt(0))) {
                    process(current.toString(), transport);
                    current.setLength(0);
                    current.append(trim);
                } else if (current.length() > 0
                        && current.length() + trim.length() + 1 <= MAX_LINE_CHARS * 2) {
                    current.append(' ').append(trim);
                } else {
                    rejectedMalformed++;
                    complete = false;
                }
            }
            process(current.toString(), transport);
        }

        private void process(String record, String transport) {
            if (record.isEmpty()) return;
            Matcher u = UID.matcher(record);
            if (!u.find()) return;
            int uid;
            try {
                uid = Integer.parseInt(u.group(1));
            } catch (NumberFormatException invalid) {
                rejectedMalformed++;
                return;
            }
            if (!requested.contains(uid)) return;
            if (u.find()) {
                rejectedMalformed++;
                return;
            }
            observedMatchingRecords++;
            Matcher m = MARK.matcher(record);
            if (!m.find()) {
                missingOrAmbiguousMark++;
                return;
            }
            String raw = m.group(1);
            long mark;
            try {
                mark = raw.startsWith("0x")
                        ? Long.parseLong(raw.substring(2), 16)
                        : Long.parseLong(raw);
            } catch (NumberFormatException invalid) {
                missingOrAmbiguousMark++;
                return;
            }
            if (mark < 0 || mark > 0xffffffffL || m.find()) {
                missingOrAmbiguousMark++;
                return;
            }

            // ss -H outputs STATE Recv-Q Send-Q Local Address:Port Peer
            // Address:Port, with uid/fwmark fields following those columns.
            // Deliberately refuse unknown formats; never attempt shell
            // lookups for fields resembling hostnames or commands.
            String[] fields = record.split("\\s+");
            if (fields.length < 5) {
                rejectedMalformed++;
                return;
            }
            String peerLiteral = literalPublicPeer(fields[4]);
            if (peerLiteral == null) {
                localOrUnconnected++;
                return;
            }
            int family = peerLiteral.indexOf(':') >= 0 ? 6 : 4;
            boolean udp443 = "UDP".equals(transport)
                    && fields[4].endsWith(":443");
            Candidate candidate = new Candidate(
                    uid, family, peerLiteral, mark, transport, udp443);
            LinkedHashMap<String, Candidate> perUid = byUid.get(uid);
            if (perUid.containsKey(candidate.key())) return;
            if (perUid.size() >= MAX_CANDIDATES_PER_UID
                    || allCandidates().size() >= MAX_TOTAL_CANDIDATES) {
                candidateLimitReached++;
                return;
            }
            perUid.put(candidate.key(), candidate);
        }

        List<Candidate> allCandidates() {
            List<Candidate> result = new ArrayList<>();
            for (LinkedHashMap<String, Candidate> m : byUid.values()) {
                result.addAll(m.values());
            }
            return result;
        }

        List<Candidate> forUid(int uid) {
            LinkedHashMap<String, Candidate> match = byUid.get(uid);
            return match == null ? new ArrayList<>() : new ArrayList<>(match.values());
        }
    }

    /**
     * Returns strictly canonical numeric *public* peer IP or null.
     * Hostnames, zone identifiers, wildcard/unconnected peers, local RFC1918,
     * link-local, loopback and documentation/test networks are omitted.
     * These exclusions protect local services such as KDE Connect and Navidrome.
     */
    static String literalPublicPeer(String addressPort) {
        if (addressPort == null || addressPort.length() > 100) return null;
        String host;
        String portString;
        if (addressPort.startsWith("[")) {
            int bracket = addressPort.indexOf("]:");
            if (bracket < 2) return null;
            host = addressPort.substring(1, bracket);
            portString = addressPort.substring(bracket + 2);
            if (!IPV6.matcher(host).matches()
                    || host.indexOf(':') < 0) return null;
        } else {
            int colon = addressPort.lastIndexOf(':');
            if (colon <= 0) return null;
            host = addressPort.substring(0, colon);
            portString = addressPort.substring(colon + 1);
            if (!IPV4.matcher(host).matches()) return null;
        }
        if (!portString.matches("[0-9]{1,5}")) return null;
        int port;
        try {
            port = Integer.parseInt(portString);
        } catch (NumberFormatException bad) {
            return null;
        }
        if (port < 1 || port > 65535) return null;
        try {
            // With an allowed decimal-dotted/colon-hex literal, getByName
            // performs numeric parsing, not hostname/DNS resolution.
            InetAddress addr = InetAddress.getByName(host);
            if (addr.isAnyLocalAddress() || addr.isLinkLocalAddress()
                    || addr.isLoopbackAddress() || addr.isMulticastAddress()
                    || addr.isSiteLocalAddress()) return null;
            byte[] b = addr.getAddress();
            if (addr instanceof Inet4Address && IPV4.matcher(host).matches()) {
                int a = b[0] & 0xff, c = b[1] & 0xff, d = b[2] & 0xff;
                // RFC6598, reserved and documentation blocks.
                if (a == 0 || a == 10 || a == 127 || a >= 224
                        || (a == 100 && c >= 64 && c <= 127)
                        || (a == 169 && c == 254)
                        || (a == 172 && c >= 16 && c <= 31)
                        || (a == 192 && (c == 0 || c == 168)
                                && (c == 168 || d < 24))
                        || (a == 198 && (c == 18 || c == 19
                                || (c == 51 && d == 100)))
                        || (a == 203 && c == 0 && d == 113)) return null;
                return addr.getHostAddress();
            }
            if (addr instanceof Inet6Address && IPV6.matcher(host).matches()) {
                int first = b[0] & 0xff;
                // Global-unicast 2000::/3 only, excluding 2001:db8::/32.
                if (first < 0x20 || first > 0x3f
                        || (first == 0x20 && (b[1] & 0xff) == 0x01
                                && (b[2] & 0xff) == 0x0d
                                && (b[3] & 0xff) == 0xb8)) return null;
                return addr.getHostAddress();
            }
        } catch (Exception ignored) {
            // A malformed numeric literal cannot be inspected; never query
            // DNS to resolve an arbitrary app-supplied peer name.
        }
        return null;
    }
}
