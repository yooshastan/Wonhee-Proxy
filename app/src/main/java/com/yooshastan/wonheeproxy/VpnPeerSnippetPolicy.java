package com.yooshastan.wonheeproxy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Opt-in multi-gateway profile import guard. Only appends ONE peer-only section
 * to an existing WireGuard interface. It never merges independent Interface
 * private keys or automatically edits server peer configuration.
 *
 * Pure Java so route and malformed-input checks run before any Android VPN work.
 */
final class VpnPeerSnippetPolicy {
    private static final int MAX_BYTES = 8192;
    private static final int MAX_HOME_ROUTES = 4;

    private VpnPeerSnippetPolicy() { }

    static String checkedPrivatePeer(String raw, List<String> alreadyAllowed) {
        if (raw == null || raw.isEmpty()
                || raw.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new IllegalArgumentException("Invalid peer-only file.");
        }
        String source = raw.startsWith("\uFEFF") ? raw.substring(1) : raw;
        StringBuilder clean = new StringBuilder();
        Set<String> seenKeys = new HashSet<>();
        boolean peerStarted = false;
        String allowed = null;
        for (String line : source.split("\\r?\\n", -1)) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#") || value.startsWith(";")) continue;
            if (value.startsWith("[") || value.endsWith("]")) {
                if (!value.equals("[Peer]") || peerStarted) {
                    throw new IllegalArgumentException("Provide a single [Peer] section, not a full VPN configuration.");
                }
                peerStarted = true;
                clean.append("[Peer]\\n");
                continue;
            }
            if (!peerStarted) throw new IllegalArgumentException("Expected [Peer] section.");
            String[] parts = value.split("=", 2);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid peer field.");
            String key = parts[0].trim();
            String parameter = parts[1].trim();
            if (!key.equals("PublicKey") && !key.equals("PresharedKey")
                    && !key.equals("Endpoint") && !key.equals("AllowedIPs")
                    && !key.equals("PersistentKeepalive")) {
                throw new IllegalArgumentException("Only standard peer fields are allowed.");
            }
            if (parameter.isEmpty() || !seenKeys.add(key)) {
                throw new IllegalArgumentException("Missing or repeated peer value.");
            }
            if (key.equals("AllowedIPs")) allowed = parameter;
            clean.append(key).append(" = ").append(parameter).append('\\n');
        }
        if (!peerStarted || !seenKeys.contains("PublicKey")
                || !seenKeys.contains("Endpoint") || allowed == null) {
            throw new IllegalArgumentException("Peer requires PublicKey, Endpoint and AllowedIPs.");
        }

        List<Ipv4Range> existing = new ArrayList<>();
        if (alreadyAllowed != null) {
            for (String cidr : alreadyAllowed) {
                if (cidr == null || cidr.contains(":")) continue;
                Ipv4Range range = parseIpv4Cidr(cidr.trim());
                if (range.prefix != 0) existing.add(range); // One default exit peer is intentional.
            }
        }
        String[] requested = allowed.split(",");
        if (requested.length == 0 || requested.length > MAX_HOME_ROUTES) {
            throw new IllegalArgumentException("Choose one to four private IPv4 home routes.");
        }
        List<Ipv4Range> proposed = new ArrayList<>();
        for (String cidr : requested) {
            Ipv4Range range = parseIpv4Cidr(cidr.trim());
            if (!range.entirelyPrivate()) {
                throw new IllegalArgumentException("Home peer routes must be wholly RFC1918 IPv4.");
            }
            for (Ipv4Range used : existing) {
                if (range.overlaps(used)) {
                    throw new IllegalArgumentException("Home route conflicts with an existing non-default peer route.");
                }
            }
            for (Ipv4Range other : proposed) {
                if (range.overlaps(other)) {
                    throw new IllegalArgumentException("New home routes overlap each other.");
                }
            }
            proposed.add(range);
        }
        return clean.toString();
    }

    private static final class Ipv4Range {
        final long start;
        final long end;
        final int prefix;

        Ipv4Range(long address, int prefix) {
            this.prefix = prefix;
            long mask = prefix == 0 ? 0L : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            start = address & mask;
            end = start | (~mask & 0xffffffffL);
        }

        boolean overlaps(Ipv4Range other) {
            return start <= other.end && other.start <= end;
        }

        boolean entirelyPrivate() {
            return within(10, 0, 0, 0, 8)
                    || within(172, 16, 0, 0, 12)
                    || within(192, 168, 0, 0, 16);
        }

        private boolean within(int a, int b, int c, int d, int p) {
            Ipv4Range block = new Ipv4Range(
                    ((long) a << 24) | ((long) b << 16) | ((long) c << 8) | d, p);
            return start >= block.start && end <= block.end;
        }
    }

    private static Ipv4Range parseIpv4Cidr(String cidr) {
        String[] parts = cidr.split("/", -1);
        if (parts.length != 2 || !parts[1].matches("[0-9]{1,2}")) {
            throw new IllegalArgumentException("Use numeric IPv4 CIDRs.");
        }
        int prefix = Integer.parseInt(parts[1]);
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("Invalid CIDR prefix.");
        String[] octets = parts[0].split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Use dotted IPv4 CIDRs.");
        long address = 0;
        for (String segment : octets) {
            if (!segment.matches("0|[1-9][0-9]{0,2}")) {
                throw new IllegalArgumentException("Invalid IPv4 octet.");
            }
            int octet = Integer.parseInt(segment);
            if (octet > 255) throw new IllegalArgumentException("Invalid IPv4 octet.");
            address = (address << 8) | octet;
        }
        return new Ipv4Range(address, prefix);
    }
}
