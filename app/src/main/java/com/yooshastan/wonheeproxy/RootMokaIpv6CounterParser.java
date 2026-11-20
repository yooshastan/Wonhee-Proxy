package com.yooshastan.wonheeproxy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only parser for exact ip6tables -t filter -L <chain> -nvx counters.
 * Counts are observational only: counters are not proof of leak prevention.
 */
final class RootMokaIpv6CounterParser {
    private static final Pattern LINE = Pattern.compile(
            "^\\s*([0-9]+)\\s+([0-9]+)\\s+([A-Za-z0-9_]+)(?:\\s+.*)?$");
    static final class Counts {
        final long packets;
        final long bytes;
        Counts(long packets, long bytes) {
            if (packets < 0 || bytes < 0) {
                throw new IllegalArgumentException("Negative firewall counter.");
            }
            this.packets = packets;
            this.bytes = bytes;
        }
    }
    private RootMokaIpv6CounterParser() { }

    static Counts target(String listing, String expectedTarget) {
        if (listing == null || listing.length() > 32768
                || expectedTarget == null || !expectedTarget.matches("[A-Z0-9_]{1,28}")) {
            throw new IllegalArgumentException("Invalid counter listing.");
        }
        Counts found = null;
        for (String line : listing.split("\\r?\\n")) {
            Matcher match = LINE.matcher(line);
            if (!match.matches() || !expectedTarget.equals(match.group(3))) continue;
            if (found != null) {
                throw new IllegalArgumentException("Ambiguous duplicate target counter.");
            }
            try {
                found = new Counts(Long.parseLong(match.group(1)),
                        Long.parseLong(match.group(2)));
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("Unrepresentable firewall counter.", invalid);
            }
        }
        if (found == null) throw new IllegalArgumentException("Expected target missing.");
        return found;
    }

    static long delta(long before, long after) {
        if (before < 0 || after < before) return -1L; // reset/overflow, never fake zero
        return after - before;
    }
}
