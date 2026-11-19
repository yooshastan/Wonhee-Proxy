package com.yooshastan.wonheeproxy;

import java.util.HashSet;
import java.util.Set;

/**
 * Pure parser for narrow Android iproute2 readback. Never guesses ownership
 * from a wnm prefix alone: names, exact route destinations and devices must
 * match. The caller separately verifies live interface public keys.
 */
final class RootIsolatedWireGuardKernelListing {
    enum Match { ABSENT, EXACT, FOREIGN_OR_CHANGED }

    private RootIsolatedWireGuardKernelListing() { }

    static Match address(String output, int family, String cidr, String device) {
        if (output == null || !safeDevice(device) || !numericLiteral(cidr, family)) {
            return Match.FOREIGN_OR_CHANGED;
        }
        String af = family == 4 ? "inet" : "inet6";
        boolean found = false;
        for (String raw : output.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            String[] pieces = line.split("\\s+");
            // Typical: 7: wnmabcdef123456 inet 10.15.0.2/32 scope global ...
            if (pieces.length < 4 || !device.equals(pieces[1])
                    || !af.equals(pieces[2])) {
                return Match.FOREIGN_OR_CHANGED;
            }
            if (cidr.equals(pieces[3])) found = true;
            // Do not let a foreign address on our link be silently adopted.
            else if (!(family == 6 && pieces[3].startsWith("fe80:"))) {
                return Match.FOREIGN_OR_CHANGED;
            }
        }
        return found ? Match.EXACT : Match.ABSENT;
    }

    static Match privateRoute(String output, int family, String cidr,
            String device) {
        if (output == null || !safeDevice(device) || !numericLiteral(cidr, family)) {
            return Match.FOREIGN_OR_CHANGED;
        }
        String wanted = "0.0.0.0/0".equals(cidr) || "::/0".equals(cidr)
                ? "default" : cidr;
        boolean present = false;
        for (String raw : output.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            String[] t = line.split("\\s+");
            if (!wanted.equals(t[0])) continue;
            String actualDev = tokenAfter(t, "dev");
            if (!device.equals(actualDev) || hasAny(t,
                    "via", "nhid", "nexthop", "unreachable", "blackhole",
                    "prohibit", "throw", "encap")) {
                return Match.FOREIGN_OR_CHANGED;
            }
            if (present) return Match.FOREIGN_OR_CHANGED;
            present = true;
        }
        return present ? Match.EXACT : Match.ABSENT;
    }

    static Match interfaceKind(String ipLink, String device) {
        if (ipLink == null || !safeDevice(device)) return Match.FOREIGN_OR_CHANGED;
        if (ipLink.trim().isEmpty()) return Match.ABSENT;
        // -d -o output includes 'wireguard' on Linux; if this Android tool
        // omits kind even for valid links, refuse rather than guess.
        if (!ipLink.matches("(?s).*\\b" + device + "(?:@[^:]*)?:.*")
                || !ipLink.matches("(?s).*\\bwireguard\\b.*")) {
            return Match.FOREIGN_OR_CHANGED;
        }
        return Match.EXACT;
    }

    static Match interfaceUp(String ipLink, String device) {
        Match kind = interfaceKind(ipLink, device);
        if (kind != Match.EXACT) return kind;
        int start = ipLink.indexOf('<');
        int end = ipLink.indexOf('>', start + 1);
        if (start < 0 || end < 0) return Match.FOREIGN_OR_CHANGED;
        for (String flag : ipLink.substring(start + 1, end).split(",")) {
            if ("UP".equals(flag.trim())) return Match.EXACT;
        }
        return Match.ABSENT;
    }

    private static String tokenAfter(String[] words, String key) {
        for (int i = 0; i + 1 < words.length; i++) {
            if (key.equals(words[i])) return words[i + 1];
        }
        return null;
    }

    private static boolean hasAny(String[] words, String... forbidden) {
        Set<String> tokens = new HashSet<>();
        java.util.Collections.addAll(tokens, words);
        for (String word : forbidden) {
            if (tokens.contains(word)) return true;
        }
        return false;
    }

    private static boolean safeDevice(String value) {
        return value != null && value.matches("wnm[0-9a-f]{12}");
    }

    private static boolean numericLiteral(String cidr, int family) {
        if (cidr == null) return false;
        String[] pair = cidr.split("/", -1);
        if (pair.length != 2 || !pair[1].matches("[0-9]{1,3}")) return false;
        try {
            int bits = Integer.parseInt(pair[1]);
            if (family == 4) {
                if (!pair[0].matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")
                        || bits > 32) return false;
                for (String part : pair[0].split("\\.")) {
                    if (Integer.parseInt(part) > 255) return false;
                }
                return true;
            }
            return family == 6 && bits <= 128
                    && pair[0].contains(":")
                    && pair[0].matches("[0-9A-Fa-f:]+");
        } catch (NumberFormatException invalid) {
            return false;
        }
    }
}
