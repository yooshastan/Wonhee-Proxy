package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Pure rule planner for the experimental Android kernel routing mismatch.
 * Never changes netd's priority-13000 rules. Commands must only run after
 * device-specific collision, endpoint-mark and identity checks.
 */
final class RootSplitRouteRules {
    static final int FIRST_PRIORITY = 12500;
    static final int LAST_PRIORITY = 12799;
    // Match only unbound/unmarked traffic, not Android sockets with an explicit
    // network ID (low 16 bits), protection bits, or WireGuard's UDP fwmark.
    static final String MARK = "0x0/0x2ffff";
    static final long MARK_MASK = 0x2ffffL;
    static final String UIDS = "0-99999";

    static final class Rule {
        final int family;
        final int priority;
        final String destination;
        final String device;
        final String probe;

        Rule(int family, int priority, String destination, String device, String probe) {
            this.family = family;
            this.priority = priority;
            this.destination = destination;
            this.device = device;
            this.probe = probe;
        }

        String familyCommand() { return family == 6 ? "ip -6" : "ip -4"; }

        String add() {
            return familyCommand() + " rule add pref " + priority + " to " + destination
                    + " fwmark " + MARK + " iif lo uidrange " + UIDS
                    + " lookup " + device;
        }

        String delete() {
            return familyCommand() + " rule del pref " + priority + " to " + destination
                    + " fwmark " + MARK + " iif lo uidrange " + UIDS
                    + " lookup " + device;
        }

        boolean matchesListing(String line) {
            return line != null && parsePriority(line) == priority
                    && sameCidr(destination, wordAfter(line, "to"))
                    && MARK.equals(wordAfter(line, "fwmark"))
                    && line.contains("iif lo")
                    && line.contains("uidrange " + UIDS)
                    && line.contains("lookup " + device);
        }
    }

    private RootSplitRouteRules() { }

    static List<Rule> plan(List<RootMultiTunnelPlan.Entry> entries) {
        RootMultiTunnelPlan.validate(entries);
        String default4 = null;
        String default6 = null;
        for (RootMultiTunnelPlan.Entry entry : entries) {
            for (String cidr : entry.peerRoutes) {
                if ("0.0.0.0/0".equals(cidr)) default4 = entry.device;
                if ("::/0".equals(cidr) || "0:0:0:0:0:0:0:0/0".equals(cidr)) {
                    default6 = entry.device;
                }
            }
        }
        // No changes required when no split destination competes with a default.
        List<Rule> planned = new ArrayList<>();
        for (RootMultiTunnelPlan.Entry entry : entries) {
            for (String cidr : entry.peerRoutes) {
                int family = cidr.indexOf(':') >= 0 ? 6 : 4;
                String defaultDevice = family == 6 ? default6 : default4;
                if (defaultDevice == null || defaultDevice.equals(entry.device)
                        || cidr.endsWith("/0")) continue;
                String probe = probe(cidr);
                planned.add(new Rule(family, 0, cidr, entry.device, probe));
            }
        }
        // Specific routes first, then a stable device/CIDR ordering.
        Collections.sort(planned, Comparator
                .comparingInt((Rule r) -> -prefix(r.destination))
                .thenComparingInt(r -> r.family)
                .thenComparing(r -> r.device)
                .thenComparing(r -> r.destination));
        if (planned.size() > LAST_PRIORITY - FIRST_PRIORITY + 1) {
            throw new IllegalArgumentException("Too many routing rules for the reserved range.");
        }
        List<Rule> assigned = new ArrayList<>();
        for (int i = 0; i < planned.size(); i++) {
            Rule rule = planned.get(i);
            assigned.add(new Rule(rule.family, FIRST_PRIORITY + i,
                    rule.destination, rule.device, rule.probe));
        }
        return assigned;
    }

    static int parsePriority(String line) {
        if (line == null) return -1;
        int colon = line.indexOf(':');
        if (colon < 0 || colon > 6) return -1;
        try { return Integer.parseInt(line.substring(0, colon).trim()); }
        catch (NumberFormatException ignored) { return -1; }
    }

    static boolean reservedPriorityPresent(List<String> lines) {
        if (lines == null) return true;
        for (String line : lines) {
            int value = parsePriority(line);
            if (value >= FIRST_PRIORITY && value <= LAST_PRIORITY) return true;
        }
        return false;
    }

    /** Kernel WireGuard transport packets must not match any owned rule. */
    static boolean transportBypassesRules(String rawMark) {
        if (rawMark == null) return false;
        try {
            String mark = rawMark.trim();
            if (mark.equals("off") || mark.isEmpty()) return false;
            return (Long.decode(mark) & MARK_MASK) != 0;
        } catch (NumberFormatException invalid) { return false; }
    }

    static String encode(List<Rule> rules) {
        StringBuilder result = new StringBuilder();
        for (Rule rule : rules) {
            result.append(rule.family).append('|').append(rule.priority).append('|')
                    .append(rule.destination).append('|').append(rule.device).append('|')
                    .append(rule.probe).append('\n');
        }
        return result.toString();
    }

    /** Strictly validate a saved ledger before it can generate root commands. */
    static List<Rule> decode(String serialized) {
        List<Rule> rules = new ArrayList<>();
        if (serialized == null || serialized.isEmpty()) return rules;
        String[] lines = serialized.split("\\n", -1);
        if (lines.length > LAST_PRIORITY - FIRST_PRIORITY + 2) {
            throw new IllegalArgumentException("Invalid owned-rule ledger.");
        }
        java.util.Set<Integer> priority4 = new java.util.HashSet<>();
        java.util.Set<Integer> priority6 = new java.util.HashSet<>();
        for (String line : lines) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\\|", -1);
            if (parts.length != 5 || !(parts[0].equals("4") || parts[0].equals("6"))
                    || !parts[1].matches("[0-9]{5}")
                    || !parts[3].matches("wnm[0-9a-f]{12}")
                    || !parts[2].matches("[0-9a-fA-F:.]+/[0-9]{1,3}")
                    || !parts[4].matches("[0-9a-fA-F:.]+")) {
                throw new IllegalArgumentException("Invalid owned-rule ledger.");
            }
            int family = Integer.parseInt(parts[0]);
            int priority = Integer.parseInt(parts[1]);
            if (priority < FIRST_PRIORITY || priority > LAST_PRIORITY
                    || !(family == 4 ? priority4 : priority6).add(priority)
                    || (family == 6) != parts[2].contains(":")) {
                throw new IllegalArgumentException("Invalid owned-rule ledger.");
            }
            String calculated = probe(parts[2]);
            if (!parts[4].equals(calculated)) {
                throw new IllegalArgumentException("Invalid owned-rule ledger.");
            }
            rules.add(new Rule(family, priority, parts[2], parts[3], parts[4]));
        }
        return rules;
    }

    static String preview(List<Rule> rules) {
        if (rules.isEmpty()) {
            return "No cross-tunnel split-route priority adjustments are needed by this plan.";
        }
        StringBuilder text = new StringBuilder("ROUTING POLICY PLAN (installation status checked separately)\n");
        for (Rule rule : rules) {
            text.append(rule.priority).append(" · IPv").append(rule.family)
                    .append(" · ").append(rule.destination).append(" → ")
                    .append(rule.device).append("\n");
        }
        return text.append("These priority-12500+ rules would be owned by Wonhee and "
                + "precede Android's priority-13000 default selection. Device-specific "
                + "root routing, app fwmarks, transport marks, DNS and rollback "
                + "must be verified before calling the result safe.").toString();
    }

    private static int prefix(String cidr) {
        return Integer.parseInt(cidr.substring(cidr.lastIndexOf('/') + 1));
    }

    private static String wordAfter(String line, String word) {
        if (line == null) return "";
        String[] tokens = line.trim().split("\\s+");
        for (int i = 0; i < tokens.length - 1; i++) {
            if (tokens[i].equals(word)) return tokens[i + 1];
        }
        return "";
    }

    /** A kernel may canonicalize a host-form CIDR to its network address. */
    private static boolean sameCidr(String expected, String shown) {
        try {
            if (prefix(expected) != prefix(shown)) return false;
            String left = expected.substring(0, expected.indexOf('/'));
            String right = shown.substring(0, shown.indexOf('/'));
            if (!left.matches("[0-9a-fA-F:.]+") || !right.matches("[0-9a-fA-F:.]+")) return false;
            byte[] l = InetAddress.getByName(left).getAddress();
            byte[] r = InetAddress.getByName(right).getAddress();
            if (l.length != r.length || prefix(expected) > l.length * 8) return false;
            for (int bit = 0; bit < prefix(expected); bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((l[bit / 8] & mask) != (r[bit / 8] & mask)) return false;
            }
            return true;
        } catch (Exception invalid) { return false; }
    }

    private static String probe(String cidr) {
        try {
            String address = cidr.substring(0, cidr.indexOf('/'));
            int prefix = prefix(cidr);
            byte[] bytes = InetAddress.getByName(address).getAddress();
            int total = bytes.length * 8;
            // Prefer the first address inside the prefix; use +1 for networks
            // with host bits, avoiding a network-base-only routing test.
            for (int bit = prefix; bit < total; bit++) {
                bytes[bit / 8] &= ~(1 << (7 - bit % 8));
            }
            if (prefix < total - 1) bytes[bytes.length - 1] |= 1;
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (Exception invalid) {
            throw new IllegalArgumentException("Unable to select numeric route probe.");
        }
    }
}
