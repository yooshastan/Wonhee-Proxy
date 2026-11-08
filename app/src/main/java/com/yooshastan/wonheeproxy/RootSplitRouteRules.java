package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Pure rule planner for the experimental Android kernel routing mismatch.
 * Never changes netd's priority-13000 rules. Commands must only run after
 * device-specific collision, endpoint-mark and identity checks.
 */
final class RootSplitRouteRules {
    static final int FIRST_PRIORITY = 12500;
    static final int LAST_PRIORITY = 12799;
    // Android Fwmark bit 17 is protectedFromVpn. Match locally generated
    // traffic that is NOT protected from VPN, regardless of its network ID.
    // This lets private split destinations override Android's VPN default rule
    // while preserving VpnService.protect() sockets.
    static final String MARK = "0x0/0x20000";
    // Old persisted ledgers used this narrower selector; retain it for exact rollback.
    static final String LEGACY_MARK = "0x0/0x2ffff";
    static final long PROTECTED_FROM_VPN_MASK = 0x20000L;
    // Used only to validate that WireGuard transport marks carry routing identity bits.
    static final long TRANSPORT_MARK_IDENTITY_MASK = 0x2ffffL;
    static final long MARK_MASK = TRANSPORT_MARK_IDENTITY_MASK;
    static final String UIDS = "0-99999";

    static final class Rule {
        final int family;
        final int priority;
        final String destination;
        final String device;
        final String probe;
        // Stored per rule so older five-field ledgers can still remove their exact
        // legacy fwmark selector after an APK upgrade.
        final String mark;

        Rule(int family, int priority, String destination, String device, String probe) {
            this(family, priority, destination, device, probe, MARK);
        }

        Rule(int family, int priority, String destination, String device, String probe, String mark) {
            this.family = family;
            this.priority = priority;
            this.destination = destination;
            this.device = device;
            this.probe = probe;
            this.mark = mark;
        }

        String familyCommand() { return family == 6 ? "ip -6" : "ip -4"; }

        String add() {
            return familyCommand() + " rule add pref " + priority + " to " + destination
                    + " fwmark " + mark + " iif lo uidrange " + UIDS
                    + " lookup " + device;
        }

        String delete() {
            return familyCommand() + " rule del pref " + priority + " to " + destination
                    + " fwmark " + mark + " iif lo uidrange " + UIDS
                    + " lookup " + device;
        }

        boolean matchesListing(String line) {
            return line != null && parsePriority(line) == priority
                    && sameCidr(destination, wordAfter(line, "to"))
                    && mark.equals(wordAfter(line, "fwmark"))
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

    /**
     * Audit-only condition: a route match is not sufficient to claim that
     * Wonhee can safely roll back its reserved kernel rules. Refuse missing,
     * stale, foreign or unverified ledgers, including count-only matches.
     * No kernel changes are performed here.
     */
    static boolean auditOwnershipConsistent(List<Rule> planned, List<Rule> recorded,
            int reserved, boolean exactLiveVerified) {
        if (planned == null || recorded == null || reserved < 0) return false;
        if (recorded.isEmpty()) return reserved == 0;
        if (!exactLiveVerified || reserved != recorded.size()
                || recorded.size() != planned.size()) return false;
        for (int i = 0; i < planned.size(); i++) {
            Rule expected = planned.get(i);
            Rule owned = recorded.get(i);
            // A legacy selector can still be safely owned and rolled back,
            // but only after its exact live kernel rule is verified. Do not
            // infer ownership from matching route destinations alone.
            if (expected.family != owned.family || expected.priority != owned.priority
                    || !expected.destination.equals(owned.destination)
                    || !expected.device.equals(owned.device)
                    || !expected.probe.equals(owned.probe)
                    || !(MARK.equals(owned.mark) || LEGACY_MARK.equals(owned.mark))) {
                return false;
            }
        }
        return true;
    }

    static boolean reservedPriorityPresent(List<String> lines) {
        if (lines == null) return true;
        for (String line : lines) {
            int value = parsePriority(line);
            if (value >= FIRST_PRIORITY && value <= LAST_PRIORITY) return true;
        }
        return false;
    }

    /**
     * Check that a WireGuard fwmark is present and carries nonzero Android
     * routing-identity bits. This is NOT endpoint-egress proof: numeric endpoint
     * routing is checked separately against the physical underlay.
     */
    static boolean transportMarkHasIdentity(String rawMark) {
        if (rawMark == null) return false;
        try {
            String mark = rawMark.trim();
            if (mark.equals("off") || mark.isEmpty()) return false;
            return (Long.decode(mark) & TRANSPORT_MARK_IDENTITY_MASK) != 0;
        } catch (NumberFormatException invalid) { return false; }
    }

    static String encode(List<Rule> rules) {
        StringBuilder result = new StringBuilder();
        for (Rule rule : rules) {
            result.append(rule.family).append('|').append(rule.priority).append('|')
                    .append(rule.destination).append('|').append(rule.device).append('|')
                    .append(rule.probe).append('|').append(rule.mark).append('\n');
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
            if ((parts.length != 5 && parts.length != 6)
                    || !(parts[0].equals("4") || parts[0].equals("6"))
                    || !parts[1].matches("[0-9]{5}")
                    || !parts[3].matches("wnm[0-9a-f]{12}")
                    || !parts[2].matches("[0-9a-fA-F:.]+/[0-9]{1,3}")
                    || !parts[4].matches("[0-9a-fA-F:.]+")) {
                throw new IllegalArgumentException("Invalid owned-rule ledger.");
            }
            // Five-field entries predate the mark-aware selector. Preserve their
            // original exact command until the user explicitly removes them.
            String mark = parts.length == 5 ? LEGACY_MARK : parts[5];
            if (!MARK.equals(mark) && !LEGACY_MARK.equals(mark)) {
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
            rules.add(new Rule(family, priority, parts[2], parts[3], parts[4], mark));
        }
        return rules;
    }

    /**
     * Pure rollback preflight: allow a partially installed/removing recorded
     * ledger, but NEVER accept duplicate priorities, unrecorded rules, modified
     * selectors or a cross-family priority collision.
     *
     * Android prints tabs after priorities on some releases; parsePriority and
     * the token matching tolerate that harmless formatting difference.
     */
    static int verifyRollbackCandidates(List<Rule> owned, List<String> ipv4,
            List<String> ipv6) {
        if (owned == null || ipv4 == null || ipv6 == null) {
            throw new IllegalArgumentException("Missing rollback audit evidence.");
        }
        Set<String> observed = new LinkedHashSet<>();
        int found = 0;
        for (int family : new int[]{4, 6}) {
            for (String line : family == 4 ? ipv4 : ipv6) {
                int priority = parsePriority(line);
                if (priority < FIRST_PRIORITY || priority > LAST_PRIORITY) continue;
                String key = family + ":" + priority;
                if (!observed.add(key)) {
                    throw new IllegalStateException("Duplicate reserved routing priority.");
                }
                int matches = 0;
                for (Rule candidate : owned) {
                    if (candidate.family == family && candidate.priority == priority
                            && candidate.matchesListing(line)) {
                        matches++;
                    }
                }
                if (matches != 1) {
                    throw new IllegalStateException(
                            "Reserved policy rule differs from exact saved ownership.");
                }
                found++;
            }
        }
        if (found > owned.size()) {
            throw new IllegalStateException("More reserved rules than owned ledger entries.");
        }
        return found;
    }

    /** True when the split-route selector should match this Android packet mark. */
    static boolean splitRouteMarkMatches(long mark) {
        return mark >= 0 && mark <= 0xffffffffL
                && (mark & PROTECTED_FROM_VPN_MASK) == 0;
    }

    /**
     * Extract representative, unprotected fwmark values from live Android RPDB
     * rules. These values drive read-only UID/mark route simulations; they are
     * not treated as an exhaustive inventory of actual application sockets.
     */
    static List<Long> unprotectedMarkProbes(List<String> ruleLines) {
        Set<Long> marks = new LinkedHashSet<>();
        if (ruleLines == null) return new ArrayList<>();
        for (String line : ruleLines) {
            if (line == null) continue;
            String[] tokens = line.trim().split("\\s+");
            for (int i = 0; i + 1 < tokens.length; i++) {
                if (!tokens[i].equals("fwmark")) continue;
                String value = tokens[i + 1].split("/", 2)[0];
                if (!value.matches("0x[0-9a-fA-F]{1,8}")) continue;
                try {
                    long mark = Long.parseLong(value.substring(2), 16);
                    if (mark != 0 && splitRouteMarkMatches(mark)) marks.add(mark);
                } catch (NumberFormatException ignored) { /* ignore malformed kernel text */ }
            }
        }
        return new ArrayList<>(marks);
    }

    /** Refuse a split plan if a WireGuard outer endpoint falls inside a HOME prefix. */
    static boolean endpointOutsideSplitRoutes(String address, List<Rule> rules) {
        if (address == null || !address.matches("[0-9a-fA-F:.]+") || rules == null) return false;
        try {
            byte[] target = InetAddress.getByName(address).getAddress();
            for (Rule rule : rules) {
                String network = rule.destination.substring(0, rule.destination.indexOf('/'));
                byte[] base = InetAddress.getByName(network).getAddress();
                int bits = prefix(rule.destination);
                if (base.length != target.length || bits > base.length * 8) continue;
                boolean inside = true;
                for (int bit = 0; bit < bits; bit++) {
                    int mask = 1 << (7 - bit % 8);
                    if ((base[bit / 8] & mask) != (target[bit / 8] & mask)) {
                        inside = false;
                        break;
                    }
                }
                if (inside) return false;
            }
            return true;
        } catch (Exception invalid) {
            return false;
        }
    }

    static String preview(List<Rule> rules) {
        if (rules.isEmpty()) {
            return "No cross-tunnel split-route priority adjustments are needed by this plan.";
        }
        StringBuilder text = new StringBuilder("ROUTING POLICY PLAN (installation status checked separately)\n");
        for (Rule rule : rules) {
            text.append(rule.priority).append(" · IPv").append(rule.family)
                    .append(" · fwmark ").append(rule.mark)
                    .append(" · ").append(rule.destination).append(" → ")
                    .append(rule.device).append("\n");
        }
        return text.append("These priority-12500+ rules are Wonhee-owned and precede "
                + "Android's priority-13000 VPN defaults. The selector matches locally "
                + "generated traffic not protectedFromVpn; protected sockets bypass it. "
                + "Actual app sockets, endpoint egress, DNS and rollback still require "
                + "device verification.").toString();
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

    /** Shared non-network-base probe for both the routing audit and F's hard gate. */
    static String probe(String cidr) {
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
