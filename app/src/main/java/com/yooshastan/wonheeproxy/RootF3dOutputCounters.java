package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * F.3d: read-only comparison of pre-existing filter/OUTPUT counters.
 *
 * The only command used to obtain input is ip[6]tables -t filter -n -v -x -L OUTPUT.
 * Never use -Z, -A, -I, -D, -F, -P, nft mutations or counter-creating rules.
 * This is NOT a packet trace, UID/provenance test or proof of OUTPUT traversal.
 * Raw rule lines/fingerprints must remain RAM-only and must never be logged.
 */
final class RootF3dOutputCounters {
    private RootF3dOutputCounters() { }

    private static final Pattern HEADER = Pattern.compile(
            "^Chain OUTPUT \\(policy (ACCEPT|DROP) (\\d+) packets?, (\\d+) bytes\\)$");
    private static final Pattern RULE = Pattern.compile(
            "^\\s*(\\d+)\\s+(\\d+)\\s+(\\S.*\\S|\\S)\\s*$");

    static final class Snapshot {
        final boolean readable;
        final String policy;
        final long policyPackets;
        final long policyBytes;
        final List<String> ruleIdentities;
        final List<Long> rulePackets;

        Snapshot(boolean readable, String policy, long policyPackets, long policyBytes,
                 List<String> ruleIdentities, List<Long> rulePackets) {
            this.readable = readable;
            this.policy = policy;
            this.policyPackets = policyPackets;
            this.policyBytes = policyBytes;
            this.ruleIdentities = ruleIdentities;
            this.rulePackets = rulePackets;
        }
    }

    static Snapshot unavailable() {
        return new Snapshot(false, "", -1, -1,
                new ArrayList<>(), new ArrayList<>());
    }

    static String command(boolean ipv6) {
        return (ipv6 ? "ip6tables" : "iptables")
                + " -t filter -n -v -x -L OUTPUT 2>/dev/null";
    }

    static Snapshot parse(int exit, List<String> lines) {
        if (exit != 0 || lines == null || lines.size() > 512) return unavailable();
        boolean headerFound = false;
        String policy = "";
        long policyPackets = -1, policyBytes = -1;
        List<String> identities = new ArrayList<>();
        List<Long> packets = new ArrayList<>();
        for (String line : lines) {
            if (line == null || line.length() > 2048) return unavailable();
            String s = line.trim();
            if (s.isEmpty() || s.startsWith("pkts ") || s.startsWith("pkts\t")) {
                continue;
            }
            Matcher header = HEADER.matcher(s);
            if (header.matches()) {
                if (headerFound) return unavailable();
                policy = header.group(1);
                policyPackets = numeric(header.group(2));
                policyBytes = numeric(header.group(3));
                if (policyPackets < 0 || policyBytes < 0) return unavailable();
                headerFound = true;
                continue;
            }
            Matcher rule = RULE.matcher(line);
            if (rule.matches()) {
                long packetCount = numeric(rule.group(1));
                long byteCount = numeric(rule.group(2));
                if (packetCount < 0 || byteCount < 0) return unavailable();
                if (identities.size() == 256) return unavailable();
                // Canonicalize all non-counter columns to detect rule replacement.
                // Contains addresses/targets: NEVER include in reports.
                identities.add(rule.group(3).trim().replaceAll("\\s+", " "));
                packets.add(packetCount);
                continue;
            }
            // A non-empty malformed/unexpected line invalidates the comparison
            // rather than silently treating partial output as a zero snapshot.
            return unavailable();
        }
        if (!headerFound) return unavailable();
        return new Snapshot(true, policy, policyPackets, policyBytes, identities, packets);
    }

    private static long numeric(String str) {
        if (str == null || !str.matches("[0-9]{1,19}")) return -1;
        try { return Long.parseLong(str); }
        catch (NumberFormatException invalid) { return -1; }
    }

    enum Status { MOVED, NO_MOVEMENT, UNAVAILABLE, RULE_SET_CHANGED, COUNTER_RESET }

    static final class Comparison {
        final Status status;
        final int observedRules;
        final int advancedRules;
        final long sumRuleIncrements;
        final long defaultPolicyIncrements;

        Comparison(Status status, int observedRules, int advancedRules,
                   long sumRuleIncrements, long defaultPolicyIncrements) {
            this.status = status;
            this.observedRules = observedRules;
            this.advancedRules = advancedRules;
            this.sumRuleIncrements = sumRuleIncrements;
            this.defaultPolicyIncrements = defaultPolicyIncrements;
        }

        String render(String family) {
            StringBuilder r = new StringBuilder(family)
                    .append(" existing filter/OUTPUT counter comparison: ")
                    .append(status);
            if (status == Status.MOVED || status == Status.NO_MOVEMENT) {
                r.append("\nDefault-policy packet counter delta: +")
                        .append(defaultPolicyIncrements)
                        .append("\nRule entries with packet-count increase: ")
                        .append(advancedRules).append('/').append(observedRules)
                        .append("\nSum of per-rule packet-count increases: +")
                        .append(sumRuleIncrements)
                        .append(" (NOT a unique packet count)");
            } else {
                r.append("\nCounter comparison unavailable or unsafe to interpret.");
            }
            return r.append("\nThese existing, global OUTPUT counters include unrelated ")
                    .append("traffic and can miss other hooks. Correlation with a ")
                    .append("physical ICMPv6 capture does NOT identify its creator, ")
                    .append("prove this packet traversed OUTPUT, or establish what ")
                    .append("a future kill switch should allow. No rules or counters ")
                    .append("were installed, zeroed or modified.")
                    .toString();
        }
    }

    static Comparison compare(Snapshot before, Snapshot after) {
        if (before == null || after == null || !before.readable || !after.readable) {
            return new Comparison(Status.UNAVAILABLE, 0, 0, 0, 0);
        }
        if (!before.policy.equals(after.policy)
                || !before.ruleIdentities.equals(after.ruleIdentities)) {
            return new Comparison(Status.RULE_SET_CHANGED, 0, 0, 0, 0);
        }
        if (after.policyPackets < before.policyPackets
                || after.policyBytes < before.policyBytes) {
            return new Comparison(Status.COUNTER_RESET, 0, 0, 0, 0);
        }
        long sum = 0, policyDelta = after.policyPackets - before.policyPackets;
        int advanced = 0;
        for (int i = 0; i < before.rulePackets.size(); i++) {
            long start = before.rulePackets.get(i), end = after.rulePackets.get(i);
            if (end < start) return new Comparison(Status.COUNTER_RESET, 0, 0, 0, 0);
            long increment = end - start;
            if (Long.MAX_VALUE - sum < increment) {
                return new Comparison(Status.UNAVAILABLE, 0, 0, 0, 0);
            }
            sum += increment;
            if (increment > 0) advanced++;
        }
        Status status = policyDelta > 0 || advanced > 0 ? Status.MOVED : Status.NO_MOVEMENT;
        return new Comparison(status, before.rulePackets.size(), advanced, sum, policyDelta);
    }
}
