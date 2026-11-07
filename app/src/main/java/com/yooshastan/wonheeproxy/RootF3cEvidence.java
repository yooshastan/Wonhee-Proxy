package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Locale;

/**
 * Read-only F.3c classification. No packet generation, firewall mutation,
 * netfilter counter insertion or persistent packet/endpoint storage.
 *
 * This cannot prove a physical-interface packet used local OUTPUT, nor identify
 * its source process. Reports are aggregate-only and redact all raw rule lines.
 */
final class RootF3cEvidence {
    private RootF3cEvidence() { }

    enum Icmp6 {
        ROUTER_SOLICITATION, ROUTER_ADVERTISEMENT,
        NEIGHBOR_SOLICITATION, NEIGHBOR_ADVERTISEMENT, REDIRECT,
        ECHO_REQUEST, ECHO_REPLY, OTHER_KNOWN, UNKNOWN
    }

    static Icmp6 classifyIcmp6(String raw) {
        if (raw == null) return Icmp6.UNKNOWN;
        String s = raw.toLowerCase(Locale.ROOT);
        int idx = s.indexOf("icmp6,");
        if (idx < 0) idx = s.indexOf("icmpv6,");
        if (idx < 0) return Icmp6.UNKNOWN;
        String type = s.substring(s.indexOf(',', idx) + 1);
        // Never infer ICMPv6 type from the multicast destination or IP version.
        if (type.contains("router solicitation")) return Icmp6.ROUTER_SOLICITATION;
        if (type.contains("router advertisement")) return Icmp6.ROUTER_ADVERTISEMENT;
        if (type.contains("neighbor solicitation")
                || type.contains("neighbour solicitation")) return Icmp6.NEIGHBOR_SOLICITATION;
        if (type.contains("neighbor advertisement")
                || type.contains("neighbour advertisement")) return Icmp6.NEIGHBOR_ADVERTISEMENT;
        if (type.contains("redirect")) return Icmp6.REDIRECT;
        if (type.contains("echo request")) return Icmp6.ECHO_REQUEST;
        if (type.contains("echo reply")) return Icmp6.ECHO_REPLY;
        if (type.contains("destination unreachable") || type.contains("packet too big")
                || type.contains("time exceeded") || type.contains("parameter problem")) {
            return Icmp6.OTHER_KNOWN;
        }
        return Icmp6.UNKNOWN;
    }

    static final class OutputInventory {
        final boolean readable;
        final int appendedRules;
        final int jumps;
        final boolean defaultPolicyKnown;
        final String policy;

        OutputInventory(boolean readable, int appendedRules, int jumps,
                boolean defaultPolicyKnown, String policy) {
            this.readable = readable;
            this.appendedRules = appendedRules;
            this.jumps = jumps;
            this.defaultPolicyKnown = defaultPolicyKnown;
            this.policy = policy;
        }

        String render(String family) {
            if (!readable) return family + " OUTPUT rules: UNAVAILABLE";
            return family + " OUTPUT rules: " + appendedRules
                    + " rule entries / " + jumps + " jump-or-goto entries; default policy: "
                    + (defaultPolicyKnown ? policy : "NOT REPORTED")
                    + ". Rules were inspected read only. No counters installed and no "
                    + "packet-to-OUTPUT attribution established.";
        }
    }

    static OutputInventory inventory(int exitCode, List<String> raw) {
        if (exitCode != 0 || raw == null) {
            return new OutputInventory(false, 0, 0, false, "");
        }
        int rules = 0, jumps = 0;
        String policy = "";
        boolean seenExpected = false;
        for (String line : raw) {
            if (line == null || line.length() > 2048) continue;
            String s = line.trim();
            if (s.startsWith("-P OUTPUT ")) {
                String candidate = s.substring("-P OUTPUT ".length()).trim();
                if (candidate.matches("ACCEPT|DROP|REJECT")) {
                    policy = candidate;
                    seenExpected = true;
                }
            } else if (s.startsWith("-A OUTPUT ")) {
                rules++;
                seenExpected = true;
                if (s.contains(" -j ") || s.contains(" -g ")) jumps++;
            }
        }
        // Missing policy/rules is not sufficient evidence of an empty chain.
        return new OutputInventory(seenExpected, rules, jumps,
                !policy.isEmpty(), policy);
    }
}
