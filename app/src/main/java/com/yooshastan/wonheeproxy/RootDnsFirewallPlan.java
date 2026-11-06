package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An exact, bounded DNS-only interception plan. Commands are never inferred
 * from a live firewall listing and are only executable after an app-owned
 * rollback intent has been committed. This is separate from Batch F's
 * full-network kill switch.
 *
 * The Go DNS relay listens on IPv4 loopback. IPv6 port-53 DNS is refused, not
 * redirected across families; classic DoT (TCP/853) is refused. Application-
 * implemented HTTPS/QUIC on arbitrary ports is outside this DNS-port guard.
 */
final class RootDnsFirewallPlan {
    static final int PORT = 53535;
    static final String LEDGER = "wonhee_dns_firewall_v1";

    static final class Rule {
        final boolean ipv6;
        final boolean nat;
        final String tag;
        final String args;

        Rule(boolean ipv6, boolean nat, String tag, String args) {
            this.ipv6 = ipv6;
            this.nat = nat;
            this.tag = tag;
            this.args = args;
        }

        String commandPrefix() { return (ipv6 ? "ip6tables" : "iptables") + " -w"
                + (nat ? " -t nat" : ""); }

        String add() { return commandPrefix() + " -I OUTPUT " + args; }
        String delete() { return commandPrefix() + " -D OUTPUT " + args; }
        String exists() { return commandPrefix() + " -C OUTPUT " + args; }

        /** Exact canonical listing equality; never adopt another app's rule. */
        boolean matchesListing(String entry) {
            if (entry == null || !entry.startsWith("-A OUTPUT ")) return false;
            // iptables -S may print the comment with optional shell quotes.
            String listed = entry.replace("\"" + tag + "\"", tag);
            return listed.equals("-A OUTPUT " + args);
        }
    }

    private RootDnsFirewallPlan() { }

    static List<Rule> rules() {
        List<Rule> result = new ArrayList<>();
        result.add(new Rule(false, true, "WN_DNS4_UDP",
                "-p udp --dport 53 -m comment --comment WN_DNS4_UDP -j REDIRECT --to-ports " + PORT));
        result.add(new Rule(false, true, "WN_DNS4_TCP",
                "-p tcp --dport 53 -m comment --comment WN_DNS4_TCP -j REDIRECT --to-ports " + PORT));
        result.add(new Rule(false, false, "WN_DOT4_TCP",
                "-p tcp --dport 853 -m comment --comment WN_DOT4_TCP -j REJECT"));
        result.add(new Rule(false, false, "WN_DOQ4_APP",
                "-p udp --dport 853 -m owner ! --uid-owner 0 -m comment --comment WN_DOQ4_APP -j REJECT"));
        result.add(new Rule(true, false, "WN_DNS6_UDP",
                "-p udp --dport 53 -m comment --comment WN_DNS6_UDP -j REJECT"));
        result.add(new Rule(true, false, "WN_DNS6_TCP",
                "-p tcp --dport 53 -m comment --comment WN_DNS6_TCP -j REJECT"));
        result.add(new Rule(true, false, "WN_DOT6_TCP",
                "-p tcp --dport 853 -m comment --comment WN_DOT6_TCP -j REJECT"));
        result.add(new Rule(true, false, "WN_DOQ6_APP",
                "-p udp --dport 853 -m owner ! --uid-owner 0 -m comment --comment WN_DOQ6_APP -j REJECT"));
        return Collections.unmodifiableList(result);
    }

    static String serializedIntent() { return LEDGER; }

    static boolean validIntent(String value) { return LEDGER.equals(value); }
}
