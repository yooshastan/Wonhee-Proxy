package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * User-selected global TCP/UDP destination-port rules that point to an
 * APP-USE CATEGORY. Categories then resolve to a saved tunnel profile.
 *
 * Pure draft metadata. NO packet handling, UID filtering, root or networking.
 * These override an app's ordinary category assignment. An explicitly
 * configured per-app TCP/UDP override remains more specific and wins first.
 */
final class RootCategoryProtocolRule {
    static final int MAX_GLOBAL_RULES = 20;

    static final class Rule {
        final int transport;
        final int destinationPort;
        final int category;

        Rule(int transport, int destinationPort, int category) {
            if (!RootProtocolRouteDraft.supportedTransport(transport)
                    || destinationPort < 0 || destinationPort > 65535
                    || !AppUseCategories.valid(category)) {
                throw new IllegalArgumentException("Invalid category protocol rule.");
            }
            this.transport = transport;
            this.destinationPort = destinationPort;
            this.category = category;
        }

        String selector() {
            return transport + ":" + destinationPort;
        }

        String summary() {
            return (transport == RootProtocolRouteDraft.TCP ? "TCP" : "UDP")
                    + (destinationPort == RootProtocolRouteDraft.ANY_PORT
                    ? " · all destination ports" : " · destination port " + destinationPort)
                    + " → " + AppUseCategories.label(category);
        }
    }

    private RootCategoryProtocolRule() { }

    static List<Rule> validateAndSort(List<Rule> rules) {
        if (rules == null || rules.size() > MAX_GLOBAL_RULES) {
            throw new IllegalArgumentException("Too many global protocol rules.");
        }
        Set<String> selectors = new HashSet<>();
        List<Rule> copy = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule == null || !selectors.add(rule.selector())) {
                throw new IllegalArgumentException("Duplicate global protocol selector.");
            }
            copy.add(rule);
        }
        copy.sort(Comparator.comparingInt((Rule r) -> r.transport)
                .thenComparingInt(r -> r.destinationPort == 0 ? 1 : 0)
                .thenComparingInt(r -> r.destinationPort));
        return Collections.unmodifiableList(copy);
    }

    static int matchingCategory(List<Rule> sortedRules, int transport,
            int destinationPort, int ordinaryCategory) {
        int fallback = AppUseCategories.safe(ordinaryCategory);
        if (!RootProtocolRouteDraft.supportedTransport(transport)
                || destinationPort < 1 || destinationPort > 65535) {
            return fallback;
        }
        Rule generic = null;
        if (sortedRules != null) for (Rule rule : sortedRules) {
            if (rule.transport != transport) continue;
            if (rule.destinationPort == destinationPort) return rule.category;
            if (rule.destinationPort == 0) generic = rule;
        }
        return generic == null ? fallback : generic.category;
    }
}
