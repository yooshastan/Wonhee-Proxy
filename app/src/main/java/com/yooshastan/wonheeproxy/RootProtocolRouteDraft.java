package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Exact L4 transport + destination-port policy metadata.
 *
 * TCP/UDP and the destination port can be identified from packet metadata.
 * HTTPS, browsing, streaming, messaging, QUIC, DoH and DoQ are NOT reliably
 * identified from port numbers. Port 443 may be many different services.
 *
 * This is a pure policy model; no root, app packet inspection or enforcement.
 */
final class RootProtocolRouteDraft {
    static final int TCP = 6;
    static final int UDP = 17;
    static final int ANY_PORT = 0;
    static final int MAX_OVERRIDES_PER_APP = 6;
    static final int MAX_OVERRIDES_TOTAL = 72;

    static final class Override {
        final String packageName;
        final int transport;
        final int destinationPort;
        final String tunnelName;

        Override(String packageName, int transport, int destinationPort,
                String tunnelName) {
            if (!AppUseCategories.validPackageName(packageName)
                    || !supportedTransport(transport) || destinationPort < 0
                    || destinationPort > 65535 || tunnelName == null
                    || tunnelName.isEmpty() || tunnelName.length() > 64) {
                throw new IllegalArgumentException("Invalid transport-based routing rule.");
            }
            this.packageName = packageName;
            this.transport = transport;
            this.destinationPort = destinationPort;
            this.tunnelName = tunnelName;
        }

        String selectorKey() {
            return packageName + ":" + transport + ":" + destinationPort;
        }

        String transportLabel() {
            return transport == TCP ? "TCP" : "UDP";
        }

        String portLabel() {
            return destinationPort == ANY_PORT ? "all ports"
                    : "destination port " + destinationPort;
        }

        String summary() {
            return transportLabel() + " · " + portLabel() + " → " + tunnelName;
        }
    }

    private RootProtocolRouteDraft() { }

    static boolean supportedTransport(int protocol) {
        return protocol == TCP || protocol == UDP;
    }

    static List<Override> validateAndSort(List<Override> rules) {
        if (rules == null || rules.size() > MAX_OVERRIDES_TOTAL) {
            throw new IllegalArgumentException("Too many protocol rules.");
        }
        Set<String> selectors = new HashSet<>();
        java.util.Map<String, Integer> byPackage = new java.util.HashMap<>();
        List<Override> copy = new ArrayList<>();
        for (Override rule : rules) {
            if (rule == null || !selectors.add(rule.selectorKey())) {
                throw new IllegalArgumentException("Duplicate protocol selector.");
            }
            int next = byPackage.containsKey(rule.packageName)
                    ? byPackage.get(rule.packageName) + 1 : 1;
            if (next > MAX_OVERRIDES_PER_APP) {
                throw new IllegalArgumentException("Too many rules for one app.");
            }
            byPackage.put(rule.packageName, next);
            copy.add(rule);
        }
        copy.sort(Comparator.comparing((Override r) -> r.packageName)
                .thenComparingInt(r -> r.transport)
                // Match an exact port before an all-ports transport rule.
                .thenComparingInt(r -> r.destinationPort == ANY_PORT ? 1 : 0)
                .thenComparingInt(r -> r.destinationPort));
        return Collections.unmodifiableList(copy);
    }

    static String matchingTunnel(List<Override> rules, String pkg, int protocol,
            int destinationPort, String fallback) {
        if (!AppUseCategories.validPackageName(pkg)
                || !supportedTransport(protocol)
                || destinationPort < 1 || destinationPort > 65535) {
            return fallback;
        }
        Override generic = null;
        if (rules != null) {
            for (Override rule : rules) {
                if (rule == null || !pkg.equals(rule.packageName)
                        || protocol != rule.transport) continue;
                if (rule.destinationPort == destinationPort) {
                    return rule.tunnelName;
                }
                if (rule.destinationPort == ANY_PORT) generic = rule;
            }
        }
        return generic != null ? generic.tunnelName : fallback;
    }
}
