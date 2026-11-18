package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Pure, non-executing prototype of per-Android-app UID policy-based routing.
 *
 * Distinct full IPv4+IPv6 WireGuard exits are isolated in separate routing
 * tables; only explicitly selected package UIDs would be steered to one.
 *
 * CRITICAL: A valid plan is NOT an enforceable policy. Correct Android DNS
 * attribution, fwmark/protectedFromVpn bypass prevention, tunnel-down
 * fail-closed firewall, ownership journal, and kernel rollback have NOT
 * been established. There is deliberately no method to apply this plan.
 */
final class RootPerAppUidPolicyPlan {
    static final int MIN_USER_APP_UID = 10000;
    static final int MAX_PRIMARY_USER_APP_UID = 99999;
    static final int FIRST_TABLE = 51000;
    static final int FIRST_PRIORITY = 12800;
    static final int LAST_PRIORITY = 12999;
    static final String UNPROTECTED_MARK = "0x0/0x20000";

    static final class App {
        final String packageName;
        final int uid;
        final String tunnelName;

        App(String packageName, int uid, String tunnelName) {
            this.packageName = packageName;
            this.uid = uid;
            this.tunnelName = tunnelName;
        }
    }

    static final class Route {
        final int family;
        final String destination;
        final String device;
        final int table;

        Route(int family, String destination, String device, int table) {
            this.family = family;
            this.destination = destination;
            this.device = device;
            this.table = table;
        }

        // Not called by a shell runner. Printed in review only.
        String preview() {
            return "IPv" + family + " " + destination + " → " + device
                    + " (private table " + table + ")";
        }
    }

    static final class PerAppRule {
        final int uid;
        final String packageName;
        final String tunnelName;
        final String device;
        final int table;
        final int lookupPriority;
        final int blockPriority;
        final int transport; // 0 = any TCP/UDP; otherwise IPPROTO_TCP/UDP
        final int destinationPort; // 0 = any; only meaningful with transport

        PerAppRule(int uid, String pkg, String tunnel, String device, int table,
                int lookup, int block, int transport, int destinationPort) {
            this.uid = uid;
            this.packageName = pkg;
            this.tunnelName = tunnel;
            this.device = device;
            this.table = table;
            this.lookupPriority = lookup;
            this.blockPriority = block;
            this.transport = transport;
            this.destinationPort = destinationPort;
        }

        String preview() {
            String selector = transport == 0 ? "all app traffic"
                    : (transport == RootProtocolRouteDraft.TCP ? "TCP" : "UDP")
                    + (destinationPort == RootProtocolRouteDraft.ANY_PORT
                        ? " all ports" : " port " + destinationPort);
            return packageName + " (UID " + uid + " · " + selector + ") → " + tunnelName
                    + " [" + device + "] · IPv4+IPv6 lookup pref "
                    + lookupPriority + " followed by unreachable pref "
                    + blockPriority + " if its table has no route";
        }
    }

    static final class Plan {
        final String defaultExit;
        final List<Route> routes;
        final List<PerAppRule> rules;
        final List<String> blockers;

        Plan(String defaultExit, List<Route> routes, List<PerAppRule> rules) {
            this.defaultExit = defaultExit;
            this.routes = Collections.unmodifiableList(new ArrayList<>(routes));
            this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
            this.blockers = Collections.unmodifiableList(java.util.Arrays.asList(
                    "Application DNS requests cannot yet be attributed to their exit.",
                    "Android protectedFromVpn fwmarks and private DNS bypasses are unverified.",
                    "TCP/UDP destination-port matching is not proven on real Android sockets.",
                    "Global transport rules cannot be safely attributed to all apps/system UIDs yet.",
                    "A tunnel-down firewall and exact-owned rollback ledger are missing.",
                    "A verified root multi-exit lifecycle and packet-leak test are pending."));
        }

        /** No caller may treat this plan as permission to mutate the kernel. */
        boolean activationAllowed() { return false; }

        String summary() {
            StringBuilder out = new StringBuilder();
            out.append("DRY-RUN ONLY — NO PER-APP ROUTING INSTALLED\n");
            out.append("Device-wide default: ").append(defaultExit).append('\n');
            out.append("Proposed app-specific UID routes: ").append(rules.size()).append('\n');
            for (PerAppRule rule : rules) out.append(rule.preview()).append('\n');
            out.append("\nActivation blocked until:\n");
            for (String b : blockers) out.append("• ").append(b).append('\n');
            return out.toString();
        }
    }

    private RootPerAppUidPolicyPlan() { }

    static Plan prepare(String defaultExitName, List<RootMultiTunnelPlan.Entry> tunnels,
            List<App> requestedApps) {
        return prepare(defaultExitName, tunnels, requestedApps, Collections.emptyList());
    }

    /**
     * READ-ONLY app UID + TCP/UDP + destination-port rule planner.
     * Exact-port rules are proposed ahead of transport-wide rules, and both
     * precede the category's app fallback. Each matching lookup is followed
     * by a terminal block in case the selected exit has no route, preventing
     * fallback to Android's ordinary default in the hypothetical policy.
     *
     * No command executor calls this method; no live enforcement exists.
     */
    static Plan prepare(String defaultExitName, List<RootMultiTunnelPlan.Entry> tunnels,
            List<App> requestedApps, List<RootProtocolRouteDraft.Override> overrides) {
        return prepare(defaultExitName, tunnels, requestedApps, overrides,
                Collections.emptyList(), Collections.emptyMap());
    }

    /**
     * Protocol routing precedence in this proposed policy:
     *   explicit app transport + port / app transport-wide
     *   > global protocol/port → app-use category
     *   > ordinary category assigned to this app.
     * Every global category MUST resolve to a configured dual-stack Internet
     * exit (never silently fall back). Still a non-enforcing draft.
     */
    static Plan prepare(String defaultExitName, List<RootMultiTunnelPlan.Entry> tunnels,
            List<App> requestedApps, List<RootProtocolRouteDraft.Override> overrides,
            List<RootCategoryProtocolRule.Rule> globalRules,
            Map<Integer, String> categoryExits) {
        List<RootProtocolRouteDraft.Override> validatedOverrides =
                RootProtocolRouteDraft.validateAndSort(overrides);
        List<RootCategoryProtocolRule.Rule> validatedGlobal =
                RootCategoryProtocolRule.validateAndSort(globalRules);
        if (categoryExits == null) {
            throw new IllegalArgumentException("Category target mapping missing.");
        }
        if (tunnels == null || tunnels.isEmpty()
                || tunnels.size() > RootMultiTunnelPlan.MAX_TUNNELS) {
            throw new IllegalArgumentException("Select 1–8 saved WireGuard tunnels.");
        }
        if (defaultExitName == null || defaultExitName.isEmpty()) {
            throw new IllegalArgumentException("Choose the device-wide Internet exit first.");
        }
        if (requestedApps == null || requestedApps.isEmpty() || requestedApps.size() > 100) {
            throw new IllegalArgumentException("Choose 1–100 explicitly assigned apps.");
        }
        Map<String, RootMultiTunnelPlan.Entry> byName = new HashMap<>();
        Set<String> devices = new HashSet<>();
        for (RootMultiTunnelPlan.Entry tunnel : tunnels) {
            // Reuse the existing numeric AllowedIPs/interface-address parser
            // on one entry at a time; its cross-exit two-default check is
            // intentionally NOT applicable to independent per-UID tables.
            RootMultiTunnelPlan.validate(Collections.singletonList(tunnel));
            if (byName.put(tunnel.name, tunnel) != null
                    || !devices.add(tunnel.device)) {
                throw new IllegalArgumentException("Duplicate tunnel identities.");
            }
            boolean v4 = tunnel.peerRoutes.contains("0.0.0.0/0");
            boolean v6 = tunnel.peerRoutes.contains("::/0")
                    || tunnel.peerRoutes.contains("0:0:0:0:0:0:0:0/0");
            if (v4 != v6) {
                throw new IllegalArgumentException("Every selected Internet exit "
                        + "must include both IPv4 and IPv6 default routes.");
            }
        }
        RootMultiTunnelPlan.Entry defaultTunnel = byName.get(defaultExitName);
        if (defaultTunnel == null || !fullDualStack(defaultTunnel)) {
            throw new IllegalArgumentException("Default exit needs dual-stack "
                    + "IPv4 and IPv6 WireGuard routes.");
        }
        // Never silently alter the encrypted or live WireGuard profiles.
        List<RootMultiTunnelPlan.Entry> ordered = new ArrayList<>(tunnels);
        ordered.sort(Comparator.comparing(e -> e.name.toLowerCase(Locale.ROOT)));
        Map<String, Integer> tables = new LinkedHashMap<>();
        List<Route> plannedRoutes = new ArrayList<>();
        for (RootMultiTunnelPlan.Entry e : ordered) {
            int table = FIRST_TABLE + tables.size();
            tables.put(e.name, table);
            for (String cidr : e.peerRoutes) {
                int family = cidr.contains(":") ? 6 : 4;
                plannedRoutes.add(new Route(family, cidr, e.device, table));
            }
        }
        List<App> orderedApps = new ArrayList<>(requestedApps);
        orderedApps.sort(Comparator.comparingInt((App a) -> a.uid)
                .thenComparing(a -> a.packageName));
        Set<Integer> usedUids = new HashSet<>();
        Set<String> usedPackages = new HashSet<>();
        List<PerAppRule> appRules = new ArrayList<>();
        for (App app : orderedApps) {
            if (!AppUseCategories.validPackageName(app.packageName)
                    || app.uid < MIN_USER_APP_UID
                    || app.uid > MAX_PRIMARY_USER_APP_UID) {
                throw new IllegalArgumentException("App UID is not a supported "
                        + "primary-user application UID.");
            }
            if (!usedUids.add(app.uid) || !usedPackages.add(app.packageName)) {
                throw new IllegalArgumentException("Shared or duplicate app UIDs "
                        + "must not be routed independently.");
            }
            RootMultiTunnelPlan.Entry target = byName.get(app.tunnelName);
            if (target == null) {
                throw new IllegalArgumentException("An assigned tunnel is missing.");
            }
            if (!fullDualStack(target)) {
                throw new IllegalArgumentException("Per-app default tunnel must "
                        + "have IPv4 and IPv6 Internet routes. A Home/private "
                        + "split tunnel requires destination-specific rules, "
                        + "not all-traffic UID routing.");
            }

            // A packet's exact destination port rule takes precedence over a
            // generic TCP/UDP rule, then the app's category default. No
            // protocol/port means "any traffic from this package UID".
            for (RootProtocolRouteDraft.Override override : validatedOverrides) {
                if (!app.packageName.equals(override.packageName)) continue;
                RootMultiTunnelPlan.Entry protocolTarget = byName.get(override.tunnelName);
                if (protocolTarget == null || !fullDualStack(protocolTarget)) {
                    throw new IllegalArgumentException("Protocol override target "
                            + "needs a saved dual-stack Internet tunnel. "
                            + "Home/private destinations require explicit "
                            + "destination routing instead.");
                }
                if (appRules.size() >= (LAST_PRIORITY - FIRST_PRIORITY + 1) / 2) {
                    throw new IllegalArgumentException("Too many routing selectors "
                            + "for the reserved kernel priority range.");
                }
                int pref = FIRST_PRIORITY + 2 * appRules.size();
                appRules.add(new PerAppRule(app.uid, app.packageName,
                        protocolTarget.name, protocolTarget.device,
                        tables.get(protocolTarget.name), pref, pref + 1,
                        override.transport, override.destinationPort));
            }
            // Global transport/port selectors override the app's ordinary
            // category, but not the app's explicit transport overrides.
            for (RootCategoryProtocolRule.Rule global : validatedGlobal) {
                String globalExitName = categoryExits.get(global.category);
                if (globalExitName == null || globalExitName.isEmpty()) {
                    throw new IllegalArgumentException("A global protocol "
                            + "category has no configured tunnel.");
                }
                RootMultiTunnelPlan.Entry globalExit = byName.get(globalExitName);
                if (globalExit == null || !fullDualStack(globalExit)) {
                    throw new IllegalArgumentException("Global protocol category "
                            + "must resolve to a saved dual-stack Internet exit.");
                }
                if (appRules.size() >= (LAST_PRIORITY - FIRST_PRIORITY + 1) / 2) {
                    throw new IllegalArgumentException("Too many routing selectors.");
                }
                int pref = FIRST_PRIORITY + 2 * appRules.size();
                appRules.add(new PerAppRule(app.uid, app.packageName,
                        globalExit.name, globalExit.device,
                        tables.get(globalExit.name), pref, pref + 1,
                        global.transport, global.destinationPort));
            }
            if (appRules.size() >= (LAST_PRIORITY - FIRST_PRIORITY + 1) / 2) {
                throw new IllegalArgumentException("Too many routing selectors "
                        + "for the reserved kernel priority range.");
            }
            int pref = FIRST_PRIORITY + 2 * appRules.size();
            appRules.add(new PerAppRule(app.uid, app.packageName, target.name,
                    target.device, tables.get(target.name), pref, pref + 1, 0, 0));
        }
        for (RootProtocolRouteDraft.Override rule : validatedOverrides) {
            if (!usedPackages.contains(rule.packageName)) {
                throw new IllegalArgumentException("Protocol override references "
                        + "an app that has no explicit category assignment.");
            }
        }
        return new Plan(defaultExitName, plannedRoutes, appRules);
    }

    private static boolean fullDualStack(RootMultiTunnelPlan.Entry entry) {
        return entry.peerRoutes.contains("0.0.0.0/0")
                && (entry.peerRoutes.contains("::/0")
                    || entry.peerRoutes.contains("0:0:0:0:0:0:0:0/0"));
    }
}
