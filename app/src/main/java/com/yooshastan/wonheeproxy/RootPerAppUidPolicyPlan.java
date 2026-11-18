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

        PerAppRule(int uid, String pkg, String tunnel, String device, int table,
                int lookup, int block) {
            this.uid = uid;
            this.packageName = pkg;
            this.tunnelName = tunnel;
            this.device = device;
            this.table = table;
            this.lookupPriority = lookup;
            this.blockPriority = block;
        }

        String preview() {
            return packageName + " (UID " + uid + ") → " + tunnelName
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
            if (appRules.size() >= (LAST_PRIORITY - FIRST_PRIORITY + 1) / 2) {
                throw new IllegalArgumentException("Too many per-app routing rules.");
            }
            int pref = FIRST_PRIORITY + 2 * appRules.size();
            appRules.add(new PerAppRule(app.uid, app.packageName, target.name,
                    target.device, tables.get(target.name), pref, pref + 1));
        }
        return new Plan(defaultExitName, plannedRoutes, appRules);
    }

    private static boolean fullDualStack(RootMultiTunnelPlan.Entry entry) {
        return entry.peerRoutes.contains("0.0.0.0/0")
                && (entry.peerRoutes.contains("::/0")
                    || entry.peerRoutes.contains("0:0:0:0:0:0:0:0/0"));
    }
}
