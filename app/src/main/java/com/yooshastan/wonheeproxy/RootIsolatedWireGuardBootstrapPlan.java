package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Non-executing blueprint for kernel WireGuard interfaces without wg-quick.
 *
 * wg-quick may install an overlapping default route in Android's ordinary
 * routing policy. This blueprint instead keeps all peer routes in distinct
 * private tables derived from RootPerAppUidPolicyPlan. It NEVER invokes a
 * shell, loads private keys, changes Android DNS, or enables an interface.
 *
 * A separate implementation MUST authenticate the ownership ledger, load
 * secrets from an app-private file descriptor (not a shell command), prove
 * WireGuard endpoint UDP escapes through the physical underlay, and verify
 * netd/fail-closed behavior before running any kernel operation.
 */
final class RootIsolatedWireGuardBootstrapPlan {
    static final class Step {
        final String kind;
        final String install;
        final String inverse;
        final String device;

        Step(String kind, String install, String inverse, String device) {
            this.kind = kind;
            this.install = install;
            this.inverse = inverse;
            this.device = device;
        }

        boolean requiresSecretHandoff() { return "PEER_CONFIG".equals(kind); }
    }

    static final class Plan {
        final List<Step> steps;
        final int devices;
        final int privateRoutes;

        Plan(List<Step> steps, int devices, int privateRoutes) {
            this.steps = Collections.unmodifiableList(new ArrayList<>(steps));
            this.devices = devices;
            this.privateRoutes = privateRoutes;
        }

        List<Step> rollbackOrder() {
            List<Step> reversed = new ArrayList<>(steps);
            Collections.reverse(reversed);
            return Collections.unmodifiableList(reversed);
        }

        /** There is no runnable kernel executor in this milestone. */
        boolean activationAllowed() { return false; }

        String summary() {
            return "ISOLATED WIREGUARD BOOTSTRAP — DRY RUN ONLY: " + devices
                    + " interfaces, " + privateRoutes + " private-table peer "
                    + "routes. No main-table/default-network route, DNS change "
                    + "or WireGuard link was installed. Private-key handoff, "
                    + "kernel ownership, physical UDP underlay, dual-stack "
                    + "fail-closed enforcement and Safe Stop are NOT VERIFIED.";
        }
    }

    private RootIsolatedWireGuardBootstrapPlan() { }

    static Plan compile(List<RootMultiTunnelPlan.Entry> tunnels,
            RootPerAppUidPolicyPlan.Plan uidPlan) {
        if (tunnels == null || tunnels.isEmpty()
                || uidPlan == null || uidPlan.activationAllowed()) {
            throw new IllegalArgumentException("Missing offline tunnel policy.");
        }
        RootMultiTunnelPlan.validateIndependentInterfaceAddresses(tunnels);
        // Require route table and UID ownership to be internally consistent.
        RootMultiExitKernelPlan.compile(uidPlan);
        Map<String, List<RootPerAppUidPolicyPlan.Route>> routesByDevice = new HashMap<>();
        Map<String, Integer> tableByDevice = new HashMap<>();
        for (RootPerAppUidPolicyPlan.Route route : uidPlan.routes) {
            Integer old = tableByDevice.putIfAbsent(route.device, route.table);
            if (old != null && old != route.table) {
                throw new IllegalArgumentException("Device has conflicting private tables.");
            }
            routesByDevice.computeIfAbsent(route.device, unused -> new ArrayList<>())
                    .add(route);
        }
        if (routesByDevice.size() != tunnels.size()) {
            throw new IllegalArgumentException("Selected profiles and table plan disagree.");
        }
        List<RootMultiTunnelPlan.Entry> ordered = new ArrayList<>(tunnels);
        ordered.sort(Comparator.comparing(e -> e.name.toLowerCase(Locale.ROOT)));
        List<Step> steps = new ArrayList<>();
        int routeCount = 0;
        Set<String> seen = new HashSet<>();
        for (RootMultiTunnelPlan.Entry tunnel : ordered) {
            RootMultiTunnelPlan.validate(Collections.singletonList(tunnel));
            String dev = tunnel.device; // SHA-256 derived, IFNAMSIZ-safe.
            if (!dev.matches("wnm[0-9a-f]{12}") || !seen.add(dev)) {
                throw new IllegalArgumentException("Invalid managed WireGuard device.");
            }
            List<RootPerAppUidPolicyPlan.Route> routes = routesByDevice.get(dev);
            Integer table = tableByDevice.get(dev);
            if (routes == null || table == null
                    || routes.size() != tunnel.peerRoutes.size()) {
                throw new IllegalArgumentException("Peer routes do not match private table.");
            }
            Set<String> expected = new HashSet<>(tunnel.peerRoutes);
            if (expected.size() != tunnel.peerRoutes.size()) {
                throw new IllegalArgumentException("Duplicate WireGuard peer route.");
            }
            for (RootPerAppUidPolicyPlan.Route route : routes) {
                if (route.table != table || !expected.remove(route.destination)
                        || route.family != (route.destination.contains(":") ? 6 : 4)) {
                    throw new IllegalArgumentException("Route/table identity mismatch.");
                }
            }
            if (!expected.isEmpty()) {
                throw new IllegalArgumentException("Peer route missing from private table.");
            }

            // The link create/delete commands may only be attempted later
            // under a transaction that owns and verifies this exact interface.
            steps.add(new Step("LINK_CREATE",
                    "ip link add dev " + dev + " type wireguard",
                    "ip link del dev " + dev, dev));
            // No raw keys, endpoints or temporary config paths may enter an
            // ordinary shell plan or diagnostic. Secure peer setup is separate.
            steps.add(new Step("PEER_CONFIG", "", "", dev));
            for (String address : tunnel.interfaceAddresses) {
                int slash = address.lastIndexOf('/');
                if (slash <= 0) {
                    throw new IllegalArgumentException("Invalid interface host address.");
                }
                boolean v6 = address.indexOf(':') >= 0;
                String hostBits = v6 ? "128" : "32";
                if (!address.substring(slash + 1).equals(hostBits)) {
                    // A non-host address could create a connected route in
                    // main, defeating supposedly independent per-exit tables.
                    throw new IllegalArgumentException(
                            "Isolated bootstrap requires /32 or /128 interface hosts.");
                }
                String cmd = "ip -" + (v6 ? "6" : "4") + " addr ";
                String suffix = address + " dev " + dev;
                steps.add(new Step("HOST_ADDRESS",
                        cmd + "add " + suffix, cmd + "del " + suffix, dev));
            }
            steps.add(new Step("LINK_UP",
                    "ip link set dev " + dev + " up",
                    "ip link set dev " + dev + " down", dev));
            for (RootPerAppUidPolicyPlan.Route route : routes) {
                String command = "ip -" + route.family + " route ";
                String args = "table " + table + " " + route.destination
                        + " dev " + dev;
                steps.add(new Step("PRIVATE_ROUTE",
                        command + "add " + args, command + "del " + args, dev));
                routeCount++;
            }
        }
        return new Plan(steps, ordered.size(), routeCount);
    }
}
