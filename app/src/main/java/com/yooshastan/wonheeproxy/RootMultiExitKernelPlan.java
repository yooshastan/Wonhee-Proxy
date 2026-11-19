package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Non-executing compiler for independently routed root Internet exits.
 *
 * The existing RootPerAppUidPolicyPlan has already validated the effective
 * WireGuard AllowedIPs, primary-user UIDs and draft rule precedence. This
 * compiler adds independently inspectable IPv4/IPv6 route-table and policy
 * operations with exact inverse commands. Nothing invokes root or shell here.
 *
 * NOT an activation engine: Android kernel support for ipproto/dport, actual
 * PacketManager UID identity, resolver attribution, netd priority ownership,
 * WireGuard endpoint marks and fail-closed enforcement all need live probes.
 */
final class RootMultiExitKernelPlan {
    static final class Step {
        final int family;
        final String install;
        final String rollback;
        final String kind;

        Step(int family, String install, String rollback, String kind) {
            this.family = family;
            this.install = install;
            this.rollback = rollback;
            this.kind = kind;
        }
    }

    static final class Result {
        final List<Step> routes;
        final List<Step> policy;
        final int ipv4Rules;
        final int ipv6Rules;
        final int independentTables;

        Result(List<Step> routes, List<Step> policy, int tables) {
            this.routes = Collections.unmodifiableList(new ArrayList<>(routes));
            this.policy = Collections.unmodifiableList(new ArrayList<>(policy));
            this.independentTables = tables;
            int v4 = 0;
            int v6 = 0;
            for (Step step : policy) {
                if (step.family == 4) v4++;
                else if (step.family == 6) v6++;
            }
            ipv4Rules = v4;
            ipv6Rules = v6;
        }

        /**
         * A future verified stop must undo selectors before deleting the
         * private routes they reference. This is an ordering preview only.
         */
        List<Step> rollbackOrder() {
            List<Step> reversed = new ArrayList<>(policy.size() + routes.size());
            for (int i = policy.size() - 1; i >= 0; i--) {
                reversed.add(policy.get(i));
            }
            for (int i = routes.size() - 1; i >= 0; i--) {
                reversed.add(routes.get(i));
            }
            return Collections.unmodifiableList(reversed);
        }

        /** A dry-run compile can NEVER be passed to a root executor. */
        boolean activationAllowed() { return false; }

        String summary() {
            return "DRY-RUN MULTI-EXIT KERNEL POLICY — NOT CONNECTED: "
                    + independentTables + " independent route tables, "
                    + routes.size() + " route additions and "
                    + policy.size() + " lookup/block policy additions. "
                    + "No WireGuard interfaces, routes, firewall rules or DNS "
                    + "policies were changed.";
        }
    }

    private RootMultiExitKernelPlan() { }

    /**
     * Produce commands for review only. No callers may execute these steps.
     * The ordered plan uses adjacent lookup+unreachable priorities so an exit
     * with a missing route cannot accidentally fall through to another VPN
     * or to Android's unprotected physical network.
     */
    static Result compile(RootPerAppUidPolicyPlan.Plan proposed) {
        if (proposed == null || proposed.routes == null || proposed.rules == null
                || proposed.routes.isEmpty() || proposed.rules.isEmpty()) {
            throw new IllegalArgumentException("Incomplete multi-exit plan.");
        }
        if (proposed.activationAllowed()) {
            throw new IllegalArgumentException("Only non-activating plans may be compiled.");
        }
        List<Step> routes = new ArrayList<>();
        List<Step> policies = new ArrayList<>();
        Map<Integer, String> owner = new HashMap<>();
        Map<String, Integer> deviceOwners = new HashMap<>();
        Set<String> distinctRoutes = new HashSet<>();
        Set<Integer> v4Tables = new HashSet<>();
        Set<Integer> v6Tables = new HashSet<>();
        for (RootPerAppUidPolicyPlan.Route route : proposed.routes) {
            if (route == null || (route.family != 4 && route.family != 6)
                    || !safeDevice(route.device) || !tableValid(route.table)
                    || !numericCidr(route.destination, route.family)) {
                throw new IllegalArgumentException("Unsafe independent exit route.");
            }
            String previous = owner.putIfAbsent(route.table, route.device);
            if (previous != null && !previous.equals(route.device)) {
                throw new IllegalArgumentException("A private table has two owners.");
            }
            Integer priorTable = deviceOwners.putIfAbsent(route.device, route.table);
            if (priorTable != null && priorTable != route.table) {
                throw new IllegalArgumentException("A tunnel cannot own two private exit tables.");
            }
            String identity = route.family + "|" + route.table + "|" + route.destination;
            if (!distinctRoutes.add(identity)) {
                throw new IllegalArgumentException("Duplicate private-table route.");
            }
            if (route.family == 4 && "0.0.0.0/0".equals(route.destination)
                    && !v4Tables.add(route.table)) {
                throw new IllegalArgumentException("Duplicate IPv4 default in a private table.");
            }
            if (route.family == 6 && ("::/0".equals(route.destination)
                    || "0:0:0:0:0:0:0:0/0".equals(route.destination))
                    && !v6Tables.add(route.table)) {
                throw new IllegalArgumentException("Duplicate IPv6 default in a private table.");
            }
            String command = "ip -" + route.family + " route";
            String suffix = "table " + route.table + " " + route.destination
                    + " dev " + route.device;
            routes.add(new Step(route.family, command + " add " + suffix,
                    command + " del " + suffix, "ROUTE"));
        }
        Set<Integer> priorities = new HashSet<>();
        for (RootPerAppUidPolicyPlan.PerAppRule rule : proposed.rules) {
            if (rule == null || rule.uid < RootPerAppUidPolicyPlan.MIN_USER_APP_UID
                    || rule.uid > RootPerAppUidPolicyPlan.MAX_PRIMARY_USER_APP_UID
                    || !safeDevice(rule.device) || !tableValid(rule.table)
                    || !rule.device.equals(owner.get(rule.table))
                    || rule.lookupPriority < RootPerAppUidPolicyPlan.FIRST_PRIORITY
                    || rule.blockPriority > RootPerAppUidPolicyPlan.LAST_PRIORITY
                    || rule.blockPriority != rule.lookupPriority + 1
                    || !priorities.add(rule.lookupPriority)
                    || !priorities.add(rule.blockPriority)
                    || (rule.transport != 0 && rule.transport != RootProtocolRouteDraft.TCP
                        && rule.transport != RootProtocolRouteDraft.UDP)
                    || rule.destinationPort < 0 || rule.destinationPort > 65535
                    || (rule.transport == 0 && rule.destinationPort != 0)
                    || !v4Tables.contains(rule.table)
                    || !v6Tables.contains(rule.table)) {
                throw new IllegalArgumentException("Unsafe per-app policy selector.");
            }
            String selector = " fwmark 0x0/0x20000 iif lo uidrange "
                    + rule.uid + "-" + rule.uid;
            if (rule.transport != 0) {
                selector += " ipproto " + rule.transport;
                if (rule.destinationPort != 0) {
                    selector += " dport " + rule.destinationPort;
                }
            }
            for (int family : new int[]{4, 6}) {
                String prefix = "ip -" + family + " rule";
                String lookup = "pref " + rule.lookupPriority + selector
                        + " lookup " + rule.table;
                String block = "pref " + rule.blockPriority + selector
                        + " unreachable";
                policies.add(new Step(family, prefix + " add " + lookup,
                        prefix + " del " + lookup, "LOOKUP"));
                policies.add(new Step(family, prefix + " add " + block,
                        prefix + " del " + block, "BLOCK"));
            }
        }
        if (owner.size() > RootMultiTunnelPlan.MAX_TUNNELS) {
            throw new IllegalArgumentException("Too many exit tables.");
        }
        return new Result(routes, policies, owner.size());
    }

    private static boolean safeDevice(String value) {
        return value != null && value.matches("wnm[0-9a-f]{12}");
    }

    private static boolean tableValid(int value) {
        return value >= RootPerAppUidPolicyPlan.FIRST_TABLE
                && value < RootPerAppUidPolicyPlan.FIRST_TABLE
                        + RootMultiTunnelPlan.MAX_TUNNELS;
    }

    private static boolean numericCidr(String cidr, int family) {
        if (cidr == null) return false;
        String[] parts = cidr.split("/", -1);
        if (parts.length != 2 || !parts[1].matches("[0-9]{1,3}")) return false;
        String ip = parts[0];
        if (family == 4) {
            if (!ip.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
            for (String octet : ip.split("\\.")) {
                if (Integer.parseInt(octet) > 255) return false;
            }
        }
        if (family == 6 && (!ip.contains(":") || !ip.matches("[0-9a-fA-F:.]+"))) {
            return false;
        }
        try {
            byte[] raw = java.net.InetAddress.getByName(ip).getAddress();
            int bits = Integer.parseInt(parts[1]);
            return raw.length == (family == 4 ? 4 : 16)
                    && bits >= 0 && bits <= raw.length * 8;
        } catch (Exception invalid) {
            return false;
        }
    }
}
