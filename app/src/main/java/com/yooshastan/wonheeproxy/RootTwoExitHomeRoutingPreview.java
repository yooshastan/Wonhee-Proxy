package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Offline-only routing contract for a third Home split tunnel alongside the
 * two proven full-Internet WireGuard exits. This is NOT a kernel executor.
 *
 * A Home destination selector would need to run BEFORE app UID-exit rules,
 * and a retained unreachable destination in Home's private table must make
 * loss of Home fail closed rather than fall through to an Internet default.
 *
 * No home route, UID rule, firewall, DNS, or WireGuard interface is installed.
 */
final class RootTwoExitHomeRoutingPreview {
    static final int HOME_TABLE = 51002;
    // Reserved before the existing 12800+ per-app UID selection priorities;
    // exact collisions and actual Android/netd behavior still need testing.
    static final int HOME_PRIORITY = 12700;

    static final class Plan {
        final RootIsolatedWireGuardBootstrapPlan.Plan internetLinks;
        final RootMultiTunnelPlan.Entry home;
        final List<String> homeDestinations;
        final int homeTable;
        final int homePriority;

        Plan(RootIsolatedWireGuardBootstrapPlan.Plan internetLinks,
                RootMultiTunnelPlan.Entry home, List<String> homeDestinations) {
            this.internetLinks = internetLinks;
            this.home = home;
            this.homeDestinations = Collections.unmodifiableList(
                    new ArrayList<>(homeDestinations));
            homeTable = HOME_TABLE;
            homePriority = HOME_PRIORITY;
        }

        boolean activationAllowed() { return false; }

        String summary() {
            return "OFFLINE TWO-INTERNET + HOME SPLIT PLAN — NOT ACTIVE: "
                    + "two independently verified Internet peers are required, "
                    + homeDestinations.size()
                    + " private Home destination(s) assigned a separate table. "
                    + "Home destination lookup must precede per-app Internet "
                    + "exit selection, and loss of Home must block instead "
                    + "of falling back. No Android routes, UID rules, "
                    + "WireGuard links or DNS changes were made.";
        }
    }

    private RootTwoExitHomeRoutingPreview() { }

    static Plan compile(List<RootMultiTunnelPlan.Entry> internetPeers,
            RootMultiTunnelPlan.Entry home) {
        if (internetPeers == null || internetPeers.size() != 2 || home == null) {
            throw new IllegalArgumentException(
                    "Exactly two Internet exits and one Home profile required.");
        }
        // Reuse the tested two-peer planner, but NEVER activate its output.
        RootIsolatedWireGuardBootstrapPlan.Plan internet =
                RootIsolatedTwoPeerLinkPlan.compile(internetPeers);
        List<RootMultiTunnelPlan.Entry> all = new ArrayList<>(internetPeers);
        all.add(home);
        RootMultiTunnelPlan.validateIndependentInterfaceAddresses(all);
        RootMultiTunnelPlan.validate(Collections.singletonList(home));

        Set<String> allowed = new HashSet<>();
        for (String destination : home.peerRoutes) {
            // First Home pilot is deliberately IPv4 RFC1918 LAN access only.
            // Never accept a /0 Internet exit or an arbitrary public prefix.
            // IPv6 ULA and the destination-specific dual-stack block are
            // separate release gates; no family may silently fall back.
            if (!privateLanNetwork(destination) || !allowed.add(destination)) {
                throw new IllegalArgumentException(
                        "Home requires distinct private IPv4 LAN subnets "
                        + "without an Internet default or overlapping prefixes.");
            }
        }
        List<String> ordered = new ArrayList<>(allowed);
        Collections.sort(ordered);
        for (int i = 0; i < ordered.size(); i++) {
            for (int j = i + 1; j < ordered.size(); j++) {
                if (overlap(ordered.get(i), ordered.get(j))) {
                    throw new IllegalArgumentException(
                            "Overlapping Home destinations require a single explicit route.");
                }
            }
        }
        return new Plan(internet, home, ordered);
    }

    private static boolean privateLanNetwork(String prefix) {
        if (prefix == null || prefix.length() > 32
                || !prefix.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}")) {
            return false;
        }
        String[] p = prefix.split("/", -1);
        try {
            byte[] raw = InetAddress.getByName(p[0]).getAddress();
            if (raw.length != 4) return false;
            int length = Integer.parseInt(p[1]);
            // Keep the first pilot narrow. Broad /8 /12 /16 destinations
            // could accidentally capture other private network traffic.
            if (length < 24 || length > 32) return false;
            int ip = 0;
            for (byte b : raw) ip = (ip << 8) | (b & 0xff);
            int mask = length == 32 ? -1 : -1 << (32 - length);
            if ((ip & mask) != ip) return false;
            int a = raw[0] & 0xff, b = raw[1] & 0xff;
            return a == 10
                    || (a == 172 && b >= 16 && b <= 31)
                    || (a == 192 && b == 168);
        } catch (Exception invalid) {
            return false;
        }
    }

    private static boolean overlap(String left, String right) {
        int maskA = Integer.parseInt(left.substring(left.indexOf('/') + 1));
        int maskB = Integer.parseInt(right.substring(right.indexOf('/') + 1));
        int bits = Math.min(maskA, maskB);
        try {
            byte[] a = InetAddress.getByName(left.substring(0, left.indexOf('/')))
                    .getAddress();
            byte[] b = InetAddress.getByName(right.substring(0, right.indexOf('/')))
                    .getAddress();
            for (int bit = 0; bit < bits; bit++) {
                int byteIndex = bit / 8;
                int bitMask = 0x80 >>> (bit % 8);
                if ((a[byteIndex] & bitMask) != (b[byteIndex] & bitMask)) {
                    return false;
                }
            }
            return true;
        } catch (Exception invalid) {
            // Unreachable after privateLanNetwork, but reject on uncertainty.
            throw new IllegalArgumentException("Unverifiable Home network.");
        }
    }
}
