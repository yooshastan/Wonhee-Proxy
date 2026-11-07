package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Batch F.3a OFFLINE policy-contract matrix.
 *
 * Pure simulation: no RootShell, iptables, networking, files, DNS or Android APIs.
 * RETURN means only that this one modeled Wonhee-owned chain returns; it does
 * not imply that another firewall owner, kernel routing or the Internet accepts
 * a packet. This matrix is intentionally incapable of authorizing activation.
 */
final class RootGuardF3PolicyMatrix {
    private RootGuardF3PolicyMatrix() { }

    static final class Assessment {
        private final List<String> checks = new ArrayList<>();
        private final List<String> failures = new ArrayList<>();
        private final List<String> blockers = new ArrayList<>();

        private void expect(String name, RootFailClosedFirewallPlan.Plan plan,
                RootGuardFlowModel.Flow flow, RootGuardFlowModel.Result expected) {
            RootGuardFlowModel.Result actual = RootGuardFlowModel.evaluate(plan, flow);
            checks.add(name);
            if (actual != expected) {
                failures.add(name + " — modeled " + actual + ", expected " + expected);
            }
        }

        private void require(boolean condition, String check) {
            checks.add(check);
            if (!condition) failures.add(check + " — FAILED");
        }

        int checkCount() { return checks.size(); }
        int failureCount() { return failures.size(); }
        int blockerCount() { return blockers.size(); }
        boolean modelChecksPass() { return failures.isEmpty(); }
        boolean activationAllowed() { return false; }

        String report() {
            StringBuilder out = new StringBuilder("BATCH F.3a — OFFLINE POLICY CONTRACT\n")
                    .append("Modeled checks: ")
                    .append(checks.size() - failures.size())
                    .append('/').append(checks.size())
                    .append(failures.isEmpty() ? " (expected)" : " (DISCREPANCY)")
                    .append('\n');
            for (String failure : failures) out.append("CHECK REQUIRED: ").append(failure).append('\n');
            for (String blocker : blockers) out.append("UNRESOLVED: ").append(blocker).append('\n');
            return out.append("ACTIVATION: BLOCKED. Simulated rule matches do not prove ")
                    .append("Android OUTPUT path, socket provenance, current underlay, ")
                    .append("endpoint rotation, DNS, leak prevention or rollback.")
                    .toString();
        }
    }

    private static RootGuardFlowModel.Flow flow(int family, String dest, String out,
            String proto, int port, long mark) {
        return new RootGuardFlowModel.Flow(family, dest, out, proto, port, mark);
    }

    private static String unusedEndpoint(int family, Set<String> known) {
        String[] choices = family == 4
                ? new String[]{"192.0.2.250", "198.51.100.250", "203.0.113.250"}
                : new String[]{"2001:db8:ffff::250", "2001:db8:ffff::251"};
        for (String choice : choices) if (!known.contains(choice)) return choice;
        throw new IllegalArgumentException("Cannot choose synthetic rotated endpoint.");
    }

    /**
     * HOME and INTERNET must be the *selected*, verified device names, not
     * arbitrary interfaces. Even with a perfect simulation, actual socket
     * identity and underlay continuity remain unproved, so activation stays OFF.
     */
    static Assessment inspect(RootFailClosedFirewallPlan.Plan actual,
            List<RootFailClosedFirewallPlan.Tunnel> tunnels,
            String home, String internet, String underlay) {
        if (actual == null || tunnels == null || tunnels.size() != 2
                || home == null || internet == null || home.equals(internet)
                || !home.matches("wnm[0-9a-f]{12}")
                || !internet.matches("wnm[0-9a-f]{12}")
                || underlay == null
                || !underlay.matches("(wlan|rmnet|eth|usb|clat)[A-Za-z0-9_.-]*")) {
            throw new IllegalArgumentException("Verified dual-tunnel/underlay inputs required.");
        }

        Assessment a = new Assessment();
        RootFailClosedFirewallPlan.Plan expected = RootFailClosedFirewallPlan.build(tunnels);
        a.require(actual.encode().equals(expected.encode()),
                "Exact current owned plan layout and order");

        Set<String> devices = new HashSet<>();
        Set<String> endpoints = new HashSet<>();
        Set<Long> marks = new HashSet<>();
        RootFailClosedFirewallPlan.Tunnel homeTunnel = null;
        RootFailClosedFirewallPlan.Tunnel internetTunnel = null;
        for (RootFailClosedFirewallPlan.Tunnel tunnel : tunnels) {
            devices.add(tunnel.device);
            endpoints.add(tunnel.address);
            marks.add(tunnel.mark);
            if (home.equals(tunnel.device)) homeTunnel = tunnel;
            if (internet.equals(tunnel.device)) internetTunnel = tunnel;
        }
        a.require(devices.size() == 2 && homeTunnel != null && internetTunnel != null,
                "Two independent selected tunnel interfaces");
        if (homeTunnel == null || internetTunnel == null) {
            a.blockers.add("Selected HOME/Internet mapping is inconsistent.");
            return a;
        }
        a.require(homeTunnel.allowedIps.contains("10.0.0.0/24"),
                "HOME private destination plan is present");
        a.require(internetTunnel.allowedIps.contains("0.0.0.0/0")
                        && internetTunnel.allowedIps.contains("::/0"),
                "Internet dual-stack defaults are present");

        for (int family : new int[]{4, 6}) {
            a.require(actual.family(family).size() > 0
                            && "-j REJECT".equals(actual.family(family)
                                .get(actual.family(family).size() - 1).args),
                    "IPv" + family + " terminal reject remains final");
        }

        a.expect("HOME private HTTP over HOME tunnel", actual,
                flow(4, "10.0.0.169", home, "tcp", 4533, 0),
                RootGuardFlowModel.Result.RETURN);
        a.expect("HOME private destination rejected over Internet tunnel", actual,
                flow(4, "10.0.0.169", internet, "tcp", 4533, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("HOME private destination rejected directly", actual,
                flow(4, "10.0.0.169", underlay, "tcp", 4533, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Public IPv4 HTTPS through Internet tunnel", actual,
                flow(4, "1.1.1.1", internet, "tcp", 443, 0),
                RootGuardFlowModel.Result.RETURN);
        a.expect("Public IPv6 HTTPS through Internet tunnel", actual,
                flow(6, "2606:4700:4700::1111", internet, "tcp", 443, 0),
                RootGuardFlowModel.Result.RETURN);
        a.expect("Public IPv4 HTTPS directly rejected", actual,
                flow(4, "1.1.1.1", underlay, "tcp", 443, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Public IPv6 HTTPS directly rejected", actual,
                flow(6, "2606:4700:4700::1111", underlay, "tcp", 443, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Physical UDP DNS rejected", actual,
                flow(4, "1.1.1.1", underlay, "udp", 53, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Physical TCP DNS rejected", actual,
                flow(4, "1.1.1.1", underlay, "tcp", 53, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Physical DHCPv4 candidate rejected", actual,
                flow(4, "255.255.255.255", underlay, "udp", 67, 0),
                RootGuardFlowModel.Result.REJECT);
        a.expect("Physical IPv6 router solicitation candidate rejected", actual,
                flow(6, "ff02::2", underlay, "icmpv6", 0, 0),
                RootGuardFlowModel.Result.REJECT);

        for (RootFailClosedFirewallPlan.Tunnel t : tunnels) {
            int family = t.address.contains(":") ? 6 : 4;
            String otherUnderlay = underlay.equals("wlan0") ? "rmnet16" : "wlan0";
            String rotated = unusedEndpoint(family, endpoints);
            int wrongPort = t.port == 65535 ? t.port - 1 : t.port + 1;
            a.expect("Exact IPv" + family + " marked UDP endpoint exception", actual,
                    flow(family, t.address, underlay, "udp", t.port, t.mark),
                    RootGuardFlowModel.Result.RETURN);
            a.expect("Missing WireGuard UDP mark blocked", actual,
                    flow(family, t.address, underlay, "udp", t.port, 0),
                    RootGuardFlowModel.Result.REJECT);
            a.expect("Changed UDP port blocked", actual,
                    flow(family, t.address, underlay, "udp", wrongPort, t.mark),
                    RootGuardFlowModel.Result.REJECT);
            a.expect("Unplanned numeric endpoint blocked", actual,
                    flow(family, rotated, underlay, "udp", t.port, t.mark),
                    RootGuardFlowModel.Result.REJECT);
            a.expect("Existing exception is not physical-interface scoped", actual,
                    flow(family, t.address, otherUnderlay, "udp", t.port, t.mark),
                    RootGuardFlowModel.Result.RETURN);
        }

        if (marks.size() != tunnels.size()) {
            a.blockers.add("WireGuard transport mark shared by selected tunnels; "
                    + "fwmark cannot authenticate the selected socket.");
        }
        // The current modeled rule grammar only sees destination/port/mark,
        // so it cannot tell two same-attribute sockets apart even with unique marks.
        a.blockers.add("Exact marked UDP endpoint exceptions have no verified "
                + "kernel socket provenance, owner binding or interface binding.");
        a.blockers.add("Android underlay control-plane traffic classification and "
                + "handoff/endpoint-rotation continuity lack observed evidence.");
        a.blockers.add("Independent recovery and live dual-stack fail-closed "
                + "packet tests have not passed. No firewall activation authorized.");
        return a;
    }
}
