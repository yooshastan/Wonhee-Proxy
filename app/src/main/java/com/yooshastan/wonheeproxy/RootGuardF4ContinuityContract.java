package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;

/**
 * Batch F.4 design-only continuity contract. Evaluates the CURRENT, paused
 * firewall chain against representative network-control and VPN flows.
 *
 * Not an enforcement policy, a packet tracer, a firewall authorizer or a
 * substitute for on-device socket/provenance evidence. Never calls RootShell.
 */
final class RootGuardF4ContinuityContract {
    private RootGuardF4ContinuityContract() { }

    static final class Assessment {
        private final List<String> mismatches = new ArrayList<>();
        private final List<String> controlRisks = new ArrayList<>();
        private final List<String> unresolved = new ArrayList<>();
        private int modeledChecks;

        int modeledChecks() { return modeledChecks; }
        int mismatchCount() { return mismatches.size(); }
        int controlRiskCount() { return controlRisks.size(); }
        int unresolvedCount() { return unresolved.size(); }

        // Never convert a passing offline simulation into permission to enable
        // the device's root firewall. Batch F remains independently gated.
        boolean activationAllowed() { return false; }

        String report() {
            StringBuilder report = new StringBuilder("BATCH F.4 — OFFLINE UNDERLAY CONTINUITY CONTRACT\n")
                    .append("Current chain model checks: ")
                    .append(modeledChecks - mismatches.size())
                    .append('/').append(modeledChecks).append('\n');
            for (String mismatch : mismatches) {
                report.append("MODEL DISCREPANCY: ").append(mismatch).append('\n');
            }
            for (String risk : controlRisks) {
                report.append("CONTROL-PLANE RISK: ").append(risk).append('\n');
            }
            for (String blocker : unresolved) {
                report.append("UNRESOLVED: ").append(blocker).append('\n');
            }
            return report.append("ACTIVATION: BLOCKED. A physical header or filter/OUTPUT "
                    + "counter increment does not prove the captured packet traversed OUTPUT; "
                    + "the 5-second Pixel capture observed one outgoing ICMPv6 Neighbor "
                    + "Solicitation but did not establish its origin or processing path. "
                    + "No firewall rules, routes, DNS, packets or tunnels changed.").toString();
        }
    }

    private static RootGuardFlowModel.Flow flow(int family, String destination,
            String out, String protocol, int port, long mark) {
        return new RootGuardFlowModel.Flow(
                family, destination, out, protocol, port, mark);
    }

    private static void expect(Assessment a, RootFailClosedFirewallPlan.Plan plan,
            String label, RootGuardFlowModel.Flow flow, RootGuardFlowModel.Result expected) {
        a.modeledChecks++;
        RootGuardFlowModel.Result actual = RootGuardFlowModel.evaluate(plan, flow);
        if (actual != expected) {
            a.mismatches.add(label + ": modeled " + actual + ", expected " + expected);
        }
    }

    /**
     * Observe only synthetically modeled flows across two distinct example
     * physical interfaces; the concrete Android OUTPUT path is not observed.
     * Must be invoked with independently verified selected tunnels.
     */
    static Assessment inspect(RootFailClosedFirewallPlan.Plan plan,
            List<RootFailClosedFirewallPlan.Tunnel> tunnels, String home,
            String internet, String wifi, String cellular) {
        if (plan == null || tunnels == null || tunnels.size() != 2
                || home == null || internet == null || home.equals(internet)
                || !home.matches("wnm[0-9a-f]{12}")
                || !internet.matches("wnm[0-9a-f]{12}")
                || wifi == null || !wifi.matches("wlan[A-Za-z0-9_.-]*")
                || cellular == null || !cellular.matches("rmnet[A-Za-z0-9_.-]*")) {
            throw new IllegalArgumentException(
                    "Verified HOME/Internet tunnel identities and distinct example underlays required.");
        }

        RootFailClosedFirewallPlan.Tunnel homeTunnel = null;
        RootFailClosedFirewallPlan.Tunnel internetTunnel = null;
        for (RootFailClosedFirewallPlan.Tunnel t : tunnels) {
            if (t.device.equals(home)) homeTunnel = t;
            if (t.device.equals(internet)) internetTunnel = t;
        }
        if (homeTunnel == null || internetTunnel == null
                || !homeTunnel.allowedIps.contains("10.0.0.0/24")
                || !internetTunnel.allowedIps.contains("0.0.0.0/0")
                || !internetTunnel.allowedIps.contains("::/0")) {
            throw new IllegalArgumentException(
                    "HOME private route and Internet IPv4/IPv6 default route required.");
        }

        Assessment a = new Assessment();
        a.modeledChecks++;
        if (!plan.encode().equals(RootFailClosedFirewallPlan.build(tunnels).encode())) {
            a.mismatches.add("Current firewall plan differs from selected tunnel endpoint plan.");
        }

        for (String underlay : new String[]{wifi, cellular}) {
            // These are representative *locally originated* candidate flows.
            // Actual DHCP/ND might use other hooks; never infer OUTPUT traversal.
            expect(a, plan, "DHCPv4 renewal on " + underlay,
                    flow(4, "255.255.255.255", underlay, "udp", 67, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "IPv6 NS (135) link-local multicast on " + underlay,
                    flow(6, "ff02::1:ff00:1", underlay, "icmpv6", 0, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "IPv6 NA (136) link-local multicast on " + underlay,
                    flow(6, "ff02::1", underlay, "icmpv6", 0, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "IPv6 RS (133) on " + underlay,
                    flow(6, "ff02::2", underlay, "icmpv6", 0, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "Android HTTP connectivity validation on " + underlay,
                    flow(4, "1.1.1.1", underlay, "tcp", 80, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "Plaintext DNS outside VPN on " + underlay,
                    flow(4, "1.1.1.1", underlay, "udp", 53, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "Unprotected public HTTPS outside VPN on " + underlay,
                    flow(4, "1.1.1.1", underlay, "tcp", 443, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "Unprotected IPv6 HTTPS outside VPN on " + underlay,
                    flow(6, "2606:4700:4700::1111", underlay, "tcp", 443, 0),
                    RootGuardFlowModel.Result.REJECT);
            expect(a, plan, "HOME Navidrome direct-underlay fallback on " + underlay,
                    flow(4, "10.0.0.169", underlay, "tcp", 4533, 0),
                    RootGuardFlowModel.Result.REJECT);

            // The current rule matches endpoint IP:port+mark regardless of
            // underlay; it does not bind to the originating kernel WG socket.
            for (RootFailClosedFirewallPlan.Tunnel t : tunnels) {
                int family = t.address.contains(":") ? 6 : 4;
                expect(a, plan, "Exact marked UDP endpoint on " + underlay,
                        flow(family, t.address, underlay, "udp", t.port, t.mark),
                        RootGuardFlowModel.Result.RETURN);
                expect(a, plan, "Exact endpoint without mark on " + underlay,
                        flow(family, t.address, underlay, "udp", t.port, 0),
                        RootGuardFlowModel.Result.REJECT);
                String rotated = family == 4 ? "203.0.113.250" : "2001:db8:ffff::250";
                if (!rotated.equals(t.address)) {
                    expect(a, plan, "Changed endpoint IP on " + underlay,
                            flow(family, rotated, underlay, "udp", t.port, t.mark),
                            RootGuardFlowModel.Result.REJECT);
                }
            }
        }
        expect(a, plan, "HTTPS through Internet IPv4 tunnel",
                flow(4, "1.1.1.1", internet, "tcp", 443, 0),
                RootGuardFlowModel.Result.RETURN);
        expect(a, plan, "HTTPS through Internet IPv6 tunnel",
                flow(6, "2606:4700:4700::1111", internet, "tcp", 443, 0),
                RootGuardFlowModel.Result.RETURN);
        expect(a, plan, "HOME Navidrome via HOME tunnel",
                flow(4, "10.0.0.169", home, "tcp", 4533, 0),
                RootGuardFlowModel.Result.RETURN);
        expect(a, plan, "HOME Navidrome blocked on Internet tunnel",
                flow(4, "10.0.0.169", internet, "tcp", 4533, 0),
                RootGuardFlowModel.Result.REJECT);

        a.controlRisks.add("Old chain rejects modeled DHCPv4 physical-underlay requests.");
        a.controlRisks.add("Old chain rejects modeled outgoing IPv6 Neighbor Solicitation "
                + "(type 135), Advertisement (136), and Router Solicitation (133).");
        a.controlRisks.add("Old chain rejects modeled direct HTTP connectivity validation. "
                + "No general unprotected Internet exception is recommended.");
        a.unresolved.add("Kernel-generated Android control traffic might use INPUT/OUTPUT "
                + "or other hooks; physical header capture does not establish firewall traversal.");
        a.unresolved.add("Root WireGuard endpoint exceptions are not bound to verified "
                + "socket provenance and match identically across Wi-Fi/cellular underlays.");
        a.unresolved.add("A rotated endpoint is rejected until independently revalidated; "
                + "the firewall cannot assume handoff or endpoint continuity.");
        a.unresolved.add("A shared Android protected-from-VPN mark such as 0x20000 "
                + "is metadata, not an individual socket identity.");
        a.unresolved.add("No independent rollback watchdog, dual-stack packet challenge, "
                + "or Wi-Fi/cellular failover certification has passed.");
        return a;
    }
}
