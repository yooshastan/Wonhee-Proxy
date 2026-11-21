package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless isolated three-WireGuard-link plan: never routes app traffic. */
public final class RootIsolatedThreePeerLinkPlanTest {
    private static RootMultiTunnelPlan.Entry peer(String name, String host,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name,
                Arrays.asList(routes), Collections.singletonList(host));
    }
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
    private static void reject(List<RootMultiTunnelPlan.Entry> exits,
            RootMultiTunnelPlan.Entry home, String why) {
        try { RootIsolatedThreePeerLinkPlan.compile(exits, home); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Unsafe third Home link accepted: " + why);
    }
    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry a = peer("Exit A", "10.150.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry b = peer("Exit B", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = peer("Home", "10.6.0.2/32",
                "10.0.0.0/24", "10.77.0.0/24");
        List<RootMultiTunnelPlan.Entry> exits = Arrays.asList(a, b);
        RootIsolatedWireGuardBootstrapPlan.Plan plan =
                RootIsolatedThreePeerLinkPlan.compile(exits, home);
        RootIsolatedWireGuardBootstrapPlan.Plan old =
                RootIsolatedTwoPeerLinkPlan.compile(exits);
        check(plan.devices == 3 && plan.privateRoutes == 6
                        && !plan.activationAllowed(), "Three link plan scope");
        check(plan.steps.size() == old.steps.size() + 6,
                "Home stages added independently to two intact Internet peers");
        for (int i = 0; i < old.steps.size(); i++) {
            check(old.steps.get(i).install.equals(plan.steps.get(i).install)
                            && old.steps.get(i).device.equals(plan.steps.get(i).device),
                    "Proven dual-peer stages must remain unmodified");
        }
        int homeSteps = 0, homeRoutes = 0;
        for (RootIsolatedWireGuardBootstrapPlan.Step s : plan.steps) {
            check(RootIsolatedWireGuardTransaction.safeStep(s),
                    "Every live action passes strict exact-root command whitelist");
            check(!s.install.contains("ip rule add")
                            && !s.install.contains("iptables")
                            && !s.install.contains("route add default")
                            && !s.install.contains("DNS=")
                            && !s.install.contains("set-mark")
                            && !s.install.contains("table main"),
                    "Third link never touches Android main, UID, firewall or DNS");
            if (s.device.equals(home.device)) {
                homeSteps++;
                if (s.kind.equals("PRIVATE_ROUTE")) {
                    homeRoutes++;
                    check(s.install.contains("route add table 51002 ")
                                    && !s.install.contains("0.0.0.0/0")
                                    && !s.install.contains("::/0"),
                            "Home routes only private destinations in Home table");
                }
            }
        }
        check(homeSteps == 6 && homeRoutes == 2,
                "All Home stages independently journaled");
        check(plan.rollbackOrder().get(0).device.equals(home.device)
                        && plan.rollbackOrder().get(plan.steps.size()-1)
                                .kind.equals("LINK_CREATE"),
                "Safe Stop must first remove the third Home route and "
                        + "last remove first exact-owned Internet link");
        RootIsolatedWireGuardBootstrapPlan.Plan reversed =
                RootIsolatedThreePeerLinkPlan.compile(
                        Arrays.asList(b, a), home);
        for (int i = 0; i < plan.steps.size(); i++) {
            check(plan.steps.get(i).install.equals(reversed.steps.get(i).install),
                    "Journal and table identity independent of import order");
        }
        reject(exits, peer("Home", "10.6.0.2/32", "0.0.0.0/0"),
                "Home cannot be an Internet default");
        reject(exits, peer("Home", "10.150.0.2/32", "10.0.0.0/24"),
                "Home overlaps an Internet interface");
        reject(exits, peer("Home", "10.6.0.2/24", "10.0.0.0/24"),
                "Home /24 host could create main route");
        reject(exits, peer("Home", "10.6.0.2/32", "8.8.8.0/24"),
                "Home public exit destination refused");
        reject(exits, peer("Home", "10.6.0.2/32", "10.0.0.0/8"),
                "Home broad subnet refused");
        reject(exits, peer("Exit A", "10.6.0.2/32", "10.0.0.0/24"),
                "Home device name cannot duplicate Internet exit");
        System.out.println("RootIsolatedThreePeerLinkPlanTest passed");
    }
}
