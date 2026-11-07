package com.yooshastan.wonheeproxy;

import java.util.Arrays;

/** Pure regression tests; no root or firewall writes. */
public final class RootGuardFlowModelTest {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        String home = "wnma292ddb4b6da";
        String internet = "wnm68fe81200daa";
        RootFailClosedFirewallPlan.Tunnel homeTunnel = new RootFailClosedFirewallPlan.Tunnel(
                home, "192.0.2.10", 51820, 0x20000,
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"));
        RootFailClosedFirewallPlan.Tunnel internetTunnel = new RootFailClosedFirewallPlan.Tunnel(
                internet, "2001:db8::1", 1637, 0x20000,
                Arrays.asList("0.0.0.0/0", "::/0"));
        RootFailClosedFirewallPlan.Plan plan = RootFailClosedFirewallPlan.build(
                Arrays.asList(homeTunnel, internetTunnel));
        RootGuardFlowModel.Result ok = RootGuardFlowModel.Result.RETURN;
        RootGuardFlowModel.Result denied = RootGuardFlowModel.Result.REJECT;

        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "192.0.2.10", "rmnet16", "udp", 51820, 0x20000)) == ok,
                "exact marked HOME UDP endpoint remains permitted");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "192.0.2.10", "rmnet16", "udp", 51820, 0)) == denied,
                "same UDP endpoint without exact mark rejected");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "192.0.2.10", "rmnet16", "udp", 51821, 0x20000)) == denied,
                "same UDP endpoint with wrong destination port rejected");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                6, "2001:db8::1", "wlan0", "udp", 1637, 0x20000)) == ok,
                "IPv6 exact marked UDP endpoint remains permitted");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "10.0.0.169", home, "tcp", 4533, 0)) == ok,
                "HOME application destination may flow on HOME");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "10.0.0.169", internet, "tcp", 4533, 0)) == denied,
                "HOME application destination rejected on AirVPN");
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "1.1.1.1", internet, "tcp", 443, 0)) == ok,
                "public Internet on selected AirVPN default permitted");
        for (String underlay : new String[] {"wlan0", "rmnet16"}) {
            check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                    4, "255.255.255.255", underlay, "udp", 67, 0)) == denied,
                    "DHCPv4 underlay control traffic modeled as rejected");
            check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                    4, "1.1.1.1", underlay, "tcp", 80, 0)) == denied,
                    "underlay validation HTTP modeled as rejected");
            check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                    4, "1.1.1.1", underlay, "udp", 53, 0)) == denied,
                    "underlay plain DNS modeled as rejected");
            check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                    6, "ff02::2", underlay, "icmpv6", 0, 0)) == denied,
                    "IPv6 neighbor/router control flow modeled as rejected");
            String report = RootGuardFlowModel.preview(plan, underlay, home, internet);
            check(report.contains("Batch F activation is PAUSED")
                            && report.contains("DHCPv4 UDP/67 on underlay: REJECT")
                            && report.contains("IPv6 router solicitation on underlay: REJECT"),
                    "read-only report warns about control-plane flow rejections");
        }
        check(RootGuardFlowModel.evaluate(null, new RootGuardFlowModel.Flow(
                4, "1.1.1.1", "wlan0", "tcp", 80, 0))
                == RootGuardFlowModel.Result.UNKNOWN,
                "no plan is inconclusive, never implicitly permitted");
        check(RootGuardFlowModel.preview(plan, "wnm68fe81200daa", home, internet)
                .contains("UNAVAILABLE"), "do not label VPN interface as underlay");
        System.out.println("RootGuardFlowModelTest PASS");
    }
}
