package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.List;

public final class RootMultiTunnelPlanTest {
    private static RootMultiTunnelPlan.Entry entry(String name, String route, String address) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(route), Arrays.asList(address));
    }

    private static void rejects(String reason, List<RootMultiTunnelPlan.Entry> entries) {
        try {
            RootMultiTunnelPlan.validate(entries);
            throw new AssertionError("Expected rejection: " + reason);
        } catch (IllegalArgumentException expected) { /* preflight must reject without root */ }
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry home = entry("Home", "10.0.0.0/24", "10.6.0.2/24");
        RootMultiTunnelPlan.Entry internet = new RootMultiTunnelPlan.Entry("AirVPN",
                Arrays.asList("0.0.0.0/0", "::/0"), Arrays.asList("10.77.0.2/32", "fd7a::2/128"));
        // An Internet /0 inevitably overlaps other IPv4 destinations. For this
        // experiment, explicitly allow more-specific routes to a separate tunnel.
        RootMultiTunnelPlan.validate(Arrays.asList(home, internet));
        RootMultiTunnelPlan.validate(Arrays.asList(home));
        if (RootMultiTunnelPlan.interfaceName("  HOME ")
                .equals(RootMultiTunnelPlan.interfaceName("Home")) == false) {
            throw new AssertionError("Stable names should ignore case/outer spaces");
        }
        if (RootMultiTunnelPlan.interfaceName("Home").length() != 15) {
            throw new AssertionError("Interface name exceeds Linux IFNAMSIZ");
        }
        RootMultiTunnelPlan.Entry more = entry("Other network", "172.20.0.0/16", "10.88.0.2/32");
        RootMultiTunnelPlan.validate(Arrays.asList(home, internet, more));
        rejects("overlapping destinations", Arrays.asList(home,
                entry("Bad home", "10.0.0.128/25", "10.90.0.2/32")));
        rejects("duplicate default route", Arrays.asList(internet,
                entry("Bad exit", "0.0.0.0/0", "10.90.0.2/32")));
        rejects("conflicting interface networks", Arrays.asList(home,
                entry("Same iface subnet", "192.168.3.0/24", "10.6.0.8/24")));
        rejects("duplicate name", Arrays.asList(home,
                entry("HOME", "172.31.0.0/16", "10.90.0.2/32")));
        rejects("malformed CIDR", Arrays.asList(entry("Bad", "hello/24", "10.5.0.2/32")));
        RootMultiTunnelPlan.validate(Arrays.asList(
                entry("IPv6 A", "fd00:aaaa::/64", "fd00:bbbb::2/128"),
                entry("IPv6 B", "fd00:cccc::/64", "fd00:dddd::2/128")));
        rejects("IPv6 collision", Arrays.asList(
                entry("IPv6 A", "fd00:aaaa::/64", "fd00:bbbb::2/128"),
                entry("IPv6 B", "fd00:aaaa::1/128", "fd00:dddd::2/128")));
        System.out.println("RootMultiTunnelPlanTest passed");
    }
}
