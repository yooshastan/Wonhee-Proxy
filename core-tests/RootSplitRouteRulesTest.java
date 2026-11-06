package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class RootSplitRouteRulesTest {
    private static RootMultiTunnelPlan.Entry entry(String name, List<String> cidrs, String address) {
        return new RootMultiTunnelPlan.Entry(name, cidrs, Collections.singletonList(address));
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry home = entry("wgs_client1",
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"), "10.55.0.2/32");
        RootMultiTunnelPlan.Entry internet = entry("AirVPNEurope",
                Arrays.asList("0.0.0.0/0", "::/0"), "10.159.187.150/32");
        List<RootSplitRouteRules.Rule> rules = RootSplitRouteRules.plan(Arrays.asList(home, internet));
        check(rules.size() == 3, "Three home CIDRs should override the Internet default");
        check(rules.get(0).priority == 12500, "Must precede Android priority 13000");
        check(rules.get(0).family == 4 && rules.get(0).destination.equals("10.0.0.0/24"),
                "Stable CIDR order is required for persisted removal");
        check(rules.get(0).probe.equals("10.0.0.1"), "Expected a numeric host probe");
        check(rules.get(0).device.equals(home.device), "Home needs to win for private destinations");
        check(rules.get(0).add().contains("fwmark 0x0/0x2ffff iif lo uidrange 0-99999"),
                "Explicit network-bound sockets should not match");
        check(rules.get(0).delete().contains("pref 12500"), "Removal should be exact");
        String kernelLine = "12500: from all to 10.0.0.0/24 fwmark 0x0/0x2ffff "
                + "iif lo uidrange 0-99999 lookup " + home.device;
        check(rules.get(0).matchesListing(kernelLine), "Owned rule must match exact listing");
        check(!rules.get(0).matchesListing(kernelLine.replace(home.device, internet.device)),
                "Never claim another lookup table as owned");
        check(!rules.get(0).matchesListing(kernelLine.replace("12500", "12501")),
                "Do not delete another rule priority");
        check(RootSplitRouteRules.reservedPriorityPresent(Arrays.asList(kernelLine)),
                "Reserved priorities must be checked for collisions");
        check(!RootSplitRouteRules.reservedPriorityPresent(Arrays.asList(
                "13000: from all lookup wlan0", "12000: from all lookup local_network")),
                "Android-owned rules are not collisions");
        check(RootSplitRouteRules.transportBypassesRules("0xcc53a"),
                "Observed kernel fwmark must bypass unmarked routing correction");
        check(!RootSplitRouteRules.transportBypassesRules("off"), "Off fwmark must refuse");
        check(!RootSplitRouteRules.transportBypassesRules("0x40000"),
                "A mark with no masked bits must refuse");
        List<RootSplitRouteRules.Rule> decoded = RootSplitRouteRules.decode(
                RootSplitRouteRules.encode(rules));
        check(decoded.size() == rules.size(), "Persistent rules should survive restart");
        check(decoded.get(1).add().equals(rules.get(1).add()),
                "Persisted rule must retain exact install command");
        try {
            RootSplitRouteRules.decode("4|12500|10.0.0.0/24|wlan0|10.0.0.1\n");
            throw new AssertionError("Unowned table must not load as a Wonhee rule");
        } catch (IllegalArgumentException expected) { /* reject */ }
        check(RootSplitRouteRules.plan(Collections.singletonList(internet)).isEmpty(),
                "One default tunnel needs no priority correction");
        RootMultiTunnelPlan.Entry v6 = entry("IPv6 Home",
                Collections.singletonList("fd00:1234::/64"), "fd00:5678::2/128");
        List<RootSplitRouteRules.Rule> ipv6Rules = RootSplitRouteRules.plan(Arrays.asList(v6, internet));
        check(ipv6Rules.size() == 1 && ipv6Rules.get(0).family == 6,
                "IPv6 split network needs a family-specific rule");
        System.out.println("RootSplitRouteRulesTest passed");
    }
}
