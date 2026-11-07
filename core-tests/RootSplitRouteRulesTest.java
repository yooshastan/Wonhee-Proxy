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
        check(RootSplitRouteRules.probe("10.6.0.0/24").equals("10.6.0.1"),
                "Batch F must test a real host address, not the CIDR network base");
        check(RootSplitRouteRules.probe("10.77.0.0/24").equals("10.77.0.1"),
                "Batch F must share Batch B's route probe selection");
        check(rules.get(0).device.equals(home.device), "Home needs to win for private destinations");
        check(rules.get(0).add().contains("fwmark 0x0/0x20000 iif lo uidrange 0-99999"),
                "All non-protected Android network marks must match private split routes");
        check(RootSplitRouteRules.splitRouteMarkMatches(0x1009dL), "Wi-Fi netId mark should match");
        check(RootSplitRouteRules.splitRouteMarkMatches(0xc489eL), "AirVPN netId mark should match");
        check(RootSplitRouteRules.splitRouteMarkMatches(0xce8a6L), "HOME netId mark should match");
        check(RootSplitRouteRules.splitRouteMarkMatches(0x1489eL), "Explicit network mark should match");
        check(RootSplitRouteRules.splitRouteMarkMatches(0x1e8a6L), "HOME network mark should match");
        check(!RootSplitRouteRules.splitRouteMarkMatches(0x20000L),
                "protectedFromVpn sockets must bypass the HOME split rule");
        check(rules.get(0).delete().contains("pref 12500"), "Removal should be exact");
        String kernelLine = "12500: from all to 10.0.0.0/24 fwmark 0x0/0x20000 "
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
        check(RootSplitRouteRules.transportMarkHasIdentity("0xcc53a"),
                "Observed kernel fwmark must carry routing identity bits");
        check(!RootSplitRouteRules.transportMarkHasIdentity("off"), "Off fwmark must refuse");
        check(!RootSplitRouteRules.transportMarkHasIdentity("0x40000"),
                "A mark with no identity bits must refuse");
        List<Long> markProbes = RootSplitRouteRules.unprotectedMarkProbes(Arrays.asList(
                "13000: from all fwmark 0xc489e/0xcffff lookup 1075",
                "13000: from all fwmark 0xce8a6/0xcffff lookup 1076",
                "15040: from all fwmark 0x1009d/0x1ffff lookup 1047",
                "16000: from all fwmark 0x1489e/0x1ffff lookup 1075",
                "16000: from all fwmark 0x1e8a6/0x1ffff lookup 1076",
                "16000: from all fwmark 0x20000/0x20000 lookup 99",
                "16000: from all fwmark 0x1009d/0x1ffff lookup 1047"));
        check(markProbes.size() == 5 && markProbes.contains(0x1009dL)
                        && markProbes.contains(0xc489eL) && markProbes.contains(0xce8a6L)
                        && markProbes.contains(0x1489eL) && markProbes.contains(0x1e8a6L),
                "Collect unique unprotected Android mark probes and exclude protected marks");
        check(RootSplitRouteRules.endpointOutsideSplitRoutes("203.0.113.10", rules),
                "Public WireGuard endpoint should not overlap HOME split routes");
        check(!RootSplitRouteRules.endpointOutsideSplitRoutes("10.0.0.169", rules),
                "WireGuard endpoint inside HOME split route must refuse");
        String oldLedger = "4|12500|10.0.0.0/24|" + home.device + "|10.0.0.1\n";
        List<RootSplitRouteRules.Rule> legacy = RootSplitRouteRules.decode(oldLedger);
        check(legacy.size() == 1 && legacy.get(0).mark.equals(RootSplitRouteRules.LEGACY_MARK),
                "Old five-field rollback ledgers must retain their original selector");
        check(legacy.get(0).delete().contains("fwmark 0x0/0x2ffff"),
                "Legacy rollback must remove the exact old fwmark rule");
        String legacyListing = "12500: from all to 10.0.0.0/24 fwmark 0x0/0x2ffff "
                + "iif lo uidrange 0-99999 lookup " + home.device;
        check(legacy.get(0).matchesListing(legacyListing),
                "Legacy ownership must still match the exact old kernel listing");
        // A route-lookup PASS cannot conceal an untracked live priority rule.
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules,
                        Collections.emptyList(), 3, false),
                "Untracked live rules must make the audit CHECK REQUIRED");
        check(RootSplitRouteRules.auditOwnershipConsistent(rules,
                        Collections.emptyList(), 0, false),
                "Clean guard-off route state has no ownership discrepancy");
        check(RootSplitRouteRules.auditOwnershipConsistent(rules, rules, 3, true),
                "Three exact planned/live/owned rules should verify");
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules, rules, 3, false),
                "Matching ledger/count is insufficient without exact live checks");
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules, rules, 2, true),
                "Missing reserved rules must refuse even with a matching ledger");
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules, rules, 4, true),
                "Extra unowned reserved-priority rules must refuse");
        List<RootSplitRouteRules.Rule> legacyPlan = Arrays.asList(
                new RootSplitRouteRules.Rule(4, 12500, "10.0.0.0/24",
                        home.device, "10.0.0.1", RootSplitRouteRules.LEGACY_MARK),
                new RootSplitRouteRules.Rule(4, 12501, "10.6.0.0/24",
                        home.device, "10.6.0.1", RootSplitRouteRules.LEGACY_MARK),
                new RootSplitRouteRules.Rule(4, 12502, "10.77.0.0/24",
                        home.device, "10.77.0.1", RootSplitRouteRules.LEGACY_MARK));
        check(RootSplitRouteRules.auditOwnershipConsistent(rules, legacyPlan, 3, true),
                "Verified original mark selector may still be safely owned");
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules, legacyPlan, 3, false),
                "Unverified legacy selector must never be assumed owned");
        List<RootSplitRouteRules.Rule> foreign = Arrays.asList(
                new RootSplitRouteRules.Rule(4, 12500, "10.0.0.0/24",
                        internet.device, "10.0.0.1"), rules.get(1), rules.get(2));
        check(!RootSplitRouteRules.auditOwnershipConsistent(rules, foreign, 3, true),
                "Matching rule count cannot legitimize a foreign tunnel lookup");
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
        check(!RootSplitRouteRules.endpointOutsideSplitRoutes("fd00:1234::8", ipv6Rules),
                "IPv6 endpoint inside a private split prefix must refuse");
        check(RootSplitRouteRules.endpointOutsideSplitRoutes("2001:db8::8", ipv6Rules),
                "IPv6 endpoint outside private split prefixes should pass");
        System.out.println("RootSplitRouteRulesTest passed");
    }
}
