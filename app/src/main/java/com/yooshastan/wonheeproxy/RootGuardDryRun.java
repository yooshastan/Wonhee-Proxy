package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Set;

/** Hypothetical fail-closed decisions. Does not construct or install firewall rules. */
final class RootGuardDryRun {
    private RootGuardDryRun() { }

    static String requiredTunnel(List<RootMultiTunnelPlan.Entry> entries,
                                 String numericDestination) {
        if (entries == null || entries.isEmpty()) return "";
        return RootProtectionPolicy.expectedDevice(entries, numericDestination);
    }

    static String modelDecision(List<RootMultiTunnelPlan.Entry> entries,
                                String numericDestination, Set<String> availableDevices) {
        String needed = requiredTunnel(entries, numericDestination);
        if (needed.isEmpty()) return "UNDEFINED — no selected destination policy";
        if (!availableDevices.contains(needed)) return "WOULD BLOCK — required tunnel unavailable";
        return "WOULD REQUIRE " + needed + " — packet path must be verified";
    }
}
