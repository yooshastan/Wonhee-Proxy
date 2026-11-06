package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class RootGuardDryRunTest {
    private static void check(boolean value) { if (!value) throw new AssertionError(); }

    public static void main(String[] ignored) {
        List<RootMultiTunnelPlan.Entry> entries = Arrays.asList(
                new RootMultiTunnelPlan.Entry("home", Arrays.asList("10.0.0.0/24"),
                        Arrays.asList("10.9.0.2/32")),
                new RootMultiTunnelPlan.Entry("office", Arrays.asList("10.30.0.0/24"),
                        Arrays.asList("10.30.1.2/32")),
                new RootMultiTunnelPlan.Entry("internet", Arrays.asList("0.0.0.0/0", "::/0"),
                        Arrays.asList("10.19.0.2/32")));
        Set<String> up = new HashSet<>();
        for (RootMultiTunnelPlan.Entry e : entries) up.add(e.device);
        String home = RootGuardDryRun.requiredTunnel(entries, "10.0.0.169");
        String office = RootGuardDryRun.requiredTunnel(entries, "10.30.0.44");
        String internet = RootGuardDryRun.requiredTunnel(entries, "1.1.1.1");
        check(!home.equals(office) && !office.equals(internet));
        check(RootGuardDryRun.modelDecision(entries, "10.0.0.169", up).contains(home));
        up.remove(home);
        check(RootGuardDryRun.modelDecision(entries, "10.0.0.169", up).contains("WOULD BLOCK"));
        check(RootGuardDryRun.modelDecision(entries, "10.30.0.44", up).contains(office));
        check(RootGuardDryRun.modelDecision(entries, "2606:4700:4700::1111", up).contains(internet));
        check(RootGuardDryRun.modelDecision(Collections.emptyList(), "192.0.2.1", up)
                .contains("UNDEFINED"));
        System.out.println("RootGuardDryRunTest passed");
    }
}
