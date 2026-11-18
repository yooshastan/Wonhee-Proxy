package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Never starts a tunnel. Tests truthful multi-selection before Start. */
public final class RootTunnelStartSelectionTest {
    static RootMultiTunnelPlan.Entry p(String name, String address, String... routes) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(routes),
                Collections.singletonList(address));
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry nl = p("NL exit", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = p("US exit", "10.152.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry asia = p("Asia exit", "10.153.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = p("Home LAN", "10.6.0.2/32",
                "10.0.0.0/24", "10.6.0.0/24");
        RootMultiTunnelPlan.Entry work = p("Work LAN", "10.7.0.2/32",
                "10.20.0.0/16");
        List<RootMultiTunnelPlan.Entry> chosen = Arrays.asList(nl, home, us,
                asia, work);
        RootTunnelStartSelection.Review ask =
                RootTunnelStartSelection.review(chosen, "");
        if (!ask.needsPrimaryChoice || ask.ready
                || ask.primaryChoices.size() != 3
                || !ask.active.isEmpty()) {
            throw new AssertionError("Multiple full exits must require explicit choice.");
        }
        RootTunnelStartSelection.Review resolved =
                RootTunnelStartSelection.review(chosen, "NL exit");
        if (!resolved.ready || resolved.active.size() != 3
                || resolved.parked.size() != 2
                || !resolved.active.contains("NL exit")
                || !resolved.active.contains("Home LAN")
                || !resolved.active.contains("Work LAN")
                || resolved.active.contains("US exit")
                || resolved.active.contains("Asia exit")
                || !resolved.message.contains("NOT connected")) {
            throw new AssertionError("Only primary and compatible split tunnels can start: "
                    + resolved.message);
        }
        RootTunnelStartSelection.Review usPrimary =
                RootTunnelStartSelection.review(chosen, "US exit");
        if (!usPrimary.ready || usPrimary.active.contains("NL exit")
                || !usPrimary.active.contains("US exit")) {
            throw new AssertionError("User must control the primary region.");
        }
        RootTunnelStartSelection.Review noSplit =
                RootTunnelStartSelection.review(Arrays.asList(nl, us), "NL exit");
        if (noSplit.ready) {
            throw new AssertionError("Existing root full-stack requirement "
                    + "must not be bypassed by parking all additional exits.");
        }
        RootTunnelStartSelection.Review overlap =
                RootTunnelStartSelection.review(Arrays.asList(nl, home,
                        p("Overlapping Home", "10.8.0.2/32",
                                "10.0.0.0/25")), "NL exit");
        if (overlap.ready) {
            throw new AssertionError("Do not relax active CIDR overlap checks.");
        }
        RootTunnelStartSelection.Review ipv4Only =
                RootTunnelStartSelection.review(Arrays.asList(nl, home,
                        p("Bad IPv4-only", "10.9.0.2/32",
                                "0.0.0.0/0")), "NL exit");
        if (ipv4Only.ready) {
            throw new AssertionError("A selected full exit cannot have half a stack.");
        }
        List<RootMultiTunnelPlan.Entry> nine = new ArrayList<>(chosen);
        for (int i = 1; i <= 4; i++) {
            nine.add(p("Extra " + i, "10." + (180 + i) + ".0.2/32",
                    "10." + (180 + i) + ".1.0/24"));
        }
        if (RootTunnelStartSelection.review(nine, "NL exit").ready) {
            throw new AssertionError("Eight selected profiles maximum.");
        }
        if (RootTunnelStartSelection.review(Collections.emptyList(), "").ready) {
            throw new AssertionError("Empty selection accepted.");
        }
        System.out.println("RootTunnelStartSelectionTest passed");
    }
}
