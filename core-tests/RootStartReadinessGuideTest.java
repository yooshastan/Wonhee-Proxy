package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootStartReadinessGuideTest {
    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("Setup guidance failed");
    }
    public static void main(String[] args) {
        String pass = RootStartReadinessGuide.message(true,
                "Batch H.1 preflight PASS", 3, Arrays.asList("US exit", "Asia exit"));
        check(pass.contains("3 compatible tunnels")
                && pass.contains("2 additional full-Internet profiles")
                && pass.contains("NOT connected")
                && pass.contains("NOT been tested")
                && !pass.contains("US exit"));
        String prior = RootStartReadinessGuide.message(false,
                "DNS ownership ledger must be cleared first.", 2,
                Collections.emptyList());
        check(prior.contains("failed BEFORE")
                && prior.contains("independent H.2a")
                && !prior.contains("ownership ledger must be cleared first."));
        check(RootStartReadinessGuide.message(false,
                "Set Android Private DNS to OFF first.", 2,
                Collections.emptyList()).contains("remain OFF"));
        check(RootStartReadinessGuide.message(false,
                "Untracked priority-12500+ rules remain.", 2,
                Collections.emptyList()).contains("routing/firewall"));
        check(RootStartReadinessGuide.message(false,
                "A tunnel is already UP; audit/stop it first.", 2,
                Collections.emptyList()).contains("already present"));
        check(RootStartReadinessGuide.message(false,
                "Selection has no HOME split-route correction.", 2,
                Collections.emptyList()).contains("destination-specific"));
        check(RootStartReadinessGuide.message(false,
                "root operation unavailable", 2,
                Collections.emptyList()).contains("root access"));
        check(RootStartReadinessGuide.message(false, null, 2,
                Collections.emptyList()).contains("could not prove"));
        System.out.println("RootStartReadinessGuideTest passed");
    }
}
