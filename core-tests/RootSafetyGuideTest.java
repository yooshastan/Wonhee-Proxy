package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootSafetyGuideTest {
    public static void main(String[] args) {
        check(RootSafetyGuide.assess(0, 2, true, "a (wnm1): UP; identity MATCH\n"
                + "b (wnm2): UP; identity MATCH\n").needsAttention == false);
        check(RootSafetyGuide.assess(0, 2, true, "a (wnm1): UP; identity MATCH\n"
                + "b (wnm2): DOWN; identity not checked\n").needsAttention);
        check(RootSafetyGuide.assess(1, 2, true, "Split-route matches: 3/3. These are UID-0 queries").needsAttention == false);
        check(RootSafetyGuide.assess(1, 2, true, "WARNING untracked rules\nSplit-route matches: 3/3").needsAttention);
        check(RootSafetyGuide.assess(1, 2, true, "MISMATCH\nSplit-route matches: 2/3").needsAttention);
        check(RootSafetyGuide.assess(2, 2, true, "Configured resolver root-route matches: 3/3").needsAttention == false);
        check(RootSafetyGuide.assess(2, 2, true, "Configured resolver root-route matches: 0/0").needsAttention);
        check(RootSafetyGuide.assess(2, 2, true, "Configured resolver root-route matches: 2/3").needsAttention);
        check(RootSafetyGuide.assess(3, 2, true, "audit only").label.equals("INVENTORY RECORDED"));
        check(RootSafetyGuide.assess(4, 2, true, "PARTIAL PASS").label.equals("KILL SWITCH OFF"));
        check(RootSafetyGuide.assess(4, 2, true, "PARTIAL PASS").needsAttention == false);
        check(RootSafetyGuide.assess(0, 2, false, "root unavailable").needsAttention);
        String summary = RootSafetyGuide.summary(Arrays.asList(
                RootSafetyGuide.assess(0, 2, true, "a (wnm1): UP; identity MATCH\n"
                        + "b (wnm2): UP; identity MATCH"),
                RootSafetyGuide.assess(1, 2, true, "Split-route matches: 3/3"),
                RootSafetyGuide.assess(2, 2, true, "Configured resolver root-route matches: 3/3"),
                RootSafetyGuide.assess(3, 2, true, "inventory"),
                RootSafetyGuide.assess(4, 2, true, "PARTIAL PASS")));
        check(summary.contains("No DNS protection or kill switch was activated"));
        System.out.println("RootSafetyGuideTest PASS");
    }

    private static void check(boolean value) {
        if (!value) throw new AssertionError("Safety guide assessment failed");
    }
}
