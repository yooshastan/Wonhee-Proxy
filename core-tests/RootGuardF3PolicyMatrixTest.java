package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.List;

/** Pure offline policy-contract tests. Never activate or manipulate a firewall. */
public final class RootGuardF3PolicyMatrixTest {
    private RootGuardF3PolicyMatrixTest() { }

    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }

    private static RootFailClosedFirewallPlan.Tunnel home(long mark) {
        return new RootFailClosedFirewallPlan.Tunnel(
                "wnma292ddb4b6da", "2001:db8::17", 51820, mark,
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"));
    }

    private static RootFailClosedFirewallPlan.Tunnel internet(long mark) {
        return new RootFailClosedFirewallPlan.Tunnel(
                "wnm68fe81200daa", "198.51.100.42", 1637, mark,
                Arrays.asList("0.0.0.0/0", "::/0"));
    }

    public static void main(String[] args) {
        List<RootFailClosedFirewallPlan.Tunnel> shared =
                Arrays.asList(home(0x20000L), internet(0x20000L));
        RootFailClosedFirewallPlan.Plan plan = RootFailClosedFirewallPlan.build(shared);
        for (String underlay : new String[]{"wlan0", "rmnet16"}) {
            RootGuardF3PolicyMatrix.Assessment assessment =
                    RootGuardF3PolicyMatrix.inspect(plan, shared,
                            "wnma292ddb4b6da", "wnm68fe81200daa", underlay);
            check(assessment.checkCount() >= 27,
                    "both IPv4/IPv6 positive and negative scenarios must be evaluated");
            check(assessment.modelChecksPass() && assessment.failureCount() == 0,
                    "exact owned chain grammar should have expected modeled behavior");
            check(assessment.blockerCount() >= 4,
                    "known ownership, underlay and recovery blockers must be reported");
            check(!assessment.activationAllowed(),
                    "passing simulated rules MUST NOT authorize firewall activation");
            String report = assessment.report();
            check(report.contains("ACTIVATION: BLOCKED")
                            && report.contains("fwmark cannot authenticate")
                            && report.contains("kernel socket provenance")
                            && !report.contains("198.51.100.42")
                            && !report.contains("2001:db8::17"),
                    "report must explain unverified transport provenance, redact endpoints");
        }

        List<RootFailClosedFirewallPlan.Tunnel> unique =
                Arrays.asList(home(0x20000L), internet(0x40000L));
        RootGuardF3PolicyMatrix.Assessment distinct =
                RootGuardF3PolicyMatrix.inspect(
                        RootFailClosedFirewallPlan.build(unique), unique,
                        "wnma292ddb4b6da", "wnm68fe81200daa", "wlan0");
        check(distinct.modelChecksPass() && !distinct.activationAllowed()
                        && distinct.blockerCount() >= 3,
                "unique marks still do not authenticate the real kernel socket");
        check(!distinct.report().contains("fwmark cannot authenticate"),
                "do not report shared mark if the chosen marks differ");

        List<RootFailClosedFirewallPlan.Tunnel> changed =
                Arrays.asList(home(0x20000L),
                        new RootFailClosedFirewallPlan.Tunnel(
                                "wnm68fe81200daa", "198.51.100.42", 1638, 0x20000L,
                                Arrays.asList("0.0.0.0/0", "::/0")));
        RootGuardF3PolicyMatrix.Assessment stale =
                RootGuardF3PolicyMatrix.inspect(plan, changed,
                        "wnma292ddb4b6da", "wnm68fe81200daa", "wlan0");
        check(stale.failureCount() > 0 && !stale.modelChecksPass()
                        && !stale.activationAllowed()
                        && stale.report().contains("DISCREPANCY"),
                "stale endpoint plan must fail the offline contract and remain disabled");

        try {
            RootGuardF3PolicyMatrix.inspect(plan, shared,
                    "wnma292ddb4b6da", "wnm68fe81200daa", "wnm68fe81200daa");
            throw new AssertionError("a tunnel device is not a physical underlay");
        } catch (IllegalArgumentException expected) { /* required */ }

        try {
            RootGuardF3PolicyMatrix.inspect(plan, shared,
                    "wnma292ddb4b6da", "wnma292ddb4b6da", "wlan0");
            throw new AssertionError("same tunnel cannot be HOME and Internet");
        } catch (IllegalArgumentException expected) { /* required */ }

        // The first-match model cannot distinguish a legitimate WireGuard socket
        // from a different sender with *identical* packet attributes. This is
        // a model limitation to investigate, not proof of a real exploit.
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                4, "198.51.100.42", "wlan0", "udp", 1637, 0x20000L))
                == RootGuardFlowModel.Result.RETURN,
                "exact endpoint tuple and mark allowed without socket provenance");

        System.out.println("RootGuardF3PolicyMatrixTest PASS");
    }
}
