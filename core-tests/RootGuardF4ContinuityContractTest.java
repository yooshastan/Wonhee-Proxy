package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.List;

/** Pure offline regression; must never install any firewall or send packets. */
public final class RootGuardF4ContinuityContractTest {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static RootFailClosedFirewallPlan.Tunnel home() {
        return new RootFailClosedFirewallPlan.Tunnel(
                "wnma292ddb4b6da", "192.0.2.10", 51820, 0x20000L,
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"));
    }

    private static RootFailClosedFirewallPlan.Tunnel internet() {
        return new RootFailClosedFirewallPlan.Tunnel(
                "wnm68fe81200daa", "2001:db8::1", 1637, 0x20000L,
                Arrays.asList("0.0.0.0/0", "::/0"));
    }

    public static void main(String[] args) {
        List<RootFailClosedFirewallPlan.Tunnel> selected =
                Arrays.asList(home(), internet());
        RootFailClosedFirewallPlan.Plan plan = RootFailClosedFirewallPlan.build(selected);
        RootGuardF4ContinuityContract.Assessment a =
                RootGuardF4ContinuityContract.inspect(plan, selected,
                        home().device, internet().device, "wlan0", "rmnet16");
        check(a.modeledChecks() >= 30,
                "both underlays require control-plane, direct-leak and endpoint coverage");
        check(a.mismatchCount() == 0, "current firewall model must match known limitations");
        check(a.controlRiskCount() >= 3, "must record all observed control-plane risks");
        check(a.unresolvedCount() >= 5, "must not erase continuity/provenance blockers");
        check(!a.activationAllowed(), "offline simulation cannot enable the kill switch");
        String report = a.report();
        check(report.contains("Neighbor Solicitation")
                        && report.contains("ACTIVATION: BLOCKED")
                        && report.contains("Wi-Fi/cellular")
                        && report.contains("one outgoing ICMPv6 Neighbor"),
                "report must flag observed ND and limitations without claiming causation");
        check(!report.contains("192.0.2.10") && !report.contains("2001:db8::1"),
                "reports must not reveal concrete endpoint addresses");

        // A candidate that silently changes an endpoint must fail, not be
        // adopted by a model using stale stored firewall exceptions.
        RootFailClosedFirewallPlan.Tunnel rotated =
                new RootFailClosedFirewallPlan.Tunnel(
                        internet().device, "2001:db8::2", 1637, 0x20000L,
                        Arrays.asList("0.0.0.0/0", "::/0"));
        RootGuardF4ContinuityContract.Assessment stale =
                RootGuardF4ContinuityContract.inspect(plan,
                        Arrays.asList(home(), rotated),
                        home().device, internet().device, "wlan0", "rmnet16");
        check(stale.mismatchCount() >= 1 && !stale.activationAllowed(),
                "endpoint rotation cannot silently reuse old firewall plan");

        try {
            RootGuardF4ContinuityContract.inspect(
                    plan, selected, home().device, internet().device, "wlan0", "wlan0");
            throw new AssertionError("two distinct physical underlay examples required");
        } catch (IllegalArgumentException expected) { /* required */ }

        try {
            RootGuardF4ContinuityContract.inspect(plan, selected,
                    internet().device, home().device, "wlan0", "rmnet16");
            throw new AssertionError("selected HOME vs Internet routes must not be reversed");
        } catch (IllegalArgumentException expected) { /* required */ }

        // The physical observed ICMPv6 type (135) has no source-UID,
        // source address, or kernel hook attribution; refuse to infer any
        // permission to install real ip6tables exceptions.
        check(RootGuardFlowModel.evaluate(plan, new RootGuardFlowModel.Flow(
                6, "ff02::1:ff00:1", "wlan0", "icmpv6", 0, 0))
                == RootGuardFlowModel.Result.REJECT,
                "old terminal REJECT covers representative outgoing IPv6 NS");
        check(RootGuardSafetyGate.activationPaused(),
                "Batch F guard must remain paused throughout design/test stage");

        System.out.println("RootGuardF4ContinuityContractTest PASS");
    }
}
