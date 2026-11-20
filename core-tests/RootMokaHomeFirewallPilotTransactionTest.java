package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Zero-device mock backend: tests exact ownership and failure rollback. */
public final class RootMokaHomeFirewallPilotTransactionTest {
    static int cases;
    static void assertTrue(boolean result, String message) {
        if (!result) throw new AssertionError(message);
        cases++;
    }
    static class Fake implements RootMokaHomeFirewallPilotTransaction.Kernel {
        final Set<String> live = new HashSet<>();
        boolean passedPreflight;
        int failAt = -1;
        int ordinal;
        boolean foreign;
        boolean undoFails;
        String key(RootMokaHomeFirewallPilotPlan.Step s) { return s.install; }
        @Override public void requirePreflight() {
            if (!passedPreflight) throw new IllegalStateException("Not ready");
        }
        @Override public RootMokaHomeFirewallPilotTransaction.Presence inspect(
                RootMokaHomeFirewallPilotPlan.Step s) {
            if (foreign && live.contains(key(s)))
                return RootMokaHomeFirewallPilotTransaction.Presence.FOREIGN_OR_CHANGED;
            return live.contains(key(s))
                    ? RootMokaHomeFirewallPilotTransaction.Presence.EXACT_OWNED
                    : RootMokaHomeFirewallPilotTransaction.Presence.ABSENT;
        }
        @Override public void apply(RootMokaHomeFirewallPilotPlan.Step s) {
            ordinal++;
            if (failAt == ordinal) throw new IllegalStateException("Simulated crash");
            live.add(key(s));
        }
        @Override public void undo(RootMokaHomeFirewallPilotPlan.Step s) {
            if (undoFails) throw new IllegalStateException("Unknown kernel state");
            live.remove(key(s));
        }
    }
    static class Journal implements RootMokaHomeFirewallPilotTransaction.Journal {
        final List<RootMokaHomeFirewallPilotPlan.Step> owned = new ArrayList<>();
        @Override public boolean empty() { return owned.isEmpty(); }
        @Override public void intent(RootMokaHomeFirewallPilotPlan.Step s) { owned.add(s); }
        @Override public void applied(RootMokaHomeFirewallPilotPlan.Step s) {}
        @Override public List<RootMokaHomeFirewallPilotPlan.Step> snapshot() {
            return new ArrayList<>(owned);
        }
        @Override public void clearExact(RootMokaHomeFirewallPilotPlan.Step s) {
            if (owned.isEmpty() || owned.get(owned.size() - 1) != s)
                throw new IllegalStateException("Non-LIFO cleanup");
            owned.remove(owned.size() - 1);
        }
    }
    public static void main(String[] args) throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan p =
                RootMokaHomeFirewallPilotPlan.compile(10300, "wnm4ea140588150");
        assertTrue(!p.activationAllowed(), "preview must not authorize activation");
        assertTrue(p.steps.size() == 7, "v4/v6 chains, deny, v4 allow, two hooks");
        assertTrue(p.steps.get(5).kind.equals("OWNER_ANCHOR"),
                "both protective chains populated before hooks");
        assertTrue(p.steps.get(6).family == 6, "IPv6 anchor last");
        RootMokaHomeFirewallPilotTransaction.validate(p);
        assertTrue(p.steps.get(1).install.contains("10.0.0.169/32")
                && p.steps.get(1).install.contains("--dport 4533"),
                "exact numeric service scope");
        for (int i = 0; i < p.steps.size(); i++) {
            assertTrue(RootMokaHomeFirewallPilotPlan.safeStep(p, p.steps.get(i)),
                    "only exact canonical step");
        }
        assertTrue(!RootMokaHomeFirewallPilotPlan.safeStep(p,
                new RootMokaHomeFirewallPilotPlan.Step(4,"OWNER_ANCHOR",
                        "iptables -F OUTPUT", "iptables -F OUTPUT")),
                "foreign destructive step refused");
        try {
            RootMokaHomeFirewallPilotPlan.compile(1000, "wlan0");
            throw new AssertionError("unsafe uid/device accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(true, "unsafe UID/device refused");
        }
        Fake noPreflight = new Fake();
        Journal j0 = new Journal();
        try {
            RootMokaHomeFirewallPilotTransaction.start(p, noPreflight, j0);
            throw new AssertionError("missing preflight accepted");
        } catch (IllegalStateException expected) {
            assertTrue(j0.empty() && noPreflight.live.isEmpty(),
                    "no mutation before preflight");
        }
        Fake normal = new Fake();
        normal.passedPreflight = true;
        Journal j = new Journal();
        var started = RootMokaHomeFirewallPilotTransaction.start(p, normal, j);
        assertTrue(started.applied && started.phase.equals("STRUCTURAL_ONLY"),
                "fake start structural only");
        assertTrue(j.snapshot().size() == 7, "all journal steps retained");
        var stopped = RootMokaHomeFirewallPilotTransaction.stop(p, normal, j);
        assertTrue(stopped.clean && j.empty() && normal.live.isEmpty(),
                "complete inverse rollback");
        for (int n = 1; n <= p.steps.size(); n++) {
            Fake broken = new Fake();
            broken.passedPreflight = true;
            broken.failAt = n;
            Journal pending = new Journal();
            var result = RootMokaHomeFirewallPilotTransaction.start(p, broken, pending);
            assertTrue(!result.applied && result.clean
                    && pending.empty() && broken.live.isEmpty(),
                    "atomic rollback for step " + n);
        }
        Fake changed = new Fake();
        changed.passedPreflight = true;
        Journal pending = new Journal();
        RootMokaHomeFirewallPilotTransaction.start(p, changed, pending);
        changed.foreign = true;
        var paused = RootMokaHomeFirewallPilotTransaction.stop(p, changed, pending);
        assertTrue(!paused.clean && pending.snapshot().size() == 7,
                "foreign chain blocks destructive cleanup");
        changed.foreign = false;
        changed.undoFails = true;
        var failedStop = RootMokaHomeFirewallPilotTransaction.stop(p, changed, pending);
        assertTrue(!failedStop.clean && !pending.empty(),
                "undo failure keeps ownership ledger");
        changed.undoFails = false;
        assertTrue(RootMokaHomeFirewallPilotTransaction.stop(p, changed, pending).clean,
                "retry exact recovery succeeds");
        System.out.println("MOKA_HOME_FIREWALL_TRANSACTION " + cases + " assertions PASS");
    }
}
