package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** No Android, shell, sockets, kernel routes or private WireGuard material. */
public final class RootIsolatedWireGuardTransactionTest {
    private static final class MemoryJournal
            implements RootIsolatedWireGuardTransaction.Journal {
        final List<RootIsolatedWireGuardBootstrapPlan.Step> entries =
                new ArrayList<>();
        int failWriteAt = -1;
        int writes;

        @Override public boolean empty() { return entries.isEmpty(); }

        @Override public void beforeMutation(RootIsolatedWireGuardBootstrapPlan.Step step)
                throws Exception {
            writes++;
            if (writes == failWriteAt) throw new IllegalStateException("disk write failed");
            entries.add(step);
        }

        @Override public void committed(RootIsolatedWireGuardBootstrapPlan.Step step)
                throws Exception {
            if (!entries.contains(step)) {
                throw new IllegalStateException("Committed without durable intent.");
            }
        }

        @Override public List<RootIsolatedWireGuardBootstrapPlan.Step> snapshot() {
            return new ArrayList<>(entries);
        }

        @Override public void clearExact(RootIsolatedWireGuardBootstrapPlan.Step step)
                throws Exception {
            if (!entries.remove(step)) throw new IllegalStateException("Lost ledger entry");
        }
    }

    private static final class MemoryKernel
            implements RootIsolatedWireGuardTransaction.Kernel {
        final Set<RootIsolatedWireGuardBootstrapPlan.Step> installed =
                new HashSet<>();
        final Set<RootIsolatedWireGuardBootstrapPlan.Step> foreign =
                new HashSet<>();
        int preflightCalls;
        int applyCalls;
        int undoCalls;
        int failApplyAt = -1;
        int failSafeAt = -1;
        int failUndoAt = -1;
        boolean gate = true;

        @Override public void requireActivationPreflight() throws Exception {
            preflightCalls++;
            if (!gate) throw new IllegalStateException("preflight denied");
        }

        @Override public RootIsolatedWireGuardTransaction.Presence inspect(
                RootIsolatedWireGuardBootstrapPlan.Step step) {
            if (foreign.contains(step)) {
                return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            return installed.contains(step)
                    ? RootIsolatedWireGuardTransaction.Presence.EXACT_OWNED
                    : RootIsolatedWireGuardTransaction.Presence.ABSENT;
        }

        @Override public void apply(RootIsolatedWireGuardBootstrapPlan.Step step)
                throws Exception {
            applyCalls++;
            if (!gate) throw new AssertionError("Mutated without preflight.");
            installed.add(step);
            if (applyCalls == failSafeAt) {
                throw new RootIsolatedWireGuardTransaction.SafeFailure(
                        "WG_SETCONF_COMMAND_FAILED");
            }
            if (applyCalls == failApplyAt) {
                throw new IllegalStateException("Command failed after partial mutation");
            }
        }

        @Override public void undo(RootIsolatedWireGuardBootstrapPlan.Step step)
                throws Exception {
            undoCalls++;
            if (undoCalls == failUndoAt) {
                throw new IllegalStateException("Simulated exact rollback failure");
            }
            if (!installed.remove(step)) throw new AssertionError("Undo of foreign object");
        }
    }

    private static void check(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
    }

    private static RootIsolatedWireGuardBootstrapPlan.Plan plan() {
        RootMultiTunnelPlan.Entry eu = new RootMultiTunnelPlan.Entry("EU",
                Arrays.asList("0.0.0.0/0", "::/0"),
                Collections.singletonList("10.150.0.2/32"));
        RootMultiTunnelPlan.Entry us = new RootMultiTunnelPlan.Entry("US",
                Arrays.asList("0.0.0.0/0", "::/0"),
                Collections.singletonList("10.151.0.2/32"));
        List<RootMultiTunnelPlan.Entry> profiles = Arrays.asList(eu, us);
        RootPerAppUidPolicyPlan.Plan policy = RootPerAppUidPolicyPlan.prepare(
                "EU", profiles, Arrays.asList(
                        new RootPerAppUidPolicyPlan.App("com.example.eu", 10341, "EU"),
                        new RootPerAppUidPolicyPlan.App("com.example.us", 10342, "US")));
        return RootIsolatedWireGuardBootstrapPlan.compile(profiles, policy);
    }

    public static void main(String[] args) throws Exception {
        RootIsolatedWireGuardBootstrapPlan.Plan plan = plan();
        MemoryKernel kernel = new MemoryKernel();
        MemoryJournal journal = new MemoryJournal();
        RootIsolatedWireGuardTransaction.Outcome started =
                RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        check(started.connected && !started.cleanupComplete
                        && journal.entries.size() == plan.steps.size()
                        && kernel.installed.size() == plan.steps.size(),
                "Successful staged bootstrap retains a durable stop journal");
        check(!RootIsolatedWireGuardTransaction.start(plan, kernel, journal).connected
                        && kernel.preflightCalls == 1,
                "Second Start must refuse existing ledger before root preflight");
        RootIsolatedWireGuardTransaction.Outcome stopped =
                RootIsolatedWireGuardTransaction.recover(kernel, journal);
        check(stopped.cleanupComplete && journal.empty() && kernel.installed.isEmpty()
                        && stopped.stage.equals("CLEAN_STOPPED"),
                "Safe Stop must reverse all exact-owned stages");
        check(RootIsolatedWireGuardTransaction.recover(kernel, journal).cleanupComplete,
                "Repeated Safe Stop must be idempotent");

        // Fault injection at EVERY stage, including failure AFTER mutation.
        for (int i = 1; i <= plan.steps.size(); i++) {
            kernel = new MemoryKernel();
            journal = new MemoryJournal();
            kernel.failApplyAt = i;
            RootIsolatedWireGuardTransaction.Outcome failed =
                    RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
            check(!failed.connected && failed.cleanupComplete
                            && journal.empty() && kernel.installed.isEmpty(),
                    "Partial kernel mutation at step " + i + " must fully roll back");
        }

        // Verify that a PEER_CONFIG failure provides an actionably precise
        // stage and a fixed safe category, without preserving stderr/keys.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        kernel.failSafeAt = 2;
        RootIsolatedWireGuardTransaction.Outcome peerFailed =
                RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        check(!peerFailed.connected && peerFailed.cleanupComplete
                        && journal.empty() && kernel.installed.isEmpty()
                        && peerFailed.stage.equals("PEER_CONFIG")
                        && peerFailed.failurePhase.equals("KERNEL_APPLY")
                        && peerFailed.failureCode.equals("WG_SETCONF_COMMAND_FAILED")
                        && peerFailed.summary().contains("reason=WG_SETCONF_COMMAND_FAILED")
                        && !peerFailed.summary().contains("PrivateKey"),
                "Exact peer failure must report sanitized code and roll back cleanly");

        // Fail before writing the current intent. No current-step mutation.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        journal.failWriteAt = 3;
        RootIsolatedWireGuardTransaction.Outcome writeFailed =
                RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        check(!writeFailed.connected && writeFailed.cleanupComplete
                        && journal.empty() && kernel.installed.isEmpty()
                        && kernel.applyCalls == 2,
                "Cannot execute a step without first durably writing its intent");

        // A corrupted late stage MUST be rejected before the first device
        // change, even if its inverse appears plausible to the caller.
        List<RootIsolatedWireGuardBootstrapPlan.Step> tampered =
                new ArrayList<>(plan.steps);
        RootIsolatedWireGuardBootstrapPlan.Step target =
                tampered.get(tampered.size() - 1);
        tampered.set(tampered.size() - 1,
                new RootIsolatedWireGuardBootstrapPlan.Step(
                        "PRIVATE_ROUTE", "ip -4 route add default dev wlan0",
                        "ip -4 route del default dev wlan0", target.device));
        RootIsolatedWireGuardBootstrapPlan.Plan corruptPlan =
                new RootIsolatedWireGuardBootstrapPlan.Plan(
                        tampered, plan.devices, plan.privateRoutes);
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        boolean rejectedPlan = false;
        try {
            RootIsolatedWireGuardTransaction.start(corruptPlan, kernel, journal);
        } catch (IllegalArgumentException expected) { rejectedPlan = true; }
        check(rejectedPlan && journal.empty() && kernel.preflightCalls == 0
                        && kernel.applyCalls == 0,
                "All command shapes must validate before any root work");

        // The caller's live preflight is mandatory and cannot be bypassed.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        kernel.gate = false;
        boolean refused = false;
        try {
            RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        } catch (IllegalStateException expected) { refused = true; }
        check(refused && kernel.applyCalls == 0 && journal.empty(),
                "Unverified DNS/underlay/fail-closed gate must prevent ALL changes");

        // An alien live object must never be undone on a matching name alone.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        RootIsolatedWireGuardBootstrapPlan.Step first = plan.steps.get(0);
        kernel.foreign.add(first);
        RootIsolatedWireGuardTransaction.Outcome conflict =
                RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        check(!conflict.connected && conflict.cleanupComplete
                        && kernel.applyCalls == 0 && journal.empty()
                        && kernel.foreign.contains(first),
                "Unknown interface must be preserved");

        // Recovery must pause and retain ledger if exact ownership is lost.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        RootIsolatedWireGuardBootstrapPlan.Step last =
                plan.steps.get(plan.steps.size() - 1);
        kernel.foreign.add(last);
        RootIsolatedWireGuardTransaction.Outcome paused =
                RootIsolatedWireGuardTransaction.recover(kernel, journal);
        check(!paused.cleanupComplete && !journal.empty()
                        && kernel.foreign.contains(last) && kernel.undoCalls == 0,
                "Safe Stop must pause rather than deleting an unowned rule");
        kernel.foreign.remove(last);
        check(RootIsolatedWireGuardTransaction.recover(kernel, journal).cleanupComplete,
                "Restored exact ownership must permit a retryable Safe Stop");

        // Error during rollback retains the remaining durable journal.
        kernel = new MemoryKernel();
        journal = new MemoryJournal();
        RootIsolatedWireGuardTransaction.start(plan, kernel, journal);
        kernel.failUndoAt = 2;
        paused = RootIsolatedWireGuardTransaction.recover(kernel, journal);
        check(!paused.cleanupComplete && journal.entries.size() > 0,
                "Interrupted rollback must retain exact pending ledger entries");
        kernel.failUndoAt = -1;
        check(RootIsolatedWireGuardTransaction.recover(kernel, journal).cleanupComplete
                        && journal.empty() && kernel.installed.isEmpty(),
                "Retry must finish interrupted exact cleanup");

        System.out.println("RootIsolatedWireGuardTransactionTest passed");
    }
}
