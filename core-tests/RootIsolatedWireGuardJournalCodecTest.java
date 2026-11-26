package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless simulation of crash recovery metadata; no private VPN profiles. */
public final class RootIsolatedWireGuardJournalCodecTest {
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }

    private static void rejects(Runnable run, String reason) {
        try { run.run(); }
        catch (IllegalArgumentException | IllegalStateException expected) { return; }
        throw new AssertionError("Unsafe journal was accepted: " + reason);
    }

    private static RootIsolatedWireGuardBootstrapPlan.Plan sample() {
        RootMultiTunnelPlan.Entry eu = new RootMultiTunnelPlan.Entry("Europe",
                Arrays.asList("0.0.0.0/0", "::/0"),
                Collections.singletonList("10.150.0.2/32"));
        RootMultiTunnelPlan.Entry us = new RootMultiTunnelPlan.Entry("America",
                Arrays.asList("0.0.0.0/0", "::/0"),
                Collections.singletonList("10.151.0.2/32"));
        List<RootMultiTunnelPlan.Entry> selected = Arrays.asList(eu, us);
        RootPerAppUidPolicyPlan.Plan policy = RootPerAppUidPolicyPlan.prepare(
                "Europe", selected, Arrays.asList(
                        new RootPerAppUidPolicyPlan.App("com.example.eu", 10341, "Europe"),
                        new RootPerAppUidPolicyPlan.App("com.example.us", 10342, "America")));
        return RootIsolatedWireGuardBootstrapPlan.compile(selected, policy);
    }

    public static void main(String[] args) {
        RootIsolatedWireGuardBootstrapPlan.Plan plan = sample();
        RootIsolatedWireGuardJournalCodec codec = new RootIsolatedWireGuardJournalCodec(plan);
        check(codec.encode(Collections.emptyList()).isEmpty(),
                "An empty journal encodes to the canonical empty document");
        RootIsolatedWireGuardBootstrapPlan.Step first = plan.steps.get(0);
        RootIsolatedWireGuardBootstrapPlan.Step second = plan.steps.get(1);
        List<RootIsolatedWireGuardJournalCodec.Entry> entries =
                codec.beforeMutation(codec.decode(""), first);
        String pending = codec.encode(entries);
        check(pending.matches("WNI1\\|[0-9a-f]{64}\\|0P")
                        && !pending.contains(first.device)
                        && !pending.contains(first.install)
                        && !pending.contains("PrivateKey"),
                "Durable record must contain only fingerprint, step index and state");
        entries = codec.committed(codec.decode(pending), first);
        check(codec.encode(entries).endsWith("0A"),
                "A committed step is explicitly distinguished from pending");
        entries = codec.beforeMutation(entries, second);
        String partial = codec.encode(entries);
        check(partial.endsWith("0A,1P"),
                "Mid-start crash must preserve applied and in-flight stages");

        // A fresh process with the same plan can reopen the journal.
        RootIsolatedWireGuardBootstrapPlan.Plan rebuilt = sample();
        RootIsolatedWireGuardJournalCodec reopened =
                new RootIsolatedWireGuardJournalCodec(rebuilt);
        List<RootIsolatedWireGuardJournalCodec.Entry> restored =
                reopened.decode(partial);
        check(restored.size() == 2
                        && restored.get(0).step == rebuilt.steps.get(0)
                        && restored.get(0).applied && !restored.get(1).applied,
                "Recovery indexes refer to reconstructed, validated plan entries");
        restored = reopened.clearExact(restored, rebuilt.steps.get(1));
        restored = reopened.clearExact(restored, rebuilt.steps.get(0));
        check(reopened.encode(restored).isEmpty(),
                "Exact last-to-first cleanup clears the durable journal");

        final List<RootIsolatedWireGuardJournalCodec.Entry> original =
                codec.decode(partial);
        rejects(() -> codec.clearExact(original, first),
                "Cannot clear early stage while later stage remains");
        rejects(() -> codec.committed(original, first),
                "Cannot commit a non-last or already committed stage");
        rejects(() -> codec.beforeMutation(original, second),
                "Cannot duplicate the in-flight journal entry");

        RootIsolatedWireGuardBootstrapPlan.Step last =
                plan.steps.get(plan.steps.size() - 1);
        rejects(() -> codec.beforeMutation(original, last),
                "Cannot skip over required bootstrap stages");

        // A changed profile/route map may NEVER adopt the previous ledger.
        List<RootIsolatedWireGuardBootstrapPlan.Step> modified =
                new ArrayList<>(plan.steps);
        RootIsolatedWireGuardBootstrapPlan.Step prev =
                modified.get(modified.size() - 1);
        modified.set(modified.size() - 1,
                new RootIsolatedWireGuardBootstrapPlan.Step(prev.kind,
                        prev.install + " ", prev.inverse + " ", prev.device));
        RootIsolatedWireGuardJournalCodec changed =
                new RootIsolatedWireGuardJournalCodec(
                        new RootIsolatedWireGuardBootstrapPlan.Plan(modified,
                                plan.devices, plan.privateRoutes));
        rejects(() -> changed.decode(partial),
                "Changed routes must not adopt old owned kernel objects");
        rejects(() -> codec.decode(partial.replace("0A,1P", "0P,1A")),
                "Crash ledger cannot commit a step after an earlier pending stage");
        rejects(() -> codec.decode(partial.replace("0A,1P", "0A,2P")),
                "Skipped index corrupts journal");
        rejects(() -> codec.decode(partial.replace("WNI1", "WNI2")),
                "Unknown journal version must refuse");
        rejects(() -> codec.decode(partial + ",1A"),
                "Duplicate index must refuse");
        rejects(() -> codec.decode("WNI1|unknown|0A"),
                "Unmatched plan fingerprint cannot authorize cleanup");

        System.out.println("RootIsolatedWireGuardJournalCodecTest passed");
    }
}
