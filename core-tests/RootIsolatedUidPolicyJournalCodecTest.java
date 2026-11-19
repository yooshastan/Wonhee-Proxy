package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless crash-restart and tamper tests for the UID policy metadata. */
public final class RootIsolatedUidPolicyJournalCodecTest {
    private static void check(boolean ok, String why) {
        if (!ok) throw new AssertionError(why);
    }

    private static void reject(Runnable task, String why) {
        try { task.run(); }
        catch (IllegalStateException | IllegalArgumentException expected) { return; }
        throw new AssertionError("Corrupted UID journal accepted: " + why);
    }

    private static RootIsolatedUidOnlyPolicyPlan.Plan plan() {
        List<RootMultiTunnelPlan.Entry> peers = Arrays.asList(
                new RootMultiTunnelPlan.Entry("Europe",
                        Arrays.asList("0.0.0.0/0", "::/0"),
                        Collections.singletonList("10.150.0.2/32")),
                new RootMultiTunnelPlan.Entry("America",
                        Arrays.asList("0.0.0.0/0", "::/0"),
                        Collections.singletonList("10.151.0.2/32")));
        RootPerAppUidPolicyPlan.Plan policy = RootPerAppUidPolicyPlan.prepare(
                "Europe", peers, Arrays.asList(
                        new RootPerAppUidPolicyPlan.App(
                                "com.example.browser", 10341, "Europe"),
                        new RootPerAppUidPolicyPlan.App(
                                "com.example.shop", 10342, "America")));
        return RootIsolatedUidOnlyPolicyPlan.compile(policy);
    }

    public static void main(String[] args) {
        RootIsolatedUidOnlyPolicyPlan.Plan model = plan();
        RootIsolatedUidPolicyJournalCodec journal =
                new RootIsolatedUidPolicyJournalCodec(model);
        List<RootIsolatedUidPolicyJournalCodec.Entry> entries =
                journal.decode("");
        check(entries.isEmpty() && journal.encode(entries).isEmpty(),
                "Empty isolated policy journal is canonical.");
        RootIsolatedUidOnlyPolicyPlan.Step first = model.startOrder().get(0);
        RootIsolatedUidOnlyPolicyPlan.Step second = model.startOrder().get(1);
        entries = journal.intent(entries, first);
        String partial = journal.encode(entries);
        check(partial.matches("WNUP1\\|[0-9a-f]{64}\\|0P")
                        && !partial.contains(first.add)
                        && !partial.contains(first.remove),
                "No shell command or original route in journal contents.");
        entries = journal.applied(entries, first);
        entries = journal.intent(entries, second);
        partial = journal.encode(entries);
        check(partial.endsWith("0A,1P"),
                "Partially applied policy retains a pending second rule.");
        RootIsolatedUidOnlyPolicyPlan.Plan rebuilt = plan();
        RootIsolatedUidPolicyJournalCodec reopened =
                new RootIsolatedUidPolicyJournalCodec(rebuilt);
        List<RootIsolatedUidPolicyJournalCodec.Entry> loaded =
                reopened.decode(partial);
        check(loaded.size() == 2 && loaded.get(0).applied
                        && !loaded.get(1).applied,
                "Restart restores journal identity and per-step states.");

        final String snapshot = partial;
        reject(() -> reopened.decode(snapshot.replace("0A,1P", "0P,1A")),
                "Earlier uncommitted operation before a later stage rejected.");
        reject(() -> reopened.decode(snapshot.replace("1P", "2P")),
                "Out-of-order index rejected.");
        reject(() -> reopened.decode(snapshot + ",1P"),
                "Duplicate pending index rejected.");
        reject(() -> reopened.decode(snapshot.replace("WNUP1", "WNUP2")),
                "Unknown format rejected.");
        reject(() -> reopened.decode(snapshot.replace("0A", "0X")),
                "Unknown commit state rejected.");
        reject(() -> reopened.decode("WNUP1|broken|0P"),
                "Mismatched fingerprint rejected.");

        final List<RootIsolatedUidPolicyJournalCodec.Entry> loadedFinal = loaded;
        reject(() -> reopened.clearLast(loadedFinal, rebuilt.startOrder().get(0)),
                "Cannot remove a terminal block while later policy is owned.");
        reject(() -> reopened.applied(loadedFinal, rebuilt.startOrder().get(0)),
                "Cannot commit a non-last or already committed rule.");
        reject(() -> reopened.intent(loadedFinal, rebuilt.startOrder().get(1)),
                "Cannot duplicate an in-flight rule.");

        loaded = reopened.clearLast(loaded, rebuilt.startOrder().get(1));
        loaded = reopened.clearLast(loaded, rebuilt.startOrder().get(0));
        check(reopened.encode(loaded).isEmpty(),
                "Exact reverse-order cleanup clears persistent policy metadata.");

        List<RootIsolatedUidOnlyPolicyPlan.Step> changed =
                new ArrayList<>(model.uidSelectors);
        RootIsolatedUidOnlyPolicyPlan.Step prev = changed.get(0);
        changed.set(0, new RootIsolatedUidOnlyPolicyPlan.Step(prev.family,
                prev.kind, prev.add.replace("10341", "10343"),
                prev.remove.replace("10341", "10343")));
        RootIsolatedUidOnlyPolicyPlan.Plan altered =
                new RootIsolatedUidOnlyPolicyPlan.Plan(model.blockers, changed,
                        model.assignedApps, model.selectedExits);
        RootIsolatedUidPolicyJournalCodec changedCodec =
                new RootIsolatedUidPolicyJournalCodec(altered);
        reject(() -> changedCodec.decode(snapshot),
                "Reassigned app UIDs invalidate pending kernel ownership.");

        System.out.println("RootIsolatedUidPolicyJournalCodecTest passed");
    }
}
