package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;

/**
 * Persistent metadata-only adapter for the isolated bootstrap transaction.
 *
 * NO Android Start/Stop code instantiates or activates this yet. A future
 * single-worker executor must serialize all journal/kernel calls, bind an
 * encrypted-profile fingerprint to the same immutable plan, and verify every
 * exact kernel object before undo. This record deliberately stores only
 * step indexes/states and the SHA-256 plan fingerprint, never keys/endpoints.
 */
final class RootIsolatedWireGuardPreferencesJournal
        implements RootIsolatedWireGuardTransaction.Journal {
    private static final String PREFS = "wonhee_isolated_bootstrap_ownership_v1";
    private static final String KEY = "pending_or_installed_steps_v1";

    private final SharedPreferences prefs;
    private final RootIsolatedWireGuardJournalCodec codec;

    RootIsolatedWireGuardPreferencesJournal(Context context,
            RootIsolatedWireGuardBootstrapPlan.Plan plan) {
        if (context == null) {
            throw new IllegalArgumentException("Application context required.");
        }
        prefs = context.getApplicationContext().getSharedPreferences(
                PREFS, Context.MODE_PRIVATE);
        codec = new RootIsolatedWireGuardJournalCodec(plan);
    }

    private List<RootIsolatedWireGuardJournalCodec.Entry> read() {
        // Corrupt or mismatched plan fingerprints throw. Do not silently reset.
        return codec.decode(prefs.getString(KEY, ""));
    }

    private void persist(List<RootIsolatedWireGuardJournalCodec.Entry> entries) {
        String next = codec.encode(entries);
        if (!prefs.edit().putString(KEY, next).commit()
                || !next.equals(prefs.getString(KEY, null))) {
            throw new IllegalStateException("Isolated bootstrap journal not durable.");
        }
    }

    @Override public synchronized boolean empty() {
        return read().isEmpty();
    }

    @Override public synchronized void beforeMutation(
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        persist(codec.beforeMutation(read(), step));
    }

    @Override public synchronized void committed(
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        persist(codec.committed(read(), step));
    }

    @Override public synchronized List<RootIsolatedWireGuardBootstrapPlan.Step> snapshot() {
        List<RootIsolatedWireGuardBootstrapPlan.Step> steps = new ArrayList<>();
        for (RootIsolatedWireGuardJournalCodec.Entry e : read()) {
            steps.add(e.step);
        }
        return java.util.Collections.unmodifiableList(steps);
    }

    @Override public synchronized void clearExact(
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        persist(codec.clearExact(read(), step));
    }
}
