package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * UID policy counterpart of the existing WireGuard journal. All writes use
 * synchronous commit; no root operation is allowed without a durable intent.
 *
 * NO instance is created by Home Start or Safe Stop until an on-device,
 * independently verified fail-closed and DNS safety gate exists.
 */
final class RootIsolatedUidPolicyPreferencesJournal
        implements RootIsolatedUidPolicyTransaction.Journal {
    private static final String PREFS = "wonhee_isolated_uid_ownership_v1";
    private static final String KEY = "pending_or_installed_uid_rules_v1";

    private final SharedPreferences prefs;
    private final RootIsolatedUidPolicyJournalCodec codec;

    RootIsolatedUidPolicyPreferencesJournal(Context context,
            RootIsolatedUidOnlyPolicyPlan.Plan plan) {
        if (context == null || plan == null) {
            throw new IllegalArgumentException("Application and policy required.");
        }
        prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        codec = new RootIsolatedUidPolicyJournalCodec(plan);
    }

    static boolean pendingOrUnknown(Context context) {
        if (context == null) return true;
        try {
            SharedPreferences prefs = context.getApplicationContext()
                    .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            if (!prefs.contains(KEY)) return false;
            String raw = prefs.getString(KEY, null);
            return raw == null || !raw.isEmpty();
        } catch (RuntimeException uncertain) {
            return true;
        }
    }

    private List<RootIsolatedUidPolicyJournalCodec.Entry> read() {
        return codec.decode(prefs.getString(KEY, ""));
    }

    private void persist(List<RootIsolatedUidPolicyJournalCodec.Entry> entries) {
        String encoded = codec.encode(entries);
        if (!prefs.edit().putString(KEY, encoded).commit()
                || !encoded.equals(prefs.getString(KEY, null))) {
            throw new IllegalStateException("UID rule journal not durably committed.");
        }
    }

    @Override public synchronized boolean empty() {
        return read().isEmpty();
    }

    @Override public synchronized void recordIntent(
            RootIsolatedUidOnlyPolicyPlan.Step step) {
        persist(codec.intent(read(), step));
    }

    @Override public synchronized void recordApplied(
            RootIsolatedUidOnlyPolicyPlan.Step step) {
        persist(codec.applied(read(), step));
    }

    @Override public synchronized List<RootIsolatedUidOnlyPolicyPlan.Step> snapshot() {
        List<RootIsolatedUidOnlyPolicyPlan.Step> out = new ArrayList<>();
        for (RootIsolatedUidPolicyJournalCodec.Entry entry : read()) {
            out.add(entry.step);
        }
        return Collections.unmodifiableList(out);
    }

    @Override public synchronized void clearExact(
            RootIsolatedUidOnlyPolicyPlan.Step step) {
        persist(codec.clearLast(read(), step));
    }
}
