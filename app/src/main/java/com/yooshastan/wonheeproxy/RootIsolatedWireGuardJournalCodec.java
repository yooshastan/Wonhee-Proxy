package com.yooshastan.wonheeproxy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Rootless, sensitive-data-free durable journal encoding for the isolated
 * kernel bootstrap transaction. Only indexes and PENDING/APPLIED states are
 * stored; commands, endpoints, WireGuard keys and profiles NEVER enter
 * SharedPreferences.
 *
 * Every recovery must reconstruct and authenticate exactly the same
 * bootstrap plan from locally encrypted profiles. A changed profile or a
 * partial/corrupt ledger is REFUSED, not silently adopted or reset.
 */
final class RootIsolatedWireGuardJournalCodec {
    static final class Entry {
        final RootIsolatedWireGuardBootstrapPlan.Step step;
        final int index;
        final boolean applied;

        Entry(RootIsolatedWireGuardBootstrapPlan.Step step,
                int index, boolean applied) {
            this.step = step;
            this.index = index;
            this.applied = applied;
        }
    }

    private static final String VERSION = "WNI1";
    private final List<RootIsolatedWireGuardBootstrapPlan.Step> steps;
    private final String fingerprint;

    RootIsolatedWireGuardJournalCodec(RootIsolatedWireGuardBootstrapPlan.Plan plan) {
        if (plan == null || plan.steps.isEmpty()) {
            throw new IllegalArgumentException("Missing immutable bootstrap plan.");
        }
        steps = plan.steps;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (RootIsolatedWireGuardBootstrapPlan.Step step : steps) {
                if (step == null || step.kind == null || step.device == null
                        || step.install == null || step.inverse == null) {
                    throw new IllegalArgumentException("Invalid bootstrap identity.");
                }
                for (String field : new String[] {
                        step.kind, step.device, step.install, step.inverse }) {
                    // Length prefix prevents ambiguity when a field has a delimiter.
                    byte[] b = field.getBytes(StandardCharsets.UTF_8);
                    sha.update((byte) (b.length >>> 24));
                    sha.update((byte) (b.length >>> 16));
                    sha.update((byte) (b.length >>> 8));
                    sha.update((byte) b.length);
                    sha.update(b);
                }
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : sha.digest()) {
                hex.append(Character.forDigit((b >>> 4) & 15, 16));
                hex.append(Character.forDigit(b & 15, 16));
            }
            fingerprint = hex.toString();
        } catch (IllegalArgumentException refused) {
            throw refused;
        } catch (Exception noDigest) {
            throw new IllegalStateException("Plan fingerprint unavailable.");
        }
    }

    List<Entry> decode(String text) {
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        String[] parts = text.split("\\|", -1);
        if (parts.length != 3 || !VERSION.equals(parts[0])
                || !fingerprint.equals(parts[1]) || parts[2].isEmpty()) {
            throw new IllegalStateException("Bootstrap journal identity mismatch.");
        }
        String[] tokens = parts[2].split(",", -1);
        if (tokens.length > steps.size()) {
            throw new IllegalStateException("Bootstrap journal exceeds planned steps.");
        }
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < tokens.length; i++) {
            if (!tokens[i].equals(i + "P") && !tokens[i].equals(i + "A")) {
                throw new IllegalStateException("Bootstrap journal sequence corrupt.");
            }
            if (i + 1 < tokens.length && tokens[i].endsWith("P")) {
                throw new IllegalStateException("Earlier WireGuard startup stage uncommitted.");
            }
            entries.add(new Entry(steps.get(i), i, tokens[i].endsWith("A")));
        }
        return Collections.unmodifiableList(entries);
    }

    String encode(List<Entry> entries) {
        if (entries == null) throw new IllegalArgumentException("No journal entries.");
        if (entries.isEmpty()) return "";
        if (entries.size() > steps.size()) {
            throw new IllegalArgumentException("Journal exceeds planned operations.");
        }
        StringBuilder result = new StringBuilder(VERSION)
                .append('|').append(fingerprint).append('|');
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            if (e == null || e.index != i || e.step != steps.get(i)) {
                throw new IllegalArgumentException("Journal entries do not match plan.");
            }
            if (i > 0) result.append(',');
            result.append(i).append(e.applied ? 'A' : 'P');
        }
        return result.toString();
    }

    List<Entry> beforeMutation(List<Entry> previous,
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        String existing = encode(previous); // validates plan and ordering.
        List<Entry> entries = new ArrayList<>(decode(existing));
        int next = entries.size();
        if (next >= steps.size() || steps.get(next) != step) {
            throw new IllegalStateException("Bootstrap step out of order.");
        }
        entries.add(new Entry(step, next, false));
        return Collections.unmodifiableList(entries);
    }

    List<Entry> committed(List<Entry> previous,
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        String existing = encode(previous);
        List<Entry> entries = new ArrayList<>(decode(existing));
        int last = entries.size() - 1;
        if (last < 0 || steps.get(last) != step || entries.get(last).applied) {
            throw new IllegalStateException("Unknown or duplicate commit.");
        }
        entries.set(last, new Entry(step, last, true));
        return Collections.unmodifiableList(entries);
    }

    List<Entry> clearExact(List<Entry> previous,
            RootIsolatedWireGuardBootstrapPlan.Step step) {
        String existing = encode(previous);
        List<Entry> entries = new ArrayList<>(decode(existing));
        int last = entries.size() - 1;
        if (last < 0 || steps.get(last) != step) {
            throw new IllegalStateException("Only the last exact-owned step may clear.");
        }
        entries.remove(last);
        return Collections.unmodifiableList(entries);
    }
}
