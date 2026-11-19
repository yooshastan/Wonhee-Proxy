package com.yooshastan.wonheeproxy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Metadata-only durable UID policy journal format. A fingerprint of all
 * exact rule command forms binds recovery to the same unchanged proposal.
 * No app package names, endpoint IPs or WireGuard secrets are persisted.
 */
final class RootIsolatedUidPolicyJournalCodec {
    static final class Entry {
        final int index;
        final boolean applied;
        final RootIsolatedUidOnlyPolicyPlan.Step step;

        Entry(int index, boolean applied, RootIsolatedUidOnlyPolicyPlan.Step step) {
            this.index = index;
            this.applied = applied;
            this.step = step;
        }
    }

    private static final String VERSION = "WNUP1";
    private final List<RootIsolatedUidOnlyPolicyPlan.Step> steps;
    private final String fingerprint;

    RootIsolatedUidPolicyJournalCodec(RootIsolatedUidOnlyPolicyPlan.Plan plan) {
        if (plan == null || plan.startOrder().isEmpty()) {
            throw new IllegalArgumentException("No immutable UID policy plan.");
        }
        steps = plan.startOrder();
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            for (RootIsolatedUidOnlyPolicyPlan.Step step : steps) {
                if (!RootIsolatedUidPolicyTransaction.safeStep(step)) {
                    throw new IllegalArgumentException("Invalid UID policy ledger operation.");
                }
                for (String field : new String[]{
                        String.valueOf(step.family), step.kind, step.add, step.remove}) {
                    byte[] data = field.getBytes(StandardCharsets.UTF_8);
                    int length = data.length;
                    hash.update((byte)(length >>> 24));
                    hash.update((byte)(length >>> 16));
                    hash.update((byte)(length >>> 8));
                    hash.update((byte)length);
                    hash.update(data);
                }
            }
            StringBuilder encoded = new StringBuilder();
            for (byte b : hash.digest()) {
                encoded.append(Character.forDigit((b >>> 4) & 15, 16));
                encoded.append(Character.forDigit(b & 15, 16));
            }
            fingerprint = encoded.toString();
        } catch (IllegalArgumentException rejected) {
            throw rejected;
        } catch (Exception unavailable) {
            throw new IllegalStateException("UID policy journal hash unavailable.");
        }
    }

    List<Entry> decode(String record) {
        if (record == null || record.isEmpty()) return Collections.emptyList();
        String[] parts = record.split("\\|", -1);
        if (parts.length != 3 || !VERSION.equals(parts[0])
                || !fingerprint.equals(parts[1]) || parts[2].isEmpty()) {
            throw new IllegalStateException("Unknown UID policy journal identity.");
        }
        String[] states = parts[2].split(",", -1);
        if (states.length > steps.size()) {
            throw new IllegalStateException("UID policy journal sequence too long.");
        }
        List<Entry> out = new ArrayList<>();
        for (int i = 0; i < states.length; i++) {
            if (!states[i].equals(i + "P") && !states[i].equals(i + "A")) {
                throw new IllegalStateException("UID policy journal sequence corrupt.");
            }
            // Only the final in-flight stage may be PENDING. All earlier
            // stages must have committed; otherwise the record is corrupt.
            if (i + 1 < states.length && states[i].endsWith("P")) {
                throw new IllegalStateException("Earlier UID policy journal stage uncommitted.");
            }
            out.add(new Entry(i, states[i].endsWith("A"), steps.get(i)));
        }
        return Collections.unmodifiableList(out);
    }

    String encode(List<Entry> entries) {
        if (entries == null || entries.size() > steps.size()) {
            throw new IllegalArgumentException("Invalid UID journal size.");
        }
        if (entries.isEmpty()) return "";
        StringBuilder out = new StringBuilder(VERSION).append('|')
                .append(fingerprint).append('|');
        for (int i = 0; i < entries.size(); i++) {
            Entry item = entries.get(i);
            if (item == null || item.index != i || item.step != steps.get(i)) {
                throw new IllegalArgumentException("UID journal and plan disagree.");
            }
            if (i > 0) out.append(',');
            out.append(i).append(item.applied ? 'A' : 'P');
        }
        return out.toString();
    }

    List<Entry> intent(List<Entry> previous, RootIsolatedUidOnlyPolicyPlan.Step next) {
        List<Entry> out = new ArrayList<>(decode(encode(previous)));
        int index = out.size();
        if (index == steps.size() || steps.get(index) != next) {
            throw new IllegalStateException("UID policy stage out of sequence.");
        }
        out.add(new Entry(index, false, next));
        return Collections.unmodifiableList(out);
    }

    List<Entry> applied(List<Entry> previous, RootIsolatedUidOnlyPolicyPlan.Step last) {
        List<Entry> out = new ArrayList<>(decode(encode(previous)));
        int index = out.size() - 1;
        if (index < 0 || steps.get(index) != last || out.get(index).applied) {
            throw new IllegalStateException("Unknown/duplicate UID commit.");
        }
        out.set(index, new Entry(index, true, last));
        return Collections.unmodifiableList(out);
    }

    List<Entry> clearLast(List<Entry> previous, RootIsolatedUidOnlyPolicyPlan.Step last) {
        List<Entry> out = new ArrayList<>(decode(encode(previous)));
        int index = out.size() - 1;
        if (index < 0 || steps.get(index) != last) {
            throw new IllegalStateException("Out-of-order UID policy cleanup.");
        }
        out.remove(index);
        return Collections.unmodifiableList(out);
    }
}
