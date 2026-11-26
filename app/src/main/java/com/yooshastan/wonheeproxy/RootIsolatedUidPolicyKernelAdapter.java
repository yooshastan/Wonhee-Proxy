package com.yooshastan.wonheeproxy;

import com.wireguard.android.util.RootShell;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Live-capable but UNWIRED Android UID-rule adapter. It is only usable by a
 * future, exact-owned policy transaction after an independent physical
 * underlay, DNS, UID-identity and per-exit no-fallback SafetyGate.
 *
 * The current app deliberately does NOT instantiate this class. No new
 * fwmarks or iptables chains are allocated; existing Android policy is never
 * overwritten, flushed or considered Wonhee-owned based on name alone.
 */
final class RootIsolatedUidPolicyKernelAdapter
        implements RootIsolatedUidPolicyTransaction.Kernel {

    interface SafetyGate {
        void proveConnectedExitsDnsAndFailClosed() throws Exception;
    }

    private static final Pattern BLOCK = Pattern.compile(
            "^ip -([46]) route add unreachable default table (5100[0-7]) metric 42700$");
    private static final Pattern UID = Pattern.compile(
            "^ip -([46]) rule add pref (12[89][0-9]{2})"
            + " fwmark 0x0/0x20000 iif lo uidrange"
            + " ([1-9][0-9]{4})-([1-9][0-9]{4}) lookup (5100[0-7])$");

    private final RootShell shell;
    private final SafetyGate gate;
    private boolean approved;

    RootIsolatedUidPolicyKernelAdapter(RootShell shell, SafetyGate gate) {
        if (shell == null || gate == null) {
            throw new IllegalArgumentException("Verified UID routing gate required.");
        }
        this.shell = shell;
        this.gate = gate;
    }

    @Override public void requireFailClosedPreflight() throws Exception {
        approved = false;
        // A plan that says "unreachable" is NOT a no-leak proof.
        // The gate MUST independently prove both families, actual app UID
        // ownership, encrypted DNS, protected WireGuard transport packets,
        // and that this Android build honors the terminal route.
        gate.proveConnectedExitsDnsAndFailClosed();
        shell.start();
        for (int family : new int[] {4, 6}) {
            List<String> listing = read("ip -" + family + " rule show");
            for (String line : listing) {
                if (line.trim().matches("^12[89][0-9]{2}:.*")) {
                    throw new IllegalStateException(
                            "Foreign or orphan UID routing priority exists.");
                }
            }
        }
        approved = true;
    }

    @Override public RootIsolatedUidPolicyTransaction.Presence inspect(
            RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception {
        if (!RootIsolatedUidPolicyTransaction.safeStep(step)) {
            return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        RootIsolatedUidPolicyListing.Match result;
        if ("TERMINAL_ROUTE".equals(step.kind)) {
            Matcher m = BLOCK.matcher(step.add);
            if (!m.matches() || Integer.parseInt(m.group(1)) != step.family) {
                return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            result = RootIsolatedUidPolicyListing.terminalDefault(
                    String.join("\n", read("ip -" + step.family
                            + " route show table " + m.group(2))), step.family);
        } else if ("APP_UID".equals(step.kind)) {
            Matcher m = UID.matcher(step.add);
            if (!m.matches()
                    || Integer.parseInt(m.group(1)) != step.family
                    || !m.group(3).equals(m.group(4))) {
                return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            result = RootIsolatedUidPolicyListing.selector(
                    String.join("\n", read("ip -" + step.family + " rule show")),
                    step.family, Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)), Integer.parseInt(m.group(5)));
        } else {
            return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        switch (result) {
            case EXACT: return RootIsolatedUidPolicyTransaction.Presence.EXACT_OWNED;
            case ABSENT: return RootIsolatedUidPolicyTransaction.Presence.ABSENT;
            default: return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
        }
    }

    @Override public void apply(RootIsolatedUidOnlyPolicyPlan.Step step)
            throws Exception {
        if (!approved || !RootIsolatedUidPolicyTransaction.safeStep(step)) {
            throw new IllegalStateException("UID rule installation not authorized.");
        }
        if (inspect(step) != RootIsolatedUidPolicyTransaction.Presence.ABSENT) {
            throw new IllegalStateException("UID rule collision before install.");
        }
        requireSuccess(step.add);
        if (inspect(step) != RootIsolatedUidPolicyTransaction.Presence.EXACT_OWNED) {
            throw new IllegalStateException("UID policy kernel readback mismatch.");
        }
    }

    @Override public void undo(RootIsolatedUidOnlyPolicyPlan.Step step)
            throws Exception {
        if (!RootIsolatedUidPolicyTransaction.safeStep(step)
                || inspect(step) != RootIsolatedUidPolicyTransaction.Presence.EXACT_OWNED) {
            throw new IllegalStateException("Unknown UID rule is not owned by Wonhee.");
        }
        // Transaction's durable journal and LIFO cleanup order must already
        // have been checked; never enumerate/remove a broad rule range.
        requireSuccess(step.remove);
    }

    private List<String> read(String command) throws Exception {
        List<String> output = new ArrayList<>();
        if (shell.run(output, command) != 0) {
            throw new IllegalStateException("UID policy kernel readback unavailable.");
        }
        return output;
    }

    private void requireSuccess(String command) throws Exception {
        if (shell.run(null, command) != 0) {
            throw new IllegalStateException("Exact UID rule operation failed.");
        }
    }
}
