package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * Opt-in, debug-only, exact-journaled firewall STAGING test.
 *
 * Creates two disconnected filter chains populated with restricted rules.
 * NEVER adds OUTPUT hooks or IP rules: Android app traffic remains untouched.
 * Unknown/stale ownership is retained for inspection rather than broad cleanup.
 */
final class RootlabDetachedMokaFirewall {
    private static final String PREF = "wonhee_rootlab_detached_moka_firewall_v1";
    private static final String KEY = "pending";
    private static final String VERSION = "WMH1";
    private final Context context;

    RootlabDetachedMokaFirewall(Context context) {
        this.context = context.getApplicationContext();
    }

    static boolean pendingOrUnknown(Context context) {
        try {
            SharedPreferences pref = context.getApplicationContext()
                    .getSharedPreferences(PREF, Context.MODE_PRIVATE);
            return pref.contains(KEY);
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static final class State {
        final RootMokaHomeFirewallPilotPlan.Plan plan;
        final int count;
        State(RootMokaHomeFirewallPilotPlan.Plan plan, int count) {
            this.plan = plan;
            this.count = count;
        }
    }

    private SharedPreferences prefs() {
        return context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private static List<RootMokaHomeFirewallPilotPlan.Step> detached(
            RootMokaHomeFirewallPilotPlan.Plan plan) {
        RootMokaHomeFirewallPilotTransaction.validate(plan);
        List<RootMokaHomeFirewallPilotPlan.Step> selected = new ArrayList<>();
        for (RootMokaHomeFirewallPilotPlan.Step step : plan.steps) {
            if ("OWNER_ANCHOR".equals(step.kind)) continue;
            selected.add(step);
        }
        if (selected.size() != 5) throw new IllegalStateException("Noncanonical stage.");
        return selected;
    }

    private State load() {
        String raw = prefs().getString(KEY, null);
        if (raw == null) return null;
        String[] tokens = raw.split("\\|", -1);
        if (tokens.length != 4 || !VERSION.equals(tokens[0])
                || !tokens[1].matches("[0-9]{5}")
                || !tokens[2].matches("wnm[0-9a-f]{12}")
                || !tokens[3].matches("[1-5]")) {
            throw new IllegalStateException("Unknown staged firewall journal; retain app data.");
        }
        RootMokaHomeFirewallPilotPlan.Plan plan =
                RootMokaHomeFirewallPilotPlan.compile(
                        Integer.parseInt(tokens[1]), tokens[2]);
        return new State(plan, Integer.parseInt(tokens[3]));
    }

    private void persist(RootMokaHomeFirewallPilotPlan.Plan plan, int count) {
        String entry = VERSION + "|" + plan.uid + "|" + plan.homeDevice + "|" + count;
        if (!prefs().edit().putString(KEY, entry).commit()
                || !entry.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("Staged firewall intent not durably stored.");
        }
    }

    private void clear() {
        if (!prefs().edit().remove(KEY).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("Staged firewall journal could not be cleared.");
        }
    }

    private static String chain(int family) {
        return family == 4 ? RootMokaHomeFirewallPilotPlan.CHAIN4
                : RootMokaHomeFirewallPilotPlan.CHAIN6;
    }
    private static String tool(int family) {
        return family == 4 ? "iptables" : "ip6tables";
    }

    private static List<String> read(RootShell shell, String command) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, command) != 0) {
            throw new IllegalStateException("Firewall inspection unavailable.");
        }
        return lines;
    }

    /** Examine full filter listing so foreign jumps into staging chains abort cleanup. */
    private static void requireDetached(RootShell shell, int family) throws Exception {
        String name = chain(family);
        String all = String.join("\n", read(shell, tool(family)
                + " -w -t filter -S"));
        for (String line : all.split("\n")) {
            if (!line.startsWith("-A " + name + " ")
                    && (line.contains(" -j " + name)
                        || line.contains(" -g " + name))) {
                throw new IllegalStateException(
                        "Staging chain referenced by a foreign firewall hook.");
            }
        }
    }

    private static boolean present(RootShell shell, int family) throws Exception {
        return shell.run(null, tool(family) + " -w -t filter -S "
                + chain(family) + " >/dev/null 2>&1") == 0;
    }

    private static boolean rulePresent(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Step step) throws Exception {
        // -C requires exact rule semantics; never rely on chain name alone.
        return shell.run(null, step.install.replace(" -A ", " -C ")
                + " >/dev/null 2>&1") == 0;
    }

    /**
     * Verify exact in-chain contents for the installed prefix, before any
     * operation. A partial -N before a crash is the only empty-chain case.
     */
    private static void verifyChain(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan, int family,
            int appliedSteps) throws Exception {
        List<RootMokaHomeFirewallPilotPlan.Step> stages = detached(plan);
        int expectedRules = 0;
        boolean shouldExist = false;
        for (int i = 0; i < appliedSteps; i++) {
            RootMokaHomeFirewallPilotPlan.Step step = stages.get(i);
            if (step.family != family) continue;
            if ("CHAIN".equals(step.kind)) shouldExist = true;
            else {
                expectedRules++;
                if (!rulePresent(shell, step)) {
                    throw new IllegalStateException("Owned firewall rule differs.");
                }
            }
        }
        if (present(shell, family) != shouldExist) {
            throw new IllegalStateException("Staging chain state differs.");
        }
        if (!shouldExist) return;
        List<String> listing = read(shell,
                tool(family) + " -w -t filter -S " + chain(family));
        int actualRules = 0;
        for (String line : listing) {
            if (line.startsWith("-A " + chain(family) + " ")) actualRules++;
            else if (!line.trim().equals("-N " + chain(family))) {
                throw new IllegalStateException("Unexpected chain listing.");
            }
        }
        if (actualRules != expectedRules) {
            throw new IllegalStateException("Foreign or missing staged rule.");
        }
    }

    private static void verifyPrefix(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan, int applied) throws Exception {
        requireDetached(shell, 4);
        requireDetached(shell, 6);
        verifyChain(shell, plan, 4, applied);
        verifyChain(shell, plan, 6, applied);
    }

    String stage(int uid, String device) throws Exception {
        if (pendingOrUnknown(context)) {
            return "DETACHED FIREWALL STAGE REFUSED: existing ownership journal; "
                    + "use Exact-owned Safe Stop first.";
        }
        RootMokaHomeFirewallPilotPlan.Plan plan =
                RootMokaHomeFirewallPilotPlan.compile(uid, device);
        List<RootMokaHomeFirewallPilotPlan.Step> stages = detached(plan);
        RootShell shell = new RootShell(context);
        shell.start();
        // Fail rather than adopt another process's chain.
        requireDetached(shell, 4);
        requireDetached(shell, 6);
        if (present(shell, 4) || present(shell, 6)) {
            return "DETACHED FIREWALL STAGE REFUSED: reserved chain already exists.";
        }
        for (int n = 0; n < stages.size(); n++) {
            try {
                verifyPrefix(shell, plan, n);
                RootMokaHomeFirewallPilotPlan.Step step = stages.get(n);
                persist(plan, n + 1); // write-ahead before ANY kernel mutation
                if (shell.run(null, step.install) != 0) {
                    throw new IllegalStateException("Staging operation failed.");
                }
                verifyPrefix(shell, plan, n + 1);
            } catch (Exception failure) {
                String recovered = recover();
                return "DETACHED STAGING FAILED (" + failure.getClass().getSimpleName()
                        + "). " + recovered;
            }
        }
        return "DETACHED FIREWALL STAGE VERIFIED: 5/5 rules/chain operations; "
                + "both private filter chains exist, IPv4 Home allow and IPv4/IPv6 "
                + "terminal REJECT listed. NO OUTPUT hooks or UID rules installed. "
                + "No Android app traffic is routed or filtered. "
                + "Use Exact-owned Safe Stop to recover.";
    }

    /** Read-only structural proof for the anchored IPv6 OUTPUT test. */
    boolean exactStagingPresent(int uid, String device) throws Exception {
        State state = load();
        if (state == null || state.count != 5
                || state.plan.uid != uid || !state.plan.homeDevice.equals(device)) {
            return false;
        }
        RootShell shell = new RootShell(context);
        shell.start();
        verifyPrefix(shell, state.plan, 5);
        return true;
    }

    String recover() throws Exception {
        State state = load();
        if (state == null) return "DETACHED FIREWALL: no ownership journal.";
        List<RootMokaHomeFirewallPilotPlan.Step> steps = detached(state.plan);
        RootShell shell = new RootShell(context);
        shell.start();
        for (int n = state.count - 1; n >= 0; n--) {
            RootMokaHomeFirewallPilotPlan.Step step = steps.get(n);
            try {
                requireDetached(shell, 4);
                requireDetached(shell, 6);
                // The highest step is intent-only after a crash; it may
                // exist OR be absent. All earlier stages must be exact.
                boolean installed = "CHAIN".equals(step.kind)
                        ? present(shell, step.family)
                        : rulePresent(shell, step);
                verifyPrefix(shell, state.plan, installed ? n + 1 : n);
                if (installed && shell.run(null, step.inverse) != 0) {
                    throw new IllegalStateException("Exact inverse failed.");
                }
                verifyPrefix(shell, state.plan, n);
                if (n == 0) clear();
                else persist(state.plan, n);
            } catch (Exception uncertain) {
                return "DETACHED FIREWALL RECOVERY PAUSED at stage " + (n + 1)
                        + "; journal retained; no OUTPUT hooks were intentionally "
                        + "installed. Do not clear app data.";
            }
        }
        return "DETACHED FIREWALL CLEAN_STOPPED; journal=0; "
                + "both pilot chains removed; OUTPUT unchanged.";
    }
}
