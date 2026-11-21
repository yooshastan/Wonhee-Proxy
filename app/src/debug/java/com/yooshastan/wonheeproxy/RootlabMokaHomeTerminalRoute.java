package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * Opt-in, debug-only, destination-scoped unreachable fallback test for
 * private Home routing table 51002. Does NOT create any Android UID selector.
 *
 * The extra high-metric unreachable /32 is installed alongside the existing
 * lower-metric Home link route. If the link disappears, it is intended to
 * prevent a future UID rule from falling through to cellular; that property
 * MUST STILL BE PROVED ON DEVICE BEFORE installing any UID rule.
 *
 * Exact-owned durable intent precedes kernel mutation. Recovery never removes
 * routes by broad name, destination-only filters or shared Android tables.
 */
final class RootlabMokaHomeTerminalRoute {
    private static final String PREF = "wonhee_rootlab_moka_home_terminal_v1";
    private static final String KEY = "pending";
    private static final String VERSION = "WMHT1";
    private final Context app;

    RootlabMokaHomeTerminalRoute(Context context) {
        app = context.getApplicationContext();
    }

    static boolean pendingOrUnknown(Context context) {
        try {
            return context.getApplicationContext()
                    .getSharedPreferences(PREF, Context.MODE_PRIVATE).contains(KEY);
        } catch (RuntimeException uncertain) {
            return true;
        }
    }

    private SharedPreferences prefs() {
        return app.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private RootMokaHomeRouteSafetyPlan.Plan load() {
        String raw = prefs().getString(KEY, null);
        if (raw == null) return null;
        String[] parts = raw.split("\\|", -1);
        if (parts.length != 3 || !VERSION.equals(parts[0])
                || !parts[1].matches("[1-9][0-9]{4}")
                || !parts[2].matches("wnm[0-9a-f]{12}")) {
            throw new IllegalStateException(
                    "Unrecognized Home terminal route journal; preserve app data.");
        }
        return RootMokaHomeRouteSafetyPlan.compile(
                Integer.parseInt(parts[1]), parts[2]);
    }

    private void commitIntent(RootMokaHomeRouteSafetyPlan.Plan plan) {
        String raw = VERSION + "|" + plan.uid + "|" + plan.homeDevice;
        if (!prefs().edit().putString(KEY, raw).commit()
                || !raw.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("Cannot persist Home route intent.");
        }
    }

    private void clearExact() {
        if (!prefs().edit().remove(KEY).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("Cannot clear owned terminal journal.");
        }
    }

    private static RootMokaHomeTerminalRouteEvidence.Snapshot inspect(
            RootShell shell, String device) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, "ip -4 route show table 51002") != 0) {
            throw new IllegalStateException("Cannot inspect private Home table.");
        }
        return RootMokaHomeTerminalRouteEvidence.inspect(
                String.join("\n", lines), device);
    }

    private static void requireNoUidSelector(RootShell shell) throws Exception {
        List<String> rules = new ArrayList<>();
        if (shell.run(rules, "ip -4 rule show") != 0 || rules.isEmpty()) {
            throw new IllegalStateException("Cannot audit Android UID selectors.");
        }
        for (String line : rules) {
            String value = line.trim().replaceAll("\\s+", " ");
            if (value.startsWith("12700:")
                    || value.matches(".*\\b(?:lookup|table) 51002\\b.*")) {
                throw new IllegalStateException(
                        "Existing Android rule controls the reserved Home table.");
            }
        }
    }

    /**
     * Confirm the stage journal was committed and both exact destination /32
     * routes still exist. A UID selector may be attached AFTER this check,
     * so do not infer anything about Android application routing here.
     */
    boolean exactStaged(int uid, String device) throws Exception {
        RootMokaHomeRouteSafetyPlan.Plan saved = load();
        if (saved == null || saved.uid != uid
                || !saved.homeDevice.equals(device)) return false;
        RootShell shell = new RootShell(app);
        shell.start();
        RootMokaHomeTerminalRouteEvidence.Snapshot state =
                inspect(shell, device);
        return state.homePresent && state.terminalPresent && !state.collision;
    }

    String stage(int uid, String device) throws Exception {
        if (pendingOrUnknown(app)) {
            return "MOKA HOME FALLBACK STAGE REFUSED: previous journal pending; "
                    + "run Exact-owned Safe Stop.";
        }
        RootMokaHomeRouteSafetyPlan.Plan plan =
                RootMokaHomeRouteSafetyPlan.compile(uid, device);
        if (!new RootlabMokaIpv4OutputTest(app).exactAttached(uid, device)
                || !new RootlabMokaIpv6OutputTest(app).exactAttached(uid, device)
                || !new RootlabDetachedMokaFirewall(app)
                        .exactStagingPresentWithVerifiedDualHooks(uid, device)) {
            return "MOKA HOME FALLBACK STAGE REFUSED: both exact-owned Moka "
                    + "firewall hooks and private chains must be active.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        requireNoUidSelector(shell);
        RootMokaHomeTerminalRouteEvidence.Snapshot before =
                inspect(shell, device);
        if (!before.homePresent || before.terminalPresent || before.collision) {
            return "MOKA HOME FALLBACK STAGE REFUSED: Home route missing, "
                    + "terminal already present, or private route collision.";
        }
        try {
            commitIntent(plan); // durable intent BEFORE ip route add
            if (shell.run(null, plan.candidateTerminal) != 0) {
                throw new IllegalStateException("Unable to install Home terminal.");
            }
            RootMokaHomeTerminalRouteEvidence.Snapshot after =
                    inspect(shell, device);
            if (!after.homePresent || !after.terminalPresent || after.collision) {
                throw new IllegalStateException(
                        "Home fallback terminal readback mismatched.");
            }
            return "MOKA HOME FALLBACK TERMINAL VERIFIED (ISOLATED)\n"
                    + "Table 51002: exact Home /32 route and high-metric "
                    + "unreachable 10.0.0.169/32 both observed.\n"
                    + "Verified UID: " + uid + "\n"
                    + "NO UID policy rule installed. Moka is NOT being routed "
                    + "through Home. This does NOT prove Home-loss packet "
                    + "blocking or Android rule precedence. "
                    + "Next run the read-only terminal audit, then "
                    + "Exact-owned Safe Stop.";
        } catch (Exception failed) {
            return "MOKA HOME FALLBACK STAGE FAILED ("
                    + failed.getClass().getSimpleName() + "). " + recover();
        }
    }

    String audit() throws Exception {
        RootMokaHomeRouteSafetyPlan.Plan plan = load();
        if (plan == null) {
            return "MOKA HOME FALLBACK AUDIT: no terminal route journal.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        requireNoUidSelector(shell);
        RootMokaHomeTerminalRouteEvidence.Snapshot state =
                inspect(shell, plan.homeDevice);
        return "MOKA HOME FALLBACK TABLE AUDIT (READ ONLY)\n"
                + "Private table: 51002; Moka UID " + plan.uid + "\n"
                + "Home 10.0.0.169/32 via owned interface: "
                    + (state.homePresent ? "OBSERVED" : "NOT PRESENT") + "\n"
                + "High-metric unreachable 10.0.0.169/32: "
                    + (state.terminalPresent ? "OBSERVED" : "NOT PRESENT") + "\n"
                + "Foreign/duplicate destination routes: "
                    + (state.collision ? "COLLISION" : "NONE OBSERVED") + "\n"
                + "No Android UID rule, DNS or Moka routing activated. "
                + "A private terminal route alone is NOT proof of "
                + "no cellular fallback. Use Exact-owned Safe Stop.";
    }

    String recover() throws Exception {
        RootMokaHomeRouteSafetyPlan.Plan plan = load();
        if (plan == null) return "MOKA HOME FALLBACK: no owned terminal journal.";
        RootShell shell = new RootShell(app);
        shell.start();
        try {
            RootMokaHomeTerminalRouteEvidence.Snapshot state =
                    inspect(shell, plan.homeDevice);
            if (state.collision) {
                throw new IllegalStateException(
                        "Foreign/changed Home route; retain journal.");
            }
            // A crash after durable intent but before 'ip route add' can
            // legitimately leave no terminal route to undo.
            if (state.terminalPresent) {
                String inverse = plan.candidateTerminal.replace(
                        " route add ", " route del ");
                if (shell.run(null, inverse) != 0) {
                    throw new IllegalStateException("Exact terminal inverse failed.");
                }
            }
            RootMokaHomeTerminalRouteEvidence.Snapshot after =
                    inspect(shell, plan.homeDevice);
            if (after.terminalPresent || after.collision) {
                throw new IllegalStateException("Terminal still present after rollback.");
            }
            clearExact();
            return "MOKA HOME FALLBACK CLEAN_STOPPED; terminal journal=0; "
                    + "no owned unreachable /32 remains.";
        } catch (Exception uncertain) {
            return "MOKA HOME FALLBACK RECOVERY PAUSED; journal retained. "
                    + "Do not uninstall or clear RootLab data.";
        }
    }
}
