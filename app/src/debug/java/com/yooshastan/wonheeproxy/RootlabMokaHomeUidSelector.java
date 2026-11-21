package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.provider.Settings;
import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * EXPERIMENTAL live, opt-in Moka UID -> private Home /32 selector.
 *
 * No app/DNS policy or general device routing. Requires both Moka-only
 * IPv4/IPv6 OUTPUT guards, exact private Home route and unreachable terminal
 * installed and owned. A selector is written LAST and recovered FIRST.
 *
 * Even a verified route-get lookup is not proof that Moka packets traverse
 * the tunnel or that all Android socket marking paths are covered. This is
 * a rooted device test only; never silently enable it in a production build.
 */
final class RootlabMokaHomeUidSelector {
    private static final String PREF = "wonhee_rootlab_moka_home_uid_selector_v1";
    private static final String KEY = "pending";
    private static final String LAST_OUTCOME = "last_outcome";
    private static final String VERSION = "WMHR1";
    private final Context app;

    RootlabMokaHomeUidSelector(Context context) {
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

    String lastOutcome() {
        return prefs().getString(LAST_OUTCOME, "NEVER_REQUESTED");
    }

    void noteRefusal(String reason) {
        if (reason == null || !reason.matches("[A-Z_]{3,64}")) {
            throw new IllegalArgumentException("Invalid diagnostic refusal code.");
        }
        persistOutcome("REFUSED_" + reason);
    }

    private void persistOutcome(String status) {
        if (!prefs().edit().putString(LAST_OUTCOME, status).commit()) {
            throw new IllegalStateException("Cannot persist redacted UID selector outcome.");
        }
    }

    private RootMokaHomeRouteSafetyPlan.Plan journalPlan() {
        String raw = prefs().getString(KEY, null);
        if (raw == null) return null;
        String[] p = raw.split("\\|", -1);
        if (p.length != 3 || !VERSION.equals(p[0])
                || !p[1].matches("[1-9][0-9]{4}")
                || !p[2].matches("wnm[0-9a-f]{12}")) {
            throw new IllegalStateException("Unknown Moka Home UID selector journal.");
        }
        return RootMokaHomeRouteSafetyPlan.compile(
                Integer.parseInt(p[1]), p[2]);
    }

    private void commitIntent(RootMokaHomeRouteSafetyPlan.Plan plan) {
        String value = VERSION + "|" + plan.uid + "|" + plan.homeDevice;
        if (!prefs().edit().putString(KEY, value).commit()
                || !value.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("Cannot persist exact Moka UID rule intent.");
        }
    }

    private void clearExact() {
        if (!prefs().edit().remove(KEY).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("UID selector journal cleanup failed.");
        }
    }

    private static RootMokaHomeUidRuleEvidence.Snapshot inspect(RootShell shell,
            int uid) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, "ip -4 rule show") != 0 || lines.isEmpty()) {
            throw new IllegalStateException("Cannot inspect Android IPv4 policy rules.");
        }
        return RootMokaHomeUidRuleEvidence.inspect(String.join("\n", lines), uid);
    }

    private static void requireCellularPhysical(Context context) {
        if (!"off".equals(Settings.Global.getString(
                context.getContentResolver(), "private_dns_mode"))) {
            throw new IllegalStateException("Android Private DNS must remain OFF.");
        }
        ConnectivityManager manager = (ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) throw new IllegalStateException("Network service missing.");
        Network active = manager.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null
                : manager.getNetworkCapabilities(active);
        if (caps == null || !caps.hasTransport(
                NetworkCapabilities.TRANSPORT_CELLULAR)
                || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new IllegalStateException(
                    "Opt-in Moka selector requires active cellular with no Android VPN.");
        }
    }

    private static void requireFirstOutputHook(RootShell shell, int uid,
            int family) throws Exception {
        List<String> lines = new ArrayList<>();
        String cmd = family == 4 ? "iptables" : "ip6tables";
        if (shell.run(lines, cmd + " -w -t filter -S OUTPUT") != 0) {
            throw new IllegalStateException("Cannot verify firewall hook ordering.");
        }
        String chain = family == 4
                ? RootMokaHomeFirewallPilotPlan.CHAIN4
                : RootMokaHomeFirewallPilotPlan.CHAIN6;
        String tag = family == 4
                ? RootMokaHomeFirewallPilotPlan.TAG4
                : RootMokaHomeFirewallPilotPlan.TAG6;
        String expected = "-A OUTPUT -m owner --uid-owner " + uid
                + " -m comment --comment " + tag + " -j " + chain;
        for (String raw : lines) {
            String line = raw.trim().replace("\"", "")
                    .replaceAll("\\s+", " ");
            if (!line.startsWith("-A OUTPUT ")) continue;
            if (!line.equals(expected)) {
                throw new IllegalStateException("Moka IPv" + family
                        + " hook not first in OUTPUT; do not enable UID route.");
            }
            return;
        }
        throw new IllegalStateException("No Moka IPv" + family + " OUTPUT hook.");
    }

    static final class Lookup {
        final boolean home;
        final String summary;
        Lookup(boolean home, String summary) {
            this.home = home;
            this.summary = summary;
        }
    }

    private static Lookup lookup(RootShell shell, int uid, String device)
            throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, "ip -4 route get 10.0.0.169 uid " + uid) != 0
                || lines.isEmpty()) {
            return new Lookup(false, "UNAVAILABLE");
        }
        String route = " " + String.join(" ", lines)
                .replaceAll("\\s+", " ").trim() + " ";
        boolean home = route.contains(" dev " + device + " ")
                && route.contains(" table 51002 ");
        String selection = home ? "HOME_TABLE_51002"
                : route.contains(" dev rmnet") ? "CELLULAR_SELECTED"
                : "NOT_VERIFIED_HOME";
        return new Lookup(home, selection);
    }

    /**
     * On-device selector experiment. If a synthetic lookup doesn't select
     * the Home table immediately, roll the selector back before returning.
     */
    String activate(int uid, String device) throws Exception {
        if (pendingOrUnknown(app)) {
            noteRefusal("PREEXISTING_JOURNAL");
            return "MOKA HOME UID ROUTE REFUSED: previous journal needs Safe Stop.";
        }
        try {
            requireCellularPhysical(app);
        } catch (IllegalStateException preflight) {
            String code = preflight.getMessage() != null
                    && preflight.getMessage().contains("Private DNS")
                    ? "PRIVATE_DNS_NOT_OFF" : "CELLULAR_REQUIRED";
            noteRefusal(code);
            return "MOKA HOME UID ROUTE REFUSED: " + code
                    + ". No UID policy was installed.";
        }
        RootMokaHomeRouteSafetyPlan.Plan plan =
                RootMokaHomeRouteSafetyPlan.compile(uid, device);
        RootlabMokaIpv4OutputTest guard4 = new RootlabMokaIpv4OutputTest(app);
        RootlabMokaIpv6OutputTest guard6 = new RootlabMokaIpv6OutputTest(app);
        if (!guard4.exactAttached(uid, device)
                || !guard6.exactAttached(uid, device)
                || !new RootlabDetachedMokaFirewall(app)
                        .exactStagingPresentWithVerifiedDualHooks(uid, device)
                || !new RootlabMokaHomeTerminalRoute(app)
                        .exactStaged(uid, device)) {
            noteRefusal("DUAL_STACK_OR_HOME_TERMINAL_MISSING");
            return "MOKA HOME UID ROUTE REFUSED: dual-stack guards, "
                    + "Home route and exact unreachable terminal required.";
        }

        RootShell shell = new RootShell(app);
        shell.start();
        try {
            requireFirstOutputHook(shell, uid, 4);
            requireFirstOutputHook(shell, uid, 6);
        } catch (IllegalStateException invalidHook) {
            noteRefusal("OUTPUT_HOOK_ORDER");
            return "MOKA HOME UID ROUTE REFUSED: OUTPUT_HOOK_ORDER. "
                    + "No UID policy was installed.";
        }
        RootMokaHomeUidRuleEvidence.Snapshot before = inspect(shell, uid);
        if (before.conflict || before.exact != 0) {
            noteRefusal("POLICY_COLLISION");
            return "MOKA HOME UID ROUTE REFUSED: Android priority/table collision.";
        }
        try {
            commitIntent(plan); // durable intent BEFORE making app routing visible
            persistOutcome("ACTIVATING");
            if (shell.run(null, plan.candidateSelector) != 0) {
                throw new IllegalStateException("Android UID rule insertion failed.");
            }
            RootMokaHomeUidRuleEvidence.Snapshot after = inspect(shell, uid);
            Lookup observed = lookup(shell, uid, device);
            boolean protectionsStillOwned = guard4.exactAttached(uid, device)
                    && guard6.exactAttached(uid, device)
                    && new RootlabMokaHomeTerminalRoute(app)
                            .exactStaged(uid, device);
            requireFirstOutputHook(shell, uid, 4);
            requireFirstOutputHook(shell, uid, 6);
            requireCellularPhysical(app);
            if (after.conflict || after.exact != 1 || !observed.home
                    || !protectionsStillOwned) {
                throw new IllegalStateException(
                        "Moka UID rule installed but Home lookup not verified.");
            }
            persistOutcome("ACTIVE_VERIFIED");
            return "MOKA HOME UID ROUTE ATTACHED (DEVICE EXPERIMENT)\n"
                    + "Exact UID " + uid + ", 10.0.0.169/32, priority 12700, "
                    + "private table 51002: VERIFIED\n"
                    + "Synthetic UID lookup: " + observed.summary + "\n"
                    + "IPv4 and IPv6 Moka OUTPUT guards remained attached.\n"
                    + "Now attempt Navidrome in Moka over cellular and "
                    + "check firewall counters; other apps should be unchanged.\n"
                    + "NOT YET PROVEN: actual socket delivery, cellular "
                    + "fallback on Home loss, DNS and Android mark variations.\n"
                    + "Use Exact-owned Safe Stop immediately after the test.";
        } catch (Exception error) {
            String cleanup = recover();
            persistOutcome(pendingOrUnknown(app)
                    ? "RECOVERY_PAUSED" : "ROLLED_BACK");
            return "MOKA HOME UID ROUTE FAILED ("
                    + error.getClass().getSimpleName() + "): " + cleanup;
        }
    }

    String audit() throws Exception {
        RootMokaHomeRouteSafetyPlan.Plan plan = journalPlan();
        if (plan == null) {
            return "MOKA HOME UID AUDIT: no owned UID selector journal.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        RootMokaHomeUidRuleEvidence.Snapshot rule = inspect(shell, plan.uid);
        Lookup path = lookup(shell, plan.uid, plan.homeDevice);
        boolean guard = new RootlabMokaIpv4OutputTest(app)
                .exactAttached(plan.uid, plan.homeDevice)
                && new RootlabMokaIpv6OutputTest(app)
                        .exactAttached(plan.uid, plan.homeDevice);
        return "MOKA HOME UID ROUTE AUDIT (READ ONLY)\n"
                + "Exact UID rule: "
                + (rule.exact == 1 && !rule.conflict ? "VERIFIED" : "UNKNOWN") + "\n"
                + "Synthetic UID route: " + path.summary + "\n"
                + "Dual-stack Moka firewall hooks: "
                + (guard ? "BOTH PRESENT" : "UNVERIFIED") + "\n"
                + "This is NOT proof of application packet delivery "
                + "or Home-loss fail-closed behavior. "
                + "After testing Moka, run Exact-owned Safe Stop.";
    }

    String recover() throws Exception {
        RootMokaHomeRouteSafetyPlan.Plan plan = journalPlan();
        if (plan == null) return "MOKA HOME UID ROUTE: no owned selector journal.";
        RootShell shell = new RootShell(app);
        shell.start();
        try {
            RootMokaHomeUidRuleEvidence.Snapshot state = inspect(shell, plan.uid);
            if (state.conflict || state.exact > 1) {
                throw new IllegalStateException("Foreign/changed UID route.");
            }
            if (state.exact == 1) {
                String inverse = plan.candidateSelector.replace(
                        " rule add ", " rule del ");
                if (shell.run(null, inverse) != 0) {
                    throw new IllegalStateException("Exact UID rule inverse failed.");
                }
            }
            RootMokaHomeUidRuleEvidence.Snapshot after = inspect(shell, plan.uid);
            if (after.conflict || after.exact != 0) {
                throw new IllegalStateException("UID selector remains or changed.");
            }
            clearExact();
            persistOutcome("CLEAN_STOPPED");
            return "MOKA HOME UID ROUTE CLEAN_STOPPED; selector journal=0; "
                    + "reserved priority 12700 and private-table selector absent.";
        } catch (Exception uncertain) {
            // Preserve the original exact-owned journal; never treat an
            // inconclusive inverse as success.
            try { persistOutcome("RECOVERY_PAUSED"); }
            catch (IllegalStateException ignored) { /* report pause */ }
            return "MOKA HOME UID ROUTE RECOVERY PAUSED; journal retained. "
                    + "Do not uninstall or clear app data.";
        }
    }
}
