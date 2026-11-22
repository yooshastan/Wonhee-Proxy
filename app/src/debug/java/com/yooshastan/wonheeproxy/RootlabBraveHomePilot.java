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
 * DEBUG-ONLY exact-owned Brave Nightly -> Navidrome /32 cellular experiment.
 * Both IP firewall hooks are installed BEFORE the UID selector. The only
 * allowed IPv4 connection is TCP/4533 via the exact Home WG interface.
 *
 * Activation does NOT establish Android socket-mark compatibility or prove
 * no-fallback after loss of Home. Never perform a deliberate Home-loss test.
 * Moka's own active UID selector/dual-stack hook + terminal must be staged.
 */
final class RootlabBraveHomePilot {
    private static final String PREF = "wonhee_rootlab_brave_home_pilot_v1";
    private static final String KEY = "pending";
    private static final String VERSION = "WBH1";
    private static final String PACKAGE = "com.brave.browser_nightly";
    private final Context app;

    RootlabBraveHomePilot(Context context) {
        app = context.getApplicationContext();
    }

    static boolean pendingOrUnknown(Context context) {
        try {
            return context.getApplicationContext()
                    .getSharedPreferences(PREF, Context.MODE_PRIVATE).contains(KEY);
        } catch (RuntimeException unknown) {
            return true;
        }
    }

    private SharedPreferences prefs() {
        return app.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private RootBraveHomePilotPlan saved() {
        String raw = prefs().getString(KEY, null);
        if (raw == null) return null;
        String[] p = raw.split("\\|", -1);
        if (p.length != 3 || !VERSION.equals(p[0])
                || !p[1].matches("[1-9][0-9]{4}")
                || !p[2].matches("wnm[0-9a-f]{12}")) {
            throw new IllegalStateException("Unrecognized Brave ownership journal.");
        }
        return RootBraveHomePilotPlan.compile(Integer.parseInt(p[1]), p[2]);
    }

    private void persist(RootBraveHomePilotPlan plan) {
        String raw = VERSION + "|" + plan.uid + "|" + plan.dev;
        if (!prefs().edit().putString(KEY, raw).commit()
                || !raw.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("Cannot persist Brave exact-owner intent.");
        }
    }

    private void clear() {
        if (!prefs().edit().remove(KEY).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("Brave ownership journal cleanup failed.");
        }
    }

    private static List<String> read(RootShell shell, String command) throws Exception {
        List<String> out = new ArrayList<>();
        if (shell.run(out, command) != 0) {
            throw new IllegalStateException("Brave safety inventory unavailable.");
        }
        return out;
    }

    private static String listing(RootShell shell, String command) throws Exception {
        return String.join("\n", read(shell, command));
    }

    private static String maybeChain(RootShell shell, String command) throws Exception {
        List<String> out = new ArrayList<>();
        int result = shell.run(out, command);
        if (result == 0) return String.join("\n", out);
        // A missing chain is permissible during intent-only/partial recovery.
        // Kernel failures are not reliably distinguishable from absence here,
        // so require fresh OUTPUT and a working root shell before using this.
        return null;
    }

    private static void run(RootShell shell, String command) throws Exception {
        if (shell.run(null, command) != 0) {
            throw new IllegalStateException("Exact-owned Brave kernel step refused.");
        }
    }

    private static int uid(RootShell shell, String pkg) throws Exception {
        List<String> lines = read(shell, "pm list packages -U " + pkg);
        String prefix = "package:" + pkg + " uid:";
        int seen = -1;
        for (String raw : lines) {
            String line = raw.trim();
            if (!line.startsWith(prefix)) continue;
            String tail = line.substring(prefix.length()).trim();
            if (!tail.matches("[1-9][0-9]{4}")) return -1;
            if (seen != -1) return -1;
            seen = Integer.parseInt(tail);
        }
        return seen;
    }

    private static void requireCellular(Context app) {
        if (!"off".equals(Settings.Global.getString(
                app.getContentResolver(), "private_dns_mode"))) {
            throw new IllegalStateException("Keep Android Private DNS OFF.");
        }
        ConnectivityManager cm = (ConnectivityManager)
                app.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network net = cm == null ? null : cm.getActiveNetwork();
        NetworkCapabilities caps = net == null ? null
                : cm.getNetworkCapabilities(net);
        if (caps == null
                || !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new IllegalStateException("Brave pilot requires cellular and no Android VPN.");
        }
    }

    private static boolean exactHook(RootShell shell,
            String family, String chain, String tag,
            String expected, boolean required) throws Exception {
        String listing = listing(shell, family + " -w -t filter -S OUTPUT");
        return RootBraveHomePilotPlan.onlyExactOutputHook(
                listing, chain, tag, expected, required);
    }

    private static int countRule(RootShell shell,
            RootBraveHomePilotPlan plan) throws Exception {
        return RootBraveHomePilotPlan.exactSelector(
                listing(shell, "ip -4 rule show"), plan.uid);
    }

    private static String counter(RootShell shell,
            String family, String chain, String target) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, family + " -w -t filter -L " + chain
                + " -n -v -x") != 0) return "UNAVAILABLE";
        try {
            RootMokaIpv6CounterParser.Counts counts =
                    RootMokaIpv6CounterParser.target(String.join("\n", lines), target);
            return counts.packets + " packets / " + counts.bytes + " bytes";
        } catch (IllegalArgumentException ambiguous) {
            return "MISSING_OR_AMBIGUOUS";
        }
    }

    private static boolean firstOutputHook(RootShell shell,
            String family, String expected) throws Exception {
        String listing = listing(shell, family + " -w -t filter -S OUTPUT");
        for (String raw : listing.split("\\r?\\n")) {
            String line = RootBraveHomePilotPlan.normalized(raw);
            if (line.startsWith("-A OUTPUT ")) return line.equals(expected);
        }
        return false;
    }

    private static boolean chainValid(RootShell shell, String family,
            String chain, String dev, boolean v4) throws Exception {
        String raw = maybeChain(shell, family + " -w -t filter -S " + chain);
        return raw == null || RootBraveHomePilotPlan.chainIsExactPrefix(
                raw, chain, dev, v4);
    }

    private static boolean chainExists(RootShell shell,
            String family, String chain) throws Exception {
        return shell.run(null, family + " -w -t filter -S " + chain
                + " >/dev/null 2>&1") == 0;
    }

    private static boolean exactRule(RootShell shell,
            String family, String chain, String command) throws Exception {
        return shell.run(null, family + " -w -t filter -C " + chain
                + command + " >/dev/null 2>&1") == 0;
    }

    private static void delIfPresent(RootShell shell,
            String family, String chain, String command) throws Exception {
        if (exactRule(shell, family, chain, command)) {
            run(shell, family + " -w -t filter -D " + chain + command);
        }
    }

    private static boolean verifyNoConflict(RootShell shell,
            RootBraveHomePilotPlan plan, int mokaUid) throws Exception {
        String all = listing(shell, "ip -4 rule show");
        if (RootBraveHomePilotPlan.exactSelector(all, plan.uid) != 0) return false;
        // The Home table may be selected ONLY by the exact already-verified
        // Moka rule (12700); all other references are foreign conflicts.
        RootMokaHomeUidRuleEvidence.Snapshot moka =
                RootMokaHomeUidRuleEvidence.inspect(all, mokaUid);
        if (moka.conflict || moka.exact != 1) return false;
        for (String raw : all.split("\\r?\\n")) {
            String line = RootBraveHomePilotPlan.normalized(raw);
            if (line.matches(".*\\b(?:lookup|table) 51002\\b.*")
                    && !line.startsWith("12700:")) return false;
        }
        return true;
    }

    private static String targetRoute(RootShell shell,
            RootBraveHomePilotPlan plan) throws Exception {
        List<String> lines = read(shell,
                "ip -4 route get 10.0.0.169 uid " + plan.uid);
        String route = " " + String.join(" ", lines).replaceAll("\\s+", " ") + " ";
        return route.contains(" dev " + plan.dev + " ")
                && route.contains(" table 51002 ")
                ? "SYNTHETIC_HOME" : "NOT_HOME";
    }

    String activate(int mokaUid, String homeDev) throws Exception {
        if (pendingOrUnknown(app)) {
            return "BRAVE HOME REFUSED: previous ownership journal; run Safe Stop.";
        }
        requireCellular(app);
        RootShell shell = new RootShell(app);
        shell.start();
        int braveUid = uid(shell, PACKAGE);
        if (braveUid < 10000 || braveUid == mokaUid) {
            return "BRAVE HOME REFUSED: unique Brave Nightly package UID not found.";
        }
        RootBraveHomePilotPlan plan =
                RootBraveHomePilotPlan.compile(braveUid, homeDev);
        if (!new RootlabMokaHomeTerminalRoute(app).exactStaged(mokaUid, homeDev)
                || !new RootlabMokaIpv4OutputTest(app)
                        .exactAttached(mokaUid, homeDev)
                || !new RootlabMokaIpv6OutputTest(app)
                        .exactAttached(mokaUid, homeDev)
                || !RootlabMokaHomeUidSelector.pendingOrUnknown(app)
                || !verifyNoConflict(shell, plan, mokaUid)) {
            return "BRAVE HOME REFUSED: Moka's verified selector, dual-stack "
                    + "guards and exact Home fallback must all remain active.";
        }
        if (chainExists(shell, "iptables", RootBraveHomePilotPlan.CHAIN4)
                || chainExists(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6)
                || !exactHook(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                        RootBraveHomePilotPlan.TAG4, plan.hook4, false)
                || !exactHook(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6,
                        RootBraveHomePilotPlan.TAG6, plan.hook6, false)) {
            return "BRAVE HOME REFUSED: reserved chain/hook collision.";
        }
        try {
            persist(plan); // one full transaction intent BEFORE first mutation
            run(shell, "ip6tables -w -t filter -N " + RootBraveHomePilotPlan.CHAIN6);
            run(shell, "ip6tables -w -t filter -A " + RootBraveHomePilotPlan.CHAIN6
                    + " -j REJECT");
            run(shell, "ip6tables -w -t filter -I OUTPUT 1 -m owner --uid-owner "
                    + braveUid + " -m comment --comment "
                    + RootBraveHomePilotPlan.TAG6 + " -j "
                    + RootBraveHomePilotPlan.CHAIN6);
            run(shell, "iptables -w -t filter -N " + RootBraveHomePilotPlan.CHAIN4);
            run(shell, "iptables -w -t filter -A " + RootBraveHomePilotPlan.CHAIN4
                    + " -o " + homeDev + " -d 10.0.0.169/32 -p tcp"
                    + " --dport 4533 -j RETURN");
            run(shell, "iptables -w -t filter -A " + RootBraveHomePilotPlan.CHAIN4
                    + " -j REJECT");
            run(shell, "iptables -w -t filter -I OUTPUT 1 -m owner --uid-owner "
                    + braveUid + " -m comment --comment "
                    + RootBraveHomePilotPlan.TAG4 + " -j "
                    + RootBraveHomePilotPlan.CHAIN4);

            // Routing last: at this point both firewall restrictions apply.
            requireCellular(app);
            if (!chainValid(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                    homeDev, true)
                    || !chainValid(shell, "ip6tables",
                    RootBraveHomePilotPlan.CHAIN6, homeDev, false)
                    || !exactHook(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                    RootBraveHomePilotPlan.TAG4, plan.hook4, true)
                    || !exactHook(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6,
                    RootBraveHomePilotPlan.TAG6, plan.hook6, true)
                    || !firstOutputHook(shell, "iptables", plan.hook4)
                    || !firstOutputHook(shell, "ip6tables", plan.hook6)) {
                throw new IllegalStateException("Brave guard readback failed.");
            }
            run(shell, plan.selector);
            if (countRule(shell, plan) != 1
                    || !"SYNTHETIC_HOME".equals(targetRoute(shell, plan))) {
                throw new IllegalStateException("Brave UID lookup did not select Home.");
            }
            return "BRAVE NIGHTLY HOME ROUTE ATTACHED (EXPERIMENT)\n"
                    + "Brave UID " + braveUid + "; 10.0.0.169:4533 via private "
                    + "table 51002: synthetic route VERIFIED.\n"
                    + "Exact IPv4 Home-only and IPv6 REJECT hooks VERIFIED.\n"
                    + "All other Brave IPv4/IPv6 output is intentionally BLOCKED.\n"
                    + "NOT PROVEN: live browser packet delivery or Home-loss safety. "
                    + "Try only http://10.0.0.169:4533/ on cellular; "
                    + "never disconnect Home during this experiment. "
                    + "Use Exact-owned Safe Stop immediately afterward.";
        } catch (Exception failed) {
            return "BRAVE HOME ACTIVATION FAILED ("
                    + failed.getClass().getSimpleName() + "): " + recover();
        }
    }

    String audit() throws Exception {
        RootBraveHomePilotPlan plan = saved();
        if (plan == null) return "BRAVE HOME: no owned pilot journal.";
        RootShell shell = new RootShell(app);
        shell.start();
        int selector = countRule(shell, plan);
        boolean v4 = exactHook(shell, "iptables",
                RootBraveHomePilotPlan.CHAIN4, RootBraveHomePilotPlan.TAG4,
                plan.hook4, true);
        boolean v6 = exactHook(shell, "ip6tables",
                RootBraveHomePilotPlan.CHAIN6, RootBraveHomePilotPlan.TAG6,
                plan.hook6, true);
        return "BRAVE NIGHTLY HOME AUDIT (READ-ONLY)\n"
                + "Owned Brave UID: " + plan.uid + "\n"
                + "Selector: " + (selector == 1 ? "EXACT" : "UNVERIFIED") + "\n"
                + "Brave IPv4 OUTPUT guard: " + (v4 ? "EXACT" : "UNVERIFIED") + "\n"
                + "Brave IPv6 OUTPUT guard: " + (v6 ? "EXACT" : "UNVERIFIED") + "\n"
                + "Synthetic UID route: " + targetRoute(shell, plan) + "\n"
                + "Brave IPv4 OUTPUT hook: "
                + counter(shell, "iptables", "OUTPUT", RootBraveHomePilotPlan.CHAIN4)
                + "\\nBrave Home TCP/4533 RETURN: "
                + counter(shell, "iptables", RootBraveHomePilotPlan.CHAIN4, "RETURN")
                + "\\nBrave IPv4 REJECT: "
                + counter(shell, "iptables", RootBraveHomePilotPlan.CHAIN4, "REJECT")
                + "\\nBrave IPv6 REJECT: "
                + counter(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6, "REJECT")
                + "\n"
                + "Real browser packets and Home-loss fail-closed behavior "
                + "remain unproven. Use Exact-owned Safe Stop.";
    }

    String recover() throws Exception {
        RootBraveHomePilotPlan plan = saved();
        if (plan == null) return "BRAVE HOME: no owned pilot journal.";
        RootShell shell = new RootShell(app);
        shell.start();
        try {
            // Inventory FIRST: if a foreign rule/chain took our reserved name,
            // never delete by guess. Retain the journal and fail closed.
            int selector = countRule(shell, plan);
            if (selector < 0
                    || !exactHook(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                        RootBraveHomePilotPlan.TAG4, plan.hook4,
                        hasHook(shell, "iptables", plan.hook4))
                    || !exactHook(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6,
                        RootBraveHomePilotPlan.TAG6, plan.hook6,
                        hasHook(shell, "ip6tables", plan.hook6))
                    || !chainValid(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                        plan.dev, true)
                    || !chainValid(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6,
                        plan.dev, false)) {
                throw new IllegalStateException("Foreign/changed Brave policy.");
            }

            // Remove routing BEFORE either packet guard or Home table.
            if (selector == 1) {
                run(shell, plan.selector.replace(" rule add ", " rule del "));
            }
            if (countRule(shell, plan) != 0) {
                throw new IllegalStateException("Brave UID selector still active.");
            }
            removeHook(shell, "iptables", plan.hook4);
            removeHook(shell, "ip6tables", plan.hook6);

            if (chainExists(shell, "iptables", RootBraveHomePilotPlan.CHAIN4)) {
                delIfPresent(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                        " -j REJECT");
                delIfPresent(shell, "iptables", RootBraveHomePilotPlan.CHAIN4,
                        " -o " + plan.dev + " -d 10.0.0.169/32 -p tcp"
                        + " --dport 4533 -j RETURN");
                run(shell, "iptables -w -t filter -X " + RootBraveHomePilotPlan.CHAIN4);
            }
            if (chainExists(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6)) {
                delIfPresent(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6,
                        " -j REJECT");
                run(shell, "ip6tables -w -t filter -X " + RootBraveHomePilotPlan.CHAIN6);
            }
            if (countRule(shell, plan) != 0
                    || hasHook(shell, "iptables", plan.hook4)
                    || hasHook(shell, "ip6tables", plan.hook6)
                    || chainExists(shell, "iptables", RootBraveHomePilotPlan.CHAIN4)
                    || chainExists(shell, "ip6tables", RootBraveHomePilotPlan.CHAIN6)) {
                throw new IllegalStateException("Brave exact-owned cleanup incomplete.");
            }
            clear();
            return "BRAVE HOME CLEAN_STOPPED; selector, dual-stack hooks, "
                    + "private chains absent; journal=0.";
        } catch (Exception unknown) {
            return "BRAVE HOME RECOVERY PAUSED; ownership journal retained. "
                    + "Keep Home connected, do not uninstall or clear RootLab data.";
        }
    }

    private static boolean hasHook(RootShell shell, String family,
            String expected) throws Exception {
        String lines = listing(shell, family + " -w -t filter -S OUTPUT");
        for (String line : lines.split("\\r?\\n")) {
            if (RootBraveHomePilotPlan.normalized(line).equals(expected)) {
                return true;
            }
        }
        return false;
    }

    private static void removeHook(RootShell shell,
            String family, String expected) throws Exception {
        if (hasHook(shell, family, expected)) {
            String del = expected.replace("-A OUTPUT ", "-D OUTPUT ");
            run(shell, family + " -w -t filter " + del);
        }
    }
}
