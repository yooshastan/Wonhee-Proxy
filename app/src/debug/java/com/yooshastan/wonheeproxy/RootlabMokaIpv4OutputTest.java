package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * Debug-only LIVE IPv4 firewall hook, restricted to detected Moka UID.
 *
 * This is NOT a routing selector. It requires the IPv6 guard, two exact-owned
 * staged chains, and an existing Home WG identity before it can attach.
 * On cellular, ordinary Moka IPv4 requests will generally be rejected
 * because NO Android UID rule redirects them to the Home interface.
 *
 * The durable journal is committed BEFORE invoking the single iptables hook.
 * Recovery MUST run before IPv6 hook, chain, or WireGuard link recovery.
 */
final class RootlabMokaIpv4OutputTest {
    private static final String PREF = "wonhee_rootlab_moka_ipv4_hook_v1";
    private static final String KEY = "pending";
    private static final String VERSION = "WMH4V1";
    private static final String COUNTER_PACKETS = "last_ipv4_reject_packets";
    private static final String COUNTER_BYTES = "last_ipv4_reject_bytes";
    private final Context app;

    RootlabMokaIpv4OutputTest(Context context) {
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

    private RootMokaHomeFirewallPilotPlan.Plan journalPlan() {
        String raw = prefs().getString(KEY, null);
        if (raw == null) return null;
        String[] parts = raw.split("\\|", -1);
        if (parts.length != 3 || !VERSION.equals(parts[0])
                || !parts[1].matches("[1-9][0-9]{4}")
                || !parts[2].matches("wnm[0-9a-f]{12}")) {
            throw new IllegalStateException(
                    "Unknown IPv4 OUTPUT ownership; preserve journal.");
        }
        return RootMokaHomeFirewallPilotPlan.compile(
                Integer.parseInt(parts[1]), parts[2]);
    }

    private void recordIntent(RootMokaHomeFirewallPilotPlan.Plan plan) {
        String raw = VERSION + "|" + plan.uid + "|" + plan.homeDevice;
        if (!prefs().edit().putString(KEY, raw).commit()
                || !raw.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("IPv4 OUTPUT intent commit failed.");
        }
    }

    private void clearExact() {
        if (!prefs().edit().remove(KEY).remove(COUNTER_PACKETS)
                .remove(COUNTER_BYTES).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("IPv4 hook journal clear failed.");
        }
    }

    private static RootMokaHomeFirewallPilotPlan.Step canonicalHook(
            RootMokaHomeFirewallPilotPlan.Plan plan) {
        RootMokaHomeFirewallPilotTransaction.validate(plan);
        for (RootMokaHomeFirewallPilotPlan.Step step : plan.steps) {
            if (step.family == 4 && "OWNER_ANCHOR".equals(step.kind)
                    && RootMokaHomeFirewallPilotPlan.safeStep(plan, step)) {
                return step;
            }
        }
        throw new IllegalStateException("No canonical Moka IPv4 hook.");
    }

    private static int references(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan) throws Exception {
        List<String> rules = new ArrayList<>();
        if (shell.run(rules, "iptables -w -t filter -S") != 0 || rules.isEmpty()) {
            throw new IllegalStateException("IPv4 filter listing unavailable.");
        }
        RootMokaHomeFirewallPilotPlan.Step hook = canonicalHook(plan);
        String expected = hook.install.replace(
                "iptables -w -t filter -I OUTPUT 1 ", "-A OUTPUT ");
        int count = 0;
        for (String line : rules) {
            boolean refer = line.contains(" -j " + RootMokaHomeFirewallPilotPlan.CHAIN4)
                    || line.contains(" -g " + RootMokaHomeFirewallPilotPlan.CHAIN4)
                    || line.contains(RootMokaHomeFirewallPilotPlan.TAG4);
            if (!refer) continue;
            String normalized = line.trim().replace("\"", "")
                    .replaceAll("\\s+", " ");
            if (!expected.equals(normalized)) {
                throw new IllegalStateException(
                        "Foreign IPv4 chain hook; retain ownership journal.");
            }
            count++;
        }
        if (count > 1) throw new IllegalStateException("Duplicate IPv4 hook.");
        return count;
    }

    private static boolean exactHook(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan) throws Exception {
        if (references(shell, plan) != 1) return false;
        RootMokaHomeFirewallPilotPlan.Step hook = canonicalHook(plan);
        String check = hook.inverse.replace(" -D OUTPUT ", " -C OUTPUT ");
        return shell.run(null, check + " >/dev/null 2>&1") == 0;
    }

    /** Read-only exact owned hook prerequisite for the Home fallback pilot. */
    boolean exactAttached(int uid, String device) throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan saved = journalPlan();
        if (saved == null || saved.uid != uid
                || !saved.homeDevice.equals(device)) return false;
        RootShell shell = new RootShell(app);
        shell.start();
        return exactHook(shell, saved);
    }

    String attach(int uid, String device) throws Exception {
        if (pendingOrUnknown(app)) {
            return "MOKA IPv4 HOOK REFUSED: previous journal needs Safe Stop.";
        }
        RootMokaHomeFirewallPilotPlan.Plan plan =
                RootMokaHomeFirewallPilotPlan.compile(uid, device);
        // Exact owned IPv6 protection must be installed and readable before
        // any IPv4 hook is exposed to Android app packets.
        if (!new RootlabMokaIpv6OutputTest(app).exactAttached(uid, device)
                || !new RootlabDetachedMokaFirewall(app)
                        .exactStagingPresentWithVerifiedIpv6Hook(uid, device)) {
            return "MOKA IPv4 HOOK REFUSED: exact IPv6 guard and both "
                    + "staged chains must be verified first.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        if (references(shell, plan) != 0) {
            return "MOKA IPv4 HOOK REFUSED: existing reserved IPv4 reference.";
        }
        RootMokaHomeFirewallPilotPlan.Step step = canonicalHook(plan);
        try {
            recordIntent(plan);
            if (shell.run(null, step.install) != 0 || !exactHook(shell, plan)
                    || !new RootlabDetachedMokaFirewall(app)
                            .exactStagingPresentWithVerifiedDualHooks(uid, device)) {
                throw new IllegalStateException("IPv4 hook readback mismatch.");
            }
            return "MOKA DUAL-STACK FIREWALL HOOKS VERIFIED (STRUCTURAL)\n"
                    + "Moka UID: " + uid + "\n"
                    + "IPv4: only TCP 10.0.0.169:4533 on verified Home "
                    + "interface may RETURN to Android OUTPUT; all other "
                    + "Moka IPv4 packets REJECT.\n"
                    + "IPv6: Moka IPv6 packets REJECT.\n"
                    + "NO Moka UID routing, fwmark, DNS or VPN activation. "
                    + "This is NOT proof of fail-closed packet delivery or "
                    + "Home reachability. Other Moka streaming may fail. "
                    + "Read IPv4 counters, then Exact-owned Safe Stop.";
        } catch (Exception failed) {
            String recovery = recover();
            return "MOKA IPv4 HOOK TEST FAILED (" + failed.getClass()
                    .getSimpleName() + "); " + recovery;
        }
    }

    String readCounters() throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan plan = journalPlan();
        if (plan == null) {
            return "MOKA IPv4 COUNTERS REFUSED: no owned hook journal.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        if (!exactHook(shell, plan)
                || !new RootlabMokaIpv6OutputTest(app)
                        .exactAttached(plan.uid, plan.homeDevice)
                || !new RootlabDetachedMokaFirewall(app)
                        .exactStagingPresentWithVerifiedDualHooks(
                                plan.uid, plan.homeDevice)) {
            return "MOKA IPv4 COUNTERS REFUSED: exact dual-stack firewall "
                    + "ownership not verified. Use Safe Stop.";
        }
        List<String> output = new ArrayList<>();
        List<String> chain = new ArrayList<>();
        if (shell.run(output, "iptables -w -t filter -L OUTPUT -nvx") != 0
                || shell.run(chain, "iptables -w -t filter -L "
                + RootMokaHomeFirewallPilotPlan.CHAIN4 + " -nvx") != 0) {
            return "MOKA IPv4 COUNTERS UNAVAILABLE: no kernel change.";
        }
        RootMokaIpv6CounterParser.Counts owner = RootMokaIpv6CounterParser.target(
                String.join("\n", output), RootMokaHomeFirewallPilotPlan.CHAIN4);
        RootMokaIpv6CounterParser.Counts allow = RootMokaIpv6CounterParser.target(
                String.join("\n", chain), "RETURN");
        RootMokaIpv6CounterParser.Counts reject = RootMokaIpv6CounterParser.target(
                String.join("\n", chain), "REJECT");
        boolean hadBaseline = prefs().contains(COUNTER_PACKETS)
                && prefs().contains(COUNTER_BYTES);
        long previous = prefs().getLong(COUNTER_PACKETS, 0);
        long previousBytes = prefs().getLong(COUNTER_BYTES, 0);
        long delta = hadBaseline
                ? RootMokaIpv6CounterParser.delta(previous, reject.packets) : -1;
        long bytesDelta = hadBaseline
                ? RootMokaIpv6CounterParser.delta(previousBytes, reject.bytes) : -1;
        if (!prefs().edit().putLong(COUNTER_PACKETS, reject.packets)
                .putLong(COUNTER_BYTES, reject.bytes).commit()) {
            return "MOKA IPv4 COUNTERS BASELINE SAVE FAILED; no kernel changes.";
        }
        return "MOKA IPv4 FIREWALL PACKET COUNTERS (READ ONLY)\n"
                + "UID " + plan.uid + "; Home device exact-owned\n"
                + "IPv4 OUTPUT Moka hook: " + owner.packets + " packets, "
                + owner.bytes + " bytes\n"
                + "IPv4 Home TCP/4533 RETURN: " + allow.packets + " packets, "
                + allow.bytes + " bytes\n"
                + "IPv4 terminal REJECT: " + reject.packets + " packets, "
                + reject.bytes + " bytes\n"
                + (delta < 0 || bytesDelta < 0
                    ? "DELTA: first reading or counter reset; no claim\n"
                    : "SINCE LAST READING: +" + delta + " rejected packets, +"
                    + bytesDelta + " bytes\n")
                + "These counts alone cannot prove Moka->Home routing "
                + "or no cellular fallback. No rules reset or changed. "
                + "Use Exact-owned Safe Stop.";
    }

    String recover() throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan plan = journalPlan();
        if (plan == null) return "MOKA IPv4 OUTPUT: no journaled hook.";
        RootShell shell = new RootShell(app);
        shell.start();
        try {
            int found = references(shell, plan);
            if (found == 1) {
                if (!exactHook(shell, plan)
                        || shell.run(null, canonicalHook(plan).inverse) != 0) {
                    throw new IllegalStateException("IPv4 exact inverse failed.");
                }
            }
            if (references(shell, plan) != 0) {
                throw new IllegalStateException("IPv4 hook still exists.");
            }
            clearExact();
            return "MOKA IPv4 OUTPUT CLEAN_STOPPED; hook journal=0; "
                    + "no reserved IPv4 OUTPUT reference remains.";
        } catch (Exception uncertain) {
            return "MOKA IPv4 OUTPUT RECOVERY PAUSED; journal retained. "
                    + "Do not clear app data or uninstall.";
        }
    }
}
